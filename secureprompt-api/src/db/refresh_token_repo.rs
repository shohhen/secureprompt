//! Phase 5 / Plan 05-01 — refresh-token repository.
//!
//! Single-use rotating refresh: each `rotate` atomically revokes the old row
//! and inserts a successor, so a replayed refresh token surfaces as "already
//! revoked" and triggers `revoke_all_for_user` (threat T-05-03).
//!
//! Refresh tokens are hashed with SHA-256 (NOT Argon2) per CONTEXT D-06 and
//! RESEARCH A7 — Argon2id is too expensive for every-request lookup on
//! `/v1/auth/refresh`. Entropy comes from the 32-byte random payload, so
//! SHA-256 over full-entropy input is sufficient pre-image protection.

use crate::db::scope;
use chrono::{DateTime, Utc};
use secureprompt_common::errors::ApiError;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// A refresh-token row as stored in `refresh_tokens`.
#[derive(Debug, Clone)]
pub struct RefreshTokenRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub workspace_id: Uuid,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub replaced_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// FU4 — everything one sign-in records, in one struct rather than eight
/// positional arguments.
///
/// The three FU4 fields are what turn this row into a listable session:
/// `session_id` names the rotation CHAIN (so a browser left open for a day is
/// one session and not ninety-six), `access_jti` is the id of the access token
/// minted alongside it (so one session can be revoked without touching the
/// others), and the device pair says which machine it is.
///
/// This adds no statement to the login path. The INSERT that
/// `build_token_pair_body` already issued now carries four more values.
#[derive(Debug, Clone)]
pub struct NewSessionRow<'a> {
    pub user_id: Uuid,
    pub workspace_id: Uuid,
    pub raw_token: &'a str,
    pub expires_at: DateTime<Utc>,
    /// Fresh per sign-in. Every successor row copies it in `rotate`.
    pub session_id: Uuid,
    pub access_jti: &'a str,
    /// Recorded HERE and nowhere else. `rotate` deliberately does not carry
    /// these forward — see migration 027 on why a per-rotation copy would be a
    /// movement log rather than a session list.
    pub client_ip: Option<&'a str>,
    pub client_descriptor: Option<&'a str>,
}

/// Outcome of `rotate`. Kept as a tagged enum so handlers can discriminate
/// between normal rotation, replay (→ revoke_all_for_user), and invalid
/// tokens (→ 401) without string matching on `ApiError` strings.
#[derive(Debug, Clone)]
pub enum RotationOutcome {
    Rotated {
        old_id: Uuid,
        new_id: Uuid,
        user_id: Uuid,
        workspace_id: Uuid,
    },
    ReplayDetected {
        user_id: Uuid,
    },
    /// FU4 — the row was revoked WITHOUT being rotated: logout, WS4-3's
    /// user-wide revocation, FU4's narrow one, or an earlier
    /// `revoke_all_for_user`. 401, and nothing else.
    ///
    /// # Why this is not `ReplayDetected`
    ///
    /// Before FU4, `rotate` treated `revoked_at IS NOT NULL` as replay full
    /// stop, so it answered `ReplayDetected` here — and the handler's response
    /// to that is `revoke_all_for_user`. That was invisible while every
    /// revocation was user-wide: everything was already revoked, so revoking it
    /// again changed nothing. It stops being invisible the moment ONE session
    /// can be ended: the ended device retries its refresh once, the gateway
    /// reads it as a stolen token, and every OTHER session that person holds is
    /// terminated. `ending_one_session_leaves_the_other_signed_in` caught
    /// exactly that, on its "the surviving session must still rotate" control.
    ///
    /// `replaced_by` is what separates the two, and it is not a proxy: it is
    /// set by, and only by, the rotation that revoked the row. Present means a
    /// successor was minted and this presentation is a SECOND use of a token
    /// that already worked — threat T-05-03, and still `ReplayDetected`.
    /// Absent means the row was killed administratively and was never used
    /// twice. No detection is lost; `refresh_replay_detect` in
    /// `tests/dashboard/auth_tests.rs` still drives the real replay path.
    Revoked,
    NotFound,
    Expired,
}

pub struct RefreshTokenRepository {
    pub pool: PgPool,
}

impl RefreshTokenRepository {
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Insert a freshly minted refresh row — which is to say, OPEN A SESSION.
    /// Caller supplies the raw token; storage holds only the SHA-256 hash.
    ///
    /// # Errors
    /// Returns `ApiError::Database` for pool/query failures.
    pub async fn insert(&self, row: &NewSessionRow<'_>) -> Result<Uuid, ApiError> {
        let id = Uuid::new_v4();
        let hash = hash_refresh_token(row.raw_token);

        let mut tx = scope::begin_scoped(&self.pool, row.workspace_id).await?;
        sqlx::query(
            "INSERT INTO refresh_tokens
                 (id, user_id, workspace_id, token_hash, expires_at, created_at,
                  session_id, access_jti, client_ip, client_descriptor)
             VALUES ($1, $2, $3, $4, $5, NOW(), $6, $7, $8, $9)",
        )
        .bind(id)
        .bind(row.user_id)
        .bind(row.workspace_id)
        .bind(&hash)
        .bind(row.expires_at)
        .bind(row.session_id)
        .bind(row.access_jti)
        .bind(row.client_ip)
        .bind(row.client_descriptor)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        Ok(id)
    }

    /// Rotate an active refresh token atomically. Returns an explicit
    /// outcome so the handler can decide whether to mint a new pair,
    /// revoke-all (replay), or 401.
    ///
    /// Process:
    ///   1. Pre-lookup without RLS to obtain `user_id` + `workspace_id`
    ///      for the hash (needed to bind RLS for the UPDATE).
    ///   2. Inside the workspace-bound transaction, update-revoke the
    ///      active row (WHERE revoked_at IS NULL); zero rows → replay or
    ///      not-found branch.
    ///   3. If revoked, insert the successor row and return `Rotated`.
    ///
    /// # FU4: the successor inherits the session, not the device
    ///
    /// `session_id` is COPIED from the row being rotated, so the whole chain
    /// answers to one name and the listing reports one session. `access_jti` is
    /// the id of the access token the caller is about to mint alongside this
    /// row, which is why it is a parameter rather than something this function
    /// invents: `POST /v1/auth/refresh` must record the jti it actually
    /// returned, or a later narrow revocation blacklists a token nobody holds.
    ///
    /// `client_ip` and `client_descriptor` are deliberately NOT carried
    /// forward. They stay NULL on every successor, so exactly one row per
    /// session — the sign-in — describes a device. Copying them here would be
    /// harmless-looking and would turn this table into a record of where each
    /// person was every fifteen minutes for the life of a thirty-day refresh
    /// chain; `rotation_does_not_re_record_the_device` is the test that fails
    /// if a later change adds them.
    ///
    /// # Errors
    /// Returns `ApiError::Database` for pool/query failures.
    pub async fn rotate(
        &self,
        old_raw: &str,
        new_raw: &str,
        new_access_jti: &str,
        new_expires_at: DateTime<Utc>,
    ) -> Result<RotationOutcome, ApiError> {
        let old_hash = hash_refresh_token(old_raw);
        let new_hash = hash_refresh_token(new_raw);

        // Pre-lookup. CROSS-TENANT BY NECESSITY: the presented token is thirty-
        // two bytes of entropy and does not name its workspace, so this read is
        // what DISCOVERS the scope the write below is armed to.
        //
        // It runs inside a POSSESSION PROBE rather than on the bare pool.
        // Migration 032's `refresh_token_possession` policy admits, for SELECT
        // only, the single row whose `token_hash` this transaction names — so a
        // role that does not bypass RLS finds the row it was handed and still
        // finds nothing else. On the bare pool this returned `None` under such
        // a role and `rotate` answered `NotFound`, which 401s every
        // `/v1/auth/refresh` in the deployment.
        let mut probe_tx = scope::begin_refresh_token_probe(&self.pool, &old_hash).await?;
        let pre = sqlx::query(
            "SELECT id, user_id, workspace_id, expires_at, revoked_at, replaced_by, session_id
             FROM refresh_tokens
             WHERE token_hash = $1
             LIMIT 1",
        )
        .bind(&old_hash)
        .fetch_optional(&mut *probe_tx)
        .await
        .map_err(db_err)?;
        // Read-only, and the probe must not stay armed while the scoped write
        // below runs on another checkout of the pool.
        probe_tx.rollback().await.map_err(db_err)?;

        let Some(row) = pre else {
            return Ok(RotationOutcome::NotFound);
        };

        let old_id: Uuid = row.get("id");
        let user_id: Uuid = row.get("user_id");
        let workspace_id: Uuid = row.get("workspace_id");
        let session_id: Uuid = row.get("session_id");
        let expires_at: DateTime<Utc> = row.get("expires_at");
        let revoked_at: Option<DateTime<Utc>> = row.get("revoked_at");
        let replaced_by: Option<Uuid> = row.get("replaced_by");

        // Already revoked. WHY it was revoked decides the answer — see
        // `RotationOutcome::Revoked`. A row with a successor was used once
        // already and is being presented again (replay, threat T-05-03); a row
        // without one was killed administratively and its presentation is
        // simply a dead token.
        if revoked_at.is_some() {
            return Ok(if replaced_by.is_some() {
                RotationOutcome::ReplayDetected { user_id }
            } else {
                RotationOutcome::Revoked
            });
        }

        if expires_at <= Utc::now() {
            return Ok(RotationOutcome::Expired);
        }

        // Perform the atomic rotate under workspace RLS.
        let new_id = Uuid::new_v4();
        let mut tx = scope::begin_scoped(&self.pool, workspace_id).await?;

        // Insert the successor FIRST so replaced_by can reference it. No
        // `client_ip` / `client_descriptor` columns here, on purpose — see the
        // doc comment above.
        sqlx::query(
            "INSERT INTO refresh_tokens
                 (id, user_id, workspace_id, token_hash, expires_at, created_at,
                  session_id, access_jti)
             VALUES ($1, $2, $3, $4, $5, NOW(), $6, $7)",
        )
        .bind(new_id)
        .bind(user_id)
        .bind(workspace_id)
        .bind(&new_hash)
        .bind(new_expires_at)
        .bind(session_id)
        .bind(new_access_jti)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        // Revoke old row and set replaced_by. WHERE revoked_at IS NULL
        // is the race-safe gate — if another concurrent rotate already
        // revoked it, we see 0 rows affected and unwind as replay.
        let updated = sqlx::query(
            "UPDATE refresh_tokens
             SET revoked_at = NOW(), replaced_by = $2
             WHERE id = $1 AND revoked_at IS NULL",
        )
        .bind(old_id)
        .bind(new_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        if updated.rows_affected() == 0 {
            // Race: another concurrent refresh won. Treat as replay.
            tx.rollback().await.map_err(db_err)?;
            return Ok(RotationOutcome::ReplayDetected { user_id });
        }

        tx.commit().await.map_err(db_err)?;
        Ok(RotationOutcome::Rotated {
            old_id,
            new_id,
            user_id,
            workspace_id,
        })
    }

    /// Revoke every active refresh row for the user. This is what
    /// `POST /v1/auth/logout` calls, and what replay detection calls
    /// (threat T-05-03).
    ///
    /// # The two halves, and which one is load-bearing
    ///
    /// The `users` read is on the bare pool because `users` is NOT under row-
    /// level security — deliberately, and migration 031 Part 2 is the record of
    /// why and of what has to happen before it can be. `tests/
    /// migration_031_rls.rs::users_is_not_armed_and_this_is_the_open_defect` is
    /// the tripwire that fires if that changes; when it does, THIS read becomes
    /// a silent zero and logout stops revoking, because a missing user row is
    /// resolved to `Ok(())` three lines down.
    ///
    /// The UPDATE goes through [`scope::begin_scoped`], not a bare
    /// `set_config`, and that is the load-bearing half. An UPDATE whose scope
    /// did not arm is filtered by the policy's `USING` clause and matches ZERO
    /// rows WITHOUT erroring — the loud-write intuition only holds for INSERT,
    /// where `WITH CHECK` rejects. `begin_scoped` reads the setting back, so an
    /// unarmed logout raises instead of returning 204 over a session that is
    /// still refreshable. Measured: `logout_revokes_the_refresh_token_under_a_
    /// non_bypassing_role` fails if the arming is removed.
    ///
    /// # Errors
    /// Returns `ApiError::Database` for pool/query failures.
    pub async fn revoke_all_for_user(&self, user_id: Uuid) -> Result<(), ApiError> {
        // Need workspace_id for RLS binding; users have a single workspace.
        let row = sqlx::query("SELECT workspace_id FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        let Some(record) = row else {
            // User doesn't exist — nothing to revoke.
            return Ok(());
        };
        let workspace_id: Uuid = record.get("workspace_id");

        let mut tx = scope::begin_scoped(&self.pool, workspace_id).await?;
        sqlx::query(
            "UPDATE refresh_tokens
             SET revoked_at = NOW()
             WHERE user_id = $1 AND revoked_at IS NULL",
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        Ok(())
    }

    /// Look up an active (non-revoked, non-expired) refresh row by the SHA-256
    /// of its raw token.
    ///
    /// # Who calls this
    ///
    /// NOTHING, as of this commit — verified by grep across every tracked file
    /// in the repository. The doc comment this replaces said "Used by the
    /// logout handler to best-effort revoke the current refresh row of the user
    /// who just logged out", and that has been false since `bc2b586` introduced
    /// the method: `dashboard::auth::logout` calls
    /// [`Self::revoke_all_for_user`]. The claim is recorded here because
    /// `tests/rls_call_site_guard.rs` graded this method's silent zero as the
    /// severe one ON THAT COMMENT, and a reader who inherits the entry needs to
    /// know the comment was the only evidence for it.
    ///
    /// It is kept, and fixed, rather than deleted because it is the same
    /// cross-tenant by-hash primitive `rotate`'s pre-lookup needs, and the
    /// scoping it now carries is the thing worth pinning.
    ///
    /// # Scoping
    ///
    /// CROSS-TENANT BY NECESSITY, and therefore run inside the same possession
    /// probe as `rotate`'s pre-lookup — see
    /// [`scope::begin_refresh_token_probe`]. On the bare pool this returned
    /// `None` for a live row under a role that does not bypass RLS.
    ///
    /// # Errors
    /// Returns `ApiError::Database` for pool/query failures.
    pub async fn find_active_by_hash(
        &self,
        hash: &str,
    ) -> Result<Option<RefreshTokenRow>, ApiError> {
        let mut probe_tx = scope::begin_refresh_token_probe(&self.pool, hash).await?;
        let row = sqlx::query(
            "SELECT id, user_id, workspace_id, token_hash, expires_at,
                    revoked_at, replaced_by, created_at
             FROM refresh_tokens
             WHERE token_hash = $1 AND revoked_at IS NULL
               AND expires_at > NOW()
             LIMIT 1",
        )
        .bind(hash)
        .fetch_optional(&mut *probe_tx)
        .await
        .map_err(db_err)?;
        probe_tx.rollback().await.map_err(db_err)?;
        Ok(row.map(|record| RefreshTokenRow {
            id: record.get("id"),
            user_id: record.get("user_id"),
            workspace_id: record.get("workspace_id"),
            token_hash: record.get("token_hash"),
            expires_at: record.get("expires_at"),
            revoked_at: record.get("revoked_at"),
            replaced_by: record.get("replaced_by"),
            created_at: record.get("created_at"),
        }))
    }
}

/// SHA-256 hex of the raw refresh token. Public module-level helper so
/// handlers and tests can derive the same hash the repo stores.
#[must_use]
pub fn hash_refresh_token(raw: &str) -> String {
    hex::encode(Sha256::digest(raw.as_bytes()))
}

fn db_err(error: sqlx::Error) -> ApiError {
    ApiError::Database(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_stable_and_deterministic() {
        let raw = "rt_abc123";
        let first = hash_refresh_token(raw);
        let second = hash_refresh_token(raw);
        assert_eq!(first, second);
        assert_eq!(first.len(), 64, "SHA-256 hex is 64 chars");
    }

    #[test]
    fn hash_differs_for_different_inputs() {
        assert_ne!(hash_refresh_token("a"), hash_refresh_token("b"));
    }
}
