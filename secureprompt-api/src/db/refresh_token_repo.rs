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

    /// Insert a freshly minted refresh row. Caller supplies the raw token;
    /// storage holds only the SHA-256 hash.
    ///
    /// # Errors
    /// Returns `ApiError::Database` for pool/query failures.
    pub async fn insert(
        &self,
        user_id: Uuid,
        workspace_id: Uuid,
        raw_token: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<Uuid, ApiError> {
        let id = Uuid::new_v4();
        let hash = hash_refresh_token(raw_token);

        let mut tx = self.pool.begin().await.map_err(db_err)?;
        bind_workspace(&mut tx, workspace_id).await?;
        sqlx::query(
            "INSERT INTO refresh_tokens
                 (id, user_id, workspace_id, token_hash, expires_at, created_at)
             VALUES ($1, $2, $3, $4, $5, NOW())",
        )
        .bind(id)
        .bind(user_id)
        .bind(workspace_id)
        .bind(&hash)
        .bind(expires_at)
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
    /// # Errors
    /// Returns `ApiError::Database` for pool/query failures.
    pub async fn rotate(
        &self,
        old_raw: &str,
        new_raw: &str,
        new_expires_at: DateTime<Utc>,
    ) -> Result<RotationOutcome, ApiError> {
        let old_hash = hash_refresh_token(old_raw);
        let new_hash = hash_refresh_token(new_raw);

        // Pre-lookup — bypasses RLS so we can find the owning workspace.
        let pre = sqlx::query(
            "SELECT id, user_id, workspace_id, expires_at, revoked_at
             FROM refresh_tokens
             WHERE token_hash = $1
             LIMIT 1",
        )
        .bind(&old_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;

        let Some(row) = pre else {
            return Ok(RotationOutcome::NotFound);
        };

        let old_id: Uuid = row.get("id");
        let user_id: Uuid = row.get("user_id");
        let workspace_id: Uuid = row.get("workspace_id");
        let expires_at: DateTime<Utc> = row.get("expires_at");
        let revoked_at: Option<DateTime<Utc>> = row.get("revoked_at");

        // Already revoked — this is a replay. The handler will call
        // revoke_all_for_user and return 401.
        if revoked_at.is_some() {
            return Ok(RotationOutcome::ReplayDetected { user_id });
        }

        if expires_at <= Utc::now() {
            return Ok(RotationOutcome::Expired);
        }

        // Perform the atomic rotate under workspace RLS.
        let new_id = Uuid::new_v4();
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        bind_workspace(&mut tx, workspace_id).await?;

        // Insert the successor FIRST so replaced_by can reference it.
        sqlx::query(
            "INSERT INTO refresh_tokens
                 (id, user_id, workspace_id, token_hash, expires_at, created_at)
             VALUES ($1, $2, $3, $4, $5, NOW())",
        )
        .bind(new_id)
        .bind(user_id)
        .bind(workspace_id)
        .bind(&new_hash)
        .bind(new_expires_at)
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

    /// Revoke every active refresh row for the user. Invoked on replay
    /// detection (threat T-05-03).
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

        let mut tx = self.pool.begin().await.map_err(db_err)?;
        bind_workspace(&mut tx, workspace_id).await?;
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

    /// Look up an active (non-revoked, non-expired) refresh row by raw
    /// token. Used by the logout handler to best-effort revoke the
    /// current refresh row of the user who just logged out.
    ///
    /// # Errors
    /// Returns `ApiError::Database` for pool/query failures.
    pub async fn find_active_by_hash(
        &self,
        hash: &str,
    ) -> Result<Option<RefreshTokenRow>, ApiError> {
        let row = sqlx::query(
            "SELECT id, user_id, workspace_id, token_hash, expires_at,
                    revoked_at, replaced_by, created_at
             FROM refresh_tokens
             WHERE token_hash = $1 AND revoked_at IS NULL
               AND expires_at > NOW()
             LIMIT 1",
        )
        .bind(hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
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

async fn bind_workspace(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    workspace_id: Uuid,
) -> Result<(), ApiError> {
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
        .bind(workspace_id.to_string())
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    Ok(())
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
