//! WS4-3 — the Postgres half of admin-initiated session revocation.
//!
//! Two operations, both workspace-bound:
//!
//!   * [`SessionRevocationRepository::find_target`] — resolve the user whose
//!     sessions are about to be terminated, WITHIN the caller's workspace.
//!     A user in another workspace resolves to `None`, exactly like a user
//!     that does not exist, so the handler's 404 cannot be used to enumerate
//!     other tenants' members.
//!   * [`SessionRevocationRepository::revoke`] — close every active refresh
//!     row for that user AND write the audit record, in ONE transaction.
//!
//! # Why one transaction
//!
//! "The session was terminated" and "somebody is on the hook for terminating
//! it" have to commit together. The same reasoning
//! `RawCaptureRepository::upsert_audited` gives for raw capture: a control
//! whose audit trail can fail independently of the control is a control with a
//! silent mode.
//!
//! # The RLS silent-zero trap
//!
//! `current_setting('app.current_workspace_id', true)` returns NULL when the
//! GUC is unset. Under the `workspace_isolation` policy the predicate is then
//! NULL for every row, so a bare `UPDATE` matches ZERO rows and **succeeds** —
//! a revocation that revoked nothing, reporting no error. Migration 020
//! documents the shape; [`crate::db::scope::begin_scoped`] is the mitigation
//! and it is called as the first statement of the transaction, before any table
//! is touched. FU4 replaced this module's own `bind_workspace` with it: the
//! shared helper does the same `set_config` and then READS THE VALUE BACK, so a
//! transaction that failed to arm fails loudly instead of silently matching
//! nothing. Same set of statements, one extra `SELECT current_setting(...)`.
//!
//! Two further defences, because binding alone is invisible when it is
//! forgotten:
//!
//!   1. The `UPDATE` carries an explicit `workspace_id = $2` predicate as well
//!      as the RLS policy, so tenancy does not rest on the GUC alone.
//!   2. `revoke` RETURNS the number of rows it closed and the handler puts
//!      that number in the audit row, so a revocation that silently matched
//!      nothing is visible as a `0` in a table an auditor reads rather than as
//!      a success nobody can distinguish.

use chrono::{DateTime, Utc};
use secureprompt_common::errors::ApiError;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::db::scope::begin_scoped;

/// The user whose sessions are to be revoked, as they read at the moment of
/// the action. Email and role are copied into the audit row rather than
/// referenced, so deleting the account later cannot rewrite the record.
#[derive(Debug, Clone)]
pub struct RevocationTarget {
    pub user_id: Uuid,
    pub email: String,
    /// The raw `users.role` string. Parsed by the caller with
    /// `UserRole::from_db_str` so an unrecognised value fails the same way it
    /// would on the target's own next request.
    pub role: String,
}

/// Everything the caller needs to describe what the revocation did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevocationOutcome {
    pub audit_id: Uuid,
    /// Active `refresh_tokens` rows this call closed. Zero is a legitimate
    /// answer — a user with only an access token has no refresh row — and is
    /// recorded as such.
    pub refresh_tokens_revoked: i64,
    pub created_at: DateTime<Utc>,
}

/// Immutable description of one revocation, assembled by the handler and
/// written verbatim. Deliberately carries no IP address, no User-Agent and no
/// free-text reason — see migration 026's header for why a never-purged table
/// takes only what it needs.
#[derive(Debug, Clone)]
pub struct RevocationRecord<'a> {
    pub workspace_id: Uuid,
    pub actor_user_id: Uuid,
    pub actor_email: Option<&'a str>,
    pub actor_role: &'a str,
    pub target: &'a RevocationTarget,
    /// The watermark, in UNIX seconds, that the caller is about to publish to
    /// Redis. Recorded here so the audit row says which tokens it killed even
    /// after the Redis key has expired.
    pub revoked_before_unix: i64,
    /// FU4 — which session was ended, or `None` for WS4-3's user-wide lever.
    ///
    /// This is not decoration. [`SessionRevocationRepository::latest_watermark`]
    /// filters on it, because a per-session revocation must NOT become a
    /// user-wide one when Redis is unreachable — see that function's own note.
    pub session_id: Option<Uuid>,
}

pub struct SessionRevocationRepository {
    pub pool: PgPool,
}

impl SessionRevocationRepository {
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Resolve a revocation target inside `workspace_id`.
    ///
    /// The `workspace_id = $2` predicate is what makes a cross-tenant target
    /// indistinguishable from an absent one.
    ///
    /// # Errors
    /// Returns `ApiError::Database` for pool/query failures.
    pub async fn find_target(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<RevocationTarget>, ApiError> {
        let row =
            sqlx::query("SELECT id, email, role FROM users WHERE id = $1 AND workspace_id = $2")
                .bind(user_id)
                .bind(workspace_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(db_err)?;
        Ok(row.map(|record| RevocationTarget {
            user_id: record.get("id"),
            email: record.get("email"),
            role: record.get("role"),
        }))
    }

    /// FU3 — the durable half of the revocation watermark.
    ///
    /// `jwt_auth::require` normally reads `session_revoked:{user_id}` from
    /// Redis on every authenticated request. When Redis is unreachable that
    /// read is the only thing standing between a revoked token and a served
    /// request, so the same fact is read here from the table that recorded it.
    /// [`RevocationRecord::revoked_before_unix`] is the value published to
    /// Redis, written in the transaction that closes the refresh chain, so the
    /// two sources cannot disagree about a revocation that committed.
    ///
    /// `MAX` because watermarks only move forward: the newest revocation
    /// subsumes every earlier one, exactly as the Redis `SET` overwrite does.
    ///
    /// # `session_id IS NULL` is a security predicate, not a tidy-up
    ///
    /// FU4 writes a row into this same table for a NARROW revocation — one
    /// session ended, the user's other sessions deliberately left alone. Those
    /// rows carry the same `revoked_before_unix` shape. Without this filter,
    /// `MAX` would pick one up and hand it to `session_gate`, which compares it
    /// against `iat` for the USER: a revocation scoped to one lost laptop would
    /// silently become a revocation of every session that person holds, but
    /// only while Redis was unreachable. That is a scope escalation nobody
    /// would ever see in a green test run, because it is invisible while Redis
    /// answers. The narrow lever's durable half is the jti blacklist, and its
    /// residual during an outage is stated in `revoke_one_session`.
    ///
    /// Every row that existed before FU4 has `session_id IS NULL`, so this
    /// changes no historical answer — FU3's suite passes unchanged.
    ///
    /// Unlike the Redis key this row has no TTL, so it still answers for
    /// revocations whose watermark key has expired — strictly safer, because a
    /// token old enough for that to matter expired on its own terms long ago.
    ///
    /// # The workspace bind is not bookkeeping
    ///
    /// This table has FORCE ROW LEVEL SECURITY and a policy whose predicate is
    /// NULL for every row when `app.current_workspace_id` is unset, so an
    /// unbound `SELECT` returns the EMPTY SET and reports no error (migration
    /// 026's header names the trap). Read without binding, this function would
    /// answer "never revoked" for every user on the day the API stops
    /// connecting as a superuser, and the control would be silently off. The
    /// bind therefore happens in the SAME transaction as the read, and
    /// `tests/auth_redis_outage.rs::the_durable_watermark_survives_row_level_security`
    /// asserts it from a NOSUPERUSER/NOBYPASSRLS connection rather than from
    /// the `#[sqlx::test]` superuser pool that cannot observe the mistake.
    ///
    /// # Errors
    /// Returns `ApiError::Database` for pool/query failures. The caller MUST
    /// NOT read an error as "not revoked" — that is the whole failure this
    /// function exists to close.
    pub async fn latest_watermark(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<i64>, ApiError> {
        let mut tx = begin_scoped(&self.pool, workspace_id).await?;
        // Aggregate over zero rows is one row containing NULL, so `fetch_one`
        // is correct and `None` means "no revocation on record".
        let watermark: Option<i64> = sqlx::query_scalar(
            "SELECT MAX(revoked_before_unix) FROM session_revocation_audit
             WHERE target_user_id = $1 AND workspace_id = $2 AND session_id IS NULL",
        )
        .bind(user_id)
        .bind(workspace_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        Ok(watermark)
    }

    /// Look up an actor's email for the audit row. `None` when the row cannot
    /// be read — the audit record still gets written with the actor's id,
    /// because a missing display name must not stop a security action.
    ///
    /// # Errors
    /// Returns `ApiError::Database` for pool/query failures.
    pub async fn actor_email(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<String>, ApiError> {
        sqlx::query_scalar("SELECT email FROM users WHERE id = $1 AND workspace_id = $2")
            .bind(user_id)
            .bind(workspace_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)
    }

    /// Close every active refresh row for the target and write the audit
    /// record, in one workspace-bound transaction.
    ///
    /// # Errors
    /// Returns `ApiError::Database` for pool/query/commit failures. Nothing is
    /// committed on failure, so a caller that surfaces the error is telling
    /// the truth: neither the revocation nor its record happened.
    pub async fn revoke(
        &self,
        record: &RevocationRecord<'_>,
    ) -> Result<RevocationOutcome, ApiError> {
        let mut tx = begin_scoped(&self.pool, record.workspace_id).await?;

        // Explicit workspace predicate in ADDITION to the RLS policy — see the
        // module header. `refresh_tokens` carries `workspace_id`, so a row
        // belonging to another tenant cannot be reached even if the GUC were
        // wrong.
        let closed = sqlx::query(
            "UPDATE refresh_tokens
             SET revoked_at = NOW()
             WHERE user_id = $1 AND workspace_id = $2 AND revoked_at IS NULL",
        )
        .bind(record.target.user_id)
        .bind(record.workspace_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        let refresh_tokens_revoked = i64::try_from(closed.rows_affected()).unwrap_or(i64::MAX);

        let outcome = write_audit(&mut tx, record, refresh_tokens_revoked).await?;
        tx.commit().await.map_err(db_err)?;
        Ok(outcome)
    }

    /// FU4 — close ONE session's refresh chain and audit it, in one
    /// workspace-scoped transaction.
    ///
    /// Identical in shape to [`Self::revoke`] and different in exactly one
    /// predicate: `session_id = $3`. That predicate is the whole feature — it
    /// is what turns "terminate this person's access" into "sign this laptop
    /// out". The caller must have resolved the session through
    /// [`crate::db::session_repo::SessionRepository::find_live_session`] first,
    /// which is what proves it belongs to this user in this workspace.
    ///
    /// # What this does NOT do, deliberately
    ///
    /// It does not publish the per-user `session_revoked:{user_id}` watermark.
    /// That key is WS4-3's user-wide lever and applies to every token the user
    /// holds; using it here would end every session, which is the behaviour
    /// this endpoint exists to avoid. The already-minted access token for THIS
    /// session is stopped by `jti_blacklist:{jti}` instead, which
    /// `jwt_auth::session_gate` already consults on every request.
    ///
    /// # The residual, stated
    ///
    /// The jti blacklist is the one session control with no Redis-independent
    /// record — FU3 established that and degrades on it rather than failing
    /// closed. So a narrow revocation that committed BEFORE a Redis outage
    /// leaves that session's current access token servable for the remainder of
    /// its own lifetime (≤ `access_ttl` + 60 s leeway) on a pod that cannot
    /// reach Redis. The refresh chain is closed here, durably, so the session
    /// cannot renew past that one token. A narrow revocation attempted DURING
    /// an outage fails loudly instead: the handler surfaces the Redis error and
    /// reports no success.
    ///
    /// # Errors
    /// Returns `ApiError::Database` for pool/query/commit failures and
    /// `ApiError::Internal` if the workspace scope does not arm. Nothing is
    /// committed on failure.
    pub async fn revoke_one_session(
        &self,
        record: &RevocationRecord<'_>,
        session_id: Uuid,
    ) -> Result<RevocationOutcome, ApiError> {
        let mut tx = begin_scoped(&self.pool, record.workspace_id).await?;

        let closed = sqlx::query(
            "UPDATE refresh_tokens
             SET revoked_at = NOW()
             WHERE user_id = $1 AND workspace_id = $2 AND session_id = $3
               AND revoked_at IS NULL",
        )
        .bind(record.target.user_id)
        .bind(record.workspace_id)
        .bind(session_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        let refresh_tokens_revoked = i64::try_from(closed.rows_affected()).unwrap_or(i64::MAX);

        let outcome = write_audit(&mut tx, record, refresh_tokens_revoked).await?;
        tx.commit().await.map_err(db_err)?;
        Ok(outcome)
    }
}

/// The single writer of `session_revocation_audit`.
///
/// Shared by the user-wide and the narrow lever so there is not a second copy
/// of the column list to drift — the defect `role::privilege_level` was
/// extracted to avoid. `record.session_id` is what distinguishes the two shapes
/// in the trail, and it is the caller's to set.
async fn write_audit(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    record: &RevocationRecord<'_>,
    refresh_tokens_revoked: i64,
) -> Result<RevocationOutcome, ApiError> {
    let audit_id = Uuid::new_v4();
    let created_at: DateTime<Utc> = sqlx::query_scalar(
        "INSERT INTO session_revocation_audit
             (id, workspace_id, actor_user_id, actor_email, actor_role,
              target_user_id, target_email, target_role,
              revoked_before_unix, refresh_tokens_revoked, session_id, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
         RETURNING created_at",
    )
    .bind(audit_id)
    .bind(record.workspace_id)
    .bind(record.actor_user_id)
    .bind(record.actor_email)
    .bind(record.actor_role)
    .bind(record.target.user_id)
    .bind(&record.target.email)
    .bind(&record.target.role)
    .bind(record.revoked_before_unix)
    .bind(refresh_tokens_revoked)
    .bind(record.session_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(db_err)?;
    Ok(RevocationOutcome {
        audit_id,
        refresh_tokens_revoked,
        created_at,
    })
}

fn db_err(error: sqlx::Error) -> ApiError {
    ApiError::Database(error.to_string())
}
