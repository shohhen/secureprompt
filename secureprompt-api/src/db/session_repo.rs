//! FU4 — the read side of "which sessions does this account hold?".
//!
//! # A session is a refresh-token chain
//!
//! There is no session table. `refresh_tokens` already holds one row per
//! sign-in and one row per rotation, and migration 027 gave every row in a
//! chain the same `session_id`. So the answer to "how many sessions" is
//! `COUNT(DISTINCT session_id)` over rows that are still live, and the answer
//! to "when did it start" is the OLDEST row in the chain while "when was it
//! last used" is the NEWEST. Counting rows instead of chains would report a
//! browser left open for a day as ninety-six devices.
//!
//! # What "live" means, and what happens to sessions nobody ends
//!
//! Live is `revoked_at IS NULL AND expires_at > NOW()` on at least one row of
//! the chain. Nothing has to observe a session ending for it to leave this
//! listing:
//!
//!   * Closed laptop, killed browser, crashed pod — the refresh row is simply
//!     never rotated again and drops out at its own `expires_at`. There is no
//!     heartbeat to miss and no orphan to reap.
//!   * `POST /v1/auth/logout`, replay detection, WS4-3's user-wide revocation
//!     and FU4's narrow one all set `revoked_at`, so the session leaves the
//!     listing in the same transaction that ends it.
//!
//! That is the entire reason this is not a new table: a bespoke session record
//! would have needed a lifetime invented for it and kept in step with the
//! refresh row's, and the two would eventually disagree.
//!
//! # The silent-zero trap
//!
//! `refresh_tokens` has carried FORCE ROW LEVEL SECURITY since migration 002,
//! so an unscoped read here returns the EMPTY SET and reports NO ERROR — an
//! administrator would be told "this account has no active sessions" and
//! believe it. Every query below runs inside [`crate::db::scope::begin_scoped`],
//! which reads the GUC back and refuses rather than answering nothing.

use chrono::{DateTime, Utc};
use secureprompt_common::errors::ApiError;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::db::scope::begin_scoped;

/// One live session, as an administrator or the account holder sees it.
///
/// Deliberately absent: `token_hash` and `access_jti`. The first authenticates
/// the session and the second is the key of the blacklist that revokes it;
/// neither is a description of a device, and a listing endpoint is not a place
/// to hand them out.
#[derive(Debug, Clone)]
pub struct SessionSummary {
    pub session_id: Uuid,
    /// The sign-in. Oldest row in the chain.
    pub started_at: DateTime<Utc>,
    /// The most recent rotation, which is the closest thing to "last used"
    /// this data has: an access token is used without touching the database,
    /// so only a refresh leaves a mark.
    pub last_seen_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// `None` when the client sent no usable address, or when
    /// `retention.purge` has since scrubbed it because the session ended.
    pub client_ip: Option<String>,
    pub client_descriptor: Option<String>,
    /// This is the session whose access token is making the request.
    pub is_current: bool,
}

/// What a narrow revocation needs to know before it acts.
#[derive(Debug, Clone)]
pub struct LiveSession {
    pub session_id: Uuid,
    /// The `jti` of every access token in this chain that could still be
    /// inside its own validity window — see
    /// [`SessionRepository::find_live_session`].
    pub revocable_jtis: Vec<String>,
}

pub struct SessionRepository {
    pub pool: PgPool,
}

impl SessionRepository {
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Every live session `user_id` holds inside `workspace_id`, newest use
    /// first.
    ///
    /// `current_jti` is the caller's own access-token id, used only to mark
    /// which row is "this device". It is compared, never returned.
    ///
    /// # Why the aggregates are what they are
    ///
    /// `MAX(client_ip)` looks like a strange way to read a column. It is
    /// correct because AT MOST ONE row per chain carries device context: it is
    /// written by `RefreshTokenRepository::insert` (sign-in) and deliberately
    /// not by `rotate` (see migration 027 on why a per-rotation copy would be a
    /// movement log). SQL aggregates skip NULLs, so `MAX` over one value and N
    /// nulls is that value, and over N nulls is NULL. `first_value` would need
    /// a window and a sort for the same answer.
    ///
    /// # Errors
    /// Returns `ApiError::Database` for pool/query failures and
    /// `ApiError::Internal` if the workspace scope does not arm.
    pub async fn list_live(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        current_jti: &str,
    ) -> Result<Vec<SessionSummary>, ApiError> {
        let mut tx = begin_scoped(&self.pool, workspace_id).await?;
        let rows = sqlx::query(
            "SELECT session_id,
                    MIN(created_at)        AS started_at,
                    MAX(created_at)        AS last_seen_at,
                    MAX(expires_at)        AS expires_at,
                    MAX(client_ip)         AS client_ip,
                    MAX(client_descriptor) AS client_descriptor,
                    COALESCE(bool_or(access_jti = $3), FALSE) AS is_current
             FROM refresh_tokens
             WHERE user_id = $1 AND workspace_id = $2
             GROUP BY session_id
             HAVING bool_or(revoked_at IS NULL AND expires_at > NOW())
             ORDER BY MAX(created_at) DESC",
        )
        .bind(user_id)
        .bind(workspace_id)
        .bind(current_jti)
        .fetch_all(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;

        Ok(rows
            .into_iter()
            .map(|row| SessionSummary {
                session_id: row.get("session_id"),
                started_at: row.get("started_at"),
                last_seen_at: row.get("last_seen_at"),
                expires_at: row.get("expires_at"),
                client_ip: row.get("client_ip"),
                client_descriptor: row.get("client_descriptor"),
                is_current: row.get("is_current"),
            })
            .collect())
    }

    /// Resolve one LIVE session belonging to `user_id` inside `workspace_id`,
    /// and collect the access-token ids that still need blacklisting.
    ///
    /// Returns `None` for a session that does not exist, belongs to another
    /// user, belongs to another workspace, or has already ended — all four give
    /// the caller one answer, so a 404 cannot be used to enumerate sessions the
    /// caller may not see.
    ///
    /// # Which jtis, and why that set is exactly right
    ///
    /// Each row records the `jti` of the access token minted alongside it, so a
    /// chain that has rotated three times has three jtis. Blacklisting all of
    /// them would be wasteful and blacklisting only the newest would be WRONG:
    /// the token minted just before the last rotation is still inside its own
    /// validity window and would keep working. The exact set is the rows minted
    /// within one access-token lifetime, because `jwt_auth::require` validates
    /// `exp` with a 60-second leeway and refuses anything older on its own
    /// terms. `access_ttl + leeway` is that boundary, and the caller supplies it
    /// as `minted_after` so the arithmetic lives with the configuration.
    ///
    /// Rows with a NULL `access_jti` — sessions that existed before migration
    /// 027 — contribute nothing. Their refresh chain is still closed by
    /// [`crate::db::session_revocation_repo::SessionRevocationRepository::revoke_one_session`],
    /// so they die at the current access token's own expiry rather than
    /// instantly. The response reports how many were blacklisted, so a caller
    /// can see the difference.
    ///
    /// # Errors
    /// Returns `ApiError::Database` for pool/query failures and
    /// `ApiError::Internal` if the workspace scope does not arm.
    pub async fn find_live_session(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        session_id: Uuid,
        minted_after: DateTime<Utc>,
    ) -> Result<Option<LiveSession>, ApiError> {
        let mut tx = begin_scoped(&self.pool, workspace_id).await?;
        let row = sqlx::query(
            "SELECT bool_or(revoked_at IS NULL AND expires_at > NOW()) AS live,
                    COALESCE(
                        array_agg(access_jti) FILTER (
                            WHERE access_jti IS NOT NULL AND created_at > $4
                        ),
                        ARRAY[]::TEXT[]
                    ) AS jtis
             FROM refresh_tokens
             WHERE user_id = $1 AND workspace_id = $2 AND session_id = $3",
        )
        .bind(user_id)
        .bind(workspace_id)
        .bind(session_id)
        .bind(minted_after)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;

        // Aggregate over zero rows is one row of NULLs, so "no such session"
        // and "session is over" both arrive here as a non-true `live`.
        if row.get::<Option<bool>, _>("live") != Some(true) {
            return Ok(None);
        }
        Ok(Some(LiveSession {
            session_id,
            revocable_jtis: row.get("jtis"),
        }))
    }
}

fn db_err(error: sqlx::Error) -> ApiError {
    ApiError::Database(error.to_string())
}
