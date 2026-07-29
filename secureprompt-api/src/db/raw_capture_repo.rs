//! WS3-1 / WS3-2 — per-workspace raw-content capture settings (migration 021).
//!
//! Answers one question for the request path: may this workspace's raw
//! prompt, raw upstream response and PII-restored response be persisted at
//! all, and for how long?
//!
//! Read/write shape deliberately mirrors
//! [`crate::db::sidecar_policy_repo::SidecarPolicyRepository`]: `get` returns
//! `None` when the workspace has never chosen, `get_effective` resolves that
//! `None` against the safe default, and `upsert` writes one row per
//! workspace.
//!
//! ## Why there is no deployment-level "capture on" default
//!
//! `sidecar_unavailable` has an env-var default because an operator may
//! legitimately want the whole gateway to fail open. Capture has no
//! equivalent: an environment variable that switches plaintext prompt
//! retention on for every workspace at once is precisely the control a bank
//! security review would object to, and it would make the guarantee "a fresh
//! install stores zero raw content" depend on the deployment environment
//! rather than on the code. [`RawCaptureSettings::default`] is the ONLY
//! default, it is `enabled: false`, and the sole way to leave it is an
//! admin-authenticated write that lands a row in `raw_capture_audit`.
//!
//! ## Why `workspace_raw_capture` has no row-level security
//!
//! Same position as [`crate::db::sidecar_policy_repo`], and the same honest
//! caveat: the codebase's actual pattern is RLS **plus** a `set_config` on
//! the same connection (see [`crate::db::budget_repo`]), which is a few lines
//! of work, not impossible. RLS is omitted here because every method below
//! binds the authenticated `workspace_id` explicitly, so there is no
//! cross-tenant read to prevent, and because adding it to this table alone
//! while `workspace_secure_mode` (007) and `workspace_sidecar_policy` (018)
//! stay un-RLS'd would be inconsistency for its own sake. Adding RLS to all
//! three together is a reasonable follow-up.

use secureprompt_common::{errors::ApiError, types::WorkspaceId};
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// WS3-2 — retention for captured content when a workspace has opted in but
/// has not named a window. Days, counted from the request timestamp.
pub const DEFAULT_RETENTION_DAYS: i32 = 30;

/// Inclusive bounds accepted for `retention_days`, enforced both here and by
/// the CHECK constraint in migration 021.
pub const MIN_RETENTION_DAYS: i32 = 1;
pub const MAX_RETENTION_DAYS: i32 = 3650;

/// A workspace's effective raw-capture settings.
///
/// [`Default`] is "off, 30 days" and every fallback in this module funnels to
/// it — an unset workspace and (at the call site) a failed database read both
/// resolve to NOT capturing. The only way to get `enabled: true` is for the
/// value to be stored and readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawCaptureSettings {
    /// When false, no raw prompt, raw response or restored response is
    /// persisted anywhere. This is the state of every workspace that has
    /// never opted in, including every workspace on a fresh install.
    pub enabled: bool,
    /// Days captured content is retained. Meaningless while `enabled` is
    /// false; carried anyway so the settings API can round-trip a value an
    /// admin configured before switching capture on.
    pub retention_days: i32,
}

impl Default for RawCaptureSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            retention_days: DEFAULT_RETENTION_DAYS,
        }
    }
}

impl RawCaptureSettings {
    /// Clamp a caller-supplied retention into the accepted range rather than
    /// letting the database CHECK reject the whole PUT.
    #[must_use]
    pub const fn clamp_retention(days: i32) -> i32 {
        if days < MIN_RETENTION_DAYS {
            MIN_RETENTION_DAYS
        } else if days > MAX_RETENTION_DAYS {
            MAX_RETENTION_DAYS
        } else {
            days
        }
    }
}

/// One accepted change to a workspace's capture settings, as recorded in
/// `raw_capture_audit`.
#[derive(Debug, Clone)]
pub struct RawCaptureAuditEntry {
    pub actor_user_id: Option<Uuid>,
    pub actor_email: Option<String>,
    pub before: RawCaptureSettings,
    pub after: RawCaptureSettings,
}

pub struct RawCaptureRepository {
    pool: PgPool,
}

impl RawCaptureRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// The workspace's stored choice, if it has ever made one.
    ///
    /// `None` means no row — the normal state for every workspace, because
    /// migration 021 deliberately does not backfill. Resolve it with
    /// [`Self::get_effective`]; do not treat `None` as a setting.
    ///
    /// # Errors
    /// Returns `ApiError::Database` when the query fails.
    pub async fn get(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Option<RawCaptureSettings>, ApiError> {
        let row = sqlx::query(
            "SELECT enabled, retention_days
             FROM workspace_raw_capture
             WHERE workspace_id = $1",
        )
        .bind(workspace_id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        Ok(row.map(|r| RawCaptureSettings {
            enabled: r.get::<bool, _>("enabled"),
            retention_days: r.get::<i32, _>("retention_days"),
        }))
    }

    /// The settings that actually apply: the workspace's stored choice, or
    /// [`RawCaptureSettings::default`] (capture OFF) when it has never
    /// chosen.
    ///
    /// # Errors
    /// Returns `ApiError::Database` when the query fails. Callers on the
    /// request path treat that as capture disabled — see
    /// [`crate::pipeline::service`].
    pub async fn get_effective(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<RawCaptureSettings, ApiError> {
        Ok(self.get(workspace_id).await?.unwrap_or_default())
    }

    /// Upsert the workspace's settings AND append the immutable audit row, in
    /// ONE transaction.
    ///
    /// The transaction is the point. WS3-1's acceptance criterion is that
    /// enabling capture is itself audited; a settings write that commits while
    /// its audit row is rolled back would mean a workspace silently capturing
    /// raw prompts with nothing recording who turned it on. Committing them
    /// together makes "capture is on" and "somebody is on the hook for it"
    /// the same fact.
    ///
    /// Returns the stored settings.
    ///
    /// # Errors
    /// Returns `ApiError::Database` when the write fails.
    pub async fn upsert_audited(
        &self,
        workspace_id: WorkspaceId,
        settings: RawCaptureSettings,
        actor_user_id: Option<Uuid>,
        actor_email: Option<&str>,
    ) -> Result<RawCaptureSettings, ApiError> {
        let before = self.get_effective(workspace_id).await?;
        let retention_days = RawCaptureSettings::clamp_retention(settings.retention_days);

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?;

        let row = sqlx::query(
            "INSERT INTO workspace_raw_capture
                 (workspace_id, enabled, retention_days, updated_at, updated_by)
             VALUES ($1, $2, $3, NOW(), $4)
             ON CONFLICT (workspace_id) DO UPDATE SET
                enabled        = EXCLUDED.enabled,
                retention_days = EXCLUDED.retention_days,
                updated_at     = NOW(),
                updated_by     = EXCLUDED.updated_by
             RETURNING enabled, retention_days",
        )
        .bind(workspace_id.0)
        .bind(settings.enabled)
        .bind(retention_days)
        .bind(actor_user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        let stored = RawCaptureSettings {
            enabled: row.get::<bool, _>("enabled"),
            retention_days: row.get::<i32, _>("retention_days"),
        };

        sqlx::query(
            "INSERT INTO raw_capture_audit
                 (id, workspace_id, actor_user_id, actor_email,
                  enabled_before, enabled_after,
                  retention_days_before, retention_days_after, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())",
        )
        .bind(Uuid::new_v4())
        .bind(workspace_id.0)
        .bind(actor_user_id)
        .bind(actor_email)
        .bind(before.enabled)
        .bind(stored.enabled)
        .bind(before.retention_days)
        .bind(stored.retention_days)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?;

        if stored.enabled && !before.enabled {
            // Deliberately `warn!`, not `info!`: a workspace beginning to
            // retain plaintext prompts is an event an on-prem operator's log
            // pipeline should surface without anyone having asked it to.
            tracing::warn!(
                alert = "raw_capture_enabled",
                workspace_id = %workspace_id,
                actor_user_id = ?actor_user_id,
                retention_days = stored.retention_days,
                "raw request/response capture ENABLED for a workspace"
            );
        }

        Ok(stored)
    }

    /// The audit trail for a workspace, newest first. Read by
    /// `GET /v1/secure-mode` consumers and by the WS3-1 tests.
    ///
    /// # Errors
    /// Returns `ApiError::Database` when the query fails.
    pub async fn audit_trail(
        &self,
        workspace_id: WorkspaceId,
        limit: i64,
    ) -> Result<Vec<RawCaptureAuditEntry>, ApiError> {
        let rows = sqlx::query(
            "SELECT actor_user_id, actor_email,
                    enabled_before, enabled_after,
                    retention_days_before, retention_days_after
             FROM raw_capture_audit
             WHERE workspace_id = $1
             ORDER BY created_at DESC
             LIMIT $2",
        )
        .bind(workspace_id.0)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|r| RawCaptureAuditEntry {
                actor_user_id: r.get::<Option<Uuid>, _>("actor_user_id"),
                actor_email: r.get::<Option<String>, _>("actor_email"),
                before: RawCaptureSettings {
                    enabled: r.get::<bool, _>("enabled_before"),
                    retention_days: r.get::<i32, _>("retention_days_before"),
                },
                after: RawCaptureSettings {
                    enabled: r.get::<bool, _>("enabled_after"),
                    retention_days: r.get::<i32, _>("retention_days_after"),
                },
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The single most important line in this file: absence of a stored
    /// choice must mean capture is OFF.
    #[test]
    fn default_is_capture_disabled_with_thirty_day_retention() {
        let settings = RawCaptureSettings::default();
        assert!(
            !settings.enabled,
            "a workspace with no stored choice must not capture raw content"
        );
        assert_eq!(settings.retention_days, 30);
    }

    #[test]
    fn retention_is_clamped_to_the_accepted_range() {
        assert_eq!(RawCaptureSettings::clamp_retention(0), MIN_RETENTION_DAYS);
        assert_eq!(RawCaptureSettings::clamp_retention(-5), MIN_RETENTION_DAYS);
        assert_eq!(
            RawCaptureSettings::clamp_retention(9_999),
            MAX_RETENTION_DAYS
        );
        // A value inside the range passes through untouched — without this
        // the two assertions above would also pass for a function that
        // always returned MIN.
        assert_eq!(RawCaptureSettings::clamp_retention(7), 7);
        assert_eq!(RawCaptureSettings::clamp_retention(90), 90);
    }
}
