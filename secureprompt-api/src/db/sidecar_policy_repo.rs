//! WS2-3 — per-workspace `sidecar_unavailable` policy (migration 018).
//!
//! Answers one question for the request path: when the ML sidecar produced no
//! coverage for this prompt, does this workspace want the request to fail
//! closed, or to proceed on the deterministic Rust floor with an alert?
//!
//! Read/write shape deliberately mirrors
//! [`crate::db::secure_mode_repo::SecureModeRepository`]: `get` returns the
//! default when no row exists, `upsert` writes one row per workspace.

use secureprompt_common::{errors::ApiError, types::WorkspaceId};
use sqlx::{PgPool, Row};

/// What to do when the ML sidecar produced no coverage for a request.
///
/// `Default` is [`Self::Block`] and every fallback in this module funnels to
/// it — an unset workspace, an unparseable stored value, and (at the call
/// site) a failed database read all fail CLOSED. The only way to get
/// [`Self::DegradeWithAlert`] is for the value to be stored, readable and
/// exactly `degrade_with_alert`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SidecarUnavailablePolicy {
    /// Reject the request with a 503 rather than forward a prompt the ML
    /// detector never saw.
    #[default]
    Block,
    /// Proceed on the deterministic floor, but make the degradation loud:
    /// alert, response header, and `floor_only = true` on the analytics row.
    DegradeWithAlert,
}

impl SidecarUnavailablePolicy {
    /// Parse a stored `workspace_sidecar_policy.sidecar_unavailable` value.
    ///
    /// Anything unrecognised — a value written by a newer node mid-rolling-
    /// upgrade, or one that somehow bypassed the CHECK constraint — falls
    /// back to [`Self::Block`]. A PII gateway must not fail open because it
    /// failed to understand its own configuration.
    #[must_use]
    pub fn from_db(value: &str) -> Self {
        match value {
            "degrade_with_alert" => Self::DegradeWithAlert,
            "block" => Self::Block,
            other => {
                tracing::warn!(
                    value = %other,
                    "unrecognised sidecar_unavailable policy; failing closed to 'block'"
                );
                Self::Block
            }
        }
    }

    /// Canonical stored / API / metric-label form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::DegradeWithAlert => "degrade_with_alert",
        }
    }
}

pub struct SidecarPolicyRepository {
    pool: PgPool,
}

impl SidecarPolicyRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Read the workspace's policy, or the fail-closed default when the
    /// workspace has never chosen one.
    ///
    /// Migration 018 deliberately does not backfill existing workspaces, so
    /// "no row" is the normal state for every workspace that predates WS2-3
    /// and for every workspace created after it. See the migration header.
    ///
    /// # Errors
    /// Returns `ApiError::Database` when the query fails. Callers on the
    /// request path treat that as [`SidecarUnavailablePolicy::Block`].
    pub async fn get(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<SidecarUnavailablePolicy, ApiError> {
        let row = sqlx::query(
            "SELECT sidecar_unavailable
             FROM workspace_sidecar_policy
             WHERE workspace_id = $1",
        )
        .bind(workspace_id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        Ok(row.map_or_else(SidecarUnavailablePolicy::default, |r| {
            SidecarUnavailablePolicy::from_db(&r.get::<String, _>("sidecar_unavailable"))
        }))
    }

    /// Upsert the workspace's policy.
    ///
    /// # Errors
    /// Returns `ApiError::Database` when the write fails.
    pub async fn upsert(
        &self,
        workspace_id: WorkspaceId,
        policy: SidecarUnavailablePolicy,
    ) -> Result<SidecarUnavailablePolicy, ApiError> {
        let row = sqlx::query(
            "INSERT INTO workspace_sidecar_policy (workspace_id, sidecar_unavailable, updated_at)
             VALUES ($1, $2, NOW())
             ON CONFLICT (workspace_id) DO UPDATE SET
                sidecar_unavailable = EXCLUDED.sidecar_unavailable,
                updated_at          = NOW()
             RETURNING sidecar_unavailable",
        )
        .bind(workspace_id.0)
        .bind(policy.as_str())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        Ok(SidecarUnavailablePolicy::from_db(
            &row.get::<String, _>("sidecar_unavailable"),
        ))
    }
}
