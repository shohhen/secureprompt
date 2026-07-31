//! WS2-3 — per-workspace `sidecar_unavailable` policy (migration 018).
//!
//! Answers one question for the request path: when the ML sidecar produced no
//! coverage for this prompt, does this workspace want the request to fail
//! closed, or to proceed on the deterministic Rust floor with an alert?
//!
//! Read/write shape deliberately mirrors
//! [`crate::db::secure_mode_repo::SecureModeRepository`]: `get` returns the
//! default when no row exists, `upsert` writes one row per workspace.
//!
//! ## Row-level security
//!
//! Migration 018 shipped this table without any, and this module used to
//! explain why: both methods bind the authenticated `workspace_id`, "so there
//! is no cross-tenant read to prevent". Measured from a NOSUPERUSER /
//! NOBYPASSRLS role armed to another workspace, there was: the table was
//! readable and its rows overwritable across tenants, so one tenant could
//! flip another's fail-open/fail-closed choice. Binding `workspace_id` in
//! these queries protected these queries.
//!
//! Migration 030 arms it with the standard `workspace_isolation` policy. The
//! "FORCE RLS alone would make every read return zero rows" that 018's header
//! warns about is real and is exactly why every method here goes through
//! [`crate::db::scope::begin_scoped`]: it sets `app.current_workspace_id`
//! transaction-locally and READS IT BACK, so an unarmed transaction fails
//! loudly instead of answering nothing. Without that, an unset GUC would make
//! [`Self::get_effective`] silently revert a workspace that chose
//! `degrade_with_alert` back to `block` — fail-closed, so nothing would page,
//! and the gateway would simply stop honouring a choice its operator made.

use secureprompt_common::{errors::ApiError, types::WorkspaceId};
use serde_json::json;
use sqlx::{PgPool, Row};

use crate::db::admin_audit_repo::{self, AdminActor, AdminAuditAction, AdminAuditEntry};
use crate::db::scope::begin_scoped;

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

    /// Read the workspace's stored choice, if it has ever made one.
    ///
    /// `None` means no row — the normal state for every workspace that
    /// predates WS2-3 and for every workspace created after it, because
    /// migration 018 deliberately does not backfill. Resolve `None` against
    /// the deployment default with [`Self::get_effective`]; do not treat it
    /// as a policy in its own right.
    ///
    /// # Errors
    /// Returns `ApiError::Database` when the query fails and
    /// `ApiError::Internal` when the tenancy scope does not arm — the latter
    /// in preference to returning `None`, which the caller would read as
    /// "this workspace never chose".
    pub async fn get(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Option<SidecarUnavailablePolicy>, ApiError> {
        let mut tx = begin_scoped(&self.pool, workspace_id.0).await?;

        let row = sqlx::query(
            "SELECT sidecar_unavailable
             FROM workspace_sidecar_policy
             WHERE workspace_id = $1",
        )
        .bind(workspace_id.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?;

        Ok(row
            .map(|r| SidecarUnavailablePolicy::from_db(&r.get::<String, _>("sidecar_unavailable"))))
    }

    /// The policy that actually applies to this workspace: its stored choice
    /// if it has one, otherwise the deployment default from
    /// `SECUREPROMPT_SIDECAR_UNAVAILABLE_DEFAULT` (itself `block` unless an
    /// operator opted out).
    ///
    /// # Errors
    /// Returns `ApiError::Database` when the query fails. Callers on the
    /// request path treat that as [`SidecarUnavailablePolicy::Block`].
    pub async fn get_effective(
        &self,
        workspace_id: WorkspaceId,
        deployment_default: SidecarUnavailablePolicy,
    ) -> Result<SidecarUnavailablePolicy, ApiError> {
        Ok(self.get(workspace_id).await?.unwrap_or(deployment_default))
    }

    /// Upsert the workspace's policy, and audit the move (P1A).
    ///
    /// This is the control that decides whether a prompt the PII detector never
    /// saw is forwarded upstream anyway. `degrade_with_alert` is the setting a
    /// customer will be asked about after a leak, and until now nothing
    /// recorded who chose it or when.
    ///
    /// `deployment_default` is needed to state the BEFORE honestly: a workspace
    /// with no row is not "unset", it is running the deployment's default, and
    /// an audit row saying `before: null` would misdescribe the control that
    /// was actually in force. That is the same distinction
    /// [`Self::get_effective`] exists to make.
    ///
    /// Writes NO row when the effective policy does not move — re-submitting
    /// the same value is not a change to a security control. See
    /// `CONTROL_COVERAGE`.
    ///
    /// # Errors
    /// Returns `ApiError::Database` when the write fails and
    /// `ApiError::Internal` when the tenancy scope does not arm.
    pub async fn upsert(
        &self,
        workspace_id: WorkspaceId,
        policy: SidecarUnavailablePolicy,
        deployment_default: SidecarUnavailablePolicy,
        actor: &AdminActor,
    ) -> Result<SidecarUnavailablePolicy, ApiError> {
        // Both `admin_audit` (028) and this table (030) are under FORCE RLS,
        // so the transaction has to be scoped for either write to be accepted.
        // When this line was written only `admin_audit` was armed; 030 closed
        // the other half.
        let mut tx = begin_scoped(&self.pool, workspace_id.0).await?;

        let before = sqlx::query(
            "SELECT sidecar_unavailable
             FROM workspace_sidecar_policy
             WHERE workspace_id = $1",
        )
        .bind(workspace_id.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?
        .map_or(deployment_default, |r| {
            SidecarUnavailablePolicy::from_db(&r.get::<String, _>("sidecar_unavailable"))
        });

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
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        let after = SidecarUnavailablePolicy::from_db(&row.get::<String, _>("sidecar_unavailable"));
        if before != after {
            admin_audit_repo::write(
                &mut tx,
                actor,
                &AdminAuditEntry::on_object(
                    AdminAuditAction::SidecarPolicyUpdated,
                    workspace_id.0,
                    None,
                )
                .with_detail(json!({
                    "before": before.as_str(),
                    "after": after.as_str(),
                })),
            )
            .await?;
        }

        tx.commit()
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?;

        Ok(after)
    }
}
