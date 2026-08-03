//! Phase 5 / Plan 05-05 — Workspace budget repository.
//!
//! Single-row-per-workspace pattern per CONTEXT D-23:
//! - `workspace_budgets(workspace_id PK, daily_token_limit BIGINT NULL,`
//! - `  monthly_token_limit BIGINT NULL,`
//! - `  behavior TEXT CHECK('block'|'warn'|'flag'),`
//! - `  updated_at TIMESTAMPTZ)`
//!
//! RLS is enforced via the standard `set_config('app.current_workspace_id', ...)` template
//! used throughout Phase 1–5 repositories.

use chrono::{DateTime, Utc};
use secureprompt_common::errors::ApiError;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::db::admin_audit_repo::{
    self, changed_field, AdminActor, AdminAuditAction, AdminAuditEntry,
};
use crate::db::scope::begin_scoped;

/// The three enforcement modes for a workspace budget.
///
/// Serialises to/from lowercase strings matching the Postgres CHECK constraint
/// `('block','warn','flag')`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BudgetBehavior {
    Block,
    Warn,
    Flag,
}

impl BudgetBehavior {
    /// Convert to the exact DB string stored in `workspace_budgets.behavior`.
    #[must_use]
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Warn => "warn",
            Self::Flag => "flag",
        }
    }

    /// Parse from the DB string.
    ///
    /// # Errors
    /// Returns `ApiError::Internal` when the stored string is not a recognised variant
    /// (schema constraint should prevent this, but we defend in-depth).
    pub fn from_db_str(s: &str) -> Result<Self, ApiError> {
        match s {
            "block" => Ok(Self::Block),
            "warn" => Ok(Self::Warn),
            "flag" => Ok(Self::Flag),
            other => Err(ApiError::Internal(format!(
                "unknown BudgetBehavior in DB: {other}"
            ))),
        }
    }
}

/// The persisted workspace budget row.
#[derive(Debug, Clone)]
pub struct WorkspaceBudgetRow {
    pub workspace_id: Uuid,
    pub daily_token_limit: Option<i64>,
    pub monthly_token_limit: Option<i64>,
    pub behavior: BudgetBehavior,
    pub updated_at: DateTime<Utc>,
}

/// Read/write access to `workspace_budgets` with RLS context.
pub struct BudgetRepository {
    pool: PgPool,
}

impl BudgetRepository {
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Fetch the budget configuration for `workspace_id`.
    ///
    /// Returns `None` when no row exists (the workspace has no explicit budget).
    ///
    /// # Errors
    /// Returns `ApiError::Database` on SQL failure.
    pub async fn get(&self, workspace_id: Uuid) -> Result<Option<WorkspaceBudgetRow>, ApiError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?;

        sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
            .bind(workspace_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?;

        let row = sqlx::query(
            "SELECT workspace_id, daily_token_limit, monthly_token_limit, behavior, updated_at
             FROM workspace_budgets
             WHERE workspace_id = $1",
        )
        .bind(workspace_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?;

        let Some(r) = row else {
            return Ok(None);
        };
        let behavior_str: String = r.get("behavior");
        Ok(Some(WorkspaceBudgetRow {
            workspace_id: r.get("workspace_id"),
            daily_token_limit: r.get("daily_token_limit"),
            monthly_token_limit: r.get("monthly_token_limit"),
            behavior: BudgetBehavior::from_db_str(&behavior_str)?,
            updated_at: r.get("updated_at"),
        }))
    }

    /// Upsert the budget configuration for `workspace_id`, and audit what
    /// moved (P1A).
    ///
    /// On conflict (duplicate `workspace_id`), replaces the existing row.
    ///
    /// # Why the "before" is read inside this transaction
    ///
    /// The audit row's whole content is the DIFF, so it has to be taken from
    /// the state the write is actually replacing. Reading it in the handler
    /// and passing it in would leave a window in which a concurrent PUT lands
    /// between the read and the write, and the record would then describe a
    /// change that never happened. The SELECT below is in the same transaction
    /// as the upsert and the audit row.
    ///
    /// # When nothing moved, nothing is recorded
    ///
    /// A dashboard that re-saves the form on every page view would otherwise
    /// bury the real changes under identical rows. Same rule as a repeated
    /// `POST /v1/keys/{id}/rotate` inside its grace window, and it is stated in
    /// `CONTROL_COVERAGE` so an auditor reads this section as CHANGES rather
    /// than as form submissions.
    ///
    /// # Errors
    /// Returns `ApiError::BadRequest` when a limit value is negative,
    /// `ApiError::Database` on SQL failure, and `ApiError::Internal` when the
    /// tenancy scope does not arm.
    pub async fn upsert(
        &self,
        workspace_id: Uuid,
        daily: Option<i64>,
        monthly: Option<i64>,
        behavior: BudgetBehavior,
        actor: &AdminActor,
    ) -> Result<WorkspaceBudgetRow, ApiError> {
        // Validate: limits must be non-negative when provided.
        if daily.is_some_and(|d| d < 0) {
            return Err(ApiError::BadRequest(
                "daily_token_limit must be >= 0".into(),
            ));
        }
        if monthly.is_some_and(|m| m < 0) {
            return Err(ApiError::BadRequest(
                "monthly_token_limit must be >= 0".into(),
            ));
        }

        // `begin_scoped` rather than a bare `begin` + `set_config`: it sets the
        // GUC and READS IT BACK, so a transaction whose scope did not take
        // fails loudly instead of writing under an unarmed policy.
        let mut tx = begin_scoped(&self.pool, workspace_id).await?;

        let before = sqlx::query(
            "SELECT daily_token_limit, monthly_token_limit, behavior
             FROM workspace_budgets
             WHERE workspace_id = $1",
        )
        .bind(workspace_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        // NULL rather than a zero or a default when the workspace had no
        // budget at all: "no limit configured" and "a limit of zero" are
        // different starting points and the record must distinguish them.
        let (before_daily, before_monthly, before_behavior): (Value, Value, Value) =
            before.map_or((Value::Null, Value::Null, Value::Null), |row| {
                (
                    json!(row.get::<Option<i64>, _>("daily_token_limit")),
                    json!(row.get::<Option<i64>, _>("monthly_token_limit")),
                    json!(row.get::<String, _>("behavior")),
                )
            });

        let row = sqlx::query(
            "INSERT INTO workspace_budgets
                 (workspace_id, daily_token_limit, monthly_token_limit, behavior, updated_at)
             VALUES ($1, $2, $3, $4, NOW())
             ON CONFLICT (workspace_id) DO UPDATE
                 SET daily_token_limit  = EXCLUDED.daily_token_limit,
                     monthly_token_limit = EXCLUDED.monthly_token_limit,
                     behavior            = EXCLUDED.behavior,
                     updated_at          = NOW()
             RETURNING workspace_id, daily_token_limit, monthly_token_limit, behavior, updated_at",
        )
        .bind(workspace_id)
        .bind(daily)
        .bind(monthly)
        .bind(behavior.as_db_str())
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        let mut changed = serde_json::Map::new();
        changed_field(
            &mut changed,
            "daily_token_limit",
            &before_daily,
            &json!(daily),
        );
        changed_field(
            &mut changed,
            "monthly_token_limit",
            &before_monthly,
            &json!(monthly),
        );
        changed_field(
            &mut changed,
            "behavior",
            &before_behavior,
            &json!(behavior.as_db_str()),
        );
        if !changed.is_empty() {
            admin_audit_repo::write(
                &mut tx,
                actor,
                &AdminAuditEntry::on_object(AdminAuditAction::BudgetUpdated, workspace_id, None)
                    .with_detail(json!({ "changed": Value::Object(changed) })),
            )
            .await?;
        }

        tx.commit()
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?;

        let behavior_str: String = row.get("behavior");
        Ok(WorkspaceBudgetRow {
            workspace_id: row.get("workspace_id"),
            daily_token_limit: row.get("daily_token_limit"),
            monthly_token_limit: row.get("monthly_token_limit"),
            behavior: BudgetBehavior::from_db_str(&behavior_str)?,
            updated_at: row.get("updated_at"),
        })
    }
}
