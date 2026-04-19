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
use sqlx::{PgPool, Row};
use uuid::Uuid;

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

    /// Upsert the budget configuration for `workspace_id`.
    ///
    /// On conflict (duplicate `workspace_id`), replaces the existing row.
    ///
    /// # Errors
    /// Returns `ApiError::BadRequest` when a limit value is negative.
    /// Returns `ApiError::Database` on SQL failure.
    pub async fn upsert(
        &self,
        workspace_id: Uuid,
        daily: Option<i64>,
        monthly: Option<i64>,
        behavior: BudgetBehavior,
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
