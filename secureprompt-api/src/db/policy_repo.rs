use chrono::{DateTime, Utc};
use secureprompt_common::{errors::ApiError, types::WorkspaceId};
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct PolicyRuleRow {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub name: String,
    pub priority: i32,
    pub conditions: serde_json::Value,
    pub action: String,
    pub action_params: serde_json::Value,
    pub enabled: bool,
    pub dry_run: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct PolicyRepository {
    pub pool: PgPool,
}

impl PolicyRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn list_rules(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<PolicyRuleRow>, ApiError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|error| ApiError::Database(error.to_string()))?;

        // Equivalent to `SET LOCAL app.current_workspace_id = $1`, but parameter-safe.
        sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
            .bind(workspace_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|error| ApiError::Database(error.to_string()))?;

        let rows = sqlx::query(
            "SELECT id, workspace_id, name, priority, conditions, action, action_params,
                    enabled, dry_run, created_at, updated_at
             FROM policy_rules
             ORDER BY priority ASC, id ASC",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(|error| ApiError::Database(error.to_string()))?;

        tx.commit()
            .await
            .map_err(|error| ApiError::Database(error.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|record| PolicyRuleRow {
                id: record.get("id"),
                workspace_id: record.get("workspace_id"),
                name: record.get("name"),
                priority: record.get("priority"),
                conditions: record.get("conditions"),
                action: record.get("action"),
                action_params: record.get("action_params"),
                enabled: record.get("enabled"),
                dry_run: record.get("dry_run"),
                created_at: record.get("created_at"),
                updated_at: record.get("updated_at"),
            })
            .collect())
    }
}
