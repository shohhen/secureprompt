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

        // Explicit tenant filter — the runtime DB role is a superuser that
        // bypasses RLS, so this WHERE (not the set_config above) is the real
        // isolation boundary. Do not remove.
        let rows = sqlx::query(
            "SELECT id, workspace_id, name, priority, conditions, action, action_params,
                    enabled, dry_run, created_at, updated_at
             FROM policy_rules
             WHERE workspace_id = $1
             ORDER BY priority ASC, id ASC",
        )
        .bind(workspace_id.0)
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

    /// Fetch a single rule by ID within the workspace.
    ///
    /// # Errors
    /// Returns `ApiError::NotFound` when the rule does not exist.
    pub async fn get_rule(
        &self,
        workspace_id: WorkspaceId,
        rule_id: Uuid,
    ) -> Result<PolicyRuleRow, ApiError> {
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
            "SELECT id, workspace_id, name, priority, conditions, action, action_params,
                    enabled, dry_run, created_at, updated_at
             FROM policy_rules WHERE id = $1 AND workspace_id = $2",
        )
        .bind(rule_id)
        .bind(workspace_id.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?
        .ok_or_else(|| ApiError::NotFound(format!("policy rule {rule_id} not found")))?;

        tx.commit()
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?;

        Ok(PolicyRuleRow {
            id: row.get("id"),
            workspace_id: row.get("workspace_id"),
            name: row.get("name"),
            priority: row.get("priority"),
            conditions: row.get("conditions"),
            action: row.get("action"),
            action_params: row.get("action_params"),
            enabled: row.get("enabled"),
            dry_run: row.get("dry_run"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }

    /// Create a new policy rule.
    ///
    /// `action` must be one of `deny | allow | redact | transform | flag`.
    /// Priority uniqueness is checked by the caller (handler) before calling
    /// this method so the constraint check is separate from the INSERT.
    ///
    /// # Errors
    /// Returns `ApiError::Database` on SQL failure.
    pub async fn create_rule(
        &self,
        workspace_id: WorkspaceId,
        name: &str,
        priority: i32,
        conditions: serde_json::Value,
        action: &str,
        action_params: serde_json::Value,
        enabled: bool,
        dry_run: bool,
    ) -> Result<PolicyRuleRow, ApiError> {
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
            "INSERT INTO policy_rules
                (id, workspace_id, name, priority, conditions, action, action_params, enabled, dry_run, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
             RETURNING id, workspace_id, name, priority, conditions, action, action_params,
                       enabled, dry_run, created_at, updated_at",
        )
        .bind(Uuid::new_v4())
        .bind(workspace_id.0)
        .bind(name)
        .bind(priority)
        .bind(&conditions)
        .bind(action)
        .bind(&action_params)
        .bind(enabled)
        .bind(dry_run)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?;

        Ok(map_rule_row(&row))
    }

    /// Update an existing rule. All fields are replaced.
    ///
    /// Priority uniqueness is checked by the caller before invoking this method.
    ///
    /// # Errors
    /// Returns `ApiError::NotFound` when the rule does not exist.
    /// Returns `ApiError::Database` on SQL failure.
    pub async fn update_rule(
        &self,
        workspace_id: WorkspaceId,
        rule_id: Uuid,
        name: &str,
        priority: i32,
        conditions: serde_json::Value,
        action: &str,
        action_params: serde_json::Value,
        enabled: bool,
        dry_run: bool,
    ) -> Result<PolicyRuleRow, ApiError> {
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
            "UPDATE policy_rules
             SET name=$3, priority=$4, conditions=$5, action=$6, action_params=$7,
                 enabled=$8, dry_run=$9, updated_at=NOW()
             WHERE id=$1 AND workspace_id=$2
             RETURNING id, workspace_id, name, priority, conditions, action, action_params,
                       enabled, dry_run, created_at, updated_at",
        )
        .bind(rule_id)
        .bind(workspace_id.0)
        .bind(name)
        .bind(priority)
        .bind(&conditions)
        .bind(action)
        .bind(&action_params)
        .bind(enabled)
        .bind(dry_run)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?
        .ok_or_else(|| ApiError::NotFound(format!("policy rule {rule_id} not found")))?;

        tx.commit()
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?;

        Ok(map_rule_row(&row))
    }

    /// Delete a rule by ID.
    ///
    /// # Errors
    /// Returns `ApiError::NotFound` when the rule does not exist.
    pub async fn delete_rule(
        &self,
        workspace_id: WorkspaceId,
        rule_id: Uuid,
    ) -> Result<(), ApiError> {
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

        let result = sqlx::query(
            "DELETE FROM policy_rules WHERE id = $1 AND workspace_id = $2",
        )
        .bind(rule_id)
        .bind(workspace_id.0)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(ApiError::NotFound(format!(
                "policy rule {rule_id} not found"
            )));
        }
        Ok(())
    }

    /// Toggle the `enabled` flag on a rule.
    ///
    /// # Errors
    /// Returns `ApiError::NotFound` when the rule does not exist.
    pub async fn set_enabled(
        &self,
        workspace_id: WorkspaceId,
        rule_id: Uuid,
        enabled: bool,
    ) -> Result<PolicyRuleRow, ApiError> {
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
            "UPDATE policy_rules SET enabled=$3, updated_at=NOW()
             WHERE id=$1 AND workspace_id=$2
             RETURNING id, workspace_id, name, priority, conditions, action, action_params,
                       enabled, dry_run, created_at, updated_at",
        )
        .bind(rule_id)
        .bind(workspace_id.0)
        .bind(enabled)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?
        .ok_or_else(|| ApiError::NotFound(format!("policy rule {rule_id} not found")))?;

        tx.commit()
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?;

        Ok(map_rule_row(&row))
    }

    /// Toggle the `dry_run` flag on a rule.
    ///
    /// # Errors
    /// Returns `ApiError::NotFound` when the rule does not exist.
    pub async fn set_dry_run(
        &self,
        workspace_id: WorkspaceId,
        rule_id: Uuid,
        dry_run: bool,
    ) -> Result<PolicyRuleRow, ApiError> {
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
            "UPDATE policy_rules SET dry_run=$3, updated_at=NOW()
             WHERE id=$1 AND workspace_id=$2
             RETURNING id, workspace_id, name, priority, conditions, action, action_params,
                       enabled, dry_run, created_at, updated_at",
        )
        .bind(rule_id)
        .bind(workspace_id.0)
        .bind(dry_run)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?
        .ok_or_else(|| ApiError::NotFound(format!("policy rule {rule_id} not found")))?;

        tx.commit()
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?;

        Ok(map_rule_row(&row))
    }

    /// Check whether a priority is already taken by another rule in the workspace.
    ///
    /// Pass `exclude_id = Some(rule_id)` when updating an existing rule so the
    /// rule itself is excluded from the uniqueness check.
    ///
    /// # Errors
    /// Returns `ApiError::Database` on SQL failure.
    pub async fn priority_in_use(
        &self,
        workspace_id: WorkspaceId,
        priority: i32,
        exclude_id: Option<Uuid>,
    ) -> Result<bool, ApiError> {
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

        let row = if let Some(excl) = exclude_id {
            sqlx::query(
                "SELECT 1 FROM policy_rules
                 WHERE workspace_id = $1 AND priority = $2 AND id != $3
                 LIMIT 1",
            )
            .bind(workspace_id.0)
            .bind(priority)
            .bind(excl)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?
        } else {
            sqlx::query(
                "SELECT 1 FROM policy_rules
                 WHERE workspace_id = $1 AND priority = $2
                 LIMIT 1",
            )
            .bind(workspace_id.0)
            .bind(priority)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?
        };

        tx.commit()
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?;

        Ok(row.is_some())
    }

    pub async fn list_enabled_rules(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<PolicyRuleRow>, ApiError> {
        Ok(self
            .list_rules(workspace_id)
            .await?
            .into_iter()
            .filter(|rule| rule.enabled)
            .collect())
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn map_rule_row(row: &sqlx::postgres::PgRow) -> PolicyRuleRow {
    PolicyRuleRow {
        id: row.get("id"),
        workspace_id: row.get("workspace_id"),
        name: row.get("name"),
        priority: row.get("priority"),
        conditions: row.get("conditions"),
        action: row.get("action"),
        action_params: row.get("action_params"),
        enabled: row.get("enabled"),
        dry_run: row.get("dry_run"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}
