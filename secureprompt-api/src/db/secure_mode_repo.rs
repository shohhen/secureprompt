use chrono::{DateTime, Utc};
use secureprompt_common::{errors::ApiError, types::WorkspaceId};
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct SecureModeRow {
    pub workspace_id: Uuid,
    pub enabled: bool,
    pub level: String,
    pub block_on_pii_detection: bool,
    pub block_on_injection_detection: bool,
    pub redact_pii_in_responses: bool,
    pub updated_at: DateTime<Utc>,
}

impl Default for SecureModeRow {
    fn default() -> Self {
        Self {
            workspace_id: Uuid::nil(),
            enabled: false,
            level: "standard".to_owned(),
            block_on_pii_detection: false,
            block_on_injection_detection: false,
            redact_pii_in_responses: false,
            updated_at: Utc::now(),
        }
    }
}

pub struct SecureModeRepository {
    pool: PgPool,
}

impl SecureModeRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Returns the current config, or defaults when no row exists yet.
    pub async fn get(&self, workspace_id: WorkspaceId) -> Result<SecureModeRow, ApiError> {
        let row = sqlx::query(
            "SELECT workspace_id, enabled, level,
                    block_on_pii_detection, block_on_injection_detection,
                    redact_pii_in_responses, updated_at
             FROM workspace_secure_mode
             WHERE workspace_id = $1",
        )
        .bind(workspace_id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        Ok(row.map_or_else(
            || SecureModeRow {
                workspace_id: workspace_id.0,
                ..SecureModeRow::default()
            },
            |r| SecureModeRow {
                workspace_id: r.get("workspace_id"),
                enabled: r.get("enabled"),
                level: r.get("level"),
                block_on_pii_detection: r.get("block_on_pii_detection"),
                block_on_injection_detection: r.get("block_on_injection_detection"),
                redact_pii_in_responses: r.get("redact_pii_in_responses"),
                updated_at: r.get("updated_at"),
            },
        ))
    }

    /// Upsert the config for the workspace.
    pub async fn upsert(
        &self,
        workspace_id: WorkspaceId,
        enabled: Option<bool>,
        level: Option<&str>,
        block_on_pii_detection: Option<bool>,
        block_on_injection_detection: Option<bool>,
        redact_pii_in_responses: Option<bool>,
    ) -> Result<SecureModeRow, ApiError> {
        // Read current values so unset fields keep their existing values.
        let current = self.get(workspace_id).await?;

        let new_enabled = enabled.unwrap_or(current.enabled);
        let new_level = level.unwrap_or(&current.level).to_owned();
        let new_block_pii = block_on_pii_detection.unwrap_or(current.block_on_pii_detection);
        let new_block_inj = block_on_injection_detection.unwrap_or(current.block_on_injection_detection);
        let new_redact = redact_pii_in_responses.unwrap_or(current.redact_pii_in_responses);

        let row = sqlx::query(
            "INSERT INTO workspace_secure_mode
                (workspace_id, enabled, level,
                 block_on_pii_detection, block_on_injection_detection,
                 redact_pii_in_responses, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, NOW())
             ON CONFLICT (workspace_id) DO UPDATE SET
                enabled                     = EXCLUDED.enabled,
                level                       = EXCLUDED.level,
                block_on_pii_detection      = EXCLUDED.block_on_pii_detection,
                block_on_injection_detection = EXCLUDED.block_on_injection_detection,
                redact_pii_in_responses     = EXCLUDED.redact_pii_in_responses,
                updated_at                  = NOW()
             RETURNING workspace_id, enabled, level,
                       block_on_pii_detection, block_on_injection_detection,
                       redact_pii_in_responses, updated_at",
        )
        .bind(workspace_id.0)
        .bind(new_enabled)
        .bind(&new_level)
        .bind(new_block_pii)
        .bind(new_block_inj)
        .bind(new_redact)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        Ok(SecureModeRow {
            workspace_id: row.get("workspace_id"),
            enabled: row.get("enabled"),
            level: row.get("level"),
            block_on_pii_detection: row.get("block_on_pii_detection"),
            block_on_injection_detection: row.get("block_on_injection_detection"),
            redact_pii_in_responses: row.get("redact_pii_in_responses"),
            updated_at: row.get("updated_at"),
        })
    }
}
