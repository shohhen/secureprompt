use chrono::{DateTime, Utc};
use secureprompt_common::{errors::ApiError, types::WorkspaceId};
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ProviderRow {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub name: String,
    pub provider_type: String,
    pub encrypted_credential: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct ModelRow {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub provider_id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

pub struct ProviderRepository {
    pub pool: PgPool,
}

impl ProviderRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn list_providers(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<ProviderRow>, ApiError> {
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
            "SELECT id, workspace_id, name, provider_type, encrypted_credential, created_at, updated_at
             FROM providers
             ORDER BY created_at DESC",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(|error| ApiError::Database(error.to_string()))?;

        tx.commit()
            .await
            .map_err(|error| ApiError::Database(error.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|record| ProviderRow {
                id: record.get("id"),
                workspace_id: record.get("workspace_id"),
                name: record.get("name"),
                provider_type: record.get("provider_type"),
                encrypted_credential: record.get("encrypted_credential"),
                created_at: record.get("created_at"),
                updated_at: record.get("updated_at"),
            })
            .collect())
    }

    pub async fn list_models(&self, workspace_id: WorkspaceId) -> Result<Vec<ModelRow>, ApiError> {
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
            "SELECT id, workspace_id, provider_id, name, created_at
             FROM models
             ORDER BY created_at DESC",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(|error| ApiError::Database(error.to_string()))?;

        tx.commit()
            .await
            .map_err(|error| ApiError::Database(error.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|record| ModelRow {
                id: record.get("id"),
                workspace_id: record.get("workspace_id"),
                provider_id: record.get("provider_id"),
                name: record.get("name"),
                created_at: record.get("created_at"),
            })
            .collect())
    }
}
