use chrono::{DateTime, Utc};
use secureprompt_common::{
    errors::ApiError,
    types::{ProviderId, WorkspaceId},
};
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

#[derive(Debug, Clone)]
pub struct ResolvedModelTarget {
    pub model_id: Uuid,
    pub workspace_id: WorkspaceId,
    pub provider_id: ProviderId,
    pub provider_name: String,
    pub provider_type: String,
    pub model_name: String,
    pub encrypted_credential: Option<String>,
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

    pub async fn resolve_model_targets(
        &self,
        workspace_id: WorkspaceId,
        model_name: &str,
    ) -> Result<Vec<ResolvedModelTarget>, ApiError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|error| ApiError::Database(error.to_string()))?;

        sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
            .bind(workspace_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|error| ApiError::Database(error.to_string()))?;

        let rows = sqlx::query(
            "SELECT models.id AS model_id,
                    models.workspace_id,
                    models.name AS model_name,
                    providers.id AS provider_id,
                    providers.name AS provider_name,
                    providers.provider_type,
                    providers.encrypted_credential
             FROM models
             INNER JOIN providers ON providers.id = models.provider_id
             WHERE models.name = $2
             ORDER BY models.created_at ASC, providers.created_at ASC",
        )
        .bind(workspace_id.to_string())
        .bind(model_name)
        .fetch_all(&mut *tx)
        .await
        .map_err(|error| ApiError::Database(error.to_string()))?;

        tx.commit()
            .await
            .map_err(|error| ApiError::Database(error.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|record| ResolvedModelTarget {
                model_id: record.get("model_id"),
                workspace_id: WorkspaceId(record.get("workspace_id")),
                provider_id: ProviderId(record.get("provider_id")),
                provider_name: record.get("provider_name"),
                provider_type: record.get("provider_type"),
                model_name: record.get("model_name"),
                encrypted_credential: record.get("encrypted_credential"),
            })
            .collect())
    }
}
