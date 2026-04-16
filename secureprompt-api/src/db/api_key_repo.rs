use chrono::{DateTime, Utc};
use secureprompt_common::{errors::ApiError, types::WorkspaceId};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ApiKeyRow {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub name: String,
    pub key_hash: String,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

pub struct ApiKeyRepository {
    pub pool: PgPool,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedApiKey {
    pub id: Uuid,
    pub workspace_id: WorkspaceId,
    pub name: String,
}

impl ApiKeyRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn list_api_keys(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<ApiKeyRow>, ApiError> {
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
            "SELECT id, workspace_id, name, key_hash, created_at, revoked_at
             FROM api_keys
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
            .map(|record| ApiKeyRow {
                id: record.get("id"),
                workspace_id: record.get("workspace_id"),
                name: record.get("name"),
                key_hash: record.get("key_hash"),
                created_at: record.get("created_at"),
                revoked_at: record.get("revoked_at"),
            })
            .collect())
    }

    pub async fn authenticate_api_key(
        &self,
        presented_key: &str,
    ) -> Result<Option<AuthenticatedApiKey>, ApiError> {
        let workspace_rows = sqlx::query("SELECT id FROM workspaces ORDER BY created_at ASC")
            .fetch_all(&self.pool)
            .await
            .map_err(|error| ApiError::Database(error.to_string()))?;

        let presented_hash = hash_api_key(presented_key);

        for workspace in workspace_rows {
            let workspace_id: Uuid = workspace.get("id");
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

            let row = sqlx::query(
                "SELECT id, workspace_id, name
                 FROM api_keys
                 WHERE revoked_at IS NULL
                   AND (key_hash = $1 OR key_hash = $2)
                 ORDER BY created_at DESC
                 LIMIT 1",
            )
            .bind(&presented_hash)
            .bind(presented_key)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|error| ApiError::Database(error.to_string()))?;

            if let Some(record) = row {
                tx.commit()
                    .await
                    .map_err(|error| ApiError::Database(error.to_string()))?;

                return Ok(Some(AuthenticatedApiKey {
                    id: record.get("id"),
                    workspace_id: WorkspaceId(record.get("workspace_id")),
                    name: record.get("name"),
                }));
            }

            tx.rollback()
                .await
                .map_err(|error| ApiError::Database(error.to_string()))?;
        }

        Ok(None)
    }
}

#[must_use]
pub fn hash_api_key(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}
