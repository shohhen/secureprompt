use chrono::{DateTime, Utc};
use secureprompt_common::{errors::ApiError, types::WorkspaceId};
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct WorkspaceRow {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct WorkspaceRepository {
    pub pool: PgPool,
}

impl WorkspaceRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn find_by_id(&self, id: WorkspaceId) -> Result<Option<WorkspaceRow>, ApiError> {
        let row =
            sqlx::query("SELECT id, name, created_at, updated_at FROM workspaces WHERE id = $1")
                .bind(id.0)
                .fetch_optional(&self.pool)
                .await
                .map_err(|error| ApiError::Database(error.to_string()))?;

        Ok(row.map(|record| WorkspaceRow {
            id: record.get("id"),
            name: record.get("name"),
            created_at: record.get("created_at"),
            updated_at: record.get("updated_at"),
        }))
    }

    pub async fn list_workspace_ids(&self) -> Result<Vec<WorkspaceId>, ApiError> {
        let rows = sqlx::query("SELECT id FROM workspaces ORDER BY created_at ASC")
            .fetch_all(&self.pool)
            .await
            .map_err(|error| ApiError::Database(error.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|record| WorkspaceId(record.get("id")))
            .collect())
    }
}
