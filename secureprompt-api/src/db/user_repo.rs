use chrono::{DateTime, Utc};
use secureprompt_common::{errors::ApiError, types::WorkspaceId};
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct UserRow {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct UserRepository {
    pub pool: PgPool,
}

impl UserRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn find_by_email(&self, email: &str) -> Result<Option<UserRow>, ApiError> {
        let row = sqlx::query(
            "SELECT id, workspace_id, email, password_hash, created_at, updated_at
             FROM users
             WHERE email = $1",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| ApiError::Database(error.to_string()))?;

        Ok(row.map(|record| UserRow {
            id: record.get("id"),
            workspace_id: record.get("workspace_id"),
            email: record.get("email"),
            password_hash: record.get("password_hash"),
            created_at: record.get("created_at"),
            updated_at: record.get("updated_at"),
        }))
    }

    pub async fn list_workspace_users(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<UserRow>, ApiError> {
        let rows = sqlx::query(
            "SELECT id, workspace_id, email, password_hash, created_at, updated_at
             FROM users
             WHERE workspace_id = $1
             ORDER BY created_at DESC",
        )
        .bind(workspace_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| ApiError::Database(error.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|record| UserRow {
                id: record.get("id"),
                workspace_id: record.get("workspace_id"),
                email: record.get("email"),
                password_hash: record.get("password_hash"),
                created_at: record.get("created_at"),
                updated_at: record.get("updated_at"),
            })
            .collect())
    }
}
