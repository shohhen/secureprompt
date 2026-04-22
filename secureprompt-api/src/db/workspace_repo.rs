//! Workspace + owner-user creation in a single Postgres transaction.
//!
//! Used by `POST /v1/auth/register` to guarantee that a duplicate-email
//! failure on the users insert rolls back the workspace insert — no
//! orphaned workspace rows.

use chrono::{DateTime, Utc};
use secureprompt_common::{errors::ApiError, types::WorkspaceId};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::db::user_repo::UserRow;

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

    /// Insert a workspace and an owner user in a single transaction.
    ///
    /// * `password_hash` must already be Argon2id-encoded
    ///   (see `crate::db::user_repo::hash_password`).
    /// * On unique-email collision, returns `ApiError::Conflict` and the
    ///   transaction rolls back — no workspace row is left behind.
    ///
    /// # Errors
    /// `ApiError::Conflict` on duplicate email; `ApiError::Database` on any
    /// other sqlx failure.
    pub async fn create_with_owner(
        &self,
        workspace_name: &str,
        email: &str,
        password_hash: &str,
    ) -> Result<(WorkspaceRow, UserRow), ApiError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?;

        let ws_row = sqlx::query(
            "INSERT INTO workspaces (id, name, created_at, updated_at)
             VALUES (gen_random_uuid(), $1, NOW(), NOW())
             RETURNING id, name, created_at, updated_at",
        )
        .bind(workspace_name)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        let ws = WorkspaceRow {
            id: ws_row.get("id"),
            name: ws_row.get("name"),
            created_at: ws_row.get("created_at"),
            updated_at: ws_row.get("updated_at"),
        };

        let user_row = sqlx::query(
            "INSERT INTO users (id, workspace_id, email, password_hash, role, created_at, updated_at)
             VALUES (gen_random_uuid(), $1, $2, $3, 'owner', NOW(), NOW())
             RETURNING id, workspace_id, email, password_hash, created_at, updated_at",
        )
        .bind(ws.id)
        .bind(email)
        .bind(password_hash)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("unique") || msg.contains("duplicate") {
                ApiError::Conflict("email already in use".into())
            } else {
                ApiError::Database(msg)
            }
        })?;

        // If we got this far, both INSERTs succeeded — commit.
        tx.commit()
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?;

        let user = UserRow {
            id: user_row.get("id"),
            workspace_id: user_row.get("workspace_id"),
            email: user_row.get("email"),
            password_hash: user_row.get("password_hash"),
            created_at: user_row.get("created_at"),
            updated_at: user_row.get("updated_at"),
        };

        Ok((ws, user))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::user_repo::hash_password;

    #[sqlx::test]
    async fn creates_workspace_and_owner_user(pool: PgPool) {
        let repo = WorkspaceRepository::new(pool.clone());
        let hash = hash_password("pw-for-test-only").unwrap();

        let (ws, user) = repo
            .create_with_owner("Acme Inc", "owner@example.com", &hash)
            .await
            .expect("transaction must succeed");

        assert_eq!(ws.name, "Acme Inc");
        assert_eq!(user.email, "owner@example.com");
        assert_eq!(user.workspace_id, ws.id);

        let role: String = sqlx::query_scalar("SELECT role FROM users WHERE id = $1")
            .bind(user.id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(role, "owner");
    }

    #[sqlx::test]
    async fn rolls_back_workspace_when_email_already_exists(pool: PgPool) {
        let repo = WorkspaceRepository::new(pool.clone());
        let hash = hash_password("pw").unwrap();

        // First insert — succeeds.
        repo.create_with_owner("First Workspace", "dup@example.com", &hash)
            .await
            .expect("first insert");

        let ws_count_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM workspaces")
            .fetch_one(&pool)
            .await
            .unwrap();

        // Second insert with same email — must conflict.
        let err = repo
            .create_with_owner("Second Workspace", "dup@example.com", &hash)
            .await
            .expect_err("second insert must fail");

        match err {
            ApiError::Conflict(_) => {}
            other => panic!("expected Conflict, got {other:?}"),
        }

        // Workspace count must be unchanged — no orphan from the failed tx.
        let ws_count_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM workspaces")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(ws_count_after, ws_count_before);
    }
}
