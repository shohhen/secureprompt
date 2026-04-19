use chrono::{DateTime, Utc};
use rand::{distributions::Alphanumeric, Rng};
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

    /// Create a new API key for the workspace.
    ///
    /// Returns `(ApiKeyRow, plaintext)` — the plaintext is shown to the user
    /// exactly once (POST response) and never stored. The caller must put it
    /// in `CreateKeyResponse` and never log it.
    ///
    /// # Errors
    /// Returns `ApiError::Database` on any SQL failure.
    pub async fn create(
        &self,
        workspace_id: WorkspaceId,
        name: &str,
    ) -> Result<(ApiKeyRow, String), ApiError> {
        // Generate: "sp_" + 48 random alphanumeric chars = 51 chars total.
        let suffix: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(48)
            .map(char::from)
            .collect();
        let plaintext = format!("sp_{suffix}");
        let key_hash = hash_api_key(&plaintext);

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
            "INSERT INTO api_keys (id, workspace_id, name, key_hash, created_at)
             VALUES ($1, $2, $3, $4, NOW())
             RETURNING id, workspace_id, name, key_hash, created_at, revoked_at",
        )
        .bind(Uuid::new_v4())
        .bind(workspace_id.0)
        .bind(name)
        .bind(&key_hash)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?;

        let record = ApiKeyRow {
            id: row.get("id"),
            workspace_id: row.get("workspace_id"),
            name: row.get("name"),
            key_hash: row.get("key_hash"),
            created_at: row.get("created_at"),
            revoked_at: row.get("revoked_at"),
        };
        Ok((record, plaintext))
    }

    /// Revoke an API key by setting `revoked_at = NOW()`.
    ///
    /// # Errors
    /// Returns `ApiError::NotFound` when the key does not exist in this
    /// workspace. Returns `ApiError::Database` on any SQL failure.
    pub async fn revoke(
        &self,
        workspace_id: WorkspaceId,
        key_id: Uuid,
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
            "UPDATE api_keys SET revoked_at = NOW()
             WHERE id = $1 AND workspace_id = $2 AND revoked_at IS NULL",
        )
        .bind(key_id)
        .bind(workspace_id.0)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(ApiError::NotFound(format!("api key {key_id} not found")));
        }
        Ok(())
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
                   AND key_hash = $1
                 ORDER BY created_at DESC
                 LIMIT 1",
            )
            .bind(&presented_hash)
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
