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

    /// Revoke an API key by setting `revoked_at = NOW()` and `status = 'revoked'`.
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
            "UPDATE api_keys SET revoked_at = NOW(), status = 'revoked'
             WHERE id = $1 AND workspace_id = $2 AND status IN ('active', 'rotating')",
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

    /// Rotate an API key (Phase 6 / Plan 06-01, AUTH-08, D-17, D-18).
    ///
    /// - If key is `'active'`: generates a new key, marks old as `'rotating'`,
    ///   stores `successor_key_hash` + `successor_key_prefix` on the old row.
    /// - If key is `'rotating'` (already in progress): idempotent — returns
    ///   `(successor_key_prefix + "...", grace_expires_at)` without issuing
    ///   a new key (D-18).
    ///
    /// Returns `(new_plaintext, grace_expires_at)`.
    ///
    /// # Errors
    /// Returns `ApiError::NotFound` if the key does not exist or is already revoked.
    /// Returns `ApiError::Database` on SQL failures.
    pub async fn rotate(
        &self,
        workspace_id: WorkspaceId,
        key_id: Uuid,
    ) -> Result<(String, chrono::DateTime<chrono::Utc>), ApiError> {
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

        // Fetch the key — only active or rotating keys can be rotated.
        let row = sqlx::query(
            "SELECT id, status, rotated_at, rotation_grace_secs, successor_key_prefix
             FROM api_keys
             WHERE id = $1 AND workspace_id = $2 AND status IN ('active', 'rotating')
             FOR UPDATE",
        )
        .bind(key_id)
        .bind(workspace_id.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        let row = row.ok_or_else(|| {
            ApiError::NotFound(format!("api key {key_id} not found or already revoked"))
        })?;

        let status: String = row.get("status");
        let rotation_grace_secs: i32 = row.get("rotation_grace_secs");

        if status == "rotating" {
            // Idempotent: rotation already in progress — return existing successor info (D-18).
            let rotated_at: DateTime<Utc> = row.get("rotated_at");
            let grace_expires_at = rotated_at
                + chrono::Duration::seconds(i64::from(rotation_grace_secs));
            let successor_prefix: Option<String> = row.get("successor_key_prefix");
            // Return prefix + "..." so caller can confirm which key was issued without
            // exposing the full secret.
            let display_key = format!("{}...", successor_prefix.unwrap_or_default());
            tx.commit()
                .await
                .map_err(|e| ApiError::Database(e.to_string()))?;
            return Ok((display_key, grace_expires_at));
        }

        // status == "active" — generate new key and mark old as rotating.
        let suffix: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(48)
            .map(char::from)
            .collect();
        let new_plaintext = format!("sp_{suffix}");
        let new_hash = hash_api_key(&new_plaintext);
        let new_prefix: String = new_plaintext.chars().take(12).collect();

        // INSERT the new key record with status = 'active'.
        sqlx::query(
            "INSERT INTO api_keys (id, workspace_id, name, key_hash, created_at, status)
             SELECT $1, workspace_id, name || ' (rotated)', $2, NOW(), 'active'
             FROM api_keys WHERE id = $3",
        )
        .bind(Uuid::new_v4())
        .bind(&new_hash)
        .bind(key_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        // UPDATE the old key to 'rotating' with successor metadata.
        let rotated_row = sqlx::query(
            "UPDATE api_keys
             SET status = 'rotating',
                 rotated_at = NOW(),
                 successor_key_hash = $1,
                 successor_key_prefix = $2
             WHERE id = $3
             RETURNING rotated_at, rotation_grace_secs",
        )
        .bind(&new_hash)
        .bind(&new_prefix)
        .bind(key_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        let rotated_at: DateTime<Utc> = rotated_row.get("rotated_at");
        let grace_secs: i32 = rotated_row.get("rotation_grace_secs");
        let grace_expires_at = rotated_at + chrono::Duration::seconds(i64::from(grace_secs));

        tx.commit()
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?;

        Ok((new_plaintext, grace_expires_at))
    }

    /// Authenticate using a presented API key, accepting keys within their
    /// grace window (Phase 6 / Plan 06-01, AUTH-08).
    ///
    /// PITFALL 8: filters on `status IN ('active', 'rotating')` with grace
    /// check, NOT `revoked_at IS NULL`. Rotating keys in their grace window
    /// are still valid for authentication.
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

            // Accept: status = 'active'
            // Accept: status = 'rotating' AND within grace window
            // Reject: status = 'revoked' (even if revoked_at IS NULL from pre-migration data)
            let row = sqlx::query(
                "SELECT id, workspace_id, name
                 FROM api_keys
                 WHERE key_hash = $1
                   AND (
                     status = 'active'
                     OR (
                       status = 'rotating'
                       AND rotated_at + (rotation_grace_secs || ' seconds')::INTERVAL > NOW()
                     )
                   )
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
