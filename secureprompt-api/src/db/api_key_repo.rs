use chrono::{DateTime, Utc};
use rand::{distributions::Alphanumeric, Rng};
use secureprompt_common::{errors::ApiError, kms::KmsBackend, types::WorkspaceId};
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
    /// Set when an admin assigned this key to a specific workspace member.
    /// `None` for legacy/unassigned workspace-scoped keys.
    pub assigned_user_id: Option<Uuid>,
}

pub struct ApiKeyRepository {
    pub pool: PgPool,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedApiKey {
    pub id: Uuid,
    pub workspace_id: WorkspaceId,
    pub name: String,
    /// `assigned_user_id` from the api_keys row — `Some(...)` when an admin
    /// minted this key for a specific workspace member, `None` for legacy
    /// workspace-scoped keys. The audit detail page uses this to attribute
    /// the request to a user.
    pub assigned_user_id: Option<Uuid>,
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

        // Explicit tenant filter. RLS on api_keys is a defence-in-depth second
        // layer only — the runtime connects as a Postgres SUPERUSER, which
        // bypasses RLS unconditionally (FORCE ROW LEVEL SECURITY does not stop a
        // superuser), so this WHERE is the actual isolation boundary. Do not
        // remove it in reliance on the set_config above.
        let rows = sqlx::query(
            "SELECT id, workspace_id, name, key_hash, created_at, revoked_at, assigned_user_id
             FROM api_keys
             WHERE workspace_id = $1
             ORDER BY created_at DESC",
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
            .map(|record| ApiKeyRow {
                id: record.get("id"),
                workspace_id: record.get("workspace_id"),
                name: record.get("name"),
                key_hash: record.get("key_hash"),
                created_at: record.get("created_at"),
                revoked_at: record.get("revoked_at"),
                assigned_user_id: record.get("assigned_user_id"),
            })
            .collect())
    }

    /// Retrieve the plaintext API key for the workspace member whose JWT
    /// is presented (called by `GET /v1/me/api-key` from the LibreChat
    /// backend). The plaintext is decrypted on the fly from
    /// `key_ciphertext` using the configured provider key.
    ///
    /// Returns the most recent ACTIVE key assigned to `user_id` in this
    /// workspace. Returns `None` if the user has no assigned key
    /// (admin must create one first), or if the assigned key was a
    /// pre-009 record with no encrypted plaintext.
    ///
    /// # Errors
    /// Returns `ApiError::Database` on SQL failures and
    /// `ApiError::Internal` if the stored ciphertext fails to decrypt
    /// (indicates a misconfigured provider key or DB tampering).
    pub async fn fetch_plaintext_for_user(
        &self,
        workspace_id: WorkspaceId,
        user_id: Uuid,
        kms: &dyn KmsBackend,
    ) -> Result<Option<String>, ApiError> {
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
            "SELECT key_ciphertext
             FROM api_keys
             WHERE workspace_id = $1
               AND assigned_user_id = $2
               AND status = 'active'
               AND key_ciphertext IS NOT NULL
             ORDER BY created_at DESC
             LIMIT 1",
        )
        .bind(workspace_id.0)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?;

        let Some(record) = row else {
            return Ok(None);
        };

        let stored: String = record.get("key_ciphertext");
        let plaintext_bytes = kms
            .decrypt(stored.as_bytes())
            .await
            .map_err(|e| ApiError::Internal(format!("api key decrypt: {e}")))?;
        let plaintext = String::from_utf8(plaintext_bytes)
            .map_err(|_| ApiError::Internal("api key plaintext is not valid UTF-8".into()))?;
        Ok(Some(plaintext))
    }

    /// Create a new API key for the workspace.
    ///
    /// `assigned_user_id` — when `Some(user_id)`, this key belongs to a
    /// specific workspace member. The plaintext is also encrypted with
    /// `provider_key` and stored in `key_ciphertext` so the LibreChat
    /// backend can later retrieve it server-to-server via the user's
    /// JWT (see `fetch_plaintext_for_user`). When `None`, only `key_hash`
    /// is stored — legacy unassigned workspace-scoped keys.
    ///
    /// Returns `(ApiKeyRow, plaintext)` — the plaintext is shown to the
    /// admin exactly once (POST response) and never stored unencrypted.
    /// The caller must put it in `CreateKeyResponse` and never log it.
    ///
    /// # Errors
    /// Returns `ApiError::Database` on any SQL failure.
    /// Returns `ApiError::Internal` when AES-GCM encryption fails (bad
    /// provider key — should never happen with a 32-byte key).
    pub async fn create(
        &self,
        workspace_id: WorkspaceId,
        name: &str,
        assigned_user_id: Option<Uuid>,
        kms: Option<&dyn KmsBackend>,
    ) -> Result<(ApiKeyRow, String), ApiError> {
        // Generate: "sp_" + 48 random alphanumeric chars = 51 chars total.
        let suffix: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(48)
            .map(char::from)
            .collect();
        let plaintext = format!("sp_{suffix}");
        let key_hash = hash_api_key(&plaintext);

        // When the key is being assigned to a member, encrypt the plaintext
        // via KMS for later server-to-server retrieval. The `kms` arg must
        // be `Some` whenever `assigned_user_id` is `Some` — the handler
        // enforces this; the repo defends with an Internal error.
        let key_ciphertext = match (assigned_user_id, kms) {
            (Some(_), Some(kms)) => {
                let stored = kms
                    .encrypt(plaintext.as_bytes())
                    .await
                    .map_err(|e| ApiError::Internal(format!("api key encrypt: {e}")))?;
                Some(
                    String::from_utf8(stored)
                        .map_err(|_| ApiError::Internal("KMS ciphertext not UTF-8".into()))?,
                )
            }
            (Some(_), None) => {
                return Err(ApiError::Internal(
                    "assigned API key requires kms backend for plaintext encryption".into(),
                ));
            }
            (None, _) => None,
        };

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
            "INSERT INTO api_keys (id, workspace_id, name, key_hash, created_at,
                                   assigned_user_id, key_ciphertext)
             VALUES ($1, $2, $3, $4, NOW(), $5, $6)
             RETURNING id, workspace_id, name, key_hash, created_at, revoked_at,
                       assigned_user_id",
        )
        .bind(Uuid::new_v4())
        .bind(workspace_id.0)
        .bind(name)
        .bind(&key_hash)
        .bind(assigned_user_id)
        .bind(key_ciphertext)
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
            assigned_user_id: row.get("assigned_user_id"),
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
                "SELECT id, workspace_id, name, assigned_user_id
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
                    assigned_user_id: record.get("assigned_user_id"),
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
