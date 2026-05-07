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

    /// Create a new provider with an encrypted credential.
    ///
    /// `encrypted_credential` is `Some(base64url(nonce||ct))` when the caller
    /// supplied a plaintext credential, `None` otherwise.
    ///
    /// # Errors
    /// Returns `ApiError::Database` on SQL failure.
    pub async fn create_provider(
        &self,
        workspace_id: WorkspaceId,
        name: &str,
        provider_type: &str,
        encrypted_credential: Option<String>,
    ) -> Result<ProviderRow, ApiError> {
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
            "INSERT INTO providers (id, workspace_id, name, provider_type, encrypted_credential, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
             RETURNING id, workspace_id, name, provider_type, encrypted_credential, created_at, updated_at",
        )
        .bind(Uuid::new_v4())
        .bind(workspace_id.0)
        .bind(name)
        .bind(provider_type)
        .bind(encrypted_credential.as_deref())
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?;

        Ok(ProviderRow {
            id: row.get("id"),
            workspace_id: row.get("workspace_id"),
            name: row.get("name"),
            provider_type: row.get("provider_type"),
            encrypted_credential: row.get("encrypted_credential"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }

    /// Update a provider's name/type/credential. Passing `None` for
    /// `encrypted_credential` leaves the stored credential unchanged; passing
    /// `Some(None)` clears it.
    ///
    /// # Errors
    /// Returns `ApiError::NotFound` when the provider does not exist in this
    /// workspace. Returns `ApiError::Database` on SQL failure.
    pub async fn update_provider(
        &self,
        workspace_id: WorkspaceId,
        provider_id: Uuid,
        name: Option<&str>,
        provider_type: Option<&str>,
        encrypted_credential: Option<Option<String>>,
    ) -> Result<ProviderRow, ApiError> {
        // Build the SET clause dynamically based on which fields were provided.
        let mut sets: Vec<String> = vec!["updated_at = NOW()".to_owned()];
        if name.is_some() {
            sets.push("name = $3".to_owned());
        }
        if provider_type.is_some() {
            sets.push(format!("provider_type = ${}", sets.len() + 2));
        }
        if encrypted_credential.is_some() {
            sets.push(format!("encrypted_credential = ${}", sets.len() + 2));
        }

        // Simpler approach: full-replace with explicit params.
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

        // Fetch current to fill unset fields.
        let current = sqlx::query(
            "SELECT id, workspace_id, name, provider_type, encrypted_credential, created_at, updated_at
             FROM providers WHERE id = $1 AND workspace_id = $2",
        )
        .bind(provider_id)
        .bind(workspace_id.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?
        .ok_or_else(|| ApiError::NotFound(format!("provider {provider_id} not found")))?;

        let new_name: String = name.map(String::from).unwrap_or_else(|| current.get("name"));
        let new_type: String = provider_type.map(String::from).unwrap_or_else(|| current.get("provider_type"));
        let new_cred: Option<String> = match encrypted_credential {
            Some(v) => v,
            None => current.get("encrypted_credential"),
        };

        let _ = sets; // suppress the unused warning from the dynamic builder above

        let row = sqlx::query(
            "UPDATE providers
             SET name = $3, provider_type = $4, encrypted_credential = $5, updated_at = NOW()
             WHERE id = $1 AND workspace_id = $2
             RETURNING id, workspace_id, name, provider_type, encrypted_credential, created_at, updated_at",
        )
        .bind(provider_id)
        .bind(workspace_id.0)
        .bind(&new_name)
        .bind(&new_type)
        .bind(new_cred.as_deref())
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?;

        Ok(ProviderRow {
            id: row.get("id"),
            workspace_id: row.get("workspace_id"),
            name: row.get("name"),
            provider_type: row.get("provider_type"),
            encrypted_credential: row.get("encrypted_credential"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }

    /// Delete a provider by ID within the workspace.
    ///
    /// # Errors
    /// Returns `ApiError::NotFound` when the provider does not exist.
    /// Returns `ApiError::Database` on SQL failure.
    pub async fn delete_provider(
        &self,
        workspace_id: WorkspaceId,
        provider_id: Uuid,
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
            "DELETE FROM providers WHERE id = $1 AND workspace_id = $2",
        )
        .bind(provider_id)
        .bind(workspace_id.0)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(ApiError::NotFound(format!(
                "provider {provider_id} not found"
            )));
        }
        Ok(())
    }

    /// List all model rows registered for a single provider in this workspace.
    /// Used by the dashboard's per-provider model panel and by the
    /// `/v1/providers` list response (nested `models` array) so LibreChat's
    /// discovery client gets the authoritative model list per provider.
    pub async fn list_models_for_provider(
        &self,
        workspace_id: WorkspaceId,
        provider_id: Uuid,
    ) -> Result<Vec<ModelRow>, ApiError> {
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
            "SELECT id, workspace_id, provider_id, name, created_at
             FROM models
             WHERE provider_id = $1
             ORDER BY name ASC",
        )
        .bind(provider_id)
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

    /// Register a model name against a provider. Idempotent — duplicate
    /// (provider_id, name) inserts return the existing row instead of
    /// failing, so the UI doesn't need to track race conditions.
    pub async fn create_model(
        &self,
        workspace_id: WorkspaceId,
        provider_id: Uuid,
        name: &str,
    ) -> Result<ModelRow, ApiError> {
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

        // Validate provider belongs to this workspace.
        let provider_row = sqlx::query(
            "SELECT 1 FROM providers WHERE id = $1 AND workspace_id = $2",
        )
        .bind(provider_id)
        .bind(workspace_id.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;
        if provider_row.is_none() {
            return Err(ApiError::NotFound(format!(
                "provider {provider_id} not found in workspace"
            )));
        }

        // Try insert; if (workspace_id, provider_id, name) already exists,
        // return the existing row.
        let existing = sqlx::query(
            "SELECT id, workspace_id, provider_id, name, created_at
             FROM models
             WHERE workspace_id = $1 AND provider_id = $2 AND name = $3",
        )
        .bind(workspace_id.0)
        .bind(provider_id)
        .bind(name)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;
        if let Some(row) = existing {
            tx.commit().await.map_err(|e| ApiError::Database(e.to_string()))?;
            return Ok(ModelRow {
                id: row.get("id"),
                workspace_id: row.get("workspace_id"),
                provider_id: row.get("provider_id"),
                name: row.get("name"),
                created_at: row.get("created_at"),
            });
        }

        let row = sqlx::query(
            "INSERT INTO models (id, workspace_id, provider_id, name, created_at)
             VALUES ($1, $2, $3, $4, NOW())
             RETURNING id, workspace_id, provider_id, name, created_at",
        )
        .bind(Uuid::new_v4())
        .bind(workspace_id.0)
        .bind(provider_id)
        .bind(name)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        tx.commit().await.map_err(|e| ApiError::Database(e.to_string()))?;

        Ok(ModelRow {
            id: row.get("id"),
            workspace_id: row.get("workspace_id"),
            provider_id: row.get("provider_id"),
            name: row.get("name"),
            created_at: row.get("created_at"),
        })
    }

    /// Remove a registered model by `(provider_id, name)`. Returns
    /// `NotFound` if no row matched (idempotency: subsequent calls don't
    /// error after the row is gone, only the first miss does).
    pub async fn delete_model(
        &self,
        workspace_id: WorkspaceId,
        provider_id: Uuid,
        name: &str,
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
            "DELETE FROM models
             WHERE workspace_id = $1 AND provider_id = $2 AND name = $3",
        )
        .bind(workspace_id.0)
        .bind(provider_id)
        .bind(name)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        tx.commit().await.map_err(|e| ApiError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(ApiError::NotFound(format!(
                "model {name} not found for provider {provider_id}"
            )));
        }
        Ok(())
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
             WHERE models.workspace_id = $1::uuid
               AND models.name = $2
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
