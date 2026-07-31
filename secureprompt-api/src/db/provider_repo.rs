use chrono::{DateTime, Utc};
use secureprompt_common::{
    errors::ApiError,
    types::{ProviderId, WorkspaceId},
};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::db::admin_audit_repo::{self, AdminActor, AdminAuditAction, AdminAuditEntry};
use crate::db::scope::begin_scoped;

#[derive(Debug, Clone)]
pub struct ProviderRow {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub name: String,
    pub provider_type: String,
    pub encrypted_credential: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub config: serde_json::Value,
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
    pub config: serde_json::Value,
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
        let mut tx = begin_scoped(&self.pool, workspace_id.0).await?;

        // Explicit tenant filter — the runtime DB role is a superuser that
        // bypasses RLS, so this WHERE (not `begin_scoped` above) is the real
        // isolation boundary. Do not remove.
        let rows = sqlx::query(
            "SELECT id, workspace_id, name, provider_type, encrypted_credential, created_at, updated_at, config
             FROM providers
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
            .map(|record| ProviderRow {
                id: record.get("id"),
                workspace_id: record.get("workspace_id"),
                name: record.get("name"),
                provider_type: record.get("provider_type"),
                encrypted_credential: record.get("encrypted_credential"),
                created_at: record.get("created_at"),
                updated_at: record.get("updated_at"),
                config: record.get("config"),
            })
            .collect())
    }

    /// Create a new provider with an encrypted credential.
    ///
    /// `encrypted_credential` is `Some(base64url(nonce||ct))` when the caller
    /// supplied a plaintext credential, `None` otherwise.
    ///
    /// `config` carries provider-type-specific settings that aren't a single
    /// credential string (e.g. Vertex's `{"region": "...", "project": "..."}`).
    /// Pass `serde_json::json!({})` for provider types that don't need it.
    ///
    /// FU5: writes a `provider_credential.created` audit row in the SAME
    /// transaction. Adding a provider is the act of giving the gateway the
    /// ability to spend money and ship prompts to a third party, and it was
    /// unaudited.
    ///
    /// The credential itself never enters the audit row — not the plaintext,
    /// which this method never sees, and not the ciphertext, which is a
    /// decryptable copy of a live secret. Only WHETHER one was supplied.
    ///
    /// # Errors
    /// Returns `ApiError::Database` on SQL failure.
    pub async fn create_provider(
        &self,
        workspace_id: WorkspaceId,
        name: &str,
        provider_type: &str,
        encrypted_credential: Option<String>,
        config: serde_json::Value,
        actor: &AdminActor,
    ) -> Result<ProviderRow, ApiError> {
        let mut tx = begin_scoped(&self.pool, workspace_id.0).await?;

        let row = sqlx::query(
            "INSERT INTO providers (id, workspace_id, name, provider_type, encrypted_credential, config, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
             RETURNING id, workspace_id, name, provider_type, encrypted_credential, created_at, updated_at, config",
        )
        .bind(Uuid::new_v4())
        .bind(workspace_id.0)
        .bind(name)
        .bind(provider_type)
        .bind(encrypted_credential.as_deref())
        .bind(config)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        let provider_id: Uuid = row.get("id");
        admin_audit_repo::write(
            &mut tx,
            actor,
            &AdminAuditEntry::on_object(
                AdminAuditAction::ProviderCredentialCreated,
                provider_id,
                Some(name.to_owned()),
            )
            .with_detail(serde_json::json!({
                "provider_type": provider_type,
                "credential_present": encrypted_credential.is_some(),
            })),
        )
        .await?;

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
            config: row.get("config"),
        })
    }

    /// Update a provider's name/type/credential/config. Passing `None` for
    /// `encrypted_credential` leaves the stored credential unchanged; passing
    /// `Some(None)` clears it. Passing `None` for `config` leaves the stored
    /// config unchanged; passing `Some(value)` replaces it wholesale.
    ///
    /// FU5: writes a `provider_credential.updated` audit row in the same
    /// transaction, carrying a DIFF rather than the word "updated".
    ///
    /// The diff names only the fields that actually moved, and only the
    /// non-secret ones by value. A credential change is reported as the boolean
    /// `credential_replaced`: comparing ciphertexts would be meaningless anyway
    /// (AES-GCM re-encrypts the same plaintext to different bytes each time),
    /// and the security-relevant fact is that the credential was replaced, not
    /// what it was replaced with.
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
        config: Option<serde_json::Value>,
        actor: &AdminActor,
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
        if config.is_some() {
            sets.push(format!("config = ${}", sets.len() + 2));
        }

        // Simpler approach: full-replace with explicit params.
        let mut tx = begin_scoped(&self.pool, workspace_id.0).await?;

        // Fetch current to fill unset fields.
        let current = sqlx::query(
            "SELECT id, workspace_id, name, provider_type, encrypted_credential, created_at, updated_at, config
             FROM providers WHERE id = $1 AND workspace_id = $2",
        )
        .bind(provider_id)
        .bind(workspace_id.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?
        .ok_or_else(|| ApiError::NotFound(format!("provider {provider_id} not found")))?;

        // Captured BEFORE the UPDATE overwrites them — the "before" half of
        // the audit diff cannot be recovered afterwards.
        let old_name: String = current.get("name");
        let old_type: String = current.get("provider_type");
        let old_config: serde_json::Value = current.get("config");
        // Read before `encrypted_credential` is consumed below. Both are facts
        // about the REQUEST, not about the secret: whether one was supplied,
        // and whether the stored one was explicitly cleared.
        let credential_replaced = matches!(encrypted_credential, Some(Some(_)));
        let credential_cleared = matches!(encrypted_credential, Some(None));

        let new_name: String = name.map(String::from).unwrap_or_else(|| current.get("name"));
        let new_type: String = provider_type.map(String::from).unwrap_or_else(|| current.get("provider_type"));
        let new_cred: Option<String> = match encrypted_credential {
            Some(v) => v,
            None => current.get("encrypted_credential"),
        };
        let new_config: serde_json::Value = match config {
            Some(v) => v,
            None => current.get("config"),
        };

        let _ = sets; // suppress the unused warning from the dynamic builder above

        let row = sqlx::query(
            "UPDATE providers
             SET name = $3, provider_type = $4, encrypted_credential = $5, config = $6, updated_at = NOW()
             WHERE id = $1 AND workspace_id = $2
             RETURNING id, workspace_id, name, provider_type, encrypted_credential, created_at, updated_at, config",
        )
        .bind(provider_id)
        .bind(workspace_id.0)
        .bind(&new_name)
        .bind(&new_type)
        .bind(new_cred.as_deref())
        .bind(&new_config)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        let mut changed = serde_json::Map::new();
        admin_audit_repo::changed_field(
            &mut changed,
            "name",
            &serde_json::json!(old_name),
            &serde_json::json!(new_name),
        );
        admin_audit_repo::changed_field(
            &mut changed,
            "provider_type",
            &serde_json::json!(old_type),
            &serde_json::json!(new_type),
        );
        admin_audit_repo::write(
            &mut tx,
            actor,
            &AdminAuditEntry::on_object(
                AdminAuditAction::ProviderCredentialUpdated,
                provider_id,
                Some(new_name.clone()),
            )
            .with_detail(serde_json::json!({
                "changed": serde_json::Value::Object(changed),
                "credential_replaced": credential_replaced,
                "credential_cleared": credential_cleared,
                // The config blob is provider-type-specific and
                // administrator-supplied, so WHETHER it moved is recorded and
                // its contents are not — the rule migration 028's header sets
                // for a table that is never purged.
                "config_changed": old_config != new_config,
            })),
        )
        .await?;

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
            config: row.get("config"),
        })
    }

    /// Delete a provider by ID within the workspace.
    ///
    /// FU5: writes a `provider_credential.deleted` audit row in the same
    /// transaction. The DELETE now RETURNS the name and type, because after it
    /// commits the audit row is the ONLY surviving description of what was
    /// deleted — a line naming a UUID that resolves to nothing months later
    /// fails the one job an audit record has.
    ///
    /// # Errors
    /// Returns `ApiError::NotFound` when the provider does not exist.
    /// Returns `ApiError::Database` on SQL failure.
    pub async fn delete_provider(
        &self,
        workspace_id: WorkspaceId,
        provider_id: Uuid,
        actor: &AdminActor,
    ) -> Result<(), ApiError> {
        let mut tx = begin_scoped(&self.pool, workspace_id.0).await?;

        let deleted = sqlx::query(
            "DELETE FROM providers WHERE id = $1 AND workspace_id = $2
             RETURNING name, provider_type",
        )
        .bind(provider_id)
        .bind(workspace_id.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        // Decided before the audit write and before the commit, so a delete
        // that matched nothing leaves no row claiming it deleted something.
        let Some(deleted) = deleted else {
            return Err(ApiError::NotFound(format!(
                "provider {provider_id} not found"
            )));
        };
        let name: String = deleted.get("name");
        let provider_type: String = deleted.get("provider_type");

        admin_audit_repo::write(
            &mut tx,
            actor,
            &AdminAuditEntry::on_object(
                AdminAuditAction::ProviderCredentialDeleted,
                provider_id,
                Some(name),
            )
            .with_detail(serde_json::json!({ "provider_type": provider_type })),
        )
        .await?;

        tx.commit()
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?;

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
        let mut tx = begin_scoped(&self.pool, workspace_id.0).await?;

        let rows = sqlx::query(
            "SELECT id, workspace_id, provider_id, name, created_at
             FROM models
             WHERE provider_id = $1
               AND excluded = FALSE
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
        let mut tx = begin_scoped(&self.pool, workspace_id.0).await?;

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
        // return the existing row. A previously-removed (excluded) model is
        // revived here — a manual "Add model" is an explicit request to bring
        // it back, so we clear the exclusion flag (this is what lets an admin
        // undo a deletion the additive sync would otherwise permanently skip).
        let existing = sqlx::query(
            "SELECT id, workspace_id, provider_id, name, created_at, excluded
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
            let id: Uuid = row.get("id");
            if row.get::<bool, _>("excluded") {
                sqlx::query("UPDATE models SET excluded = FALSE WHERE id = $1")
                    .bind(id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| ApiError::Database(e.to_string()))?;
            }
            tx.commit().await.map_err(|e| ApiError::Database(e.to_string()))?;
            return Ok(ModelRow {
                id,
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
        let mut tx = begin_scoped(&self.pool, workspace_id.0).await?;

        // Soft-delete: mark excluded rather than removing the row, so the
        // additive upstream sync knows NOT to re-add this model. A hard DELETE
        // would let the next credential-save / "Sync from upstream" re-import it.
        let result = sqlx::query(
            "UPDATE models SET excluded = TRUE
             WHERE workspace_id = $1 AND provider_id = $2 AND name = $3
               AND excluded = FALSE",
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

    /// Soft-delete many models at once (bulk "Delete selected" in the dashboard).
    /// Idempotent: names that don't exist or are already excluded are skipped.
    /// Returns the number of models newly excluded by this call.
    pub async fn bulk_exclude_models(
        &self,
        workspace_id: WorkspaceId,
        provider_id: Uuid,
        names: &[String],
    ) -> Result<u64, ApiError> {
        if names.is_empty() {
            return Ok(0);
        }
        let mut tx = begin_scoped(&self.pool, workspace_id.0).await?;

        let result = sqlx::query(
            "UPDATE models SET excluded = TRUE
             WHERE workspace_id = $1 AND provider_id = $2
               AND name = ANY($3::text[]) AND excluded = FALSE",
        )
        .bind(workspace_id.0)
        .bind(provider_id)
        .bind(names)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        tx.commit().await.map_err(|e| ApiError::Database(e.to_string()))?;
        Ok(result.rows_affected())
    }

    /// Names of models the admin has removed (soft-deleted) for this provider.
    /// `persist_synced_models` uses this to skip re-adding them during an
    /// upstream sync, so curated deletions survive credential rotations.
    pub async fn list_excluded_model_names_for_provider(
        &self,
        workspace_id: WorkspaceId,
        provider_id: Uuid,
    ) -> Result<Vec<String>, ApiError> {
        let mut tx = begin_scoped(&self.pool, workspace_id.0).await?;

        let rows = sqlx::query(
            "SELECT name FROM models
             WHERE provider_id = $1 AND excluded = TRUE",
        )
        .bind(provider_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        tx.commit().await.map_err(|e| ApiError::Database(e.to_string()))?;
        Ok(rows.into_iter().map(|r| r.get("name")).collect())
    }

    pub async fn list_models(&self, workspace_id: WorkspaceId) -> Result<Vec<ModelRow>, ApiError> {
        let mut tx = begin_scoped(&self.pool, workspace_id.0).await?;

        let rows = sqlx::query(
            "SELECT id, workspace_id, provider_id, name, created_at
             FROM models
             WHERE excluded = FALSE
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
        let mut tx = begin_scoped(&self.pool, workspace_id.0).await?;

        let rows = sqlx::query(
            "SELECT models.id AS model_id,
                    models.workspace_id,
                    models.name AS model_name,
                    providers.id AS provider_id,
                    providers.name AS provider_name,
                    providers.provider_type,
                    providers.encrypted_credential,
                    providers.config
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
                config: record.get("config"),
            })
            .collect())
    }
}
