use crate::{
    app_state::AppState,
    db::{ProviderRepository, ResolvedModelTarget},
};
use secureprompt_common::{
    errors::ApiError,
    types::{ProviderId, WorkspaceId},
};
use std::{collections::HashMap, time::{Duration, Instant}};
use tokio::sync::RwLock;
use uuid::Uuid;

/// TTL for cached API key and model entries. After this duration a cache miss
/// is returned so the caller re-validates against Postgres. This ensures that
/// revoked keys and rotated credentials are reflected within 60 seconds.
const CACHE_TTL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct CachedApiKey {
    pub api_key_id: Uuid,
    pub workspace_id: WorkspaceId,
    pub name: String,
    /// Mirrors `AuthenticatedApiKey.assigned_user_id` so downstream handlers
    /// (analytics writer, audit detail) can attribute requests to a user
    /// without re-querying Postgres on the cache hot-path.
    pub assigned_user_id: Option<Uuid>,
    /// Instant at which this entry was inserted; used to enforce CACHE_TTL.
    pub cached_at: Instant,
}

#[derive(Debug, Clone)]
pub struct ModelTarget {
    pub model_id: Uuid,
    pub workspace_id: WorkspaceId,
    pub provider_id: ProviderId,
    pub provider_name: String,
    pub provider_type: String,
    pub model_name: String,
    pub encrypted_credential: Option<String>,
    pub config: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct ResolvedModel {
    pub public_model: String,
    pub targets: Vec<ModelTarget>,
}

#[derive(Debug)]
pub struct ConfigCache {
    api_keys: RwLock<HashMap<String, CachedApiKey>>,
    /// Model entries are stored with the instant they were cached so TTL can be enforced.
    models: RwLock<HashMap<String, (ResolvedModel, Instant)>>,
}

impl Default for ConfigCache {
    fn default() -> Self {
        Self {
            api_keys: RwLock::new(HashMap::new()),
            models: RwLock::new(HashMap::new()),
        }
    }
}

impl ConfigCache {
    /// Returns a cached API key only if it was inserted within CACHE_TTL.
    /// Returning `None` causes the caller to re-validate against the database,
    /// ensuring that revoked keys stop authenticating within 60 seconds.
    pub async fn get_api_key(&self, token: &str) -> Option<CachedApiKey> {
        let entry = self.api_keys.read().await.get(token).cloned()?;
        if entry.cached_at.elapsed() > CACHE_TTL {
            return None;
        }
        Some(entry)
    }

    pub async fn set_api_key(&self, token: &str, value: CachedApiKey) {
        self.api_keys.write().await.insert(token.to_owned(), value);
    }

    /// Returns a cached model only if it was inserted within CACHE_TTL.
    pub async fn get_model(&self, key: &str) -> Option<ResolvedModel> {
        let (model, cached_at) = self.models.read().await.get(key).cloned()?;
        if cached_at.elapsed() > CACHE_TTL {
            return None;
        }
        Some(model)
    }

    pub async fn set_model(&self, key: &str, value: ResolvedModel) {
        self.models
            .write()
            .await
            .insert(key.to_owned(), (value, Instant::now()));
    }
}

pub async fn resolve_model(
    state: &AppState,
    workspace_id: WorkspaceId,
    public_model: &str,
) -> Result<ResolvedModel, ApiError> {
    let cache_key = format!("{workspace_id}:{public_model}");

    if let Some(cached) = state.redis_config_cache.get_model(&cache_key).await {
        return Ok(cached);
    }

    let repo = ProviderRepository::new(state.db.clone());
    let targets = repo
        .resolve_model_targets(workspace_id, public_model)
        .await?;

    if targets.is_empty() {
        // Phase 1 fallback: if no exact model row matches, fall back to the
        // first provider in the workspace and pass the model name through
        // verbatim. The provider's adapter will reject unknown models with
        // an upstream 4xx if the user typed something Google/OpenAI doesn't
        // accept — better UX than a SP-side 404 that hides which layer
        // rejected. Phase 2 introduces an explicit "models" UI so the
        // dashboard can register the exact strings allowed per provider,
        // at which point this fallback can be tightened.
        let providers = repo.list_providers(workspace_id).await?;
        if let Some(p) = providers.into_iter().next() {
            use crate::db::provider_repo::ResolvedModelTarget;
            use secureprompt_common::types::ProviderId;
            use uuid::Uuid;
            let synthetic = ResolvedModelTarget {
                model_id: Uuid::nil(),
                workspace_id,
                provider_id: ProviderId(p.id),
                provider_name: p.name,
                provider_type: p.provider_type,
                model_name: public_model.to_owned(),
                encrypted_credential: p.encrypted_credential,
                config: p.config,
            };
            return Ok(ResolvedModel {
                public_model: public_model.to_owned(),
                targets: vec![ModelTarget::from(synthetic)],
            });
        }
        return Err(ApiError::NotFound(format!(
            "no provider configured for model {public_model}"
        )));
    }

    let resolved = ResolvedModel {
        public_model: public_model.to_owned(),
        targets: targets.into_iter().map(ModelTarget::from).collect(),
    };

    state
        .redis_config_cache
        .set_model(&cache_key, resolved.clone())
        .await;

    Ok(resolved)
}

impl From<ResolvedModelTarget> for ModelTarget {
    fn from(value: ResolvedModelTarget) -> Self {
        Self {
            model_id: value.model_id,
            workspace_id: value.workspace_id,
            provider_id: value.provider_id,
            provider_name: value.provider_name,
            provider_type: value.provider_type,
            model_name: value.model_name,
            encrypted_credential: value.encrypted_credential,
            config: value.config,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn config_cache_stores_and_retrieves_api_key() {
        let cache = ConfigCache::default();
        let key_id = uuid::Uuid::new_v4();
        let workspace_id = secureprompt_common::types::WorkspaceId(uuid::Uuid::new_v4());

        cache
            .set_api_key(
                "sp_testkey",
                CachedApiKey {
                    api_key_id: key_id,
                    workspace_id,
                    name: "test".to_owned(),
                    assigned_user_id: None,
                    cached_at: Instant::now(),
                },
            )
            .await;

        let retrieved = cache.get_api_key("sp_testkey").await;
        assert!(retrieved.is_some());
        let cached = retrieved.unwrap();
        assert_eq!(cached.api_key_id, key_id);
        assert_eq!(cached.workspace_id, workspace_id);
    }

    #[tokio::test]
    async fn config_cache_returns_none_for_missing_key() {
        let cache = ConfigCache::default();
        assert!(cache.get_api_key("sp_nonexistent").await.is_none());
        assert!(cache.get_model("workspace:model").await.is_none());
    }

    #[tokio::test]
    async fn config_cache_stores_and_retrieves_model() {
        let cache = ConfigCache::default();
        let workspace_id = secureprompt_common::types::WorkspaceId(uuid::Uuid::new_v4());
        let provider_id = secureprompt_common::types::ProviderId(uuid::Uuid::new_v4());

        let resolved = ResolvedModel {
            public_model: "gpt-4o-mini".to_owned(),
            targets: vec![ModelTarget {
                model_id: uuid::Uuid::new_v4(),
                workspace_id,
                provider_id,
                provider_name: "openai-primary".to_owned(),
                provider_type: "openai".to_owned(),
                model_name: "gpt-4o-mini".to_owned(),
                encrypted_credential: None,
                config: serde_json::json!({}),
            }],
        };

        let cache_key = format!("{workspace_id}:gpt-4o-mini");
        cache.set_model(&cache_key, resolved.clone()).await;

        let retrieved = cache.get_model(&cache_key).await;
        assert!(retrieved.is_some());
        let cached = retrieved.unwrap();
        assert_eq!(cached.public_model, "gpt-4o-mini");
        assert_eq!(cached.targets.len(), 1);
        assert_eq!(cached.targets[0].provider_type, "openai");
    }

    #[test]
    fn model_target_from_resolved_carries_config() {
        let cfg = serde_json::json!({"region": "us-central1", "project": "p"});
        let resolved = ResolvedModelTarget {
            model_id: uuid::Uuid::nil(),
            workspace_id: WorkspaceId(uuid::Uuid::nil()),
            provider_id: ProviderId(uuid::Uuid::nil()),
            provider_name: "v".into(),
            provider_type: "vertex".into(),
            model_name: "gemini-2.5-flash".into(),
            encrypted_credential: None,
            config: cfg.clone(),
        };
        let target = ModelTarget::from(resolved);
        assert_eq!(target.config, cfg);
    }
}
