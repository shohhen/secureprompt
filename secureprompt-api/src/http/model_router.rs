use crate::{
    app_state::AppState,
    db::{ProviderRepository, ResolvedModelTarget},
};
use secureprompt_common::{
    errors::ApiError,
    types::{ProviderId, WorkspaceId},
};
use std::collections::HashMap;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct CachedApiKey {
    pub api_key_id: Uuid,
    pub workspace_id: WorkspaceId,
    pub name: String,
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
}

#[derive(Debug, Clone)]
pub struct ResolvedModel {
    pub public_model: String,
    pub targets: Vec<ModelTarget>,
}

#[derive(Debug, Default)]
pub struct ConfigCache {
    api_keys: RwLock<HashMap<String, CachedApiKey>>,
    models: RwLock<HashMap<String, ResolvedModel>>,
}

impl ConfigCache {
    pub async fn get_api_key(&self, token: &str) -> Option<CachedApiKey> {
        self.api_keys.read().await.get(token).cloned()
    }

    pub async fn set_api_key(&self, token: &str, value: CachedApiKey) {
        self.api_keys.write().await.insert(token.to_owned(), value);
    }

    pub async fn get_model(&self, key: &str) -> Option<ResolvedModel> {
        self.models.read().await.get(key).cloned()
    }

    pub async fn set_model(&self, key: &str, value: ResolvedModel) {
        self.models.write().await.insert(key.to_owned(), value);
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
}
