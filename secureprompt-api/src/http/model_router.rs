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
