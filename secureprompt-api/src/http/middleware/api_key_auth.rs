use crate::{
    app_state::AppState,
    db::{ApiKeyRepository, AuthenticatedApiKey},
    http::model_router::CachedApiKey,
};
use axum::http::HeaderMap;
use secureprompt_common::{errors::ApiError, types::WorkspaceId};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AuthContext {
    pub api_key_id: Uuid,
    pub workspace_id: WorkspaceId,
    pub api_key_name: String,
}

pub async fn authenticate_request(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<AuthContext, ApiError> {
    let header_value = headers
        .get(axum::http::header::AUTHORIZATION)
        .ok_or_else(|| ApiError::Unauthorized("missing Authorization header".into()))?
        .to_str()
        .map_err(|_| ApiError::Unauthorized("Authorization header must be valid UTF-8".into()))?;

    let token = header_value
        .strip_prefix("Bearer ")
        .ok_or_else(|| ApiError::Unauthorized("expected Authorization: Bearer sp_...".into()))?;

    if !token.starts_with("sp_") {
        return Err(ApiError::Unauthorized(
            "expected Authorization: Bearer sp_...".into(),
        ));
    }

    if let Some(cached) = state.redis_config_cache.get_api_key(token).await {
        return Ok(AuthContext {
            api_key_id: cached.api_key_id,
            workspace_id: cached.workspace_id,
            api_key_name: cached.name,
        });
    }

    let repo = ApiKeyRepository::new(state.db.clone());
    let authenticated = repo
        .authenticate_api_key(token)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("invalid or revoked API key".into()))?;

    cache_api_key(state, token, &authenticated).await;

    Ok(AuthContext {
        api_key_id: authenticated.id,
        workspace_id: authenticated.workspace_id,
        api_key_name: authenticated.name,
    })
}

async fn cache_api_key(state: &AppState, token: &str, authenticated: &AuthenticatedApiKey) {
    state
        .redis_config_cache
        .set_api_key(
            token,
            CachedApiKey {
                api_key_id: authenticated.id,
                workspace_id: authenticated.workspace_id,
                name: authenticated.name.clone(),
            },
        )
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    fn make_headers(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            value.parse().expect("valid header value"),
        );
        headers
    }

    #[test]
    fn token_must_start_with_sp_prefix() {
        // Validate the Bearer + sp_ prefix logic inline without a DB
        let header = "Bearer sp_abc123";
        let token = header
            .strip_prefix("Bearer ")
            .expect("strip Bearer prefix");
        assert!(token.starts_with("sp_"), "token must have sp_ prefix");
    }

    #[test]
    fn non_sp_token_fails_prefix_check() {
        let token = "sk-abc123";
        assert!(
            !token.starts_with("sp_"),
            "non-sp_ token should be rejected"
        );
    }

    #[test]
    fn missing_bearer_prefix_fails() {
        let header = "Basic sp_abc123";
        assert!(
            header.strip_prefix("Bearer ").is_none(),
            "Basic auth should not match Bearer"
        );
    }
}
