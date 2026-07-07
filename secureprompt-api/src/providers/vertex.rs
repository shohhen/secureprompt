//! Vertex AI provider adapter — Gemini through Google Cloud (Cloud Billing),
//! separate from the AI Studio `google` adapter. See
//! docs/superpowers/specs/2026-07-07-vertex-ai-provider-design.md.

/// Build the Vertex OpenAI-compat chat-completions URL. `global` uses the
/// unprefixed host; every other region uses `{region}-aiplatform...`.
pub(crate) fn vertex_completions_url(region: &str, project: &str) -> String {
    let host = if region == "global" {
        "aiplatform.googleapis.com".to_owned()
    } else {
        format!("{region}-aiplatform.googleapis.com")
    };
    format!(
        "https://{host}/v1/projects/{project}/locations/{region}/endpoints/openapi/chat/completions"
    )
}

/// Vertex OpenAI-compat requires the `google/` publisher prefix; the console
/// stores bare ids. Idempotent.
pub(crate) fn google_prefixed(model: &str) -> String {
    if model.starts_with("google/") {
        model.to_owned()
    } else {
        format!("google/{model}")
    }
}

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(crate) struct VertexConfig {
    pub region: Option<String>,
    pub project: Option<String>,
}

impl VertexConfig {
    pub(crate) fn from_value(v: &serde_json::Value) -> Self {
        serde_json::from_value(v.clone()).unwrap_or(VertexConfig { region: None, project: None })
    }
}

/// Cache key for a credential: SHA-256 of the SA JSON, or the literal "adc"
/// when no credential is configured (Application Default Credentials).
pub(crate) fn credential_fingerprint(credential: Option<&str>) -> String {
    match credential {
        Some(json) => {
            use sha2::{Digest, Sha256};
            let digest = Sha256::digest(json.as_bytes());
            format!("sa:{:x}", digest)
        }
        None => "adc".to_owned(),
    }
}

use async_trait::async_trait;
use gcp_auth::{CustomServiceAccount, TokenProvider};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::http::model_router::ModelTarget;
use super::openai_compat::{invoke, invoke_stream};
use super::{
    ProviderAdapter, ProviderEventStream, ProviderFailure, ProviderInvocation, ProviderOutput,
};

const CLOUD_PLATFORM_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
const DEFAULT_REGION: &str = "us-central1";

pub struct VertexAdapter {
    /// Token providers cached by credential fingerprint so one provider (and
    /// its internal token cache) is reused across requests, not re-created.
    providers: RwLock<HashMap<String, Arc<dyn TokenProvider>>>,
}

impl VertexAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self { providers: RwLock::new(HashMap::new()) }
    }

    async fn token_provider(
        &self,
        credential: Option<&str>,
    ) -> Result<Arc<dyn TokenProvider>, ProviderFailure> {
        let key = credential_fingerprint(credential);
        if let Some(p) = self.providers.read().await.get(&key) {
            return Ok(p.clone());
        }
        let provider: Arc<dyn TokenProvider> = match credential {
            Some(sa_json) => {
                let account = CustomServiceAccount::from_json(sa_json).map_err(|e| ProviderFailure {
                    message: format!("vertex: invalid service-account JSON: {e}"),
                    retryable: false,
                })?;
                Arc::new(account)
            }
            None => gcp_auth::provider().await.map_err(|e| ProviderFailure {
                message: format!("vertex: no Application Default Credentials available: {e}"),
                retryable: false,
            })?,
        };
        self.providers.write().await.insert(key, provider.clone());
        Ok(provider)
    }

    async fn access_token(&self, credential: Option<&str>) -> Result<String, ProviderFailure> {
        let provider = self.token_provider(credential).await?;
        let token = provider
            .token(&[CLOUD_PLATFORM_SCOPE])
            .await
            .map_err(|e| ProviderFailure {
                message: format!("vertex: failed to mint access token: {e}"),
                retryable: false,
            })?;
        Ok(token.as_str().to_owned())
    }

    /// Resolve (region, project) from the provider config + SA JSON fallback.
    async fn resolve_target(
        &self,
        target: &ModelTarget,
        credential: Option<&str>,
    ) -> Result<(String, String), ProviderFailure> {
        let cfg = VertexConfig::from_value(&target.config);
        let region = cfg.region.filter(|s| !s.is_empty()).unwrap_or_else(|| DEFAULT_REGION.to_owned());
        let project = cfg
            .project
            .filter(|s| !s.is_empty())
            .or_else(|| sa_project_id(credential))
            .or_else(|| std::env::var("GOOGLE_CLOUD_PROJECT").ok())
            .ok_or_else(|| ProviderFailure {
                message: "vertex: no project configured (set the provider's project, or use an SA key / GOOGLE_CLOUD_PROJECT)".to_owned(),
                retryable: false,
            })?;
        Ok((region, project))
    }
}

impl Default for VertexAdapter {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract `project_id` from an SA JSON credential, if present.
fn sa_project_id(credential: Option<&str>) -> Option<String> {
    let json = credential?;
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    v.get("project_id").and_then(|p| p.as_str()).map(str::to_owned)
}

#[async_trait]
impl ProviderAdapter for VertexAdapter {
    fn provider_type(&self) -> &'static str {
        "vertex"
    }

    async fn complete(
        &self,
        target: &ModelTarget,
        invocation: &ProviderInvocation,
    ) -> Result<ProviderOutput, ProviderFailure> {
        let cred = invocation.decrypted_credential.as_deref();
        let (region, project) = self.resolve_target(target, cred).await?;
        let token = self.access_token(cred).await?;
        let url = vertex_completions_url(&region, &project);
        let model = google_prefixed(&invocation.model);
        invoke("vertex", &url, &token, &model, invocation, false).await
    }

    async fn stream(
        &self,
        target: &ModelTarget,
        invocation: &ProviderInvocation,
    ) -> Result<ProviderOutput, ProviderFailure> {
        let cred = invocation.decrypted_credential.as_deref();
        let (region, project) = self.resolve_target(target, cred).await?;
        let token = self.access_token(cred).await?;
        let url = vertex_completions_url(&region, &project);
        let model = google_prefixed(&invocation.model);
        invoke("vertex", &url, &token, &model, invocation, true).await
    }

    async fn stream_events(
        &self,
        target: &ModelTarget,
        invocation: &ProviderInvocation,
    ) -> Result<ProviderEventStream, ProviderFailure> {
        let cred = invocation.decrypted_credential.as_deref();
        let (region, project) = self.resolve_target(target, cred).await?;
        let token = self.access_token(cred).await?;
        let url = vertex_completions_url(&region, &project);
        let model = google_prefixed(&invocation.model);
        invoke_stream("vertex", &url, &token, &model, invocation).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_regional() {
        assert_eq!(
            vertex_completions_url("us-central1", "proj"),
            "https://us-central1-aiplatform.googleapis.com/v1/projects/proj/locations/us-central1/endpoints/openapi/chat/completions"
        );
    }

    #[test]
    fn url_global() {
        assert_eq!(
            vertex_completions_url("global", "proj"),
            "https://aiplatform.googleapis.com/v1/projects/proj/locations/global/endpoints/openapi/chat/completions"
        );
    }

    #[test]
    fn prefix_added_once() {
        assert_eq!(google_prefixed("gemini-2.5-flash"), "google/gemini-2.5-flash");
        assert_eq!(google_prefixed("google/gemini-2.5-pro"), "google/gemini-2.5-pro");
    }

    #[test]
    fn fingerprint_sa_vs_adc() {
        assert_eq!(credential_fingerprint(None), "adc");
        let a = credential_fingerprint(Some("{\"x\":1}"));
        let b = credential_fingerprint(Some("{\"x\":1}"));
        let c = credential_fingerprint(Some("{\"x\":2}"));
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("sa:"));
    }

    #[test]
    fn config_parse() {
        let cfg = VertexConfig::from_value(&serde_json::json!({"region":"us-central1","project":"p"}));
        assert_eq!(cfg.region.as_deref(), Some("us-central1"));
        assert_eq!(cfg.project.as_deref(), Some("p"));
        let empty = VertexConfig::from_value(&serde_json::json!({}));
        assert!(empty.region.is_none() && empty.project.is_none());
    }
}
