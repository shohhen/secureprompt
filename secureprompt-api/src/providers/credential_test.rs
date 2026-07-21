//! Provider-credential connectivity tester used by the dashboard's
//! "Test Connection" feature and reused by the real-cloud HTTP adapters.
//!
//! Each provider type has a cheap, side-effect-free probe endpoint:
//!   - `openai` / `custom` (OpenAI-compatible): `GET {base_url}/models`
//!     with `Authorization: Bearer {api_key}`.
//!   - `google` (native Gemini API): `GET https://generativelanguage.googleapis.com/v1beta/models?key={api_key}`.
//!     Google's OpenAI-compat endpoint at `/v1beta/openai` also accepts
//!     the same Bearer-token shape so we treat it as openai-compat.
//!   - `anthropic`: `GET https://api.anthropic.com/v1/models` with
//!     `x-api-key: {api_key}` and `anthropic-version: 2023-06-01`.
//!
//! All probes use a 10s timeout. Successful probe returns the count of
//! models the API returned (zero is technically valid but unusual; the
//! caller can flag it). Failure returns a short error string suitable
//! for display in the dashboard.

use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize)]
pub struct TestResult {
    pub success: bool,
    pub model_count: Option<u32>,
    pub error: Option<String>,
}

impl TestResult {
    fn ok(model_count: u32) -> Self {
        Self {
            success: true,
            model_count: Some(model_count),
            error: None,
        }
    }

    fn err(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            model_count: None,
            error: Some(msg.into()),
        }
    }
}

/// Default base URLs per provider_type. Used when the caller doesn't
/// supply one (e.g. the dashboard's "Test Connection" with empty URL field).
#[must_use]
pub fn default_base_url(provider_type: &str) -> &'static str {
    match provider_type.to_lowercase().as_str() {
        "openai" => "https://api.openai.com/v1",
        // Google ships an OpenAI-compatible endpoint that accepts the
        // same /chat/completions + /models routes and `Authorization:
        // Bearer` auth — much simpler than wiring a separate
        // generateContent client.
        "google" => "https://generativelanguage.googleapis.com/v1beta/openai",
        "anthropic" => "https://api.anthropic.com",
        _ => "",
    }
}

/// Probe the provider with the given credentials. Selects the right
/// protocol per `provider_type`. `base_url` overrides the default.
/// `region`/`project` are Vertex-only (ignored by every other provider
/// type) — see `probe_vertex`.
pub async fn test_connection(
    provider_type: &str,
    api_key: &str,
    base_url: Option<&str>,
    region: Option<&str>,
    project: Option<&str>,
) -> TestResult {
    // Vertex auth is OAuth (SA JSON or ADC), not a bearer API key, and the
    // credential may legitimately be empty (ADC) — handle it before the
    // shared empty-api_key short-circuit below applies to every other
    // provider type.
    if provider_type.eq_ignore_ascii_case("vertex") {
        return probe_vertex(api_key, region, project).await;
    }

    if api_key.trim().is_empty() {
        return TestResult::err("api_key is empty");
    }

    let resolved_base = base_url
        .map(|s| s.trim_end_matches('/').to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| default_base_url(provider_type).to_owned());

    if resolved_base.is_empty() {
        return TestResult::err(format!(
            "no default base_url for provider_type={provider_type}; supply one explicitly"
        ));
    }

    // SSRF guard: validate + resolve + screen before any connection, then
    // pin the validated address so the host cannot be re-resolved.
    let policy = crate::security::EgressPolicy::from_env();
    let validated = match crate::security::validate_outbound_url(&resolved_base, &policy).await {
        Ok(v) => v,
        Err(e) => return TestResult::err(format!("base_url rejected: {e}")),
    };

    let client = match crate::security::build_pinned_client(&validated, Duration::from_secs(10)) {
        Ok(c) => c,
        Err(e) => return TestResult::err(format!("failed to build HTTP client: {e}")),
    };

    match provider_type.to_lowercase().as_str() {
        "anthropic" => probe_anthropic(&client, &resolved_base, api_key).await,
        // openai, google, custom, openai_compat all use the same probe.
        _ => probe_openai_compat(&client, &resolved_base, api_key).await,
    }
}

/// Vertex probe: mint an OAuth access token (SA JSON or ADC) and hit the
/// publishers/models listing for the resolved region+project. Unlike the
/// other providers, Vertex doesn't use a static bearer API key, so this
/// bypasses the shared `reqwest`/`base_url` scaffolding in `test_connection`
/// entirely.
async fn probe_vertex(
    credential: &str,
    region: Option<&str>,
    project: Option<&str>,
) -> TestResult {
    // For Vertex, `credential` is the SA JSON (may be empty => ADC).
    let cred = if credential.trim().is_empty() { None } else { Some(credential) };
    let token = match crate::providers::vertex::mint_access_token(cred).await {
        Ok(t) => t,
        Err(e) => return TestResult::err(format!("vertex auth failed: {e}")),
    };
    let region = region.filter(|s| !s.is_empty()).unwrap_or("us-central1");
    let project = match project.filter(|s| !s.is_empty()) {
        Some(p) => p.to_owned(),
        None => match crate::providers::vertex::sa_project_id_public(cred) {
            Some(p) => p,
            None => return TestResult::err("vertex: project required (set project or use an SA key)"),
        },
    };
    let host = if region == "global" {
        "aiplatform.googleapis.com".to_owned()
    } else {
        format!("{region}-aiplatform.googleapis.com")
    };
    let url = format!(
        "https://{host}/v1/projects/{project}/locations/{region}/publishers/google/models"
    );
    let client = match reqwest::Client::builder().timeout(Duration::from_secs(10)).build() {
        Ok(c) => c,
        Err(e) => return TestResult::err(format!("http client: {e}")),
    };
    match client.get(&url).bearer_auth(&token).send().await {
        Ok(resp) if resp.status().is_success() => TestResult::ok(0),
        Ok(resp) => TestResult::err(format!("vertex HTTP {}", resp.status())),
        Err(e) => TestResult::err(format!("vertex request failed: {e}")),
    }
}

/// `GET {base_url}/models` with `Authorization: Bearer {key}`.
/// Works for OpenAI, Google's OpenAI-compat endpoint, and any custom
/// OpenAI-compatible gateway.
async fn probe_openai_compat(
    client: &reqwest::Client,
    base_url: &str,
    api_key: &str,
) -> TestResult {
    match fetch_openai_compat_models(client, base_url, api_key).await {
        Ok(models) => TestResult::ok(models.len() as u32),
        Err(e) => TestResult::err(e),
    }
}

/// Inner fetch shared by `probe_openai_compat` and `list_upstream_models`.
/// Returns the raw `data[].id` list (no normalization). The upstream Google
/// OpenAI-compat endpoint returns names prefixed with `models/`; normalize
/// at the call site.
async fn fetch_openai_compat_models(
    client: &reqwest::Client,
    base_url: &str,
    api_key: &str,
) -> Result<Vec<String>, String> {
    let url = format!("{base_url}/models");
    let resp = client
        .get(&url)
        .bearer_auth(api_key)
        .send()
        .await
        .map_err(|e| format!("connection failed to {url}: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body_snippet = resp
            .text()
            .await
            .ok()
            .map(|s| s.chars().take(200).collect::<String>())
            .unwrap_or_default();
        return Err(format!("HTTP {status} from {url}: {body_snippet}"));
    }
    // OpenAI shape: `{"object":"list","data":[{"id":"...","object":"model",...}, ...]}`
    #[derive(Deserialize)]
    struct ModelEntry {
        id: String,
    }
    #[derive(Deserialize)]
    struct ModelsList {
        data: Vec<ModelEntry>,
    }
    let parsed: ModelsList = resp
        .json()
        .await
        .map_err(|e| format!("invalid /models response shape: {e}"))?;
    Ok(parsed.data.into_iter().map(|m| m.id).collect())
}

/// Anthropic uses `x-api-key` header (not Bearer) and an `anthropic-version`
/// header.  `GET {base_url}/v1/models`.
async fn probe_anthropic(
    client: &reqwest::Client,
    base_url: &str,
    api_key: &str,
) -> TestResult {
    match fetch_anthropic_models(client, base_url, api_key).await {
        Ok(models) => TestResult::ok(models.len() as u32),
        Err(e) => TestResult::err(e),
    }
}

async fn fetch_anthropic_models(
    client: &reqwest::Client,
    base_url: &str,
    api_key: &str,
) -> Result<Vec<String>, String> {
    let url = format!("{}/v1/models", base_url.trim_end_matches('/'));
    let resp = client
        .get(&url)
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .send()
        .await
        .map_err(|e| format!("connection failed to {url}: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body_snippet = resp
            .text()
            .await
            .ok()
            .map(|s| s.chars().take(200).collect::<String>())
            .unwrap_or_default();
        return Err(format!("HTTP {status} from {url}: {body_snippet}"));
    }
    #[derive(Deserialize)]
    struct ModelEntry {
        id: String,
    }
    #[derive(Deserialize)]
    struct ModelsList {
        data: Vec<ModelEntry>,
    }
    let parsed: ModelsList = resp
        .json()
        .await
        .map_err(|e| format!("invalid Anthropic /models response: {e}"))?;
    Ok(parsed.data.into_iter().map(|m| m.id).collect())
}

/// Fetch every chat-capable model the upstream returns for the given
/// credential, normalized to the bare model id we store in `provider_models`
/// (e.g. `gemini-2.5-flash`, not `models/gemini-2.5-flash`). Filters out
/// embedding-only / retrieval-only / TTS / image-gen models so the chat
/// picker never offers something the gateway can't actually proxy.
///
/// Returns the de-duplicated, sorted list of model ids — same shape the
/// dashboard "Models" panel persists into the `provider_models` table.
pub async fn list_upstream_models(
    provider_type: &str,
    api_key: &str,
    base_url: Option<&str>,
) -> Result<Vec<String>, String> {
    if api_key.trim().is_empty() {
        return Err("api_key is empty".to_owned());
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;

    let resolved_base = base_url
        .map(|s| s.trim_end_matches('/').to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| default_base_url(provider_type).to_owned());
    if resolved_base.is_empty() {
        return Err(format!(
            "no default base_url for provider_type={provider_type}; supply one explicitly"
        ));
    }

    let raw_ids = match provider_type.to_lowercase().as_str() {
        "anthropic" => fetch_anthropic_models(&client, &resolved_base, api_key).await?,
        _ => fetch_openai_compat_models(&client, &resolved_base, api_key).await?,
    };

    let lowered_type = provider_type.to_lowercase();
    let mut chat_models: Vec<String> = raw_ids
        .into_iter()
        .map(normalize_model_id)
        .filter(|id| is_chat_capable(&lowered_type, id))
        .collect();
    chat_models.sort();
    chat_models.dedup();
    Ok(chat_models)
}

/// Strip provider-specific prefixes from a raw `/models` id so the value
/// matches what users type in the chat client (and what SP stores in
/// `provider_models.name`). Currently only Google's OpenAI-compat endpoint
/// returns prefixed ids (`models/gemini-2.5-flash`).
fn normalize_model_id(id: String) -> String {
    if let Some(stripped) = id.strip_prefix("models/") {
        return stripped.to_owned();
    }
    id
}

/// Heuristic filter: keep models that can plausibly serve a chat-completions
/// request. Rejects embedding-only, retrieval, TTS, image-gen, and
/// fine-tuning-base entries that show up alongside chat models in the same
/// `/models` listing on every major provider. Conservative — false-positives
/// (admin can manually delete unwanted rows in the dashboard) beat
/// false-negatives (admin can't add what we filtered out).
fn is_chat_capable(provider_type: &str, id: &str) -> bool {
    let lower = id.to_lowercase();
    // Universal denylist — these never serve /chat/completions.
    if lower.contains("embedding")
        || lower.contains("text-embedding")
        || lower.contains("whisper")
        || lower.contains("tts-")
        || lower.contains("dall-e")
        || lower.contains("image-")
        || lower.starts_with("image-")
        || lower.contains("moderation")
        || lower.contains("babbage")
        || lower.contains("davinci-")
        || lower.contains("ada-")
    {
        return false;
    }
    match provider_type {
        "google" => {
            // Google ships retrieval/aqa, vision-only, and translation models
            // alongside chat ones — drop the ones that won't answer
            // /chat/completions.
            !(lower.contains("aqa")
                || lower.contains("imagen")
                || lower.contains("veo")
                || lower.contains("text-bison")
                || lower.contains("chat-bison"))
        }
        "anthropic" => {
            // Anthropic /models currently lists only chat-capable claude-*.
            true
        }
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_api_key_short_circuits() {
        let result = test_connection("openai", "", None, None, None).await;
        assert!(!result.success);
        assert!(result.error.unwrap().contains("empty"));
    }

    #[tokio::test]
    async fn unknown_provider_type_with_no_base_url_errors() {
        let result = test_connection("nonexistent", "sk-test", None, None, None).await;
        assert!(!result.success);
        assert!(result.error.unwrap().contains("no default base_url"));
    }

    #[test]
    fn default_base_urls_are_set_for_known_providers() {
        assert!(!default_base_url("openai").is_empty());
        assert!(!default_base_url("google").is_empty());
        assert!(!default_base_url("anthropic").is_empty());
        assert!(default_base_url("nonexistent").is_empty());
    }

    #[test]
    fn normalize_strips_google_models_prefix() {
        assert_eq!(
            normalize_model_id("models/gemini-2.5-flash".to_owned()),
            "gemini-2.5-flash"
        );
        assert_eq!(
            normalize_model_id("gpt-4o-mini".to_owned()),
            "gpt-4o-mini"
        );
    }

    #[test]
    fn chat_filter_drops_embeddings_and_image_gen() {
        assert!(!is_chat_capable("openai", "text-embedding-3-small"));
        assert!(!is_chat_capable("openai", "whisper-1"));
        assert!(!is_chat_capable("openai", "dall-e-3"));
        assert!(!is_chat_capable("openai", "tts-1-hd"));
        assert!(!is_chat_capable("google", "embedding-001"));
        assert!(!is_chat_capable("google", "aqa"));
        assert!(!is_chat_capable("google", "imagen-3.0-generate-002"));
    }

    #[test]
    fn chat_filter_keeps_modern_chat_models() {
        assert!(is_chat_capable("openai", "gpt-4o"));
        assert!(is_chat_capable("openai", "gpt-4o-mini"));
        assert!(is_chat_capable("google", "gemini-2.5-flash"));
        assert!(is_chat_capable("google", "gemini-2.5-pro"));
        assert!(is_chat_capable("anthropic", "claude-sonnet-4-5"));
    }
}

#[cfg(test)]
mod ssrf_tests {
    use super::*;

    #[tokio::test]
    async fn test_connection_refuses_metadata_base_url() {
        let r = test_connection(
            "openai",
            "sk-test",
            Some("http://169.254.169.254/latest/meta-data"),
            None,
            None,
        )
        .await;
        assert!(!r.success, "metadata endpoint must be refused");
        let msg = r.error.unwrap_or_default();
        assert!(
            msg.contains("blocked") || msg.contains("metadata"),
            "error should name the egress refusal, got: {msg}"
        );
    }

    #[tokio::test]
    async fn test_connection_refuses_file_scheme() {
        let r = test_connection("openai", "sk-test", Some("file:///etc/passwd"), None, None).await;
        assert!(!r.success);
        assert!(r.error.unwrap_or_default().contains("scheme"));
    }
}
