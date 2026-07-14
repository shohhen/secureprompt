pub mod anthropic;
pub mod credential_test;
pub mod ollama;
pub mod openai;
pub mod openai_compat;
pub mod vertex;
pub mod vllm;
#[cfg(test)]
mod tests;

use crate::{http::model_router::ModelTarget, token_usage::dispatch::estimate_tokens};
use async_trait::async_trait;
use futures_util::stream::{self, Stream};
use secureprompt_common::types::{Message, RequestId, TokenUsage};
use serde_json::Value;
use std::{collections::HashMap, pin::Pin, sync::Arc};
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct ProviderCatalog {
    adapters: Arc<RwLock<HashMap<String, Arc<dyn ProviderAdapter>>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvocationKind {
    Chat,
    Completion,
    Embedding,
}

#[derive(Debug, Clone)]
pub struct ProviderInvocation {
    pub request_id: RequestId,
    pub model: String,
    pub prompt: String,
    pub messages: Vec<Message>,
    pub extra_params: Value,
    pub stream: bool,
    pub kind: InvocationKind,
    /// Plaintext credential (e.g. "sk-..." or a Google API key), decrypted
    /// from `target.encrypted_credential` by the pipeline before invoking
    /// the adapter. `None` means no credential is configured — the adapter
    /// can fail-fast or use anonymous defaults (e.g. ollama).
    pub decrypted_credential: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ProviderOutput {
    pub content: String,
    pub model: String,
    pub usage: Option<TokenUsage>,
    pub embedding: Option<Vec<f32>>,
    pub stream_chunks: Vec<String>,
    pub finish_reason: Option<String>,
    /// Time-to-first-byte from upstream — measured between issuing the
    /// HTTP request and the moment the response headers arrive.
    /// `None` for adapters that don't make a network call (debug mode,
    /// stub adapters in tests).
    pub ttft_ms: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct ProviderFailure {
    pub message: String,
    pub retryable: bool,
}

/// One event in an incremental provider response stream.
///
/// `Token` carries a raw text delta exactly as the upstream model emitted it
/// (still containing any `{{Placeholder}}` the prompt redaction injected —
/// the pipeline's streaming redactor restores/re-redacts before the client
/// sees it). `Done` arrives exactly once, last, with the terminal bookkeeping
/// the pipeline needs to finalize the request (usage for billing, finish
/// reason, resolved model, and the time-to-first-token sample).
#[derive(Debug, Clone)]
pub enum ProviderEvent {
    Token(String),
    Done {
        usage: Option<TokenUsage>,
        finish_reason: Option<String>,
        model: Option<String>,
        ttft_ms: Option<u32>,
    },
}

/// A boxed, owned (`'static`) stream of provider events. Owned so it can be
/// handed to the Axum SSE response and outlive the request borrow.
pub type ProviderEventStream =
    Pin<Box<dyn Stream<Item = Result<ProviderEvent, ProviderFailure>> + Send>>;

#[async_trait]
pub trait ProviderAdapter: Send + Sync {
    fn provider_type(&self) -> &'static str;

    async fn complete(
        &self,
        target: &ModelTarget,
        invocation: &ProviderInvocation,
    ) -> Result<ProviderOutput, ProviderFailure>;

    async fn stream(
        &self,
        target: &ModelTarget,
        invocation: &ProviderInvocation,
    ) -> Result<ProviderOutput, ProviderFailure>;

    /// Incremental event stream for `stream: true` requests.
    ///
    /// Default implementation adapts the buffered `stream()` result into an
    /// event stream: it emits each `stream_chunks` entry (or the whole
    /// `content` if there are none) as a `Token`, then a single `Done`. This
    /// keeps the stub/echo adapters (anthropic, ollama, vllm) working without
    /// change — they already fan `content` into multiple chunks via
    /// `chunk_content`. Adapters with a real upstream SSE surface (see
    /// `openai_compat`) override this to stream token-by-token as the
    /// provider produces them, which is what actually reduces time-to-first-
    /// token for long answers.
    async fn stream_events(
        &self,
        target: &ModelTarget,
        invocation: &ProviderInvocation,
    ) -> Result<ProviderEventStream, ProviderFailure> {
        let out = self.stream(target, invocation).await?;
        let mut events: Vec<Result<ProviderEvent, ProviderFailure>> = Vec::new();
        if out.stream_chunks.is_empty() {
            if !out.content.is_empty() {
                events.push(Ok(ProviderEvent::Token(out.content.clone())));
            }
        } else {
            for chunk in out.stream_chunks {
                events.push(Ok(ProviderEvent::Token(chunk)));
            }
        }
        events.push(Ok(ProviderEvent::Done {
            usage: out.usage,
            finish_reason: out.finish_reason,
            model: Some(out.model),
            ttft_ms: out.ttft_ms,
        }));
        Ok(Box::pin(stream::iter(events)))
    }
}

impl ProviderCatalog {
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut adapters: HashMap<String, Arc<dyn ProviderAdapter>> = HashMap::new();
        // Real HTTP adapter for OpenAI's API and Google's OpenAI-compat
        // endpoint. Both speak the same /chat/completions protocol so one
        // implementation covers both — registered under each canonical
        // provider_type. The legacy `openai::OpenAiAdapter` stub is left in
        // the codebase for tests but no longer registered as the runtime
        // adapter for `openai`.
        adapters.insert(
            "openai".to_owned(),
            Arc::new(openai_compat::OpenAiCompatAdapter::openai()),
        );
        adapters.insert(
            "google".to_owned(),
            Arc::new(openai_compat::OpenAiCompatAdapter::google()),
        );
        adapters.insert(
            "vertex".to_owned(),
            Arc::new(vertex::VertexAdapter::new()),
        );
        adapters.insert(
            "anthropic".to_owned(),
            Arc::new(anthropic::AnthropicAdapter),
        );
        adapters.insert("ollama".to_owned(), Arc::new(ollama::OllamaAdapter));
        adapters.insert("vllm".to_owned(), Arc::new(vllm::VllmAdapter));

        Self {
            adapters: Arc::new(RwLock::new(adapters)),
        }
    }

    pub async fn adapter_for(&self, provider_type: &str) -> Option<Arc<dyn ProviderAdapter>> {
        self.adapters.read().await.get(provider_type).cloned()
    }

    pub async fn register(&self, provider_type: &str, adapter: Arc<dyn ProviderAdapter>) {
        self.adapters
            .write()
            .await
            .insert(provider_type.to_owned(), adapter);
    }
}

/// Strip test-only control parameters from `extra_params` so that production
/// traffic cannot suppress usage reporting or force provider failures via the
/// request body. This function is a no-op in test builds.
#[cfg(not(test))]
pub(crate) fn sanitize_extra_params(mut params: serde_json::Value) -> serde_json::Value {
    if let serde_json::Value::Object(ref mut map) = params {
        map.remove("omit_usage");
        map.remove("force_provider_failure");
    }
    params
}

#[cfg(test)]
pub(crate) fn sanitize_extra_params(params: serde_json::Value) -> serde_json::Value {
    // In test builds, allow test-only params to pass through unchanged.
    params
}

pub(crate) fn maybe_fail(
    provider_type: &str,
    target: &ModelTarget,
    invocation: &ProviderInvocation,
) -> Option<ProviderFailure> {
    if target.encrypted_credential.as_deref() == Some("force_retryable") {
        return Some(ProviderFailure {
            message: format!("{provider_type} adapter forced retryable failure"),
            retryable: true,
        });
    }

    if target.encrypted_credential.as_deref() == Some("force_fatal") {
        return Some(ProviderFailure {
            message: format!("{provider_type} adapter forced fatal failure"),
            retryable: false,
        });
    }

    if invocation
        .extra_params
        .get("force_provider_failure")
        .and_then(Value::as_str)
        == Some(provider_type)
    {
        return Some(ProviderFailure {
            message: format!("{provider_type} adapter forced failure via request"),
            retryable: true,
        });
    }

    None
}

pub(crate) fn render_output(
    provider_label: &str,
    target: &ModelTarget,
    invocation: &ProviderInvocation,
    streaming: bool,
) -> ProviderOutput {
    if invocation.kind == InvocationKind::Embedding {
        return ProviderOutput {
            content: String::new(),
            model: target.model_name.clone(),
            usage: maybe_usage(provider_label, invocation, ""),
            embedding: Some(fake_embedding(&invocation.prompt)),
            stream_chunks: Vec::new(),
            finish_reason: Some("stop".to_owned()),
            ttft_ms: None,
        };
    }

    let content = format!("{provider_label} echo: {}", invocation.prompt);
    let chunks = if streaming {
        chunk_content(
            &content,
            invocation
                .extra_params
                .get("chunk_size")
                .and_then(Value::as_u64)
                .unwrap_or(7) as usize,
        )
    } else {
        Vec::new()
    };

    ProviderOutput {
        content: content.clone(),
        model: target.model_name.clone(),
        usage: maybe_usage(provider_label, invocation, &content),
        embedding: None,
        stream_chunks: chunks,
        finish_reason: Some("stop".to_owned()),
        ttft_ms: None,
    }
}

fn maybe_usage(
    provider_type: &str,
    invocation: &ProviderInvocation,
    output: &str,
) -> Option<TokenUsage> {
    if invocation
        .extra_params
        .get("omit_usage")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return None;
    }

    Some(TokenUsage {
        input_tokens: Some(estimate_tokens(provider_type, &invocation.prompt)),
        output_tokens: Some(estimate_tokens(provider_type, output)),
        reasoning_tokens: Some(0),
        cache_read_tokens: Some(0),
        cache_write_tokens: Some(0),
    })
}

fn chunk_content(content: &str, chunk_size: usize) -> Vec<String> {
    if chunk_size == 0 {
        return vec![content.to_owned()];
    }

    let mut chunks = Vec::new();
    let mut start = 0usize;
    let chars: Vec<char> = content.chars().collect();

    while start < chars.len() {
        let end = (start + chunk_size).min(chars.len());
        chunks.push(chars[start..end].iter().collect());
        start = end;
    }

    chunks
}

fn fake_embedding(prompt: &str) -> Vec<f32> {
    let mut values = vec![0.0f32; 8];

    for (index, byte) in prompt.bytes().enumerate() {
        let slot = index % values.len();
        values[slot] += f32::from(byte) / 255.0;
    }

    values
}
