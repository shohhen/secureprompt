pub mod anthropic;
pub mod ollama;
pub mod openai;
pub mod vllm;
#[cfg(test)]
mod tests;

use crate::{http::model_router::ModelTarget, token_usage::dispatch::estimate_tokens};
use async_trait::async_trait;
use secureprompt_common::types::{Message, RequestId, TokenUsage};
use serde_json::Value;
use std::{collections::HashMap, sync::Arc};
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
}

#[derive(Debug, Clone, Default)]
pub struct ProviderOutput {
    pub content: String,
    pub model: String,
    pub usage: Option<TokenUsage>,
    pub embedding: Option<Vec<f32>>,
    pub stream_chunks: Vec<String>,
    pub finish_reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ProviderFailure {
    pub message: String,
    pub retryable: bool,
}

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
}

impl ProviderCatalog {
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut adapters: HashMap<String, Arc<dyn ProviderAdapter>> = HashMap::new();
        adapters.insert("openai".to_owned(), Arc::new(openai::OpenAiAdapter));
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
