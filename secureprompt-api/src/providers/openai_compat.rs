//! Real HTTP adapter that speaks the OpenAI Chat Completions REST
//! protocol. Used for `provider_type = "openai"` against api.openai.com,
//! and for `provider_type = "google"` against Google's OpenAI-compatible
//! endpoint at `https://generativelanguage.googleapis.com/v1beta/openai`.
//!
//! Both paths take the same `POST {base_url}/chat/completions` shape with
//! `Authorization: Bearer {api_key}`, so a single adapter implementation
//! covers both. This is intentional: rather than maintain a separate
//! `google.rs` that wraps Google's native `generateContent` API, we route
//! through Google's OpenAI-compat surface which is byte-identical to
//! OpenAI's, just with a different base URL and a different model
//! catalogue.
//!
//! Streaming: this first revision returns the full response in a single
//! `stream_chunks` entry so the upstream pipeline can fan it out as one
//! SSE chunk. Real chunk-by-chunk SSE parsing is a follow-up; the
//! placeholder-safe streaming wrapper handles single-chunk emissions
//! correctly.

use crate::{
    http::model_router::ModelTarget,
    providers::{
        ProviderAdapter, ProviderEvent, ProviderEventStream, ProviderFailure, ProviderInvocation,
        ProviderOutput,
    },
};
use async_trait::async_trait;
use futures_util::StreamExt;
use secureprompt_common::types::TokenUsage;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Process-wide HTTP client. `OnceLock` is the cheapest way to lazily
/// initialize a singleton on stable Rust without an extra dep. Returning
/// `&'static reqwest::Client` is fine — `reqwest::Client` is `Clone`-cheap
/// (Arc-wrapped internals) and we never need ownership.
fn shared_http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            // Keep idle connections around for ~90s — long enough that
            // typical chat sessions land on a warm pool.
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(32)
            // HTTP/2 is on by default for HTTPS; explicit TCP keep-alive
            // helps the rare HTTP/1.1 fallbacks.
            .tcp_keepalive(Duration::from_secs(30))
            .build()
            .expect("reqwest::Client build with default-only options cannot fail")
    })
}

/// Generic OpenAI-compatible adapter. The `base_url` is fixed at
/// construction time so we can register one instance per provider_type
/// without doing a runtime lookup on every request.
pub struct OpenAiCompatAdapter {
    /// Static identifier returned to the registry (e.g. "openai", "google").
    provider_type: &'static str,
    /// Base URL for the upstream provider — `/chat/completions` is appended.
    base_url: &'static str,
}

impl OpenAiCompatAdapter {
    #[must_use]
    pub const fn openai() -> Self {
        Self {
            provider_type: "openai",
            base_url: "https://api.openai.com/v1",
        }
    }

    #[must_use]
    pub const fn google() -> Self {
        Self {
            provider_type: "google",
            base_url: "https://generativelanguage.googleapis.com/v1beta/openai",
        }
    }

    /// Resolve the bearer token from the invocation's decrypted credential,
    /// preserving the previous "no credential configured" error behavior.
    fn bearer(&self, invocation: &ProviderInvocation) -> Result<String, ProviderFailure> {
        invocation
            .decrypted_credential
            .as_deref()
            .map(str::to_owned)
            .ok_or_else(|| ProviderFailure {
                message: format!("{}: no credential configured", self.provider_type),
                retryable: false,
            })
    }
}

#[async_trait]
impl ProviderAdapter for OpenAiCompatAdapter {
    fn provider_type(&self) -> &'static str {
        self.provider_type
    }

    async fn complete(
        &self,
        _target: &ModelTarget,
        invocation: &ProviderInvocation,
    ) -> Result<ProviderOutput, ProviderFailure> {
        let bearer = self.bearer(invocation)?;
        let url = format!("{}/chat/completions", self.base_url);
        invoke(self.provider_type, &url, &bearer, &invocation.model, invocation, false).await
    }

    async fn stream(
        &self,
        _target: &ModelTarget,
        invocation: &ProviderInvocation,
    ) -> Result<ProviderOutput, ProviderFailure> {
        // Buffered fallback: fetch the full response in one shot. Retained for
        // callers that still want a complete `ProviderOutput` (and as the
        // default `stream_events` adapter's source). True incremental
        // streaming lives in `stream_events` below.
        let bearer = self.bearer(invocation)?;
        let url = format!("{}/chat/completions", self.base_url);
        invoke(self.provider_type, &url, &bearer, &invocation.model, invocation, true).await
    }

    async fn stream_events(
        &self,
        _target: &ModelTarget,
        invocation: &ProviderInvocation,
    ) -> Result<ProviderEventStream, ProviderFailure> {
        let bearer = self.bearer(invocation)?;
        let url = format!("{}/chat/completions", self.base_url);
        invoke_stream(self.provider_type, &url, &bearer, &invocation.model, invocation).await
    }
}

/// Real upstream SSE streaming. Asks the provider for `stream: true`, then
/// parses the `text/event-stream` body into `ProviderEvent`s as bytes arrive,
/// so the first token can reach the client as soon as the model emits it
/// instead of after the whole answer is generated.
pub(crate) async fn invoke_stream(
    provider_type: &'static str,
    completions_url: &str,
    bearer_token: &str,
    model: &str,
    invocation: &ProviderInvocation,
) -> Result<ProviderEventStream, ProviderFailure> {
    let client = shared_http_client();

    let extra_map = match &invocation.extra_params {
        serde_json::Value::Object(m) => m.clone(),
        _ => serde_json::Map::new(),
    };

    let body = ChatRequest {
        model,
        messages: invocation
            .messages
            .iter()
            .map(|m| ChatMessageBody {
                role: m.role.as_str(),
                content: m.content.as_str(),
            })
            .collect(),
        stream: Some(true), // genuine incremental SSE from upstream
        extra: extra_map,
    };

    let url = completions_url;
    let send_started = Instant::now();
    let response = client
        .post(url)
        .bearer_auth(bearer_token)
        .json(&body)
        .send()
        .await
        .map_err(|e| ProviderFailure {
            message: format!("{provider_type}: HTTP request failed: {e}"),
            retryable: true,
        })?;

    let status = response.status();
    if !status.is_success() {
        let body_text = response.text().await.unwrap_or_default();
        return Err(ProviderFailure {
            message: format!(
                "{provider_type}: HTTP {status}: {}",
                body_text.chars().take(500).collect::<String>()
            ),
            retryable: status.is_server_error(),
        });
    }

    // Parse the SSE body incrementally. We accumulate raw bytes (a single SSE
    // event, or even one UTF-8 codepoint, can straddle TCP chunk boundaries)
    // and split on the `\n\n` event delimiter. Each event's `data:` payload is
    // either an OpenAI `chat.completion.chunk` JSON object or the `[DONE]`
    // sentinel.
    let stream = async_stream::stream! {
        let mut byte_stream = response.bytes_stream();
        let mut buf: Vec<u8> = Vec::new();
        let mut finish_reason: Option<String> = None;
        let mut usage: Option<TokenUsage> = None;
        let mut model: Option<String> = None;
        let mut ttft_ms: Option<u32> = None;
        let mut saw_done = false;

        'outer: while let Some(item) = byte_stream.next().await {
            let bytes = match item {
                Ok(b) => b,
                Err(e) => {
                    yield Err(ProviderFailure {
                        message: format!("{provider_type}: stream read error: {e}"),
                        retryable: true,
                    });
                    return;
                }
            };
            buf.extend_from_slice(&bytes);

            // Drain every complete `\n\n`-delimited event currently in `buf`.
            while let Some(pos) = find_subslice(&buf, b"\n\n") {
                let event_bytes: Vec<u8> = buf.drain(..pos + 2).collect();
                let block = String::from_utf8_lossy(&event_bytes);
                for line in block.lines() {
                    let line = line.trim_start();
                    let Some(payload) = line.strip_prefix("data:") else {
                        continue; // ignore comments / `event:` / `id:` lines
                    };
                    let payload = payload.trim();
                    if payload.is_empty() {
                        continue;
                    }
                    if payload == "[DONE]" {
                        saw_done = true;
                        break 'outer;
                    }
                    let Ok(chunk) = serde_json::from_str::<StreamChunk>(payload) else {
                        continue; // tolerate keep-alive / non-JSON frames
                    };
                    if model.is_none() {
                        model = chunk.model.clone();
                    }
                    if let Some(u) = chunk.usage {
                        usage = Some(TokenUsage {
                            input_tokens: u.prompt_tokens,
                            output_tokens: u.completion_tokens,
                            reasoning_tokens: None,
                            cache_read_tokens: None,
                            cache_write_tokens: None,
                        });
                    }
                    if let Some(choice) = chunk.choices.into_iter().next() {
                        if choice.finish_reason.is_some() {
                            finish_reason = choice.finish_reason;
                        }
                        if let Some(content) = choice.delta.content {
                            if !content.is_empty() {
                                if ttft_ms.is_none() {
                                    ttft_ms = Some(
                                        u32::try_from(send_started.elapsed().as_millis())
                                            .unwrap_or(u32::MAX),
                                    );
                                }
                                yield Ok(ProviderEvent::Token(content));
                            }
                        }
                    }
                }
            }
        }

        let _ = saw_done;
        yield Ok(ProviderEvent::Done {
            usage,
            finish_reason,
            model,
            ttft_ms,
        });
    };

    Ok(Box::pin(stream))
}

/// Byte-slice substring search (no extra deps). Returns the start index of the
/// first occurrence of `needle` in `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[derive(Deserialize)]
struct StreamChunk {
    #[serde(default)]
    choices: Vec<StreamChoice>,
    #[serde(default)]
    usage: Option<UsageBody>,
    #[serde(default)]
    model: Option<String>,
}

#[derive(Deserialize)]
struct StreamChoice {
    #[serde(default)]
    delta: StreamDelta,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Deserialize, Default)]
struct StreamDelta {
    #[serde(default)]
    content: Option<String>,
}

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: Vec<ChatMessageBody<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stream: Option<bool>,
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Serialize)]
struct ChatMessageBody<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Deserialize)]
struct ChatResponse {
    #[serde(default)]
    choices: Vec<Choice>,
    #[serde(default)]
    usage: Option<UsageBody>,
    #[serde(default)]
    model: Option<String>,
}

#[derive(Deserialize)]
struct Choice {
    message: Option<MessageBody>,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct MessageBody {
    #[serde(default)]
    content: Option<String>,
}

#[derive(Deserialize)]
struct UsageBody {
    #[serde(default)]
    prompt_tokens: Option<u32>,
    #[serde(default)]
    completion_tokens: Option<u32>,
}

pub(crate) async fn invoke(
    provider_type: &'static str,
    completions_url: &str,
    bearer_token: &str,
    model: &str,
    invocation: &ProviderInvocation,
    streaming: bool,
) -> Result<ProviderOutput, ProviderFailure> {
    // Reuse a process-wide reqwest::Client so HTTP/2 streams + idle TLS
    // connections are kept alive across requests. Building a fresh client
    // per call paid the full TCP+TLS handshake every time (~50–300ms
    // depending on RTT to the upstream provider) and dominated TTFT for
    // low-latency models. The pool is large enough (32 idle per host) for
    // our concurrency targets without starving providers with smaller
    // server-side limits.
    let client = shared_http_client();

    // Filter `extra_params` to a JSON map (anything that isn't an object
    // becomes empty). The pipeline's `sanitize_extra_params` already
    // strips control fields like `stream` and dangerous keys; what's left
    // is forwarded verbatim (temperature, top_p, etc.).
    let extra_map = match &invocation.extra_params {
        serde_json::Value::Object(m) => m.clone(),
        _ => serde_json::Map::new(),
    };

    let body = ChatRequest {
        model,
        messages: invocation
            .messages
            .iter()
            .map(|m| ChatMessageBody {
                role: m.role.as_str(),
                content: m.content.as_str(),
            })
            .collect(),
        stream: streaming.then_some(false),  // We bridge to single-chunk SSE upstream; ask provider for non-streaming.
        extra: extra_map,
    };

    let url = completions_url;
    let send_started = Instant::now();
    let response = client
        .post(url)
        .bearer_auth(bearer_token)
        .json(&body)
        .send()
        .await
        .map_err(|e| {
            // Network errors are retryable (transient connectivity).
            ProviderFailure {
                message: format!("{provider_type}: HTTP request failed: {e}"),
                retryable: true,
            }
        })?;
    // `reqwest::send().await` resolves once response headers (i.e. first
    // byte) arrive — the body hasn't been read yet. This is the natural
    // TTFT measurement for the upstream call.
    let ttft_ms = u32::try_from(send_started.elapsed().as_millis()).unwrap_or(u32::MAX);

    let status = response.status();
    if !status.is_success() {
        let body_text = response.text().await.unwrap_or_default();
        // 5xx is transient; 4xx is fatal (bad creds, bad model, etc.).
        let retryable = status.is_server_error();
        return Err(ProviderFailure {
            message: format!(
                "{provider_type}: HTTP {status}: {}",
                body_text.chars().take(500).collect::<String>()
            ),
            retryable,
        });
    }

    let parsed: ChatResponse = response.json().await.map_err(|e| ProviderFailure {
        message: format!("{provider_type}: invalid JSON response: {e}"),
        retryable: false,
    })?;

    let first = parsed.choices.into_iter().next();
    let content = first
        .as_ref()
        .and_then(|c| c.message.as_ref())
        .and_then(|m| m.content.clone())
        .unwrap_or_default();
    let finish_reason = first.and_then(|c| c.finish_reason);
    let usage = parsed.usage.map(|u| TokenUsage {
        input_tokens: u.prompt_tokens,
        output_tokens: u.completion_tokens,
        reasoning_tokens: None,
        cache_read_tokens: None,
        cache_write_tokens: None,
    });

    Ok(ProviderOutput {
        content: content.clone(),
        model: parsed.model.unwrap_or_else(|| invocation.model.clone()),
        usage,
        embedding: None,
        // Pipeline-side `placeholder_safe_chunks` wraps this into SSE
        // events when the request was `stream: true`. Single chunk is
        // fine for a non-streaming upstream call.
        stream_chunks: if streaming { vec![content] } else { Vec::new() },
        finish_reason,
        ttft_ms: Some(ttft_ms),
    })
}
