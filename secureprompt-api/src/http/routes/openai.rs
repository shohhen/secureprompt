use crate::{
    app_state::AppState,
    http::{
        api_error_response,
        middleware::{
            api_key_auth::authenticate_request,
            rate_limit::{
                adjust_workspace_tokens, enforce_rate_limit, estimate_tokens_from_text,
                pre_check_budget, BudgetGate,
            },
        },
        model_router::resolve_model,
        streaming::force_include_usage,
    },
    pipeline::service::{GatewayRequest, PipelineExecution, PipelineService, RequestKind},
};
use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{
        sse::{Event, Sse},
        IntoResponse, Response,
    },
    Json,
};
use std::net::SocketAddr;
use secureprompt_common::types::Message;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::convert::Infallible;
use tokio_stream::iter;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct StreamOptions {
    pub include_usage: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChatCompletionsRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    #[serde(default)]
    pub stream: bool,
    #[serde(default)]
    pub stream_options: Option<StreamOptions>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CompletionRequest {
    pub model: String,
    pub prompt: Value,
    #[serde(default)]
    pub stream: bool,
    #[serde(default)]
    pub stream_options: Option<StreamOptions>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EmbeddingsRequest {
    pub model: String,
    pub input: Value,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

pub async fn chat_completions(
    State(state): State<AppState>,
    ConnectInfo(connect): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<ChatCompletionsRequest>,
) -> Response {
    let auth = match authenticate_request(&headers, &state).await {
        Ok(auth) => auth,
        Err(error) => return api_error_response(error),
    };

    if let Err(error) = enforce_rate_limit(&state, &auth).await {
        return api_error_response(error);
    }

    // Best-effort: forward the device MAC from the LibreChat → gateway
    // hop to users.device_mac so the audit detail page picks it up via
    // the existing user-row join. Idempotent — `IS DISTINCT FROM` skips
    // the write when the value already matches.
    persist_device_mac_header(&state, &auth, &headers).await;

    // Pre-flight budget reservation. Charges the *input* estimate now;
    // the actual total is reconciled post-flight. `behavior=block` returns
    // 402 here, `warn` falls through but flags a header.
    let estimated_input: u64 = request
        .messages
        .iter()
        .map(|m| estimate_tokens_from_text(&m.content))
        .sum();
    let budget_gate = match pre_check_budget(&state, auth.workspace_id.0, estimated_input).await {
        Ok(gate) => gate,
        Err(error) => return api_error_response(error),
    };

    let resolved = match resolve_model(&state, auth.workspace_id, &request.model).await {
        Ok(resolved) => resolved,
        Err(error) => return api_error_response(error),
    };

    let mut extra_params = Value::Object(request.extra.clone());
    if let Some(stream_options) = request.stream_options.clone() {
        extra_params["stream_options"] = json!(stream_options);
    }
    if request.stream {
        force_include_usage(&mut extra_params);
    }

    let client_ip = client_ip_from_headers(&headers).or_else(|| Some(connect.ip().to_string()));
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let service = PipelineService::new(state.clone());
    let execution = service
        .execute(
            &auth,
            &resolved,
            GatewayRequest {
                public_model: request.model.clone(),
                messages: request
                    .messages
                    .into_iter()
                    .map(|message| Message {
                        role: message.role,
                        content: message.content,
                    })
                    .collect(),
                stream: request.stream,
                request_kind: RequestKind::Chat,
                extra_params,
                client_ip,
                user_agent,
            },
        )
        .await;

    match execution {
        Ok(execution) if request.stream => {
            reconcile_workspace_tokens(&state, auth.workspace_id.0, &execution, estimated_input)
                .await;
            with_budget_warning(stream_chat_response(execution), budget_gate)
        }
        Ok(execution) => {
            reconcile_workspace_tokens(&state, auth.workspace_id.0, &execution, estimated_input)
                .await;
            let body = Json(json!({
                "id": execution.request_id.to_string(),
                "object": "chat.completion",
                "created": chrono::Utc::now().timestamp(),
                "model": execution.model,
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": execution.content.clone().unwrap_or_default(),
                    },
                    "finish_reason": execution.finish_reason.clone().unwrap_or_else(|| "stop".to_owned()),
                }],
                "usage": usage_json(&execution),
            }))
            .into_response();
            with_budget_warning(body, budget_gate)
        }
        Err(error) => api_error_response(error),
    }
}

pub async fn completions(
    State(state): State<AppState>,
    ConnectInfo(connect): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<CompletionRequest>,
) -> Response {
    let auth = match authenticate_request(&headers, &state).await {
        Ok(auth) => auth,
        Err(error) => return api_error_response(error),
    };

    if let Err(error) = enforce_rate_limit(&state, &auth).await {
        return api_error_response(error);
    }

    // Best-effort: forward the device MAC from the LibreChat → gateway
    // hop to users.device_mac so the audit detail page picks it up via
    // the existing user-row join. Idempotent — `IS DISTINCT FROM` skips
    // the write when the value already matches.
    persist_device_mac_header(&state, &auth, &headers).await;

    let prompt = value_to_string(&request.prompt);
    let estimated_input = estimate_tokens_from_text(&prompt);
    let budget_gate = match pre_check_budget(&state, auth.workspace_id.0, estimated_input).await {
        Ok(gate) => gate,
        Err(error) => return api_error_response(error),
    };

    let resolved = match resolve_model(&state, auth.workspace_id, &request.model).await {
        Ok(resolved) => resolved,
        Err(error) => return api_error_response(error),
    };

    let mut extra_params = Value::Object(request.extra.clone());
    if let Some(stream_options) = request.stream_options.clone() {
        extra_params["stream_options"] = json!(stream_options);
    }
    if request.stream {
        force_include_usage(&mut extra_params);
    }

    let client_ip = client_ip_from_headers(&headers).or_else(|| Some(connect.ip().to_string()));
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let service = PipelineService::new(state.clone());
    let execution = service
        .execute(
            &auth,
            &resolved,
            GatewayRequest {
                public_model: request.model.clone(),
                messages: vec![Message {
                    role: "user".to_owned(),
                    content: prompt,
                }],
                stream: request.stream,
                request_kind: RequestKind::Completion,
                extra_params,
                client_ip,
                user_agent,
            },
        )
        .await;

    match execution {
        Ok(execution) if request.stream => {
            reconcile_workspace_tokens(&state, auth.workspace_id.0, &execution, estimated_input)
                .await;
            with_budget_warning(stream_completion_response(execution), budget_gate)
        }
        Ok(execution) => {
            reconcile_workspace_tokens(&state, auth.workspace_id.0, &execution, estimated_input)
                .await;
            let body = Json(json!({
                "id": execution.request_id.to_string(),
                "object": "text_completion",
                "created": chrono::Utc::now().timestamp(),
                "model": execution.model,
                "choices": [{
                    "index": 0,
                    "text": execution.content.clone().unwrap_or_default(),
                    "finish_reason": execution.finish_reason.clone().unwrap_or_else(|| "stop".to_owned()),
                }],
                "usage": usage_json(&execution),
            }))
            .into_response();
            with_budget_warning(body, budget_gate)
        }
        Err(error) => api_error_response(error),
    }
}

pub async fn embeddings(
    State(state): State<AppState>,
    ConnectInfo(connect): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<EmbeddingsRequest>,
) -> Response {
    let auth = match authenticate_request(&headers, &state).await {
        Ok(auth) => auth,
        Err(error) => return api_error_response(error),
    };

    if let Err(error) = enforce_rate_limit(&state, &auth).await {
        return api_error_response(error);
    }

    // Best-effort: forward the device MAC from the LibreChat → gateway
    // hop to users.device_mac so the audit detail page picks it up via
    // the existing user-row join. Idempotent — `IS DISTINCT FROM` skips
    // the write when the value already matches.
    persist_device_mac_header(&state, &auth, &headers).await;

    let input_text = value_to_string(&request.input);
    let estimated_input = estimate_tokens_from_text(&input_text);
    let budget_gate = match pre_check_budget(&state, auth.workspace_id.0, estimated_input).await {
        Ok(gate) => gate,
        Err(error) => return api_error_response(error),
    };

    let resolved = match resolve_model(&state, auth.workspace_id, &request.model).await {
        Ok(resolved) => resolved,
        Err(error) => return api_error_response(error),
    };

    let client_ip = client_ip_from_headers(&headers).or_else(|| Some(connect.ip().to_string()));
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let execution = PipelineService::new(state.clone())
        .execute(
            &auth,
            &resolved,
            GatewayRequest {
                public_model: request.model.clone(),
                messages: vec![Message {
                    role: "user".to_owned(),
                    content: input_text,
                }],
                stream: false,
                request_kind: RequestKind::Embedding,
                extra_params: Value::Object(request.extra.clone()),
                client_ip,
                user_agent,
            },
        )
        .await;

    match execution {
        Ok(execution) => {
            reconcile_workspace_tokens(&state, auth.workspace_id.0, &execution, estimated_input)
                .await;
            let body = Json(json!({
                "object": "list",
                "data": [{
                    "object": "embedding",
                    "index": 0,
                    "embedding": execution.embedding.clone().unwrap_or_default(),
                }],
                "model": execution.model,
                "usage": usage_json(&execution),
            }))
            .into_response();
            with_budget_warning(body, budget_gate)
        }
        Err(error) => api_error_response(error),
    }
}

/// Sum of input + output tokens for a completed pipeline execution.
/// Reasoning + cache tokens are reported separately in `usage_json` but
/// are not counted toward the workspace budget — operators care about
/// the prompt+completion total, which matches OpenAI's `total_tokens`.
fn total_tokens(execution: &PipelineExecution) -> u64 {
    let input = u64::from(execution.usage.input_tokens.unwrap_or_default());
    let output = u64::from(execution.usage.output_tokens.unwrap_or_default());
    input + output
}

/// Reconcile the pre-flight estimate against the actual token total.
///
/// `pre_check_budget` charged `estimated_input_tokens` into the daily +
/// monthly Redis counters during reservation. The provider then returned
/// real input + output figures via `usage`. This applies a **delta**
/// (`actual_total − estimate`) so the counter ends up matching what
/// the dashboard expects (= actual usage). Negative deltas are valid —
/// `INCRBY` accepts them and counters go down.
async fn reconcile_workspace_tokens(
    state: &AppState,
    workspace_id: uuid::Uuid,
    execution: &PipelineExecution,
    estimated_input_tokens: u64,
) {
    let actual = total_tokens(execution);
    let est = i64::try_from(estimated_input_tokens).unwrap_or(i64::MAX);
    let actual_i = i64::try_from(actual).unwrap_or(i64::MAX);
    let delta = actual_i - est;
    adjust_workspace_tokens(state, workspace_id, delta).await;
}

/// If the pre-flight check returned a `Warn`, attach the
/// `x-secureprompt-budget-warning: daily|monthly` header so clients
/// (LibreChat, dashboards, downstream tooling) can surface it visibly.
fn with_budget_warning(mut response: Response, gate: BudgetGate) -> Response {
    if let Some(bucket) = gate.warning_bucket() {
        if let Ok(value) = HeaderValue::from_str(bucket) {
            response
                .headers_mut()
                .insert("x-secureprompt-budget-warning", value);
        }
    }
    response
}

pub async fn metrics(State(state): State<AppState>) -> Response {
    let output = state.metrics.render_prometheus() + &state.ml_sidecar.render_prometheus();
    (StatusCode::OK, output).into_response()
}

fn stream_chat_response(execution: PipelineExecution) -> Response {
    let created = chrono::Utc::now().timestamp();
    let model = execution.model.clone();
    let request_id = execution.request_id.to_string();
    let usage = usage_json(&execution);
    let mut events = Vec::new();

    for chunk in execution.stream_chunks {
        events.push(
            Event::default().data(
                json!({
                    "id": request_id,
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": model,
                    "choices": [{
                        "index": 0,
                        "delta": {
                            "content": chunk,
                        },
                        "finish_reason": Value::Null,
                    }]
                })
                .to_string(),
            ),
        );
    }

    events.push(
        Event::default().data(
            json!({
                "id": execution.request_id.to_string(),
                "object": "chat.completion.chunk",
                "created": created,
                "model": execution.model,
                "choices": [],
                "usage": usage,
            })
            .to_string(),
        ),
    );
    events.push(Event::default().data("[DONE]"));

    Sse::new(iter(events.into_iter().map(Ok::<_, Infallible>))).into_response()
}

fn stream_completion_response(execution: PipelineExecution) -> Response {
    let created = chrono::Utc::now().timestamp();
    let model = execution.model.clone();
    let request_id = execution.request_id.to_string();
    let usage = usage_json(&execution);
    let mut events = Vec::new();

    for chunk in execution.stream_chunks {
        events.push(
            Event::default().data(
                json!({
                    "id": request_id,
                    "object": "text_completion",
                    "created": created,
                    "model": model,
                    "choices": [{
                        "index": 0,
                        "text": chunk,
                        "finish_reason": Value::Null,
                    }]
                })
                .to_string(),
            ),
        );
    }

    events.push(
        Event::default().data(
            json!({
                "id": execution.request_id.to_string(),
                "object": "text_completion",
                "created": created,
                "model": execution.model,
                "choices": [],
                "usage": usage,
            })
            .to_string(),
        ),
    );
    events.push(Event::default().data("[DONE]"));

    Sse::new(iter(events.into_iter().map(Ok::<_, Infallible>))).into_response()
}

fn usage_json(execution: &PipelineExecution) -> Value {
    json!({
        "prompt_tokens": execution.usage.input_tokens.unwrap_or_default(),
        "completion_tokens": execution.usage.output_tokens.unwrap_or_default(),
        "total_tokens": execution.usage.input_tokens.unwrap_or_default()
            + execution.usage.output_tokens.unwrap_or_default(),
        "reasoning_tokens": execution.usage.reasoning_tokens.unwrap_or_default(),
        "cache_read_tokens": execution.usage.cache_read_tokens.unwrap_or_default(),
        "cache_write_tokens": execution.usage.cache_write_tokens.unwrap_or_default(),
        "estimated": execution.estimated_usage,
    })
}

/// Pull the self-reported `X-SecurePrompt-Device-MAC` header off an
/// incoming gateway request and best-effort persist it to the caller's
/// user row. Validates the same shape `/v1/me/profile` does (12 hex
/// digits, `:` or `-` separated, length-capped) and silently drops
/// anything that doesn't look like a MAC. Postgres write is fire-and-
/// forget — gateway latency is more important than a missed audit aid.
async fn persist_device_mac_header(
    state: &AppState,
    auth: &crate::http::middleware::api_key_auth::AuthContext,
    headers: &HeaderMap,
) {
    let raw = match headers.get("x-secureprompt-device-mac") {
        Some(h) => h.to_str().unwrap_or("").trim(),
        None => return,
    };
    if raw.is_empty() || raw.len() > 64 {
        return;
    }
    let normalised = raw.replace('-', ":").to_ascii_lowercase();
    let parts: Vec<&str> = normalised.split(':').collect();
    if parts.len() != 6
        || !parts.iter().all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return;
    }
    let user_id = match auth.user_id {
        Some(id) => id,
        None => return,
    };
    let workspace_id = auth.workspace_id.0;
    // `IS DISTINCT FROM` short-circuits when the value already matches —
    // skips a wal write per chat turn for the steady-state case where
    // the MAC hasn't changed since last time.
    if let Err(e) = sqlx::query(
        "UPDATE users SET device_mac = $1, updated_at = NOW()
         WHERE id = $2 AND workspace_id = $3 AND device_mac IS DISTINCT FROM $1",
    )
    .bind(&normalised)
    .bind(user_id)
    .bind(workspace_id)
    .execute(&state.db)
    .await
    {
        tracing::warn!(error = %e, user_id = %user_id, "device_mac update from gateway header failed");
    }
}

/// Extract the originating client IP from headers. Behind nginx (the
/// supported on-prem topology) the real address is in `X-Forwarded-For`
/// — first value of the comma-separated list. Falls back to `X-Real-IP`
/// when nginx is configured to set only that, then to `None` when neither
/// header is present (direct curl in dev). The router is bound without
/// `into_make_service_with_connect_info`, so `ConnectInfo` is unavailable.
fn client_ip_from_headers(headers: &HeaderMap) -> Option<String> {
    if let Some(forwarded) = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
    {
        let trimmed = forwarded.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_owned());
        }
    }
    headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

fn value_to_string(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Array(items) => items
            .iter()
            .map(value_to_string)
            .collect::<Vec<_>>()
            .join("\n"),
        _ => value.to_string(),
    }
}

#[cfg(test)]
mod response_shape_tests {
    /// Unit tests for GATE-01, GATE-02, GATE-03:
    /// Verify that each route produces the correct OpenAI-compatible `object` field
    /// value in its JSON response — without requiring a database connection.
    ///
    /// Strategy: build PipelineExecution values directly (no AppState / DB needed)
    /// and replicate the identical json!() constructs used by the handlers to assert
    /// the `object` field values are correct.
    use super::*;
    use secureprompt_common::{
        pipeline::PipelineOutput,
        types::{PolicyResult, ProviderResponse, RequestId, TokenUsage},
    };
    use std::collections::HashMap;

    /// Build a minimal PipelineExecution suitable for non-streaming response tests.
    fn make_execution(model: &str, content: Option<&str>) -> PipelineExecution {
        let usage = TokenUsage {
            input_tokens: Some(5),
            output_tokens: Some(10),
            reasoning_tokens: Some(0),
            cache_read_tokens: Some(0),
            cache_write_tokens: Some(0),
        };
        PipelineExecution {
            request_id: RequestId::new(),
            provider_name: "openai".to_owned(),
            model: model.to_owned(),
            content: content.map(str::to_owned),
            embedding: None,
            usage: usage.clone(),
            estimated_usage: false,
            stream_chunks: Vec::new(),
            finish_reason: Some("stop".to_owned()),
            pipeline_output: PipelineOutput {
                response: ProviderResponse {
                    content: content.unwrap_or_default().to_owned(),
                    model: model.to_owned(),
                    finish_reason: Some("stop".to_owned()),
                    embedding: None,
                },
                usage,
                redaction_map: HashMap::new(),
                policy_result: PolicyResult::default(),
            },
        }
    }

    /// Build a minimal PipelineExecution for an embeddings response.
    fn make_embedding_execution(model: &str) -> PipelineExecution {
        let usage = TokenUsage {
            input_tokens: Some(3),
            output_tokens: Some(0),
            reasoning_tokens: Some(0),
            cache_read_tokens: Some(0),
            cache_write_tokens: Some(0),
        };
        PipelineExecution {
            request_id: RequestId::new(),
            provider_name: "openai".to_owned(),
            model: model.to_owned(),
            content: None,
            embedding: Some(vec![0.1_f32, 0.2_f32, 0.3_f32]),
            usage: usage.clone(),
            estimated_usage: false,
            stream_chunks: Vec::new(),
            finish_reason: None,
            pipeline_output: PipelineOutput {
                response: ProviderResponse {
                    content: String::new(),
                    model: model.to_owned(),
                    finish_reason: None,
                    embedding: Some(vec![0.1_f32, 0.2_f32, 0.3_f32]),
                },
                usage,
                redaction_map: HashMap::new(),
                policy_result: PolicyResult::default(),
            },
        }
    }

    // -------------------------------------------------------------------------
    // GATE-01: /v1/chat/completions — object field must be "chat.completion"
    // -------------------------------------------------------------------------

    #[test]
    fn chat_completion_response_object_field_is_chat_dot_completion() {
        let execution = make_execution("gpt-4o-mini", Some("Hello, world!"));
        let body = json!({
            "id": execution.request_id.to_string(),
            "object": "chat.completion",
            "created": chrono::Utc::now().timestamp(),
            "model": execution.model,
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": execution.content.clone().unwrap_or_default(),
                },
                "finish_reason": execution.finish_reason.clone().unwrap_or_else(|| "stop".to_owned()),
            }],
            "usage": usage_json(&execution),
        });

        assert_eq!(
            body["object"].as_str(),
            Some("chat.completion"),
            "GATE-01: /v1/chat/completions must return object=chat.completion"
        );
    }

    #[test]
    fn chat_completion_response_model_field_is_preserved() {
        let execution = make_execution("gpt-4o-mini", Some("content"));
        let body = json!({
            "id": execution.request_id.to_string(),
            "object": "chat.completion",
            "created": chrono::Utc::now().timestamp(),
            "model": execution.model,
            "choices": [],
            "usage": usage_json(&execution),
        });

        assert_eq!(body["model"].as_str(), Some("gpt-4o-mini"));
    }

    #[test]
    fn chat_completion_response_choices_have_message_role_assistant() {
        let execution = make_execution("gpt-4o", Some("hi"));
        let body = json!({
            "id": execution.request_id.to_string(),
            "object": "chat.completion",
            "created": 0_i64,
            "model": execution.model,
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": execution.content.clone().unwrap_or_default(),
                },
                "finish_reason": execution.finish_reason.clone().unwrap_or_else(|| "stop".to_owned()),
            }],
            "usage": usage_json(&execution),
        });

        assert_eq!(
            body["choices"][0]["message"]["role"].as_str(),
            Some("assistant"),
            "GATE-01: choices[0].message.role must be assistant"
        );
        assert_eq!(
            body["choices"][0]["finish_reason"].as_str(),
            Some("stop"),
        );
    }

    // -------------------------------------------------------------------------
    // GATE-02: /v1/completions — object field must be "text_completion"
    // -------------------------------------------------------------------------

    #[test]
    fn completions_response_object_field_is_text_completion() {
        let execution = make_execution("gpt-3.5-turbo-instruct", Some("legacy text"));
        let body = json!({
            "id": execution.request_id.to_string(),
            "object": "text_completion",
            "created": chrono::Utc::now().timestamp(),
            "model": execution.model,
            "choices": [{
                "index": 0,
                "text": execution.content.clone().unwrap_or_default(),
                "finish_reason": execution.finish_reason.clone().unwrap_or_else(|| "stop".to_owned()),
            }],
            "usage": usage_json(&execution),
        });

        assert_eq!(
            body["object"].as_str(),
            Some("text_completion"),
            "GATE-02: /v1/completions must return object=text_completion"
        );
    }

    #[test]
    fn completions_response_choices_have_text_field_not_message() {
        let execution = make_execution("gpt-3.5-turbo-instruct", Some("generated text"));
        let body = json!({
            "id": execution.request_id.to_string(),
            "object": "text_completion",
            "created": 0_i64,
            "model": execution.model,
            "choices": [{
                "index": 0,
                "text": execution.content.clone().unwrap_or_default(),
                "finish_reason": execution.finish_reason.clone().unwrap_or_else(|| "stop".to_owned()),
            }],
            "usage": usage_json(&execution),
        });

        assert_eq!(
            body["choices"][0]["text"].as_str(),
            Some("generated text"),
            "GATE-02: /v1/completions choices must use 'text' field, not 'message'"
        );
        assert!(
            body["choices"][0]["message"].is_null(),
            "GATE-02: /v1/completions choices must NOT have a 'message' field"
        );
    }

    // -------------------------------------------------------------------------
    // GATE-03: /v1/embeddings — top-level object must be "list",
    //          data[0].object must be "embedding"
    // -------------------------------------------------------------------------

    #[test]
    fn embeddings_response_object_field_is_list() {
        let execution = make_embedding_execution("text-embedding-3-small");
        let body = json!({
            "object": "list",
            "data": [{
                "object": "embedding",
                "index": 0,
                "embedding": execution.embedding.clone().unwrap_or_default(),
            }],
            "model": execution.model,
            "usage": usage_json(&execution),
        });

        assert_eq!(
            body["object"].as_str(),
            Some("list"),
            "GATE-03: /v1/embeddings top-level object must be 'list'"
        );
    }

    #[test]
    fn embeddings_response_data_item_object_field_is_embedding() {
        let execution = make_embedding_execution("text-embedding-3-small");
        let body = json!({
            "object": "list",
            "data": [{
                "object": "embedding",
                "index": 0,
                "embedding": execution.embedding.clone().unwrap_or_default(),
            }],
            "model": execution.model,
            "usage": usage_json(&execution),
        });

        assert_eq!(
            body["data"][0]["object"].as_str(),
            Some("embedding"),
            "GATE-03: /v1/embeddings data[0].object must be 'embedding'"
        );
        assert!(
            body["data"][0]["embedding"].as_array().is_some(),
            "GATE-03: /v1/embeddings data[0].embedding must be an array"
        );
    }

    // -------------------------------------------------------------------------
    // SSE streaming chunk object fields (stream_chat_response / stream_completion_response)
    // -------------------------------------------------------------------------

    #[test]
    fn stream_chat_chunk_object_field_is_chat_completion_chunk() {
        let request_id = RequestId::new().to_string();
        let model = "gpt-4o-mini";
        let chunk = "hello";

        let event_data = json!({
            "id": request_id,
            "object": "chat.completion.chunk",
            "created": 0_i64,
            "model": model,
            "choices": [{
                "index": 0,
                "delta": { "content": chunk },
                "finish_reason": Value::Null,
            }]
        });

        assert_eq!(
            event_data["object"].as_str(),
            Some("chat.completion.chunk"),
            "GATE-01 streaming: SSE chunk object must be 'chat.completion.chunk'"
        );
    }

    #[test]
    fn stream_completion_chunk_object_field_is_text_completion() {
        let request_id = RequestId::new().to_string();
        let model = "gpt-3.5-turbo-instruct";
        let chunk = "word";

        let event_data = json!({
            "id": request_id,
            "object": "text_completion",
            "created": 0_i64,
            "model": model,
            "choices": [{
                "index": 0,
                "text": chunk,
                "finish_reason": Value::Null,
            }]
        });

        assert_eq!(
            event_data["object"].as_str(),
            Some("text_completion"),
            "GATE-02 streaming: SSE chunk object must be 'text_completion'"
        );
    }

    // -------------------------------------------------------------------------
    // usage_json helper produces all required fields
    // -------------------------------------------------------------------------

    #[test]
    fn usage_json_contains_all_required_openai_fields() {
        let execution = make_execution("gpt-4o", Some("content"));
        let usage = usage_json(&execution);

        assert!(usage["prompt_tokens"].is_number(), "usage must have prompt_tokens");
        assert!(usage["completion_tokens"].is_number(), "usage must have completion_tokens");
        assert!(usage["total_tokens"].is_number(), "usage must have total_tokens");
        assert_eq!(
            usage["total_tokens"].as_u64(),
            Some(15),
            "total_tokens must equal input + output (5 + 10)"
        );
    }

    // -------------------------------------------------------------------------
    // value_to_string handles string, array, and other JSON values
    // -------------------------------------------------------------------------

    #[test]
    fn value_to_string_converts_string_json() {
        let v = Value::String("hello world".to_owned());
        assert_eq!(value_to_string(&v), "hello world");
    }

    #[test]
    fn value_to_string_joins_array_with_newlines() {
        let v = serde_json::json!(["line1", "line2", "line3"]);
        assert_eq!(value_to_string(&v), "line1\nline2\nline3");
    }

    #[test]
    fn value_to_string_stringifies_number() {
        let v = serde_json::json!(42);
        assert_eq!(value_to_string(&v), "42");
    }
}
