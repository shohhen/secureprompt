use crate::{
    app_state::AppState,
    http::{
        api_error_response,
        middleware::{api_key_auth::authenticate_request, rate_limit::enforce_rate_limit},
        model_router::resolve_model,
        streaming::force_include_usage,
    },
    pipeline::service::{GatewayRequest, PipelineExecution, PipelineService, RequestKind},
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{
        sse::{Event, Sse},
        IntoResponse, Response,
    },
    Json,
};
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
            },
        )
        .await;

    match execution {
        Ok(execution) if request.stream => stream_chat_response(execution),
        Ok(execution) => Json(json!({
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
        .into_response(),
        Err(error) => api_error_response(error),
    }
}

pub async fn completions(
    State(state): State<AppState>,
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

    let service = PipelineService::new(state.clone());
    let prompt = value_to_string(&request.prompt);
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
            },
        )
        .await;

    match execution {
        Ok(execution) if request.stream => stream_completion_response(execution),
        Ok(execution) => Json(json!({
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
        .into_response(),
        Err(error) => api_error_response(error),
    }
}

pub async fn embeddings(
    State(state): State<AppState>,
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

    let resolved = match resolve_model(&state, auth.workspace_id, &request.model).await {
        Ok(resolved) => resolved,
        Err(error) => return api_error_response(error),
    };

    let execution = PipelineService::new(state.clone())
        .execute(
            &auth,
            &resolved,
            GatewayRequest {
                public_model: request.model.clone(),
                messages: vec![Message {
                    role: "user".to_owned(),
                    content: value_to_string(&request.input),
                }],
                stream: false,
                request_kind: RequestKind::Embedding,
                extra_params: Value::Object(request.extra.clone()),
            },
        )
        .await;

    match execution {
        Ok(execution) => Json(json!({
            "object": "list",
            "data": [{
                "object": "embedding",
                "index": 0,
                "embedding": execution.embedding.clone().unwrap_or_default(),
            }],
            "model": execution.model,
            "usage": usage_json(&execution),
        }))
        .into_response(),
        Err(error) => api_error_response(error),
    }
}

pub async fn metrics(State(state): State<AppState>) -> Response {
    (StatusCode::OK, state.metrics.render_prometheus()).into_response()
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
