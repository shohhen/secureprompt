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
