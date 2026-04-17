use crate::{
    analytics::events::RequestEvent,
    app_state::AppState,
    detection::detect_content,
    http::{
        middleware::api_key_auth::AuthContext,
        model_router::{ModelTarget, ResolvedModel},
        streaming::placeholder_safe_chunks,
    },
    observability::tracing::{log_request_finish, log_request_start},
    policy::engine::{evaluate, PolicyEvaluationInput},
    providers::{sanitize_extra_params, InvocationKind, ProviderInvocation},
    token_usage::dispatch::{derive_usage, UsageComputation},
    vault::restore_content,
};
use secureprompt_common::{
    errors::ApiError,
    pipeline::{PipelineInput, PipelineOutput, PipelineState},
    types::{Message, ProviderResponse, RequestId, TokenUsage},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    Chat,
    Completion,
    Embedding,
}

#[derive(Debug, Clone)]
pub struct GatewayRequest {
    pub public_model: String,
    pub messages: Vec<Message>,
    pub stream: bool,
    pub request_kind: RequestKind,
    pub extra_params: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct PipelineExecution {
    pub request_id: RequestId,
    pub provider_name: String,
    pub model: String,
    pub content: Option<String>,
    pub embedding: Option<Vec<f32>>,
    pub usage: TokenUsage,
    pub estimated_usage: bool,
    pub stream_chunks: Vec<String>,
    pub finish_reason: Option<String>,
    pub pipeline_output: PipelineOutput,
}

#[derive(Clone)]
pub struct PipelineService {
    state: AppState,
}

impl PipelineService {
    #[must_use]
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    pub async fn execute(
        &self,
        auth: &AuthContext,
        resolved: &ResolvedModel,
        request: GatewayRequest,
    ) -> Result<PipelineExecution, ApiError> {
        let request_id = RequestId::new();
        let prompt = prompt_from_messages(&request.messages);
        let mut pipeline_state = PipelineState::default();
        pipeline_state.detections = detect_content(&prompt);

        log_request_start(request_id, auth.workspace_id, &request.public_model);

        let policy_repo = crate::db::PolicyRepository::new(self.state.db.clone());
        let primary_provider_name = resolved
            .targets
            .first()
            .map(|target| target.provider_name.as_str())
            .unwrap_or("unconfigured");

        let policy_outcome = evaluate(
            &policy_repo,
            PolicyEvaluationInput {
                request_id,
                workspace_id: auth.workspace_id,
                provider_name: primary_provider_name,
                model: &request.public_model,
                content: &prompt,
                detections: &pipeline_state.detections,
            },
            &mut pipeline_state.vault,
            &mut pipeline_state.redaction_map,
        )
        .await?;

        if policy_outcome.denied {
            let usage = TokenUsage::default();
            let cost_usd = self
                .state
                .pricing
                .compute_cost(&request.public_model, &usage);
            let event = RequestEvent::new(
                request_id,
                auth.workspace_id,
                primary_provider_name.to_owned(),
                request.public_model.clone(),
                policy_outcome.result.final_action.clone(),
                &usage,
                false,
                cost_usd,
                policy_outcome.result.events.clone(),
            );
            self.state
                .analytics
                .enqueue(event, self.state.metrics.as_ref())
                .await;
            self.state.metrics.record_request(false);
            log_request_finish(
                request_id,
                auth.workspace_id,
                &policy_outcome.result.final_action,
                false,
            );
            return Err(ApiError::Forbidden("request denied by policy".into()));
        }

        let sanitized_messages = vec![Message {
            role: "user".to_owned(),
            content: policy_outcome.content.clone(),
        }];

        let pipeline_input = PipelineInput {
            request_id,
            workspace_id: auth.workspace_id,
            provider_id: resolved.targets[0].provider_id,
            messages: sanitized_messages.clone(),
            stream: request.stream,
            model: request.public_model.clone(),
            extra_params: request.extra_params.clone(),
        };

        let (chosen_target, provider_output) = self
            .invoke_provider_chain(&resolved.targets, &request, &pipeline_input)
            .await?;

        let restored_content =
            if provider_output.embedding.is_some() && provider_output.content.is_empty() {
                None
            } else {
                Some(restore_content(
                    &provider_output.content,
                    &pipeline_state.vault,
                ))
            };

        let UsageComputation { usage, estimated } = derive_usage(
            &chosen_target.provider_type,
            provider_output.usage.clone(),
            &policy_outcome.content,
            restored_content.as_deref().unwrap_or_default(),
        );
        let cost_usd = self
            .state
            .pricing
            .compute_cost(&request.public_model, &usage);

        let stream_chunks = if request.stream {
            let raw_chunks = if provider_output.stream_chunks.is_empty() {
                restored_content
                    .clone()
                    .map(|content| vec![content])
                    .unwrap_or_default()
            } else {
                provider_output.stream_chunks.clone()
            };
            placeholder_safe_chunks(&raw_chunks, &pipeline_state.vault)
        } else {
            Vec::new()
        };

        let response = ProviderResponse {
            content: restored_content.clone().unwrap_or_default(),
            model: chosen_target.model_name.clone(),
            finish_reason: provider_output.finish_reason.clone(),
            embedding: provider_output.embedding.clone(),
        };

        let pipeline_output = PipelineOutput {
            response,
            usage: usage.clone(),
            redaction_map: pipeline_state.redaction_map.clone(),
            policy_result: policy_outcome.result.clone(),
        };

        let event = RequestEvent::new(
            request_id,
            auth.workspace_id,
            chosen_target.provider_name.clone(),
            request.public_model.clone(),
            policy_outcome.result.final_action.clone(),
            &usage,
            estimated,
            cost_usd,
            policy_outcome.result.events.clone(),
        );
        self.state
            .analytics
            .enqueue(event, self.state.metrics.as_ref())
            .await;

        self.state.metrics.record_request(true);
        log_request_finish(
            request_id,
            auth.workspace_id,
            &policy_outcome.result.final_action,
            true,
        );

        Ok(PipelineExecution {
            request_id,
            provider_name: chosen_target.provider_name.clone(),
            model: chosen_target.model_name.clone(),
            content: restored_content,
            embedding: provider_output.embedding.clone(),
            usage,
            estimated_usage: estimated,
            stream_chunks,
            finish_reason: provider_output.finish_reason.clone(),
            pipeline_output,
        })
    }

    async fn invoke_provider_chain(
        &self,
        targets: &[ModelTarget],
        request: &GatewayRequest,
        pipeline_input: &PipelineInput,
    ) -> Result<(ModelTarget, crate::providers::ProviderOutput), ApiError> {
        let kind = match request.request_kind {
            RequestKind::Chat => InvocationKind::Chat,
            RequestKind::Completion => InvocationKind::Completion,
            RequestKind::Embedding => InvocationKind::Embedding,
        };

        let invocation = ProviderInvocation {
            request_id: pipeline_input.request_id,
            model: pipeline_input.model.clone(),
            prompt: prompt_from_messages(&pipeline_input.messages),
            messages: pipeline_input.messages.clone(),
            extra_params: sanitize_extra_params(pipeline_input.extra_params.clone()),
            stream: pipeline_input.stream,
            kind,
        };

        let mut last_retryable_error = None;

        for target in targets {
            let Some(adapter) = self
                .state
                .providers
                .adapter_for(&target.provider_type)
                .await
            else {
                continue;
            };

            let result = if request.stream {
                adapter.stream(target, &invocation).await
            } else {
                adapter.complete(target, &invocation).await
            };

            match result {
                Ok(output) => return Ok((target.clone(), output)),
                Err(error) if error.retryable => {
                    tracing::warn!(
                        provider = target.provider_name,
                        message = error.message,
                        "retryable provider failure; trying fallback before first byte"
                    );
                    last_retryable_error = Some(error.message);
                }
                Err(error) => {
                    return Err(ApiError::Internal(error.message));
                }
            }
        }

        Err(ApiError::Internal(
            last_retryable_error.unwrap_or_else(|| "all providers failed".to_owned()),
        ))
    }
}

fn prompt_from_messages(messages: &[Message]) -> String {
    messages
        .iter()
        .map(|message| message.content.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}
