use crate::errors::ApiError;
use crate::types::{
    Detection, Message, PolicyEvent, PolicyResult, ProviderId, ProviderResponse, RequestId,
    TokenUsage, TokenVault, WorkspaceId,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineInput {
    pub request_id: RequestId,
    pub workspace_id: WorkspaceId,
    pub provider_id: ProviderId,
    pub messages: Vec<Message>,
    pub stream: bool,
    pub model: String,
    pub extra_params: serde_json::Value,
}

#[derive(Debug, Default)]
pub struct PipelineState {
    pub vault: TokenVault,
    pub detections: Vec<Detection>,
    pub policy_events: Vec<PolicyEvent>,
    pub redaction_map: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineOutput {
    pub response: ProviderResponse,
    pub usage: TokenUsage,
    pub redaction_map: HashMap<String, String>,
    pub policy_result: PolicyResult,
}

pub async fn run_pipeline(
    _state: &mut PipelineState,
    _input: PipelineInput,
) -> Result<PipelineOutput, ApiError> {
    Err(ApiError::NotImplemented(
        "pipeline not yet implemented — Phase 2 deliverable".into(),
    ))
}
