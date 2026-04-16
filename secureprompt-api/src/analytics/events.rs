use secureprompt_common::types::{PolicyEvent, RequestId, TokenUsage, WorkspaceId};

#[derive(Debug, Clone)]
pub struct RequestEvent {
    pub request_id: RequestId,
    pub workspace_id: WorkspaceId,
    pub provider: String,
    pub model: String,
    pub final_action: String,
    pub input_tokens: Option<u32>,
    pub output_tokens: Option<u32>,
    pub reasoning_tokens: Option<u32>,
    pub cache_read_tokens: Option<u32>,
    pub cache_write_tokens: Option<u32>,
    pub estimated_usage: bool,
    pub cost_usd: f64,
    pub policy_events: Vec<PolicyEvent>,
}

impl RequestEvent {
    #[must_use]
    pub fn new(
        request_id: RequestId,
        workspace_id: WorkspaceId,
        provider: String,
        model: String,
        final_action: String,
        usage: &TokenUsage,
        estimated_usage: bool,
        cost_usd: f64,
        policy_events: Vec<PolicyEvent>,
    ) -> Self {
        Self {
            request_id,
            workspace_id,
            provider,
            model,
            final_action,
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
            reasoning_tokens: usage.reasoning_tokens,
            cache_read_tokens: usage.cache_read_tokens,
            cache_write_tokens: usage.cache_write_tokens,
            estimated_usage,
            cost_usd,
            policy_events,
        }
    }
}
