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
    pub latency_ms: Option<u32>,
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
            latency_ms: None,
        }
    }
}

use clickhouse::Row;
use serde::Serialize;

#[derive(Row, Serialize)]
pub struct RequestEventRow {
    #[serde(with = "clickhouse::serde::uuid")]
    pub request_id: uuid::Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    pub workspace_id: uuid::Uuid,
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
    #[serde(with = "clickhouse::serde::chrono::datetime")]
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl RequestEventRow {
    pub fn from_event(e: &RequestEvent, created_at: chrono::DateTime<chrono::Utc>) -> Self {
        Self {
            request_id: e.request_id.0,
            workspace_id: e.workspace_id.0,
            provider: e.provider.clone(),
            model: e.model.clone(),
            final_action: e.final_action.clone(),
            input_tokens: e.input_tokens,
            output_tokens: e.output_tokens,
            reasoning_tokens: e.reasoning_tokens,
            cache_read_tokens: e.cache_read_tokens,
            cache_write_tokens: e.cache_write_tokens,
            estimated_usage: e.estimated_usage,
            cost_usd: e.cost_usd,
            created_at,
        }
    }
}

#[derive(Row, Serialize)]
pub struct PolicyEventRow {
    #[serde(with = "clickhouse::serde::uuid")]
    pub request_id: uuid::Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    pub workspace_id: uuid::Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    pub rule_id: uuid::Uuid,
    pub rule_name: String,
    pub action: String,
    pub dry_run: bool,
    #[serde(with = "clickhouse::serde::chrono::datetime")]
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl PolicyEventRow {
    pub fn from_policy_event(
        pe: &secureprompt_common::types::PolicyEvent,
        request_id: uuid::Uuid,
        workspace_id: uuid::Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        Self {
            request_id,
            workspace_id,
            rule_id: pe.rule_id,
            rule_name: pe.rule_name.clone(),
            action: pe.action.clone(),
            dry_run: pe.dry_run,
            created_at,
        }
    }
}

#[derive(Row, Serialize)]
pub struct LatencySampleRow {
    #[serde(with = "clickhouse::serde::uuid")]
    pub request_id: uuid::Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    pub workspace_id: uuid::Uuid,
    pub model: String,
    pub latency_ms: u32,
    #[serde(with = "clickhouse::serde::chrono::datetime")]
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Row, Serialize)]
pub struct TokenUsageRow {
    #[serde(with = "clickhouse::serde::uuid")]
    pub workspace_id: uuid::Uuid,
    pub model: String,
    #[serde(with = "clickhouse::serde::chrono::date32")]
    pub date: chrono::NaiveDate,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_usd: f64,
}

impl TokenUsageRow {
    pub fn from_event(e: &RequestEvent, date: chrono::NaiveDate) -> Self {
        Self {
            workspace_id: e.workspace_id.0,
            model: e.model.clone(),
            date,
            input_tokens: e.input_tokens.unwrap_or(0) as u64,
            output_tokens: e.output_tokens.unwrap_or(0) as u64,
            cost_usd: e.cost_usd,
        }
    }
}
