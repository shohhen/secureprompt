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
    /// Time-to-first-byte from upstream (provider-side). `None` for paths
    /// that don't make a network call (debug mode, denied requests).
    pub ttft_ms: Option<u32>,
    /// Workspace member who issued the request (api_keys.assigned_user_id).
    /// `None` for legacy unassigned workspace-scoped keys.
    pub user_id: Option<uuid::Uuid>,
    pub api_key_id: Option<uuid::Uuid>,
    pub api_key_name: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    /// Placeholder-safe prompt body — what was forwarded to the upstream
    /// after PII redaction. Required for the audit detail view.
    pub redacted_prompt: Option<String>,
    /// What we returned to the client after placeholder restoration.
    /// Powers the "AI:" half of the audit log; `None` for denied/embedding
    /// requests where no chat response exists.
    pub restored_response: Option<String>,
    /// Raw last user message before any redaction — paired with
    /// `redacted_prompt` on the audit detail page so reviewers can see
    /// what was inspected.
    pub raw_prompt: Option<String>,
    /// Raw upstream response before placeholder restoration. Paired with
    /// `restored_response` so reviewers can see exactly what the model
    /// emitted (placeholders intact) vs what the client received.
    pub raw_response: Option<String>,
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
            ttft_ms: None,
            user_id: None,
            api_key_id: None,
            api_key_name: None,
            ip_address: None,
            user_agent: None,
            redacted_prompt: None,
            restored_response: None,
            raw_prompt: None,
            raw_response: None,
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
    // ── Migration 002: per-request actor + transport context ───────────────
    // Column order MUST match the ALTER TABLE order; ClickHouse appends
    // ADD COLUMN at the end of the row.
    #[serde(with = "clickhouse::serde::uuid::option")]
    pub user_id: Option<uuid::Uuid>,
    #[serde(with = "clickhouse::serde::uuid::option")]
    pub api_key_id: Option<uuid::Uuid>,
    pub api_key_name: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub redacted_prompt: Option<String>,
    // ── Migration 004: AI response capture for the audit log ───────────────
    pub restored_response: Option<String>,
    // ── Migration 005: raw input + raw upstream output ─────────────────────
    pub raw_prompt: Option<String>,
    pub raw_response: Option<String>,
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
            user_id: e.user_id,
            api_key_id: e.api_key_id,
            api_key_name: e.api_key_name.clone(),
            ip_address: e.ip_address.clone(),
            user_agent: e.user_agent.clone(),
            redacted_prompt: e.redacted_prompt.clone(),
            restored_response: e.restored_response.clone(),
            raw_prompt: e.raw_prompt.clone(),
            raw_response: e.raw_response.clone(),
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
    // ── Migration 003: time-to-first-byte from upstream ────────────────────
    // Nullable because debug mode and adapters that don't issue a real
    // HTTP call (stubs, embeddings emitted from cached models) cannot
    // measure TTFT. Column order MUST match the ALTER TABLE order.
    pub ttft_ms: Option<u32>,
}

#[derive(Row, Serialize)]
pub struct TokenUsageRow {
    #[serde(with = "clickhouse::serde::uuid")]
    pub workspace_id: uuid::Uuid,
    pub model: String,
    // Column is `Date` (i16 days since epoch) — must use the `date` adapter,
    // not `date32` (i32). Mismatch produces:
    //   "attempting to (de)serialize ClickHouse type Date as i32"
    // and the row write fails silently in the analytics writer, leaving the
    // dashboard analytics queries with no rows to read.
    #[serde(with = "clickhouse::serde::chrono::date")]
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
