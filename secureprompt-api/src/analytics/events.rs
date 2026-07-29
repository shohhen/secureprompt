use crate::analytics::capture::{seal, CaptureDecision, CapturedContent};
use secureprompt_common::{
    kms::KmsBackend,
    types::{PolicyEvent, RequestId, TokenUsage, WorkspaceId},
};

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
    ///
    /// Deliberately NOT behind the WS3-1 capture gate: this is the
    /// post-tokenization text, the same bytes that were forwarded upstream.
    /// It is what makes the audit row exist at all for a request whose raw
    /// content is not captured, and it is what the WS3-1 tests use as their
    /// positive control that a plaintext search against ClickHouse works.
    pub redacted_prompt: Option<String>,
    /// WS3-1 / WS3-2 — the raw user message, the raw upstream response and
    /// the PII-restored response, encrypted, IF AND ONLY IF the workspace
    /// opted in.
    ///
    /// PRIVATE ON PURPOSE. This replaced three `pub` fields
    /// (`raw_prompt`, `raw_response`, `restored_response`) that seven call
    /// sites in `pipeline/service.rs` assigned unconditionally. The only way
    /// to populate it is [`Self::capture_content`], whose only route to a
    /// `Some` is [`crate::analytics::capture::seal`] — so the gate cannot be
    /// bypassed by a new call site, and forgetting it is a compile error
    /// rather than a leak.
    captured: Option<CapturedContent>,
    /// WS2-3 — this answer was produced with the deterministic Rust floor
    /// alone: the ML sidecar produced no detection coverage for the request
    /// and the workspace's `sidecar_unavailable` policy is
    /// `degrade_with_alert`. `false` on every normally-served request, so a
    /// reviewer can scope an incident to exactly the traffic that ran without
    /// NER rather than guessing from sidecar uptime.
    pub floor_only: bool,
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
            captured: None,
            floor_only: false,
        }
    }

    /// WS3-1 / WS3-2 — the ONLY way raw request content is ever attached to
    /// an analytics event.
    ///
    /// Call it at every site that used to assign `event.raw_prompt`,
    /// `event.raw_response` or `event.restored_response`. When `decision` is
    /// not enabled — the state of every workspace that has not explicitly
    /// opted in, which on a fresh install is all of them — this is a no-op
    /// and the plaintext arguments are dropped without ever leaving the
    /// process. When it IS enabled, the content is encrypted via `kms`
    /// before it is stored, and a KMS failure drops the capture rather than
    /// falling back to plaintext.
    pub async fn capture_content(
        &mut self,
        decision: CaptureDecision,
        kms: &dyn KmsBackend,
        raw_prompt: Option<String>,
        raw_response: Option<String>,
        restored_response: Option<String>,
    ) {
        self.captured = seal(decision, kms, raw_prompt, raw_response, restored_response).await;
    }

    /// Read-only view of whatever survived the gate. Reading is not the leak;
    /// writing is, which is why there is no corresponding setter.
    #[must_use]
    pub fn captured(&self) -> Option<&CapturedContent> {
        self.captured.as_ref()
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
    // ── Migration 005: raw input + raw upstream output ─────────────────────
    //
    // WS3-1: these three columns are RETAINED so historical rows written
    // before the capture gate stay readable, and so the row layout keeps
    // matching the live table. The writer now sends NULL for all three,
    // ALWAYS — `from_event` below has no path that populates them. Captured
    // content, when a workspace has opted in, goes to
    // `request_content_captures` as ciphertext instead. See
    // `clickhouse/migrations/007_request_content_captures.sql` for why it
    // cannot live here.
    pub restored_response: Option<String>,
    pub raw_prompt: Option<String>,
    pub raw_response: Option<String>,
    // ── Migration 006 (WS2-3): deterministic-floor-only answer ─────────────
    // Column order MUST match the ALTER TABLE order; ClickHouse appends
    // ADD COLUMN at the end of the row, so this field stays last.
    pub floor_only: bool,
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
            // WS3-1 — UNCONDITIONALLY NULL. `request_events` is the table the
            // cost, latency and audit-list dashboards read; nothing raw goes
            // into it again, whether or not the workspace opted in. The
            // opted-in case is served by `RequestContentCaptureRow`.
            restored_response: None,
            raw_prompt: None,
            raw_response: None,
            floor_only: e.floor_only,
        }
    }
}

/// WS3-1 / WS3-2 — one row of captured content, in
/// `request_content_captures` (ClickHouse migration 007).
///
/// Field order MUST match the CREATE TABLE column order.
#[derive(Row, Serialize)]
pub struct RequestContentCaptureRow {
    #[serde(with = "clickhouse::serde::uuid")]
    pub request_id: uuid::Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    pub workspace_id: uuid::Uuid,
    #[serde(with = "clickhouse::serde::chrono::datetime")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// `created_at + retention_days`. The table's `TTL expires_at DELETE`
    /// drops the row after it, independently of the 90-day row TTL on
    /// `request_events`.
    #[serde(with = "clickhouse::serde::chrono::datetime")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub encrypted: bool,
    pub raw_prompt: Option<String>,
    pub raw_response: Option<String>,
    pub restored_response: Option<String>,
}

impl RequestContentCaptureRow {
    /// `None` when the event carries no captured content — i.e. whenever the
    /// workspace has not opted in, which is the default.
    ///
    /// `created_at` is the SAME instant the writer stamps on the
    /// `request_events` row, so `dateDiff('day', created_at, expires_at)`
    /// equals the workspace's configured `retention_days` exactly rather than
    /// drifting by the time between the two.
    pub fn from_event(
        e: &RequestEvent,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Option<Self> {
        let captured = e.captured()?;
        let expires_at = created_at
            + chrono::Duration::try_days(i64::from(captured.retention_days))
                .unwrap_or_else(|| chrono::Duration::days(30));
        Some(Self {
            request_id: e.request_id.0,
            workspace_id: e.workspace_id.0,
            created_at,
            expires_at,
            encrypted: captured.encrypted,
            raw_prompt: captured.raw_prompt.clone(),
            raw_response: captured.raw_response.clone(),
            restored_response: captured.restored_response.clone(),
        })
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
