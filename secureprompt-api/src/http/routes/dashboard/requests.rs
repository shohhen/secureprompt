//! Phase 5 / Plan 05-04 — `/v1/requests` list (cursor-paginated) and
//! `/v1/requests/:id` detail.
//!
//! Reads raw `request_events` + `policy_events` ClickHouse tables — this is
//! the ONLY handler in Phase 5 that reads raw tables, and it is intentional.
//! The `check-mart-only.sh` CI gate is scoped to `analytics.rs` only and must
//! NOT be extended to this file.
//!
//! Security (T-05-05 IDOR):
//!   * `?workspace_id=<other>` is rejected with 403.
//!   * Hard LIMIT ≤ 200 enforced in code.
//!   * Time window cap: `from` must be within 90 days.
//!   * DO NOT read `token_vault_entries` — the no_leak test enforces this.
//!
//! Cursor encoding: `base64url_no_pad(json({ts, request_id}))` where `ts` is
//! the Unix-second timestamp of the last row. Tie-break:
//! `ORDER BY created_at DESC, request_id DESC`.

use axum::{
    extract::{Extension, Path, Query, State},
    routing::get,
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use clickhouse::Row;
use secureprompt_common::errors::ApiError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    app_state::AppState,
    http::{api_error_response, middleware::jwt_auth::JwtAuthContext},
};

// ── Query params ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ListRequestsParams {
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub model: Option<String>,
    pub has_violation: Option<bool>,
    pub cursor: Option<String>,
    pub limit: Option<u32>,
    /// Optional IDOR guard: if present, MUST equal the JWT `workspace_id`.
    pub workspace_id: Option<Uuid>,
}

// ── Cursor ────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct CursorPayload {
    /// Unix-second timestamp of the last row.
    ts: i64,
    /// request_id tie-break.
    request_id: Uuid,
}

fn encode_cursor(ts: i64, request_id: Uuid) -> String {
    let payload = serde_json::to_string(&CursorPayload { ts, request_id })
        .expect("cursor json must serialize");
    URL_SAFE_NO_PAD.encode(payload.as_bytes())
}

fn decode_cursor(cursor: &str) -> Result<CursorPayload, ApiError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|_| ApiError::BadRequest("invalid cursor".into()))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| ApiError::BadRequest("invalid cursor payload".into()))
}

// ── ClickHouse row types ──────────────────────────────────────────────────────

/// Raw row from `request_events` joined with `policy_events` count.
#[derive(Debug, Clone, Row, Deserialize)]
struct RequestEventRow {
    #[serde(with = "clickhouse::serde::uuid")]
    pub request_id: Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    pub workspace_id: Uuid,
    pub provider: String,
    pub model: String,
    pub final_action: String,
    pub input_tokens: Option<u32>,
    pub output_tokens: Option<u32>,
    pub cost_usd: f64,
    /// `toUnixTimestamp(re.created_at)` in ClickHouse returns `UInt32` —
    /// must match here, otherwise rowbinary deserialization fails with
    /// `schema mismatch: ... UInt32 as i64`. Cast to i64 at usage sites
    /// (DateTime::from_timestamp wants i64) using `i64::from(...)`.
    pub created_at_unix: u32,
    pub has_violation: u8,
}

/// Raw row from `request_events` for the detail endpoint.
#[derive(Debug, Clone, Row, Deserialize)]
struct RequestDetailRow {
    #[serde(with = "clickhouse::serde::uuid")]
    pub request_id: Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    pub workspace_id: Uuid,
    pub provider: String,
    pub model: String,
    pub final_action: String,
    pub input_tokens: Option<u32>,
    pub output_tokens: Option<u32>,
    pub reasoning_tokens: Option<u32>,
    pub cache_read_tokens: Option<u32>,
    pub cache_write_tokens: Option<u32>,
    pub cost_usd: f64,
    pub created_at_unix: u32,
    // ── Migration 002: per-request actor + transport context ──────────────
    #[serde(with = "clickhouse::serde::uuid::option")]
    pub user_id: Option<Uuid>,
    #[serde(with = "clickhouse::serde::uuid::option")]
    pub api_key_id: Option<Uuid>,
    pub api_key_name: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub redacted_prompt: Option<String>,
    pub restored_response: Option<String>,
    // ── Migration 005: raw input + raw upstream output ─────────────────────
    pub raw_prompt: Option<String>,
    pub raw_response: Option<String>,
}

/// Raw row from `policy_events`.
#[derive(Debug, Clone, Row, Deserialize)]
struct PolicyEventRow {
    #[serde(with = "clickhouse::serde::uuid")]
    pub rule_id: Uuid,
    pub rule_name: String,
    pub action: String,
    pub dry_run: u8,
}

// ── Response types ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct PolicyEventSummary {
    pub rule_id: Uuid,
    pub rule_name: String,
    pub action: String,
    pub dry_run: bool,
}

#[derive(Debug, Serialize)]
pub struct RequestListItem {
    pub request_id: Uuid,
    pub workspace_id: Uuid,
    pub provider: String,
    pub model: String,
    pub final_action: String,
    pub input_tokens: Option<u32>,
    pub output_tokens: Option<u32>,
    pub cost_usd: f64,
    pub has_violation: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ListRequestsResponse {
    pub items: Vec<RequestListItem>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RequestDetail {
    pub request_id: Uuid,
    pub workspace_id: Uuid,
    pub provider: String,
    pub model: String,
    pub final_action: String,
    pub input_tokens: Option<u32>,
    pub output_tokens: Option<u32>,
    pub reasoning_tokens: Option<u32>,
    pub cache_read_tokens: Option<u32>,
    pub cache_write_tokens: Option<u32>,
    pub cost_usd: f64,
    pub created_at: DateTime<Utc>,
    pub policy_events: Vec<PolicyEventSummary>,
    // ── Per-request actor + transport context (migration 002) ─────────────
    pub user_id: Option<Uuid>,
    /// Email of the workspace member who issued the request, looked up
    /// from `users` at read time so the dashboard can render it directly.
    pub user_email: Option<String>,
    pub api_key_id: Option<Uuid>,
    pub api_key_name: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    /// User-side checked content — the latest user message in this turn,
    /// post-PII redaction (placeholders substituted in).
    pub redacted_prompt: Option<String>,
    /// AI-side checked content — what we returned to the client after
    /// placeholder restoration. `None` for embeddings or denied requests.
    pub restored_response: Option<String>,
    /// Raw user input pre-redaction. Paired with `redacted_prompt` on the
    /// detail page so reviewers can see what the user actually typed.
    pub raw_prompt: Option<String>,
    /// Raw upstream output pre-restoration. Paired with `restored_response`.
    pub raw_response: Option<String>,
    /// Profile fields pulled from `users` so the detail page can show the
    /// actor's display name + position alongside their email.
    pub user_first_name: Option<String>,
    pub user_last_name: Option<String>,
    pub user_position: Option<String>,
    /// Self-reported MAC address from the desktop wrapper. `None` for
    /// browser users or for users who haven't opened the dashboard from
    /// the desktop yet.
    pub user_device_mac: Option<String>,
    /// Coarse classifier of where the request came from, derived from
    /// the user-agent header. `None` when no UA was sent.
    pub source: Option<String>,
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_requests))
        .route("/{id}", get(get_request_detail))
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `GET /v1/requests` — cursor-paginated request list.
///
/// Reads raw `request_events` + `policy_events`. This is intentional.
/// Do NOT add this file to `check-mart-only.sh`.
async fn list_requests(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Query(params): Query<ListRequestsParams>,
) -> Result<Json<ListRequestsResponse>, axum::response::Response> {
    // T-05-05 IDOR guard
    if let Some(w) = params.workspace_id {
        if w != ctx.workspace_id.0 {
            return Err(api_error_response(ApiError::Forbidden(
                "workspace_id mismatch".into(),
            )));
        }
    }

    let ws = ctx.workspace_id.0;
    let limit = u64::from(params.limit.unwrap_or(50).min(200));

    // Time window: default from = now - 7 days, to = now
    let now = Utc::now();
    let ninety_days_ago = now - chrono::Duration::days(90);
    let from = params.from.unwrap_or_else(|| now - chrono::Duration::days(7));
    let to = params.to.unwrap_or(now);

    // Time window cap: from >= now() - 90 days
    if from < ninety_days_ago {
        return Err(api_error_response(ApiError::BadRequest(
            "from must be within the last 90 days".into(),
        )));
    }

    // Decode cursor if present
    let cursor_payload = if let Some(ref c) = params.cursor {
        Some(decode_cursor(c).map_err(api_error_response)?)
    } else {
        None
    };

    // Build cursor WHERE clause
    let cursor_clause = cursor_payload.as_ref().map_or_else(String::new, |cp| {
        format!(
            "AND (re.created_at < toDateTime({ts}) \
             OR (re.created_at = toDateTime({ts}) AND re.request_id < toUUID('{rid}')))",
            ts = cp.ts,
            rid = cp.request_id
        )
    });

    let model_clause = params.model.as_ref().map_or_else(String::new, |m| {
        format!("AND re.model = '{}'", m.replace('\'', "''"))
    });

    // Employee/Viewer roles can only see their own requests. Owner +
    // Developer (and legacy Admin) see the full workspace.
    let user_scope_clause = if ctx.role.can_read_all_audit() {
        String::new()
    } else {
        format!("AND re.user_id = toUUID('{uid}')", uid = ctx.user_id)
    };

    // has_violation filter: INNER JOIN keeps only rows with at least one event,
    // LEFT JOIN keeps all rows (violation flag derived from count).
    let join_type = if params.has_violation.unwrap_or(false) {
        "INNER JOIN"
    } else {
        "LEFT JOIN"
    };

    // Fetch limit+1 to determine if there is a next page.
    let fetch_limit = limit + 1;

    let query = format!(
        "SELECT \
            re.request_id AS request_id, \
            re.workspace_id AS workspace_id, \
            re.provider AS provider, \
            re.model AS model, \
            re.final_action AS final_action, \
            re.input_tokens AS input_tokens, \
            re.output_tokens AS output_tokens, \
            re.cost_usd AS cost_usd, \
            toUnixTimestamp(re.created_at) AS created_at_unix, \
            countIf(pe.rule_id != toUUID('00000000-0000-0000-0000-000000000000')) > 0 AS has_violation \
        FROM request_events AS re \
        {join_type} policy_events AS pe \
            ON re.request_id = pe.request_id AND re.workspace_id = pe.workspace_id \
        WHERE re.workspace_id = toUUID('{ws}') \
          AND re.created_at >= toDateTime({from_ts}) \
          AND re.created_at <= toDateTime({to_ts}) \
          {cursor_clause} \
          {model_clause} \
          {user_scope_clause} \
        GROUP BY \
            re.request_id, re.workspace_id, re.provider, re.model, \
            re.final_action, re.input_tokens, re.output_tokens, \
            re.cost_usd, re.created_at \
        ORDER BY re.created_at DESC, re.request_id DESC \
        LIMIT {fetch_limit}",
        join_type = join_type,
        ws = ws,
        from_ts = from.timestamp(),
        to_ts = to.timestamp(),
        cursor_clause = cursor_clause,
        model_clause = model_clause,
        user_scope_clause = user_scope_clause,
        fetch_limit = fetch_limit,
    );

    let rows = state
        .dashboard_reader
        .client()
        .query(&query)
        .fetch_all::<RequestEventRow>()
        .await
        .map_err(|e| {
            api_error_response(ApiError::Internal(format!(
                "clickhouse list_requests failed: {e}"
            )))
        })?;

    let has_more = rows.len() as u64 > limit;
    let items_raw: Vec<RequestEventRow> = if has_more {
        rows[..limit as usize].to_vec()
    } else {
        rows
    };

    let next_cursor = if has_more {
        items_raw.last().map(|r| encode_cursor(i64::from(r.created_at_unix), r.request_id))
    } else {
        None
    };

    let items = items_raw
        .into_iter()
        .map(|r| RequestListItem {
            request_id: r.request_id,
            workspace_id: r.workspace_id,
            provider: r.provider,
            model: r.model,
            final_action: r.final_action,
            input_tokens: r.input_tokens,
            output_tokens: r.output_tokens,
            cost_usd: r.cost_usd,
            has_violation: r.has_violation != 0,
            created_at: DateTime::from_timestamp(i64::from(r.created_at_unix), 0)
                .unwrap_or(DateTime::UNIX_EPOCH),
        })
        .collect();

    Ok(Json(ListRequestsResponse { items, next_cursor }))
}

/// `GET /v1/requests/:id` — request detail with policy events.
///
/// Reads raw `request_events` + `policy_events`. DO NOT read `token_vault_entries`.
async fn get_request_detail(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Path(request_id): Path<Uuid>,
) -> Result<Json<RequestDetail>, axum::response::Response> {
    let ws = ctx.workspace_id.0;

    // Fetch main request row. The workspace_id guard is in the WHERE clause.
    // Migration 002 adds the trailing actor + transport columns; older rows
    // (pre-002) carry NULLs which deserialize cleanly into Option<...>.
    let req_query = format!(
        "SELECT \
            request_id, workspace_id, provider, model, final_action, \
            input_tokens, output_tokens, reasoning_tokens, \
            cache_read_tokens, cache_write_tokens, cost_usd, \
            toUnixTimestamp(created_at) AS created_at_unix, \
            user_id, api_key_id, api_key_name, \
            ip_address, user_agent, redacted_prompt, restored_response, \
            raw_prompt, raw_response \
        FROM request_events \
        WHERE workspace_id = toUUID('{ws}') \
          AND request_id = toUUID('{rid}') \
        LIMIT 1",
        ws = ws,
        rid = request_id
    );

    let req_rows = state
        .dashboard_reader
        .client()
        .query(&req_query)
        .fetch_all::<RequestDetailRow>()
        .await
        .map(|rows| {
            // Employee scope: silently treat other users' rows as "not
            // found" rather than returning 403 — leaks less information
            // about whether a given request_id exists in the workspace.
            if ctx.role.can_read_all_audit() {
                rows
            } else {
                rows.into_iter()
                    .filter(|r| r.user_id == Some(ctx.user_id))
                    .collect()
            }
        })
        .map_err(|e| {
            api_error_response(ApiError::Internal(format!(
                "clickhouse get_request_detail failed: {e}"
            )))
        })?;

    let req_row = req_rows.into_iter().next().ok_or_else(|| {
        api_error_response(ApiError::NotFound(format!(
            "request {request_id} not found"
        )))
    })?;

    // Fetch associated policy events. DO NOT read token_vault_entries.
    let pe_query = format!(
        "SELECT \
            rule_id, rule_name, action, \
            toUInt8(dry_run) AS dry_run \
        FROM policy_events \
        WHERE workspace_id = toUUID('{ws}') \
          AND request_id = toUUID('{rid}') \
        ORDER BY created_at ASC",
        ws = ws,
        rid = request_id
    );

    let pe_rows = state
        .dashboard_reader
        .client()
        .query(&pe_query)
        .fetch_all::<PolicyEventRow>()
        .await
        .map_err(|e| {
            api_error_response(ApiError::Internal(format!(
                "clickhouse policy_events query failed: {e}"
            )))
        })?;

    let policy_events = pe_rows
        .into_iter()
        .map(|pe| PolicyEventSummary {
            rule_id: pe.rule_id,
            rule_name: pe.rule_name,
            action: pe.action,
            dry_run: pe.dry_run != 0,
        })
        .collect();

    // Resolve user_id → email + profile via Postgres. The `users` table is
    // small and the lookup is cached in pg's plan; doing this server-side
    // keeps the dashboard from having to render a UUID and then fetch
    // each field separately. Failures are non-fatal — fields stay None.
    let (
        user_email,
        user_first_name,
        user_last_name,
        user_position,
        user_device_mac,
    ) = if let Some(uid) = req_row.user_id {
        match sqlx::query_as::<
            _,
            (
                String,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
            ),
        >(
            "SELECT email, first_name, last_name, position, device_mac
             FROM users WHERE id = $1 AND workspace_id = $2",
        )
        .bind(uid)
        .bind(ws)
        .fetch_optional(&state.db)
        .await
        {
            Ok(Some((email, first, last, pos, mac))) => {
                (Some(email), first, last, pos, mac)
            }
            Ok(None) => (None, None, None, None, None),
            Err(e) => {
                tracing::warn!(error = %e, user_id = %uid, "user profile lookup failed");
                (None, None, None, None, None)
            }
        }
    } else {
        (None, None, None, None, None)
    };

    let source = classify_source(req_row.user_agent.as_deref());

    Ok(Json(RequestDetail {
        request_id: req_row.request_id,
        workspace_id: req_row.workspace_id,
        provider: req_row.provider,
        model: req_row.model,
        final_action: req_row.final_action,
        input_tokens: req_row.input_tokens,
        output_tokens: req_row.output_tokens,
        reasoning_tokens: req_row.reasoning_tokens,
        cache_read_tokens: req_row.cache_read_tokens,
        cache_write_tokens: req_row.cache_write_tokens,
        cost_usd: req_row.cost_usd,
        created_at: DateTime::from_timestamp(i64::from(req_row.created_at_unix), 0)
            .unwrap_or(DateTime::UNIX_EPOCH),
        policy_events,
        user_id: req_row.user_id,
        user_email,
        api_key_id: req_row.api_key_id,
        api_key_name: req_row.api_key_name,
        ip_address: req_row.ip_address,
        user_agent: req_row.user_agent,
        redacted_prompt: req_row.redacted_prompt,
        restored_response: req_row.restored_response,
        raw_prompt: req_row.raw_prompt,
        raw_response: req_row.raw_response,
        user_first_name,
        user_last_name,
        user_position,
        user_device_mac,
        source,
    }))
}

/// Classify a request's origin from its user-agent header.
///
/// Returns a short label suitable for the audit "From" card. The set is
/// intentionally small — it's a guide for the reviewer, not a security
/// boundary. New shapes can be added as we observe them; the default
/// catches anything we don't recognise as "External API client" rather
/// than emitting raw UA text twice.
fn classify_source(ua: Option<&str>) -> Option<String> {
    let ua = ua?;
    if ua.is_empty() {
        return None;
    }
    let lower = ua.to_ascii_lowercase();
    let label = if lower.contains("librechat") {
        "LibreChat"
    } else if lower.contains("electron") {
        "Desktop chat (Electron)"
    } else if lower.contains("customopenaiclient") {
        // LibreChat's internal HTTP client name. Treat as the chat app.
        "LibreChat"
    } else if lower.contains("openai-python") {
        "External API (openai-python)"
    } else if lower.contains("openai-node") || lower.contains("openai/js") {
        "External API (openai-js)"
    } else if lower.contains("anthropic") {
        "External API (anthropic-sdk)"
    } else if lower.contains("python-requests") || lower.contains("httpx/") {
        "External API (Python)"
    } else if lower.starts_with("curl/") {
        "External (curl)"
    } else if lower.contains("postman") || lower.contains("insomnia") {
        "External API (Postman/Insomnia)"
    } else if lower.contains("mozilla") || lower.contains("chrome") || lower.contains("safari") {
        "Browser"
    } else {
        "External API"
    };
    Some(label.to_owned())
}

