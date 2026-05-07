//! Phase 5 / Plan 05-03 — Analytics endpoint handlers.
//!
//! Four GET routes reading exclusively from dbt mart tables:
//!   GET /v1/analytics/usage-daily
//!   GET /v1/analytics/cost-by-model
//!   GET /v1/analytics/policy-violations
//!   GET /v1/analytics/latency-pctiles
//!
//! Security (T-05-05 IDOR): first line of every handler checks that the
//! optional `workspace_id` query parameter matches the JWT context.
//! `ClickHouse` has no RLS; this guard is the only tenant boundary on reads.
//!
//! CI gate: `scripts/ci/check-mart-only.sh` runs ripgrep on THIS file and
//! asserts every FROM clause references a `mart_*` table. Do NOT add any
//! FROM clause referencing raw/staging tables to this file.

use axum::{
    extract::{Extension, Query, State},
    routing::get,
    Json, Router,
};
use chrono::NaiveDate;
use secureprompt_common::errors::ApiError;
use serde::Deserialize;
use std::time::Instant;
use uuid::Uuid;

use crate::{
    analytics::dashboard_reader::{
        CostByModelRow, LatencyPctilesHourlyRow, LatencyPctilesRow, PolicyViolationsRow,
        UsageDailyRow,
    },
    app_state::AppState,
    http::{api_error_response, middleware::jwt_auth::JwtAuthContext},
};

// ── Query parameter DTO ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct DateRangeParams {
    pub from: NaiveDate,
    pub to: NaiveDate,
    /// Optional IDOR guard: if present, MUST equal the JWT `workspace_id`.
    pub workspace_id: Option<Uuid>,
    /// Optional model filter (usage-daily + latency-pctiles only).
    pub model: Option<String>,
    /// Bucket granularity (latency-pctiles only). `"hour"` switches the
    /// response to `LatencyPctilesHourlyRow` shape with a `bucket_ts`
    /// timestamp field; otherwise the daily mart row is returned.
    /// Capped at 31 days for hourly to keep payload size bounded.
    pub bucket: Option<String>,
}

/// Tagged response so the frontend can switch chart formatting based on
/// granularity without inspecting field names. Hourly rows carry full
/// timestamps; daily rows carry calendar dates.
#[derive(Debug, serde::Serialize)]
#[serde(tag = "bucket", rename_all = "lowercase")]
pub enum LatencyPctilesResponse {
    Day { rows: Vec<LatencyPctilesRow> },
    Hour { rows: Vec<LatencyPctilesHourlyRow> },
}

// ── Router ───────────────────────────────────────────────────────────────────

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/usage-daily", get(usage_daily))
        .route("/cost-by-model", get(cost_by_model))
        .route("/policy-violations", get(policy_violations))
        .route("/latency-pctiles", get(latency_pctiles))
}

// ── Handlers ─────────────────────────────────────────────────────────────────

async fn usage_daily(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Query(params): Query<DateRangeParams>,
) -> Result<Json<Vec<UsageDailyRow>>, axum::response::Response> {
    // T-05-05 IDOR guard
    if let Some(w) = params.workspace_id {
        if w != ctx.workspace_id.0 {
            return Err(api_error_response(ApiError::Forbidden(
                "workspace_id mismatch".into(),
            )));
        }
    }

    tracing::info!(
        workspace_id = %ctx.workspace_id.0,
        endpoint = "usage-daily",
        from = ?params.from,
        to = ?params.to,
        model = ?params.model,
    );

    let start = Instant::now();
    let result = state
        .dashboard_reader
        .query_usage_daily(
            &state.metrics,
            ctx.workspace_id.0,
            params.from,
            params.to,
            params.model.as_deref(),
        )
        .await;
    let elapsed = start.elapsed();

    match result {
        Ok(rows) => {
            state
                .metrics
                .record_dashboard_request("usage-daily", elapsed, "success");
            Ok(Json(rows))
        }
        Err(e) => {
            state
                .metrics
                .record_dashboard_request("usage-daily", elapsed, "error");
            state
                .metrics
                .inc_dashboard_error("usage-daily", &http_code_label(&e));
            Err(api_error_response(e))
        }
    }
}

async fn cost_by_model(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Query(params): Query<DateRangeParams>,
) -> Result<Json<Vec<CostByModelRow>>, axum::response::Response> {
    // T-05-05 IDOR guard
    if let Some(w) = params.workspace_id {
        if w != ctx.workspace_id.0 {
            return Err(api_error_response(ApiError::Forbidden(
                "workspace_id mismatch".into(),
            )));
        }
    }

    tracing::info!(
        workspace_id = %ctx.workspace_id.0,
        endpoint = "cost-by-model",
        from = ?params.from,
        to = ?params.to,
    );

    let start = Instant::now();
    let result = state
        .dashboard_reader
        .query_cost_by_model(&state.metrics, params.from, params.to)
        .await;
    let elapsed = start.elapsed();

    match result {
        Ok(rows) => {
            state
                .metrics
                .record_dashboard_request("cost-by-model", elapsed, "success");
            Ok(Json(rows))
        }
        Err(e) => {
            state
                .metrics
                .record_dashboard_request("cost-by-model", elapsed, "error");
            state
                .metrics
                .inc_dashboard_error("cost-by-model", &http_code_label(&e));
            Err(api_error_response(e))
        }
    }
}

async fn policy_violations(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Query(params): Query<DateRangeParams>,
) -> Result<Json<Vec<PolicyViolationsRow>>, axum::response::Response> {
    // T-05-05 IDOR guard
    if let Some(w) = params.workspace_id {
        if w != ctx.workspace_id.0 {
            return Err(api_error_response(ApiError::Forbidden(
                "workspace_id mismatch".into(),
            )));
        }
    }

    tracing::info!(
        workspace_id = %ctx.workspace_id.0,
        endpoint = "policy-violations",
        from = ?params.from,
        to = ?params.to,
    );

    let start = Instant::now();
    let result = state
        .dashboard_reader
        .query_policy_violations(
            &state.metrics,
            ctx.workspace_id.0,
            params.from,
            params.to,
        )
        .await;
    let elapsed = start.elapsed();

    match result {
        Ok(rows) => {
            state
                .metrics
                .record_dashboard_request("policy-violations", elapsed, "success");
            Ok(Json(rows))
        }
        Err(e) => {
            state
                .metrics
                .record_dashboard_request("policy-violations", elapsed, "error");
            state
                .metrics
                .inc_dashboard_error("policy-violations", &http_code_label(&e));
            Err(api_error_response(e))
        }
    }
}

async fn latency_pctiles(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Query(params): Query<DateRangeParams>,
) -> Result<Json<LatencyPctilesResponse>, axum::response::Response> {
    // T-05-05 IDOR guard
    if let Some(w) = params.workspace_id {
        if w != ctx.workspace_id.0 {
            return Err(api_error_response(ApiError::Forbidden(
                "workspace_id mismatch".into(),
            )));
        }
    }

    let hourly = matches!(params.bucket.as_deref(), Some("hour"));

    tracing::info!(
        workspace_id = %ctx.workspace_id.0,
        endpoint = "latency-pctiles",
        from = ?params.from,
        to = ?params.to,
        model = ?params.model,
        bucket = if hourly { "hour" } else { "day" },
    );

    let start = Instant::now();
    let response = if hourly {
        state
            .dashboard_reader
            .query_latency_pctiles_hourly(
                &state.metrics,
                ctx.workspace_id.0,
                params.from,
                params.to,
                params.model.as_deref(),
            )
            .await
            .map(|rows| LatencyPctilesResponse::Hour { rows })
    } else {
        state
            .dashboard_reader
            .query_latency_pctiles(
                &state.metrics,
                ctx.workspace_id.0,
                params.from,
                params.to,
                params.model.as_deref(),
            )
            .await
            .map(|rows| LatencyPctilesResponse::Day { rows })
    };
    let elapsed = start.elapsed();

    match response {
        Ok(body) => {
            state
                .metrics
                .record_dashboard_request("latency-pctiles", elapsed, "success");
            Ok(Json(body))
        }
        Err(e) => {
            state
                .metrics
                .record_dashboard_request("latency-pctiles", elapsed, "error");
            state
                .metrics
                .inc_dashboard_error("latency-pctiles", &http_code_label(&e));
            Err(api_error_response(e))
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn http_code_label(e: &ApiError) -> String {
    match e {
        ApiError::Forbidden(_) => "403".into(),
        ApiError::NotFound(_) => "404".into(),
        ApiError::Unauthorized(_) => "401".into(),
        ApiError::BadRequest(_) => "400".into(),
        ApiError::BudgetExceeded(_) => "402".into(),
        _ => "500".into(),
    }
}
