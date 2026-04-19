//! Phase 5 / Plan 05-05 — `/v1/workspaces/:id/budgets` handlers.
//!
//! Routes:
//!   GET  /:id/budgets — any authenticated role (IDOR guard: id must match JWT workspace)
//!   PUT  /:id/budgets — admin only (role gate via `require_role`)
//!
//! Current usage (daily_used, monthly_used) is read live from Redis
//! using `get_counter` — no ClickHouse dependency, stays live even during
//! analytics outage (Pitfall #12 in 05-PATTERNS.md).

use axum::{
    extract::{Path, State},
    middleware::from_fn_with_state,
    routing::get,
    Extension, Json, Router,
};
use chrono::Utc;
use secureprompt_common::errors::ApiError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    app_state::AppState,
    db::budget_repo::BudgetBehavior,
    http::{
        api_error_response,
        middleware::{
            jwt_auth::{self, JwtAuthContext, UserRole},
        },
    },
    redis,
};

use super::role::require_role;

// ── DTOs ──────────────────────────────────────────────────────────────────────

/// Response shape for both GET and PUT `/v1/workspaces/:id/budgets`.
#[derive(Debug, Serialize)]
pub struct BudgetResponse {
    pub daily_token_limit: Option<i64>,
    pub monthly_token_limit: Option<i64>,
    pub behavior: BudgetBehavior,
    pub updated_at: chrono::DateTime<Utc>,
    /// Current daily usage from Redis INCRBY counter (0 if no usage this window).
    pub daily_used: i64,
    /// Current monthly usage from Redis INCRBY counter (0 if no usage this window).
    pub monthly_used: i64,
}

/// Request body for PUT `/v1/workspaces/:id/budgets`.
#[derive(Debug, Deserialize)]
pub struct PutBudgetRequest {
    pub daily_token_limit: Option<i64>,
    pub monthly_token_limit: Option<i64>,
    /// Must be one of "block", "warn", "flag".
    pub behavior: BudgetBehavior,
}

// ── Key helpers ───────────────────────────────────────────────────────────────

fn daily_redis_key(workspace_id: Uuid) -> String {
    format!("budget:{}:tokens:{}", workspace_id, Utc::now().format("%Y%m%d"))
}

fn monthly_redis_key(workspace_id: Uuid) -> String {
    format!("budget:{}:tokens:{}", workspace_id, Utc::now().format("%Y%m"))
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// GET /v1/workspaces/:id/budgets
///
/// Returns the current budget configuration plus live Redis usage counters.
/// When no row exists, returns sensible defaults (null limits, behavior=warn).
///
/// # Errors
/// 403 when the workspace in the path does not match the caller's JWT workspace.
async fn get_budget(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Path(workspace_id): Path<Uuid>,
) -> Result<Json<BudgetResponse>, axum::response::Response> {
    // IDOR guard (T-05-05): callers can only access their own workspace.
    if workspace_id != ctx.workspace_id.0 {
        return Err(api_error_response(ApiError::Forbidden(
            "workspace mismatch".into(),
        )));
    }

    let row = state
        .budgets
        .get(workspace_id)
        .await
        .map_err(api_error_response)?;

    // Fetch live counters regardless of whether a budget row exists.
    let daily_used = redis::get_counter(&state.redis_pool, &daily_redis_key(workspace_id))
        .await
        .unwrap_or(0);
    let monthly_used = redis::get_counter(&state.redis_pool, &monthly_redis_key(workspace_id))
        .await
        .unwrap_or(0);

    let response = match row {
        Some(r) => BudgetResponse {
            daily_token_limit: r.daily_token_limit,
            monthly_token_limit: r.monthly_token_limit,
            behavior: r.behavior,
            updated_at: r.updated_at,
            daily_used,
            monthly_used,
        },
        None => {
            // No explicit budget configured — return defaults.
            // behavior defaults to "warn" (the safer choice: no silent blocking).
            BudgetResponse {
                daily_token_limit: None,
                monthly_token_limit: None,
                behavior: BudgetBehavior::Warn,
                updated_at: Utc::now(),
                daily_used,
                monthly_used,
            }
        }
    };

    Ok(Json(response))
}

/// PUT /v1/workspaces/:id/budgets
///
/// Upsert budget configuration. Admin only.
///
/// # Errors
/// 403 on IDOR or insufficient role. 400 on invalid limits.
async fn put_budget(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Path(workspace_id): Path<Uuid>,
    Json(body): Json<PutBudgetRequest>,
) -> Result<Json<BudgetResponse>, axum::response::Response> {
    // IDOR guard — checked before role so cross-workspace probing always yields 403.
    if workspace_id != ctx.workspace_id.0 {
        return Err(api_error_response(ApiError::Forbidden(
            "workspace mismatch".into(),
        )));
    }

    // Role gate — admin only (LIM-02).
    require_role(&ctx, UserRole::Admin).map_err(api_error_response)?;

    let row = state
        .budgets
        .upsert(
            workspace_id,
            body.daily_token_limit,
            body.monthly_token_limit,
            body.behavior,
        )
        .await
        .map_err(api_error_response)?;

    // Fetch live counters for the response (counters are not reset by a PUT).
    let daily_used = redis::get_counter(&state.redis_pool, &daily_redis_key(workspace_id))
        .await
        .unwrap_or(0);
    let monthly_used = redis::get_counter(&state.redis_pool, &monthly_redis_key(workspace_id))
        .await
        .unwrap_or(0);

    Ok(Json(BudgetResponse {
        daily_token_limit: row.daily_token_limit,
        monthly_token_limit: row.monthly_token_limit,
        behavior: row.behavior,
        updated_at: row.updated_at,
        daily_used,
        monthly_used,
    }))
}

// ── Router ────────────────────────────────────────────────────────────────────

/// Build the budget sub-router mounted at `/v1/workspaces` by `http/mod.rs`.
///
/// The JWT middleware is applied inside this function so both verbs are
/// protected. Route: `/{id}/budgets` (GET + PUT).
pub fn build_router(state: AppState) -> Router<AppState> {
    let jwt_layer = from_fn_with_state(state.clone(), jwt_auth::require);
    Router::new()
        .route("/{id}/budgets", get(get_budget).put(put_budget))
        .route_layer(jwt_layer)
}

/// Stub `routes()` used by compile-time checks; real mounting uses `build_router`.
pub fn routes() -> Router<AppState> {
    Router::new().route("/{id}/budgets", get(get_budget).put(put_budget))
}
