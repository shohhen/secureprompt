//! Phase 5 / Plan 05-04 — `/v1/policy-rules` CRUD handlers.
//!
//! Routes:
//!   GET    /v1/policy-rules              — list rules (any role)
//!   GET    /v1/policy-rules/:id          — get single rule (any role)
//!   POST   /v1/policy-rules              — create rule (admin only)
//!   PUT    /v1/policy-rules/:id          — update rule (admin only)
//!   DELETE /v1/policy-rules/:id          — delete rule (admin only)
//!   PATCH  /v1/policy-rules/:id/enabled  — toggle enabled flag (admin only)
//!   PATCH  /v1/policy-rules/:id/dry-run  — toggle dry_run flag (admin only)
//!
//! Constraints:
//!   * `action` must be in `{deny, allow, redact, transform, flag}`.
//!   * Priority uniqueness: 409 `{code: "priority_conflict"}` on conflict.
//!   * `conditions` + `action_params` pass through as `serde_json::Value`.

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    routing::{get, patch},
    Json, Router,
};
use chrono::{DateTime, Utc};
use secureprompt_common::errors::ApiError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    app_state::AppState,
    db::policy_repo::PolicyRepository,
    http::{
        api_error_response,
        middleware::jwt_auth::{JwtAuthContext, UserRole},
        routes::dashboard::role::require_role,
    },
};

// ── Valid actions ─────────────────────────────────────────────────────────────

const VALID_ACTIONS: &[&str] = &["deny", "allow", "redact", "transform", "flag"];

fn validate_action(action: &str) -> Result<(), ApiError> {
    if VALID_ACTIONS.contains(&action) {
        Ok(())
    } else {
        Err(ApiError::BadRequest(format!(
            "action must be one of: {}",
            VALID_ACTIONS.join(", ")
        )))
    }
}

// ── DTOs ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct PolicyRuleResponse {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub name: String,
    pub priority: i32,
    pub conditions: Value,
    pub action: String,
    pub action_params: Value,
    pub enabled: bool,
    pub dry_run: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateRuleRequest {
    pub name: String,
    pub priority: i32,
    pub conditions: Option<Value>,
    pub action: String,
    pub action_params: Option<Value>,
    pub enabled: Option<bool>,
    pub dry_run: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateRuleRequest {
    pub name: String,
    pub priority: i32,
    pub conditions: Option<Value>,
    pub action: String,
    pub action_params: Option<Value>,
    pub enabled: Option<bool>,
    pub dry_run: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct ToggleRequest {
    pub value: bool,
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_rules).post(create_rule))
        .route("/{id}", get(get_rule).put(update_rule).delete(delete_rule))
        .route("/{id}/enabled", patch(toggle_enabled))
        .route("/{id}/dry-run", patch(toggle_dry_run))
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `GET /v1/policy-rules` — list all rules (any role).
async fn list_rules(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
) -> Result<Json<Vec<PolicyRuleResponse>>, axum::response::Response> {
    let repo = PolicyRepository::new(state.db.clone());
    let rows = repo
        .list_rules(ctx.workspace_id)
        .await
        .map_err(api_error_response)?;

    Ok(Json(rows.into_iter().map(into_response).collect()))
}

/// `GET /v1/policy-rules/:id` — get a single rule (any role).
async fn get_rule(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Path(rule_id): Path<Uuid>,
) -> Result<Json<PolicyRuleResponse>, axum::response::Response> {
    let repo = PolicyRepository::new(state.db.clone());
    let row = repo
        .get_rule(ctx.workspace_id, rule_id)
        .await
        .map_err(api_error_response)?;

    Ok(Json(into_response(row)))
}

/// `POST /v1/policy-rules` — create a rule (admin only).
async fn create_rule(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Json(body): Json<CreateRuleRequest>,
) -> Result<(StatusCode, Json<PolicyRuleResponse>), axum::response::Response> {
    require_role(&ctx, UserRole::Admin).map_err(api_error_response)?;
    validate_action(&body.action).map_err(api_error_response)?;

    let repo = PolicyRepository::new(state.db.clone());

    // Priority uniqueness check.
    if repo
        .priority_in_use(ctx.workspace_id, body.priority, None)
        .await
        .map_err(api_error_response)?
    {
        return Err(priority_conflict_response());
    }

    let row = repo
        .create_rule(
            ctx.workspace_id,
            &body.name,
            body.priority,
            body.conditions.unwrap_or(Value::Array(vec![])),
            &body.action,
            body.action_params.unwrap_or(Value::Object(Default::default())),
            body.enabled.unwrap_or(true),
            body.dry_run.unwrap_or(false),
        )
        .await
        .map_err(api_error_response)?;

    Ok((StatusCode::CREATED, Json(into_response(row))))
}

/// `PUT /v1/policy-rules/:id` — update a rule (admin only).
async fn update_rule(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Path(rule_id): Path<Uuid>,
    Json(body): Json<UpdateRuleRequest>,
) -> Result<Json<PolicyRuleResponse>, axum::response::Response> {
    require_role(&ctx, UserRole::Admin).map_err(api_error_response)?;
    validate_action(&body.action).map_err(api_error_response)?;

    let repo = PolicyRepository::new(state.db.clone());

    // Priority uniqueness check (exclude self).
    if repo
        .priority_in_use(ctx.workspace_id, body.priority, Some(rule_id))
        .await
        .map_err(api_error_response)?
    {
        return Err(priority_conflict_response());
    }

    let row = repo
        .update_rule(
            ctx.workspace_id,
            rule_id,
            &body.name,
            body.priority,
            body.conditions.unwrap_or(Value::Array(vec![])),
            &body.action,
            body.action_params.unwrap_or(Value::Object(Default::default())),
            body.enabled.unwrap_or(true),
            body.dry_run.unwrap_or(false),
        )
        .await
        .map_err(api_error_response)?;

    Ok(Json(into_response(row)))
}

/// `DELETE /v1/policy-rules/:id` — delete a rule (admin only).
async fn delete_rule(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Path(rule_id): Path<Uuid>,
) -> Result<StatusCode, axum::response::Response> {
    require_role(&ctx, UserRole::Admin).map_err(api_error_response)?;

    let repo = PolicyRepository::new(state.db.clone());
    repo.delete_rule(ctx.workspace_id, rule_id)
        .await
        .map_err(api_error_response)?;

    Ok(StatusCode::NO_CONTENT)
}

/// `PATCH /v1/policy-rules/:id/enabled` — toggle enabled flag (admin only).
async fn toggle_enabled(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Path(rule_id): Path<Uuid>,
    Json(body): Json<ToggleRequest>,
) -> Result<Json<PolicyRuleResponse>, axum::response::Response> {
    require_role(&ctx, UserRole::Admin).map_err(api_error_response)?;

    let repo = PolicyRepository::new(state.db.clone());
    let row = repo
        .set_enabled(ctx.workspace_id, rule_id, body.value)
        .await
        .map_err(api_error_response)?;

    Ok(Json(into_response(row)))
}

/// `PATCH /v1/policy-rules/:id/dry-run` — toggle dry_run flag (admin only).
async fn toggle_dry_run(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Path(rule_id): Path<Uuid>,
    Json(body): Json<ToggleRequest>,
) -> Result<Json<PolicyRuleResponse>, axum::response::Response> {
    require_role(&ctx, UserRole::Admin).map_err(api_error_response)?;

    let repo = PolicyRepository::new(state.db.clone());
    let row = repo
        .set_dry_run(ctx.workspace_id, rule_id, body.value)
        .await
        .map_err(api_error_response)?;

    Ok(Json(into_response(row)))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn into_response(row: crate::db::policy_repo::PolicyRuleRow) -> PolicyRuleResponse {
    PolicyRuleResponse {
        id: row.id,
        workspace_id: row.workspace_id,
        name: row.name,
        priority: row.priority,
        conditions: row.conditions,
        action: row.action,
        action_params: row.action_params,
        enabled: row.enabled,
        dry_run: row.dry_run,
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

/// HTTP 409 with `{"code": "priority_conflict"}` body.
fn priority_conflict_response() -> axum::response::Response {
    use axum::{http::StatusCode, response::IntoResponse, Json};
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({
            "code": "priority_conflict",
            "message": "a rule with this priority already exists in the workspace"
        })),
    )
        .into_response()
}
