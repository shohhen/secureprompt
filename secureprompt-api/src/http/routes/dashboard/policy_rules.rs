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

use secureprompt_common::tasks::{task_types, TaskEnvelope, QUEUE_POLICY_INDEX};

use crate::{
    app_state::AppState,
    db::admin_audit_repo::AdminActor,
    db::policy_repo::PolicyRepository,
    http::{
        api_error_response,
        middleware::jwt_auth::{JwtAuthContext, UserRole},
        routes::dashboard::role::require_role,
    },
    redis::enqueue_task,
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

/// Reject rule shapes the engine cannot honour, at SAVE time, rather than
/// letting them sit in the database looking enforced.
///
/// `conditions` arrives as an unvalidated `serde_json::Value` from any API
/// client, so anything not rejected here is something `policy/engine.rs` has
/// to survive at request time. Two shapes are rejected:
///
///   * an invalid `content_regex` pattern (WS1-6b). The field was evaluated
///     with `str::contains` until this fix wave, so `^sk-[A-Za-z0-9]{32}$`
///     was accepted and silently matched nothing. Now that it compiles as a
///     real regex, an operator who mistypes one must be told at save time
///     rather than discovering it from a breach.
///
///   * two or more `detection_class` conditions on one rule (WS1-8). A
///     detection has exactly one class, and `rule_matches` requires a
///     SINGLE detection to satisfy every detection-scoped condition, so
///     such a rule can never fire. The operator almost certainly means OR;
///     `detection_class in [...]` is that, as ONE condition. Rejecting is
///     better than silently reinterpreting, because guessing OR would turn
///     an `allow` rule that currently protects the request by not firing
///     into one that waves it through.
///
/// Deliberately NOT exhaustive: unknown field names still pass, because
/// `matches_condition` returns `false` for them and the fail-closed net in
/// `pipeline/service.rs` covers the request. Tightening that into a
/// whitelist would break any workspace already storing extra metadata on a
/// condition object, which is a compatibility decision, not a security one.
pub(crate) fn validate_conditions(conditions: &Value) -> Result<(), ApiError> {
    let Some(array) = conditions.as_array() else {
        // A non-array `conditions` makes `rule_matches` return `true`
        // (match everything) — odd, but pre-existing and not a leak.
        return Ok(());
    };

    let mut detection_class_conditions = 0usize;

    for condition in array {
        let field = condition.get("field").and_then(Value::as_str);

        if field == Some("detection_class") {
            detection_class_conditions += 1;
        }

        if field == Some("content_regex") {
            if let Some(pattern) = condition.get("value").and_then(Value::as_str) {
                if let Err(error) = regex::Regex::new(pattern) {
                    // `regex`'s Display is multi-line and includes a caret
                    // diagram; flatten it so it survives a JSON error body.
                    let detail = error.to_string().replace('\n', " ");
                    return Err(ApiError::BadRequest(format!(
                        "condition field `content_regex` is not a valid regular expression: {detail}"
                    )));
                }
            }
        }
    }

    if detection_class_conditions > 1 {
        return Err(ApiError::BadRequest(format!(
            "a rule may have at most one `detection_class` condition, found \
             {detection_class_conditions}. A detection has exactly one class, so a rule \
             requiring two of them can never match anything. Combine the \
             classes into a single condition: \
             {{\"field\": \"detection_class\", \"op\": \"in\", \"value\": [...]}}"
        )));
    }

    Ok(())
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
    let actor = AdminActor::resolve(
        &state.db,
        ctx.workspace_id.0,
        ctx.user_id,
        ctx.role.as_db_str(),
    )
    .await;

    // Priority uniqueness check.
    if repo
        .priority_in_use(ctx.workspace_id, body.priority, None)
        .await
        .map_err(api_error_response)?
    {
        return Err(priority_conflict_response());
    }

    let conditions = body.conditions.unwrap_or(Value::Array(vec![]));
    validate_conditions(&conditions).map_err(api_error_response)?;

    let row = repo
        .create_rule(
            ctx.workspace_id,
            &body.name,
            body.priority,
            conditions,
            &body.action,
            body.action_params.unwrap_or(Value::Object(Default::default())),
            body.enabled.unwrap_or(true),
            body.dry_run.unwrap_or(false),
            &actor,
        )
        .await
        .map_err(api_error_response)?;

    let response = into_response(row);
    enqueue_index_task(&state, response.id, &response.name, ctx.workspace_id.0).await;
    Ok((StatusCode::CREATED, Json(response)))
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
    let actor = AdminActor::resolve(
        &state.db,
        ctx.workspace_id.0,
        ctx.user_id,
        ctx.role.as_db_str(),
    )
    .await;

    // Priority uniqueness check (exclude self).
    if repo
        .priority_in_use(ctx.workspace_id, body.priority, Some(rule_id))
        .await
        .map_err(api_error_response)?
    {
        return Err(priority_conflict_response());
    }

    let conditions = body.conditions.unwrap_or(Value::Array(vec![]));
    validate_conditions(&conditions).map_err(api_error_response)?;

    let row = repo
        .update_rule(
            ctx.workspace_id,
            rule_id,
            &body.name,
            body.priority,
            conditions,
            &body.action,
            body.action_params.unwrap_or(Value::Object(Default::default())),
            body.enabled.unwrap_or(true),
            body.dry_run.unwrap_or(false),
            &actor,
        )
        .await
        .map_err(api_error_response)?;

    let response = into_response(row);
    enqueue_index_task(&state, response.id, &response.name, ctx.workspace_id.0).await;
    Ok(Json(response))
}

/// `DELETE /v1/policy-rules/:id` — delete a rule (admin only).
async fn delete_rule(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Path(rule_id): Path<Uuid>,
) -> Result<StatusCode, axum::response::Response> {
    require_role(&ctx, UserRole::Admin).map_err(api_error_response)?;

    let repo = PolicyRepository::new(state.db.clone());
    let actor = AdminActor::resolve(
        &state.db,
        ctx.workspace_id.0,
        ctx.user_id,
        ctx.role.as_db_str(),
    )
    .await;
    repo.delete_rule(ctx.workspace_id, rule_id, &actor)
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
    let actor = AdminActor::resolve(
        &state.db,
        ctx.workspace_id.0,
        ctx.user_id,
        ctx.role.as_db_str(),
    )
    .await;
    let row = repo
        .set_enabled(ctx.workspace_id, rule_id, body.value, &actor)
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
    let actor = AdminActor::resolve(
        &state.db,
        ctx.workspace_id.0,
        ctx.user_id,
        ctx.role.as_db_str(),
    )
    .await;
    let row = repo
        .set_dry_run(ctx.workspace_id, rule_id, body.value, &actor)
        .await
        .map_err(api_error_response)?;

    Ok(Json(into_response(row)))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Enqueue a background task to embed and index this rule in Qdrant.
/// Errors are logged but not propagated — rule creation succeeds even if indexing fails.
async fn enqueue_index_task(state: &AppState, rule_id: Uuid, rule_name: &str, workspace_id: Uuid) {
    let envelope = TaskEnvelope::new(
        task_types::INDEX_POLICY_RULE,
        serde_json::json!({
            "rule_id": rule_id.to_string(),
            "condition_text": rule_name,
        }),
        workspace_id,
    );
    let json = match serde_json::to_string(&envelope) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "failed to serialize IndexPolicyRule envelope");
            return;
        }
    };
    if let Err(e) = enqueue_task(&state.redis_pool, QUEUE_POLICY_INDEX, &json).await {
        tracing::warn!(error = %e, %rule_id, "failed to enqueue IndexPolicyRule task");
    }
}

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
