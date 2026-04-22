//! User management — GET /v1/users, POST /v1/users.
//!
//! GET  — any authenticated role; lists users in the caller's workspace.
//! POST — admin only; invites (creates) a new user in the same workspace.

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use secureprompt_common::errors::ApiError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    app_state::AppState,
    db::user_repo::UserRepository,
    http::{
        api_error_response,
        middleware::jwt_auth::{JwtAuthContext, UserRole},
        routes::dashboard::role::require_role,
    },
};

// ── DTOs ──────────────────────────────────────────────────────────────────────

const VALID_ROLES: &[&str] = &["owner", "admin", "developer", "viewer"];

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub email: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
    pub role: String,
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn routes() -> Router<AppState> {
    Router::new().route("/", get(list_users).post(create_user))
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `GET /v1/users` — list workspace members (any role).
async fn list_users(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
) -> Result<Json<Vec<UserResponse>>, axum::response::Response> {
    use sqlx::Row as _;

    let rows = sqlx::query(
        "SELECT id, workspace_id, email, role, created_at, updated_at
         FROM users
         WHERE workspace_id = $1
         ORDER BY created_at DESC",
    )
    .bind(ctx.workspace_id.0)
    .fetch_all(&state.db)
    .await
    .map_err(|e| api_error_response(ApiError::Database(e.to_string())))?;

    let result = rows
        .into_iter()
        .map(|r| UserResponse {
            id: r.get("id"),
            workspace_id: r.get("workspace_id"),
            email: r.get("email"),
            role: r.get("role"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        })
        .collect();

    Ok(Json(result))
}

/// `POST /v1/users` — create a user in the caller's workspace (admin only).
async fn create_user(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Json(body): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<UserResponse>), axum::response::Response> {
    require_role(&ctx, UserRole::Admin).map_err(api_error_response)?;

    if !VALID_ROLES.contains(&body.role.as_str()) {
        return Err(api_error_response(ApiError::BadRequest(format!(
            "role must be one of: {}",
            VALID_ROLES.join(", ")
        ))));
    }

    let repo = UserRepository::new(state.db.clone());
    let row = repo
        .create_user(ctx.workspace_id, &body.email, &body.password, &body.role)
        .await
        .map_err(api_error_response)?;

    // Fetch the role column (UserRow doesn't include it).
    let role: String = sqlx::query_scalar("SELECT role FROM users WHERE id = $1")
        .bind(row.id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| api_error_response(ApiError::Database(e.to_string())))?;

    Ok((
        StatusCode::CREATED,
        Json(UserResponse {
            id: row.id,
            workspace_id: row.workspace_id,
            email: row.email,
            role,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }),
    ))
}
