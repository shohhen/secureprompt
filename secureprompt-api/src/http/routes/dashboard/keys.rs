//! Phase 5 / Plan 05-04 — `/v1/keys` API key management handlers.
//!
//! Routes:
//!   GET  /v1/keys        — list keys (any role)
//!   POST /v1/keys        — create key (admin only); returns plaintext ONCE
//!   DELETE /v1/keys/:id  — revoke key (admin only)
//!
//! Security:
//!   * `CreateKeyResponse` and `KeyResponse` are DISTINCT structs — POST
//!     returns `api_key` (plaintext); GET never does.
//!   * Plaintext = `"sp_" + 48 random alphanumeric chars` via `OsRng`.
//!   * RLS: every repo call wraps `set_config('app.current_workspace_id', …)`.

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    routing::{delete, get},
    Json, Router,
};
use chrono::{DateTime, Utc};
use secureprompt_common::errors::ApiError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    app_state::AppState,
    db::api_key_repo::ApiKeyRepository,
    http::{
        api_error_response,
        middleware::jwt_auth::{JwtAuthContext, UserRole},
        routes::dashboard::role::require_role,
    },
};

// ── DTOs ──────────────────────────────────────────────────────────────────────

/// Response for GET /v1/keys — never includes the plaintext key.
#[derive(Debug, Serialize)]
pub struct KeyResponse {
    pub id: Uuid,
    pub name: String,
    /// First 8 characters of the plaintext key (safe to display).
    pub prefix: String,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Response for POST /v1/keys — includes `api_key` exactly once.
/// This struct is intentionally DISTINCT from `KeyResponse`.
#[derive(Debug, Serialize)]
pub struct CreateKeyResponse {
    pub id: Uuid,
    pub name: String,
    /// The full plaintext key — shown once, never stored.
    pub api_key: String,
    /// First 8 characters for display after the dialog is closed.
    pub prefix: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateKeyRequest {
    pub name: String,
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_keys).post(create_key))
        .route("/:id", delete(revoke_key))
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `GET /v1/keys` — list API keys for the workspace (any role).
async fn list_keys(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
) -> Result<Json<Vec<KeyResponse>>, axum::response::Response> {
    let repo = ApiKeyRepository::new(state.db.clone());
    let rows = repo
        .list_api_keys(ctx.workspace_id)
        .await
        .map_err(api_error_response)?;

    let items = rows
        .into_iter()
        .map(|r| {
            let prefix = r.key_hash.chars().take(8).collect::<String>();
            KeyResponse {
                id: r.id,
                name: r.name,
                prefix,
                created_at: r.created_at,
                revoked_at: r.revoked_at,
            }
        })
        .collect();

    Ok(Json(items))
}

/// `POST /v1/keys` — create a new API key (admin only).
/// Returns the plaintext key exactly once in `CreateKeyResponse.api_key`.
async fn create_key(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Json(body): Json<CreateKeyRequest>,
) -> Result<(StatusCode, Json<CreateKeyResponse>), axum::response::Response> {
    require_role(&ctx, UserRole::Admin).map_err(api_error_response)?;

    let repo = ApiKeyRepository::new(state.db.clone());
    let (record, plaintext) = repo
        .create(ctx.workspace_id, &body.name)
        .await
        .map_err(api_error_response)?;

    // Prefix = first 8 chars of the plaintext key (e.g. "sp_ABCDE").
    let prefix: String = plaintext.chars().take(8).collect();

    Ok((
        StatusCode::CREATED,
        Json(CreateKeyResponse {
            id: record.id,
            name: record.name,
            api_key: plaintext,
            prefix,
            created_at: record.created_at,
        }),
    ))
}

/// `DELETE /v1/keys/:id` — revoke an API key (admin only).
async fn revoke_key(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Path(key_id): Path<Uuid>,
) -> Result<StatusCode, axum::response::Response> {
    require_role(&ctx, UserRole::Admin).map_err(api_error_response)?;

    let repo = ApiKeyRepository::new(state.db.clone());
    repo.revoke(ctx.workspace_id, key_id)
        .await
        .map_err(|e| {
            api_error_response(match e {
                ApiError::NotFound(_) => e,
                other => other,
            })
        })?;

    Ok(StatusCode::NO_CONTENT)
}
