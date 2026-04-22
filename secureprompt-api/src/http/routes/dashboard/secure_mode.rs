//! Secure mode configuration — GET /v1/secure-mode, PUT /v1/secure-mode.
//!
//! GET  — any authenticated role; returns workspace secure mode config.
//! PUT  — admin only; upserts the config.

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
    db::secure_mode_repo::SecureModeRepository,
    http::{
        api_error_response,
        middleware::jwt_auth::{JwtAuthContext, UserRole},
        routes::dashboard::role::require_role,
    },
};

// ── DTOs ──────────────────────────────────────────────────────────────────────

const VALID_LEVELS: &[&str] = &["permissive", "standard", "strict"];

#[derive(Debug, Serialize)]
pub struct SecureModeResponse {
    pub workspace_id: Uuid,
    pub enabled: bool,
    pub level: String,
    pub block_on_pii_detection: bool,
    pub block_on_injection_detection: bool,
    pub redact_pii_in_responses: bool,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct PutSecureModeRequest {
    pub enabled: Option<bool>,
    pub level: Option<String>,
    pub block_on_pii_detection: Option<bool>,
    pub block_on_injection_detection: Option<bool>,
    pub redact_pii_in_responses: Option<bool>,
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn routes() -> Router<AppState> {
    Router::new().route("/", get(get_secure_mode).put(put_secure_mode))
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `GET /v1/secure-mode` — read workspace secure mode config.
async fn get_secure_mode(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
) -> Result<Json<SecureModeResponse>, axum::response::Response> {
    let repo = SecureModeRepository::new(state.db.clone());
    let row = repo
        .get(ctx.workspace_id)
        .await
        .map_err(api_error_response)?;

    Ok(Json(SecureModeResponse {
        workspace_id: row.workspace_id,
        enabled: row.enabled,
        level: row.level,
        block_on_pii_detection: row.block_on_pii_detection,
        block_on_injection_detection: row.block_on_injection_detection,
        redact_pii_in_responses: row.redact_pii_in_responses,
        updated_at: row.updated_at,
    }))
}

/// `PUT /v1/secure-mode` — upsert workspace secure mode config (admin only).
async fn put_secure_mode(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Json(body): Json<PutSecureModeRequest>,
) -> Result<(StatusCode, Json<SecureModeResponse>), axum::response::Response> {
    require_role(&ctx, UserRole::Admin).map_err(api_error_response)?;

    if let Some(ref level) = body.level {
        if !VALID_LEVELS.contains(&level.as_str()) {
            return Err(api_error_response(ApiError::BadRequest(format!(
                "level must be one of: {}",
                VALID_LEVELS.join(", ")
            ))));
        }
    }

    let repo = SecureModeRepository::new(state.db.clone());
    let row = repo
        .upsert(
            ctx.workspace_id,
            body.enabled,
            body.level.as_deref(),
            body.block_on_pii_detection,
            body.block_on_injection_detection,
            body.redact_pii_in_responses,
        )
        .await
        .map_err(api_error_response)?;

    Ok((
        StatusCode::OK,
        Json(SecureModeResponse {
            workspace_id: row.workspace_id,
            enabled: row.enabled,
            level: row.level,
            block_on_pii_detection: row.block_on_pii_detection,
            block_on_injection_detection: row.block_on_injection_detection,
            redact_pii_in_responses: row.redact_pii_in_responses,
            updated_at: row.updated_at,
        }),
    ))
}
