//! Phase 5 / Plan 05-06 — POST /v1/telemetry/client-error
//!
//! Accepts bounded frontend error events. Logs them via `tracing::warn!`
//! and increments the `secureprompt_dashboard_client_errors_total{component}`
//! counter. Does NOT persist to Postgres or ClickHouse (ephemeral; observable
//! only via logs + metrics — avoids write amplification on noisy client errors).

use axum::{extract::State, http::StatusCode, response::Response, Extension, Json};
use secureprompt_common::errors::ApiError;
use serde::Deserialize;

use crate::{
    app_state::AppState,
    http::{api_error_response, middleware::jwt_auth::JwtAuthContext},
};

// ── Limits (LIM-02 / threat T-05-06) ─────────────────────────────────────────

const MAX_COMPONENT_LEN: usize = 128;
const MAX_MESSAGE_LEN: usize = 1024;
const MAX_URL_LEN: usize = 512;
const MAX_CONTEXT_BYTES: usize = 2048;

// ── Request body ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ClientErrorEvent {
    pub component: String,
    pub message: String,
    pub url: String,
    pub user_agent: Option<String>,
    /// Arbitrary structured context; serialized size capped at 2 KB.
    pub context: Option<serde_json::Value>,
}

// ── Handler ───────────────────────────────────────────────────────────────────

/// POST /v1/telemetry/client-error
///
/// JWT-gated. Returns 204 No Content on success.
/// Returns 400 if any field exceeds its size limit.
/// Returns 401 without a valid JWT (enforced by the route layer in mod.rs).
///
/// # Errors
/// Returns `ApiError::BadRequest` when a payload field exceeds its size limit.
pub async fn client_error(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Json(event): Json<ClientErrorEvent>,
) -> Result<StatusCode, Response> {
    // ── Input validation ──────────────────────────────────────────────────────
    if event.component.len() > MAX_COMPONENT_LEN {
        return Err(api_error_response(ApiError::BadRequest(
            "component too long".into(),
        )));
    }
    if event.message.len() > MAX_MESSAGE_LEN {
        return Err(api_error_response(ApiError::BadRequest(
            "message too long".into(),
        )));
    }
    if event.url.len() > MAX_URL_LEN {
        return Err(api_error_response(ApiError::BadRequest(
            "url too long".into(),
        )));
    }
    if let Some(ref ctx_val) = event.context {
        let serialized_len = serde_json::to_vec(ctx_val)
            .map(|v| v.len())
            .unwrap_or(usize::MAX);
        if serialized_len > MAX_CONTEXT_BYTES {
            return Err(api_error_response(ApiError::BadRequest(
                "context too large".into(),
            )));
        }
    }

    // ── Log (structured) ──────────────────────────────────────────────────────
    tracing::warn!(
        workspace_id = %ctx.workspace_id.0,
        user_id = %ctx.user_id,
        component = %event.component,
        message = %event.message,
        url = %event.url,
        user_agent = ?event.user_agent,
        "client_error"
    );

    // ── Metric ────────────────────────────────────────────────────────────────
    state.metrics.inc_client_error(&event.component);

    Ok(StatusCode::NO_CONTENT)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_are_reasonable() {
        assert!(MAX_COMPONENT_LEN < MAX_MESSAGE_LEN);
        assert!(MAX_MESSAGE_LEN <= MAX_CONTEXT_BYTES * 2);
        assert!(MAX_CONTEXT_BYTES == 2048);
    }

    #[test]
    fn component_len_constant() {
        assert_eq!(MAX_COMPONENT_LEN, 128);
    }
}
