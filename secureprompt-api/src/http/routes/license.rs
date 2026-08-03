//! Plan 3 Task 3 — `GET/PUT/DELETE /v1/license` (admin-gated, live-apply).
//!
//! Routes:
//!   GET    /v1/license  — current license status + source
//!   PUT    /v1/license  — activate a new signed token (admin only)
//!   DELETE /v1/license  — remove DB-stored token, revert to env/none (admin only)
//!
//! Security:
//!   * All three routes require at least Admin role (same gate as /v1/providers).
//!   * PUT verifies the Ed25519 signature before touching state — bad sig → 400, no state change.
//!   * Model-key re-push is best-effort (errors are logged, never fail the response).

use axum::{
    extract::{Extension, State},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    db::license_repo,
    http::{
        api_error_response,
        middleware::jwt_auth::{JwtAuthContext, UserRole},
        routes::dashboard::role::require_role,
    },
    license::{
        effective_vendor_pubkey, load_and_verify_token, parse_vendor_key,
        resolve_active_token, LicenseStatus,
    },
};
use ed25519_dalek::VerifyingKey;
use secureprompt_common::errors::ApiError;
use sp_license::sign::decode_verified_token;

// ── DTOs ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct LicenseStatusResponse {
    pub customer_name: Option<String>,
    pub lic_id: Option<String>,
    pub expires_at: Option<String>,
    pub features: Vec<String>,
    pub status: String,
    /// "db" | "env" | "none"
    pub source: String,
}

#[derive(Debug, Deserialize)]
pub struct ActivateRequest {
    pub token: String,
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn routes() -> Router<AppState> {
    Router::new().route("/", get(get_license).put(activate_license).delete(delete_license))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Determine the license token `source` ("db" | "env" | "none") by checking
/// whether a DB row exists and whether the env token is non-empty.
async fn resolve_source(state: &AppState) -> &'static str {
    match license_repo::get(&state.db).await {
        Ok(Some(_)) => "db",
        _ => {
            if state.config.license.license_token.is_empty() {
                "none"
            } else {
                "env"
            }
        }
    }
}

/// Build the status response from the current `LicenseState` + DB source.
async fn build_response(state: &AppState) -> LicenseStatusResponse {
    let snap = state.license.snapshot();
    let status_str = match state.license.effective_status() {
        LicenseStatus::Valid => "Valid",
        LicenseStatus::Grace => "Grace",
        LicenseStatus::Unlicensed => "Unlicensed",
        LicenseStatus::Revoked => "Revoked",
    };
    let source = resolve_source(state).await;
    LicenseStatusResponse {
        customer_name: snap.customer_name,
        lic_id: snap.lic_id,
        expires_at: snap.expires_at,
        features: snap.features,
        status: status_str.to_owned(),
        source: source.to_owned(),
    }
}

/// Parse the vendor key or return a 500.
fn vendor_key(state: &AppState) -> Result<VerifyingKey, axum::response::Response> {
    let b64 = effective_vendor_pubkey(&state.config.license.pubkey_b64);
    parse_vendor_key(&b64).ok_or_else(|| {
        api_error_response(ApiError::Internal(
            "vendor public key is not configured or invalid".into(),
        ))
    })
}

/// Best-effort relay of the wrapped model blob after a license swap.
/// The gateway forwards the ciphertext as-is; the sidecar owns the MODEL-KEK.
/// Errors are logged at warn level — they never fail the caller's response.
async fn best_effort_push(state: &AppState) {
    let internal_token = &state.config.license.internal_token;
    if internal_token.is_empty() {
        return;
    }
    let snap = state.license.snapshot();
    if let (Some(w), Some(lic)) = (snap.wrapped_model_key.as_ref(), snap.lic_id.as_ref()) {
        let _ = state
            .ml_sidecar
            .push_wrapped_model_key(w, lic, internal_token)
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "best-effort wrapped model-key push failed (ignored)");
            });
    }
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `GET /v1/license` — current license status. Admin only (same gate as PUT/DELETE).
async fn get_license(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
) -> Result<Json<LicenseStatusResponse>, axum::response::Response> {
    require_role(&ctx, UserRole::Admin).map_err(api_error_response)?;
    Ok(Json(build_response(&state).await))
}

/// `PUT /v1/license` body `{"token": "<compact token>"}` — admin only.
///
/// 1. Verify the Ed25519 signature — bad sig → 400, NO state change.
/// 2. Upsert into `license_activation`.
/// 3. Live-swap the snapshot in `LicenseState`.
/// 4. Best-effort model-key re-push.
/// 5. Return new GET status.
async fn activate_license(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Json(body): Json<ActivateRequest>,
) -> Result<Json<LicenseStatusResponse>, axum::response::Response> {
    require_role(&ctx, UserRole::Admin).map_err(api_error_response)?;

    let vk = vendor_key(&state)?;

    // Signature check first — bad sig → 400, do nothing else.
    decode_verified_token(body.token.trim(), &vk).map_err(|_| {
        api_error_response(ApiError::BadRequest("invalid license signature".into()))
    })?;

    // Persist the token.
    license_repo::upsert(&state.db, body.token.trim(), Some(ctx.user_id))
        .await
        .map_err(|e| api_error_response(ApiError::Database(e.to_string())))?;

    // Live-swap the license snapshot.
    let now = chrono::Utc::now().timestamp();
    let snapshot = load_and_verify_token(body.token.trim(), &vk, now);
    let new_lic_id = snapshot.lic_id.clone();
    state.license.set(snapshot);

    // WS4-4 — a revocation is a verdict about one `lic_id`. Installing a
    // DIFFERENT vendor-signed license supersedes it, so a revoked gateway
    // recovers from the console with no container restart and no SQL against
    // `license_activation`. Re-pasting the revoked token clears nothing (see
    // `LicenseState::clear_revocation_if_superseded`), and `lic_id` is `None`
    // unless the replacement is Valid — an expired license cannot lift a
    // revocation either.
    if let Some(lic_id) = new_lic_id.as_deref() {
        if state.license.clear_revocation_if_superseded(lic_id) {
            tracing::warn!(
                lic_id,
                "revocation superseded by a newly activated license — gateway is serving again"
            );
        }
    }

    // Best-effort model-key push (ignore errors).
    best_effort_push(&state).await;

    Ok(Json(build_response(&state).await))
}

/// `DELETE /v1/license` — admin only. Removes the DB row and reverts to
/// the env/config token (or Unlicensed if that's empty too).
async fn delete_license(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
) -> Result<Json<LicenseStatusResponse>, axum::response::Response> {
    require_role(&ctx, UserRole::Admin).map_err(api_error_response)?;

    license_repo::clear(&state.db)
        .await
        .map_err(|e| api_error_response(ApiError::Database(e.to_string())))?;

    // Re-resolve and live-swap.
    let token = resolve_active_token(&state.db, &state.config.license.license_token).await;
    let now = chrono::Utc::now().timestamp();
    let snapshot = {
        let vk_b64 = effective_vendor_pubkey(&state.config.license.pubkey_b64);
        match parse_vendor_key(&vk_b64) {
            Some(vk) => load_and_verify_token(&token, &vk, now),
            None => crate::license::LicenseSnapshot::unlicensed(),
        }
    };
    state.license.set(snapshot);

    best_effort_push(&state).await;

    Ok(Json(build_response(&state).await))
}
