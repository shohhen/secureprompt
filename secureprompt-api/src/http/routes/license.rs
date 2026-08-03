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
use serde_json::json;

use crate::{
    app_state::AppState,
    db::admin_audit_repo::{AdminActor, AdminAuditAction, AdminAuditEntry},
    db::license_repo,
    http::{
        api_error_response,
        middleware::jwt_auth::{JwtAuthContext, UserRole},
        routes::dashboard::role::require_role,
    },
    license::{
        effective_vendor_pubkey, load_and_verify_token, parse_vendor_key,
        resolve_active_token, LicenseSnapshot, LicenseStatus,
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

/// The stable string form of a verdict, for both the API response and the
/// audit row — one function so the two cannot describe the same license
/// differently.
const fn status_str(status: LicenseStatus) -> &'static str {
    match status {
        LicenseStatus::Valid => "Valid",
        LicenseStatus::Grace => "Grace",
        LicenseStatus::Unlicensed => "Unlicensed",
        LicenseStatus::Revoked => "Revoked",
    }
}

/// Build the status response from the current `LicenseState` + DB source.
async fn build_response(state: &AppState) -> LicenseStatusResponse {
    let snap = state.license.snapshot();
    let status_str = status_str(state.license.effective_status());
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

    // The verdict is computed BEFORE the write, not after, because the audit
    // row has to be built from it and the row has to be in the same
    // transaction as the token it describes. `load_and_verify_token` is pure —
    // signature check, clock comparison, no I/O — so evaluating it early
    // changes nothing about what it returns.
    let now = chrono::Utc::now().timestamp();
    let snapshot = load_and_verify_token(body.token.trim(), &vk, now);
    let new_lic_id = snapshot.lic_id.clone();

    // What the deployment was running under before this paste. "Replaced the
    // license" and "licensed a deployment that had none" are different events.
    let source_before = resolve_source(&state).await;

    let actor = AdminActor::resolve(
        &state.db,
        ctx.workspace_id.0,
        ctx.user_id,
        ctx.role.as_db_str(),
    )
    .await;
    let entry = AdminAuditEntry::on_named_object(
        AdminAuditAction::LicenseActivated,
        // The vendor's `lic_id`, which is what a revocation is a verdict
        // about, and the only identifier that survives a later replacement.
        // `None` when the token did not verify as a live license — the row
        // then still records that somebody activated something and what the
        // gateway concluded about it.
        new_lic_id.clone(),
    )
    .with_detail(json!({
        "status": status_str(snapshot.status),
        "expires_at": snapshot.expires_at,
        // The COUNT, not the list: a feature list is vendor-controlled text of
        // unbounded length, and how many were granted is the auditable shape.
        "feature_count": snapshot.features.len(),
        "source_before": source_before,
        "source_after": "db",
    }));

    // Persist the token AND the record of who installed it, together. THE
    // TOKEN ITSELF IS NEVER IN `entry`: it is a bearer entitlement, it is
    // stored in `license_activation` (a declared artifact with its own
    // lifecycle), and `admin_audit` is never purged.
    license_repo::upsert_audited(
        &state.db,
        body.token.trim(),
        Some(ctx.user_id),
        &actor,
        &entry,
    )
    .await
    .map_err(api_error_response)?;

    // Live-swap the license snapshot.
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

    // What removing the row will leave behind, worked out BEFORE the delete so
    // it can go in the audit row that shares the delete's transaction. The
    // fallback is the ENV token by definition — `resolve_active_token` prefers
    // the DB row, and after this delete there is none — so this needs no read.
    let now = chrono::Utc::now().timestamp();
    let env_token = state.config.license.license_token.clone();
    let source_after = if env_token.is_empty() { "none" } else { "env" };
    let vk_b64 = effective_vendor_pubkey(&state.config.license.pubkey_b64);
    let snapshot_after = match parse_vendor_key(&vk_b64) {
        Some(vk) => load_and_verify_token(&env_token, &vk, now),
        None => LicenseSnapshot::unlicensed(),
    };

    let actor = AdminActor::resolve(
        &state.db,
        ctx.workspace_id.0,
        ctx.user_id,
        ctx.role.as_db_str(),
    )
    .await;
    let entry = AdminAuditEntry::on_named_object(
        AdminAuditAction::LicenseCleared,
        // The id of the license being REMOVED, captured while it is still the
        // active one. Afterwards there is nothing left to name it.
        state.license.snapshot().lic_id,
    )
    .with_detail(json!({
        "status_after": status_str(snapshot_after.status),
        "source_after": source_after,
    }));

    license_repo::clear_audited(&state.db, &actor, &entry)
        .await
        .map_err(api_error_response)?;

    // Re-resolve and live-swap. The re-read is kept rather than reusing
    // `snapshot_after`: it is the same value by construction, and going back
    // to `resolve_active_token` means the applied state comes from the
    // database as it now is rather than from this handler's prediction of it.
    let token = resolve_active_token(&state.db, &state.config.license.license_token).await;
    let snapshot = match parse_vendor_key(&vk_b64) {
        Some(vk) => load_and_verify_token(&token, &vk, now),
        None => LicenseSnapshot::unlicensed(),
    };
    state.license.set(snapshot);

    best_effort_push(&state).await;

    Ok(Json(build_response(&state).await))
}
