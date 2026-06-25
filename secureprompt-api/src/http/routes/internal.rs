//! Internal gateway routes (Plan 5).  Authenticated via the shared
//! `ML_SIDECAR_INTERNAL_TOKEN` bearer — the same secret used by the ML sidecar
//! push receiver.  These routes MUST NOT be reachable from the public internet;
//! they are intended for on-prem ops tooling and sp-admin reconciliation.
use crate::app_state::AppState;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};

/// Constant-time byte-slice equality to prevent timing oracles.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) { diff |= x ^ y; }
    diff == 0
}

/// Verify the request carries a valid internal bearer token.
/// Returns `Err((status, message))` on failure.
fn check_internal_token(headers: &HeaderMap, expected: &str) -> Result<(), (StatusCode, &'static str)> {
    if expected.is_empty() {
        // Internal token not configured → refuse (safer than allowing all requests).
        return Err((StatusCode::SERVICE_UNAVAILABLE, "internal token not configured"));
    }
    let auth = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let provided = auth.strip_prefix("Bearer ").unwrap_or("");
    if ct_eq(provided.as_bytes(), expected.as_bytes()) {
        Ok(())
    } else {
        Err((StatusCode::UNAUTHORIZED, "invalid internal token"))
    }
}

/// `GET /internal/attestation`
///
/// Builds and returns a signed `SignedAttestation` JSON payload for the current
/// deployment.  Best-effort: returns 503 when no valid license / attestation
/// key is available.  NEVER panics and NEVER touches the chat hot path.
pub async fn get_attestation(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // --- Auth ---
    if let Err((status, msg)) = check_internal_token(&headers, &state.config.license.internal_token) {
        return (status, Json(serde_json::json!({ "error": msg }))).into_response();
    }

    match build_signed_attestation(&state).await {
        Some(signed) => (StatusCode::OK, Json(signed)).into_response(),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "no valid license attestation key" })),
        )
            .into_response(),
    }
}

/// Build + sign an attestation bundle for the current deployment. Returns `None`
/// when there is no valid license / attestation key (the license isn't `Valid`,
/// is revoked, or the KEK is missing) — the caller decides 503 vs skip. Shared
/// by `GET /internal/attestation` and the periodic heartbeat uploader so both
/// produce byte-identical bundles. Best-effort; never panics.
pub async fn build_signed_attestation(
    state: &AppState,
) -> Option<sp_license::SignedAttestation> {
    let kek = crate::license::parse_kek(&crate::license::effective_attest_kek(
        &state.config.license.attest_kek_b64,
    ))?;
    // Only yields a key when the license is Valid and not revoked.
    let sk = state.license.unwrap_attestation_key(&kek)?;
    let lic_id = state.license.snapshot().lic_id?;

    let deployment_fp =
        std::env::var("SECUREPROMPT_DEPLOYMENT_ID").unwrap_or_else(|_| hostname_or_unknown());

    // Active seats: count users in the DB. Best-effort — 0 on any error.
    let active_seats: u32 = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0)
        .try_into()
        .unwrap_or(0);

    // TODO(plan5): wire requests to the request counter / Prometheus metric.
    let requests: u64 = 0;

    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let actual_digest = std::env::var("SECUREPROMPT_IMAGE_DIGEST").unwrap_or_default();
    let tamper_flags = state.license.tamper_flags("api", &actual_digest);

    let mut bundle = crate::license::attestation::build_bundle(
        &lic_id,
        &deployment_fp,
        active_seats,
        requests,
        &now, // period_from = point sample (same as now)
        &now,
        &now,
    );
    bundle.tamper_flags = tamper_flags;

    crate::license::attestation::sign_bundle(&bundle, &sk)
        .map_err(|e| tracing::error!(error = %e, "attestation: failed to sign bundle"))
        .ok()
}

fn hostname_or_unknown() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}
