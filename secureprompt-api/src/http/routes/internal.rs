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
    if provided == expected {
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

    // --- Unwrap attestation signing key from the current valid license ---
    let kek = match crate::license::parse_kek(&state.config.license.model_kek_b64) {
        Some(k) => k,
        None => {
            tracing::warn!("attestation: KEK not configured or invalid");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "no valid license attestation key" })),
            ).into_response();
        }
    };
    let sk = match state.license.unwrap_attestation_key(&kek) {
        Some(k) => k,
        None => {
            tracing::warn!("attestation: license not Valid or attestation key absent");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "no valid license attestation key" })),
            ).into_response();
        }
    };

    // --- Metrics ---
    let lic_id = state.license.snapshot().lic_id.unwrap_or_else(|| "unknown".into());

    let deployment_fp = std::env::var("SECUREPROMPT_DEPLOYMENT_ID")
        .unwrap_or_else(|_| hostname_or_unknown());

    // Active seats: count users in the DB.  Best-effort — 0 on any error.
    let active_seats: u32 = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0)
        .try_into()
        .unwrap_or(0);

    // TODO(plan5): wire requests to the request counter / Prometheus metric.
    let requests: u64 = 0;

    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    // --- Build + sign ---
    let bundle = crate::license::attestation::build_bundle(
        &lic_id,
        &deployment_fp,
        active_seats,
        requests,
        &now,   // period_from = point sample (same as now)
        &now,
        &now,
    );

    match crate::license::attestation::sign_bundle(&bundle, &sk) {
        Ok(signed) => (StatusCode::OK, Json(serde_json::to_value(signed).unwrap_or_default())).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "attestation: failed to sign bundle");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "failed to sign attestation bundle" })),
            ).into_response()
        }
    }
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
