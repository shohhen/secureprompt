//! Fail-closed license gate. When the license is revoked
//! (`LicenseState::is_revoked()`) OR hard-stale — the offline revalidation budget
//! is exhausted (`LicenseState::is_hard_stale()`) — this middleware blocks the
//! data plane with `403`. Soft-stale is fail-open: it only withholds the model
//! key elsewhere and keeps serving (see `license`).
//!
//! These are the gateway's fail-closed conditions — everywhere else a license
//! problem degrades to regex-only and keeps serving. A small allowlist stays open
//! so a blocked deployment isn't bricked: the operator can still reach
//! health/observability and the auth endpoints to log in, see the state, and
//! install / revalidate a license. Everything else — the entire data plane and
//! dashboard API — returns 403.

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use secureprompt_common::errors::ApiError;

use crate::{app_state::AppState, http::api_error_response};

/// Paths that remain reachable even when the license is revoked. Matched as
/// prefixes so nested routes (e.g. `/v1/auth/login`) are covered.
const ALLOWLIST: &[&str] = &[
    "/health",
    "/metrics",
    "/openapi.json",
    "/v1/auth/", // login / refresh / logout — operator must be able to sign in
    "/internal/", // attestation; already token-gated
];

fn is_allowlisted(path: &str) -> bool {
    ALLOWLIST.iter().any(|p| path == p.trim_end_matches('/') || path.starts_with(p))
}

/// Block when the license is revoked OR hard-stale (offline budget blown), unless
/// the path is on the operator allowlist. Soft-stale does NOT block here — it only
/// withholds the model key via the license state (fail-open traffic).
fn should_block(revoked: bool, hard_stale: bool, path: &str) -> bool {
    (revoked || hard_stale) && !is_allowlisted(path)
}

pub async fn enforce(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let path = req.uri().path();
    if should_block(state.license.is_revoked(), state.license.is_hard_stale(), path) {
        let reason = if state.license.is_revoked() {
            "license revoked — contact your vendor"
        } else {
            "license requires revalidation — gateway could not reach the license server"
        };
        tracing::warn!(path = %path, revoked = state.license.is_revoked(), hard_stale = state.license.is_hard_stale(), reason, "request blocked by license gate");
        return api_error_response(ApiError::Forbidden(reason.into()));
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hard_stale_blocks_like_revoked() {
        assert!(should_block(/*revoked*/ false, /*hard_stale*/ true,  "/v1/chat/completions"));
        assert!(should_block(/*revoked*/ true,  /*hard_stale*/ false, "/v1/redact"));
        assert!(!should_block(false, true, "/health"));          // allowlist still open
        assert!(!should_block(false, false, "/v1/chat/completions")); // healthy → pass
        assert!(should_block(true, true, "/v1/chat/completions")); // both → blocked (revoked reason wins in enforce)
    }

    #[test]
    fn allowlist_matches() {
        assert!(is_allowlisted("/health"));
        assert!(is_allowlisted("/metrics"));
        assert!(is_allowlisted("/openapi.json"));
        assert!(is_allowlisted("/v1/auth/login"));
        assert!(is_allowlisted("/v1/auth/refresh"));
        assert!(is_allowlisted("/internal/attestation"));
    }

    /// Task 9 (2FA backend plan): `/v1/auth/2fa/*` must stay reachable even
    /// when the license is revoked/hard-stale, exactly like `/v1/auth/login`
    /// — otherwise a revoked deployment could lock an operator out mid-login
    /// (forced enrollment or a pending challenge) with no way to finish
    /// authenticating. These already pass today because `is_allowlisted`
    /// matches on the `/v1/auth/` prefix, which `/v1/auth/2fa/...` falls
    /// under; this test pins that behavior so a future narrowing of the
    /// prefix match can't silently re-block the 2FA routes.
    #[test]
    fn twofactor_routes_are_allowlisted() {
        assert!(is_allowlisted("/v1/auth/2fa/enroll"));
        assert!(is_allowlisted("/v1/auth/2fa/verify"));
        assert!(is_allowlisted("/v1/auth/2fa/challenge"));
        assert!(is_allowlisted("/v1/auth/2fa/disable"));
    }

    #[test]
    fn data_plane_is_blocked() {
        assert!(!is_allowlisted("/v1/chat/completions"));
        assert!(!is_allowlisted("/v1/redact"));
        assert!(!is_allowlisted("/v1/analytics/overview"));
        assert!(!is_allowlisted("/v1/users"));
        // a path merely containing "auth" elsewhere must NOT be exempt
        assert!(!is_allowlisted("/v1/coauthor"));
    }
}
