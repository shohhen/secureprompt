//! Fail-closed license gate. When the online revocation poller has confirmed the
//! license is revoked (`LicenseState::is_revoked()`), this middleware blocks the
//! request pipeline with `403`.
//!
//! Revocation is the ONE place the gateway is fail-closed — everywhere else a
//! license problem degrades to regex-only and keeps serving (see `license`).
//! A small allowlist stays open so a revoked deployment isn't bricked: the
//! operator can still reach health/observability and the auth endpoints to log
//! in, see the "revoked" state, and install a fresh license. Everything else —
//! the entire data plane and dashboard API — returns 403.

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

pub async fn enforce(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if state.license.is_revoked() && !is_allowlisted(req.uri().path()) {
        tracing::warn!(path = %req.uri().path(), "request blocked — license revoked");
        return api_error_response(ApiError::Forbidden(
            "license revoked — contact your vendor".into(),
        ));
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_matches() {
        assert!(is_allowlisted("/health"));
        assert!(is_allowlisted("/metrics"));
        assert!(is_allowlisted("/openapi.json"));
        assert!(is_allowlisted("/v1/auth/login"));
        assert!(is_allowlisted("/v1/auth/refresh"));
        assert!(is_allowlisted("/internal/attestation"));
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
