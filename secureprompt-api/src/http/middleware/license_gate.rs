//! WS4-4 — the license gate, and the recovery path it must never close.
//!
//! Two conditions take the gateway out of good standing:
//!
//!   * **Revoked** — `LicenseState::is_revoked()`. A definitive verdict the
//!     vendor published about this specific `lic_id`. Fail-CLOSED: 403 for the
//!     whole data plane and dashboard API.
//!   * **Hard-stale** — `LicenseState::is_hard_stale()`. The offline
//!     revalidation budget in the signed token is exhausted because the gateway
//!     has not been able to reach the license server. Nobody said anything is
//!     wrong with this license; the gateway simply cannot confirm it is still
//!     right. That is a *connectivity* failure of the vendor's infrastructure,
//!     structurally identical to the ML sidecar going away — so it takes the
//!     WS2-3 treatment: **degrade, loudly**, rather than take the customer's
//!     traffic down for a vendor outage.
//!
//! ## Why hard-stale degrades instead of blocking
//!
//! `degrade_with_alert` here means exactly what it means in
//! [`crate::http::sidecar_coverage`]: serve the request, emit the
//! operator-facing alert (a `tracing::error!` with a stable `alert=` key plus a
//! Prometheus counter), and set a response header naming the bounded reason so
//! a client can tell without inspecting counts. The `action` labels are taken
//! from [`SidecarUnavailablePolicy::as_str`] at compile time, so the two gates
//! cannot drift into two vocabularies.
//!
//! Degrading is not a licence to run unlicensed forever: hard-stale still maps
//! to `LicenseStatus::Revoked` in `LicenseState::effective_status`, which
//! withholds every entitlement — features off, no attestation key, no model-key
//! relay. The product's paid capability stops; the gateway does not brick.
//!
//! ## The recovery allowlist
//!
//! [`RECOVERY_ALLOWLIST`] paths answer in **every** license state. It exists
//! because a gate that 403s the endpoint you need in order to fix the gate is
//! not fail-closed, it is bricked: the recorded field recovery for a revoked
//! deployment was "disable the env token, recreate the API container, reach
//! Unlicensed, activate from the console". `/v1/license` is on the list so that
//! sequence is never needed again.
//!
//! Allowlisting is **above the license gate only** — never above
//! authentication. `/v1/license` keeps the `jwt_auth::require` layer and the
//! admin RBAC check it has always had, because those layers are nested INSIDE
//! this one (see `http::build_router`). An unauthenticated caller still gets
//! 401 and a viewer still gets 403 on a revoked gateway; see
//! `tests/license_routes.rs::recovery_route_is_above_the_license_gate_not_above_auth`.

use axum::{
    extract::{Request, State},
    http::HeaderValue,
    middleware::Next,
    response::Response,
};
use secureprompt_common::errors::ApiError;

use crate::{
    app_state::AppState, db::sidecar_policy_repo::SidecarUnavailablePolicy,
    http::api_error_response,
};

/// Response header naming the license condition an answer was served under.
///
/// Bounded values only — [`LicenseOutage::as_str`]. Deliberately distinct from
/// `SIDECAR_DEGRADED_HEADER`: the two degradations have different causes and
/// different remedies, and a client that retries on one should not confuse it
/// with the other.
pub const LICENSE_DEGRADED_HEADER: &str = "x-secureprompt-license-degraded";

/// Metric/log `action` label for a license condition the gate failed closed on.
/// Bound to the WS2-3 constant at compile time so the two gates report one
/// vocabulary; a rename there is a compile error here rather than a silent
/// second series.
const ACTION_BLOCK: &str = SidecarUnavailablePolicy::Block.as_str();
/// Same, for a condition the gate served through and marked.
const ACTION_DEGRADE: &str = SidecarUnavailablePolicy::DegradeWithAlert.as_str();

/// Why the license gate acted. Bounded label vocabulary — these strings reach
/// Prometheus and the response header, so they are never free text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseOutage {
    /// The vendor published a `revoked` verdict for this `lic_id`.
    Revoked,
    /// The signed offline-revalidation budget is exhausted — the gateway has
    /// been unable to confirm the license with the license server.
    RevalidationLost,
}

impl LicenseOutage {
    /// Canonical metric-label / response-header form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Revoked => "license_revoked",
            Self::RevalidationLost => "license_revalidation_lost",
        }
    }

    /// Operator-facing 403 text. Only reachable on the fail-closed path.
    const fn refusal(self) -> &'static str {
        match self {
            Self::Revoked => "license revoked — contact your vendor",
            Self::RevalidationLost => {
                "license requires revalidation — gateway could not reach the license server"
            }
        }
    }
}

/// What the gate decided about one request. Mirrors
/// [`crate::pipeline::service::SidecarGate`] deliberately — same three
/// outcomes, same meanings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseGate {
    /// In good standing, or on the recovery allowlist. Serve normally.
    Proceed,
    /// Fail closed — 403.
    Block(LicenseOutage),
    /// Serve, and say so: alert + [`LICENSE_DEGRADED_HEADER`].
    Degrade(LicenseOutage),
}

/// Paths that answer in every license state, including revoked and hard-stale.
///
/// Matched with [`is_under`] — a segment-bounded prefix, so `/v1/license`
/// covers `/v1/license` and any future `/v1/license/<sub>` route but NOT a
/// route that merely starts with those characters. The loose `starts_with`
/// this list used before would have quietly exempted a hypothetical
/// `/v1/license-keys` from the gate; the whole risk of allowlisting above a
/// security gate lives in that kind of accident.
const RECOVERY_ALLOWLIST: &[&str] = &[
    "/health",
    "/metrics",
    "/openapi.json",
    // login / refresh / logout / 2fa — the operator must be able to sign in
    "/v1/auth",
    // attestation; already token-gated
    "/internal",
    // WS4-4 — the recovery route itself. Still JWT- and admin-gated; see the
    // module docs.
    "/v1/license",
];

/// True when `path` is `entry` or a path segment beneath it.
fn is_under(path: &str, entry: &str) -> bool {
    let base = entry.trim_end_matches('/');
    match path.strip_prefix(base) {
        Some("") => true,
        Some(rest) => rest.starts_with('/'),
        None => false,
    }
}

fn is_allowlisted(path: &str) -> bool {
    RECOVERY_ALLOWLIST.iter().any(|entry| is_under(path, entry))
}

/// The whole decision, as a pure function over plain values — no `AppState`, no
/// HTTP — so every combination of (revoked, hard-stale, path) is unit-testable.
///
/// Revoked outranks hard-stale: a definitive vendor verdict is not softened by
/// also being unable to phone home.
#[must_use]
pub fn license_gate(revoked: bool, hard_stale: bool, path: &str) -> LicenseGate {
    if is_allowlisted(path) {
        return LicenseGate::Proceed;
    }
    if revoked {
        return LicenseGate::Block(LicenseOutage::Revoked);
    }
    if hard_stale {
        return LicenseGate::Degrade(LicenseOutage::RevalidationLost);
    }
    LicenseGate::Proceed
}

/// Emit the operator-facing alert: the two signals this deployment can route —
/// a `tracing::error!` carrying a stable `alert=` key for log-based alerting,
/// and the Prometheus counter `secureprompt_license_gate_engaged_total` that
/// `monitoring/prometheus/alerts.yml` fires `LicenseGateEngaged` on. Both
/// labels are bounded: a [`LicenseOutage`] reason and one of the two `ACTION_*`
/// constants. `path` is logged but never becomes a metric label.
fn alert(state: &AppState, path: &str, reason: LicenseOutage, action: &'static str) {
    tracing::error!(
        alert = "license_gate_engaged",
        path = %path,
        reason = reason.as_str(),
        action,
        "gateway license is not in good standing"
    );
    state
        .metrics
        .record_license_gate_engaged(reason.as_str(), action);
}

pub async fn enforce(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let path = req.uri().path().to_owned();
    match license_gate(
        state.license.is_revoked(),
        state.license.is_hard_stale(),
        &path,
    ) {
        LicenseGate::Proceed => next.run(req).await,
        LicenseGate::Block(reason) => {
            alert(&state, &path, reason, ACTION_BLOCK);
            api_error_response(ApiError::Forbidden(reason.refusal().into()))
        }
        LicenseGate::Degrade(reason) => {
            alert(&state, &path, reason, ACTION_DEGRADE);
            let mut response = next.run(req).await;
            response.headers_mut().insert(
                LICENSE_DEGRADED_HEADER,
                HeaderValue::from_static(reason.as_str()),
            );
            response
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The headline defect: the recovery route answers in every state.
    #[test]
    fn recovery_route_answers_in_every_license_state() {
        for (revoked, hard_stale) in [(false, false), (true, false), (false, true), (true, true)] {
            assert_eq!(
                license_gate(revoked, hard_stale, "/v1/license"),
                LicenseGate::Proceed,
                "/v1/license must be reachable at revoked={revoked} hard_stale={hard_stale}"
            );
        }
    }

    /// Hard-stale degrades; revoked blocks. The distinction is the whole point.
    #[test]
    fn hard_stale_degrades_and_revoked_blocks() {
        assert_eq!(
            license_gate(false, true, "/v1/chat/completions"),
            LicenseGate::Degrade(LicenseOutage::RevalidationLost)
        );
        assert_eq!(
            license_gate(true, false, "/v1/chat/completions"),
            LicenseGate::Block(LicenseOutage::Revoked)
        );
        // Revoked outranks hard-stale.
        assert_eq!(
            license_gate(true, true, "/v1/redact"),
            LicenseGate::Block(LicenseOutage::Revoked)
        );
        // Healthy → untouched.
        assert_eq!(
            license_gate(false, false, "/v1/chat/completions"),
            LicenseGate::Proceed
        );
    }

    #[test]
    fn allowlist_matches() {
        assert!(is_allowlisted("/health"));
        assert!(is_allowlisted("/metrics"));
        assert!(is_allowlisted("/openapi.json"));
        assert!(is_allowlisted("/v1/auth/login"));
        assert!(is_allowlisted("/v1/auth/refresh"));
        assert!(is_allowlisted("/internal/attestation"));
        assert!(is_allowlisted("/v1/license"));
        assert!(is_allowlisted("/v1/license/"));
    }

    /// Task 9 (2FA backend plan): `/v1/auth/2fa/*` must stay reachable even
    /// when the license is revoked/hard-stale, exactly like `/v1/auth/login`
    /// — otherwise a revoked deployment could lock an operator out mid-login
    /// (forced enrollment or a pending challenge) with no way to finish
    /// authenticating.
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

    /// Allowlisting above a security gate is the shape of change that opens a
    /// hole. The match is segment-bounded, so no route that merely *starts
    /// with* an allowlisted string inherits the exemption.
    #[test]
    fn allowlist_is_segment_bounded() {
        assert!(!is_allowlisted("/v1/licensed-decoy"));
        assert!(!is_allowlisted("/v1/license-keys"));
        assert!(!is_allowlisted("/v1/authorize"));
        assert!(!is_allowlisted("/internalise"));
        assert!(!is_allowlisted("/metrics-admin"));
        // and each of those really is gated when the license is bad
        assert_eq!(
            license_gate(true, false, "/v1/licensed-decoy"),
            LicenseGate::Block(LicenseOutage::Revoked)
        );
    }

    /// The metric/log `action` labels are the WS2-3 vocabulary, not a second
    /// one. Bound at compile time; asserted here so the intent is executable.
    #[test]
    fn action_labels_are_the_ws2_3_vocabulary() {
        assert_eq!(ACTION_BLOCK, "block");
        assert_eq!(ACTION_DEGRADE, "degrade_with_alert");
        assert_eq!(ACTION_BLOCK, SidecarUnavailablePolicy::Block.as_str());
        assert_eq!(
            ACTION_DEGRADE,
            SidecarUnavailablePolicy::DegradeWithAlert.as_str()
        );
    }

    /// Header and reason values are bounded and header-safe.
    #[test]
    fn outage_reasons_are_bounded_and_header_safe() {
        assert_eq!(LicenseOutage::Revoked.as_str(), "license_revoked");
        assert_eq!(
            LicenseOutage::RevalidationLost.as_str(),
            "license_revalidation_lost"
        );
        for reason in [LicenseOutage::Revoked, LicenseOutage::RevalidationLost] {
            // `enforce` uses from_static, which panics on an invalid value.
            let _ = HeaderValue::from_static(reason.as_str());
            assert!(!reason.refusal().is_empty());
        }
    }
}
