//! WS2-4 — the workspace's `sidecar_unavailable` policy on the routes that do
//! NOT egress to a provider.
//!
//! WS2-3 built the gate ([`sidecar_gate`]) and wired it into the chat pipeline.
//! Three other routes kept taking `detect_if_available(..).detections` and
//! dropping `.coverage` on the floor, so the workspace's configured choice was
//! silently ignored on:
//!
//!   * `POST /v1/secure-mode/tokenize`
//!   * `POST /v1/redact`        (MCP `redact` tool)
//!   * `POST /v1/policy/check`  (MCP `policy_check` tool)
//!
//! ## Why `block` is still a 503 here
//!
//! On the chat path `block` returns 503 because the alternative is forwarding
//! an unscanned prompt to a third-party provider. These three routes have no
//! such egress — they hand the answer back to the caller. That makes "200 with
//! a degraded header" a genuine option, and it is the wrong one:
//!
//!   * A 200 body IS the artifact. `tokenized_text`, `redacted_text` and
//!     `allowed` are exactly what the caller pastes into a model or branches
//!     on. Serving the artifact and asking the caller to please notice a
//!     header first inverts fail-closed into fail-open-unless-you-remember —
//!     which is the defect, not the fix.
//!   * The MCP tools are consumed by agents. An MCP client surfaces a tool's
//!     JSON result to the model; response headers are not part of the tool
//!     contract and are routinely dropped by the transport. A non-2xx, by
//!     contrast, surfaces as a tool ERROR the agent must handle. On these
//!     routes the status code is the only signal that cannot be silently
//!     discarded.
//!   * A caller CAN act on a 503: retry, back off, fall back, or stop — every
//!     HTTP client already has semantics for it. Nothing is destroyed; the
//!     caller still holds the original text.
//!   * One knob, one meaning. The workspace set `sidecar_unavailable = block`
//!     once. Re-interpreting it per route ("closed on chat, floor-only answer
//!     on tokenize") is precisely the divergence that produced this bug.
//!
//! `degrade_with_alert` keeps its WS2-3 shape: answer, alert, and set
//! [`SIDECAR_DEGRADED_HEADER`] with the same bounded reason vocabulary. That
//! workspace has explicitly accepted the risk, so a header it may ignore is
//! proportionate — the caller can still TELL without inspecting counts.
//!
//! Classification is NOT re-derived here: [`sidecar_gate`] delegates to
//! `CoverageLoss::from_coverage`, the single exhaustive match over
//! `SidecarCoverage`.

use axum::{http::HeaderValue, response::Response};
use secureprompt_common::{errors::ApiError, types::RequestId, types::WorkspaceId};

use crate::{
    app_state::AppState,
    db::sidecar_policy_repo::{SidecarPolicyRepository, SidecarUnavailablePolicy},
    ml_sidecar::types::{CoverageLoss, SidecarCoverage},
    pipeline::service::{sidecar_gate, SidecarGate, SIDECAR_DEGRADED_HEADER},
};

/// Metric/log `action` label for a coverage loss in a `block` workspace.
///
/// BOUND TO THE ENUM AT COMPILE TIME, not re-typed. There is exactly one
/// source of truth for this vocabulary —
/// [`SidecarUnavailablePolicy::as_str`], which is also the value stored in
/// `workspace_sidecar_policy.sidecar_unavailable` — so
/// `secureprompt_sidecar_unavailable_total` stays one series per
/// (reason, action) across every route and
/// `monitoring/prometheus/alerts.yml` needs no new rule.
///
/// MR1 review M2: this used to be a bare `"block"` literal, one of three
/// independent copies (here, `pipeline::service`, and
/// `http::middleware::license_gate` — only the last was bound to the enum).
/// The comment that stood here claimed "the integration tests assert the
/// fully-rendered label text, so a drift between the two definitions fails a
/// test". Relying on that was the defect: a drift here splits a Prometheus
/// series, which is the failure mode alerting notices LAST. Binding makes the
/// drift a compile error instead, and makes the copies not copies.
const ACTION_BLOCK: &str = SidecarUnavailablePolicy::Block.as_str();
/// Same, for a `degrade_with_alert` workspace.
const ACTION_DEGRADE: &str = SidecarUnavailablePolicy::DegradeWithAlert.as_str();

/// Read the workspace's effective `sidecar_unavailable` policy, failing
/// CLOSED.
///
/// A database error resolves to [`SidecarUnavailablePolicy::default()`]
/// (= `Block`), matching the pipeline: a Postgres outage must not become
/// permission to serve unscanned answers.
async fn effective_policy(state: &AppState, workspace_id: WorkspaceId) -> SidecarUnavailablePolicy {
    // MR1 review M17 — yes, this is a Postgres round-trip per request, and
    // no, it is not cached. Measured (904 µs p50 through `begin_scoped`, vs
    // 316 µs for the bare SELECT) and the refusal is argued on
    // `SidecarPolicyRepository::get_effective`: a TTL cache would make
    // `degrade_with_alert -> block` take effect late, i.e. keep failing
    // OPEN during the incident in which an operator tightens it.
    SidecarPolicyRepository::new(state.db.clone())
        .get_effective(
            workspace_id,
            SidecarUnavailablePolicy::from_db(&state.config.sidecar_unavailable_default),
        )
        .await
        .unwrap_or_else(|err| {
            tracing::warn!(
                workspace_id = %workspace_id,
                error = %err,
                "sidecar_unavailable policy read failed; failing closed to 'block'"
            );
            SidecarUnavailablePolicy::default()
        })
}

/// Emit the operator-facing alert. Mirrors `pipeline::service`'s
/// `alert_sidecar_unavailable`: a `tracing::error!` carrying the stable
/// `alert=` key plus the Prometheus counter `MLSidecarCoverageLost` fires on.
/// Both labels are bounded — a reason from [`CoverageLoss::as_str`] and one of
/// the two `ACTION_*` constants — never workspace ids or free text.
fn alert(
    state: &AppState,
    request_id: RequestId,
    workspace_id: WorkspaceId,
    reason: CoverageLoss,
    action: &'static str,
) {
    tracing::error!(
        alert = "ml_sidecar_coverage_lost",
        %request_id,
        %workspace_id,
        reason = reason.as_str(),
        action,
        "ML sidecar produced no detection coverage for this request"
    );
    state
        .metrics
        .record_sidecar_unavailable(reason.as_str(), action);
}

/// Apply the workspace's `sidecar_unavailable` policy to one
/// `detect_if_available` outcome, on a route that answers the caller directly.
///
/// * `Ok(None)`         — full coverage, or nothing to do. Serve normally.
/// * `Ok(Some(reason))` — `degrade_with_alert`: serve, and pass `reason` to
///   [`with_sidecar_degraded`] so the response says so.
/// * `Err(..)`          — `block`: a 503 the caller must handle. Returned
///   BEFORE the handler persists anything, so a blocked request leaves no
///   half-redacted vault entry behind.
///
/// # Errors
/// Returns `ApiError::ServiceUnavailable` when the workspace policy is
/// `block` and coverage was lost.
pub async fn enforce(
    state: &AppState,
    request_id: RequestId,
    workspace_id: WorkspaceId,
    coverage: &SidecarCoverage,
) -> Result<Option<CoverageLoss>, ApiError> {
    let policy = effective_policy(state, workspace_id).await;
    match sidecar_gate(coverage, policy) {
        SidecarGate::Proceed => Ok(None),
        SidecarGate::Block(reason) => {
            alert(state, request_id, workspace_id, reason, ACTION_BLOCK);
            Err(ApiError::ServiceUnavailable(
                "PII detection coverage is unavailable for this request and the workspace is \
                 configured to fail closed"
                    .to_owned(),
            ))
        }
        SidecarGate::Degrade(reason) => {
            alert(state, request_id, workspace_id, reason, ACTION_DEGRADE);
            Ok(Some(reason))
        }
    }
}

/// Attach `x-secureprompt-sidecar-degraded: <reason>` when this answer was
/// produced on the deterministic floor alone.
///
/// Same header and same bounded reason values as the chat path, so one client
/// check covers every route.
#[must_use]
pub fn with_sidecar_degraded(mut response: Response, reason: Option<CoverageLoss>) -> Response {
    if let Some(reason) = reason {
        response.headers_mut().insert(
            SIDECAR_DEGRADED_HEADER,
            HeaderValue::from_static(reason.as_str()),
        );
    }
    response
}
