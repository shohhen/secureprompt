//! WS4-2 — `POST /v1/scan-file`, the audited door in front of the ML sidecar's
//! file scanner.
//!
//! # What this replaced
//!
//! `secureprompt-chat/api/server/services/Files/process.js` POSTs every
//! uploaded file for redaction before the chat client builds the provider
//! payload. Until WS4-2 it POSTed those bytes to the sidecar DIRECTLY, carrying
//! `ML_SIDECAR_INTERNAL_TOKEN` — the service-to-service secret WS1-5 introduced.
//! That worked and had two properties nobody wanted:
//!
//!   * **Nothing recorded that a scan happened.** At `fb5e1df`,
//!     `grep -rn 'file_scan\|scan_file' --include=*.rs --include=*.sql` over the
//!     workspace returned nothing at all. A document went through the product's
//!     detection stack and no table anywhere could say who sent it.
//!   * **The credential authenticated a SERVICE, not a person.** Every chat
//!     user shared one token, so the dashboard's "a viewer may search, not
//!     scan" rule (`SCAN_ROLES` in
//!     `secureprompt-web/src/app/api/proxy/ml/[...path]/route.ts`) had no
//!     counterpart on the chat path, and the chat backend held a credential
//!     that also opens `/internal/model-key`.
//!
//! The sidecar's own door was already shut and is not what this module fixes:
//! WS1-5 put `Depends(_require_internal_token)` on every sidecar route but
//! `/health`, `/ready` and `/metrics`, `docker-compose.yml` maps no host port
//! for `secureprompt-ml`, and `secureprompt-ml/tests/test_sidecar_route_auth.py`
//! passes 30/30. What was missing was a per-USER door in front of it.
//!
//! # The shape
//!
//! Three routes, mirroring the sidecar's own scan surface one-for-one so
//! `process.js` changes host and credential and nothing else:
//!
//! | gateway | sidecar | audited |
//! |---|---|---|
//! | `POST /v1/scan-file` | `POST /v1/scan-file` | yes — `mode: "sync"` |
//! | `POST /v1/scan-file/async` | `POST /v1/scan-file/async` | yes — `mode: "async"` |
//! | `GET /v1/scan-file/tasks/{id}` | same | no — see below |
//!
//! Each one: authenticate the API key, resolve the member it is assigned to,
//! refuse a viewer, write the audit row, forward the bytes unread.
//!
//! # Four decisions worth stating
//!
//! **The audit row commits BEFORE the bytes are forwarded.** No file reaches
//! the scanner without a committed record of who sent it. The residual is the
//! other direction and is why the action is called `file_scan.requested` rather
//! than `.performed`: a scan the sidecar then refuses still has a row. Same
//! trade `auth.login_succeeded` takes, and the same reason — the alternative
//! loses the record of exactly the scan that failed halfway.
//!
//! **A key with no `assigned_user_id` is refused.** The entire point of routing
//! scans through here is that the record names a person; a legacy
//! workspace-scoped key names none, and a row with a NULL actor cannot answer
//! the question it exists for.
//!
//! **The poll is not audited.** It starts no work and moves no bytes. The
//! kickoff that did is already recorded, and a row per poll would bury it under
//! its own status checks — the async client polls every 2 s.
//!
//! **The gateway never parses the multipart body.** It measures it, records the
//! size, and forwards the bytes verbatim. The sidecar's 15 MiB file ceiling,
//! its 413/429/503 answers and its response shape therefore stay exactly what
//! `process.js` already handles. A gateway that re-encoded the upload would be
//! a second place for that contract to drift.

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use secureprompt_common::errors::ApiError;
use serde_json::json;
use uuid::Uuid;

use crate::{
    app_state::AppState,
    db::admin_audit_repo::{self, AdminActor, AdminAuditAction, AdminAuditEntry},
    db::scope::begin_scoped,
    http::{
        api_error_response,
        middleware::{api_key_auth::authenticate_request, jwt_auth::UserRole, request_hygiene},
    },
    ml_sidecar::client::ProxyMethod,
};

/// Default ceiling for a scan request body.
///
/// 16 MiB, sized so the SIDECAR's own limit is the binding one. The sidecar
/// caps the extracted FILE at `ML_SCAN_FILE_MAX_BYTES` (15 MiB by default,
/// `secureprompt-ml/app/main.py`) and answers 413 with a message naming that
/// number. The gateway's ceiling applies to the whole multipart envelope, so
/// leaving a MiB of headroom means an over-sized upload gets the sidecar's own
/// explanation rather than a bare gateway 413 quoting a different number.
///
/// Deliberately NOT the gateway-wide
/// [`request_hygiene::DEFAULT_MAX_BODY_BYTES`] (2 MiB). That ceiling is sized
/// for a chat request body; applying it to a file upload would refuse most
/// PDFs, and raising it globally would let every other route accept 16 MiB.
/// `http::build_router` therefore layers the two limits separately.
pub const DEFAULT_SCAN_MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Operator override for [`DEFAULT_SCAN_MAX_BODY_BYTES`].
pub const SCAN_MAX_BODY_ENV: &str = "SECUREPROMPT_SCAN_MAX_BODY_BYTES";

/// How long a scan task's workspace binding lives in Redis.
///
/// One hour: long enough to outlive any scan a caller waits for (the chat
/// backend's whole budget is 60 s) and long enough that a caller polling a
/// finished task twice still gets it.
const SCAN_TASK_BINDING_TTL_SECS: u64 = 3_600;

/// The scan body ceiling from operator configuration.
///
/// Same fallback rule as [`request_hygiene::parse_max_body_bytes`], for the
/// same reason: a zero ceiling would refuse every upload.
#[must_use]
pub fn parse_scan_max_body_bytes(raw: Option<&str>) -> usize {
    raw.and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|bytes| *bytes > 0)
        .unwrap_or(DEFAULT_SCAN_MAX_BODY_BYTES)
}

/// Read [`SCAN_MAX_BODY_ENV`] from the environment.
///
/// Read here rather than threaded through `AppConfig` for the reason
/// `http::max_body_bytes` gives: this is a router-shaped knob, and the decision
/// itself is the pure function above.
#[must_use]
pub fn scan_max_body_bytes() -> usize {
    parse_scan_max_body_bytes(std::env::var(SCAN_MAX_BODY_ENV).ok().as_deref())
}

/// May a member holding this role run a file scan?
///
/// **Not expressible as `require_role(ctx, Developer)`**, and that is the whole
/// reason this predicate exists. `role::privilege_level` puts `Employee` and
/// `Viewer` at the SAME level (1), so any minimum-role gate that admits an
/// employee admits a viewer and any gate that refuses a viewer refuses an
/// employee. The dashboard's ML proxy draws the line by NAMING the roles
/// (`SCAN_ROLES` in `secureprompt-web/src/app/api/proxy/ml/[...path]/route.ts`)
/// and this is the same line, checked against that file by
/// `tests/file_scan_routing.rs::the_gateway_and_the_dashboard_proxy_refuse_the_same_roles`.
///
/// Written as an exhaustive `match` and not `role != Viewer`: a role added to
/// [`UserRole`] then fails to compile here, which is where a new role's scan
/// privilege should be decided.
#[must_use]
pub const fn may_run_file_scan(role: UserRole) -> bool {
    match role {
        UserRole::Owner | UserRole::Admin | UserRole::Developer | UserRole::Employee => true,
        UserRole::Viewer => false,
    }
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/scan-file", post(scan_file_sync))
        .route("/v1/scan-file/async", post(scan_file_async))
        .route("/v1/scan-file/tasks/{task_id}", get(scan_file_task))
}

/// The authenticated, role-checked member behind an API key.
struct ScanPrincipal {
    workspace_id: Uuid,
    user_id: Uuid,
    email: String,
    role: String,
    api_key_id: Uuid,
}

/// Authenticate the key, resolve the member it belongs to, and refuse anyone
/// who may not scan.
///
/// Every failure here is a refusal that writes NOTHING, which is deliberate and
/// is 029's failed-login rule: refusals must leave the trail in the same state
/// whatever they were refused for, or the absence of a row becomes an oracle.
async fn authorize_scan(headers: &HeaderMap, state: &AppState) -> Result<ScanPrincipal, ApiError> {
    let auth = authenticate_request(headers, state).await?;
    let user_id = auth.user_id.ok_or_else(|| {
        ApiError::Forbidden("file scans require an API key assigned to a workspace member".into())
    })?;

    // The member's email and role AS THEY READ NOW. Resolved with an explicit
    // workspace predicate so a key whose assignment points outside its own
    // workspace resolves to nothing and is refused, rather than borrowing
    // another tenant's member.
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT email, role FROM users WHERE id = $1 AND workspace_id = $2")
            .bind(user_id)
            .bind(auth.workspace_id.0)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?;

    // FAIL CLOSED on a missing member. `AdminActor::resolve` tolerates a failed
    // email lookup because a missing display name must not stop a security
    // action from being RECORDED; here the same lookup carries the ROLE, and a
    // security decision taken on a row that is not there is not a decision.
    let (email, role) = row.ok_or_else(|| {
        ApiError::Forbidden("the API key is assigned to no current workspace member".into())
    })?;

    if !may_run_file_scan(UserRole::from_db_str(&role)?) {
        return Err(ApiError::Forbidden(
            "this role may not run file scans".into(),
        ));
    }

    Ok(ScanPrincipal {
        workspace_id: auth.workspace_id.0,
        user_id,
        email,
        role,
        api_key_id: auth.api_key_id,
    })
}

/// Commit the record of one scan, before its bytes go anywhere.
///
/// `target_id` is the request id — the value `request_hygiene::propagate`
/// already put in the `x-request-id` response header and in the access log — so
/// an audit row joins to the request that produced it. When the middleware is
/// absent (a handler called directly from a unit test) a fresh id is minted
/// rather than the row being written without a target.
async fn record_scan(
    state: &AppState,
    principal: &ScanPrincipal,
    headers: &HeaderMap,
    mode: &str,
    request_bytes: usize,
) -> Result<(), ApiError> {
    let request_id =
        request_hygiene::request_id_from_headers(headers).map_or_else(Uuid::new_v4, |id| id.0);

    let actor = AdminActor {
        workspace_id: principal.workspace_id,
        user_id: Some(principal.user_id),
        email: Some(principal.email.clone()),
        role: Some(principal.role.clone()),
    };
    // `target_label` stays None on purpose: the obvious name for a scan is the
    // uploaded filename, and that is a chat user's content in a table that is
    // never purged. Migration 040 states the decision in full.
    let entry = AdminAuditEntry::on_object(AdminAuditAction::FileScanRequested, request_id, None)
        .targeting_user(principal.user_id, &principal.email, &principal.role)
        .with_detail(json!({
            "mode": mode,
            "request_bytes": request_bytes,
            "api_key_id": principal.api_key_id.to_string(),
        }));

    let mut tx = begin_scoped(&state.db, principal.workspace_id).await?;
    admin_audit_repo::write(&mut tx, &actor, &entry).await?;
    tx.commit()
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;
    Ok(())
}

/// Hand the sidecar's own answer back to the uploader, byte for byte.
fn relay(response: crate::ml_sidecar::client::SidecarProxyResponse) -> Response {
    let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let content_type = response
        .content_type
        .unwrap_or_else(|| "application/json".to_owned());
    match header::HeaderValue::from_str(&content_type) {
        Ok(value) => (status, [(header::CONTENT_TYPE, value)], response.body).into_response(),
        // A content-type the sidecar sent that will not fit in a header value
        // cannot be echoed; the body still is.
        Err(_) => (status, response.body).into_response(),
    }
}

/// The sidecar could not be reached. Answered as 502 rather than 500: the
/// gateway is intact and the thing it called is not, and `process.js` maps any
/// non-2xx to the same user-facing "File scanning failed; please retry or
/// contact your admin."
fn sidecar_unreachable(detail: &str) -> Response {
    tracing::error!(error = %detail, "file scan could not be forwarded to the ML sidecar");
    api_error_response(ApiError::ServiceUnavailable(
        "file scanning is unavailable".into(),
    ))
    .into_response()
}

async fn scan_file_sync(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    forward_scan(state, headers, body, "sync", "/v1/scan-file").await
}

async fn scan_file_async(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    forward_scan(state, headers, body, "async", "/v1/scan-file/async").await
}

/// Shared body of the two kickoff routes.
async fn forward_scan(
    state: AppState,
    headers: HeaderMap,
    body: Bytes,
    mode: &str,
    path: &str,
) -> Response {
    let principal = match authorize_scan(&headers, &state).await {
        Ok(principal) => principal,
        Err(error) => return api_error_response(error),
    };

    if let Err(error) = record_scan(&state, &principal, &headers, mode, body.len()).await {
        // The record failed, so the scan does not happen. Same direction
        // `admin_audit_repo`'s module docs state for every audited action: an
        // action that happened with no record of it is a trail that lies.
        return api_error_response(error);
    }

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let response = match state
        .ml_sidecar
        .proxy_scan(ProxyMethod::Post, path, content_type.as_deref(), body)
        .await
    {
        Ok(response) => response,
        Err(error) => return sidecar_unreachable(&error),
    };

    // The async kickoff hands back a task id the caller will poll. Bind it to
    // this workspace BEFORE answering, so the poll route can refuse every other
    // tenant — the sidecar itself has no notion of one.
    if mode == "async" && (200..300).contains(&response.status) {
        let task_id = serde_json::from_slice::<serde_json::Value>(&response.body)
            .ok()
            .and_then(|v| v["task_id"].as_str().map(str::to_owned));
        match task_id {
            Some(task_id) => {
                if let Err(error) = crate::redis::bind_scan_task(
                    &state.redis_pool,
                    &task_id,
                    principal.workspace_id,
                    SCAN_TASK_BINDING_TTL_SECS,
                )
                .await
                {
                    // Answering 200 with an id whose owner was never stored
                    // would hand back a task the poll route must then refuse.
                    return api_error_response(error);
                }
            }
            None => {
                return api_error_response(ApiError::ServiceUnavailable(
                    "file scanning is unavailable".into(),
                ))
            }
        }
    }

    relay(response)
}

/// `GET /v1/scan-file/tasks/{task_id}` — the async status poll.
///
/// Refused unless the caller's workspace is the one that started the scan. The
/// binding is FAIL-CLOSED: a task id with no binding is refused, because a
/// binding that never stored and a binding that belongs to somebody else are
/// indistinguishable from here, and the safe reading of an unknown owner on a
/// route that returns a document's redacted text is "not yours".
///
/// 404 and not 403 for a task that is not this workspace's, so the answer
/// carries no information about whether the id exists at all.
async fn scan_file_task(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(task_id): Path<String>,
) -> Response {
    let principal = match authorize_scan(&headers, &state).await {
        Ok(principal) => principal,
        Err(error) => return api_error_response(error),
    };

    let owner = match crate::redis::scan_task_owner(&state.redis_pool, &task_id).await {
        Ok(owner) => owner,
        Err(error) => return api_error_response(error),
    };
    if owner.as_deref() != Some(principal.workspace_id.to_string().as_str()) {
        return api_error_response(ApiError::NotFound("no such scan task".into()));
    }

    let path = format!("/v1/scan-file/tasks/{task_id}");
    match state
        .ml_sidecar
        .proxy_scan(ProxyMethod::Get, &path, None, Bytes::new())
        .await
    {
        Ok(response) => relay(response),
        Err(error) => sidecar_unreachable(&error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ceiling parser falls back on the three inputs that would otherwise
    /// produce a gateway that refuses every upload, and honours a real one.
    #[test]
    fn a_zero_or_unparseable_scan_ceiling_falls_back_to_the_default() {
        assert_eq!(parse_scan_max_body_bytes(None), DEFAULT_SCAN_MAX_BODY_BYTES);
        assert_eq!(
            parse_scan_max_body_bytes(Some("0")),
            DEFAULT_SCAN_MAX_BODY_BYTES,
            "a zero ceiling would refuse every upload"
        );
        assert_eq!(
            parse_scan_max_body_bytes(Some("not-a-number")),
            DEFAULT_SCAN_MAX_BODY_BYTES
        );
        // And it is not a constant function.
        assert_eq!(parse_scan_max_body_bytes(Some(" 4096 ")), 4096);
    }

    /// The scan ceiling must be ABOVE the gateway-wide one, or this module's
    /// whole reason for existing (a file upload is not a chat request) does not
    /// hold. Asserted rather than assumed: both are plain constants and either
    /// could be edited alone.
    #[test]
    fn the_scan_ceiling_is_above_the_gateway_wide_one() {
        assert!(
            DEFAULT_SCAN_MAX_BODY_BYTES > request_hygiene::DEFAULT_MAX_BODY_BYTES,
            "the scan route exists to carry bodies the rest of the gateway \
             refuses; {DEFAULT_SCAN_MAX_BODY_BYTES} is not above {}",
            request_hygiene::DEFAULT_MAX_BODY_BYTES
        );
    }
}
