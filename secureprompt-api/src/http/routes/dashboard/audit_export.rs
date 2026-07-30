//! WS4-1 / Task 19 — `/v1/audit-exports`, the auditor-facing export surface.
//!
//! Four routes, all `UserRole::Admin`:
//!
//! ```text
//! POST /v1/audit-exports                     request an export -> 202 + id
//! GET  /v1/audit-exports                     list this workspace's exports
//! GET  /v1/audit-exports/{id}                status, manifest, signature, key
//! GET  /v1/audit-exports/{id}/pages/{n}      one page, as the signed bytes
//! ```
//!
//! # Why poll-based, and why the API does not produce the export
//!
//! An export walks a window of `request_events`, renders it and signs it. That
//! is a background job by nature, and this codebase already has exactly one
//! way to run those: the hand-rolled Redis-list + JSON envelope protocol in
//! `secureprompt_common::tasks`. So `POST` writes a `queued` row and RPUSHes
//! an envelope onto `queue:audit_export`; `secureprompt-worker` does the work;
//! the caller polls `GET`. No job framework is introduced — the stack decision
//! rejects apalis precisely because it would duplicate that envelope.
//!
//! # Why the page route serves stored bytes rather than re-querying
//!
//! The signature covers the EXACT bytes of each page. `request_events` carries
//! a 90-day TTL, so a page regenerated at download time could legitimately
//! differ from the one that was signed — and would then fail its own
//! manifest's digest. The bytes are stored at production time (migration 025)
//! and this route hands them back verbatim.
//!
//! # This is not recovery infrastructure
//!
//! Deliberately NOT on `license_gate::RECOVERY_ALLOWLIST`. That list exists so
//! a revoked deployment can still authenticate and be re-licensed; an audit
//! export is ordinary dashboard functionality and a revoked gateway should
//! refuse it like everything else. Adding routes to that allowlist is the
//! shape of change that opens a hole, and this one has no claim to it.
//!
//! # No raw content, no unbounded strings
//!
//! Nothing here interpolates a store's message into a response body. The
//! export's `error` column is written by the worker from `&'static str`s and
//! bounded `format!`s over integers; the two error helpers below follow
//! `data_inventory::unavailable`'s rule — the store's own message goes to the
//! log, never to the caller, because a database exception quotes the statement
//! that provoked it and sometimes the value it choked on.

use axum::{
    extract::{Extension, Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use secureprompt_common::{
    audit_export::{ExportFormat, SIGNING_KEY_ENV},
    errors::ApiError,
    tasks::{task_types, TaskEnvelope, QUEUE_AUDIT_EXPORT},
};
use serde::{Deserialize, Serialize};
use sqlx::Row as _;
use uuid::Uuid;

use crate::{
    app_state::AppState,
    http::{
        api_error_response,
        middleware::jwt_auth::{JwtAuthContext, UserRole},
        routes::dashboard::role::require_role,
    },
    redis::enqueue_task,
};

/// Rows per page when the caller does not choose. Mirrors the worker's
/// `DEFAULT_PAGE_SIZE`; asserted equal in `tests/audit_export.rs` so the two
/// crates cannot drift.
pub const DEFAULT_PAGE_SIZE: u32 = 5_000;
pub const MIN_PAGE_SIZE: u32 = 1;
pub const MAX_PAGE_SIZE: u32 = 50_000;

/// Longest window an export may span, matching the analytics endpoints' cap.
/// A longer window is refused rather than silently clipped.
pub const MAX_WINDOW_DAYS: i64 = 366;

const STATUS_QUEUED: &str = "queued";
const STATUS_COMPLETE: &str = "complete";

/// What a caller is told about the signature, in the status payload. The
/// detail that matters is the last sentence: the key must arrive out of band,
/// or the whole scheme reduces to "the server says it is fine".
const SIGNATURE_NOTE: &str =
    "The `signature_b64` is a detached Ed25519 signature over the EXACT bytes of \
     `manifest_json` as served here — do not reformat, re-indent or re-serialise \
     the manifest before verifying. The manifest carries a SHA-256 for every page \
     and a hash chain over those digests in order, so removing a row from the \
     middle of a page, dropping a whole page, or reordering pages all break \
     verification. `public_key_b64` is published here for convenience ONLY: it is \
     served by the same deployment that produced the export, so it is not a trust \
     root. Obtain the deployment's audit-export public key THROUGH A SEPARATE \
     CHANNEL and compare `signing_key_id` against it before believing any of this.";

// ── Router ────────────────────────────────────────────────────────────────

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", post(create_export).get(list_exports))
        .route("/{id}", get(get_export))
        .route("/{id}/pages/{page}", get(get_export_page))
}

// ── Request / response DTOs ───────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateExportRequest {
    /// Inclusive lower bound, an RFC 3339 instant.
    pub from: DateTime<Utc>,
    /// EXCLUSIVE upper bound, an RFC 3339 instant.
    pub to: DateTime<Utc>,
    /// `csv` or `jsonl`.
    pub format: String,
    pub page_size: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct CreateExportResponse {
    pub export_id: Uuid,
    pub status: &'static str,
    /// Where to poll.
    pub status_url: String,
    pub note: &'static str,
}

#[derive(Debug, Serialize)]
pub struct ExportSummary {
    pub export_id: Uuid,
    pub status: String,
    pub format: String,
    pub window_from: DateTime<Utc>,
    pub window_to: DateTime<Utc>,
    pub total_rows: Option<i64>,
    pub total_pages: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct ExportDetail {
    pub export_id: Uuid,
    pub workspace_id: Uuid,
    pub status: String,
    pub format: String,
    pub page_size: i32,
    pub window_from: DateTime<Utc>,
    pub window_to: DateTime<Utc>,
    pub total_rows: Option<i64>,
    pub total_pages: Option<i32>,
    /// The exact bytes the signature covers. `null` until the export
    /// completes.
    pub manifest_json: Option<String>,
    pub signature_b64: Option<String>,
    pub public_key_b64: Option<String>,
    pub signing_key_id: Option<String>,
    /// Present only on a refusal, and always a bounded string — see the module
    /// docs.
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    /// Template for the page routes, so a caller does not have to build them.
    pub page_url_template: Option<String>,
    pub signature_note: &'static str,
}

// ── Errors ────────────────────────────────────────────────────────────────

/// Say WHAT failed without echoing the store's own message.
///
/// Same rule, and the same reason, as `data_inventory::unavailable`: a
/// Postgres error message quotes the statement that provoked it, and for some
/// error classes the bound value too. `context` is always a `&'static str`
/// from this file.
fn store_unavailable(context: &'static str, error: &dyn std::fmt::Display) -> ApiError {
    tracing::error!(
        context,
        error = %error,
        "audit-export store read failed; the store's message is logged here and \
         deliberately NOT returned to the caller"
    );
    ApiError::Internal(format!(
        "the audit-export store did not answer while {context}. Its own error \
         message is in the gateway log, not in this response, because a database \
         exception quotes the statement that provoked it."
    ))
}

// ── Tenancy-scoped access ─────────────────────────────────────────────────

/// Open a transaction with `app.current_workspace_id` set.
///
/// Migration 025 puts FORCE ROW LEVEL SECURITY on `audit_exports` and
/// `audit_export_pages`, keyed on this GUC. With it unset the policy predicate
/// is NULL for every row and these reads return the EMPTY SET — which, on a
/// compliance endpoint, would look exactly like "you have no exports" rather
/// than like a bug. The explicit `workspace_id = $n` in every statement is
/// still the filter; RLS is defence in depth (Global Constraint 3). Same
/// pattern, and the same measured reason, as `leak_report::registered_models`.
async fn begin_scoped(
    state: &AppState,
    workspace_id: Uuid,
) -> Result<sqlx::Transaction<'static, sqlx::Postgres>, ApiError> {
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| store_unavailable("opening a transaction", &e))?;
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
        .bind(workspace_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|e| store_unavailable("scoping the transaction to your workspace", &e))?;
    Ok(tx)
}

// ── Validation ────────────────────────────────────────────────────────────

fn validate(req: &CreateExportRequest) -> Result<(ExportFormat, u32), ApiError> {
    let format = ExportFormat::parse(&req.format).ok_or_else(|| {
        ApiError::BadRequest("format must be `csv` or `jsonl`".into())
    })?;
    if req.from >= req.to {
        return Err(ApiError::BadRequest(
            "invalid window: `from` must be strictly before `to` (the window is \
             half-open, so `from == to` selects nothing)"
                .into(),
        ));
    }
    let span = (req.to - req.from).num_days();
    if span > MAX_WINDOW_DAYS {
        return Err(ApiError::BadRequest(format!(
            "window too large: {span} days (max {MAX_WINDOW_DAYS})"
        )));
    }
    let page_size = req.page_size.unwrap_or(DEFAULT_PAGE_SIZE);
    if !(MIN_PAGE_SIZE..=MAX_PAGE_SIZE).contains(&page_size) {
        return Err(ApiError::BadRequest(format!(
            "page_size must be between {MIN_PAGE_SIZE} and {MAX_PAGE_SIZE}"
        )));
    }
    Ok((format, page_size))
}

// ── Handlers ──────────────────────────────────────────────────────────────

/// `POST /v1/audit-exports`
///
/// Records the request and hands it to the worker. Returns 202: the artifact
/// does not exist yet, and answering 200 would invite a caller to treat the
/// response as the export.
async fn create_export(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Json(body): Json<CreateExportRequest>,
) -> Result<Response, Response> {
    require_role(&ctx, UserRole::Admin).map_err(api_error_response)?;
    let ws = ctx.workspace_id.0;
    let (format, page_size) = validate(&body).map_err(api_error_response)?;

    // Refuse up front when no signing key is configured, rather than accepting
    // the request and failing it in the worker a minute later. The operator
    // fixing this is the same person making the request.
    if std::env::var(SIGNING_KEY_ENV).map(|v| v.trim().is_empty()) != Ok(false) {
        return Err(api_error_response(ApiError::ServiceUnavailable(format!(
            "no audit-export signing key is configured, so no signed export can be \
             produced. An UNSIGNED export is not offered as a fallback: it would be \
             indistinguishable from one an auditor fabricated. Set {SIGNING_KEY_ENV} \
             on the gateway and the worker."
        ))));
    }

    let export_id = Uuid::new_v4();
    let mut tx = begin_scoped(&state, ws).await.map_err(api_error_response)?;
    sqlx::query(
        "INSERT INTO audit_exports \
         (id, workspace_id, requested_by, window_from, window_to, format, page_size, status) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(export_id)
    .bind(ws)
    .bind(ctx.user_id)
    .bind(body.from)
    .bind(body.to)
    .bind(format.as_str())
    .bind(i32::try_from(page_size).unwrap_or(i32::MAX))
    .bind(STATUS_QUEUED)
    .execute(&mut *tx)
    .await
    .map_err(|e| api_error_response(store_unavailable("recording the export request", &e)))?;
    tx.commit()
        .await
        .map_err(|e| api_error_response(store_unavailable("committing the export request", &e)))?;

    // Enqueue AFTER the row is committed. The other order loses the race a
    // fast worker wins: it would BLPOP the envelope, find no `audit_exports`
    // row to update, and drop the task silently.
    let envelope = TaskEnvelope::new(
        task_types::AUDIT_EXPORT,
        serde_json::json!({
            "export_id": export_id,
            "from": body.from,
            "to": body.to,
            "format": format.as_str(),
            "page_size": page_size,
        }),
        ws,
    );
    let payload = serde_json::to_string(&envelope).map_err(|e| {
        api_error_response(store_unavailable("serializing the export task", &e))
    })?;
    if let Err(e) = enqueue_task(&state.redis_pool, QUEUE_AUDIT_EXPORT, &payload).await {
        // The row exists and says `queued`, which would be a lie if nothing is
        // ever going to pick it up. Mark it failed so the caller polls a truth.
        tracing::error!(%export_id, error = %e, "could not enqueue audit.export task");
        let _ = mark_enqueue_failed(&state, export_id, ws).await;
        return Err(api_error_response(ApiError::ServiceUnavailable(
            "the export could not be queued, so it will not be produced. The \
             request has been recorded as failed rather than left pending."
                .into(),
        )));
    }

    Ok((
        StatusCode::ACCEPTED,
        Json(CreateExportResponse {
            export_id,
            status: STATUS_QUEUED,
            status_url: format!("/v1/audit-exports/{export_id}"),
            note: "The export is produced in the background. Poll `status_url` \
                   until `status` is `complete` or `failed`.",
        }),
    )
        .into_response())
}

async fn mark_enqueue_failed(state: &AppState, export_id: Uuid, ws: Uuid) -> Result<(), ApiError> {
    let mut tx = begin_scoped(state, ws).await?;
    sqlx::query(
        "UPDATE audit_exports SET status = 'failed', error = $2, completed_at = NOW() \
         WHERE id = $1 AND workspace_id = $3",
    )
    .bind(export_id)
    .bind(
        "the export task could not be placed on the worker queue, so no export \
         was produced. Nothing partial was published.",
    )
    .bind(ws)
    .execute(&mut *tx)
    .await
    .map_err(|e| store_unavailable("recording the queueing failure", &e))?;
    tx.commit()
        .await
        .map_err(|e| store_unavailable("committing the queueing failure", &e))
}

#[derive(Debug, Deserialize)]
pub struct ListParams {
    pub limit: Option<i64>,
}

/// `GET /v1/audit-exports`
async fn list_exports(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Query(params): Query<ListParams>,
) -> Result<Json<Vec<ExportSummary>>, Response> {
    require_role(&ctx, UserRole::Admin).map_err(api_error_response)?;
    let ws = ctx.workspace_id.0;
    let limit = params.limit.unwrap_or(50).clamp(1, 200);

    let mut tx = begin_scoped(&state, ws).await.map_err(api_error_response)?;
    let rows = sqlx::query(
        "SELECT id, status, format, window_from, window_to, total_rows, total_pages, \
                created_at, completed_at \
         FROM audit_exports WHERE workspace_id = $1 \
         ORDER BY created_at DESC LIMIT $2",
    )
    .bind(ws)
    .bind(limit)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| api_error_response(store_unavailable("listing exports", &e)))?;
    tx.commit()
        .await
        .map_err(|e| api_error_response(store_unavailable("closing the list read", &e)))?;

    Ok(Json(
        rows.into_iter()
            .map(|r| ExportSummary {
                export_id: r.get("id"),
                status: r.get("status"),
                format: r.get("format"),
                window_from: r.get("window_from"),
                window_to: r.get("window_to"),
                total_rows: r.get("total_rows"),
                total_pages: r.get("total_pages"),
                created_at: r.get("created_at"),
                completed_at: r.get("completed_at"),
            })
            .collect(),
    ))
}

/// `GET /v1/audit-exports/{id}`
///
/// 404 for an export belonging to another workspace — the same answer as one
/// that does not exist, so the endpoint is not an oracle for "does this id
/// exist somewhere in the deployment".
async fn get_export(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<ExportDetail>, Response> {
    require_role(&ctx, UserRole::Admin).map_err(api_error_response)?;
    let ws = ctx.workspace_id.0;

    let mut tx = begin_scoped(&state, ws).await.map_err(api_error_response)?;
    let row = sqlx::query(
        "SELECT id, workspace_id, status, format, page_size, window_from, window_to, \
                total_rows, total_pages, manifest_json, signature_b64, public_key_b64, \
                signing_key_id, error, created_at, completed_at \
         FROM audit_exports WHERE id = $1 AND workspace_id = $2",
    )
    .bind(id)
    .bind(ws)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| api_error_response(store_unavailable("reading the export", &e)))?;
    tx.commit()
        .await
        .map_err(|e| api_error_response(store_unavailable("closing the export read", &e)))?;

    let row = row.ok_or_else(|| api_error_response(ApiError::NotFound("export not found".into())))?;
    let status: String = row.get("status");
    let total_pages: Option<i32> = row.get("total_pages");

    Ok(Json(ExportDetail {
        export_id: row.get("id"),
        workspace_id: row.get("workspace_id"),
        page_size: row.get("page_size"),
        format: row.get("format"),
        window_from: row.get("window_from"),
        window_to: row.get("window_to"),
        total_rows: row.get("total_rows"),
        total_pages,
        manifest_json: row.get("manifest_json"),
        signature_b64: row.get("signature_b64"),
        public_key_b64: row.get("public_key_b64"),
        signing_key_id: row.get("signing_key_id"),
        error: row.get("error"),
        created_at: row.get("created_at"),
        completed_at: row.get("completed_at"),
        page_url_template: (status == STATUS_COMPLETE)
            .then(|| format!("/v1/audit-exports/{id}/pages/{{page}}")),
        signature_note: SIGNATURE_NOTE,
        status,
    }))
}

/// `GET /v1/audit-exports/{id}/pages/{page}`
///
/// Serves the stored bytes verbatim, as `text/csv` or `application/x-ndjson`.
/// `page` is 1-based, matching `manifest.pages[i].page`, so an auditor reading
/// a `PageDigestMismatch { page: 2 }` fetches `/pages/2`.
async fn get_export_page(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Path((id, page)): Path<(Uuid, i32)>,
) -> Result<Response, Response> {
    require_role(&ctx, UserRole::Admin).map_err(api_error_response)?;
    let ws = ctx.workspace_id.0;

    let mut tx = begin_scoped(&state, ws).await.map_err(api_error_response)?;
    // The format lives on the parent row, and the join keeps the tenancy
    // predicate on BOTH tables rather than trusting the FK.
    let row = sqlx::query(
        "SELECT p.body, p.sha256, e.format \
         FROM audit_export_pages p \
         JOIN audit_exports e ON e.id = p.export_id \
         WHERE p.export_id = $1 AND p.page_number = $2 \
           AND p.workspace_id = $3 AND e.workspace_id = $3",
    )
    .bind(id)
    .bind(page)
    .bind(ws)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| api_error_response(store_unavailable("reading the export page", &e)))?;
    tx.commit()
        .await
        .map_err(|e| api_error_response(store_unavailable("closing the page read", &e)))?;

    let row = row.ok_or_else(|| {
        api_error_response(ApiError::NotFound(
            "export page not found — the export may still be running, may have \
             failed, or may have fewer pages than you asked for"
                .into(),
        ))
    })?;

    let body: String = row.get("body");
    let sha256: String = row.get("sha256");
    let format_text: String = row.get("format");
    let content_type = ExportFormat::parse(&format_text)
        .map_or("application/octet-stream", ExportFormat::content_type);
    let extension = if format_text == "csv" { "csv" } else { "jsonl" };

    Ok((
        [
            (header::CONTENT_TYPE, content_type.to_owned()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"audit-export-{id}-page-{page}.{extension}\""),
            ),
            // The digest of the bytes in this response, so a client can check
            // the transfer without parsing the manifest. It is NOT the
            // signature and proves nothing on its own — the same server sent
            // both — which is why the header is named for what it is.
            (
                header::ETAG,
                format!("\"sha256:{sha256}\""),
            ),
        ],
        body,
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(from: &str, to: &str, format: &str, page_size: Option<u32>) -> CreateExportRequest {
        CreateExportRequest {
            from: from.parse().expect("from"),
            to: to.parse().expect("to"),
            format: format.to_owned(),
            page_size,
        }
    }

    #[test]
    fn validate_accepts_a_normal_request() {
        let ok = validate(&req(
            "2026-06-01T00:00:00Z",
            "2026-06-02T00:00:00Z",
            "csv",
            None,
        ))
        .expect("a one-day csv window is valid");
        assert_eq!(ok, (ExportFormat::Csv, DEFAULT_PAGE_SIZE));
    }

    #[test]
    fn validate_rejects_an_unknown_format() {
        let err = validate(&req(
            "2026-06-01T00:00:00Z",
            "2026-06-02T00:00:00Z",
            "parquet",
            None,
        ))
        .expect_err("parquet is not offered");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    /// `from == to` is refused rather than producing a signed statement about
    /// a window of zero length.
    #[test]
    fn validate_rejects_an_empty_or_inverted_window() {
        for (from, to) in [
            ("2026-06-02T00:00:00Z", "2026-06-01T00:00:00Z"),
            ("2026-06-01T00:00:00Z", "2026-06-01T00:00:00Z"),
        ] {
            assert!(
                validate(&req(from, to, "csv", None)).is_err(),
                "window {from}..{to} must be refused"
            );
        }
    }

    #[test]
    fn validate_caps_the_window() {
        // Positive control: one day under the cap is accepted, so the
        // rejection below is the cap's doing.
        assert!(validate(&req(
            "2026-01-01T00:00:00Z",
            "2026-12-01T00:00:00Z",
            "jsonl",
            None
        ))
        .is_ok());
        assert!(validate(&req(
            "2020-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
            "jsonl",
            None
        ))
        .is_err());
    }

    #[test]
    fn validate_bounds_page_size() {
        let w = ("2026-06-01T00:00:00Z", "2026-06-02T00:00:00Z");
        assert!(validate(&req(w.0, w.1, "csv", Some(MIN_PAGE_SIZE))).is_ok());
        assert!(validate(&req(w.0, w.1, "csv", Some(MAX_PAGE_SIZE))).is_ok());
        assert!(validate(&req(w.0, w.1, "csv", Some(0))).is_err());
        assert!(validate(&req(w.0, w.1, "csv", Some(MAX_PAGE_SIZE + 1))).is_err());
    }

    /// The signature note has to tell an auditor the one thing that makes the
    /// scheme worth anything: the published key is not a trust root.
    #[test]
    fn the_signature_note_says_to_get_the_key_out_of_band() {
        assert!(SIGNATURE_NOTE.contains("SEPARATE CHANNEL"));
        assert!(SIGNATURE_NOTE.contains("not a trust root"));
    }
}
