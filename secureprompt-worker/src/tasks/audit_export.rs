//! WS4-1 / Task 19 — the `audit.export` worker task.
//!
//! Replaces
//! ```text
//! tracing::debug!("audit.export — no-op stub (Phase 7 implementation)");
//! ```
//! with the job that actually produces the artifact: read `request_events` for
//! one workspace and one half-open window, paginate, render CSV or JSONL, sign
//! a manifest over the page digests, and persist the exact bytes.
//!
//! The digest chain, the manifest and the signature live in
//! [`secureprompt_common::audit_export`] so the API and any external verifier
//! share one definition of "signed". This module is the I/O around it.
//!
//! # Determinism is load-bearing
//!
//! The chain hashes page BYTES, so two runs over the same window must produce
//! the same pages or the artifact is not reproducible. The read is therefore
//! `ORDER BY created_at ASC, request_id ASC` — a total order (request_id is
//! unique per row), and a prefix of the table's own
//! `ORDER BY (workspace_id, created_at, request_id)` so it costs no sort.
//! Without the `request_id` tie-break, two rows sharing a whole second could
//! swap between runs and every downstream digest would change.
//!
//! # Failure is explicit, never a shorter export
//!
//! Three conditions refuse rather than degrade, because each of their
//! degraded forms is an export that LOOKS complete:
//!
//!   * **No signing key.** Producing an unsigned export would ship the exact
//!     defect this task exists to remove.
//!   * **Window over the row cap.** Truncating would hand an auditor a partial
//!     trail with a valid signature over it — worse than no export at all.
//!   * **ClickHouse did not answer.** A zero-row export is a factual claim
//!     ("we looked, there was nothing"); emitting one because the store was
//!     down would make that claim false.
//!
//! Expiry is NOT one of them. A window behind the 90-day TTL still produces a
//! signed export, because the honest artifact is the surviving rows plus a
//! manifest that says the window is partially or wholly expired — see
//! `audit_export::retention_for`. Refusing would leave the auditor with
//! nothing to check.

use chrono::{DateTime, Utc};
use clickhouse::Row;
use secureprompt_common::{
    audit_export::{
        build_manifest, render_page, signing_key_from_env, AuditRow, ExportFormat, SignedExport,
    },
    tasks::TaskEnvelope,
};
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

/// Rows per page when the caller does not choose.
pub const DEFAULT_PAGE_SIZE: u32 = 5_000;
/// Smallest page a caller may ask for. One row per page is legal — it is the
/// shape a suspicious auditor uses to isolate exactly which row moved.
pub const MIN_PAGE_SIZE: u32 = 1;
/// Largest page a caller may ask for.
pub const MAX_PAGE_SIZE: u32 = 50_000;

/// Hard ceiling on the rows one export may contain.
///
/// An export is a MATERIALISED artifact — the exact signed bytes are stored in
/// Postgres, because `request_events` has a TTL and a regenerated page would
/// eventually stop matching its own manifest (see migration 025). So the row
/// count is a storage bill, and an unbounded window is an unbounded bill.
///
/// Over the cap the job FAILS and names the cap. It does not truncate: a
/// truncated export carrying a valid signature is a forgery the product signed
/// itself.
pub const MAX_EXPORT_ROWS: u64 = 500_000;

// ── Status vocabulary ─────────────────────────────────────────────────────

pub const STATUS_QUEUED: &str = "queued";
pub const STATUS_RUNNING: &str = "running";
pub const STATUS_COMPLETE: &str = "complete";
pub const STATUS_FAILED: &str = "failed";

// ── Request parsing ───────────────────────────────────────────────────────

/// The task payload, once validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportRequest {
    pub export_id: Uuid,
    pub workspace_id: Uuid,
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    pub format: ExportFormat,
    pub page_size: u32,
}

/// The envelope payload as it arrives on the queue.
#[derive(Debug, Deserialize)]
struct RawPayload {
    export_id: Uuid,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    format: String,
    page_size: Option<u32>,
}

/// Why a payload was refused. Bounded strings — a task payload is
/// attacker-shaped input and none of these echoes it back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestError {
    Malformed,
    UnknownFormat,
    PageSizeOutOfRange,
    WindowInverted,
}

impl RequestError {
    /// Operator-facing reason, stored in `audit_exports.error`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => {
                "export task payload is not a well-formed audit-export request"
            }
            Self::UnknownFormat => "export format must be `csv` or `jsonl`",
            Self::PageSizeOutOfRange => {
                "page_size is outside the permitted range for an audit export"
            }
            Self::WindowInverted => "export window must have `from` strictly before `to`",
        }
    }
}

/// Validate a queue envelope into an [`ExportRequest`].
///
/// `workspace_id` comes from the ENVELOPE, never from the payload: the API
/// stamps it from the caller's verified JWT, and letting the payload restate
/// it would create a second, forgeable source of tenancy.
///
/// # Errors
/// [`RequestError`].
pub fn parse_request(envelope: &TaskEnvelope) -> Result<ExportRequest, RequestError> {
    let raw: RawPayload =
        serde_json::from_value(envelope.payload.clone()).map_err(|_| RequestError::Malformed)?;
    let format = ExportFormat::parse(&raw.format).ok_or(RequestError::UnknownFormat)?;
    let page_size = raw.page_size.unwrap_or(DEFAULT_PAGE_SIZE);
    if !(MIN_PAGE_SIZE..=MAX_PAGE_SIZE).contains(&page_size) {
        return Err(RequestError::PageSizeOutOfRange);
    }
    if raw.from >= raw.to {
        return Err(RequestError::WindowInverted);
    }
    Ok(ExportRequest {
        export_id: raw.export_id,
        workspace_id: envelope.workspace_id,
        from: raw.from,
        to: raw.to,
        format,
        page_size,
    })
}

// ── ClickHouse read ───────────────────────────────────────────────────────

/// The tenancy + window predicate, written once and shared by the count and
/// the fetch so the two can never disagree about what is in scope.
///
/// Parameters are BOUND (`?`), not formatted. The two instants bind as UNIX
/// SECONDS through `toDateTime`, not as `DateTime<Utc>`: the `clickhouse`
/// crate binds a chrono datetime as RFC 3339 and ClickHouse refuses to cast
/// that to `DateTime` (`Code: 53 ... TYPE_MISMATCH`). Same reason and same
/// shape as `leak_report::SCOPE`.
const SCOPE: &str =
    "workspace_id = ? AND created_at >= toDateTime(?) AND created_at < toDateTime(?)";

/// One `request_events` row, metadata columns only.
///
/// `raw_prompt`, `raw_response`, `redacted_prompt` and `restored_response` are
/// deliberately absent — see `audit_export`'s module docs. Their absence here
/// is what makes the "no content in the export" claim structural rather than a
/// review convention: there is no field on this struct to leak them into.
#[derive(Debug, Row, Deserialize)]
struct EventRow {
    #[serde(with = "clickhouse::serde::uuid")]
    request_id: Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    workspace_id: Uuid,
    /// `toUnixTimestamp(created_at)` is `UInt32` in ClickHouse and must match
    /// here, or RowBinary deserialization fails with a schema mismatch.
    created_at_unix: u32,
    provider: String,
    model: String,
    final_action: String,
    input_tokens: Option<u32>,
    output_tokens: Option<u32>,
    estimated_usage: bool,
    cost_usd: f64,
    #[serde(with = "clickhouse::serde::uuid::option")]
    user_id: Option<Uuid>,
    #[serde(with = "clickhouse::serde::uuid::option")]
    api_key_id: Option<Uuid>,
    api_key_name: Option<String>,
    ip_address: Option<String>,
    user_agent: Option<String>,
    floor_only: bool,
    engines: Vec<String>,
}

impl EventRow {
    fn into_audit_row(self) -> AuditRow {
        AuditRow {
            request_id: self.request_id,
            workspace_id: self.workspace_id,
            created_at: DateTime::from_timestamp(i64::from(self.created_at_unix), 0)
                .unwrap_or_else(|| DateTime::from_timestamp(0, 0).unwrap_or_default()),
            provider: self.provider,
            model: self.model,
            final_action: self.final_action,
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            estimated_usage: self.estimated_usage,
            cost_usd: self.cost_usd,
            user_id: self.user_id,
            api_key_id: self.api_key_id,
            api_key_name: self.api_key_name,
            ip_address: self.ip_address,
            user_agent: self.user_agent,
            floor_only: self.floor_only,
            engines: self.engines,
        }
    }
}

/// The columns the export selects, in the order the manifest documents.
/// Shared by [`count_rows`]'s sibling [`fetch_rows`] and by the tests, so a
/// test asserting "the export equals the live query" cannot drift onto a
/// different projection than the one the job runs.
pub const SELECT_LIST: &str = "request_id, workspace_id, toUnixTimestamp(created_at) AS \
     created_at_unix, provider, model, final_action, input_tokens, output_tokens, \
     estimated_usage, cost_usd, user_id, api_key_id, api_key_name, ip_address, \
     user_agent, floor_only, engines";

/// The total order every export and every verification query uses.
pub const ORDER_BY: &str = "ORDER BY created_at ASC, request_id ASC";

async fn count_rows(
    ch: &clickhouse::Client,
    req: &ExportRequest,
) -> Result<u64, clickhouse::error::Error> {
    ch.query(&format!("SELECT count() FROM request_events WHERE {SCOPE}"))
        .bind(req.workspace_id)
        .bind(req.from.timestamp())
        .bind(req.to.timestamp())
        .fetch_one::<u64>()
        .await
}

async fn fetch_rows(
    ch: &clickhouse::Client,
    req: &ExportRequest,
) -> Result<Vec<AuditRow>, clickhouse::error::Error> {
    let rows = ch
        .query(&format!(
            "SELECT {SELECT_LIST} FROM request_events WHERE {SCOPE} {ORDER_BY}"
        ))
        .bind(req.workspace_id)
        .bind(req.from.timestamp())
        .bind(req.to.timestamp())
        .fetch_all::<EventRow>()
        .await?;
    Ok(rows.into_iter().map(EventRow::into_audit_row).collect())
}

// ── Production ────────────────────────────────────────────────────────────

/// Render `rows` into pages of `page_size` and sign the manifest over them.
///
/// Pure apart from the clock: no database, no queue. Split out so the
/// "exported bytes equal the live rows" test can drive it directly with rows
/// it fetched itself.
///
/// A zero-row export still produces ONE page. That is deliberate: "we looked
/// at this window and there was nothing" is a claim an auditor needs signed,
/// and an export with no pages at all would leave nothing to verify.
///
/// # Errors
/// Propagates [`secureprompt_common::audit_export::BuildError`].
pub fn produce(
    req: &ExportRequest,
    rows: &[AuditRow],
    generated_at: DateTime<Utc>,
    key: &ed25519_dalek::SigningKey,
) -> Result<(Vec<Vec<u8>>, SignedExport), secureprompt_common::audit_export::BuildError> {
    let chunks: Vec<&[AuditRow]> = if rows.is_empty() {
        vec![&[]]
    } else {
        rows.chunks(req.page_size as usize).collect()
    };
    let pages: Vec<Vec<u8>> = chunks
        .iter()
        .map(|chunk| render_page(chunk, req.format))
        .collect();
    let rows_per_page: Vec<u32> = chunks
        .iter()
        .map(|chunk| u32::try_from(chunk.len()).unwrap_or(u32::MAX))
        .collect();

    let signed = build_manifest(
        req.export_id,
        req.workspace_id,
        req.from,
        req.to,
        req.format,
        req.page_size,
        &pages,
        &rows_per_page,
        generated_at,
        key,
    )?;
    Ok((pages, signed))
}

// ── Persistence ───────────────────────────────────────────────────────────

/// Open a transaction with `app.current_workspace_id` set.
///
/// Every statement this module runs against `audit_exports` /
/// `audit_export_pages` goes through here. Migration 025 puts FORCE ROW LEVEL
/// SECURITY on both tables keyed on that GUC; without it the policy predicate
/// is NULL, SELECTs return nothing and INSERTs are rejected. Setting it is not
/// optional bookkeeping — it is the thing that makes the tables writable at
/// all under a non-superuser role.
async fn begin_scoped(
    pg: &PgPool,
    workspace_id: Uuid,
) -> sqlx::Result<sqlx::Transaction<'static, sqlx::Postgres>> {
    let mut tx = pg.begin().await?;
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
        .bind(workspace_id.to_string())
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

async fn mark_running(pg: &PgPool, req: &ExportRequest) -> sqlx::Result<()> {
    let mut tx = begin_scoped(pg, req.workspace_id).await?;
    sqlx::query(
        "UPDATE audit_exports SET status = $2, started_at = NOW() \
         WHERE id = $1 AND workspace_id = $3",
    )
    .bind(req.export_id)
    .bind(STATUS_RUNNING)
    .bind(req.workspace_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

/// Record a refusal. `reason` is always a `&'static str` from this binary —
/// never a store's message and never any part of the payload or the key.
async fn mark_failed(pg: &PgPool, export_id: Uuid, workspace_id: Uuid, reason: &str) {
    let outcome = async {
        let mut tx = begin_scoped(pg, workspace_id).await?;
        sqlx::query(
            "UPDATE audit_exports SET status = $2, error = $3, completed_at = NOW() \
             WHERE id = $1 AND workspace_id = $4",
        )
        .bind(export_id)
        .bind(STATUS_FAILED)
        .bind(reason)
        .bind(workspace_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await
    }
    .await;
    if let Err(e) = outcome {
        tracing::error!(%export_id, error = %e, "could not record audit-export failure");
    }
}

/// Write the pages and the signed manifest, then mark the export complete.
///
/// One transaction: a manifest visible without its pages, or pages without the
/// manifest that names them, is an artifact an auditor cannot verify and
/// cannot tell apart from tampering.
async fn persist(
    pg: &PgPool,
    req: &ExportRequest,
    pages: &[Vec<u8>],
    signed: &SignedExport,
) -> sqlx::Result<()> {
    let mut tx = begin_scoped(pg, req.workspace_id).await?;

    // Re-running a task (the queue is at-least-once) must not append a second
    // set of pages beside the first.
    sqlx::query("DELETE FROM audit_export_pages WHERE export_id = $1")
        .bind(req.export_id)
        .execute(&mut *tx)
        .await?;

    for (index, body) in pages.iter().enumerate() {
        let page_number = i32::try_from(index).unwrap_or(i32::MAX).saturating_add(1);
        // Both the digest and the row count are taken from the SIGNED figures
        // rather than recomputed here. Recomputing would let the stored row
        // count drift from the one the manifest commits to, and the stored
        // copy is what an operator reads when they are trying to work out
        // whether a page was altered at rest.
        let rows = signed.rows_per_page.get(index).copied().unwrap_or(0);
        let digest = signed
            .page_digests
            .get(index)
            .map_or("", String::as_str);
        sqlx::query(
            "INSERT INTO audit_export_pages \
             (export_id, workspace_id, page_number, row_count, sha256, body) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(req.export_id)
        .bind(req.workspace_id)
        .bind(page_number)
        .bind(i32::try_from(rows).unwrap_or(i32::MAX))
        .bind(digest)
        .bind(String::from_utf8_lossy(body).into_owned())
        .execute(&mut *tx)
        .await?;
    }

    sqlx::query(
        "UPDATE audit_exports SET status = $2, total_rows = $3, total_pages = $4, \
         manifest_json = $5, signature_b64 = $6, public_key_b64 = $7, \
         signing_key_id = $8, error = NULL, completed_at = NOW() \
         WHERE id = $1 AND workspace_id = $9",
    )
    .bind(req.export_id)
    .bind(STATUS_COMPLETE)
    .bind(i64::try_from(signed.total_rows).unwrap_or(i64::MAX))
    .bind(i32::try_from(signed.total_pages).unwrap_or(i32::MAX))
    .bind(&signed.manifest_json)
    .bind(&signed.signature_b64)
    .bind(&signed.public_key_b64)
    .bind(&signed.signing_key_id)
    .bind(req.workspace_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await
}

// ── Entry point ───────────────────────────────────────────────────────────

/// What one run did, for the metrics label and the log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub export_id: Option<Uuid>,
    pub status: &'static str,
    pub total_rows: u64,
    pub total_pages: u32,
}

impl Outcome {
    #[must_use]
    pub fn ok(&self) -> bool {
        self.status == STATUS_COMPLETE
    }
}

/// Handle one `audit.export` envelope end to end, taking the signing key and
/// the row cap from the process environment.
pub async fn run(pg: &PgPool, ch: &clickhouse::Client, envelope: &TaskEnvelope) -> Outcome {
    run_with(
        pg,
        ch,
        envelope,
        signing_key_from_env(),
        MAX_EXPORT_ROWS,
        Utc::now(),
    )
    .await
}

/// [`run`], with the three ambient inputs passed in.
///
/// Split out for a testability reason that is really a correctness reason. The
/// key and the cap would otherwise be read from process-global env vars, and
/// the refusal paths — "no signing key", "over the cap" — need those globals
/// to hold DIFFERENT values in different tests. Under the gate's
/// `--test-threads=4` that is a race, and the usual workaround (a test-only
/// mutex) buys determinism by making the tests serial while leaving the real
/// entry point untested. Passing them in means every refusal below is exercised
/// against the SAME code path production runs, with `run` reduced to the one
/// line that reads the environment.
///
/// Never panics and never returns `Err`: a worker that dies on a bad payload
/// stops draining the queue for every other tenant. Every refusal is recorded
/// on the export row instead, where the requesting auditor can read it.
pub async fn run_with(
    pg: &PgPool,
    ch: &clickhouse::Client,
    envelope: &TaskEnvelope,
    key: Result<ed25519_dalek::SigningKey, secureprompt_common::audit_export::KeyError>,
    max_export_rows: u64,
    generated_at: DateTime<Utc>,
) -> Outcome {
    let req = match parse_request(envelope) {
        Ok(req) => req,
        Err(e) => {
            // The export id may itself be the unparseable part, so this is the
            // one path that cannot record onto the row.
            tracing::error!(
                workspace_id = %envelope.workspace_id,
                reason = e.as_str(),
                "audit.export payload refused"
            );
            return Outcome {
                export_id: None,
                status: STATUS_FAILED,
                total_rows: 0,
                total_pages: 0,
            };
        }
    };

    let failed = |status| Outcome {
        export_id: Some(req.export_id),
        status,
        total_rows: 0,
        total_pages: 0,
    };

    if let Err(e) = mark_running(pg, &req).await {
        tracing::error!(export_id = %req.export_id, error = %e, "could not mark export running");
        return failed(STATUS_FAILED);
    }

    // Fail-closed on the key. An unsigned export is the defect, not a fallback.
    let key = match key {
        Ok(key) => key,
        Err(e) => {
            tracing::error!(
                export_id = %req.export_id,
                "audit.export refused: signing key unavailable"
            );
            mark_failed(pg, req.export_id, req.workspace_id, &e.to_string()).await;
            return failed(STATUS_FAILED);
        }
    };

    match count_rows(ch, &req).await {
        Ok(count) if count > max_export_rows => {
            tracing::warn!(export_id = %req.export_id, count, "audit.export over row cap");
            mark_failed(
                pg,
                req.export_id,
                req.workspace_id,
                &format!(
                    "this window selects {count} rows, over the {max_export_rows}-row export \
                     cap. The export was REFUSED rather than truncated, because a truncated \
                     export carrying a valid signature would look complete. Narrow the window \
                     and request again."
                ),
            )
            .await;
            return failed(STATUS_FAILED);
        }
        Ok(_) => {}
        Err(e) => {
            // The store's own message goes to the log, not the response body —
            // a ClickHouse exception quotes the statement and, for some error
            // classes, the value it choked on. Same rule as
            // `data_inventory::unavailable`.
            tracing::error!(export_id = %req.export_id, error = %e, "audit.export count failed");
            mark_failed(
                pg,
                req.export_id,
                req.workspace_id,
                "the analytics store did not answer, so no export was produced rather than an \
                 empty one. An empty export is a factual claim that the window held no traffic, \
                 and this run could not establish that. The store's own error message is in the \
                 gateway log.",
            )
            .await;
            return failed(STATUS_FAILED);
        }
    }

    let rows = match fetch_rows(ch, &req).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(export_id = %req.export_id, error = %e, "audit.export fetch failed");
            mark_failed(
                pg,
                req.export_id,
                req.workspace_id,
                "the analytics store did not answer, so no export was produced rather than a \
                 partial one. The store's own error message is in the gateway log.",
            )
            .await;
            return failed(STATUS_FAILED);
        }
    };

    let (pages, signed) = match produce(&req, &rows, generated_at, &key) {
        Ok(produced) => produced,
        Err(e) => {
            tracing::error!(export_id = %req.export_id, error = %e, "audit.export build failed");
            mark_failed(
                pg,
                req.export_id,
                req.workspace_id,
                "the export manifest could not be built, so nothing was published.",
            )
            .await;
            return failed(STATUS_FAILED);
        }
    };

    if let Err(e) = persist(pg, &req, &pages, &signed).await {
        tracing::error!(export_id = %req.export_id, error = %e, "audit.export persist failed");
        mark_failed(
            pg,
            req.export_id,
            req.workspace_id,
            "the export was produced but could not be stored, so nothing was published.",
        )
        .await;
        return failed(STATUS_FAILED);
    }

    tracing::info!(
        export_id = %req.export_id,
        workspace_id = %req.workspace_id,
        total_rows = signed.total_rows,
        total_pages = signed.total_pages,
        signing_key_id = %signed.signing_key_id,
        "audit.export complete"
    );

    Outcome {
        export_id: Some(req.export_id),
        status: STATUS_COMPLETE,
        total_rows: signed.total_rows,
        total_pages: signed.total_pages,
    }
}

#[cfg(test)]
mod tests;
