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
//!
//! # Two stores (FU1)
//!
//! The export now covers the control plane too, and the control plane lives in
//! Postgres while the request log lives in ClickHouse. The chain logic is not
//! duplicated and does not know: [`produce`] paginates each plane's rows into
//! pages and hands `secureprompt_common::audit_export::build_manifest` a list
//! of SECTIONS, and that function walks the pages of every section in order
//! through the one chain. Everything store-shaped stops at [`fetch_rows`] and
//! [`fetch_control_rows`], which both return plain `Vec`s of row structs.
//!
//! A fourth refusal comes with the second store, and it is the one that
//! matters most here. `session_revocation_audit` is under FORCE ROW LEVEL
//! SECURITY keyed on `app.current_workspace_id`; `current_setting(.., true)`
//! yields NULL when that GUC is unset, so the policy predicate is NULL for
//! every row and the read returns the EMPTY SET **and succeeds**. An export
//! signed over that emptiness is a valid signature over the false claim that
//! no administrator did anything — strictly worse than no export. So
//! [`begin_scoped`] READS THE GUC BACK inside the transaction and refuses if it
//! is not this workspace, turning a silent zero into a recorded failure.

use chrono::{DateTime, Utc};
use clickhouse::Row;
use secureprompt_common::{
    audit_export::{
        build_manifest, control_section, no_expiry_for, render_page, request_section,
        retention_for, signing_key_from_env, AuditRow, ControlRow, ExportFormat, ExportRow,
        SignedExport, SourceRetention, EVENT_RAW_CAPTURE_CHANGED, EVENT_RETENTION_PURGE,
        EVENT_SESSION_REVOKED,
    },
    tasks::TaskEnvelope,
};
use serde::Deserialize;
use serde_json::Value;
use sqlx::{PgPool, Row as _};
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
            Self::Malformed => "export task payload is not a well-formed audit-export request",
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

// ── Control-plane read (Postgres) ─────────────────────────────────────────

/// The instant column each control-plane source is windowed on, named here so
/// the job, the docs and the tests all cite the same thing.
///
/// `retention_purge_audit` is windowed on `completed_at` rather than
/// `started_at`: a purge run's audit row is a statement about what it HAD
/// deleted, which is only true once it finished.
pub const CONTROL_TIME_COLUMNS: &[(&str, &str)] = &[
    ("raw_capture_audit", "created_at"),
    ("retention_purge_audit", "completed_at"),
    ("session_revocation_audit", "created_at"),
    ("admin_audit", "created_at"),
];

/// The total order the control plane is exported in.
///
/// Determinism is load-bearing for the same reason it is on the ClickHouse
/// side — the chain hashes page BYTES — but the rows come from three tables, so
/// the order is imposed here rather than by one `ORDER BY`. `source_table` is
/// in the key between the instant and the id so the order is total even for
/// two events recorded in the same microsecond, without depending on UUIDs
/// from different tables never colliding.
fn control_sort_key(row: &ControlRow) -> (DateTime<Utc>, String, Uuid) {
    (row.occurred_at, row.source_table.clone(), row.event_id)
}

/// Read every audited administrative action for one workspace and window.
///
/// Runs inside a transaction opened by [`begin_scoped`], so a silent zero from
/// an unset GUC has already been refused before any row is read.
///
/// The four source tables are ALL under FORCE ROW LEVEL SECURITY, but they did
/// not start that way and the difference mattered. `session_revocation_audit`
/// (026) and `admin_audit` (028) were armed by the migrations that created
/// them. `raw_capture_audit` (021) and `retention_purge_audit` (023) were NOT:
/// until migration 030 this comment said "the RLS-armed table is readable" of
/// a table with no policy at all, and the only thing keeping one tenant's
/// audit rows out of another tenant's SIGNED attestation was the
/// `WHERE workspace_id = $1` on each query below. Measured from a
/// NOSUPERUSER/NOBYPASSRLS role, a foreign scope could read and write both.
/// Both predicates are kept: RLS is defence in depth here, not the filter.
///
/// `retention_purge_audit` carries the ONE non-standard policy in the schema —
/// it also admits `workspace_id IS NULL` — because its global purge scopes are
/// counted, not exported, by the `excluded` query at the end of this function.
/// Under the standard policy that count would silently read 0 and the
/// manifest's exclusion disclosure would become a false zero.
async fn fetch_control_rows(
    pg: &PgPool,
    req: &ExportRequest,
) -> sqlx::Result<(Vec<ControlRow>, u64)> {
    let mut tx = begin_scoped(pg, req.workspace_id).await?;
    let mut rows: Vec<ControlRow> = Vec::new();

    for record in sqlx::query(
        "SELECT id, actor_user_id, actor_email, enabled_before, enabled_after, \
                retention_days_before, retention_days_after, created_at \
         FROM raw_capture_audit \
         WHERE workspace_id = $1 AND created_at >= $2 AND created_at < $3",
    )
    .bind(req.workspace_id)
    .bind(req.from)
    .bind(req.to)
    .fetch_all(&mut *tx)
    .await?
    {
        rows.push(ControlRow {
            event_id: record.get("id"),
            workspace_id: req.workspace_id,
            occurred_at: record.get("created_at"),
            event_type: EVENT_RAW_CAPTURE_CHANGED.to_owned(),
            source_table: "raw_capture_audit".to_owned(),
            actor_user_id: record.get("actor_user_id"),
            actor_email: record.get("actor_email"),
            actor_role: None,
            target_user_id: None,
            target_email: None,
            target_role: None,
            detail: serde_json::json!({
                "enabled_before": record.get::<bool, _>("enabled_before"),
                "enabled_after": record.get::<bool, _>("enabled_after"),
                "retention_days_before": record.get::<i32, _>("retention_days_before"),
                "retention_days_after": record.get::<i32, _>("retention_days_after"),
            }),
        });
    }

    for record in sqlx::query(
        "SELECT id, run_id, scope, cutoff, rows_deleted, oldest_deleted, newest_deleted, \
                rows_remaining_past_cutoff, status, (error IS NOT NULL) AS error_present, \
                started_at, completed_at \
         FROM retention_purge_audit \
         WHERE workspace_id = $1 AND completed_at >= $2 AND completed_at < $3",
    )
    .bind(req.workspace_id)
    .bind(req.from)
    .bind(req.to)
    .fetch_all(&mut *tx)
    .await?
    {
        rows.push(ControlRow {
            event_id: record.get("id"),
            workspace_id: req.workspace_id,
            occurred_at: record.get("completed_at"),
            event_type: EVENT_RETENTION_PURGE.to_owned(),
            source_table: "retention_purge_audit".to_owned(),
            // A purge run has no human actor: it is the scheduler. NULL here
            // is a fact about the event, not a lost attribution.
            actor_user_id: None,
            actor_email: None,
            actor_role: None,
            target_user_id: None,
            target_email: None,
            target_role: None,
            detail: serde_json::json!({
                "run_id": record.get::<Uuid, _>("run_id"),
                "scope": record.get::<String, _>("scope"),
                "cutoff": record.get::<DateTime<Utc>, _>("cutoff"),
                "rows_deleted": record.get::<i64, _>("rows_deleted"),
                "oldest_deleted": record.get::<Option<DateTime<Utc>>, _>("oldest_deleted"),
                "newest_deleted": record.get::<Option<DateTime<Utc>>, _>("newest_deleted"),
                "rows_remaining_past_cutoff":
                    record.get::<i64, _>("rows_remaining_past_cutoff"),
                "status": record.get::<String, _>("status"),
                // The `error` COLUMN is deliberately not exported — it carries
                // a ClickHouse exception message, which quotes the statement
                // that provoked it. See this module's docs and
                // `audit_export`'s.
                "error_present": record.get::<bool, _>("error_present"),
                "started_at": record.get::<DateTime<Utc>, _>("started_at"),
            }),
        });
    }

    for record in sqlx::query(
        "SELECT id, actor_user_id, actor_email, actor_role, target_user_id, target_email, \
                target_role, revoked_before_unix, refresh_tokens_revoked, created_at \
         FROM session_revocation_audit \
         WHERE workspace_id = $1 AND created_at >= $2 AND created_at < $3",
    )
    .bind(req.workspace_id)
    .bind(req.from)
    .bind(req.to)
    .fetch_all(&mut *tx)
    .await?
    {
        rows.push(ControlRow {
            event_id: record.get("id"),
            workspace_id: req.workspace_id,
            occurred_at: record.get("created_at"),
            event_type: EVENT_SESSION_REVOKED.to_owned(),
            source_table: "session_revocation_audit".to_owned(),
            actor_user_id: record.get("actor_user_id"),
            actor_email: record.get("actor_email"),
            actor_role: record.get("actor_role"),
            target_user_id: record.get("target_user_id"),
            target_email: record.get("target_email"),
            target_role: record.get("target_role"),
            detail: serde_json::json!({
                "revoked_before_unix": record.get::<i64, _>("revoked_before_unix"),
                "refresh_tokens_revoked": record.get::<i64, _>("refresh_tokens_revoked"),
            }),
        });
    }

    // FU5 — `admin_audit`, the one source that is not per-action.
    //
    // THIS IS THE WHOLE POINT OF THE SINGLE-TABLE DESIGN, so it is worth being
    // explicit about what is NOT here: there is no `match` on the action, no
    // per-action `detail` construction and no `WHERE action IN (...)`. The
    // stored `action` becomes `event_type` VERBATIM and the stored `detail`
    // is carried through with the object identity merged in. A thirteenth
    // audited action therefore reaches an auditor with no change to this
    // function — there is no list here to forget to extend, which is what makes
    // "a new action cannot silently miss the export" structural rather than a
    // habit. `tests.rs::every_audited_action_reaches_the_signed_export` reads
    // the vocabulary out of migration 028's CHECK constraint and proves it.
    for record in sqlx::query(
        "SELECT id, action, actor_user_id, actor_email, actor_role, target_type, \
                target_id, target_label, target_user_id, target_email, target_role, \
                detail, created_at \
         FROM admin_audit \
         WHERE workspace_id = $1 AND created_at >= $2 AND created_at < $3",
    )
    .bind(req.workspace_id)
    .bind(req.from)
    .bind(req.to)
    .fetch_all(&mut *tx)
    .await?
    {
        // The object's identity travels in `detail` rather than in new
        // top-level columns: `CONTROL_COLUMNS` is the shared shape for all four
        // sources, and widening it for one source would change every row of the
        // other three and break the format for a reason none of them share.
        let mut detail = record.get::<Value, _>("detail");
        if let Value::Object(map) = &mut detail {
            map.insert(
                "target_type".to_owned(),
                Value::String(record.get::<String, _>("target_type")),
            );
            map.insert(
                "target_id".to_owned(),
                record
                    .get::<Option<Uuid>, _>("target_id")
                    .map_or(Value::Null, |id| Value::String(id.to_string())),
            );
            map.insert(
                "target_label".to_owned(),
                record
                    .get::<Option<String>, _>("target_label")
                    .map_or(Value::Null, Value::String),
            );
        }

        rows.push(ControlRow {
            event_id: record.get("id"),
            workspace_id: req.workspace_id,
            occurred_at: record.get("created_at"),
            event_type: record.get::<String, _>("action"),
            source_table: "admin_audit".to_owned(),
            actor_user_id: record.get("actor_user_id"),
            actor_email: record.get("actor_email"),
            actor_role: record.get("actor_role"),
            target_user_id: record.get("target_user_id"),
            target_email: record.get("target_email"),
            target_role: record.get("target_role"),
            detail,
        });
    }

    // Purge scopes that are not per-workspace — the token vault, for instance —
    // carry `workspace_id IS NULL` and are NOT this tenant's records, so they
    // are excluded. The COUNT is reported in the manifest so the exclusion is a
    // number an auditor can see rather than an absence they cannot.
    let excluded: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM retention_purge_audit \
         WHERE workspace_id IS NULL AND completed_at >= $1 AND completed_at < $2",
    )
    .bind(req.from)
    .bind(req.to)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;

    rows.sort_by_key(control_sort_key);
    Ok((rows, u64::try_from(excluded).unwrap_or(0)))
}

/// The control-plane section's retention blocks: one per source relation, all
/// `no_expiry`, with the purge table additionally stating its exclusion rule.
fn control_sources(excluded_global_purge_rows: u64) -> Vec<SourceRetention> {
    CONTROL_TIME_COLUMNS
        .iter()
        .map(|(table, _)| {
            let mut source = no_expiry_for(table);
            if *table == "retention_purge_audit" {
                source.excluded_rows = excluded_global_purge_rows;
                source.excluded_reason = Some(
                    "Rows whose `workspace_id` IS NULL are purge scopes that are not \
                     per-workspace — the token vault, for instance — and are not this \
                     tenant's records, so they are not exported. This is the number of \
                     them that fell in the window, reported so their exclusion is \
                     visible rather than silent."
                        .to_owned(),
                );
            }
            source
        })
        .collect()
}

// ── Production ────────────────────────────────────────────────────────────

/// Chunk one section's rows into pages of `page_size` and render each.
///
/// A section with no rows still produces ONE page. That is deliberate: "we
/// looked at this window and there was nothing" is a claim an auditor needs
/// signed, and a section with no pages at all is indistinguishable from one
/// that was removed — which `build_manifest` refuses outright.
fn paginate<R: ExportRow>(
    rows: &[R],
    page_size: u32,
    format: ExportFormat,
) -> (Vec<Vec<u8>>, Vec<u32>) {
    let chunks: Vec<&[R]> = if rows.is_empty() {
        vec![&[]]
    } else {
        rows.chunks(page_size as usize).collect()
    };
    let pages = chunks
        .iter()
        .map(|chunk| render_page(chunk, format))
        .collect();
    let rows_per_page = chunks
        .iter()
        .map(|chunk| u32::try_from(chunk.len()).unwrap_or(u32::MAX))
        .collect();
    (pages, rows_per_page)
}

/// Render both planes into pages and sign one manifest over all of them.
///
/// Pure apart from the clock: no database, no queue. Split out so the
/// "exported bytes equal the live rows" test can drive it directly with rows
/// it fetched itself.
///
/// The returned page vector is the whole export in page order — the data
/// plane's pages, then the control plane's — which is the order the chain, the
/// manifest and `audit_export_pages.page_number` all agree on.
///
/// # Errors
/// Propagates [`secureprompt_common::audit_export::BuildError`].
pub fn produce(
    req: &ExportRequest,
    rows: &[AuditRow],
    control: &[ControlRow],
    excluded_global_purge_rows: u64,
    generated_at: DateTime<Utc>,
    key: &ed25519_dalek::SigningKey,
) -> Result<(Vec<Vec<u8>>, SignedExport), secureprompt_common::audit_export::BuildError> {
    let (data_pages, data_rows_per_page) = paginate(rows, req.page_size, req.format);
    let (control_pages, control_rows_per_page) = paginate(control, req.page_size, req.format);

    let signed = build_manifest(
        req.export_id,
        req.workspace_id,
        req.from,
        req.to,
        req.format,
        req.page_size,
        &[
            request_section(
                data_pages.clone(),
                data_rows_per_page,
                vec![retention_for(req.from, req.to, generated_at)],
            ),
            control_section(
                control_pages.clone(),
                control_rows_per_page,
                control_sources(excluded_global_purge_rows),
            ),
        ],
        generated_at,
        key,
    )?;

    let mut pages = data_pages;
    pages.extend(control_pages);
    Ok((pages, signed))
}

// ── Persistence ───────────────────────────────────────────────────────────

/// The refusal recorded when the tenancy GUC did not take. A `&'static str`,
/// like every other reason this module stores.
const SCOPE_NOT_ARMED: &str =
    "the export transaction could not be scoped to your workspace, so nothing was read \
     and nothing was signed";

/// Open a transaction with `app.current_workspace_id` set, and PROVE it is set.
///
/// Every statement this module runs against `audit_exports`,
/// `audit_export_pages` and the control-plane audit tables goes through here.
/// Migrations 025 and 026 put FORCE ROW LEVEL SECURITY on those tables keyed on
/// that GUC; without it the policy predicate is NULL, SELECTs return nothing
/// and INSERTs are rejected. Setting it is not optional bookkeeping — it is the
/// thing that makes the tables readable and writable at all under a
/// non-superuser role.
///
/// The read-back is the part that is new with the control plane, and it is not
/// belt-and-braces. On the WRITE path a missing GUC is loud: the INSERT is
/// rejected and the export fails. On the READ path it is SILENT — the query
/// succeeds and returns the empty set, which on a compliance artifact is
/// indistinguishable from "this workspace's administrators did nothing", and
/// the product would then SIGN that. So the value is read back inside the same
/// transaction and compared, and a mismatch is an error rather than an empty
/// export.
async fn begin_scoped(
    pg: &PgPool,
    workspace_id: Uuid,
) -> sqlx::Result<sqlx::Transaction<'static, sqlx::Postgres>> {
    let mut tx = pg.begin().await?;
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
        .bind(workspace_id.to_string())
        .execute(&mut *tx)
        .await?;
    scope_is_armed(&mut tx, workspace_id).await?;
    Ok(tx)
}

/// Read `app.current_workspace_id` back and require it to be `workspace_id`.
///
/// Split out from [`begin_scoped`] so it is directly testable: a guard whose
/// deletion changes no test result is a guard that defends nothing, and this
/// one is only reachable through a transaction that has just been scoped.
async fn scope_is_armed(
    tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    workspace_id: Uuid,
) -> sqlx::Result<()> {
    let armed: Option<String> =
        sqlx::query_scalar("SELECT current_setting('app.current_workspace_id', true)")
            .fetch_one(&mut **tx)
            .await?;
    if armed.as_deref() == Some(workspace_id.to_string().as_str()) {
        Ok(())
    } else {
        Err(sqlx::Error::Protocol(SCOPE_NOT_ARMED.to_owned()))
    }
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
        let digest = signed.page_digests.get(index).map_or("", String::as_str);
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

    // The control plane FIRST, because it is the half that can fail silently.
    // A Postgres error here refuses the whole export rather than producing a
    // data-plane-only one: `build_manifest` would refuse that anyway, and an
    // auditor must never be handed an artifact that answers "what requests
    // happened" while quietly dropping "what administrators did".
    let (control, excluded_global_purge_rows) = match fetch_control_rows(pg, &req).await {
        Ok(found) => found,
        Err(e) => {
            tracing::error!(
                export_id = %req.export_id,
                error = %e,
                "audit.export control-plane read failed"
            );
            mark_failed(
                pg,
                req.export_id,
                req.workspace_id,
                "the control-plane audit trail could not be read, so no export was produced \
                 rather than one covering gateway traffic alone. An export that carried only \
                 the request log would look complete and would not be. The store's own error \
                 message is in the gateway log.",
            )
            .await;
            return failed(STATUS_FAILED);
        }
    };
    let control_rows = u64::try_from(control.len()).unwrap_or(u64::MAX);

    match count_rows(ch, &req).await {
        // The cap is over the WHOLE export, both planes, because the storage
        // bill it exists to bound is the stored page bytes.
        Ok(count) if count.saturating_add(control_rows) > max_export_rows => {
            let count = count.saturating_add(control_rows);
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

    let (pages, signed) = match produce(
        &req,
        &rows,
        &control,
        excluded_global_purge_rows,
        generated_at,
        &key,
    ) {
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
        control_rows,
        excluded_global_purge_rows,
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
