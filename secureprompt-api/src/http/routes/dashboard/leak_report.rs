//! WS3-6 — `GET /v1/leak-report`, the shadow-mode leak report.
//!
//! For a pilot window, this answers the question a bank actually buys on:
//! **what would have left the building?** Counts of detected entities by
//! class, broken down by destination model and by the actor who sent them.
//!
//! # The one rule
//!
//! NO RAW PII IN THE REPORT. Not in the counts, not in a `samples` field, not
//! in an `examples` field, not quoted back in an error message. This document
//! is produced during a pilot precisely because the customer has not yet
//! decided to trust the product with their data; a report that leaked the
//! thing it is counting would be self-refuting.
//!
//! It is enforced structurally rather than by review discipline:
//!
//! * The only table this module reads is `detection_class_counts`, which
//!   holds class names, an operator-chosen attribution and integers by
//!   construction (migration 008). There is no join to
//!   `request_content_captures`, and no payload column in scope.
//! * `entity_class` can only ever hold a string literal from this binary — the
//!   write path maps every class through
//!   `analytics::detection_counts::canonicalize`. So even a compromised ML
//!   sidecar cannot get bytes into this report through the label channel.
//! * `model` can only ever RENDER as a name in this workspace's `models`
//!   catalogue or the literal `unregistered`. This is a FIX, not an original
//!   property, and it took two goes. `resolve_model`'s Phase-1 passthrough
//!   forwards an unregistered model name verbatim, so before any mapping
//!   existed, posting `{"model": "<a name and a national id>"}` put those bytes
//!   on every counts row this workspace wrote and rendered them back in
//!   `by_model`. 912cd5e closed the WRITE path
//!   (`analytics::detection_counts::canonicalize_model`) and stopped there —
//!   but `detection_class_counts` has a 90-day TTL, so every row written before
//!   that upgrade kept rendering unbounded bytes for ninety days while this
//!   header and `CONTENT_POLICY` both asserted it could not. The RENDER is now
//!   bounded too, against the live catalogue, by [`bound_model`]. See
//!   [`registered_models`] for why that is a read-path guard rather than a
//!   backfill migration, and what it costs.
//! * Errors are built from validated dates and fixed strings. No handler in
//!   this file interpolates a request body or a stored value into an error.
//!
//! `tests/leak_report.rs::report_contains_no_detected_value` asserts the exact
//! synthetic values from a seeded dataset are absent from the response text,
//! after first asserting the counts for those same values are PRESENT.
//!
//! # "Department" does not exist, and this report says so
//!
//! The PRD asks for a breakdown by department. There is no department column,
//! table, or concept anywhere in the product — not in `users`, not in
//! `api_keys`, not in the analytics schema. Three options were available:
//!
//!   1. Invent one (e.g. parse it out of the API key name). A compliance
//!      officer would read invented numbers as measured ones. Rejected.
//!   2. Omit the dimension silently. That is the failure mode WS3-5's
//!      inventory endpoint exists to prevent — a reader cannot detect an
//!      absence nobody declared. Rejected.
//!   3. Report the attribution the schema DOES carry, and declare department
//!      as an unavailable dimension with the reason. Taken.
//!
//! This is a genuine gap in the PRD, not an implementation shortcut: deciding
//! where "department" lives (a column on `users`, a workspace-level mapping
//! from API keys to cost centres, or an org-chart sync) is a product decision
//! with a migration behind it. The response says so in the payload, so the gap
//! travels with the document rather than living in a task report.
//!
//! # Language
//!
//! The PRD requires RU/UZ. There is no i18n layer anywhere in this repo to
//! follow, so the report's STRUCTURE is language-neutral — stable machine keys
//! and integers — and the labels ride alongside as data. See
//! [`super::leak_report_labels`].

use axum::{
    extract::{Extension, Query, State},
    routing::get,
    Json, Router,
};
use chrono::{DateTime, NaiveDate, Utc};
use clickhouse::Row;
use secureprompt_common::errors::ApiError;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

use crate::{
    analytics::detection_counts::UNREGISTERED_MODEL,
    app_state::AppState,
    http::{
        api_error_response,
        middleware::jwt_auth::{JwtAuthContext, UserRole},
        routes::dashboard::role::require_role,
    },
};

use super::leak_report_labels;

/// Bumped when a field changes meaning or disappears. A pilot report is
/// archived and re-read months later; a reader needs to know which shape they
/// are holding.
///
/// 2 — `entities` figures no longer claim to equal the placeholder count, and
/// the placeholder count is reported separately as [`Placeholders`]. The
/// NUMBERS did not change; what a reader is entitled to conclude from them
/// did, which is exactly the case this counter exists for. A version-1 report
/// pulled out of an archive carries a `counting_rule` that overstates what its
/// own `entities` figures mean.
const SCHEMA_VERSION: u32 = 2;

/// Longest window the report will aggregate, matching the analytics
/// endpoints' cap. Also the practical ceiling: `detection_class_counts` has a
/// 90-day TTL, so a longer window silently reports a shorter one.
const MAX_WINDOW_DAYS: i64 = 366;

const WINDOW_INTERPRETATION: &str =
    "Both bounds are calendar dates in UTC and both are INCLUSIVE: rows are \
     selected from 00:00:00 on `from` up to 23:59:59 on `to`. Note that \
     detection_class_counts carries a 90-day TTL, so a window reaching \
     further back than that reports only what has not yet expired — the \
     report cannot distinguish an expired day from a quiet one.";

const CONTENT_POLICY: &str =
    "This report contains COUNTS ONLY. Every string in it comes from one of \
     three bounded sources, and none of them is a request body. `entity_class` \
     values are identifiers from a fixed vocabulary compiled into the gateway. \
     `model` is either a name that is in this workspace's model catalogue AS \
     OF NOW or the literal `unregistered`, which is what a request naming an \
     uncatalogued model is reported as — a caller cannot choose the bytes that \
     appear here. That bound is applied TWICE, and the second one matters for \
     reading this document: the gateway bounds `model` when it WRITES a counts \
     row, and this report bounds it again when it RENDERS one, against the \
     catalogue at the moment you asked. Two consequences, both real. (1) Rows \
     written before the write-path bound existed are still on disk for that \
     table's 90-day retention window and still carry whatever name was \
     requested; they are reported here under `unregistered`, but a reader \
     querying `detection_class_counts` DIRECTLY will see the stored value. \
     (2) A model an administrator has since DELETED from the catalogue is \
     reported as `unregistered` even for a window in which it was registered. \
     `api_key_name` and `user_id` are the operator's own attribution metadata; \
     `api_key_name` is free text an administrator chose and may name a person. \
     NO DETECTED VALUE — no name, number, card or address taken from a prompt \
     — is stored in the table this report reads or emitted anywhere in this \
     payload.";

/// What this report DOES and DOES NOT see.
///
/// Every number here is derived from `detection_class_counts`, which is written
/// from a `RequestEvent`, which reaches ClickHouse only through
/// `AnalyticsHandle::enqueue` — and the whole API crate calls that from exactly
/// one file, `pipeline/service.rs`, the gateway request pipeline. Every other
/// surface that runs the same detection pass emits nothing, so its detections
/// are absent from every figure in this document. A compliance officer reading
/// "N of M requests would have leaked" cannot be expected to know that; it is
/// stated in the payload.
///
/// `tests/leak_report.rs::the_report_states_that_it_covers_gateway_traffic_only`
/// asserts the one-call-site premise against the source, so a future endpoint
/// that starts emitting events reddens rather than making this quietly wrong.
const COVERAGE: &str = "GATEWAY TRAFFIC ONLY. These figures cover requests through \
     `/v1/chat/completions`, `/v1/completions` and `/v1/embeddings` — the paths \
     that write `request_events` and `detection_class_counts`. They do NOT \
     cover `/v1/redact`, `/v1/secure-mode/tokenize`, the MCP server, or file \
     scanning: those run the same detection pass and emit no analytics event at \
     all, so entities they found are counted nowhere in this report and their \
     requests are absent from `requests_in_window` too. This is a limit of what \
     is recorded, not a claim that those surfaces detected nothing. A workspace \
     that uses them should read these numbers as a floor.";

/// What an `entities` figure is, and — since 2026-07-30 — what it is NOT.
///
/// This constant used to end "…matching the number of placeholders the
/// redacted prompt carries". That sentence was false, and measurably so:
/// `analytics::detection_counts::per_class` counts distinct `(class, value)`
/// pairs, so a span carrying two classes contributes one to each, while
/// `vault::apply_redaction` walks the spans in order and SKIPS any whose start
/// is behind its cursor — so the nested detection produces no second
/// placeholder. `tests/leak_report.rs::a_nested_span_is_two_class_detections_\
/// and_one_placeholder` runs all three functions over
/// `Authorization: Bearer <jwt>` and measures 2 against 1.
///
/// The fix is the WORDING, not the counting. Dropping the contained detection
/// would make the old sentence true and would delete a fact: that header
/// genuinely is both a credential header and a JWT, and an auditor asking
/// "did a JWT leave the building" is entitled to the JWT row.
const COUNTING_RULE: &str =
    "An `entities` figure counts CLASS-DETECTIONS, not placeholders: distinct \
     (class, value) pairs of that class. One span may carry MORE THAN ONE \
     class — an `Authorization: Bearer <token>` header genuinely is both a \
     credential header and a JWT, and both detections are kept, because \
     discarding the inner one would delete a fact this report exists to \
     record. Such a span contributes one figure to EACH of its classes while \
     the redacted prompt carries a SINGLE placeholder for it, so the sum of \
     `entities` across `by_class` can EXCEED the number of placeholders, and \
     does on every request containing a nested detection. `entities_detected` \
     is that same sum and inherits the same caveat. The placeholder count is \
     reported separately, as `placeholders`, and is not derivable from these \
     figures — read that section before treating any number here as one. The \
     same VALUE repeated in one request still counts once for its class; the \
     redacted prompt reuses one placeholder token for it, which then appears \
     at each occurrence. A `requests` figure counts requests in which the \
     class appeared at least once, so summing `requests` across classes will \
     exceed `requests_with_detections` whenever a request contained more than \
     one class.";

/// Why `placeholders.count` is `null` and will stay null until a migration
/// records it.
///
/// Every claim in this string was executed before it was written:
///
/// * `apply_redaction` keys its placeholder table on `(class, value)` and
///   skips any detection whose span starts behind the cursor, so the token
///   count is a property of the REDACTION, not of the detections
///   (`vault/redaction.rs`).
/// * `detection_class_counts` (migration 008) has columns
///   `entity_class` + `entity_count` and no placeholder column, so
///   `BEARER_TOKEN 1, JWT 1` on one request is byte-for-byte identical
///   whether it was one placeholder or two.
/// * `request_events.redacted_prompt` — the only other stored artifact with
///   placeholders in it — is NOT a substitute, for three independent reasons
///   measured in `pipeline/service.rs`: `redact_last_user_message` redacts
///   only the LAST USER MESSAGE of the request, it runs a SECOND detection
///   pass (its own `detect_content` + sidecar call) rather than reusing the
///   one these counts came from, and `record_prompt(RedactedPrompt::\
///   CoverageLost)` stores NULL whenever ML coverage was lost. Counting
///   tokens in it would answer a different question and silently under-count.
///
/// So the honest answer is a stated gap. The alternative — publishing
/// `entities_detected` under a `placeholders` label — is the defect this
/// section was added to fix, in a new field.
const PLACEHOLDERS_NOT_RECORDED: &str =
    "NOT RECORDED. This report cannot tell you how many placeholders the \
     redacted prompts in this window carried, and reports null rather than a \
     number it cannot support. A placeholder is what the redaction step emits \
     — one token per distinct (class, value) it actually replaced — and that \
     figure exists only while the request that produced it is being served. \
     `detection_class_counts`, the table every figure above is read from, \
     stores one (entity_class, entity_count) row per request and nothing \
     else, so a request whose rows read `BEARER_TOKEN 1, JWT 1` is \
     indistinguishable from one that redacted two separate spans: the same \
     two rows describe one placeholder or two. The one other stored artifact \
     that contains placeholders, `request_events.redacted_prompt`, does not \
     answer it either — it holds only the LAST USER MESSAGE of the request, \
     it is produced by a SECOND detection pass rather than the one these \
     counts came from, and it is NULL whenever ML coverage was lost — so \
     counting tokens in it would answer a different question and under-count \
     silently. Reporting a placeholder count therefore needs a column on \
     `detection_class_counts` written from the redaction the request actually \
     applied. Until that migration exists this field stays null, and no \
     figure in this report may be read as a placeholder count.";

// ── Query parameters ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct WindowParams {
    pub from: NaiveDate,
    pub to: NaiveDate,
}

// ── DTOs ──────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct Window {
    pub from: NaiveDate,
    pub to: NaiveDate,
    pub interpretation: &'static str,
}

#[derive(Debug, Serialize)]
pub struct Totals {
    /// Every request this workspace made in the window, detections or not.
    /// The DENOMINATOR — "N of M requests carried something we would have had
    /// to redact" is the shape of the pilot story, and a numerator alone can
    /// be read as either alarming or trivial.
    ///
    /// Read from `request_events`, the only place a request with NO detections
    /// is recorded at all.
    pub requests_in_window: u64,
    pub requests_with_detections: u64,
    pub entities_detected: u64,
    pub distinct_classes: u64,
}

#[derive(Debug, Serialize)]
pub struct ClassCount {
    pub entity_class: String,
    pub entities: u64,
    pub requests: u64,
}

#[derive(Debug, Serialize)]
pub struct ModelBreakdown {
    /// The public model name the caller asked for — the DESTINATION this
    /// content would have gone to.
    pub model: String,
    pub entities: u64,
    pub requests: u64,
    pub by_class: Vec<ClassCount>,
}

#[derive(Debug, Serialize)]
pub struct ActorBreakdown {
    /// `api_keys.assigned_user_id`. `null` for a workspace-scoped key that was
    /// never assigned to a member — reported as null rather than folded into
    /// an "unknown" bucket, so the distinction stays visible.
    pub user_id: Option<Uuid>,
    pub api_key_name: Option<String>,
    pub entities: u64,
    pub requests: u64,
    pub by_class: Vec<ClassCount>,
}

/// The placeholder count, reported as the gap it is.
///
/// Shaped like `data_inventory`'s `row_count` / `row_count_status` /
/// `row_count_detail` triple on purpose: that endpoint already established
/// that a compliance document degrades into a STATED gap rather than a
/// fabricated zero, and a reader who knows one reads the other.
#[derive(Debug, Serialize)]
pub struct Placeholders {
    /// Always `null` today. Present rather than omitted, so its absence is
    /// never read as a count of zero — the same reason
    /// `data_inventory::UnenumerableClass::row_count` is present and null.
    pub count: Option<u64>,
    /// `not_recorded`. There is no other value: no code path on this route can
    /// produce a placeholder count. See [`PLACEHOLDERS_NOT_RECORDED`].
    pub status: &'static str,
    pub detail: &'static str,
}

#[derive(Debug, Serialize)]
pub struct AvailableDimension {
    pub dimension: &'static str,
    pub source: &'static str,
    pub caveat: &'static str,
}

#[derive(Debug, Serialize)]
pub struct UnavailableDimension {
    pub dimension: &'static str,
    pub reason: &'static str,
}

#[derive(Debug, Serialize)]
pub struct Attribution {
    pub available: Vec<AvailableDimension>,
    pub unavailable: Vec<UnavailableDimension>,
}

#[derive(Debug, Serialize)]
pub struct LeakReportResponse {
    pub schema_version: u32,
    pub workspace_id: Uuid,
    pub generated_at: DateTime<Utc>,
    pub window: Window,
    pub totals: Totals,
    /// Which product surfaces these numbers cover. See [`COVERAGE`].
    pub coverage: &'static str,
    pub counting_rule: &'static str,
    /// The number of placeholders, which this report does NOT know. See
    /// [`Placeholders`].
    pub placeholders: Placeholders,
    pub by_class: Vec<ClassCount>,
    pub by_model: Vec<ModelBreakdown>,
    pub by_actor: Vec<ActorBreakdown>,
    pub attribution: Attribution,
    /// `locale -> entity_class -> label`, covering exactly the classes present
    /// in `by_class`. See [`super::leak_report_labels`] for why the labels are
    /// data rather than a formatting layer.
    pub labels: BTreeMap<&'static str, BTreeMap<String, &'static str>>,
    pub content_policy: &'static str,
}

// ── Router ────────────────────────────────────────────────────────────────

pub fn routes() -> Router<AppState> {
    Router::new().route("/", get(get_leak_report))
}

// ── ClickHouse rows ───────────────────────────────────────────────────────

#[derive(Row, Deserialize)]
struct TotalsRow {
    entities: u64,
    requests: u64,
    classes: u64,
}

#[derive(Row, Deserialize)]
struct ClassRow {
    entity_class: String,
    entities: u64,
    requests: u64,
}

#[derive(Row, Deserialize)]
struct ModelClassRow {
    model: String,
    entity_class: String,
    entities: u64,
    requests: u64,
}

#[derive(Row, Deserialize)]
struct ActorClassRow {
    #[serde(with = "clickhouse::serde::uuid::option")]
    user_id: Option<Uuid>,
    api_key_name: Option<String>,
    entity_class: String,
    entities: u64,
    requests: u64,
}

/// The tenancy + window predicate, shared by every query in this module.
///
/// Written once and interpolated into each statement rather than repeated,
/// because Global Constraint 3 and this branch's own history say a filter that
/// exists on some queries and not others is how a cross-tenant leak ships:
/// `cost-by-model` had a handler guard over two unfiltered queries. Every read
/// here goes through this string, so a new breakdown cannot be added without
/// it.
///
/// The parameters are bound (`?`), not formatted, so nothing about the caller
/// reaches the SQL text.
///
/// The two instants are bound as UNIX SECONDS through `toDateTime`, not as
/// `DateTime<Utc>`. The `clickhouse` crate binds a chrono datetime as RFC 3339
/// (`2026-07-29T00:00:00Z`), and ClickHouse refuses to cast that to `DateTime`:
///
/// ```text
/// Code: 53. DB::Exception: Cannot convert string '2026-07-29T00:00:00Z'
/// to type DateTime. (TYPE_MISMATCH)
/// ```
///
/// An integer second count has no format to disagree about. Every caller binds
/// `(workspace, start.timestamp(), end.timestamp())` in that order.
const SCOPE: &str =
    "workspace_id = ? AND created_at >= toDateTime(?) AND created_at < toDateTime(?)";

/// Turn the inclusive `to` DATE into the exclusive upper bound the queries use.
///
/// `to + 1 day` at midnight, so a request at 23:59 on the last day of the
/// window is inside it. An inclusive `<= to` against a `DateTime` column would
/// silently drop almost the entire final day — the kind of off-by-one that
/// makes a pilot look quieter than it was.
fn bounds(from: NaiveDate, to: NaiveDate) -> Result<(DateTime<Utc>, DateTime<Utc>), ApiError> {
    let start = from
        .and_hms_opt(0, 0, 0)
        .ok_or_else(|| ApiError::BadRequest("invalid 'from' date".into()))?
        .and_utc();
    let end = to
        .succ_opt()
        .ok_or_else(|| ApiError::BadRequest("invalid 'to' date".into()))?
        .and_hms_opt(0, 0, 0)
        .ok_or_else(|| ApiError::BadRequest("invalid 'to' date".into()))?
        .and_utc();
    Ok((start, end))
}

/// `from <= to`, and the span within the cap.
///
/// `BadRequest`, not `Forbidden`: the analytics endpoints answer a bad date
/// range with 403, which tells an operator their token is wrong when their
/// query is. Same class of error, honest status code.
fn validate_window(from: NaiveDate, to: NaiveDate) -> Result<(), ApiError> {
    if to < from {
        return Err(ApiError::BadRequest(
            "invalid window: 'to' must be on or after 'from'".into(),
        ));
    }
    let span = (to - from).num_days();
    if span > MAX_WINDOW_DAYS {
        return Err(ApiError::BadRequest(format!(
            "window too large: {span} days (max {MAX_WINDOW_DAYS})"
        )));
    }
    Ok(())
}

/// Map a `ClickHouse` failure to an `ApiError` WITHOUT echoing the query OR
/// the store's own message.
///
/// This path had no test and it interpolated `{e}` — `clickhouse::error::Error`
/// carries the server's message verbatim, and a ClickHouse exception routinely
/// quotes the bytes it choked on (parse errors, type mismatches, constraint
/// violations all echo the offending value). The justification written here was
/// that the message "cannot contain customer data: every query in this module
/// selects `count`/`sum` aggregates over class names and never a payload
/// column". That is a statement about the SELECT list and the exception is not
/// bounded by it — so the module whose one rule is "no detected value, not even
/// quoted back in an error message" had exactly one path that could.
///
/// The operator keeps what they can act on: WHICH table failed, and why no
/// partial report is returned. The store's message goes to the log, where it is
/// already subject to the deployment's log handling rather than being handed to
/// an HTTP caller.
///
/// The model names an ADMINISTRATOR registered for this workspace, read at
/// render time.
///
/// # Why the report reads this at all
///
/// 912cd5e bounded `model` at the WRITE path and shipped no backfill, and
/// `detection_class_counts` has a 90-DAY TTL. So for ninety days after that
/// upgrade, every deployment holds rows whose `model` is whatever bytes an
/// API-key holder chose, and `by_model` rendered them underneath a
/// [`CONTENT_POLICY`] asserting the opposite — measured, from rows inserted the
/// way pre-upgrade rows sit on disk:
///
/// ```text
/// "model":"Anvar Karimov 30107030010011 anvar.karimov@example.uz"
/// "model":"Bekzod Toshmatov +998 90 123 45 67"
/// ```
///
/// # Why not a migration
///
/// A ClickHouse `ALTER TABLE ... UPDATE` was the first candidate and cannot do
/// the job, for a reason that is not about mutations being asynchronous:
/// registration is a POSTGRES fact, per workspace, and ClickHouse cannot see
/// it. A migration could therefore only either (a) apply a charset/length
/// heuristic — which 912cd5e already rejected, because any bound loose enough
/// to pass `gpt-4o-mini` also passes `4111111111111111` — or (b) rewrite EVERY
/// historical row to the bucket, destroying ninety days of legitimate
/// destination breakdown to fix a subset of it. Both are worse than the defect.
///
/// Reading the catalogue at render time evaluates the ACTUAL rule, covers every
/// row already on disk with no window at all, leaves the stored rows untouched
/// for anyone re-reading them, and defends the write path a second time.
///
/// # What it costs
///
/// The claim becomes "a name in this workspace's catalogue AS IT IS NOW". A
/// model an admin has since DELETED renders as `unregistered` in a report over
/// a window when it was registered. That is a real change in meaning and it is
/// stated in [`CONTENT_POLICY`]; it is also the more checkable claim, because a
/// reader can compare the report against the catalogue in front of them.
///
/// # RLS
///
/// `models` carries FORCE ROW LEVEL SECURITY keyed on
/// `app.current_workspace_id`. With that GUC unset the predicate is NULL for
/// every row and this returns the EMPTY SET, which would collapse every
/// destination into the bucket and silently delete the breakdown from a
/// compliance report. It looks fine today only because the compose role is a
/// superuser. So the read runs inside a transaction that sets the GUC first —
/// the same pattern, and for the same measured reason, as
/// `data_inventory::postgres_counts`. The `WHERE` clause is still the filter;
/// RLS is defence in depth (Global Constraint 3).
async fn registered_models(pool: &sqlx::PgPool, ws: Uuid) -> Result<BTreeSet<String>, ApiError> {
    let mut tx = pool.begin().await.map_err(|e| pg_err("begin", &e))?;
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
        .bind(ws.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|e| pg_err("set_config", &e))?;
    let names: Vec<String> = sqlx::query_scalar("SELECT name FROM models WHERE workspace_id = $1")
        .bind(ws)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| pg_err("models", &e))?;
    tx.commit().await.map_err(|e| pg_err("commit", &e))?;
    Ok(names.into_iter().collect())
}

/// The destination name this report may print for a stored `model`.
///
/// Same rule as `analytics::detection_counts::canonicalize_model`, evaluated
/// against the catalogue instead of against `ResolvedModel::is_registered` —
/// because a stored row carries no resolution, only the string.
///
/// [`UNREGISTERED_MODEL`] passes through: it is the bucket the write path
/// already collapsed uncatalogued destinations into, and it is a literal in
/// this binary rather than something a caller chose.
fn bound_model(stored: String, registered: &BTreeSet<String>) -> String {
    if stored == UNREGISTERED_MODEL || registered.contains(&stored) {
        stored
    } else {
        UNREGISTERED_MODEL.to_owned()
    }
}

/// Map a Postgres failure WITHOUT echoing its message.
///
/// `ApiError::Database(msg)` renders `msg` into the response body (see
/// `http::api_error_response`), and a Postgres error quotes column values in
/// constraint and cast failures. Same rule as [`ch_err`], same reason.
///
/// The report is REFUSED rather than rendered with an empty catalogue: an
/// unreadable `models` table means the destination rule cannot be evaluated,
/// and collapsing every model into the bucket would silently delete the
/// breakdown from a compliance document.
fn pg_err(what: &str, e: &sqlx::Error) -> ApiError {
    tracing::error!(
        stage = what,
        error = %e,
        "leak report could not read the model catalogue; the store's message is \
         logged here and deliberately NOT returned to the caller"
    );
    ApiError::Internal(
        "leak report could not be produced: this workspace's model catalogue \
         could not be read, so `by_model` cannot be bounded to registered \
         names. The store's own error message is in the gateway log, not in \
         this response. No partial report is returned."
            .to_owned(),
    )
}

/// A missing table is NOT converted to an empty result — the analytics
/// endpoints do that for the dbt marts, and here it would render a gateway
/// whose migrations never ran as "nothing leaked".
fn ch_err(table: &str, e: &clickhouse::error::Error) -> ApiError {
    tracing::error!(
        table,
        error = %e,
        "leak report query failed; the store's message is logged here and \
         deliberately NOT returned to the caller"
    );
    ApiError::Internal(format!(
        "leak report could not be produced: reading {table} failed. The \
         store's own error message is in the gateway log, not in this \
         response, because a database exception can quote the row that \
         provoked it. No partial report is returned, because an incomplete \
         leak report is indistinguishable from a clean one."
    ))
}

// ── Handler ───────────────────────────────────────────────────────────────

/// `GET /v1/leak-report?from=YYYY-MM-DD&to=YYYY-MM-DD`
///
/// ADMIN, and the reason is `by_actor`. This used to say "any authenticated
/// role — the payload carries no content and no credential material, and the
/// people who most need to read a pilot's leak report are rarely the ones
/// holding an admin token." The first half is true and the conclusion does not
/// follow: the payload carries no *detected* content, but `by_actor` is a
/// per-person submission profile — which named API key, attributed to which
/// named user, sent how many entities of which class to which destination. A
/// `viewer` could read the disclosure history of every colleague in the
/// workspace. The audience argument is real and is answered by granting the
/// reader admin, not by leaving the route open.
///
/// `UserRole::Admin` matches every other dashboard route that exposes or
/// changes workspace-wide state (`users.rs`, `keys.rs`, `secure_mode.rs`,
/// `license.rs`) and the `role_required: "admin"` `GET /v1/data-inventory`
/// already advertises for the raw-capture control.
///
/// There is NO `workspace_id` parameter. The workspace comes from the verified
/// JWT and is bound into every query, so there is no guard to bypass and no
/// unfiltered query to fall through to. The role check is therefore a check on
/// WHO may read this workspace's report, never the thing keeping tenants
/// apart — Global Constraint 3.
async fn get_leak_report(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Query(params): Query<WindowParams>,
) -> Result<Json<LeakReportResponse>, axum::response::Response> {
    require_role(&ctx, UserRole::Admin).map_err(api_error_response)?;
    let ws = ctx.workspace_id.0;
    validate_window(params.from, params.to).map_err(api_error_response)?;
    let (start, end) = bounds(params.from, params.to).map_err(api_error_response)?;
    let ch = state.dashboard_reader.client();

    // ── totals ────────────────────────────────────────────────────────────
    let totals: TotalsRow = ch
        .query(&format!(
            "SELECT sum(entity_count) AS entities, \
                    uniqExact(request_id) AS requests, \
                    uniqExact(entity_class) AS classes \
             FROM detection_class_counts WHERE {SCOPE}"
        ))
        .bind(ws)
        .bind(start.timestamp())
        .bind(end.timestamp())
        .fetch_one()
        .await
        .map_err(|e| api_error_response(ch_err("detection_class_counts", &e)))?;

    // The denominator. `request_events` is the only table that records a
    // request which detected NOTHING, so it cannot come from the counts table.
    let requests_in_window: u64 = ch
        .query(&format!(
            "SELECT uniqExact(request_id) FROM request_events WHERE {SCOPE}"
        ))
        .bind(ws)
        .bind(start.timestamp())
        .bind(end.timestamp())
        .fetch_one()
        .await
        .map_err(|e| api_error_response(ch_err("request_events", &e)))?;

    // ── by class ──────────────────────────────────────────────────────────
    let class_rows: Vec<ClassRow> = ch
        .query(&format!(
            "SELECT entity_class, sum(entity_count) AS entities, \
                    uniqExact(request_id) AS requests \
             FROM detection_class_counts WHERE {SCOPE} \
             GROUP BY entity_class ORDER BY entity_class"
        ))
        .bind(ws)
        .bind(start.timestamp())
        .bind(end.timestamp())
        .fetch_all()
        .await
        .map_err(|e| api_error_response(ch_err("detection_class_counts", &e)))?;

    // ── by destination model ──────────────────────────────────────────────
    let model_rows: Vec<ModelClassRow> = ch
        .query(&format!(
            "SELECT model, entity_class, sum(entity_count) AS entities, \
                    uniqExact(request_id) AS requests \
             FROM detection_class_counts WHERE {SCOPE} \
             GROUP BY model, entity_class ORDER BY model, entity_class"
        ))
        .bind(ws)
        .bind(start.timestamp())
        .bind(end.timestamp())
        .fetch_all()
        .await
        .map_err(|e| api_error_response(ch_err("detection_class_counts", &e)))?;

    // ── by actor ──────────────────────────────────────────────────────────
    let actor_rows: Vec<ActorClassRow> = ch
        .query(&format!(
            "SELECT user_id, api_key_name, entity_class, \
                    sum(entity_count) AS entities, uniqExact(request_id) AS requests \
             FROM detection_class_counts WHERE {SCOPE} \
             GROUP BY user_id, api_key_name, entity_class \
             ORDER BY api_key_name, user_id, entity_class"
        ))
        .bind(ws)
        .bind(start.timestamp())
        .bind(end.timestamp())
        .fetch_all()
        .await
        .map_err(|e| api_error_response(ch_err("detection_class_counts", &e)))?;

    // ── fold the two-level breakdowns ─────────────────────────────────────
    //
    // The per-group `requests` figure is taken from a `uniqExact` computed IN
    // THE DATABASE at that grain, never by summing the class-level numbers: a
    // request carrying two classes appears in both, so a sum would double
    // count it and report more leaking requests than the workspace made.
    let by_class: Vec<ClassCount> = class_rows
        .into_iter()
        .map(|r| ClassCount {
            entity_class: r.entity_class,
            entities: r.entities,
            requests: r.requests,
        })
        .collect();

    // Every stored `model` goes through `bound_model` on the way out, so rows
    // written before the WRITE path bounded the column — the table's whole
    // 90-day TTL of them — cannot render caller-chosen bytes. See
    // [`registered_models`] for why this is a read-path guard and not a
    // migration.
    //
    // Two destinations can now collapse into one bucket, so both levels are
    // ACCUMULATED rather than pushed. Summing is exact, not an approximation:
    // `model` is denormalised onto the counts rows from the request that
    // produced them, so every row sharing a `request_id` carries the same
    // model, and the request sets of two distinct model values are disjoint.
    // The per-CLASS figures are still never summed to make a model total —
    // a request carrying two classes appears in both, and
    // `a_model_name_stored_before_the_bound_is_never_rendered` asserts the
    // bucket reports 2 requests and not 3 for exactly that case.
    let registered = registered_models(&state.db, ws)
        .await
        .map_err(api_error_response)?;

    let mut models: BTreeMap<String, BTreeMap<String, (u64, u64)>> = BTreeMap::new();
    for row in model_rows {
        let class = models
            .entry(bound_model(row.model, &registered))
            .or_default()
            .entry(row.entity_class)
            .or_insert((0, 0));
        class.0 += row.entities;
        class.1 += row.requests;
    }
    let mut model_totals: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for (stored, (entities, requests)) in group_totals(
        ch,
        "model",
        "SELECT model AS grp, sum(entity_count) AS entities, \
         uniqExact(request_id) AS requests",
        "GROUP BY model ORDER BY model",
        ws,
        start,
        end,
    )
    .await
    .map_err(api_error_response)?
    {
        let total = model_totals
            .entry(bound_model(stored, &registered))
            .or_insert((0, 0));
        total.0 += entities;
        total.1 += requests;
    }
    let by_model: Vec<ModelBreakdown> = models
        .into_iter()
        .map(|(model, classes)| {
            let (entities, requests) = model_totals.get(&model).copied().unwrap_or((0, 0));
            ModelBreakdown {
                model,
                entities,
                requests,
                by_class: classes
                    .into_iter()
                    .map(|(entity_class, (entities, requests))| ClassCount {
                        entity_class,
                        entities,
                        requests,
                    })
                    .collect(),
            }
        })
        .collect();

    // Actors are keyed by the PAIR: a key can be reassigned to a different
    // member, and both periods are real traffic that must not be merged.
    let mut actors: BTreeMap<(Option<String>, Option<Uuid>), Vec<ClassCount>> = BTreeMap::new();
    for row in actor_rows {
        actors
            .entry((row.api_key_name, row.user_id))
            .or_default()
            .push(ClassCount {
                entity_class: row.entity_class,
                entities: row.entities,
                requests: row.requests,
            });
    }
    let actor_totals: Vec<ActorTotalsRow> = ch
        .query(&format!(
            "SELECT user_id, api_key_name, sum(entity_count) AS entities, \
                    uniqExact(request_id) AS requests \
             FROM detection_class_counts WHERE {SCOPE} \
             GROUP BY user_id, api_key_name"
        ))
        .bind(ws)
        .bind(start.timestamp())
        .bind(end.timestamp())
        .fetch_all()
        .await
        .map_err(|e| api_error_response(ch_err("detection_class_counts", &e)))?;
    let actor_index: BTreeMap<(Option<String>, Option<Uuid>), (u64, u64)> = actor_totals
        .into_iter()
        .map(|r| ((r.api_key_name, r.user_id), (r.entities, r.requests)))
        .collect();
    let by_actor: Vec<ActorBreakdown> = actors
        .into_iter()
        .map(|((api_key_name, user_id), by_class)| {
            let (entities, requests) = actor_index
                .get(&(api_key_name.clone(), user_id))
                .copied()
                .unwrap_or((0, 0));
            ActorBreakdown {
                user_id,
                api_key_name,
                entities,
                requests,
                by_class,
            }
        })
        .collect();

    // ── labels for exactly the classes present ────────────────────────────
    let mut labels: BTreeMap<&'static str, BTreeMap<String, &'static str>> = BTreeMap::new();
    for class in by_class.iter().map(|c| &c.entity_class) {
        if let Some((ru, uz)) = leak_report_labels::lookup(class) {
            labels.entry("ru").or_default().insert(class.clone(), ru);
            labels.entry("uz").or_default().insert(class.clone(), uz);
        }
    }

    Ok(Json(LeakReportResponse {
        schema_version: SCHEMA_VERSION,
        workspace_id: ws,
        generated_at: Utc::now(),
        window: Window {
            from: params.from,
            to: params.to,
            interpretation: WINDOW_INTERPRETATION,
        },
        totals: Totals {
            requests_in_window,
            requests_with_detections: totals.requests,
            entities_detected: totals.entities,
            distinct_classes: totals.classes,
        },
        coverage: COVERAGE,
        counting_rule: COUNTING_RULE,
        placeholders: Placeholders {
            count: None,
            status: "not_recorded",
            detail: PLACEHOLDERS_NOT_RECORDED,
        },
        by_class,
        by_model,
        by_actor,
        attribution: attribution(),
        labels,
        content_policy: CONTENT_POLICY,
    }))
}

#[derive(Row, Deserialize)]
struct GroupTotalsRow {
    grp: String,
    entities: u64,
    requests: u64,
}

#[derive(Row, Deserialize)]
struct ActorTotalsRow {
    #[serde(with = "clickhouse::serde::uuid::option")]
    user_id: Option<Uuid>,
    api_key_name: Option<String>,
    entities: u64,
    requests: u64,
}

/// Group-level totals for a single-column grouping, computed in the database.
async fn group_totals(
    ch: &clickhouse::Client,
    table_label: &str,
    select: &str,
    group_by: &str,
    ws: Uuid,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<BTreeMap<String, (u64, u64)>, ApiError> {
    let rows: Vec<GroupTotalsRow> = ch
        .query(&format!(
            "{select} FROM detection_class_counts WHERE {SCOPE} {group_by}"
        ))
        .bind(ws)
        .bind(start.timestamp())
        .bind(end.timestamp())
        .fetch_all()
        .await
        .map_err(|e| ch_err(table_label, &e))?;
    Ok(rows
        .into_iter()
        .map(|r| (r.grp, (r.entities, r.requests)))
        .collect())
}

/// What this report can and cannot attribute traffic to.
///
/// Emitted in the payload, not just documented, so an auditor holding an
/// archived report knows which dimensions were unavailable at the time it was
/// produced.
fn attribution() -> Attribution {
    Attribution {
        available: vec![
            AvailableDimension {
                dimension: "model",
                source: "the `model` recorded on every counts row, matched against \
                         this workspace's `models` catalogue when the report is \
                         rendered",
                caveat: "The model the CALLER asked for, but only when that name is in \
                         this workspace's catalogue at the moment the report is \
                         produced. A request naming an uncatalogued model is served \
                         anyway (the gateway passes the name through to the provider) \
                         and is reported under the single bucket `unregistered`, \
                         because the name is then caller-supplied free text and this \
                         report must not render those bytes. Two things follow from \
                         the match happening at RENDER time: a model deleted from the \
                         catalogue since the window drops into `unregistered` too, and \
                         a row written before the gateway bounded the column at write \
                         time is reported safely here while still holding the \
                         requested name on disk. A pilot that wants passthrough \
                         traffic broken down by destination must catalogue the models \
                         first. Separately: when provider fallback redirected a \
                         request, the model that actually served it can differ; the \
                         destination that mattered for disclosure is the provider, and \
                         this report groups by the requested name.",
            },
            AvailableDimension {
                dimension: "user_id",
                source: "api_keys.assigned_user_id",
                caveat: "NULL for a workspace-scoped API key that was never \
                         assigned to a member. Those rows are grouped under a null \
                         user rather than dropped or merged into another actor.",
            },
            AvailableDimension {
                dimension: "api_key_name",
                source: "api_keys.name",
                caveat: "Operator-chosen free text, not an identity. Two keys may \
                         share a name and a key may be renamed, in which case \
                         traffic before and after the rename appears as two actors.",
            },
        ],
        unavailable: vec![
            UnavailableDimension {
                dimension: "department",
                reason: "SecurePrompt has no department concept. There is no department \
                     column on `users` or `api_keys`, no departments table, and no \
                     field on the analytics schema that carries one — so any figure \
                     under this heading would be invented, and this report is read \
                     as evidence. Closing it is a PRODUCT decision with a migration \
                     behind it: department could live as a column on `users`, as a \
                     workspace-level mapping from API keys to cost centres, or as a \
                     sync from an external directory, and those three answer \
                     different questions about contractors, shared keys and \
                     reorganisations. Until one is chosen, group by `api_key_name` \
                     — pilots that need departmental reporting today typically \
                     issue one key per department, and that grouping IS supported.",
            },
            UnavailableDimension {
                dimension: "provider",
                reason: "`request_events` records the provider, but the counts table does \
                     not, and joining the two would let a lost analytics row drop \
                     whole classes out of this report. Add it to migration 008's \
                     denormalised columns if a pilot needs per-provider figures.",
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_bounds_include_the_whole_final_day() {
        let from = NaiveDate::from_ymd_opt(2026, 7, 1).expect("valid date");
        let to = NaiveDate::from_ymd_opt(2026, 7, 27).expect("valid date");
        let (start, end) = bounds(from, to).expect("valid bounds");
        assert_eq!(start.to_rfc3339(), "2026-07-01T00:00:00+00:00");
        assert_eq!(
            end.to_rfc3339(),
            "2026-07-28T00:00:00+00:00",
            "the exclusive upper bound must be `to` + 1 day, or a request at \
             23:59 on the last day of a pilot is invisible"
        );
    }

    #[test]
    fn a_single_day_window_is_a_whole_day() {
        let d = NaiveDate::from_ymd_opt(2026, 7, 27).expect("valid date");
        let (start, end) = bounds(d, d).expect("valid bounds");
        assert_eq!((end - start).num_hours(), 24);
    }

    #[test]
    fn reversed_and_oversized_windows_are_rejected() {
        let from = NaiveDate::from_ymd_opt(2026, 7, 27).expect("valid date");
        let to = NaiveDate::from_ymd_opt(2026, 7, 1).expect("valid date");
        assert!(matches!(
            validate_window(from, to),
            Err(ApiError::BadRequest(_))
        ));
        let huge_to = NaiveDate::from_ymd_opt(2028, 1, 1).expect("valid date");
        assert!(matches!(
            validate_window(from, huge_to),
            Err(ApiError::BadRequest(_))
        ));
        // Positive control: the boundary itself is accepted, so the two
        // assertions above are not passing for a function that rejects
        // everything.
        assert!(validate_window(from, from).is_ok());
        let exactly_max = from + chrono::Duration::days(MAX_WINDOW_DAYS);
        assert!(validate_window(from, exactly_max).is_ok());
    }

    /// Every read in this module must carry the tenancy predicate. The
    /// constant is the mechanism; this pins that it is what it claims to be.
    #[test]
    fn the_shared_scope_binds_the_workspace() {
        assert!(
            SCOPE.starts_with("workspace_id = ?"),
            "SCOPE must bind the workspace as its FIRST predicate: {SCOPE}"
        );
        assert_eq!(
            SCOPE.matches('?').count(),
            3,
            "SCOPE must bind exactly three parameters (workspace, start, end) \
             — every caller binds three in that order: {SCOPE}"
        );
        assert_eq!(
            SCOPE.matches("toDateTime(?)").count(),
            2,
            "both instants must go through toDateTime: a chrono datetime bound \
             directly serialises as RFC 3339 and ClickHouse rejects it with \
             TYPE_MISMATCH, which surfaced as a 500 on every report: {SCOPE}"
        );
    }

    /// The gap declaration is load-bearing product documentation, so it must
    /// actually say something.
    #[test]
    fn department_is_declared_unavailable_with_a_real_reason() {
        let a = attribution();
        let dept = a
            .unavailable
            .iter()
            .find(|d| d.dimension == "department")
            .expect("department must be declared unavailable");
        assert!(dept.reason.len() > 200, "the reason must be actionable");
        assert!(
            !a.available.iter().any(|d| d.dimension == "department"),
            "department must not appear as available"
        );
        assert!(
            a.available.iter().any(|d| d.dimension == "api_key_name"),
            "positive control: the dimensions that DO exist must be listed"
        );
    }
}
