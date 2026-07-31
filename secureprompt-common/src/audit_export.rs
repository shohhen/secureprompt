//! WS4-1 / Task 19 — the `audit.export` control: bytes, digests, signature.
//!
//! This module is the part of the audit export an auditor can check WITHOUT
//! the product. It has no I/O: give it rows, it gives you page bytes, a
//! manifest and a detached Ed25519 signature; give it those three back and it
//! tells you whether they still agree. The ClickHouse read and the Postgres
//! persistence live in `secureprompt-worker::tasks::audit_export`; the HTTP
//! surface lives in `secureprompt-api::http::routes::dashboard::audit_export`.
//! Both call into here so there is exactly one definition of what "signed"
//! means.
//!
//! # What is signed, and why that shape
//!
//! **The signature covers the manifest, and only the manifest.** The manifest
//! carries, for every page, the page's SHA-256 and a running hash CHAIN over
//! those digests in order, seeded from the export's own header.
//!
//! The attack this is aimed at is the one a paginated export invites: **remove
//! a row from the middle**. Three weaker designs were available and each fails
//! a case this one catches.
//!
//! * *Sign each page independently.* A tampered page is caught, but a whole
//!   page can be DROPPED and every surviving page still verifies on its own.
//!   Nothing in the artifact says how many pages there were supposed to be.
//!   `a_whole_page_removed_fails_verification` is that case.
//! * *Sign a manifest listing an unordered set of page digests.* Now page
//!   count is fixed, but pages can be REORDERED — and for an audit trail,
//!   order is meaning. `pages_reordered_fail_verification` is that case.
//! * *Sign the concatenation of all page bytes.* Sound, but it forces the
//!   verifier to hold the entire export in one piece to check anything, which
//!   defeats pagination. It also cannot tell an auditor WHICH page was
//!   altered.
//!
//! The chain gives all three properties at once: count (`total_pages` is
//! signed), order (`chain_i = SHA256(chain_{i-1} ‖ digest_i)`), and locality
//! (a mismatch names the page). The chain's seed — [`genesis`] — binds the
//! export id, workspace, window, format and page size, so a page lifted from a
//! DIFFERENT export of the same shape cannot be spliced in.
//!
//! The signature is **Ed25519, i.e. asymmetric, deliberately**. An HMAC over
//! the same manifest would be equally tamper-evident but only to someone
//! holding the secret — which is the gateway operator, the party the auditor
//! is checking. Ed25519 lets the auditor verify with public material alone.
//!
//! It follows that the public key must reach the auditor **out of band**, and
//! that is why [`verify_export`] takes the key as an argument instead of
//! reading it out of the manifest: an attacker who can rewrite the export can
//! also re-sign it with their own key and ship the matching public key beside
//! it. `an_export_resigned_with_a_different_key_fails_against_the_published_key`
//! is that case. [`key_id`] exists so an auditor holding a pinned key can spot
//! a substitution at a glance instead of diffing 32 bytes.
//!
//! # Two planes, one export, one chain (FU1)
//!
//! Version 1 of this format carried the DATA PLANE only: ClickHouse
//! `request_events`, i.e. what requests happened. An auditor could therefore
//! establish what the gateway's callers did and nothing at all about what its
//! ADMINISTRATORS did — who ended whose session, who switched raw prompt
//! capture on, what a retention purge deleted. For a governance product that is
//! a missing control, not a missing feature; migration 026 disclosed it rather
//! than hiding it.
//!
//! Version 2 carries both. The export is divided into SECTIONS, each a named
//! group of consecutive pages with its own column list, its own coverage
//! statement and its own per-source retention block:
//!
//! | Section | Plane | Store | Source |
//! |---|---|---|---|
//! | [`SECTION_REQUEST_EVENTS`] | `data` | ClickHouse | `request_events` |
//! | [`SECTION_CONTROL_PLANE`] | `control` | Postgres | `raw_capture_audit`, `retention_purge_audit`, `session_revocation_audit` |
//!
//! **Why one export rather than a separate control-plane export type.** The
//! requirement is not only that an auditor can tell WHICH artifact they hold —
//! a second export type would satisfy that with a `plane` field. It is that
//! they can tell nothing was silently omitted. Two artifacts fail that: handed
//! one, an auditor cannot distinguish "the other was never produced" from "the
//! other was withheld", and neither document is evidence about the other. With
//! one artifact the question cannot arise, and [`verify_export`] makes it
//! mechanical: a v2 manifest whose section list is not exactly
//! [`REQUIRED_SECTIONS`] is REJECTED. Dropping the control plane from an export
//! is not a quieter export, it is an export that fails verification.
//!
//! **The chain did not have to change, and did not.** [`genesis`] is
//! byte-identical to v1 and [`chain_step`] is untouched; the chain still runs
//! over page bytes in order across the whole export, so it spans the section
//! boundary and a control-plane page cannot be reordered in front of a
//! data-plane one. Sections are described in the MANIFEST, which the signature
//! already covers in full — so relabelling a page's section, moving the section
//! boundary or deleting a section entry breaks the signature rather than
//! needing a new hash. That is why the two stores did not produce two chains:
//! the chain never knew what a store was. It takes page bytes.
//!
//! # What the export contains
//!
//! METADATA only — see [`REQUEST_COLUMNS`] and [`CONTROL_COLUMNS`].
//! `request_events` also holds `raw_prompt`, `raw_response`, `redacted_prompt`
//! and `restored_response`, and none of them is exported. A compliance artifact
//! that shipped prompt bodies would be a PII export wearing an audit label, and
//! it would be handed to precisely the people who are not supposed to see the
//! content. `the_export_carries_no_content_columns` asserts the absence.
//!
//! The same rule bites once more on the control plane, in a place that is easy
//! to miss. `retention_purge_audit.error` is written as `&e.to_string()` on the
//! ClickHouse error — a store exception, which quotes the statement that
//! provoked it and sometimes the value it choked on. It is NOT exported; the
//! export carries `status` and a boolean [`ControlRow`] `detail.error_present`
//! instead. Copying that column would put a store's own message into a signed,
//! indefinitely-retained artifact, which is the defect this repository has
//! already fixed three times on the response path.
//!
//! # Byte-level rules the digests depend on
//!
//! * Line terminator is **LF**, never CRLF, in both formats.
//! * CSV: the header row is repeated on EVERY page, so a page is a valid CSV
//!   file on its own — and it is inside that page's digest. The header is the
//!   header of that page's SECTION, so the two sections' pages are two
//!   different CSV files, as their differing columns require.
//! * CSV: every non-NULL field is quoted, inner `"` doubled. A NULL is an
//!   unquoted empty field, so `""` (empty string) and NULL stay distinguishable
//!   — an ambiguity a naive writer introduces silently.
//! * The CSV field order and the JSONL key order are BOTH derived from the
//!   section's column list via the row's JSON form, so the two formats cannot
//!   drift from each other or from the documented column list.
//! * `cost_usd` is written with Rust's shortest round-tripping `f64`
//!   formatting, so the exported text reproduces the stored `Float64` exactly
//!   rather than to some rounded number of decimal places.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Bumped when a manifest field changes meaning or disappears. An export is
/// archived and re-verified years later; the verifier has to know which shape
/// it is holding, and refuse one it does not understand rather than silently
/// skipping a check that shape requires.
///
/// **2 (FU1).** The top-level `columns` and `retention` of version 1 moved
/// INSIDE the new `sections` array, because there is now more than one column
/// list and more than one retention story in a single export. A v1 verifier
/// reading a v2 manifest would find neither field where it expects it; a v2
/// verifier reading a v1 manifest would find no `sections` and could not tell
/// a data-plane-only export apart from one whose control plane was stripped.
/// Both must refuse, and [`verify_export`] reads `schema_version` out of the
/// document BEFORE deserializing so it can say `UnsupportedSchemaVersion`
/// rather than the useless `ManifestMalformed`.
pub const SCHEMA_VERSION: u32 = 2;

/// Env var carrying the Ed25519 signing seed. 64 hex characters or base64 of
/// 32 bytes. Never a literal in this repository, and never logged.
pub const SIGNING_KEY_ENV: &str = "SECUREPROMPT_AUDIT_EXPORT_SIGNING_KEY";

/// The ClickHouse relation the DATA-PLANE section's rows come from.
pub const SOURCE_TABLE: &str = "request_events";

/// `request_events` carries `TTL created_at + INTERVAL 90 DAY`
/// (`secureprompt-api/clickhouse/migrations/001_analytics_schema.sql:43`).
/// This is a real boundary, unlike the six dbt marts, which carry no TTL at
/// all — an export must not borrow a retention claim from a table it did not
/// read.
pub const SOURCE_TTL_DAYS: i64 = 90;

/// The three Postgres relations the CONTROL-PLANE section's rows come from,
/// in the order the manifest lists them. None of them has a TTL and none is
/// covered by the `retention.purge` job — see [`no_expiry_for`].
pub const CONTROL_SOURCE_TABLES: &[&str] = &[
    "raw_capture_audit",
    "retention_purge_audit",
    "session_revocation_audit",
];

// ── Sections ──────────────────────────────────────────────────────────────

/// The data-plane section: one row per gateway request.
pub const SECTION_REQUEST_EVENTS: &str = "request_events";
/// The control-plane section: one row per administrative action.
pub const SECTION_CONTROL_PLANE: &str = "control_plane_events";

/// `sections[i].plane` values.
pub const PLANE_DATA: &str = "data";
pub const PLANE_CONTROL: &str = "control";

/// Exactly the sections a schema-version-2 export must contain, in order.
///
/// [`verify_export`] compares a manifest's section list against this and
/// refuses anything else. That is what turns "an auditor can tell nothing was
/// silently omitted" from a promise in a document into a check: an export with
/// the control plane removed does not verify.
pub const REQUIRED_SECTIONS: &[&str] = &[SECTION_REQUEST_EVENTS, SECTION_CONTROL_PLANE];

/// `event_type` values on a [`ControlRow`], one per source table.
pub const EVENT_RAW_CAPTURE_CHANGED: &str = "raw_capture.changed";
pub const EVENT_RETENTION_PURGE: &str = "retention.purge";
pub const EVENT_SESSION_REVOKED: &str = "session.revoked";

/// Domain separator for the chain seed. Prefixed so a digest from this scheme
/// can never be confused with one from another.
///
/// DELIBERATELY still `v1` at schema version 2: it names the CHAIN
/// CONSTRUCTION, which has not changed, not the manifest shape, which has.
/// Renaming it would change every seed for no security gain and would silently
/// invalidate the worked example in `docs/audit-export-format.md`.
const GENESIS_DOMAIN: &str = "secureprompt.audit_export.v1";

// ── Format ────────────────────────────────────────────────────────────────

/// The two serialisations. Both carry the same columns in the same order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// RFC 4180-shaped, LF-terminated, header repeated per page.
    Csv,
    /// One JSON object per line, LF-terminated. No header.
    Jsonl,
}

impl ExportFormat {
    /// Canonical wire/manifest spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Csv => "csv",
            Self::Jsonl => "jsonl",
        }
    }

    /// Parse the wire spelling. `None` for anything else — the caller turns
    /// that into a 400 rather than defaulting, because silently exporting CSV
    /// when the auditor asked for JSONL is a surprise they discover late.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "csv" => Some(Self::Csv),
            "jsonl" => Some(Self::Jsonl),
            _ => None,
        }
    }

    /// `Content-Type` for a page download.
    #[must_use]
    pub const fn content_type(self) -> &'static str {
        match self {
            Self::Csv => "text/csv; charset=utf-8",
            Self::Jsonl => "application/x-ndjson; charset=utf-8",
        }
    }
}

// ── Columns ───────────────────────────────────────────────────────────────

/// One exported column and what it means to an auditor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ColumnDoc {
    pub name: String,
    pub meaning: String,
}

/// The DATA-PLANE columns, in order, with the auditor-facing meaning of each.
///
/// This list is the single source of truth for its section: [`render_page`]
/// projects each row through it for BOTH formats, and it is copied into the
/// manifest so an archived export explains its own columns without `docs/`
/// beside it.
pub const REQUEST_COLUMNS: &[(&str, &str)] = &[
    (
        "request_id",
        "Gateway-assigned identifier for the request. Unique within the workspace; \
         the join key to any other SecurePrompt record about the same request.",
    ),
    (
        "workspace_id",
        "The tenant the request belonged to. Constant across every row of one \
         export — an export is scoped to exactly one workspace.",
    ),
    (
        "created_at",
        "When the gateway recorded the request, RFC 3339 in UTC. This is the \
         column the export window selects on.",
    ),
    (
        "provider",
        "The upstream the request was routed to (e.g. `openai`, `anthropic`, \
         `vertex`).",
    ),
    (
        "model",
        "The model name the caller asked for. Free text chosen by the caller \
         when the model is not in the workspace catalogue.",
    ),
    (
        "final_action",
        "What the gateway did: `allow`, `redact`, `deny`, `block`, or `flag`. \
         This is the disposition an auditor is usually counting.",
    ),
    (
        "input_tokens",
        "Prompt tokens billed. NULL when the provider returned no usage and no \
         estimate was made.",
    ),
    (
        "output_tokens",
        "Completion tokens billed. NULL under the same condition as \
         `input_tokens`.",
    ),
    (
        "estimated_usage",
        "TRUE when the token figures on this row were ESTIMATED by the gateway \
         because the provider returned none. Read cost on such a row as an \
         approximation.",
    ),
    (
        "cost_usd",
        "Cost in USD as the gateway computed it from its pricing table at the \
         time of the request. Written with exact round-tripping decimal \
         formatting, not rounded to cents.",
    ),
    (
        "user_id",
        "The dashboard user the API key was assigned to. NULL for a \
         workspace-scoped key never assigned to a member — reported as NULL \
         rather than folded into an `unknown` bucket.",
    ),
    ("api_key_id", "Which API key authenticated the request."),
    (
        "api_key_name",
        "The administrator-chosen label for that key. FREE TEXT: it is operator \
         attribution metadata and may name a person.",
    ),
    (
        "ip_address",
        "Source address as the gateway saw it. Subject to whatever proxy sits \
         in front of the deployment.",
    ),
    (
        "user_agent",
        "Client-supplied User-Agent header. Caller-controlled and therefore \
         not evidence of anything on its own.",
    ),
    (
        "floor_only",
        "TRUE when detection ran on the deterministic floor alone because the \
         ML sidecar was unavailable. Such a request was screened by a strictly \
         weaker detector.",
    ),
    (
        "engines",
        "Which detection engines contributed to this request, as a JSON array.",
    ),
];

/// The CONTROL-PLANE columns, in order.
///
/// One normalised shape for all three source tables rather than three shapes,
/// because the auditor's question is "who did what, when" across the whole
/// administrative surface — and a single ordered table answers it, where three
/// tables to be joined by hand do not. The per-table specifics live in
/// `detail`, whose keys are documented per `event_type` below.
pub const CONTROL_COLUMNS: &[(&str, &str)] = &[
    (
        "event_id",
        "The source row's own primary key. Stable, so an auditor can point at \
         the exact Postgres row this line came from.",
    ),
    (
        "workspace_id",
        "The tenant the action was performed in. Constant across every row of \
         one export.",
    ),
    (
        "occurred_at",
        "When the action was recorded, RFC 3339 in UTC. This is the column the \
         export window selects on: `created_at` for `raw_capture_audit` and \
         `session_revocation_audit`, `completed_at` for `retention_purge_audit`.",
    ),
    (
        "event_type",
        "`raw_capture.changed` (an administrator changed whether this \
         workspace stores raw prompt/response content, or for how long), \
         `retention.purge` (a scheduled purge run reported what it deleted for \
         this workspace), or `session.revoked` (an administrator terminated a \
         user's sessions).",
    ),
    (
        "source_table",
        "The Postgres relation this row was read from, so the claim is \
         re-derivable against the live database.",
    ),
    (
        "actor_user_id",
        "The dashboard user who performed the action, taken from their \
         authenticated context and never from a request body. NULL for \
         `retention.purge`, which is performed by the scheduler and has no \
         human actor — a NULL here is a FACT about the event, not a missing \
         attribution.",
    ),
    (
        "actor_email",
        "The actor's email as it read AT THE TIME, denormalised on purpose: a \
         foreign key would let deleting a user rewrite the evidence. FREE \
         TEXT, and it names a person.",
    ),
    (
        "actor_role",
        "The actor's role as it read at the time. NULL where the source table \
         does not record one.",
    ),
    (
        "target_user_id",
        "The user the action was performed ON. Populated for \
         `session.revoked` only; equal to the actor on a self-revocation. NULL \
         for events that have no user target.",
    ),
    (
        "target_email",
        "The target's email as it read at the time. FREE TEXT, and it names a \
         person.",
    ),
    ("target_role", "The target's role as it read at the time."),
    (
        "detail",
        "A JSON object of the event-type-specific facts. \
         `raw_capture.changed`: `enabled_before`, `enabled_after`, \
         `retention_days_before`, `retention_days_after`. `retention.purge`: \
         `run_id`, `scope`, `cutoff`, `rows_deleted`, `oldest_deleted`, \
         `newest_deleted`, `rows_remaining_past_cutoff`, `status`, \
         `error_present`, `started_at`. `session.revoked`: \
         `revoked_before_unix` (every access token for the target issued at or \
         before this instant was refused thereafter) and \
         `refresh_tokens_revoked` (how many live sessions the action closed). \
         `retention_purge_audit.error` is reported as the BOOLEAN \
         `error_present` and its text is NOT exported: it is a ClickHouse \
         exception message, which quotes the statement that provoked it and \
         sometimes the value it choked on. Read it in Postgres or the gateway \
         log if a run failed.",
    ),
];

/// What the DATA-PLANE section does and does not cover. Copied into the
/// manifest, in the same spirit as `leak_report::COVERAGE`.
pub const REQUEST_COVERAGE: &str =
    "GATEWAY TRAFFIC ONLY, METADATA ONLY. Every row in this section comes from \
     `request_events`, which is written from the gateway request pipeline — the \
     paths `/v1/chat/completions`, `/v1/completions` and `/v1/embeddings`. \
     Requests to `/v1/redact`, `/v1/secure-mode/tokenize`, the MCP server and \
     file scanning write no `request_events` row at all, so they are ABSENT from \
     this export entirely; their absence is not evidence they did not happen. No \
     prompt or response content is exported: `request_events` also holds \
     `raw_prompt`, `raw_response`, `redacted_prompt` and `restored_response`, and \
     this export carries NONE of them, by construction rather than by \
     configuration.";

/// What the CONTROL-PLANE section does and does not cover.
///
/// The second half is the load-bearing half. Three administrative actions are
/// audited into a dedicated table and therefore exportable; the rest of the
/// administrative surface is not audited AT ALL, and an auditor who reads this
/// section as "every administrative action" would be reading a floor as a
/// ceiling. Listing what is missing is the same rule the data plane follows for
/// `/v1/redact`.
pub const CONTROL_COVERAGE: &str =
    "THREE AUDITED ADMINISTRATIVE ACTIONS ONLY. This section carries every row \
     of `raw_capture_audit` (WS3-1), `retention_purge_audit` (WS3-4) and \
     `session_revocation_audit` (WS4-3) whose instant falls in the window and \
     whose `workspace_id` is this workspace's. It is NOT a complete record of \
     administrative activity, and must not be read as one. The following are \
     NOT audited into any table and therefore appear NOWHERE in this export: \
     creating, revoking or reassigning an API key; adding or changing a \
     provider credential; creating, deleting or re-roling a user; editing a \
     policy rule; changing secure-mode, sidecar-failure or budget settings; \
     enrolling or resetting 2FA; activating a license; and every dashboard \
     login, successful or failed. Their absence here is not evidence they did \
     not happen. Rows of `retention_purge_audit` whose `workspace_id` is NULL — \
     purge scopes that are not per-workspace, such as the token vault — are \
     excluded because they are not this tenant's records; the section's source \
     block reports how many such rows fell in the window so their exclusion is \
     visible rather than silent. `audit_events_meta` is not included either: it \
     is a data-plane pointer from a request id to an event type, and what it \
     points at is already the first section.";

/// What the export as a whole is. Copied into the manifest above the sections.
pub const EXPORT_COVERAGE: &str =
    "TWO PLANES, ONE SIGNED ARTIFACT. Section `request_events` is the DATA \
     PLANE — what requests passed through the gateway. Section \
     `control_plane_events` is the CONTROL PLANE — what administrators did. \
     Each section states its own coverage and its own per-source retention, \
     because they come from different stores with different expiry: \
     `request_events` is ClickHouse with a 90-day TTL, the three control-plane \
     tables are Postgres with no TTL at all, so ONE window can be complete for \
     one section and partially expired for the other. Both sections are always \
     present: a manifest that declares any other set of sections is refused by \
     the verifier, so an export cannot be handed over with the control plane \
     quietly removed. A section with no rows still carries one page, and that \
     is a signed claim that the window was looked at and held nothing — not \
     evidence the section was omitted.";

/// How the window bounds are interpreted. Copied into the manifest.
pub const WINDOW_INTERPRETATION: &str =
    "`from` is INCLUSIVE and `to` is EXCLUSIVE, both instants in UTC: rows are \
     selected by `created_at >= from AND created_at < to`. A half-open window \
     means two consecutive exports abut exactly, with no row counted twice and \
     none dropped between them.";

/// The verification recipe, carried inside the signed manifest so an archived
/// export explains how to check itself.
pub const VERIFICATION_RECIPE: &str =
    "1. Obtain the deployment's audit-export public key OUT OF BAND — not from \
     this export. 2. Verify the Ed25519 signature over the manifest file's \
     EXACT bytes; the manifest is served verbatim as it was signed and must not \
     be reformatted, re-indented or re-serialised before verifying. 3. Refuse \
     any `schema_version` you do not implement; this recipe describes 2. \
     4. For each page file, compute SHA-256 and compare it to \
     `pages[i].sha256`. 5. Check you hold exactly `total_pages` pages. \
     6. Recompute `chain_genesis` = SHA256 of the LF-joined header lines \
     `secureprompt.audit_export.v1`, `export_id`, `workspace_id`, \
     `window.from`, `window.to`, `format`, `page_size`, with a trailing LF. \
     7. Recompute the chain: `chain_0 = SHA256(chain_genesis || sha256_0)` and \
     `chain_i = SHA256(chain_{i-1} || sha256_i)`, all over RAW 32-byte digests, \
     and compare each to `pages[i].chain` and the last to `chain_root`. \
     8. Check `sum(pages[i].rows) == total_rows`. 9. Check `sections` names \
     exactly `request_events` then `control_plane_events`: any other set means \
     part of the export is missing, and an export that omits the control plane \
     must be REFUSED rather than read as a shorter one. 10. Check the sections \
     partition the pages — `sections[0].first_page` is 1, each section's \
     `last_page + 1` is the next section's `first_page`, the last section's \
     `last_page` is `total_pages` — that every `pages[i].section` is the \
     section whose range contains page i+1, and that each section's `rows` is \
     the sum of its own pages' `rows`. 11. Read each section's `sources[]` \
     separately: they have different retention, so one window can be complete \
     for one section and partially expired for the other.";

// ── Rows ──────────────────────────────────────────────────────────────────

/// A row that can be rendered into a page.
///
/// This trait is the ONLY thing the renderer knows about a row, and it exists
/// so the two planes share one renderer, one digest and one chain rather than
/// forking them. `columns` is associated rather than passed in so a row type
/// cannot be rendered against another section's column list.
pub trait ExportRow {
    /// The section's columns, in order, with the meaning of each.
    fn columns() -> &'static [(&'static str, &'static str)];
    /// The row as a JSON object. This IS the JSONL line, and it is also what
    /// the CSV writer projects through `columns()` — one shape, two
    /// renderings, so a column added to one format cannot be missing from the
    /// other.
    fn to_object(&self) -> Map<String, Value>;
}

/// The default `to_object`: serialize the struct and require an object.
///
/// Written as a fallback rather than an `expect` because an audit export must
/// not panic a worker; the row types below are plain structs of serialisable
/// fields, so the `Map::new()` arm is unreachable and
/// `columns_match_the_row_shape` would fail loudly if it ever were not.
fn object_of<T: Serialize>(value: &T) -> Map<String, Value> {
    match serde_json::to_value(value) {
        Ok(Value::Object(map)) => map,
        _ => Map::new(),
    }
}

/// One exported DATA-PLANE row. Metadata only — see the module docs.
///
/// Field order here is the exported column order, and
/// `columns_match_the_row_shape` asserts it against [`REQUEST_COLUMNS`] so the
/// two cannot drift.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditRow {
    pub request_id: Uuid,
    pub workspace_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub provider: String,
    pub model: String,
    pub final_action: String,
    pub input_tokens: Option<u32>,
    pub output_tokens: Option<u32>,
    pub estimated_usage: bool,
    pub cost_usd: f64,
    pub user_id: Option<Uuid>,
    pub api_key_id: Option<Uuid>,
    pub api_key_name: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub floor_only: bool,
    pub engines: Vec<String>,
}

impl ExportRow for AuditRow {
    fn columns() -> &'static [(&'static str, &'static str)] {
        REQUEST_COLUMNS
    }
    fn to_object(&self) -> Map<String, Value> {
        object_of(self)
    }
}

/// One exported CONTROL-PLANE row: one administrative action, normalised
/// across the three source tables.
///
/// The event-type-specific facts live in [`Self::detail`] rather than in a
/// wide union of nullable columns, because a union would make every row mostly
/// NULL and would need a migration to this format every time a fourth
/// administrative action becomes auditable. `detail`'s keys are documented per
/// `event_type` in [`CONTROL_COLUMNS`], and copied into every manifest.
///
/// `detail` holds only bounded values built by the exporter from typed
/// columns. In particular it does NOT carry `retention_purge_audit.error`, a
/// ClickHouse exception message — see the module docs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControlRow {
    pub event_id: Uuid,
    pub workspace_id: Uuid,
    pub occurred_at: DateTime<Utc>,
    pub event_type: String,
    pub source_table: String,
    pub actor_user_id: Option<Uuid>,
    pub actor_email: Option<String>,
    pub actor_role: Option<String>,
    pub target_user_id: Option<Uuid>,
    pub target_email: Option<String>,
    pub target_role: Option<String>,
    pub detail: Value,
}

impl ExportRow for ControlRow {
    fn columns() -> &'static [(&'static str, &'static str)] {
        CONTROL_COLUMNS
    }
    fn to_object(&self) -> Map<String, Value> {
        object_of(self)
    }
}

// ── Rendering ─────────────────────────────────────────────────────────────

/// Quote one CSV field. `None` is a NULL and renders as an unquoted empty
/// field; `Some` always renders quoted, so an empty STRING renders `""` and
/// stays distinguishable from NULL.
fn csv_field(value: Option<&str>) -> String {
    match value {
        None => String::new(),
        Some(s) => format!("\"{}\"", s.replace('"', "\"\"")),
    }
}

/// A JSON scalar as the text CSV should carry, or `None` for JSON null.
fn json_to_csv_text(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => Some(n.to_string()),
        other => Some(other.to_string()),
    }
}

/// Render one page. The returned bytes ARE the unit the digest chain covers —
/// nothing may be appended, re-encoded or re-wrapped between here and the
/// auditor.
///
/// Generic over [`ExportRow`], so both planes go through this one function.
/// The column list comes from the row type, never from an argument, so a page
/// cannot be rendered against a section's columns it does not belong to.
#[must_use]
pub fn render_page<R: ExportRow>(rows: &[R], format: ExportFormat) -> Vec<u8> {
    let columns = R::columns();
    let mut out = String::new();
    match format {
        ExportFormat::Csv => {
            let header: Vec<String> = columns
                .iter()
                .map(|(name, _)| csv_field(Some(name)))
                .collect();
            out.push_str(&header.join(","));
            out.push('\n');
            for row in rows {
                let object = row.to_object();
                let fields: Vec<String> = columns
                    .iter()
                    .map(|(name, _)| {
                        let cell = object.get(*name).unwrap_or(&Value::Null);
                        csv_field(json_to_csv_text(cell).as_deref())
                    })
                    .collect();
                out.push_str(&fields.join(","));
                out.push('\n');
            }
        }
        ExportFormat::Jsonl => {
            for row in rows {
                let object = Value::Object(row.to_object());
                out.push_str(&object.to_string());
                out.push('\n');
            }
        }
    }
    out.into_bytes()
}

// ── Digests and the chain ─────────────────────────────────────────────────

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// An instant spelled EXACTLY as the manifest will carry it.
///
/// This function exists because of a real interoperability bug, caught by
/// executing `docs/audit-export-format.md`'s verifier against a genuine
/// export. [`genesis`] used to hash `DateTime::to_rfc3339()`, which renders UTC
/// as `2026-07-29T12:00:00+00:00`, while the manifest's JSON — chrono's
/// `Serialize` — carries `2026-07-29T12:00:00Z`. Measured, on a real artifact:
///
/// ```text
/// manifest window.from : '2026-07-29T12:00:00Z'
/// chain_genesis        : fdf68ee4...d26e
/// recomputed from the manifest's own text
///                      : 9c5cfb6e...ec42   <- disagreed
/// recomputed with '+00:00'
///                      : fdf68ee4...d26e   <- what the code actually hashed
/// ```
///
/// The chain seed was therefore NOT derivable from the document an auditor
/// holds, which makes independent verification impossible — the single thing
/// this whole module is for. Every Rust-side test passed anyway, because
/// [`verify_export`] recomputed the seed with the same wrong spelling on both
/// sides; a self-consistent scheme is exactly what a signature scheme must not
/// be graded on.
///
/// The fix goes through `serde` rather than picking the matching
/// `SecondsFormat` by hand, so the seed and the manifest cannot drift apart
/// again if chrono's serialization ever changes: both now come from the same
/// serializer.
fn manifest_instant(instant: DateTime<Utc>) -> String {
    serde_json::to_string(&instant).map_or_else(
        |_| instant.to_rfc3339(),
        |quoted| quoted.trim_matches('"').to_owned(),
    )
}

/// The chain seed. Binds the export's identity and window into every
/// subsequent link, so a page from another export cannot be spliced in even
/// when both exports have the same shape.
///
/// Every component is spelled the way the MANIFEST spells it — see
/// [`manifest_instant`] — because the auditor recomputing this has nothing but
/// the manifest to read the values out of.
#[must_use]
pub fn genesis(
    export_id: Uuid,
    workspace_id: Uuid,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    format: ExportFormat,
    page_size: u32,
) -> [u8; 32] {
    let header = format!(
        "{GENESIS_DOMAIN}\n{export_id}\n{workspace_id}\n{}\n{}\n{}\n{page_size}\n",
        manifest_instant(from),
        manifest_instant(to),
        format.as_str(),
    );
    sha256(header.as_bytes())
}

/// One link: `SHA256(prev ‖ digest)` over the RAW 32-byte values, not their
/// hex spellings. Stated in [`VERIFICATION_RECIPE`] because an independent
/// implementation that hashed the hex text would silently disagree.
#[must_use]
pub fn chain_step(prev: &[u8; 32], digest: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(prev);
    buf[32..].copy_from_slice(digest);
    sha256(&buf)
}

fn to_hex(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}

fn from_hex(s: &str) -> Option<[u8; 32]> {
    let raw = hex::decode(s).ok()?;
    let arr: [u8; 32] = raw.try_into().ok()?;
    Some(arr)
}

// ── Manifest ──────────────────────────────────────────────────────────────

/// One page's entry in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PageEntry {
    /// 1-based, so `pages[0].page == 1` and an error naming "page 2" means the
    /// second file.
    pub page: u32,
    /// Which section this page belongs to, so a page file can be interpreted
    /// without inferring its columns from its own header. Cross-checked
    /// against the owning section's page range by [`verify_export`].
    pub section: String,
    pub rows: u32,
    /// Lowercase hex SHA-256 of the page's exact bytes.
    pub sha256: String,
    /// Lowercase hex chain value AFTER folding this page in.
    pub chain: String,
}

/// One section's entry in the manifest: a contiguous run of pages sharing a
/// column list, a coverage statement and a set of source relations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SectionEntry {
    pub section: String,
    /// `data` | `control`.
    pub plane: String,
    pub description: String,
    /// 1-based, inclusive. `first_page == last_page` for a one-page section.
    pub first_page: u32,
    pub last_page: u32,
    pub pages: u32,
    pub rows: u64,
    pub columns: Vec<ColumnDoc>,
    pub coverage: String,
    /// One entry per relation this section was read from, each with its own
    /// retention verdict. See [`SourceRetention`].
    pub sources: Vec<SourceRetention>,
}

/// A section's rendered pages, on the way in to [`build_manifest`].
#[derive(Debug, Clone)]
pub struct SectionInput {
    pub section: &'static str,
    pub plane: &'static str,
    pub description: &'static str,
    pub columns: &'static [(&'static str, &'static str)],
    pub coverage: String,
    pub sources: Vec<SourceRetention>,
    /// The EXACT bytes that will be served. At least one, always: a section
    /// with no pages is indistinguishable from a section that was removed.
    pub pages: Vec<Vec<u8>>,
    pub rows_per_page: Vec<u32>,
}

const SECTION_REQUEST_DESCRIPTION: &str =
    "The DATA PLANE: one row per request the gateway handled for this workspace \
     in this window, read from ClickHouse `request_events`.";

const SECTION_CONTROL_DESCRIPTION: &str =
    "The CONTROL PLANE: one row per audited administrative action in this \
     workspace in this window, read from three Postgres audit tables and \
     normalised into one time-ordered shape.";

/// The data-plane section, with its name, plane, description, columns and
/// coverage fixed.
///
/// A constructor rather than a struct literal at each call site: the section
/// name and the column list have to agree with the row type the pages were
/// rendered from, and a caller assembling that by hand is a caller who can
/// label control-plane pages `request_events`.
#[must_use]
pub fn request_section(
    pages: Vec<Vec<u8>>,
    rows_per_page: Vec<u32>,
    sources: Vec<SourceRetention>,
) -> SectionInput {
    SectionInput {
        section: SECTION_REQUEST_EVENTS,
        plane: PLANE_DATA,
        description: SECTION_REQUEST_DESCRIPTION,
        columns: REQUEST_COLUMNS,
        coverage: REQUEST_COVERAGE.to_string(),
        sources,
        pages,
        rows_per_page,
    }
}

/// The control-plane section. See [`request_section`].
#[must_use]
pub fn control_section(
    pages: Vec<Vec<u8>>,
    rows_per_page: Vec<u32>,
    sources: Vec<SourceRetention>,
) -> SectionInput {
    SectionInput {
        section: SECTION_CONTROL_PLANE,
        plane: PLANE_CONTROL,
        description: SECTION_CONTROL_DESCRIPTION,
        columns: CONTROL_COLUMNS,
        coverage: CONTROL_COVERAGE.to_string(),
        sources,
        pages,
        rows_per_page,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Window {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    pub interpretation: String,
}

/// The retention boundary for ONE source relation, stated rather than papered
/// over.
///
/// An export whose window reaches behind `boundary` cannot be complete, and
/// saying so is the whole difference between an attestation and a short result
/// that looks complete. Same rule `leak_report` follows for `by_model`.
///
/// PER SOURCE, not per export, and that is the point. One window can be
/// `partially_expired` for ClickHouse `request_events` and `no_expiry` for the
/// Postgres control-plane tables at the same instant, because they are
/// different stores with different retention. A single export-level verdict
/// would have to pick one of those and would be a lie about the other half of
/// the artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceRetention {
    pub source_table: String,
    /// `clickhouse` | `postgres`.
    pub store: String,
    /// Which section's rows this relation supplied.
    pub section: String,
    /// `None` when the relation has no TTL at all — an absent expiry, not an
    /// unknown one.
    pub ttl_days: Option<i64>,
    /// `generated_at - ttl_days`. Rows older than this have been deleted by
    /// the store and CANNOT appear in any export. `None` where `ttl_days` is.
    pub boundary: Option<DateTime<Utc>>,
    /// `within_retention` | `partially_expired` | `wholly_expired` |
    /// `no_expiry`.
    pub window_status: String,
    pub detail: String,
    /// Rows this relation held in the window that the export deliberately did
    /// NOT carry, with `excluded_reason` saying why. `0` for every relation
    /// that is exported whole. Present so an exclusion is a number an auditor
    /// can see rather than an absence they cannot.
    pub excluded_rows: u64,
    pub excluded_reason: Option<String>,
}

/// Retention verdicts as machine-readable constants, so a caller branches on
/// a value from this binary rather than on a spelling.
pub const WITHIN_RETENTION: &str = "within_retention";
pub const PARTIALLY_EXPIRED: &str = "partially_expired";
pub const WHOLLY_EXPIRED: &str = "wholly_expired";
/// The relation has no TTL and no purge job. Distinct from
/// `within_retention`, which is a statement about a window falling inside a
/// real boundary that exists.
pub const NO_EXPIRY: &str = "no_expiry";

/// The retention block for a Postgres control-plane audit table.
///
/// These tables are append-only and are covered by NOTHING: no TTL, and the
/// `retention.purge` worker job does not touch them. That is deliberate — an
/// audit trail with a retention window is an audit trail with a deadline — and
/// it is why an auditor must not carry the data plane's 90-day caveat over to
/// this section.
#[must_use]
pub fn no_expiry_for(source_table: &str) -> SourceRetention {
    SourceRetention {
        source_table: source_table.to_string(),
        store: "postgres".to_string(),
        section: SECTION_CONTROL_PLANE.to_string(),
        ttl_days: None,
        boundary: None,
        window_status: NO_EXPIRY.to_string(),
        detail: "NO EXPIRY. This relation is append-only, carries no TTL, and is not \
                 covered by the `retention.purge` job, so no row of it has ever been \
                 removed by the product and the window is complete with respect to \
                 expiry however far back it reaches. Note this is the OPPOSITE of the \
                 data-plane section's position: do not carry `request_events`' 90-day \
                 boundary over to this section, and do not read a short control-plane \
                 section as expiry."
            .to_string(),
        excluded_rows: 0,
        excluded_reason: None,
    }
}

/// Classify the requested window against `request_events`' TTL.
#[must_use]
pub fn retention_for(
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    generated_at: DateTime<Utc>,
) -> SourceRetention {
    let boundary = generated_at - Duration::days(SOURCE_TTL_DAYS);
    let (status, detail) = if to <= boundary {
        (
            WHOLLY_EXPIRED,
            "WHOLLY EXPIRED. Every instant in the requested window is older than \
             the source table's retention boundary, so ClickHouse has already \
             deleted the rows this export would have contained. An empty or \
             short export for this window is EVIDENCE OF EXPIRY, not evidence \
             that no traffic occurred. Do not read this export as a record of a \
             quiet period.",
        )
    } else if from < boundary {
        (
            PARTIALLY_EXPIRED,
            "PARTIALLY EXPIRED. The requested window starts BEFORE the source \
             table's retention boundary, so the earliest part of it has already \
             been deleted by ClickHouse and is absent from this export. The rows \
             present are complete only from the boundary onward; the export \
             cannot distinguish an expired day from a quiet one.",
        )
    } else {
        (
            WITHIN_RETENTION,
            "WITHIN RETENTION. The whole requested window sits inside the source \
             table's retention period as of the moment this export was \
             generated, so no row was withheld by expiry. Note this is a \
             statement about the TTL only.",
        )
    };
    SourceRetention {
        source_table: SOURCE_TABLE.to_string(),
        store: "clickhouse".to_string(),
        section: SECTION_REQUEST_EVENTS.to_string(),
        ttl_days: Some(SOURCE_TTL_DAYS),
        boundary: Some(boundary),
        window_status: status.to_string(),
        detail: detail.to_string(),
        excluded_rows: 0,
        excluded_reason: None,
    }
}

/// Everything the signature covers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Manifest {
    pub schema_version: u32,
    pub export_id: Uuid,
    pub workspace_id: Uuid,
    pub window: Window,
    pub format: String,
    pub page_size: u32,
    pub total_rows: u64,
    pub total_pages: u32,
    pub chain_genesis: String,
    pub chain_root: String,
    /// In page order, partitioning `1..=total_pages` with no gap and no
    /// overlap. Version 2 replaced the single top-level `columns` and
    /// `retention` with this.
    pub sections: Vec<SectionEntry>,
    pub pages: Vec<PageEntry>,
    pub coverage: String,
    /// Fingerprint of the public key this manifest was signed with — see
    /// [`key_id`]. Present so an auditor holding a pinned key can spot a
    /// substitution without comparing 32 bytes; it is NOT a substitute for
    /// obtaining the key out of band.
    pub signing_key_id: String,
    pub generated_at: DateTime<Utc>,
    pub verification: String,
}

/// A produced, signed export. `manifest_json` is the EXACT byte string the
/// signature covers and the exact byte string the API must serve — see
/// [`VERIFICATION_RECIPE`] step 2.
#[derive(Debug, Clone)]
pub struct SignedExport {
    pub manifest_json: String,
    pub signature_b64: String,
    pub public_key_b64: String,
    pub signing_key_id: String,
    pub total_rows: u64,
    pub total_pages: u32,
    /// Lowercase hex SHA-256 per page, index 0 = page 1. Same values as
    /// `manifest.pages[i].sha256`, surfaced so a caller storing pages does not
    /// have to re-parse the manifest to label each one.
    pub page_digests: Vec<String>,
    /// Row count per page, index 0 = page 1. Surfaced for the same reason as
    /// [`Self::page_digests`], and it is the SIGNED figure — a caller that
    /// recounted its own pages could store a number the manifest contradicts.
    pub rows_per_page: Vec<u32>,
}

/// Why a manifest could not be built. Bounded strings only — none of these
/// interpolates a row, a key or a store's message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    /// `pages.len() != rows_per_page.len()`. A caller bug, caught rather than
    /// producing a manifest whose row counts describe different pages.
    PageRowCountMismatch,
    /// A section arrived with no pages. Refused rather than emitted, because a
    /// zero-page section is indistinguishable from one that was dropped —
    /// exactly the ambiguity this format exists to remove. A section with no
    /// ROWS is fine and gets one empty page.
    EmptySection,
    /// The sections offered are not [`REQUIRED_SECTIONS`], in order. Refused
    /// at BUILD time as well as at verify time, so the product cannot sign an
    /// artifact its own verifier would reject.
    SectionSetUnexpected,
    /// `serde_json` could not render the manifest.
    ManifestSerialization,
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::PageRowCountMismatch => "page list and row-count list have different lengths",
            Self::EmptySection => "a section was offered with no pages at all",
            Self::SectionSetUnexpected => {
                "the sections offered are not the ones this schema version requires"
            }
            Self::ManifestSerialization => "manifest could not be serialized",
        };
        f.write_str(text)
    }
}

impl std::error::Error for BuildError {}

/// Build and sign the manifest for an already-rendered set of sections.
///
/// Each section's `pages` must be the EXACT bytes that will be served; the
/// digests are taken over them here and never recomputed from rows again. The
/// chain runs over every page of every section IN ORDER — one chain for the
/// whole export, spanning the section boundary, so a control-plane page cannot
/// be moved in front of a data-plane one.
///
/// # Errors
/// [`BuildError`] — see its variants.
#[allow(clippy::too_many_arguments)]
pub fn build_manifest(
    export_id: Uuid,
    workspace_id: Uuid,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    format: ExportFormat,
    page_size: u32,
    sections: &[SectionInput],
    generated_at: DateTime<Utc>,
    key: &SigningKey,
) -> Result<SignedExport, BuildError> {
    if sections.len() != REQUIRED_SECTIONS.len()
        || !sections
            .iter()
            .zip(REQUIRED_SECTIONS)
            .all(|(offered, required)| offered.section == *required)
    {
        return Err(BuildError::SectionSetUnexpected);
    }
    for input in sections {
        if input.pages.len() != input.rows_per_page.len() {
            return Err(BuildError::PageRowCountMismatch);
        }
        if input.pages.is_empty() {
            return Err(BuildError::EmptySection);
        }
    }

    let seed = genesis(export_id, workspace_id, from, to, format, page_size);
    let mut chain = seed;
    let mut entries: Vec<PageEntry> = Vec::new();
    let mut digests: Vec<String> = Vec::new();
    let mut rows_per_page: Vec<u32> = Vec::new();
    let mut section_entries: Vec<SectionEntry> = Vec::new();
    let mut all_pages: Vec<&Vec<u8>> = Vec::new();
    let mut total_rows: u64 = 0;

    for input in sections {
        let first_page = u32::try_from(entries.len())
            .unwrap_or(u32::MAX)
            .saturating_add(1);
        let mut section_rows: u64 = 0;

        for (index, bytes) in input.pages.iter().enumerate() {
            let digest = sha256(bytes);
            chain = chain_step(&chain, &digest);
            let rows = input.rows_per_page[index];
            total_rows += u64::from(rows);
            section_rows += u64::from(rows);
            digests.push(to_hex(&digest));
            rows_per_page.push(rows);
            all_pages.push(bytes);
            entries.push(PageEntry {
                page: u32::try_from(entries.len())
                    .unwrap_or(u32::MAX)
                    .saturating_add(1),
                section: input.section.to_string(),
                rows,
                sha256: to_hex(&digest),
                chain: to_hex(&chain),
            });
        }

        let last_page = u32::try_from(entries.len()).unwrap_or(u32::MAX);
        section_entries.push(SectionEntry {
            section: input.section.to_string(),
            plane: input.plane.to_string(),
            description: input.description.to_string(),
            first_page,
            last_page,
            pages: last_page.saturating_sub(first_page).saturating_add(1),
            rows: section_rows,
            columns: input
                .columns
                .iter()
                .map(|(name, meaning)| ColumnDoc {
                    name: (*name).to_string(),
                    meaning: (*meaning).to_string(),
                })
                .collect(),
            coverage: input.coverage.clone(),
            sources: input.sources.clone(),
        });
    }

    let verifying = key.verifying_key();
    let manifest = Manifest {
        schema_version: SCHEMA_VERSION,
        export_id,
        workspace_id,
        window: Window {
            from,
            to,
            interpretation: WINDOW_INTERPRETATION.to_string(),
        },
        format: format.as_str().to_string(),
        page_size,
        total_rows,
        total_pages: u32::try_from(all_pages.len()).unwrap_or(u32::MAX),
        chain_genesis: to_hex(&seed),
        chain_root: to_hex(&chain),
        sections: section_entries,
        pages: entries,
        coverage: EXPORT_COVERAGE.to_string(),
        signing_key_id: key_id(&verifying),
        generated_at,
        verification: VERIFICATION_RECIPE.to_string(),
    };

    let manifest_json =
        serde_json::to_string(&manifest).map_err(|_| BuildError::ManifestSerialization)?;
    let signature = key.sign(manifest_json.as_bytes());

    Ok(SignedExport {
        manifest_json,
        signature_b64: B64.encode(signature.to_bytes()),
        public_key_b64: B64.encode(verifying.to_bytes()),
        signing_key_id: key_id(&verifying),
        total_rows: manifest.total_rows,
        total_pages: manifest.total_pages,
        page_digests: digests,
        rows_per_page,
    })
}

// ── Verification ──────────────────────────────────────────────────────────

/// Every way an export can fail to be what it claims. Each variant names the
/// check that failed and, where it is meaningful, the page — an auditor's
/// first question after "did it verify" is "which part".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    PublicKeyMalformed,
    SignatureMalformed,
    /// The manifest bytes are not the bytes this signature covers, OR they
    /// were signed by a different key.
    SignatureInvalid,
    ManifestMalformed,
    UnsupportedSchemaVersion {
        got: u32,
    },
    /// The manifest's own page list disagrees with its `total_pages`.
    ManifestInternallyInconsistent,
    /// The manifest does not declare exactly [`REQUIRED_SECTIONS`], in order.
    /// This is the check that makes "nothing was silently omitted"
    /// mechanical: an export with the control plane removed lands here.
    ///
    /// Deliberately carries NO section name. The names in a manifest under
    /// examination are attacker-controlled strings, and this module's errors
    /// are bounded — see [`KeyError`]'s docs for the disclosure this project
    /// has already shipped once.
    SectionSetUnexpected,
    /// The sections do not partition `1..=total_pages` in order with no gap
    /// and no overlap. 0-based index into `sections`.
    SectionPagesNotContiguous {
        section_index: u32,
    },
    /// A section's declared `rows` is not the sum of its pages' rows.
    SectionRowCountMismatch {
        section_index: u32,
    },
    /// A page claims a section other than the one whose range contains it.
    /// 1-based page number.
    PageSectionMismatch {
        page: u32,
    },
    /// The chain seed does not match the manifest's own header — the export
    /// was assembled from a different window, workspace, format or page size
    /// than it claims.
    GenesisMismatch,
    PageCountMismatch {
        expected: u32,
        got: u32,
    },
    /// 1-based page number.
    PageDigestMismatch {
        page: u32,
    },
    /// 1-based page number.
    ChainBroken {
        page: u32,
    },
    ChainRootMismatch,
    RowCountMismatch {
        declared: u64,
        summed: u64,
    },
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PublicKeyMalformed => f.write_str("public key is not 32 base64-encoded bytes"),
            Self::SignatureMalformed => f.write_str("signature is not 64 base64-encoded bytes"),
            Self::SignatureInvalid => f.write_str(
                "signature does not cover these manifest bytes, or was made by another key",
            ),
            Self::ManifestMalformed => f.write_str("manifest is not a well-formed export manifest"),
            Self::UnsupportedSchemaVersion { got } => {
                write!(f, "manifest schema_version {got} is not understood")
            }
            Self::ManifestInternallyInconsistent => {
                f.write_str("manifest page list disagrees with its own total_pages")
            }
            Self::SectionSetUnexpected => f.write_str(
                "manifest does not declare exactly the sections this schema version \
                 requires, so part of the export may have been removed",
            ),
            Self::SectionPagesNotContiguous { section_index } => write!(
                f,
                "section {section_index} does not continue the page sequence"
            ),
            Self::SectionRowCountMismatch { section_index } => write!(
                f,
                "section {section_index} declares a row count its own pages do not sum to"
            ),
            Self::PageSectionMismatch { page } => {
                write!(f, "page {page} claims a section it does not fall in")
            }
            Self::GenesisMismatch => f.write_str(
                "chain seed does not match the manifest header (export id, workspace, window, format or page size)",
            ),
            Self::PageCountMismatch { expected, got } => {
                write!(f, "expected {expected} pages, was given {got}")
            }
            Self::PageDigestMismatch { page } => write!(f, "page {page} does not match its digest"),
            Self::ChainBroken { page } => write!(f, "chain is broken at page {page}"),
            Self::ChainRootMismatch => f.write_str("chain root does not match"),
            Self::RowCountMismatch { declared, summed } => write!(
                f,
                "manifest declares {declared} rows, its pages sum to {summed}"
            ),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Verify a complete export: signature, page digests, chain, order, count.
///
/// `public_key_b64` is the key the AUDITOR holds, obtained out of band. It is
/// deliberately not read from the manifest — see the module docs.
///
/// `pages` must be in page order, index 0 = page 1.
///
/// # Errors
/// [`VerifyError`], naming the first check that failed.
pub fn verify_export(
    manifest_json: &str,
    signature_b64: &str,
    public_key_b64: &str,
    pages: &[&[u8]],
) -> Result<Manifest, VerifyError> {
    // 1. Signature over the manifest's exact bytes. FIRST, so that a
    //    consistent-but-forged export is rejected as a forgery rather than
    //    reported as consistent.
    let key_bytes: [u8; 32] = B64
        .decode(public_key_b64)
        .map_err(|_| VerifyError::PublicKeyMalformed)?
        .try_into()
        .map_err(|_| VerifyError::PublicKeyMalformed)?;
    let verifying =
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| VerifyError::PublicKeyMalformed)?;
    let sig_bytes: [u8; 64] = B64
        .decode(signature_b64)
        .map_err(|_| VerifyError::SignatureMalformed)?
        .try_into()
        .map_err(|_| VerifyError::SignatureMalformed)?;
    let signature = Signature::from_bytes(&sig_bytes);
    verifying
        .verify(manifest_json.as_bytes(), &signature)
        .map_err(|_| VerifyError::SignatureInvalid)?;

    // 2. Shape. The VERSION is read out of the raw document first, before the
    //    typed deserialization: a manifest of another version will not fit
    //    this struct, and reporting `ManifestMalformed` for an archived v1
    //    export would send an auditor looking for tampering instead of for the
    //    v1 verifier.
    let raw: Value =
        serde_json::from_str(manifest_json).map_err(|_| VerifyError::ManifestMalformed)?;
    let declared_version = raw
        .get("schema_version")
        .and_then(Value::as_u64)
        .and_then(|v| u32::try_from(v).ok())
        .ok_or(VerifyError::ManifestMalformed)?;
    if declared_version != SCHEMA_VERSION {
        return Err(VerifyError::UnsupportedSchemaVersion {
            got: declared_version,
        });
    }
    let manifest: Manifest =
        serde_json::from_str(manifest_json).map_err(|_| VerifyError::ManifestMalformed)?;
    if manifest.pages.len() != manifest.total_pages as usize {
        return Err(VerifyError::ManifestInternallyInconsistent);
    }
    let format =
        ExportFormat::parse(&manifest.format).ok_or(VerifyError::ManifestInternallyInconsistent)?;

    // 3. The chain seed must be the one this manifest's own header implies.
    let seed = genesis(
        manifest.export_id,
        manifest.workspace_id,
        manifest.window.from,
        manifest.window.to,
        format,
        manifest.page_size,
    );
    if to_hex(&seed) != manifest.chain_genesis {
        return Err(VerifyError::GenesisMismatch);
    }

    // 4. Do we hold every page? This is the check a per-page signature scheme
    //    structurally cannot make.
    let got = u32::try_from(pages.len()).unwrap_or(u32::MAX);
    if got != manifest.total_pages {
        return Err(VerifyError::PageCountMismatch {
            expected: manifest.total_pages,
            got,
        });
    }

    // 4b. BOTH planes are present, and the sections partition the pages.
    //
    //     Without this an export could be handed over with the control-plane
    //     section deleted, every remaining page verifying, and nothing in the
    //     artifact saying anything was ever there. The signature makes the
    //     section list unforgeable; this makes an honest-but-incomplete
    //     section list a failure rather than a quieter document.
    if manifest.sections.len() != REQUIRED_SECTIONS.len()
        || !manifest
            .sections
            .iter()
            .zip(REQUIRED_SECTIONS)
            .all(|(entry, required)| entry.section == *required)
    {
        return Err(VerifyError::SectionSetUnexpected);
    }
    let mut next_page: u32 = 1;
    for (index, section) in manifest.sections.iter().enumerate() {
        let section_index = u32::try_from(index).unwrap_or(u32::MAX);
        if section.first_page != next_page
            || section.last_page < section.first_page
            || section.pages != section.last_page - section.first_page + 1
        {
            return Err(VerifyError::SectionPagesNotContiguous { section_index });
        }
        let mut section_rows: u64 = 0;
        for page in section.first_page..=section.last_page {
            let entry = manifest
                .pages
                .get(page as usize - 1)
                .ok_or(VerifyError::ManifestInternallyInconsistent)?;
            if entry.section != section.section {
                return Err(VerifyError::PageSectionMismatch { page: entry.page });
            }
            section_rows += u64::from(entry.rows);
        }
        if section_rows != section.rows {
            return Err(VerifyError::SectionRowCountMismatch { section_index });
        }
        next_page = section.last_page.saturating_add(1);
    }
    if next_page.saturating_sub(1) != manifest.total_pages {
        return Err(VerifyError::ManifestInternallyInconsistent);
    }

    // 5. Per-page digests, then 6. the chain over them in order.
    for (index, bytes) in pages.iter().enumerate() {
        let entry = &manifest.pages[index];
        // The page list is positional: `pages[i]` describes the (i+1)th file.
        // A manifest that renumbered them would make every error message name
        // the wrong file.
        if u64::from(entry.page) != index as u64 + 1 {
            return Err(VerifyError::ManifestInternallyInconsistent);
        }
        if to_hex(&sha256(bytes)) != entry.sha256 {
            return Err(VerifyError::PageDigestMismatch { page: entry.page });
        }
    }

    let mut chain = seed;
    let mut summed: u64 = 0;
    for entry in &manifest.pages {
        let digest = from_hex(&entry.sha256).ok_or(VerifyError::ManifestMalformed)?;
        chain = chain_step(&chain, &digest);
        if to_hex(&chain) != entry.chain {
            return Err(VerifyError::ChainBroken { page: entry.page });
        }
        summed += u64::from(entry.rows);
    }
    if to_hex(&chain) != manifest.chain_root {
        return Err(VerifyError::ChainRootMismatch);
    }
    if summed != manifest.total_rows {
        return Err(VerifyError::RowCountMismatch {
            declared: manifest.total_rows,
            summed,
        });
    }

    Ok(manifest)
}

// ── Keys ──────────────────────────────────────────────────────────────────

/// Short, stable fingerprint of a public key: `sha256:` + the first 8 bytes of
/// SHA-256 over the raw key, in hex.
#[must_use]
pub fn key_id(key: &VerifyingKey) -> String {
    let digest = sha256(&key.to_bytes());
    format!("sha256:{}", hex::encode(&digest[..8]))
}

/// Why the signing key could not be loaded.
///
/// The messages are FIXED STRINGS. `hex::decode` and base64 errors quote the
/// offending character and its offset — over key material that is a partial
/// disclosure, and this project has already shipped that defect once, in
/// `data_inventory`'s provider-key self-test. Nothing derived from the key
/// value reaches a caller or a log line from here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// The env var is unset or empty. The export must FAIL, not fall back to
    /// producing an unsigned artifact: an unsigned export presented as an
    /// audit control is the exact defect this task exists to fix.
    NotConfigured,
    /// Present but not 64 hex characters or base64 of 32 bytes.
    Malformed,
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::NotConfigured => {
                "audit-export signing key is not configured, so no signed export can be \
                 produced; set SECUREPROMPT_AUDIT_EXPORT_SIGNING_KEY"
            }
            Self::Malformed => {
                "audit-export signing key is not 64 hex characters or base64 of 32 bytes; \
                 its value is deliberately not quoted here"
            }
        };
        f.write_str(text)
    }
}

impl std::error::Error for KeyError {}

/// Parse a configured signing seed. Accepts 64 hex characters or base64 of 32
/// bytes.
///
/// # Errors
/// [`KeyError`] — never carrying any part of the input.
pub fn parse_signing_key(configured: &str) -> Result<SigningKey, KeyError> {
    let trimmed = configured.trim();
    if trimmed.is_empty() {
        return Err(KeyError::NotConfigured);
    }
    if trimmed.len() == 64 {
        if let Some(bytes) = from_hex(trimmed) {
            return Ok(SigningKey::from_bytes(&bytes));
        }
    }
    let decoded = B64.decode(trimmed).map_err(|_| KeyError::Malformed)?;
    let bytes: [u8; 32] = decoded.try_into().map_err(|_| KeyError::Malformed)?;
    Ok(SigningKey::from_bytes(&bytes))
}

/// Load the signing key from [`SIGNING_KEY_ENV`].
///
/// # Errors
/// [`KeyError`].
pub fn signing_key_from_env() -> Result<SigningKey, KeyError> {
    let raw = std::env::var(SIGNING_KEY_ENV).map_err(|_| KeyError::NotConfigured)?;
    parse_signing_key(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn row() -> AuditRow {
        AuditRow {
            request_id: Uuid::from_u128(1),
            workspace_id: Uuid::from_u128(2),
            created_at: Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap(),
            provider: "openai".into(),
            model: "gpt-4o-mini".into(),
            final_action: "allow".into(),
            input_tokens: Some(1),
            output_tokens: None,
            estimated_usage: true,
            cost_usd: 0.000_012_5,
            user_id: None,
            api_key_id: None,
            api_key_name: None,
            ip_address: None,
            user_agent: None,
            floor_only: false,
            engines: vec!["floor".into(), "xlmr".into()],
        }
    }

    fn control_row() -> ControlRow {
        ControlRow {
            event_id: Uuid::from_u128(3),
            workspace_id: Uuid::from_u128(2),
            occurred_at: Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap(),
            event_type: EVENT_SESSION_REVOKED.into(),
            source_table: "session_revocation_audit".into(),
            actor_user_id: Some(Uuid::from_u128(4)),
            actor_email: Some("synthetic-admin@example.invalid".into()),
            actor_role: Some("admin".into()),
            target_user_id: Some(Uuid::from_u128(5)),
            target_email: Some("synthetic-target@example.invalid".into()),
            target_role: Some("member".into()),
            detail: serde_json::json!({
                "revoked_before_unix": 1_780_000_000_i64,
                "refresh_tokens_revoked": 2,
            }),
        }
    }

    /// A section's column list is the source of truth for BOTH renderings. If
    /// a field is added to a row type and not to its columns, CSV silently
    /// drops it while JSONL keeps it — the two formats would then disagree
    /// about what the export contains. This is the assertion that makes that a
    /// red test, and it now covers BOTH planes: the control-plane section has
    /// its own row type and its own column list, and the same drift is
    /// possible there.
    ///
    /// Compared as SETS, not as sequences, and that is a measured fact rather
    /// than a preference: `serde_json::Map` is a `BTreeMap` unless the
    /// `preserve_order` feature is on, and it is not on in this workspace — so
    /// a row's JSON keys come out ALPHABETICALLY, never in struct-field order.
    /// The first version of this test asserted sequence equality and failed
    /// with `["request_id", "workspace_id", ...]` against
    /// `["api_key_id", "api_key_name", ...]`.
    ///
    /// That is fine for JSONL, where JSON object members are unordered by
    /// spec. Column ORDER is a CSV property, and CSV gets it from the column
    /// list by NAME, which `csv_header_order_is_the_documented_column_order`
    /// pins separately.
    #[test]
    fn columns_match_the_row_shape() {
        use std::collections::BTreeSet;

        let request_object = row().to_object();
        let declared: BTreeSet<&str> = REQUEST_COLUMNS.iter().map(|(name, _)| *name).collect();
        let actual: BTreeSet<&str> = request_object.keys().map(String::as_str).collect();
        assert_eq!(
            declared, actual,
            "REQUEST_COLUMNS must list exactly the AuditRow fields — no more, no fewer"
        );

        let control_object = control_row().to_object();
        let declared: BTreeSet<&str> = CONTROL_COLUMNS.iter().map(|(name, _)| *name).collect();
        let actual: BTreeSet<&str> = control_object.keys().map(String::as_str).collect();
        assert_eq!(
            declared, actual,
            "CONTROL_COLUMNS must list exactly the ControlRow fields — no more, no fewer"
        );
    }

    /// The documented column ORDER is a CSV guarantee. An auditor's tooling
    /// reads by position as often as by header name. Asserted for both
    /// sections, because a CSV export now contains two different headers and
    /// each must be its own section's.
    #[test]
    fn csv_header_order_is_the_documented_column_order() {
        for (page, columns) in [
            (render_page(&[row()], ExportFormat::Csv), REQUEST_COLUMNS),
            (
                render_page(&[control_row()], ExportFormat::Csv),
                CONTROL_COLUMNS,
            ),
        ] {
            let page = String::from_utf8(page).unwrap();
            let header = page.lines().next().expect("header row");
            let expected: String = columns
                .iter()
                .map(|(name, _)| format!("\"{name}\""))
                .collect::<Vec<_>>()
                .join(",");
            assert_eq!(header, expected);
        }
    }

    /// The control-plane page must NOT carry `retention_purge_audit.error`.
    ///
    /// That column is written as `&e.to_string()` on a ClickHouse error
    /// (`retention_purge.rs:190,220,320,344,364`), and a store exception
    /// quotes the statement that provoked it and sometimes the value it choked
    /// on. Copying it into a signed, never-purged artifact is the defect this
    /// repository has already fixed three times on the response path. The
    /// export carries the boolean `error_present` instead.
    #[test]
    fn the_control_plane_carries_no_store_error_text() {
        const MARKER: &str = "ZZSTOREMESSAGEZZ";
        let mut row = control_row();
        row.event_type = EVENT_RETENTION_PURGE.into();
        row.source_table = "retention_purge_audit".into();
        row.detail = serde_json::json!({ "status": "error", "error_present": true });
        let page = String::from_utf8(render_page(&[row], ExportFormat::Jsonl)).unwrap();

        // Premise: we are looking at a real purge row, not an empty page that
        // would satisfy the absence check vacuously.
        assert!(
            page.contains("error_present"),
            "premise: the page must carry the purge row; got:\n{page}"
        );
        assert!(
            !page.contains(MARKER),
            "no store message may reach a page; got:\n{page}"
        );

        // Positive control: the marker really is detectable by this assertion
        // when it IS present, so the absence above is a measurement.
        let mut leaky = control_row();
        leaky.detail = serde_json::json!({ "error": MARKER });
        let leaked = String::from_utf8(render_page(&[leaky], ExportFormat::Jsonl)).unwrap();
        assert!(leaked.contains(MARKER));

        // And no column is even NAMED for it, so the absence is structural
        // rather than a value that happened to be empty today.
        assert!(!CONTROL_COLUMNS.iter().any(|(name, _)| *name == "error"));
    }

    /// NULL and the empty string are different facts about an audit row and
    /// must survive CSV round-tripping as different bytes.
    #[test]
    fn csv_distinguishes_null_from_empty_string() {
        assert_eq!(csv_field(None), "");
        assert_eq!(csv_field(Some("")), "\"\"");
        assert_ne!(csv_field(None), csv_field(Some("")));
    }

    #[test]
    fn csv_doubles_embedded_quotes() {
        assert_eq!(csv_field(Some(r#"a"b"#)), r#""a""b""#);
        // A comma or newline inside a field cannot break the row, because
        // every non-NULL field is quoted.
        assert_eq!(csv_field(Some("a,b")), "\"a,b\"");
        assert_eq!(csv_field(Some("a\nb")), "\"a\nb\"");
    }

    /// Rust's `{}` for f64 is shortest-round-trip. An audit figure written to
    /// a fixed number of decimal places would not reproduce the stored value.
    #[test]
    fn cost_is_written_without_rounding() {
        let page = String::from_utf8(render_page(&[row()], ExportFormat::Csv)).unwrap();
        assert!(
            page.contains("0.0000125"),
            "cost must round-trip exactly; page was:\n{page}"
        );
    }

    #[test]
    fn csv_page_carries_a_header_on_every_page() {
        let page = String::from_utf8(render_page(&[row()], ExportFormat::Csv)).unwrap();
        let first = page.lines().next().unwrap();
        assert!(first.starts_with("\"request_id\","), "got: {first}");
        assert_eq!(page.lines().count(), 2, "header + one row");
    }

    #[test]
    fn jsonl_page_has_no_header_and_one_object_per_line() {
        let page = String::from_utf8(render_page(&[row(), row()], ExportFormat::Jsonl)).unwrap();
        assert_eq!(page.lines().count(), 2);
        for line in page.lines() {
            let value: Value = serde_json::from_str(line).expect("each line is a JSON object");
            assert!(value.get("request_id").is_some());
        }
    }

    #[test]
    fn empty_page_renderings_differ_by_format() {
        assert_eq!(
            render_page::<AuditRow>(&[], ExportFormat::Jsonl),
            Vec::<u8>::new()
        );
        // CSV keeps its header, so an empty CSV page is still a valid CSV file.
        assert!(!render_page::<AuditRow>(&[], ExportFormat::Csv).is_empty());
        // And the empty control-plane page carries the CONTROL header, not the
        // request one — an empty section still says which section it is.
        let empty = String::from_utf8(render_page::<ControlRow>(&[], ExportFormat::Csv)).unwrap();
        assert!(empty.starts_with("\"event_id\","), "got: {empty}");
    }

    #[test]
    fn genesis_changes_with_every_header_field() {
        let (a, b) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let t0 = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
        let t1 = Utc.with_ymd_and_hms(2026, 6, 2, 0, 0, 0).unwrap();
        let base = genesis(a, b, t0, t1, ExportFormat::Csv, 100);
        assert_ne!(base, genesis(b, b, t0, t1, ExportFormat::Csv, 100));
        assert_ne!(base, genesis(a, a, t0, t1, ExportFormat::Csv, 100));
        assert_ne!(base, genesis(a, b, t1, t1, ExportFormat::Csv, 100));
        assert_ne!(base, genesis(a, b, t0, t0, ExportFormat::Csv, 100));
        assert_ne!(base, genesis(a, b, t0, t1, ExportFormat::Jsonl, 100));
        assert_ne!(base, genesis(a, b, t0, t1, ExportFormat::Csv, 101));
    }

    #[test]
    fn retention_classifies_the_three_window_positions() {
        let now = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
        let inside = retention_for(now - Duration::days(10), now, now);
        assert_eq!(inside.window_status, WITHIN_RETENTION);

        let straddling = retention_for(now - Duration::days(120), now, now);
        assert_eq!(straddling.window_status, PARTIALLY_EXPIRED);

        let gone = retention_for(now - Duration::days(400), now - Duration::days(200), now);
        assert_eq!(gone.window_status, WHOLLY_EXPIRED);

        // The boundary is exactly ttl_days back, and is reported so a reader
        // can recompute the verdict.
        assert_eq!(inside.boundary, Some(now - Duration::days(SOURCE_TTL_DAYS)));
        assert_eq!(inside.ttl_days, Some(SOURCE_TTL_DAYS));
    }

    /// Trap: an export must not lend one source's retention story to another.
    /// The control-plane tables have NO TTL, so the SAME window that is
    /// `partially_expired` for `request_events` is `no_expiry` for them — and
    /// an auditor reading a single export-level verdict would have been told
    /// one of those two things falsely.
    #[test]
    fn the_two_planes_report_different_retention_for_the_same_window() {
        let now = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
        let (from, to) = (now - Duration::days(200), now);

        let data = retention_for(from, to, now);
        assert_eq!(data.window_status, PARTIALLY_EXPIRED);
        assert_eq!(data.store, "clickhouse");

        for table in CONTROL_SOURCE_TABLES {
            let control = no_expiry_for(table);
            assert_eq!(control.window_status, NO_EXPIRY);
            assert_eq!(control.ttl_days, None, "{table} must declare no TTL");
            assert_eq!(control.boundary, None, "{table} must declare no boundary");
            assert_ne!(
                control.window_status, data.window_status,
                "{table} must not inherit the data plane's expiry verdict"
            );
        }
    }

    /// A window ending exactly ON the boundary is wholly expired, not
    /// partially: `to` is EXCLUSIVE, so no surviving instant is in range.
    #[test]
    fn a_window_ending_on_the_boundary_is_wholly_expired() {
        let now = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
        let boundary = now - Duration::days(SOURCE_TTL_DAYS);
        assert_eq!(
            retention_for(boundary - Duration::days(1), boundary, now).window_status,
            WHOLLY_EXPIRED
        );
    }

    /// The retention blocks every section built in this module's tests
    /// carries, so a fixture cannot accidentally omit the per-source
    /// statement the format requires.
    fn control_sources() -> Vec<SourceRetention> {
        CONTROL_SOURCE_TABLES
            .iter()
            .map(|t| no_expiry_for(t))
            .collect()
    }

    #[test]
    fn build_rejects_mismatched_row_counts() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let now = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
        // `.unwrap_err()` rather than comparing the whole `Result`:
        // `SignedExport` holds a signature and deliberately does not derive
        // `PartialEq`, so there is no `==` on the Ok side to lean on.
        let error = build_manifest(
            Uuid::from_u128(9),
            Uuid::from_u128(2),
            now,
            now,
            ExportFormat::Jsonl,
            1,
            &[
                request_section(
                    vec![render_page(&[row()], ExportFormat::Jsonl)],
                    vec![1, 1],
                    vec![retention_for(now, now, now)],
                ),
                control_section(
                    vec![render_page::<ControlRow>(&[], ExportFormat::Jsonl)],
                    vec![0],
                    control_sources(),
                ),
            ],
            now,
            &key,
        )
        .expect_err("two row counts for one page must be rejected");
        assert_eq!(error, BuildError::PageRowCountMismatch);
    }

    /// A section offered with NO pages at all is refused at build time, not
    /// emitted. A zero-page section cannot be told apart from one that was
    /// removed, which is the exact ambiguity this format exists to close.
    #[test]
    fn build_rejects_a_section_with_no_pages() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let now = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
        let error = build_manifest(
            Uuid::from_u128(9),
            Uuid::from_u128(2),
            now,
            now,
            ExportFormat::Jsonl,
            1,
            &[
                request_section(
                    vec![render_page(&[row()], ExportFormat::Jsonl)],
                    vec![1],
                    vec![retention_for(now, now, now)],
                ),
                control_section(vec![], vec![], control_sources()),
            ],
            now,
            &key,
        )
        .expect_err("a section with no pages must be refused");
        assert_eq!(error, BuildError::EmptySection);
    }

    /// The product cannot SIGN an artifact its own verifier would reject. A
    /// data-plane-only export is refused here as well as in `verify_export`,
    /// so the failure is a worker error an operator sees rather than an
    /// artifact an auditor discovers is unverifiable.
    #[test]
    fn build_rejects_an_export_missing_the_control_plane() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let now = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
        let error = build_manifest(
            Uuid::from_u128(9),
            Uuid::from_u128(2),
            now,
            now,
            ExportFormat::Jsonl,
            1,
            &[request_section(
                vec![render_page(&[row()], ExportFormat::Jsonl)],
                vec![1],
                vec![retention_for(now, now, now)],
            )],
            now,
            &key,
        )
        .expect_err("an export without the control plane must be refused");
        assert_eq!(error, BuildError::SectionSetUnexpected);
    }

    /// An export over ZERO rows is still a signed statement — "we looked, and
    /// there was nothing" is exactly the claim an auditor needs to be able to
    /// check, and the empty case is where an unsigned "no data" page would be
    /// trivially forgeable. BOTH sections are still present and each still
    /// carries its one page.
    #[test]
    fn an_empty_export_is_still_signed_and_verifiable() {
        let key = SigningKey::from_bytes(&[4u8; 32]);
        let now = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
        let from = now - Duration::days(1);
        let pages: Vec<Vec<u8>> = vec![
            render_page::<AuditRow>(&[], ExportFormat::Csv),
            render_page::<ControlRow>(&[], ExportFormat::Csv),
        ];
        let signed = build_manifest(
            Uuid::from_u128(9),
            Uuid::from_u128(2),
            from,
            now,
            ExportFormat::Csv,
            100,
            &[
                request_section(
                    vec![pages[0].clone()],
                    vec![0],
                    vec![retention_for(from, now, now)],
                ),
                control_section(vec![pages[1].clone()], vec![0], control_sources()),
            ],
            now,
            &key,
        )
        .unwrap();
        assert_eq!(signed.total_rows, 0);
        assert_eq!(signed.total_pages, 2, "one empty page per section");
        let refs: Vec<&[u8]> = pages.iter().map(Vec::as_slice).collect();
        let manifest = verify_export(
            &signed.manifest_json,
            &signed.signature_b64,
            &signed.public_key_b64,
            &refs,
        )
        .expect("an empty export must still verify");
        assert_eq!(
            manifest
                .sections
                .iter()
                .map(|s| s.section.as_str())
                .collect::<Vec<_>>(),
            REQUIRED_SECTIONS
        );
    }

    #[test]
    fn key_parsing_accepts_hex_and_base64_and_agrees() {
        let raw = [11u8; 32];
        let from_hex_key = parse_signing_key(&hex::encode(raw)).unwrap();
        let from_b64_key = parse_signing_key(&B64.encode(raw)).unwrap();
        assert_eq!(from_hex_key.to_bytes(), from_b64_key.to_bytes());
        assert_eq!(from_hex_key.to_bytes(), raw);
    }

    #[test]
    fn key_parsing_reports_missing_and_malformed_separately() {
        assert_eq!(parse_signing_key(""), Err(KeyError::NotConfigured));
        assert_eq!(parse_signing_key("   "), Err(KeyError::NotConfigured));
        assert_eq!(parse_signing_key("not-a-key"), Err(KeyError::Malformed));
        // 64 chars but not hex → falls through to base64, which also rejects.
        assert_eq!(parse_signing_key(&"z".repeat(64)), Err(KeyError::Malformed));
        // Right encoding, wrong length.
        assert_eq!(
            parse_signing_key(&B64.encode([1u8; 16])),
            Err(KeyError::Malformed)
        );
    }

    /// A key error must never quote the key. `hex::decode`'s own message is
    /// `Invalid character 'q' at position 0` and base64's names the offset
    /// too, so the naive `format!("...: {e}")` this project shipped once in
    /// `data_inventory`'s provider-key self-test would partially disclose the
    /// configured secret.
    ///
    /// The assertion is over a DISTINCTIVE MARKER, not over individual
    /// characters. The first version of this test also asserted the message
    /// contained no `'q'`, which fails on the fixed message's own word
    /// "quoted" — a bogus proxy that would have had to be weakened later for a
    /// reason unrelated to the property being defended.
    #[test]
    fn key_errors_do_not_quote_the_key_material() {
        const MARKER: &str = "ZZTOPSECRETZZ";
        let secret = format!("qqqq{MARKER}qqqq");
        let message = parse_signing_key(&secret).unwrap_err().to_string();

        // Premise (Constraint 2): we are looking at a real message, not an
        // empty string that would pass the absence check vacuously.
        assert!(
            message.contains("64 hex characters"),
            "premise: the error must actually say what shape it wanted; got: {message}"
        );
        assert!(
            !message.contains(MARKER),
            "key error must not echo the configured value; got: {message}"
        );

        // Positive control (Constraint 2): the marker really is detectable by
        // this assertion when it IS present, so the absence above is a
        // measurement rather than a tautology.
        assert!(format!("failed on {secret}").contains(MARKER));
    }

    #[test]
    fn key_id_is_stable_and_distinguishes_keys() {
        let a = SigningKey::from_bytes(&[1u8; 32]).verifying_key();
        let b = SigningKey::from_bytes(&[2u8; 32]).verifying_key();
        assert_eq!(key_id(&a), key_id(&a));
        assert_ne!(key_id(&a), key_id(&b));
        assert!(key_id(&a).starts_with("sha256:"));
        assert_eq!(key_id(&a).len(), "sha256:".len() + 16);
    }

    #[test]
    fn format_round_trips_and_rejects_anything_else() {
        for f in [ExportFormat::Csv, ExportFormat::Jsonl] {
            assert_eq!(ExportFormat::parse(f.as_str()), Some(f));
        }
        assert_eq!(ExportFormat::parse("CSV"), None);
        assert_eq!(ExportFormat::parse("parquet"), None);
        assert_eq!(ExportFormat::parse(""), None);
    }
}
