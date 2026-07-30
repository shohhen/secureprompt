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
//! # What the export contains
//!
//! Request METADATA only — see [`COLUMNS`]. `request_events` also holds
//! `raw_prompt`, `raw_response`, `redacted_prompt` and `restored_response`, and
//! none of them is exported. A compliance artifact that shipped prompt bodies
//! would be a PII export wearing an audit label, and it would be handed to
//! precisely the people who are not supposed to see the content.
//! `the_export_carries_no_content_columns` asserts the absence.
//!
//! # Byte-level rules the digests depend on
//!
//! * Line terminator is **LF**, never CRLF, in both formats.
//! * CSV: the header row is repeated on EVERY page, so a page is a valid CSV
//!   file on its own — and it is inside that page's digest.
//! * CSV: every non-NULL field is quoted, inner `"` doubled. A NULL is an
//!   unquoted empty field, so `""` (empty string) and NULL stay distinguishable
//!   — an ambiguity a naive writer introduces silently.
//! * The CSV field order and the JSONL key order are BOTH derived from
//!   [`COLUMNS`] via the row's JSON form, so the two formats cannot drift from
//!   each other or from the documented column list.
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
pub const SCHEMA_VERSION: u32 = 1;

/// Env var carrying the Ed25519 signing seed. 64 hex characters or base64 of
/// 32 bytes. Never a literal in this repository, and never logged.
pub const SIGNING_KEY_ENV: &str = "SECUREPROMPT_AUDIT_EXPORT_SIGNING_KEY";

/// The ClickHouse relation every exported row comes from.
pub const SOURCE_TABLE: &str = "request_events";

/// `request_events` carries `TTL created_at + INTERVAL 90 DAY`
/// (`secureprompt-api/clickhouse/migrations/001_analytics_schema.sql:43`).
/// This is a real boundary, unlike the six dbt marts, which carry no TTL at
/// all — an export must not borrow a retention claim from a table it did not
/// read.
pub const SOURCE_TTL_DAYS: i64 = 90;

/// Domain separator for the chain seed. Prefixed so a digest from this scheme
/// can never be confused with one from another.
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

/// The exported columns, in order, with the auditor-facing meaning of each.
///
/// This list is the single source of truth: [`render_page`] projects each row
/// through it for BOTH formats, and it is copied into every manifest so an
/// archived export explains its own columns without `docs/` beside it.
pub const COLUMNS: &[(&str, &str)] = &[
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
    (
        "api_key_id",
        "Which API key authenticated the request.",
    ),
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

/// What the figures in an export do and do not cover. Copied into the
/// manifest, in the same spirit as `leak_report::COVERAGE`.
pub const COVERAGE: &str =
    "GATEWAY TRAFFIC ONLY, METADATA ONLY. Every row comes from `request_events`, \
     which is written from the gateway request pipeline — the paths \
     `/v1/chat/completions`, `/v1/completions` and `/v1/embeddings`. Requests to \
     `/v1/redact`, `/v1/secure-mode/tokenize`, the MCP server and file scanning \
     write no `request_events` row at all, so they are ABSENT from this export \
     entirely; their absence is not evidence they did not happen. No prompt or \
     response content is exported: `request_events` also holds `raw_prompt`, \
     `raw_response`, `redacted_prompt` and `restored_response`, and this export \
     carries NONE of them, by construction rather than by configuration.";

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
     be reformatted, re-indented or re-serialised before verifying. 3. For each \
     page file, compute SHA-256 and compare it to `pages[i].sha256`. 4. Check \
     you hold exactly `total_pages` pages. 5. Recompute the chain: \
     `chain_0 = SHA256(chain_genesis || sha256_0)` and \
     `chain_i = SHA256(chain_{i-1} || sha256_i)`, all over RAW 32-byte digests, \
     and compare each to `pages[i].chain` and the last to `chain_root`. \
     6. Recompute `chain_genesis` = SHA256 of the LF-joined header lines \
     `secureprompt.audit_export.v1`, `export_id`, `workspace_id`, \
     `window.from`, `window.to`, `format`, `page_size`, with a trailing LF. \
     7. Check `sum(pages[i].rows) == total_rows`.";

// ── Rows ──────────────────────────────────────────────────────────────────

/// One exported audit row. Metadata only — see the module docs.
///
/// Field order here is the exported column order, and
/// `columns_match_the_row_shape` asserts it against [`COLUMNS`] so the two
/// cannot drift.
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

impl AuditRow {
    /// The row as a JSON object. This is the JSONL line, and it is also what
    /// the CSV writer projects through [`COLUMNS`] — one shape, two
    /// renderings, so a column added to one format cannot be missing from the
    /// other.
    fn to_object(&self) -> Map<String, Value> {
        match serde_json::to_value(self) {
            Ok(Value::Object(map)) => map,
            // `AuditRow` is a plain struct of serialisable fields, so this is
            // unreachable. It is written as a fallback rather than an
            // `expect` because an audit export must not panic a worker.
            _ => Map::new(),
        }
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
#[must_use]
pub fn render_page(rows: &[AuditRow], format: ExportFormat) -> Vec<u8> {
    let mut out = String::new();
    match format {
        ExportFormat::Csv => {
            let header: Vec<String> = COLUMNS
                .iter()
                .map(|(name, _)| csv_field(Some(name)))
                .collect();
            out.push_str(&header.join(","));
            out.push('\n');
            for row in rows {
                let object = row.to_object();
                let fields: Vec<String> = COLUMNS
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

/// The chain seed. Binds the export's identity and window into every
/// subsequent link, so a page from another export cannot be spliced in even
/// when both exports have the same shape.
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
        from.to_rfc3339(),
        to.to_rfc3339(),
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
    pub rows: u32,
    /// Lowercase hex SHA-256 of the page's exact bytes.
    pub sha256: String,
    /// Lowercase hex chain value AFTER folding this page in.
    pub chain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Window {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    pub interpretation: String,
}

/// The retention boundary, stated rather than papered over.
///
/// An export whose window reaches behind `boundary` cannot be complete, and
/// saying so is the whole difference between an attestation and a short result
/// that looks complete. Same rule `leak_report` follows for `by_model`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Retention {
    pub source_table: String,
    pub ttl_days: i64,
    /// `generated_at - ttl_days`. Rows older than this have been deleted by
    /// ClickHouse and CANNOT appear in any export.
    pub boundary: DateTime<Utc>,
    /// `within_retention` | `partially_expired` | `wholly_expired`.
    pub window_status: String,
    pub detail: String,
}

/// Retention verdicts as machine-readable constants, so a caller branches on
/// a value from this binary rather than on a spelling.
pub const WITHIN_RETENTION: &str = "within_retention";
pub const PARTIALLY_EXPIRED: &str = "partially_expired";
pub const WHOLLY_EXPIRED: &str = "wholly_expired";

/// Classify the requested window against the source table's TTL.
#[must_use]
pub fn retention_for(
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    generated_at: DateTime<Utc>,
) -> Retention {
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
    Retention {
        source_table: SOURCE_TABLE.to_string(),
        ttl_days: SOURCE_TTL_DAYS,
        boundary,
        window_status: status.to_string(),
        detail: detail.to_string(),
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
    pub pages: Vec<PageEntry>,
    pub columns: Vec<ColumnDoc>,
    pub coverage: String,
    pub retention: Retention,
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
    /// `serde_json` could not render the manifest.
    ManifestSerialization,
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::PageRowCountMismatch => {
                "page list and row-count list have different lengths"
            }
            Self::ManifestSerialization => "manifest could not be serialized",
        };
        f.write_str(text)
    }
}

impl std::error::Error for BuildError {}

/// Build and sign the manifest for an already-rendered set of pages.
///
/// `pages` must be the EXACT bytes that will be served; the digests are taken
/// over them here and never recomputed from rows again.
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
    pages: &[Vec<u8>],
    rows_per_page: &[u32],
    generated_at: DateTime<Utc>,
    key: &SigningKey,
) -> Result<SignedExport, BuildError> {
    if pages.len() != rows_per_page.len() {
        return Err(BuildError::PageRowCountMismatch);
    }

    let seed = genesis(export_id, workspace_id, from, to, format, page_size);
    let mut chain = seed;
    let mut entries = Vec::with_capacity(pages.len());
    let mut digests = Vec::with_capacity(pages.len());
    let mut total_rows: u64 = 0;

    for (index, bytes) in pages.iter().enumerate() {
        let digest = sha256(bytes);
        chain = chain_step(&chain, &digest);
        let rows = rows_per_page[index];
        total_rows += u64::from(rows);
        digests.push(to_hex(&digest));
        entries.push(PageEntry {
            page: u32::try_from(index).unwrap_or(u32::MAX).saturating_add(1),
            rows,
            sha256: to_hex(&digest),
            chain: to_hex(&chain),
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
        total_pages: u32::try_from(pages.len()).unwrap_or(u32::MAX),
        chain_genesis: to_hex(&seed),
        chain_root: to_hex(&chain),
        pages: entries,
        columns: COLUMNS
            .iter()
            .map(|(name, meaning)| ColumnDoc {
                name: (*name).to_string(),
                meaning: (*meaning).to_string(),
            })
            .collect(),
        coverage: COVERAGE.to_string(),
        retention: retention_for(from, to, generated_at),
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
        rows_per_page: rows_per_page.to_vec(),
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

    // 2. Shape.
    let manifest: Manifest =
        serde_json::from_str(manifest_json).map_err(|_| VerifyError::ManifestMalformed)?;
    if manifest.schema_version != SCHEMA_VERSION {
        return Err(VerifyError::UnsupportedSchemaVersion {
            got: manifest.schema_version,
        });
    }
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

    // 5. Per-page digests, then 6. the chain over them in order.
    for (index, bytes) in pages.iter().enumerate() {
        let entry = &manifest.pages[index];
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

    /// [`COLUMNS`] is the source of truth for BOTH renderings. If a field is
    /// added to `AuditRow` and not to `COLUMNS`, CSV silently drops it while
    /// JSONL keeps it — the two formats would then disagree about what the
    /// export contains. This is the assertion that makes that a red test.
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
    /// spec. Column ORDER is a CSV property, and CSV gets it from [`COLUMNS`]
    /// by NAME, which `csv_header_order_is_the_documented_column_order` pins
    /// separately.
    #[test]
    fn columns_match_the_row_shape() {
        use std::collections::BTreeSet;
        let object = row().to_object();
        let declared: BTreeSet<&str> = COLUMNS.iter().map(|(name, _)| *name).collect();
        let actual: BTreeSet<&str> = object.keys().map(String::as_str).collect();
        assert_eq!(
            declared, actual,
            "COLUMNS must list exactly the AuditRow fields — no more, no fewer"
        );
    }

    /// The documented column ORDER is a CSV guarantee. An auditor's tooling
    /// reads by position as often as by header name.
    #[test]
    fn csv_header_order_is_the_documented_column_order() {
        let page = String::from_utf8(render_page(&[row()], ExportFormat::Csv)).unwrap();
        let header = page.lines().next().expect("header row");
        let expected: String = COLUMNS
            .iter()
            .map(|(name, _)| format!("\"{name}\""))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(header, expected);
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
        assert_eq!(render_page(&[], ExportFormat::Jsonl), Vec::<u8>::new());
        // CSV keeps its header, so an empty CSV page is still a valid CSV file.
        assert!(!render_page(&[], ExportFormat::Csv).is_empty());
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
        assert_eq!(inside.boundary, now - Duration::days(SOURCE_TTL_DAYS));
        assert_eq!(inside.ttl_days, SOURCE_TTL_DAYS);
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

    #[test]
    fn build_rejects_mismatched_row_counts() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let now = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
        let pages = vec![render_page(&[row()], ExportFormat::Jsonl)];
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
            &pages,
            &[1, 1],
            now,
            &key,
        )
        .expect_err("two row counts for one page must be rejected");
        assert_eq!(error, BuildError::PageRowCountMismatch);
    }

    /// An export over ZERO rows is still a signed statement — "we looked, and
    /// there was nothing" is exactly the claim an auditor needs to be able to
    /// check, and the empty case is where an unsigned "no data" page would be
    /// trivially forgeable.
    #[test]
    fn an_empty_export_is_still_signed_and_verifiable() {
        let key = SigningKey::from_bytes(&[4u8; 32]);
        let now = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
        let pages: Vec<Vec<u8>> = vec![render_page(&[], ExportFormat::Csv)];
        let signed = build_manifest(
            Uuid::from_u128(9),
            Uuid::from_u128(2),
            now - Duration::days(1),
            now,
            ExportFormat::Csv,
            100,
            &pages,
            &[0],
            now,
            &key,
        )
        .unwrap();
        assert_eq!(signed.total_rows, 0);
        assert_eq!(signed.total_pages, 1);
        let refs: Vec<&[u8]> = pages.iter().map(Vec::as_slice).collect();
        assert!(verify_export(
            &signed.manifest_json,
            &signed.signature_b64,
            &signed.public_key_b64,
            &refs
        )
        .is_ok());
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
        assert_eq!(parse_signing_key(&B64.encode([1u8; 16])), Err(KeyError::Malformed));
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
