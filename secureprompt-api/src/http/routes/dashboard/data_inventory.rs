//! WS3-5 — `GET /v1/data-inventory`.
//!
//! Enumerates, for the CALLER'S WORKSPACE, every class of stored artifact the
//! product creates: what it is, whether it is encrypted at rest, how long it
//! is kept and BY WHAT MECHANISM, and how many rows exist right now.
//!
//! # This is a compliance attestation, so accuracy is the whole product
//!
//! An auditor reads this output and believes it. That makes an omission or an
//! overclaim worse than having no endpoint at all: it converts an unknown
//! into a false assurance. Four rules follow from that, and each one is
//! enforced by a test in `tests/data_inventory.rs`:
//!
//! 1. **Counts are queried live, per workspace, with the tenancy predicate in
//!    the QUERY.** This branch has already shipped one cross-tenant leak
//!    (`cost-by-model`) where a handler guard fired only when a parameter was
//!    supplied and neither underlying query filtered. There is no
//!    workspace parameter here at all — the workspace comes from the JWT and
//!    is bound into every count.
//!
//! 2. **Encryption state is DERIVED, never asserted.** `request_content_captures`
//!    carries its own `encrypted Bool` column, and the WS3 review found a row
//!    with `encrypted = true` over a plaintext payload. That flag is written
//!    by the same code path that writes the payload, so republishing it
//!    launders a self-attestation into evidence. This module never reads it.
//!    It instead (a) probes the live KMS with an encrypt→decrypt round trip,
//!    and (b) shape-checks the bytes actually on disk against the envelope
//!    this deployment's KMS produces. See [`CIPHERTEXT_SHAPE_CLAIM`] for what
//!    that does and does not prove — stated in the response itself, not just
//!    here.
//!
//! 3. **What cannot be said is said.** The Redis file vault
//!    (`filevault:{ref}`) carries no workspace id in its key, so it can
//!    neither be counted nor erased per tenant. It appears in
//!    `not_enumerable` with that reason, because a silently missing class is
//!    the one failure an auditor cannot detect. Likewise a `ClickHouse` `TTL`
//!    is a background merge, not a delete at the instant of expiry, and the
//!    response says which mechanism enforces every window it reports.
//!
//! 4. **No content, ever.** Counts, class names, retention and encryption
//!    state only. Nothing in this module selects a payload column; the shape
//!    checks run as `countIf`/`count(*) WHERE` inside the database and return
//!    integers.
//!
//! # Who may read it
//!
//! ADMIN — see [`get_data_inventory`]. "No content" is not "no sensitive
//! information": the response is a live map of which stores hold how much and
//! which credential classes are verifiably sealed.
//!
//! # Why the raw-capture toggle did NOT move here
//!
//! WS3-1's implementer flagged that a plaintext-retention switch living on
//! `PUT /v1/secure-mode` reads oddly to an auditor and suggested this as its
//! home. It stays where it is, for three reasons:
//!
//! * Moving it would make the attestation endpoint a MUTATION surface. "The
//!   endpoint that reports what you retain can also change what you retain"
//!   is a worse story than the one it fixes.
//! * `PUT /v1/secure-mode` writes the setting and the append-only
//!   `raw_capture_audit` row in ONE transaction
//!   (`RawCaptureRepository::upsert_audited`). Splitting the control across
//!   endpoints either duplicates that transaction or weakens it.
//! * The real complaint is discoverability, not location. This module fixes
//!   that directly: the capture class carries a `governed_by` block naming
//!   the endpoint, the field, the required role and the audit table, plus the
//!   workspace's CURRENT effective setting — so an auditor reading
//!   "capture: enabled" can follow one hop to who turned it on.

use axum::{
    extract::{Extension, State},
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use clickhouse::Row;
use secureprompt_common::errors::ApiError;
use serde::{Deserialize, Serialize};
use sqlx::Row as _;
use uuid::Uuid;

use crate::{
    app_state::AppState,
    db::raw_capture_repo::RawCaptureRepository,
    http::{
        api_error_response,
        middleware::jwt_auth::{JwtAuthContext, UserRole},
        routes::dashboard::role::require_role,
    },
};

// ── Vocabulary ────────────────────────────────────────────────────────────

/// Values [`Encryption::at_rest`] can take. Every one of them is COMPUTED
/// from a count, never written down for a class.
mod at_rest {
    /// Every stored payload in this class matched the deployment's ciphertext
    /// envelope.
    pub const CIPHERTEXT: &str = "ciphertext";
    /// No stored payload matched. The class is supposed to hold ciphertext
    /// and does not.
    pub const PLAINTEXT: &str = "plaintext";
    /// Some rows matched and some did not, or the class holds fields in
    /// different states. `note` says which.
    pub const MIXED: &str = "mixed";
    /// Every payload is a one-way hash — not recoverable, not decryptable.
    pub const HASHED: &str = "hashed";
    /// Stored exactly as written. Not a defect by itself: an aggregate row
    /// count is not a secret.
    pub const PLAIN_BY_DESIGN: &str = "plaintext_by_design";
    /// Nothing stored for this workspace, so there is nothing to verify.
    /// Deliberately NOT reported as `ciphertext`: an empty class proves
    /// nothing about the write path.
    pub const EMPTY: &str = "empty";
}

/// Values [`Encryption::basis`] can contain — what a claim actually rests on.
mod basis {
    /// The write path encrypts or returns an error; it has no plaintext
    /// fallback. Verified by code review + the WS3-2/WS3-3 test suites, not
    /// by this request.
    pub const WRITE_PATH: &str = "write_path_encrypt_or_fail";
    /// This request performed a live encrypt→decrypt round trip against the
    /// configured KMS.
    pub const KMS_SELF_TEST: &str = "kms_self_test";
    /// This request performed a live encrypt→decrypt round trip against
    /// `SECUREPROMPT_PROVIDER_KEY`, the SEPARATE AES-256-GCM key that seals
    /// `providers.encrypted_credential`, and checked that it is not the
    /// all-zero fallback.
    ///
    /// Distinct from [`KMS_SELF_TEST`] on purpose. `providers` used to cite
    /// the KMS probe, which never touches this key: the credential is encrypted
    /// with `crypto::encrypt_aes_gcm` under `ProviderKeyConfig`, and
    /// `from_env_or_zero` substitutes 32 zero bytes when the variable is unset.
    /// Zero-key ciphertext still passes `pg_sealed`, because a shape check
    /// inspects the envelope and not the key — so the class could report
    /// `ciphertext`, cite a healthy KMS, and be sealed under a key published
    /// in this repository.
    pub const PROVIDER_KEY_SELF_TEST: &str = "provider_key_self_test";
    /// This request compared the bytes on disk against the envelope shape
    /// the configured KMS produces.
    pub const STORED_SHAPE: &str = "stored_payload_shape";
    /// The stored value is a one-way hash by construction (Argon2id / SHA-256).
    pub const ONE_WAY_HASH: &str = "one_way_hash";
    /// No claim beyond "stored as written".
    pub const AS_WRITTEN: &str = "stored_as_written";
}

/// Values [`Retention::mechanism`] can take. An auditor needs the MECHANISM,
/// not just the number: a `ClickHouse` TTL and a cron job fail in different
/// ways and on different timescales.
mod mechanism {
    pub const CH_TTL: &str = "clickhouse_ttl";
    pub const CH_TTL_AND_PURGE: &str = "clickhouse_ttl+worker_purge";
    pub const WORKER_PURGE: &str = "worker_purge";
    pub const REDIS_TTL: &str = "redis_ttl";
    /// The class has no storage of its own — a dbt VIEW — so rows leave it
    /// exactly when the source table's TTL removes them, and not otherwise.
    /// Distinct from [`NONE`]: nothing deletes anything HERE, but the data is
    /// not kept forever either, and conflating the two would misreport a view
    /// as an indefinite copy.
    pub const SOURCE_TTL: &str = "inherits_source_ttl";
    /// Nothing deletes rows in this class. Reported plainly rather than
    /// dressed up with the row's own `expires_at`, which is a validity check
    /// at read time and not a deletion.
    pub const NONE: &str = "none";
}

/// The databases dbt materialises into, from `+database` in
/// `secureprompt-analytics/dbt_project.yml`.
///
/// NONE of them is the gateway's own `CLICKHOUSE_DB`. Resolving a dbt relation
/// against `{CLICKHOUSE_DB}.<name>` — which this module did for the four marts
/// — cannot ever find it, on any deployment, however many times dbt has run,
/// so `row_count_status` was permanently `unavailable` and the code comment
/// above the marts blamed the deployment ("absent until `dbt build` has run")
/// for what was a wrong database name in the query.
mod dbt_db {
    pub const STAGING: &str = "secureprompt_staging";
    pub const INTERMEDIATE: &str = "secureprompt_intermediate";
    pub const MARTS: &str = "secureprompt_marts";
}

const CH_TTL_DETAIL: &str =
    "ClickHouse `TTL ... DELETE`, applied by a background merge — NOT at the \
     instant of expiry. Rows past their TTL remain on disk and readable until \
     the containing part is merged; the delay is unbounded for a part that \
     never merges. Treat the number as a policy ceiling, not a deletion \
     receipt.";

/// What the ciphertext shape check does and does not prove. Emitted in the
/// response so the reader gets the caveat with the claim, not from a doc.
const CIPHERTEXT_SHAPE_CLAIM: &str =
    "Stored payloads were compared against the envelope this deployment's KMS \
     produces: base64url (unpadded, >= 38 chars) for the file backend, a \
     `vault:` prefix for the Vault Transit backend. This DISPROVES plaintext \
     retention — the prose, JSON and identifiers this product stores all \
     contain characters the envelope cannot — but it does NOT prove the \
     payload decrypts under the current key, and a value that is itself a \
     long unpunctuated token would pass. The row's own `encrypted` column is \
     deliberately NOT consulted: it is written by the same code path as the \
     payload, so it can only repeat what that path believed.";

/// Marker encrypted and decrypted on every request to prove the KMS is live.
/// Contains no customer data by construction.
const KMS_PROBE: &[u8] = b"secureprompt-data-inventory-kms-self-test";

/// SQL fragment (`ClickHouse` dialect) testing whether `col` looks like the
/// deployment's ciphertext envelope. Written without `{}` so nothing in the
/// chain mistakes it for a query parameter.
///
/// # `ifNull(..., 1)` means "vacuously true", not "encrypted"
///
/// A NULL column has no bytes to compare, so this returns TRUE for it — which
/// is the only sane behaviour for a per-column fragment that callers AND
/// together across three optional columns. It is also a trap: a row whose
/// content columns are ALL NULL satisfies every conjunct and was counted as
/// `matching`, so a workspace holding nothing but such rows reported
/// `at_rest: ciphertext`, `rows_not_matching: 0` — the strongest verdict this
/// endpoint can give, resting on zero bytes of evidence.
///
/// Every caller must therefore gate on the row carrying SOMETHING. See
/// [`ch_capture_shape`], which counts `with_payload` separately and feeds THAT
/// to [`Encryption::sealed`], so the empty case reaches the `empty` verdict the
/// vocabulary already had for it.
fn ch_sealed(col: &str) -> String {
    format!(
        "ifNull((match({col}, '^[A-Za-z0-9_-]+$') AND length({col}) >= 38) \
         OR startsWith({col}, 'vault:'), 1)"
    )
}

/// Postgres dialect equivalent of [`ch_sealed`], for a NOT NULL column.
fn pg_sealed(col: &str) -> String {
    format!(
        "(({col} ~ '^[A-Za-z0-9_-]+$' AND length({col}) >= 38) \
         OR {col} LIKE 'vault:%')"
    )
}

// ── DTOs ──────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct Retention {
    /// Whole days, when the window is whole days. `null` when there is no
    /// deletion window at all, or when the window is sub-day (`window`
    /// always carries the human form).
    pub days: Option<i64>,
    pub window: String,
    /// One of [`mechanism`].
    pub mechanism: &'static str,
    pub mechanism_detail: String,
}

impl Retention {
    fn none(detail: &str) -> Self {
        Self {
            days: None,
            window: "none".to_owned(),
            mechanism: mechanism::NONE,
            mechanism_detail: detail.to_owned(),
        }
    }

    fn days(days: i64, mechanism: &'static str, detail: &str) -> Self {
        Self {
            days: Some(days),
            window: format!("{days} days"),
            mechanism,
            mechanism_detail: detail.to_owned(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ShapeVerification {
    /// The predicate that was actually run, in words.
    pub predicate: String,
    pub rows_matching: u64,
    pub rows_not_matching: u64,
}

#[derive(Debug, Serialize)]
pub struct Encryption {
    /// One of [`at_rest`], COMPUTED from `verification` where one exists.
    pub at_rest: &'static str,
    /// What the verdict rests on — see [`basis`].
    pub basis: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<ShapeVerification>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl Encryption {
    fn plain(note: &str) -> Self {
        Self {
            at_rest: at_rest::PLAIN_BY_DESIGN,
            basis: vec![basis::AS_WRITTEN],
            verification: None,
            note: Some(note.to_owned()),
        }
    }

    /// Verdict computed from a shape check over sealed payloads.
    fn sealed(predicate: String, total: u64, matching: u64, note: Option<&str>) -> Self {
        let not_matching = total.saturating_sub(matching);
        let verdict = if total == 0 {
            at_rest::EMPTY
        } else if not_matching == 0 {
            at_rest::CIPHERTEXT
        } else if matching == 0 {
            at_rest::PLAINTEXT
        } else {
            at_rest::MIXED
        };
        Self {
            at_rest: verdict,
            basis: vec![basis::WRITE_PATH, basis::KMS_SELF_TEST, basis::STORED_SHAPE],
            verification: Some(ShapeVerification {
                predicate,
                rows_matching: matching,
                rows_not_matching: not_matching,
            }),
            note: note.map(str::to_owned),
        }
    }

    /// Verdict computed from a shape check over one-way hashes.
    fn hashed(predicate: String, total: u64, matching: u64, note: &str) -> Self {
        let not_matching = total.saturating_sub(matching);
        let verdict = if total == 0 {
            at_rest::EMPTY
        } else if not_matching == 0 {
            at_rest::HASHED
        } else {
            at_rest::MIXED
        };
        Self {
            at_rest: verdict,
            basis: vec![basis::ONE_WAY_HASH, basis::STORED_SHAPE],
            verification: Some(ShapeVerification {
                predicate,
                rows_matching: matching,
                rows_not_matching: not_matching,
            }),
            note: Some(note.to_owned()),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct GovernedBy {
    pub endpoint: &'static str,
    pub field: &'static str,
    pub role_required: &'static str,
    pub audit_table: &'static str,
}

#[derive(Debug, Serialize)]
pub struct ArtifactClass {
    /// Stable identifier. For database-backed classes this IS the table name,
    /// so `tests/data_inventory.rs` can derive the expected set straight from
    /// the migrations.
    pub class: String,
    pub store: &'static str,
    pub location: String,
    pub description: &'static str,
    /// `user_content` | `derived_metadata` | `credential_material` |
    /// `audit_trail` | `configuration` | `operational`
    pub sensitivity: &'static str,
    /// Live count for THIS workspace. `null` only when the store could not
    /// answer, in which case `row_count_status` says why — never a guess.
    pub row_count: Option<u64>,
    /// `counted` | `unavailable`
    pub row_count_status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub row_count_detail: Option<String>,
    pub encryption: Encryption,
    pub retention: Retention,
    /// Present on classes whose retention is switched by a control elsewhere.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub governed_by: Option<GovernedBy>,
    /// Present on classes that are off unless opted into.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct UnenumerableClass {
    pub class: &'static str,
    pub store: &'static str,
    pub location: &'static str,
    pub description: &'static str,
    /// WHY no per-workspace count is possible. An auditor acts on this, so it
    /// names the mechanism, not just the fact.
    pub reason: &'static str,
    /// `not_possible` | `whole_store_only` | `not_applicable`
    pub per_workspace_erasure: &'static str,
    /// Always `null`. Present so the field's absence is never mistaken for a
    /// count of zero.
    pub row_count: Option<u64>,
    pub encryption: Encryption,
    pub retention: Retention,
}

#[derive(Debug, Serialize)]
pub struct EncryptionBasis {
    /// `file` | `vault` | whatever `KMS_BACKEND` names.
    pub kms_backend: String,
    /// `ok` | `failed`
    pub kms_self_test: &'static str,
    pub kms_self_test_detail: String,
    /// `ok` | `failed`. The SECOND key this deployment encrypts with, probed
    /// separately because it is a separate key — see
    /// [`basis::PROVIDER_KEY_SELF_TEST`].
    pub provider_key_self_test: &'static str,
    pub provider_key_self_test_detail: String,
    pub ciphertext_shape_claim: &'static str,
}

#[derive(Debug, Serialize)]
pub struct DataInventoryResponse {
    pub schema_version: u32,
    pub workspace_id: Uuid,
    pub generated_at: DateTime<Utc>,
    pub encryption_basis: EncryptionBasis,
    pub artifacts: Vec<ArtifactClass>,
    pub not_enumerable: Vec<UnenumerableClass>,
    pub caveats: Vec<&'static str>,
}

// ── Router ────────────────────────────────────────────────────────────────

pub fn routes() -> Router<AppState> {
    Router::new().route("/", get(get_data_inventory))
}

// ── ClickHouse helpers ────────────────────────────────────────────────────

#[derive(Row, Deserialize)]
struct ShapeCount {
    /// Every row for this workspace — what `row_count` reports.
    total: u64,
    /// Rows carrying at least one non-NULL content column, i.e. rows there is
    /// anything to verify about. The DENOMINATOR of the encryption verdict.
    with_payload: u64,
    matching: u64,
}

/// `SELECT count()` for one workspace against one table.
///
/// `Err` carries the store's own message so `row_count_status: unavailable`
/// can explain itself rather than showing a bare `null`. The workspace id is
/// interpolated rather than bound: it comes from a verified JWT and is a
/// `Uuid`, so it is structurally hex-and-dashes, and `toUUID()` rejects
/// anything else outright. Same pattern as `requests.rs` and the worker's
/// retention purge.
async fn ch_count(client: &clickhouse::Client, table: &str, ws: Uuid) -> Result<u64, String> {
    client
        .query(&format!(
            "SELECT count() FROM {table} WHERE workspace_id = toUUID('{ws}')"
        ))
        .fetch_one::<u64>()
        .await
        .map_err(|e| e.to_string())
}

/// Count rows AND, in the same pass, how many of them CARRY a payload and how
/// many of those are shaped like this deployment's ciphertext envelope.
///
/// A row counts as sealed only if it carries at least one content column and
/// EVERY non-NULL one on it matches. The presence gate is load-bearing: without
/// it, `ch_sealed`'s `ifNull(..., 1)` makes an all-NULL row satisfy all three
/// conjuncts, and a workspace holding only payload-free rows reported
/// `ciphertext` on no evidence at all.
async fn ch_capture_shape(client: &clickhouse::Client, ws: Uuid) -> Result<ShapeCount, String> {
    let has_payload = "(raw_prompt IS NOT NULL OR raw_response IS NOT NULL \
                        OR restored_response IS NOT NULL)";
    let sealed = format!(
        "{} AND {} AND {}",
        ch_sealed("raw_prompt"),
        ch_sealed("raw_response"),
        ch_sealed("restored_response"),
    );
    client
        .query(&format!(
            "SELECT count() AS total, \
                    countIf({has_payload}) AS with_payload, \
                    countIf({has_payload} AND {sealed}) AS matching \
             FROM request_content_captures WHERE workspace_id = toUUID('{ws}')"
        ))
        .fetch_one::<ShapeCount>()
        .await
        .map_err(|e| e.to_string())
}

/// Say WHAT is now unknown and WHICH relation could not be read, without
/// echoing the store's own message.
///
/// `clickhouse::error::Error::to_string()` carries ClickHouse's server message
/// verbatim, and this module interpolated it into `row_count_detail` — a field
/// in the RESPONSE BODY — at three sites. `leak_report::ch_err` was fixed for
/// exactly this in 42c99f4 and these were missed, on the reasoning that every
/// query here selects aggregates so no row data can appear. That is a statement
/// about the SELECT list, and an exception is not bounded by it. Measured, on a
/// deployment where dbt has not run — which is the DEFAULT state, since nothing
/// in this product schedules a build:
///
/// ```text
/// the store did not answer, so no count is reported rather than a zero:
/// bad response: Code: 60. DB::Exception: Unknown table expression identifier
/// 'secureprompt_marts.mart_cost_by_model' in scope SELECT count() FROM
/// secureprompt_marts.mart_cost_by_model WHERE workspace_id =
/// toUUID('6c2705e7-a1b9-477e-9d8d-76f13bc9dd64'). (UNKNOWN_TABLE)
/// ```
///
/// — the whole statement and the tenancy predicate's bound value, handed to an
/// HTTP caller. Other error classes (`TYPE_MISMATCH`, `CANNOT_PARSE_*`) quote
/// the offending value instead.
///
/// `table` is safe to interpolate and is deliberately kept: every caller passes
/// a `&'static str` or a `format!` over the [`dbt_db`] constants, all literals
/// in this binary, and an operator debugging a gap needs to know which relation
/// was unreadable. The store's message goes to `tracing::error!`, where it is
/// subject to the deployment's log handling instead.
///
/// `tests/data_inventory.rs::an_unreachable_store_does_not_echo_the_stores_own_message`
/// executes both the healthy path (unbuilt dbt relations) and a database that
/// does not exist, and asserts no `DB::Exception`, no SQL and no bound
/// workspace id reaches the body.
fn unavailable(table: &str, consequence: &str, error: &str) -> String {
    tracing::error!(
        table,
        error,
        "data-inventory count failed; the store's message is logged here and \
         deliberately NOT returned to the caller"
    );
    format!(
        "{consequence} Reading `{table}` failed. The store's own error message \
         is in the gateway log, not in this response, because a database \
         exception quotes the statement that provoked it — schema, identifiers, \
         and for some error classes the value it choked on."
    )
}

/// The `consequence` sentence for a plain `count()` that did not answer.
const NO_COUNT: &str = "the store did not answer, so no count is reported rather than a zero.";

/// Turn a count result into the three reporting fields, so an unreachable
/// store degrades into a stated gap instead of a fabricated zero.
fn counted(
    table: &str,
    result: &Result<u64, String>,
) -> (Option<u64>, &'static str, Option<String>) {
    match result {
        Ok(n) => (Some(*n), "counted", None),
        Err(e) => (None, "unavailable", Some(unavailable(table, NO_COUNT, e))),
    }
}

// ── Postgres counts ───────────────────────────────────────────────────────

/// Every Postgres number this endpoint reports, in one round trip.
struct PgCounts {
    row: sqlx::postgres::PgRow,
}

impl PgCounts {
    fn n(&self, column: &str) -> u64 {
        let raw: i64 = self.row.try_get(column).unwrap_or(0);
        u64::try_from(raw).unwrap_or(0)
    }
}

/// Read every per-workspace Postgres count.
///
/// Runs inside a transaction that sets `app.current_workspace_id` first.
/// `api_keys`, `providers`, `models`, `policy_rules`, `audit_events_meta`,
/// `refresh_tokens` and `workspace_budgets` carry FORCE ROW LEVEL SECURITY
/// with `USING (workspace_id = current_setting('app.current_workspace_id',
/// true)::uuid)`. When that GUC is unset the predicate is NULL for every row,
/// so a bare count returns ZERO — see the header of migration 020, which
/// measured exactly that. It looks fine on developer machines today only
/// because the compose role is a superuser and superusers bypass RLS; under
/// the DB role-split on this project's backlog it stops being true, and an
/// inventory that silently reports 0 `api_keys` is precisely the false
/// assurance this endpoint exists to prevent.
///
/// `set_config(..., true)` is transaction-LOCAL, so the setting cannot leak
/// onto a pooled connection and follow some later request.
///
/// The tenancy predicate is bound into every subquery as well. RLS is defence
/// in depth here, not the filter: Global Constraint 3 — a handler guard over
/// an unfiltered query is not a fix.
async fn postgres_counts(pool: &sqlx::PgPool, ws: Uuid) -> Result<PgCounts, ApiError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

    sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
        .bind(ws.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

    let sql = format!(
        "SELECT
           (SELECT count(*) FROM workspaces WHERE id = $1) AS c_workspaces,
           (SELECT count(*) FROM users WHERE workspace_id = $1) AS c_users,
           (SELECT count(*) FROM users WHERE workspace_id = $1
              AND password_hash LIKE '$argon2%') AS v_users,
           (SELECT count(*) FROM users WHERE workspace_id = $1
              AND totp_secret_encrypted IS NOT NULL) AS c_users_totp,
           (SELECT count(*) FROM api_keys WHERE workspace_id = $1) AS c_api_keys,
           (SELECT count(*) FROM api_keys WHERE workspace_id = $1
              AND key_hash ~ '^[0-9a-f]+$' AND length(key_hash) = 64) AS v_api_keys,
           (SELECT count(*) FROM providers WHERE workspace_id = $1) AS c_providers,
           (SELECT count(*) FROM providers WHERE workspace_id = $1
              AND encrypted_credential IS NOT NULL) AS c_providers_cred,
           (SELECT count(*) FROM providers WHERE workspace_id = $1
              AND encrypted_credential IS NOT NULL
              AND {cred_sealed}) AS v_providers,
           (SELECT count(*) FROM models WHERE workspace_id = $1) AS c_models,
           (SELECT count(*) FROM policy_rules WHERE workspace_id = $1) AS c_policy_rules,
           (SELECT count(*) FROM audit_events_meta WHERE workspace_id = $1) AS c_audit_events_meta,
           (SELECT count(*) FROM refresh_tokens WHERE workspace_id = $1) AS c_refresh_tokens,
           (SELECT count(*) FROM refresh_tokens WHERE workspace_id = $1
              AND token_hash ~ '^[0-9a-f]+$' AND length(token_hash) = 64) AS v_refresh_tokens,
           (SELECT count(*) FROM workspace_budgets WHERE workspace_id = $1) AS c_workspace_budgets,
           (SELECT count(*) FROM token_vault_entries WHERE workspace_id = $1) AS c_token_vault_entries,
           (SELECT count(*) FROM token_vault_entries WHERE workspace_id = $1
              AND {vault_sealed}) AS v_token_vault_entries,
           (SELECT count(*) FROM workspace_secure_mode WHERE workspace_id = $1) AS c_workspace_secure_mode,
           (SELECT count(*) FROM user_backup_codes bc
              JOIN users u ON u.id = bc.user_id
              WHERE u.workspace_id = $1) AS c_user_backup_codes,
           (SELECT count(*) FROM user_backup_codes bc
              JOIN users u ON u.id = bc.user_id
              WHERE u.workspace_id = $1 AND bc.code_hash LIKE '$argon2%') AS v_user_backup_codes,
           (SELECT count(*) FROM workspace_sidecar_policy WHERE workspace_id = $1) AS c_workspace_sidecar_policy,
           (SELECT count(*) FROM workspace_raw_capture WHERE workspace_id = $1) AS c_workspace_raw_capture,
           (SELECT count(*) FROM raw_capture_audit WHERE workspace_id = $1) AS c_raw_capture_audit,
           (SELECT count(*) FROM retention_purge_audit WHERE workspace_id = $1) AS c_retention_purge_audit",
        cred_sealed = pg_sealed("encrypted_credential"),
        vault_sealed = pg_sealed("mapping_ciphertext"),
    );

    let row = sqlx::query(&sql)
        .bind(ws)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

    tx.commit()
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

    Ok(PgCounts { row })
}

// ── Handler ───────────────────────────────────────────────────────────────

/// `GET /v1/data-inventory` — every class of stored artifact for the caller's
/// workspace.
///
/// ADMIN. This used to say "any authenticated role — the payload carries no
/// content and no credential material, and a viewer who cannot see what is
/// retained about them is the problem this endpoint exists to solve." The
/// premise is right and the conclusion was wrong. It carries no credential
/// VALUES, but it carries live row counts for every store, which credential
/// classes hold verified ciphertext and which report `plaintext` or `mixed`,
/// the deployment's KMS backend and whether its self-test passed just now —
/// which is a target list for anyone holding a low-privilege token.
///
/// The subject-access argument survives the gate: an individual asking what is
/// retained about them is asking a workspace ADMIN, who can now answer with
/// this document. `UserRole::Admin` matches every other workspace-wide
/// dashboard route, and matches the `role_required: "admin"` this response
/// itself advertises for the raw-capture control.
#[allow(clippy::too_many_lines)]
async fn get_data_inventory(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
) -> Result<Json<DataInventoryResponse>, axum::response::Response> {
    require_role(&ctx, UserRole::Admin).map_err(api_error_response)?;
    let ws = ctx.workspace_id.0;
    let ch = state.dashboard_reader.client();
    let ch_db = state.config.clickhouse.database.clone();

    // ---- Is the KMS actually working, right now? --------------------------
    let (kms_self_test, kms_self_test_detail) = kms_self_test(state.kms.as_ref()).await;
    let kms_backend = std::env::var("KMS_BACKEND").unwrap_or_else(|_| "file".to_owned());
    // The SECOND key. `providers.encrypted_credential` never goes through the
    // KMS — see `provider_key_self_test`.
    let (provider_key_self_test, provider_key_self_test_detail) = provider_key_self_test();

    // ---- Live counts ------------------------------------------------------
    let pg = postgres_counts(&state.db, ws)
        .await
        .map_err(api_error_response)?;

    let capture_settings = RawCaptureRepository::new(state.db.clone())
        .get_effective(ctx.workspace_id)
        .await
        .map_err(api_error_response)?;

    let ch_request_events = ch_count(ch, "request_events", ws).await;
    let ch_policy_events = ch_count(ch, "policy_events", ws).await;
    let ch_token_usage = ch_count(ch, "token_usage", ws).await;
    let ch_latency_samples = ch_count(ch, "latency_samples", ws).await;
    let ch_detection_counts = ch_count(ch, "detection_class_counts", ws).await;
    let ch_hourly_cost = ch_count(ch, "mv_hourly_cost_agg", ws).await;
    let ch_p95_latency = ch_count(ch, "mv_p95_latency_agg", ws).await;
    let ch_captures = ch_capture_shape(ch, ws).await;

    // Rows written before WS3-1 still carry plaintext in the three columns
    // migrations 004/005 put on `request_events`. The writer sends NULL for
    // them now, but an auditor needs to know the historical rows exist rather
    // than reading "request_events: derived metadata" and stopping.
    let ch_legacy_plaintext = ch
        .query(&format!(
            "SELECT count() FROM request_events \
             WHERE workspace_id = toUUID('{ws}') \
               AND (raw_prompt IS NOT NULL OR raw_response IS NOT NULL \
                    OR restored_response IS NOT NULL)"
        ))
        .fetch_one::<u64>()
        .await
        .map_err(|e| e.to_string());

    let mut artifacts: Vec<ArtifactClass> = Vec::new();

    // ── ClickHouse ────────────────────────────────────────────────────────
    {
        let (row_count, row_count_status, row_count_detail) =
            counted("request_events", &ch_request_events);
        let legacy_note = match &ch_legacy_plaintext {
            Ok(0) => "No row for this workspace carries a legacy plaintext content column. \
                      `redacted_prompt` holds placeholder-safe text and is NULL whenever NER \
                      coverage was lost (WS2-6), so it is not a plaintext channel."
                .to_owned(),
            Ok(n) => format!(
                "{n} row(s) for this workspace still carry PLAINTEXT content in the \
                 `raw_prompt` / `raw_response` / `restored_response` columns that migrations \
                 004 and 005 put on this table. They were written before WS3-1 made capture \
                 opt-in; the writer now always sends NULL. They are deleted by this table's \
                 90-day TTL and by nothing else."
            ),
            Err(e) => unavailable(
                "request_events (legacy plaintext column scan)",
                "the legacy-plaintext column scan did not complete, so this class's \
                 plaintext exposure is UNKNOWN rather than zero.",
                e,
            ),
        };
        artifacts.push(ArtifactClass {
            class: "request_events".to_owned(),
            store: "clickhouse",
            location: format!("{ch_db}.request_events"),
            description: "One analytics row per gateway request: provider, model, action, \
                          token counts, cost, actor, client IP and user agent, plus the \
                          placeholder-safe `redacted_prompt`.",
            sensitivity: "derived_metadata",
            row_count,
            row_count_status,
            row_count_detail,
            encryption: Encryption {
                at_rest: at_rest::PLAIN_BY_DESIGN,
                basis: vec![basis::AS_WRITTEN],
                verification: None,
                note: Some(legacy_note),
            },
            retention: Retention::days(90, mechanism::CH_TTL, CH_TTL_DETAIL),
            governed_by: None,
            enabled: None,
        });
    }

    {
        let (total, with_payload, matching, status, detail) = match &ch_captures {
            Ok(counts) => (
                counts.total,
                counts.with_payload,
                counts.matching,
                "counted",
                None,
            ),
            Err(e) => (
                0,
                0,
                0,
                "unavailable",
                Some(unavailable("request_content_captures", NO_COUNT, e)),
            ),
        };
        let encryption = if status == "counted" {
            // `with_payload`, NOT `total`: a row whose three content columns
            // are all NULL has nothing to verify, and counting it as evidence
            // let an empty class report `ciphertext`.
            Encryption::sealed(
                format!(
                    "of {total} row(s), the {with_payload} carrying at least one \
                     content column were checked: every non-NULL raw_prompt / \
                     raw_response / restored_response matches the deployment's KMS \
                     envelope. Rows with no content column at all are NOT counted as \
                     evidence — there is nothing on them to verify."
                ),
                with_payload,
                matching,
                Some(CIPHERTEXT_SHAPE_CLAIM),
            )
        } else {
            Encryption {
                at_rest: at_rest::EMPTY,
                basis: vec![basis::WRITE_PATH],
                verification: None,
                note: Some(
                    "the store did not answer, so the bytes on disk were not \
                     inspected and no encryption verdict is claimed"
                        .to_owned(),
                ),
            }
        };
        artifacts.push(ArtifactClass {
            class: "request_content_captures".to_owned(),
            store: "clickhouse",
            location: format!("{ch_db}.request_content_captures"),
            description: "OPT-IN capture of the raw user message, the raw upstream response \
                          and the PII-restored response. This is the only store in the \
                          product that holds un-redacted request content, and it is OFF for \
                          every workspace that has not explicitly enabled it.",
            sensitivity: "user_content",
            row_count: if status == "counted" {
                Some(total)
            } else {
                None
            },
            row_count_status: status,
            row_count_detail: detail,
            encryption,
            retention: Retention::days(
                i64::from(capture_settings.retention_days),
                mechanism::CH_TTL_AND_PURGE,
                &format!(
                    "Two mechanisms. (1) {CH_TTL_DETAIL} `expires_at` is stamped at INSERT \
                     from the workspace's retention at that moment, so LOWERING retention \
                     does not shorten rows already on disk. (2) The worker's `retention.purge` \
                     job (daily 04:00) re-derives the boundary from the CURRENT setting and \
                     issues an explicit DELETE, which is what makes a lowered window take \
                     effect; it writes a `retention_purge_audit` row per run per workspace, \
                     including a recount after deleting."
                ),
            ),
            governed_by: Some(GovernedBy {
                endpoint: "PUT /v1/secure-mode",
                field: "capture_raw_content",
                role_required: "admin",
                audit_table: "raw_capture_audit",
            }),
            enabled: Some(capture_settings.enabled),
        });
    }

    for (class, description, result, days) in [
        (
            "policy_events",
            "One row per policy rule that matched a request: rule id, rule name, action, \
             dry-run flag. No request content.",
            &ch_policy_events,
            90_i64,
        ),
        (
            "token_usage",
            "Per workspace / model / day token and cost totals.",
            &ch_token_usage,
            365,
        ),
        (
            "latency_samples",
            "Per-request latency and time-to-first-byte measurements.",
            &ch_latency_samples,
            30,
        ),
        (
            "detection_class_counts",
            "WS3-6, the shadow-mode leak report's source. One row per request \
             per ENTITY CLASS: how many distinct entities of that class the \
             detection pass found, plus the destination model and the actor \
             (user id, API key name) already recorded on request_events. NO \
             DETECTED VALUE IS STORED — `entity_class` can only ever hold one \
             of the class-name string literals compiled into the gateway, or \
             the literal `other`, because a class arriving from the ML sidecar \
             is mapped through an allowlist before it is written.",
            &ch_detection_counts,
            90,
        ),
    ] {
        let (row_count, row_count_status, row_count_detail) = counted(class, result);
        let extra = match class {
            "token_usage" => Some(
                "SummingMergeTree: `count()` is the number of PARTS rows currently on disk, \
                 which is >= the number of logical (workspace, model, date) keys until a \
                 merge collapses them."
                    .to_owned(),
            ),
            "detection_class_counts" => Some(
                "Rows are written ONLY when something was detected, so `count()` here is a \
                 count of (request, class) pairs and NOT a request count. `api_key_name` is \
                 operator-chosen free text copied from request_events and may name a person \
                 — it is not detected PII, but it is personal data for an erasure request. \
                 The 90-day window is deliberately identical to request_events': this table \
                 is derived from the same requests, so it must not outlive them the way the \
                 mv_* aggregates and the dbt marts below do."
                    .to_owned(),
            ),
            _ => None,
        };
        artifacts.push(ArtifactClass {
            class: class.to_owned(),
            store: "clickhouse",
            location: format!("{ch_db}.{class}"),
            description,
            sensitivity: "derived_metadata",
            row_count,
            row_count_status,
            row_count_detail,
            encryption: Encryption {
                at_rest: at_rest::PLAIN_BY_DESIGN,
                basis: vec![basis::AS_WRITTEN],
                verification: None,
                note: extra,
            },
            retention: Retention::days(days, mechanism::CH_TTL, CH_TTL_DETAIL),
            governed_by: None,
            enabled: None,
        });
    }

    for (class, description, result) in [
        (
            "mv_hourly_cost_agg",
            "Materialized-view target: hourly cost aggregate per workspace and model, \
             maintained by `mv_hourly_cost` on every insert into request_events.",
            &ch_hourly_cost,
        ),
        (
            "mv_p95_latency_agg",
            "Materialized-view target: hourly p95 latency aggregate per workspace and \
             model, maintained by `mv_p95_latency` on every insert into latency_samples.",
            &ch_p95_latency,
        ),
    ] {
        let (row_count, row_count_status, row_count_detail) = counted(class, result);
        artifacts.push(ArtifactClass {
            class: class.to_owned(),
            store: "clickhouse",
            location: format!("{ch_db}.{class}"),
            description,
            sensitivity: "derived_metadata",
            row_count,
            row_count_status,
            row_count_detail,
            encryption: Encryption::plain(
                "Aggregate state only — sums and quantile sketches keyed by workspace, model \
                 and hour. No request content, no identifier.",
            ),
            retention: Retention::none(
                "NO TTL. `001_analytics_schema.sql` gives these two aggregate tables no TTL \
                 clause, so the hourly cost and latency shape of a workspace's traffic \
                 OUTLIVES the 90-day and 30-day windows on the source tables and is kept \
                 indefinitely. They contain no content and no identifier, but an auditor \
                 asking 'is everything gone after 90 days' must be told these are not.",
            ),
            governed_by: None,
            enabled: None,
        });
    }

    // ── dbt staging: VIEWS over the source tables ─────────────────────────
    //
    // A view stores no bytes, so it is not an additional copy — but it IS a
    // relation dbt materialises, in a database of its own, and an auditor
    // enumerating what exists will find it. Omitting it because "it's only a
    // view" is the same silence this endpoint exists to prevent.
    for (class, source, description) in [
        (
            "stg_request_events",
            "request_events",
            "dbt staging model: a VIEW, 1:1 with `request_events`, coalescing the \
             nullable token columns to 0 for the layers above. It selects no \
             content column — not `redacted_prompt`, not the legacy raw columns.",
        ),
        (
            "stg_policy_events",
            "policy_events",
            "dbt staging model: a VIEW, 1:1 with `policy_events`. Rule id, rule \
             name, action, dry-run flag.",
        ),
    ] {
        let relation = format!("{}.{class}", dbt_db::STAGING);
        let result = ch_count(ch, &relation, ws).await;
        let (row_count, row_count_status, row_count_detail) = counted(&relation, &result);
        artifacts.push(ArtifactClass {
            class: class.to_owned(),
            store: "clickhouse",
            location: format!("{}.{class}", dbt_db::STAGING),
            description,
            sensitivity: "derived_metadata",
            row_count,
            row_count_status,
            row_count_detail,
            encryption: Encryption::plain(
                "A VIEW has no bytes of its own — it is a saved query, so the count \
                 above is the SOURCE table's rows seen through it, not a second \
                 copy. `secureprompt-analytics/dbt_project.yml` materialises the \
                 staging layer as `view`.",
            ),
            retention: Retention {
                days: Some(90),
                window: "90 days".to_owned(),
                mechanism: mechanism::SOURCE_TTL,
                mechanism_detail: format!(
                    "Nothing deletes rows HERE, and nothing needs to: a view shows \
                     whatever `{source}` currently holds, so a row leaves it at the \
                     moment that table's 90-day TTL removes it. {CH_TTL_DETAIL} \
                     This is reported as an inherited window rather than as `none` \
                     because `none` would read as an indefinite copy, which a view \
                     is not."
                ),
            },
            governed_by: None,
            enabled: None,
        });
    }

    // ── dbt intermediate: a ROW-LEVEL copy that outlives its source ───────
    {
        let relation = format!("{}.int_requests_enriched", dbt_db::INTERMEDIATE);
        let result = ch_count(ch, &relation, ws).await;
        let (row_count, row_count_status, row_count_detail) = counted(&relation, &result);
        artifacts.push(ArtifactClass {
            class: "int_requests_enriched".to_owned(),
            store: "clickhouse",
            location: format!("{}.int_requests_enriched", dbt_db::INTERMEDIATE),
            description:
                "dbt intermediate model: ONE ROW PER GATEWAY REQUEST, copied out of \
                 `request_events` with the usage date and hour precomputed. Unlike \
                 the marts below it is NOT an aggregate — request_id, workspace_id, \
                 provider, model, final action, every token count and the cost are \
                 carried per request.",
            sensitivity: "derived_metadata",
            row_count,
            row_count_status,
            row_count_detail,
            encryption: Encryption::plain(
                "Stored as written, and it carries `model` as the CALLER supplied it: \
                 `resolve_model` passes an uncatalogued model name through to the \
                 provider verbatim, and `request_events` records that raw string, so \
                 this copy holds it too. The leak report's own `model` column is \
                 bounded to registered names (see `detection_class_counts`); this one \
                 is not, because per-model cost for a passthrough workspace depends \
                 on the raw name. No prompt or response content is selected into this \
                 model.",
            ),
            retention: Retention::none(
                "NO TTL — `materialized='table'`, `MergeTree()`, no TTL clause \
                 (secureprompt-analytics/models/intermediate/int_requests_enriched.sql). \
                 This is the sharpest retention gap in the inventory, because the copy \
                 is PER REQUEST rather than aggregated: once `request_events`' 90-day \
                 TTL has removed the source rows, a row-level record of every request \
                 this workspace made survives here. It is replaced wholesale by the \
                 next `dbt build`, which rebuilds it from whatever `request_events` \
                 still holds — so a deployment that stops running dbt keeps the old \
                 rows indefinitely, and nothing in this product schedules a build.",
            ),
            governed_by: None,
            enabled: None,
        });
    }

    // dbt marts, in the database dbt actually builds into — see [`dbt_db`].
    //
    // These four resolved to `{CLICKHOUSE_DB}.mart_*` until this was fixed,
    // which is a table that exists on no deployment, so `row_count_status`
    // was permanently `unavailable`. The comment that stood here said the
    // marts were "absent until `dbt build` has run" — true of a fresh install
    // and NOT the reason these were uncountable, so a reader chasing the
    // missing numbers was pointed at their own pipeline instead of at this
    // query. `unavailable` is now a real answer about a real relation: it
    // means dbt has genuinely not built this mart yet.
    for (class, description) in [
        (
            "mart_usage_daily",
            "dbt mart: daily token and cost totals per workspace and model.",
        ),
        (
            "mart_cost_by_model",
            "dbt mart: daily cost per model with 7-day and 30-day rolling windows.",
        ),
        (
            "mart_policy_violations",
            "dbt mart: policy violation counts per rule and day.",
        ),
        (
            "mart_latency_pctiles",
            "dbt mart: latency and TTFT percentiles per model and day.",
        ),
    ] {
        let relation = format!("{}.{class}", dbt_db::MARTS);
        let result = ch_count(ch, &relation, ws).await;
        let (row_count, row_count_status, row_count_detail) = counted(&relation, &result);
        artifacts.push(ArtifactClass {
            class: class.to_owned(),
            store: "clickhouse",
            location: format!("{}.{class}", dbt_db::MARTS),
            description,
            sensitivity: "derived_metadata",
            row_count,
            row_count_status,
            row_count_detail,
            encryption: Encryption::plain("Aggregate rows only. No request content."),
            retention: Retention::none(
                "NO TTL. dbt materialises these as plain MergeTree tables with no TTL \
                 clause (see secureprompt-analytics/models/marts/*.sql), and a full \
                 rebuild replaces rather than expires. Aggregates therefore survive the \
                 expiry of the raw rows they were derived from.",
            ),
            governed_by: None,
            enabled: None,
        });
    }

    // ── Postgres ──────────────────────────────────────────────────────────
    artifacts.push(ArtifactClass {
        class: "token_vault_entries".to_owned(),
        store: "postgres",
        location: "token_vault_entries".to_owned(),
        description: "Placeholder → original mappings produced by \
                      POST /v1/secure-mode/tokenize, so the caller can later detokenize. \
                      The originals are the un-redacted PII the caller asked SecurePrompt \
                      to protect.",
        sensitivity: "user_content",
        row_count: Some(pg.n("c_token_vault_entries")),
        row_count_status: "counted",
        row_count_detail: None,
        encryption: Encryption::sealed(
            "mapping_ciphertext matches the deployment's KMS envelope".to_owned(),
            pg.n("c_token_vault_entries"),
            pg.n("v_token_vault_entries"),
            Some(CIPHERTEXT_SHAPE_CLAIM),
        ),
        retention: Retention::days(
            1,
            mechanism::WORKER_PURGE,
            "`expires_at` defaults to NOW() + 24 hours (migration 008) and the read path \
             filters on it, so an expired entry stops resolving immediately. The ROWS are \
             deleted by the worker's `retention.purge` job (daily 04:00), which writes a \
             `retention_purge_audit` record with the cutoff, the deleted range, and a \
             recount taken after the delete. Before WS3-4 that job was a no-op stub and \
             these rows accumulated forever.",
        ),
        governed_by: None,
        enabled: None,
    });

    artifacts.push(ArtifactClass {
        class: "users".to_owned(),
        store: "postgres",
        location: "users".to_owned(),
        description: "Workspace members: email, name, position, role, password hash, TOTP \
                      enrolment state, device MAC.",
        sensitivity: "credential_material",
        row_count: Some(pg.n("c_users")),
        row_count_status: "counted",
        row_count_detail: None,
        encryption: {
            let mut enc = Encryption::hashed(
                "password_hash begins with an Argon2 identifier".to_owned(),
                pg.n("c_users"),
                pg.n("v_users"),
                "",
            );
            // The class holds fields in more than one state, so the verdict is
            // `mixed` regardless of how the password check came out — stating
            // `hashed` alone would imply the email is hashed too.
            if pg.n("c_users") > 0 {
                enc.at_rest = at_rest::MIXED;
            }
            enc.basis = vec![
                basis::ONE_WAY_HASH,
                basis::WRITE_PATH,
                basis::KMS_SELF_TEST,
                basis::STORED_SHAPE,
            ];
            enc.note = Some(format!(
                "Three states in one table. `password_hash` is Argon2id (one-way, verified \
                 above). `totp_secret_encrypted` is KMS ciphertext — {} of {} rows currently \
                 hold one. `email`, `first_name`, `last_name`, `position` and `device_mac` \
                 are stored in the clear; they are directory data, not secrets, but they ARE \
                 personal data for a GDPR/erasure request.",
                pg.n("c_users_totp"),
                pg.n("c_users"),
            ));
            enc
        },
        retention: Retention::none(
            "Rows live until the account is deleted. Deleting a workspace cascades to its \
             users; there is no time-based expiry and none is intended.",
        ),
        governed_by: None,
        enabled: None,
    });

    artifacts.push(ArtifactClass {
        class: "refresh_tokens".to_owned(),
        store: "postgres",
        location: "refresh_tokens".to_owned(),
        description: "One row per refresh token ever issued to a member of this workspace, \
                      including rotated and revoked predecessors.",
        sensitivity: "credential_material",
        row_count: Some(pg.n("c_refresh_tokens")),
        row_count_status: "counted",
        row_count_detail: None,
        encryption: Encryption::hashed(
            "token_hash is 64 lowercase hex characters (SHA-256)".to_owned(),
            pg.n("c_refresh_tokens"),
            pg.n("v_refresh_tokens"),
            "SHA-256 rather than Argon2 by design: the refresh path looks this value up on \
             every /v1/auth/refresh and a memory-hard hash there is a self-inflicted denial \
             of service. The stored value is not reversible.",
        ),
        retention: Retention::none(
            "NOTHING DELETES THESE ROWS. `expires_at` and `revoked_at` are honoured at READ \
             time, so an expired or rotated token stops working — but the row itself is kept \
             forever, one per refresh per user, and `retention.purge` does not cover this \
             table. Reported as `none` deliberately: `expires_at` is a validity check, not a \
             deletion, and presenting it as a retention window would be a false assurance.",
        ),
        governed_by: None,
        enabled: None,
    });

    artifacts.push(ArtifactClass {
        class: "api_keys".to_owned(),
        store: "postgres",
        location: "api_keys".to_owned(),
        description: "Gateway API keys for this workspace, including rotation successors.",
        sensitivity: "credential_material",
        row_count: Some(pg.n("c_api_keys")),
        row_count_status: "counted",
        row_count_detail: None,
        encryption: Encryption::hashed(
            "key_hash is 64 lowercase hex characters (SHA-256)".to_owned(),
            pg.n("c_api_keys"),
            pg.n("v_api_keys"),
            "The key itself is shown once at creation and never stored. `name`, \
             `key_prefix` and the assignment columns are plaintext.",
        ),
        retention: Retention::none(
            "Revocation sets `revoked_at`; the row is kept so an audit trail survives. \
             Nothing deletes it.",
        ),
        governed_by: None,
        enabled: None,
    });

    artifacts.push(ArtifactClass {
        class: "providers".to_owned(),
        store: "postgres",
        location: "providers".to_owned(),
        description: "Upstream LLM providers configured for this workspace, with their \
                      encrypted API credentials.",
        sensitivity: "credential_material",
        row_count: Some(pg.n("c_providers")),
        row_count_status: "counted",
        row_count_detail: None,
        encryption: {
            // The basis is REWRITTEN rather than taken from `sealed()`: this
            // class is the one place in the product that does NOT use the KMS,
            // and citing `kms_self_test` here credited it with a round trip
            // performed against a different key. See `provider_key_self_test`.
            let mut enc = Encryption::sealed(
                "encrypted_credential, where present, matches the AES-256-GCM \
                 envelope (base64url of nonce || ciphertext)"
                    .to_owned(),
                pg.n("c_providers_cred"),
                pg.n("v_providers"),
                None,
            );
            enc.basis = vec![
                basis::WRITE_PATH,
                basis::PROVIDER_KEY_SELF_TEST,
                basis::STORED_SHAPE,
            ];
            enc.note = Some(format!(
                "SEALED WITH A DIFFERENT KEY FROM EVERY OTHER CLASS HERE. \
                 `providers.encrypted_credential` is AES-256-GCM under \
                 `SECUREPROMPT_PROVIDER_KEY` (`crypto::encrypt_aes_gcm`), not through \
                 the KMS backend, so the KMS self-test says nothing about it — this \
                 request probed that key separately and reports \
                 `encryption_basis.provider_key_self_test: {provider_key_self_test}`. \
                 The key has an ALL-ZERO fallback when the variable is unset \
                 (`ProviderKeyConfig::from_env_or_zero`), and zero-key ciphertext \
                 PASSES the shape check below, because a shape check inspects the \
                 envelope and not the key. So read `ciphertext` here as a statement \
                 about the bytes and read the self-test for whether they are \
                 confidential. {CIPHERTEXT_SHAPE_CLAIM}"
            ));
            enc
        },
        retention: Retention::none("Configuration. Removed when the provider is deleted."),
        governed_by: None,
        enabled: None,
    });

    artifacts.push(ArtifactClass {
        class: "user_backup_codes".to_owned(),
        store: "postgres",
        location: "user_backup_codes".to_owned(),
        description: "Single-use 2FA recovery codes for this workspace's members. Counted \
                      through users.workspace_id — the table itself has no workspace column.",
        sensitivity: "credential_material",
        row_count: Some(pg.n("c_user_backup_codes")),
        row_count_status: "counted",
        row_count_detail: None,
        encryption: Encryption::hashed(
            "code_hash begins with an Argon2 identifier".to_owned(),
            pg.n("c_user_backup_codes"),
            pg.n("v_user_backup_codes"),
            "Plaintext codes are returned to the user exactly once, at enrolment.",
        ),
        retention: Retention::none(
            "A used code keeps its row with `used_at` set, so replay is detectable. Codes \
             are removed only when the user is deleted or re-enrols.",
        ),
        governed_by: None,
        enabled: None,
    });

    artifacts.push(ArtifactClass {
        class: "policy_rules".to_owned(),
        store: "postgres",
        location: "policy_rules".to_owned(),
        description: "Redaction and enforcement rules for this workspace: conditions, \
                      actions, priorities.",
        sensitivity: "configuration",
        row_count: Some(pg.n("c_policy_rules")),
        row_count_status: "counted",
        row_count_detail: None,
        encryption: Encryption::plain(
            "Rule bodies are stored as written. `conditions` may embed operator-supplied \
             regexes and literals, so anything an admin types into a rule is retained in \
             the clear.",
        ),
        retention: Retention::none("Configuration. Removed when the rule is deleted."),
        governed_by: None,
        enabled: None,
    });

    artifacts.push(ArtifactClass {
        class: "raw_capture_audit".to_owned(),
        store: "postgres",
        location: "raw_capture_audit".to_owned(),
        description: "Append-only record of every accepted change to this workspace's \
                      raw-capture setting: who, when, and the before/after state.",
        sensitivity: "audit_trail",
        row_count: Some(pg.n("c_raw_capture_audit")),
        row_count_status: "counted",
        row_count_detail: None,
        encryption: Encryption::plain(
            "Actor email is denormalised in the clear on purpose: a foreign key would let \
             deleting a user rewrite the evidence that they switched plaintext retention on.",
        ),
        retention: Retention::none(
            "Append-only and never purged, by design. An audit trail with a retention \
             window is an audit trail with a deadline.",
        ),
        governed_by: None,
        enabled: None,
    });

    artifacts.push(ArtifactClass {
        class: "retention_purge_audit".to_owned(),
        store: "postgres",
        location: "retention_purge_audit".to_owned(),
        description: "Proof-of-purge records: one row per scope per `retention.purge` run, \
                      with the cutoff, rows deleted, the deleted range, and a recount taken \
                      after the delete.",
        sensitivity: "audit_trail",
        row_count: Some(pg.n("c_retention_purge_audit")),
        row_count_status: "counted",
        row_count_detail: None,
        encryption: Encryption::plain(
            "Counts and timestamps only. NOTE what this table does NOT prove: it is \
             self-attestation written by the purge process into a database that same \
             process can modify, and a logical DELETE is not an assurance that the bytes \
             are irrecoverable from backups or unmerged parts.",
        ),
        retention: Retention::none("Append-only and never purged, by design."),
        governed_by: None,
        enabled: None,
    });

    for (class, description, sensitivity, count, note) in [
        (
            "workspaces",
            "This workspace's own row: name and timestamps.",
            "configuration",
            pg.n("c_workspaces"),
            "Name and timestamps only.",
        ),
        (
            "models",
            "Model catalogue entries for this workspace's providers.",
            "configuration",
            pg.n("c_models"),
            "Model names and exclusion flags.",
        ),
        (
            "audit_events_meta",
            "Postgres-side pointer rows linking a request id to an event type. The event \
             bodies live in ClickHouse.",
            "derived_metadata",
            pg.n("c_audit_events_meta"),
            "Identifiers and event type only. No content.",
        ),
        (
            "workspace_budgets",
            "Token budget limits and the enforcement behaviour for this workspace.",
            "configuration",
            pg.n("c_workspace_budgets"),
            "Limits and an enum.",
        ),
        (
            "workspace_secure_mode",
            "Secure-mode posture: level, block-on-detection flags, response redaction.",
            "configuration",
            pg.n("c_workspace_secure_mode"),
            "Flags and an enum.",
        ),
        (
            "workspace_sidecar_policy",
            "What this workspace does when the ML sidecar cannot provide detection \
             coverage: `block` or `degrade_with_alert`.",
            "configuration",
            pg.n("c_workspace_sidecar_policy"),
            "A single enum.",
        ),
        (
            "workspace_raw_capture",
            "This workspace's raw-capture setting and retention window. Absence of a row \
             IS the default — capture off, 30 days — so a zero here means nobody has ever \
             opted in.",
            "configuration",
            pg.n("c_workspace_raw_capture"),
            "A boolean, a day count and the id of whoever last changed them.",
        ),
    ] {
        artifacts.push(ArtifactClass {
            class: class.to_owned(),
            store: "postgres",
            location: class.to_owned(),
            description,
            sensitivity,
            row_count: Some(count),
            row_count_status: "counted",
            row_count_detail: None,
            encryption: Encryption::plain(note),
            retention: Retention::none(
                "Configuration. Kept for the life of the workspace and removed with it \
                 (ON DELETE CASCADE); no time-based expiry.",
            ),
            governed_by: None,
            enabled: None,
        });
    }

    // ── Redis: the one class whose key IS workspace-partitioned ───────────
    {
        let budget_keys = live_budget_keys(&state, ws).await;
        // Through the same [`unavailable`] helper as the ClickHouse counts: a
        // fourth site of the identical defect, in the identical field. The
        // Redis error text is not a ClickHouse exception, but it is still a
        // store's own message going into a response body, and the key it would
        // quote (`budget:{workspace_id}:tokens:...`) carries the tenancy value
        // this endpoint interpolates.
        let (row_count, row_count_status, row_count_detail) = match budget_keys {
            Ok(n) => (Some(n), "counted", None),
            Err(e) => (
                None,
                "unavailable",
                Some(unavailable(
                    "redis:budget (EXISTS on this workspace's two counter keys)",
                    NO_COUNT,
                    &e,
                )),
            ),
        };
        artifacts.push(ArtifactClass {
            class: "redis:budget".to_owned(),
            store: "redis",
            location: "budget:{workspace_id}:tokens:{YYYYMMDD|YYYYMM}".to_owned(),
            description: "Token spend counters for the current day and month. The count \
                          reported here is how many of this workspace's two current-window \
                          counter keys exist right now (0, 1 or 2).",
            sensitivity: "derived_metadata",
            row_count,
            row_count_status,
            row_count_detail,
            encryption: Encryption::plain("An integer per key."),
            retention: Retention {
                days: Some(32),
                window: "2 days (daily key) / 32 days (monthly key)".to_owned(),
                mechanism: mechanism::REDIS_TTL,
                mechanism_detail: "Redis key expiry, set with `EXPIRE ... NX` when the \
                                   counter is first created. Redis deletes lazily on access \
                                   plus by a background sampler, so an untouched expired key \
                                   can occupy memory past its TTL — it is never SERVED, \
                                   which is what matters here."
                    .to_owned(),
            },
            governed_by: None,
            enabled: None,
        });
    }

    // ── What this endpoint cannot enumerate, said out loud ────────────────
    let not_enumerable = vec![
        UnenumerableClass {
            class: "redis:filevault",
            store: "redis",
            location: "filevault:{ref}",
            description: "The SECOND token vault. Holds the placeholder → original map for \
                          PII found in an uploaded file, so the chat pipeline can restore it \
                          in the reply. Same data class as `token_vault_entries`: \
                          un-redacted customer PII.",
            reason: "The key is `filevault:{ref}` where ref is a bare random UUID. It \
                     carries NO workspace id, and the value is opaque ciphertext, so there \
                     is no way to attribute a key to a workspace — not by SCAN, not by \
                     reading it. Any per-workspace count would be fabricated, and this \
                     endpoint reports nothing rather than a number it cannot support.",
            per_workspace_erasure: "not_possible",
            row_count: None,
            encryption: Encryption {
                at_rest: at_rest::CIPHERTEXT,
                basis: vec![basis::WRITE_PATH, basis::KMS_SELF_TEST],
                verification: None,
                note: Some(format!(
                    "Encrypted through the same KMS as the other stores, encrypt-or-fail with \
                     no plaintext fallback (`redis::stash_file_vault`). NOT shape-verified \
                     here, because verification would require enumerating keys this endpoint \
                     has just explained it cannot enumerate. The claim therefore rests on the \
                     write path and the live KMS probe only. Also note this was made \
                     ciphertext only recently: stashes written before that upgrade are \
                     plaintext JSON, stop restoring, and age out within the 6h TTL. \
                     {CIPHERTEXT_SHAPE_CLAIM}"
                )),
            },
            retention: Retention {
                days: None,
                window: "6 hours".to_owned(),
                mechanism: mechanism::REDIS_TTL,
                mechanism_detail: "Redis key TTL of 6 hours, set at write time \
                                   (`FILE_VAULT_TTL_SECS`). This is the ONLY thing that \
                                   removes a file-vault entry: there is no purge job for it, \
                                   and because it cannot be enumerated per tenant, an \
                                   erasure request cannot be honoured against it any faster \
                                   than waiting out the TTL."
                    .to_owned(),
            },
        },
        UnenumerableClass {
            class: "mongo:librechat",
            store: "mongodb",
            location: "docker-compose service `librechat-mongo`, named volume \
                       `librechat_mongo_data` mounted at /data/db",
            description: "LibreChat's own database. It stores each conversation as the \
                          CHAT UI held it: the user's message BEFORE SecurePrompt \
                          redacted it, and the assistant's reply AFTER SecurePrompt \
                          restored the placeholders into it. That makes it the SECOND \
                          store in this deployment holding un-redacted request content, \
                          alongside `request_content_captures` — and unlike that one it \
                          is not opt-in, not gated, and not encrypted by this product.",
            reason: "A separate MongoDB service with no SecurePrompt workspace id \
                     anywhere in its schema: LibreChat has its own user and \
                     conversation model and knows nothing about workspaces. The gateway \
                     API process holds no Mongo client, so it could not attribute a \
                     document to a tenant even if the schema allowed it. Note this is \
                     NOT an optional add-on that an operator opted into: the service \
                     carries no `profiles:` key (line 127 is the only one in \
                     docker-compose.yml), so a plain `docker compose up -d` starts it.",
            per_workspace_erasure: "not_possible",
            row_count: None,
            encryption: Encryption::plain(
                "Stored as LibreChat writes it. SecurePrompt's KMS is not in this path \
                 at any point — `by_design` here means this product never encrypts it, \
                 NOT that leaving it in the clear is safe: these are un-redacted \
                 prompts and restored replies. At-rest protection is whatever MongoDB \
                 and the host volume provide, which by default is none.",
            ),
            retention: Retention::none(
                "NO TTL and no purge. LibreChat keeps a conversation until its own user \
                 deletes it; the worker's `retention.purge` job does not know this store \
                 exists; and the `librechat_mongo_data` volume survives \
                 `docker compose down` (removing it takes `-v`). A SecurePrompt erasure \
                 request does not reach this data, and neither does the retention window \
                 an operator configures on `PUT /v1/secure-mode`.",
            ),
        },
        UnenumerableClass {
            class: "redis:jti_blacklist",
            store: "redis",
            location: "jti_blacklist:{jti}",
            description: "Access-token ids revoked by logout, held until the token would \
                          have expired anyway.",
            reason: "The key is the token's random jti with no workspace id, and the value \
                     is the constant 1, so nothing associates a key with a workspace.",
            per_workspace_erasure: "not_possible",
            row_count: None,
            encryption: Encryption::plain(
                "A random identifier and the integer 1. No personal data.",
            ),
            retention: Retention {
                days: None,
                window: "remaining access-token lifetime".to_owned(),
                mechanism: mechanism::REDIS_TTL,
                mechanism_detail: "Redis key TTL, set to the token's remaining validity at \
                                   logout."
                    .to_owned(),
            },
        },
        UnenumerableClass {
            class: "redis:oidc_state",
            store: "redis",
            location: "oidc_state:{state_id}",
            description: "PKCE verifier secrets for in-flight OIDC logins.",
            reason: "Written before any workspace is known — the login has not completed — \
                     so the key cannot carry one.",
            per_workspace_erasure: "not_applicable",
            row_count: None,
            encryption: Encryption::plain(
                "The PKCE verifier is stored as written. It is single-use: the callback \
                 consumes it with GETDEL, so it cannot be replayed.",
            ),
            retention: Retention {
                days: None,
                window: "10 minutes".to_owned(),
                mechanism: mechanism::REDIS_TTL,
                mechanism_detail: "Redis key TTL, plus GETDEL on the callback so a completed \
                                   login removes it immediately."
                    .to_owned(),
            },
        },
        UnenumerableClass {
            class: "redis:queues",
            store: "redis",
            location: "queue:analytics | queue:audit_export | queue:retention | queue:policy_index",
            description: "Task envelopes waiting for the worker. A policy-index envelope \
                          carries the rule text that is about to be embedded.",
            reason: "A queue is one Redis list shared by every workspace. Counting it would \
                     mean draining or scanning other tenants' payloads, which this endpoint \
                     will not do.",
            per_workspace_erasure: "whole_store_only",
            row_count: None,
            encryption: Encryption::plain(
                "JSON task envelopes, stored as written. They are transient — the worker \
                 pops each one — but there is no TTL, so an envelope for a queue with no \
                 running consumer is retained indefinitely.",
            ),
            retention: Retention::none(
                "No TTL. An entry leaves the list when the worker pops it and not otherwise, \
                 so a stalled or absent worker means unbounded retention.",
            ),
        },
        UnenumerableClass {
            class: "license_freshness",
            store: "postgres",
            location: "license_freshness",
            description: "Last successful license revalidation and the signed freshness \
                          assertion behind it.",
            reason: "Deployment-scoped: the table has no workspace_id column, because a \
                     license covers the whole gateway rather than one tenant.",
            per_workspace_erasure: "not_applicable",
            row_count: None,
            encryption: Encryption::plain("Timestamps and a signed assertion. No tenant data."),
            retention: Retention::none("One row, overwritten in place."),
        },
        UnenumerableClass {
            class: "license_activation",
            store: "postgres",
            location: "license_activation",
            description: "The license token activated through the dashboard console.",
            reason: "Deployment-scoped: no workspace_id column.",
            per_workspace_erasure: "not_applicable",
            row_count: None,
            encryption: Encryption::plain(
                "The license token is stored as issued. It is a signed capability, not a \
                 secret about any tenant.",
            ),
            retention: Retention::none("Replaced when a new license is activated."),
        },
        UnenumerableClass {
            class: "_schema_migrations",
            store: "clickhouse",
            location: "_schema_migrations",
            description: "Which ClickHouse migrations the worker has applied.",
            reason: "Deployment-scoped bookkeeping with no workspace column.",
            per_workspace_erasure: "not_applicable",
            row_count: None,
            encryption: Encryption::plain("Version strings and timestamps."),
            retention: Retention::none("Kept for the life of the deployment, by necessity."),
        },
        UnenumerableClass {
            class: "_dbt_lock",
            store: "clickhouse",
            location: "_dbt_lock",
            description: "Single-run lock for dbt builds.",
            reason: "Deployment-scoped bookkeeping with no workspace column.",
            per_workspace_erasure: "not_applicable",
            row_count: None,
            encryption: Encryption::plain("A lock key and a holder name."),
            retention: Retention::none("Overwritten by each run."),
        },
        UnenumerableClass {
            class: "qdrant:policy_rag",
            store: "qdrant",
            location: "collection `policy_rag`",
            description: "One vector per policy rule, with a `workspace_id` payload field, \
                          written by the worker's `policy.index_rule` task.",
            reason: "The gateway API process holds no Qdrant client — vector operations \
                     belong to the worker and the ML sidecar. The points DO carry a \
                     workspace_id payload, so this class is enumerable in principle; it is \
                     not enumerable FROM HERE, and this endpoint will not report a number it \
                     did not measure.",
            per_workspace_erasure: "whole_store_only",
            row_count: None,
            encryption: Encryption::plain(
                "Embedding vectors plus a payload of workspace id, doc type and rule id. \
                 The rule TEXT is not stored; the embedding of it is.",
            ),
            retention: Retention::none(
                "No TTL and no purge. A point is overwritten when its rule is re-indexed \
                 (the rule id is the point id) and is NOT removed when the rule is deleted.",
            ),
        },
        UnenumerableClass {
            class: "qdrant:prompt_similarity",
            store: "qdrant",
            location: "collection `prompt_similarity`",
            description: "Prompt embedding collection provisioned by the ML sidecar.",
            reason: "Same as `qdrant:policy_rag`: no Qdrant client in this process.",
            per_workspace_erasure: "whole_store_only",
            row_count: None,
            encryption: Encryption::plain("Embedding vectors and their payloads."),
            retention: Retention::none("No TTL and no purge."),
        },
    ];

    Ok(Json(DataInventoryResponse {
        schema_version: 1,
        workspace_id: ws,
        generated_at: Utc::now(),
        encryption_basis: EncryptionBasis {
            kms_backend,
            kms_self_test,
            kms_self_test_detail,
            provider_key_self_test,
            provider_key_self_test_detail,
            ciphertext_shape_claim: CIPHERTEXT_SHAPE_CLAIM,
        },
        artifacts,
        not_enumerable,
        caveats: vec![
            "`at_rest` is COMPUTED from `verification` wherever a `verification` block is \
             present, and the rule is: `ciphertext` = every payload checked matched the \
             envelope, `plaintext` = none did, `mixed` = some did, `hashed` = one-way by \
             construction and every value matched, `empty` = nothing was stored so nothing \
             was verified. `plaintext_by_design` carries no `verification` and claims \
             nothing beyond `stored as written`. THREE CLASSES ARE EXCEPTIONS and their \
             verdict is DECLARED rather than computed — this caveat used to say `never \
             declared per class`, which was false: (1) `users` reports `mixed` \
             unconditionally whenever the workspace has any member, because the table \
             holds three states at once — an Argon2id password hash, a KMS-encrypted TOTP \
             secret, and plaintext directory fields — so no single computed verdict would \
             be honest; its `verification` block still carries the real Argon2 counts, and \
             those are what to read. (2) `redis:filevault` is declared `ciphertext` with \
             NO verification, because verifying it would mean enumerating keys this \
             endpoint has just explained it cannot enumerate; the claim rests on the write \
             path and the live KMS probe alone, and its own note records that stashes \
             written before the encryption upgrade are plaintext JSON. (3) `mongo:librechat` \
             is declared `plaintext_by_design` without verification because it is in a \
             store this process cannot query at all. Every other class's verdict can be \
             recomputed from the numbers printed next to it.",
            "The analytics classes above — `request_events`, `detection_class_counts`, \
             `policy_events`, `latency_samples`, `token_usage`, the mv_* aggregates and \
             every dbt relation derived from them — cover GATEWAY TRAFFIC ONLY: requests \
             through `/v1/chat/completions`, `/v1/completions` and `/v1/embeddings`. \
             `/v1/redact`, `/v1/secure-mode/tokenize`, the MCP server and file scanning \
             run the same detection pass and emit NO analytics event (the whole API crate \
             enqueues one from a single file, the gateway pipeline), so their requests are \
             absent from every count in this section. Their SIDE EFFECTS are not: \
             tokenize writes `token_vault_entries` and file scanning writes \
             `redis:filevault`, both listed above with their own counts. Read the \
             analytics counts as covering the gateway, not the product.",
            "A count of zero means the query ran and found nothing. A `row_count` of null \
             with `row_count_status: unavailable` means the store did not answer and the \
             true figure is UNKNOWN. The two are never conflated.",
            "This inventory covers the stores the gateway API can reach — Postgres, \
             ClickHouse and Redis — plus the Qdrant collections and the LibreChat \
             MongoDB it CANNOT reach and declares anyway, under `not_enumerable`. \
             The following are OUT OF SCOPE and their absence from this document is \
             not evidence of their absence from the deployment: replicas and WAL \
             archives; the `backup` compose service, its `clickhouse_backups` volume \
             and the `./backups` host directory it writes, which by construction hold \
             copies of everything listed above INCLUDING rows the TTLs have since \
             removed; the `prometheus` service's metric series and the `grafana` \
             service's dashboards, users and sessions, which carry no request content \
             but do carry model names and workspace ids as label values; the ML \
             sidecar's temporary upload directory; and any operator-side log \
             aggregation.",
            "A logical DELETE — by TTL, by the purge job, or by hand — is not an assurance \
             that the bytes are irrecoverable. ClickHouse parts, Postgres dead tuples and \
             any backup taken before the delete may still hold them.",
        ],
    }))
}

/// Probe `SECUREPROMPT_PROVIDER_KEY` — the key that actually seals
/// `providers.encrypted_credential` — with a live encrypt→decrypt round trip,
/// and detect the all-zero fallback.
///
/// `providers` used to cite [`basis::KMS_SELF_TEST`], which probes a different
/// key entirely. The gap that hid behind it:
/// `ProviderKeyConfig::from_env_or_zero` returns 32 zero bytes when the
/// variable is unset (`secureprompt-common/src/config.rs`), and ciphertext
/// under a zero key still passes [`pg_sealed`], because a shape check inspects
/// the envelope and not the key. A deployment that never set the variable could
/// therefore read `at_rest: ciphertext, basis: [.., kms_self_test, ..]` over
/// credentials anyone holding the database could decrypt.
///
/// Returns `("ok" | "failed", detail)`. The zero key is a FAILURE, not a
/// warning: the round trip succeeds perfectly under it, so a probe that only
/// checked the round trip would call it healthy.
fn provider_key_self_test() -> (&'static str, String) {
    use secureprompt_common::{config::ProviderKeyConfig, crypto};

    const PROBE: &[u8] = b"secureprompt-data-inventory-provider-key-self-test";

    let key = match ProviderKeyConfig::from_env_or_zero().to_key_bytes() {
        Ok(key) => key,
        Err(e) => {
            return (
                "failed",
                format!(
                    "SECUREPROMPT_PROVIDER_KEY is not 64 hex characters, so no \
                     provider credential can be sealed or read: {e}"
                ),
            )
        }
    };
    if key == [0_u8; 32] {
        return (
            "failed",
            "SECUREPROMPT_PROVIDER_KEY IS UNSET. `ProviderKeyConfig::\
             from_env_or_zero` substitutes an ALL-ZERO 32-byte key so the API can \
             start without provider encryption configured, and every credential \
             sealed under it is decryptable by anyone holding the ciphertext. Note \
             what this means for the `providers` class below: zero-key ciphertext \
             still PASSES the stored-shape check, because that check inspects the \
             envelope and not the key, so `at_rest: ciphertext` there is a \
             statement about the bytes and NOT about their confidentiality."
                .to_owned(),
        );
    }
    let (nonce, ciphertext) = match crypto::encrypt_aes_gcm(PROBE, &key) {
        Ok(sealed) => sealed,
        Err(e) => {
            return (
                "failed",
                format!("encrypt of a synthetic marker under the provider key failed: {e}"),
            )
        }
    };
    match crypto::decrypt_aes_gcm(&nonce, &ciphertext, &key) {
        Ok(plain) if plain == PROBE => (
            "ok",
            "a synthetic marker was encrypted and decrypted under \
             SECUREPROMPT_PROVIDER_KEY while answering this request, and the key \
             is not the all-zero fallback"
                .to_owned(),
        ),
        Ok(_) => (
            "failed",
            "the provider key round-tripped a synthetic marker to DIFFERENT bytes"
                .to_owned(),
        ),
        Err(e) => (
            "failed",
            format!("decrypt of a synthetic marker under the provider key failed: {e}"),
        ),
    }
}

/// Probe the configured KMS with a live encrypt→decrypt round trip.
///
/// Every `ciphertext` verdict in the response leans on this. A claim resting
/// on a backend nobody probed is an assertion, which is exactly what this
/// endpoint exists not to publish. The round trip is over [`KMS_PROBE`], a
/// compile-time constant, so it can never touch customer data.
///
/// Returns `("ok" | "failed", detail)`. Note the middle arm: a backend that
/// returns SUCCESS but different bytes is a failure, and the naive
/// `encrypt().is_ok()` check would call it healthy.
async fn kms_self_test(kms: &dyn secureprompt_common::kms::KmsBackend) -> (&'static str, String) {
    let sealed = match kms.encrypt(KMS_PROBE).await {
        Ok(sealed) => sealed,
        Err(e) => {
            return (
                "failed",
                format!("encrypt of a synthetic marker failed: {e}"),
            )
        }
    };
    match kms.decrypt(&sealed).await {
        Ok(plain) if plain == KMS_PROBE => (
            "ok",
            "a synthetic marker was encrypted and decrypted through the \
             configured backend while answering this request"
                .to_owned(),
        ),
        Ok(_) => (
            "failed",
            "the configured backend round-tripped a synthetic marker to \
             DIFFERENT bytes; treat every ciphertext claim below as unverified"
                .to_owned(),
        ),
        Err(e) => (
            "failed",
            format!("decrypt of a synthetic marker failed: {e}"),
        ),
    }
}

/// How many of this workspace's two current-window budget counters exist.
///
/// Key shapes are duplicated from `budgets.rs` rather than imported so this
/// module cannot widen that module's surface; the test
/// `every_redis_key_class_the_gateway_writes_is_accounted_for` names the
/// source function, so a rename there is findable from here.
async fn live_budget_keys(state: &AppState, ws: Uuid) -> Result<u64, String> {
    use deadpool_redis::redis::cmd;
    let mut conn = state
        .redis_pool
        .get()
        .await
        .map_err(|e| format!("redis checkout failed: {e}"))?;
    let now = Utc::now();
    let keys = [
        format!("budget:{}:tokens:{}", ws, now.format("%Y%m%d")),
        format!("budget:{}:tokens:{}", ws, now.format("%Y%m")),
    ];
    let mut command = cmd("EXISTS");
    for key in &keys {
        command.arg(key);
    }
    let present: i64 = command
        .query_async(&mut conn)
        .await
        .map_err(|e| format!("EXISTS failed: {e}"))?;
    u64::try_from(present).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::{at_rest, kms_self_test, Encryption, Retention, KMS_PROBE};
    use anyhow::Result;
    use async_trait::async_trait;
    use secureprompt_common::kms::KmsBackend;

    /// Backends that fail in each of the three ways `kms_self_test` must
    /// distinguish, so "the probe is real" is provable without breaking the
    /// deployment's actual KMS.
    struct StubKms {
        mode: &'static str,
    }

    #[async_trait]
    impl KmsBackend for StubKms {
        async fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
            match self.mode {
                "encrypt_fails" => anyhow::bail!("no key material"),
                // The dangerous one: reports success, and a naive
                // `encrypt().is_ok()` probe would call this healthy.
                "lossy" => Ok(b"not-the-input".to_vec()),
                _ => Ok(plaintext.to_vec()),
            }
        }
        async fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
            match self.mode {
                "decrypt_fails" => anyhow::bail!("wrong key"),
                _ => Ok(ciphertext.to_vec()),
            }
        }
    }

    #[tokio::test]
    async fn kms_self_test_passes_only_on_a_true_round_trip() {
        // Positive control: an identity backend round-trips, so the failures
        // below are the probe reacting to the backend, not a constant "failed".
        let (verdict, _) = kms_self_test(&StubKms { mode: "identity" }).await;
        assert_eq!(verdict, "ok");

        for mode in ["encrypt_fails", "decrypt_fails", "lossy"] {
            let (verdict, detail) = kms_self_test(&StubKms { mode }).await;
            assert_eq!(
                verdict, "failed",
                "a `{mode}` backend was reported healthy — every ciphertext \
                 claim in the response rests on this probe: {detail}"
            );
            assert!(!detail.is_empty(), "`{mode}` gave no reason");
        }
    }

    /// The probe must never be able to carry customer data into a log or a
    /// KMS audit trail.
    #[test]
    fn kms_probe_is_a_constant() {
        assert_eq!(KMS_PROBE, b"secureprompt-data-inventory-kms-self-test");
    }

    /// The verdict must follow the counts. These four cases are the whole
    /// point of the endpoint: an implementation that hardcodes any one of
    /// them fails here.
    #[test]
    fn sealed_verdict_is_computed_from_the_counts() {
        let p = "predicate".to_owned();
        assert_eq!(
            Encryption::sealed(p.clone(), 0, 0, None).at_rest,
            at_rest::EMPTY
        );
        assert_eq!(
            Encryption::sealed(p.clone(), 3, 3, None).at_rest,
            at_rest::CIPHERTEXT
        );
        assert_eq!(
            Encryption::sealed(p.clone(), 3, 0, None).at_rest,
            at_rest::PLAINTEXT,
            "no payload matched the envelope; the class is storing plaintext"
        );
        assert_eq!(
            Encryption::sealed(p, 3, 1, None).at_rest,
            at_rest::MIXED,
            "one sealed row must not launder two plaintext ones"
        );
    }

    #[test]
    fn sealed_reports_the_unmatched_remainder() {
        let enc = Encryption::sealed("p".to_owned(), 5, 2, None);
        let verification = enc.verification.expect("verification present");
        assert_eq!(verification.rows_matching, 2);
        assert_eq!(verification.rows_not_matching, 3);
    }

    /// A retention window with no mechanism is the shape of a false
    /// assurance, so `Retention::none` must never carry a day count.
    #[test]
    fn retention_none_has_no_day_count() {
        let retention = Retention::none("nothing purges this");
        assert_eq!(retention.days, None);
        assert_eq!(retention.window, "none");
        assert_eq!(retention.mechanism, super::mechanism::NONE);
    }
}
