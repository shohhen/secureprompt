use crate::analytics::capture::{seal, CaptureDecision, CapturedContent};
use secureprompt_common::{
    kms::KmsBackend,
    types::{PolicyEvent, RequestId, TokenUsage, WorkspaceId},
};

/// WS3 review — what a request path is allowed to record in
/// [`RequestEvent::redacted_prompt`].
///
/// The column means "the placeholder-safe body we forwarded upstream". The
/// discriminator is NER COVERAGE, not whether the request was forwarded —
/// `{{Person_1}}` is safe to store whether or not it went anywhere, and the
/// user's name is not safe to store either way.
///
/// Two paths lose that coverage, and both used to write the column anyway:
///
/// * **Fail-closed on NER coverage loss** (`final_action =
///   block_sidecar_unavailable`, HTTP 503). The text is not placeholder-safe:
///   PERSON, ORGANIZATION and ADDRESS are ML-only classes and the
///   deterministic Rust floor has no recogniser for them, so both redaction
///   helpers return the message VERBATIM. This case is the sharp one because
///   NOTHING WAS FORWARDED — the gateway refused to send the prompt precisely
///   because it could not redact it, and then wrote a plaintext copy into its
///   own warehouse, 90-day TTL, no opt-in. That copy existed nowhere else, so
///   it was a disclosure the request itself never created.
///
/// * **Degraded** (`floor_only = true`, HTTP 200, `degrade_with_alert`).
///   Those bytes DID reach the provider, so retaining them is not a new
///   disclosure to a third party — the genuinely different case. They are
///   still un-redacted PII in a table the operator never opted into, under a
///   column name that asserts the opposite to everyone reading the audit UI,
///   so they are not recorded either.
///
/// Both record [`Self::CoverageLost`] and the column is NULL. A reader is not
/// left guessing which: `final_action` identifies the first and `floor_only`
/// the second.
///
/// NOT every 503 is `CoverageLost`. The injection-gate fail-closed path also
/// forwards nothing, but it fires when the INJECTION classifier is
/// unavailable while NER is healthy — the redaction there is real, so it is
/// recorded as [`Self::Redacted`]. Same for a policy deny.
///
/// Why NULL rather than "put the column behind the capture gate": a workspace
/// that opts in already has the *raw* prompt for these requests in
/// `request_content_captures`, encrypted, under its own retention. Writing a
/// floor-redacted near-duplicate into `request_events` in the clear would add
/// a plaintext copy of a record that is deliberately ciphertext — strictly
/// worse than storing nothing, for exactly the workspaces that care most.
#[derive(Debug, Clone)]
pub enum RedactedPrompt {
    /// Detection ran with the coverage the workspace is configured for, and
    /// this is the placeholder-safe body that was — or, on a policy deny,
    /// would have been — forwarded upstream.
    Redacted(String),
    /// Detection coverage was lost on this request, so nothing here can
    /// honestly be called a redacted prompt. Records NULL.
    CoverageLost,
}

#[derive(Debug, Clone)]
pub struct RequestEvent {
    pub request_id: RequestId,
    pub workspace_id: WorkspaceId,
    pub provider: String,
    pub model: String,
    pub final_action: String,
    pub input_tokens: Option<u32>,
    pub output_tokens: Option<u32>,
    pub reasoning_tokens: Option<u32>,
    pub cache_read_tokens: Option<u32>,
    pub cache_write_tokens: Option<u32>,
    pub estimated_usage: bool,
    pub cost_usd: f64,
    pub policy_events: Vec<PolicyEvent>,
    pub latency_ms: Option<u32>,
    /// Time-to-first-byte from upstream (provider-side). `None` for paths
    /// that don't make a network call (debug mode, denied requests).
    pub ttft_ms: Option<u32>,
    /// Workspace member who issued the request (api_keys.assigned_user_id).
    /// `None` for legacy unassigned workspace-scoped keys.
    pub user_id: Option<uuid::Uuid>,
    pub api_key_id: Option<uuid::Uuid>,
    pub api_key_name: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    /// Placeholder-safe prompt body — what was forwarded to the upstream
    /// after PII redaction. Required for the audit detail view.
    ///
    /// PRIVATE ON PURPOSE, exactly like `captured` below, and settable only
    /// through [`Self::record_prompt`].
    ///
    /// This field used to be `pub`, and its doc comment used to claim it was
    /// safely exempt from the WS3-1 capture gate because it holds "the same
    /// bytes that were forwarded upstream". THAT CLAIM WAS FALSE on two of
    /// its four assignment sites, and it was false in the direction that
    /// matters: on the fail-closed path nothing is forwarded at all, and the
    /// text is un-redacted precisely because detection coverage was lost.
    /// The claim was never checked because the only tests that read this
    /// column asserted `position(prose) > 0`, which the raw prompt satisfies.
    ///
    /// See [`RedactedPrompt`] for what each path may record and why.
    redacted_prompt: Option<String>,
    /// Migration 010 — the placeholder-safe ANSWER, on the same terms as the
    /// question above. Private for the same reason `redacted_prompt` is: the
    /// only way to set it is [`RequestEvent::record_response`], so a new call
    /// site cannot assign restored (PII-bearing) text here by mistake.
    redacted_response: Option<String>,
    /// WS3-1 / WS3-2 — the raw user message, the raw upstream response and
    /// the PII-restored response, encrypted, IF AND ONLY IF the workspace
    /// opted in.
    ///
    /// PRIVATE ON PURPOSE. This replaced three `pub` fields
    /// (`raw_prompt`, `raw_response`, `restored_response`) that seven call
    /// sites in `pipeline/service.rs` assigned unconditionally. The only way
    /// to populate it is [`Self::capture_content`], whose only route to a
    /// `Some` is [`crate::analytics::capture::seal`] — so the gate cannot be
    /// bypassed by a new call site, and forgetting it is a compile error
    /// rather than a leak.
    captured: Option<CapturedContent>,
    /// WS2-3 — this answer was produced with the deterministic Rust floor
    /// alone: the ML sidecar produced no detection coverage for the request
    /// and the workspace's `sidecar_unavailable` policy is
    /// `degrade_with_alert`. `false` on every normally-served request, so a
    /// reviewer can scope an incident to exactly the traffic that ran without
    /// NER rather than guessing from sidecar uptime.
    pub floor_only: bool,
    /// WS2-4 — WHICH detection engines produced coverage for this request's
    /// prompt, as opposed to `floor_only`'s coarser "was the answer produced
    /// on the floor alone".
    ///
    /// PUBLIC, unlike `captured` and `detection_counts` above, and for a
    /// reason worth stating rather than leaving to inference: those two are
    /// private because a caller could otherwise assign an *unbounded* value —
    /// plaintext past the capture gate, or a class name off the sidecar's
    /// wire. This one is a closed three-variant enum, so there is no
    /// out-of-vocabulary value to guard against and a setter would buy
    /// nothing. What it CAN be is wrong, and the defence against that is the
    /// default: [`crate::analytics::engines::DetectionEngines::FloorOnly`]
    /// under-claims, so a forgotten call site records less scanning than
    /// happened rather than asserting a model ran when it did not.
    pub engines: crate::analytics::engines::DetectionEngines,
    /// WS3-6 — whether `model` names a `models` row an ADMINISTRATOR
    /// registered, as opposed to a string this request's caller invented and
    /// `resolve_model`'s Phase-1 passthrough forwarded verbatim.
    ///
    /// PUBLIC for the same reason as `engines`: it is a closed two-variant
    /// value, so there is no out-of-vocabulary input to guard against and a
    /// setter would buy nothing. What it can be is WRONG, and the defence
    /// against that is the default — `false` under-claims, so a call site that
    /// forgets to set it buckets a legitimate destination rather than writing
    /// caller-supplied bytes into `detection_class_counts.model`.
    ///
    /// Read only by [`DetectionClassCountRow::from_event`], through
    /// [`crate::analytics::detection_counts::canonicalize_model`].
    /// `request_events.model` keeps the raw string: it is the operational
    /// record a workspace using passthrough needs for per-model cost, and
    /// `GET /v1/data-inventory` declares that it holds the caller's string.
    pub model_registered: bool,
    /// WS3-6 — how many DISTINCT entities of each class this request's
    /// detection pass found. The source the shadow-mode leak report
    /// aggregates.
    ///
    /// PRIVATE ON PURPOSE, like `captured` and `redacted_prompt` above,
    /// though for a different reason. Those two are private so plaintext
    /// cannot be assigned past a gate. This one is private so a caller cannot
    /// assign a class name that never went through
    /// [`crate::analytics::detection_counts::canonicalize`] — the ONLY route
    /// to a value here is [`Self::record_detections`]. `detection_class_counts`
    /// is exempt from the WS3-1 capture opt-in precisely because its strings
    /// are string literals from this binary, and that is enforced here rather
    /// than asserted in a comment.
    ///
    /// Keys are `&'static str` for the same reason: an owned `String` would
    /// make it possible to construct one from request data.
    detection_counts: std::collections::BTreeMap<&'static str, u32>,
}

impl RequestEvent {
    #[must_use]
    pub fn new(
        request_id: RequestId,
        workspace_id: WorkspaceId,
        provider: String,
        model: String,
        final_action: String,
        usage: &TokenUsage,
        estimated_usage: bool,
        cost_usd: f64,
        policy_events: Vec<PolicyEvent>,
    ) -> Self {
        Self {
            request_id,
            workspace_id,
            provider,
            model,
            final_action,
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
            reasoning_tokens: usage.reasoning_tokens,
            cache_read_tokens: usage.cache_read_tokens,
            cache_write_tokens: usage.cache_write_tokens,
            estimated_usage,
            cost_usd,
            policy_events,
            latency_ms: None,
            ttft_ms: None,
            user_id: None,
            api_key_id: None,
            api_key_name: None,
            ip_address: None,
            user_agent: None,
            redacted_prompt: None,
            redacted_response: None,
            captured: None,
            floor_only: false,
            engines: crate::analytics::engines::DetectionEngines::FloorOnly,
            model_registered: false,
            detection_counts: std::collections::BTreeMap::new(),
        }
    }

    /// WS3-6 — the ONLY way per-class counts are attached to an analytics
    /// event.
    ///
    /// Takes the DETECTIONS, not a pre-built map, so the counts cannot
    /// disagree with what the pipeline acted on: every call site passes the
    /// same slice it passed to policy evaluation and redaction. A re-scan
    /// would need the stored text (which WS3-1 exists to avoid keeping) and
    /// would measure a different model version than the one that served the
    /// request.
    ///
    /// Called on all four analytics-emitting paths, including the ones that
    /// forwarded nothing. During a shadow-mode pilot the blocked and denied
    /// requests are precisely the interesting population — a counts table
    /// covering only served traffic would under-report the leak it exists to
    /// show.
    pub fn record_detections(&mut self, detections: &[secureprompt_common::types::Detection]) {
        self.detection_counts = crate::analytics::detection_counts::per_class(detections);
    }

    /// Read-only view, for the same reason as [`Self::captured`].
    #[must_use]
    pub const fn detection_counts(&self) -> &std::collections::BTreeMap<&'static str, u32> {
        &self.detection_counts
    }

    /// WS3-1 / WS3-2 — the ONLY way raw request content is ever attached to
    /// an analytics event.
    ///
    /// Call it at every site that used to assign `event.raw_prompt`,
    /// `event.raw_response` or `event.restored_response`. When `decision` is
    /// not enabled — the state of every workspace that has not explicitly
    /// opted in, which on a fresh install is all of them — this is a no-op
    /// and the plaintext arguments are dropped without ever leaving the
    /// process. When it IS enabled, the content is encrypted via `kms`
    /// before it is stored, and a KMS failure drops the capture rather than
    /// falling back to plaintext.
    pub async fn capture_content(
        &mut self,
        decision: CaptureDecision,
        kms: &dyn KmsBackend,
        raw_prompt: Option<String>,
        raw_response: Option<String>,
        restored_response: Option<String>,
    ) {
        self.captured = seal(decision, kms, raw_prompt, raw_response, restored_response).await;
    }

    /// Read-only view of whatever survived the gate. Reading is not the leak;
    /// writing is, which is why there is no corresponding setter.
    #[must_use]
    pub fn captured(&self) -> Option<&CapturedContent> {
        self.captured.as_ref()
    }

    /// WS3 review — the ONLY way a prompt body is attached to an analytics
    /// event.
    ///
    /// Taking a [`RedactedPrompt`] rather than a `String` is the point: a
    /// call site has to NAME which case its request is in, so a path where
    /// redaction did not actually run cannot record plaintext by omission.
    /// The field it writes is private, so a new `event.redacted_prompt = …`
    /// is a compile error rather than a leak.
    pub fn record_prompt(&mut self, prompt: RedactedPrompt) {
        self.redacted_prompt = match prompt {
            RedactedPrompt::Redacted(text) => Some(text),
            RedactedPrompt::CoverageLost => None,
        };
    }

    /// Read-only view, for the same reason as [`Self::captured`].
    #[must_use]
    pub fn redacted_prompt(&self) -> Option<&str> {
        self.redacted_prompt.as_deref()
    }

    /// Record the upstream answer BEFORE placeholder restoration.
    ///
    /// Takes the same `RedactedPrompt` discriminator as [`Self::record_prompt`]
    /// deliberately: the question of whether text is safe to store is the same
    /// question for both halves of a conversation — did NER cover it — and one
    /// type means the two answers cannot drift apart.
    ///
    /// The caller MUST pass the pre-restoration text. Post-restoration output
    /// carries the real values back and belongs in `restored_response`, which
    /// is gated behind the capture opt-in.
    pub fn record_response(&mut self, response: RedactedPrompt) {
        self.redacted_response = match response {
            RedactedPrompt::Redacted(text) if !text.is_empty() => Some(text),
            RedactedPrompt::Redacted(_) | RedactedPrompt::CoverageLost => None,
        };
    }

    /// Read-only view, for the same reason as [`Self::captured`].
    #[must_use]
    pub fn redacted_response(&self) -> Option<&str> {
        self.redacted_response.as_deref()
    }
}

use clickhouse::Row;
use serde::Serialize;

#[derive(Row, Serialize)]
pub struct RequestEventRow {
    #[serde(with = "clickhouse::serde::uuid")]
    pub request_id: uuid::Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    pub workspace_id: uuid::Uuid,
    pub provider: String,
    pub model: String,
    pub final_action: String,
    pub input_tokens: Option<u32>,
    pub output_tokens: Option<u32>,
    pub reasoning_tokens: Option<u32>,
    pub cache_read_tokens: Option<u32>,
    pub cache_write_tokens: Option<u32>,
    pub estimated_usage: bool,
    pub cost_usd: f64,
    #[serde(with = "clickhouse::serde::chrono::datetime")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    // ── Migration 002: per-request actor + transport context ───────────────
    // Column order MUST match the ALTER TABLE order; ClickHouse appends
    // ADD COLUMN at the end of the row.
    #[serde(with = "clickhouse::serde::uuid::option")]
    pub user_id: Option<uuid::Uuid>,
    #[serde(with = "clickhouse::serde::uuid::option")]
    pub api_key_id: Option<uuid::Uuid>,
    pub api_key_name: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub redacted_prompt: Option<String>,
    // ── Migration 004: AI response capture for the audit log ───────────────
    // ── Migration 005: raw input + raw upstream output ─────────────────────
    //
    // WS3-1: these three columns are RETAINED so historical rows written
    // before the capture gate stay readable, and so the row layout keeps
    // matching the live table. The writer now sends NULL for all three,
    // ALWAYS — `from_event` below has no path that populates them. Captured
    // content, when a workspace has opted in, goes to
    // `request_content_captures` as ciphertext instead. See
    // `clickhouse/migrations/007_request_content_captures.sql` for why it
    // cannot live here.
    pub restored_response: Option<String>,
    pub raw_prompt: Option<String>,
    pub raw_response: Option<String>,
    // ── Migration 006 (WS2-3): deterministic-floor-only answer ─────────────
    // Column order MUST match the ALTER TABLE order; ClickHouse appends
    // ADD COLUMN at the end of the row, so each new field goes last.
    pub floor_only: bool,
    // ── Migration 009 (WS2-4): which engines produced coverage ─────────────
    //
    // `Array(String)`, always one of `['floor']`, `['floor','ml']`,
    // `['floor','ml_partial']` — the three `&'static str` literals in
    // `analytics::engines`. Never a wire-sourced string; the value comes from
    // a closed enum whose only constructor is an exhaustive match over
    // `SidecarCoverage`.
    pub engines: Vec<String>,
    // ── Migration 010: the placeholder-safe answer ─────────────────────────
    // Column order MUST match the ALTER TABLE order; this one is newest so it
    // goes last.
    pub redacted_response: Option<String>,
}

impl RequestEventRow {
    pub fn from_event(e: &RequestEvent, created_at: chrono::DateTime<chrono::Utc>) -> Self {
        Self {
            request_id: e.request_id.0,
            workspace_id: e.workspace_id.0,
            provider: e.provider.clone(),
            model: e.model.clone(),
            final_action: e.final_action.clone(),
            input_tokens: e.input_tokens,
            output_tokens: e.output_tokens,
            reasoning_tokens: e.reasoning_tokens,
            cache_read_tokens: e.cache_read_tokens,
            cache_write_tokens: e.cache_write_tokens,
            estimated_usage: e.estimated_usage,
            cost_usd: e.cost_usd,
            created_at,
            user_id: e.user_id,
            api_key_id: e.api_key_id,
            api_key_name: e.api_key_name.clone(),
            ip_address: e.ip_address.clone(),
            user_agent: e.user_agent.clone(),
            redacted_prompt: e.redacted_prompt.clone(),
            redacted_response: e.redacted_response.clone(),
            // WS3-1 — UNCONDITIONALLY NULL. `request_events` is the table the
            // cost, latency and audit-list dashboards read; nothing raw goes
            // into it again, whether or not the workspace opted in. The
            // opted-in case is served by `RequestContentCaptureRow`.
            restored_response: None,
            raw_prompt: None,
            raw_response: None,
            floor_only: e.floor_only,
            engines: e.engines.to_names(),
        }
    }
}

/// WS3-1 / WS3-2 — one row of captured content, in
/// `request_content_captures` (ClickHouse migration 007).
///
/// Field order MUST match the CREATE TABLE column order.
#[derive(Row, Serialize)]
pub struct RequestContentCaptureRow {
    #[serde(with = "clickhouse::serde::uuid")]
    pub request_id: uuid::Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    pub workspace_id: uuid::Uuid,
    #[serde(with = "clickhouse::serde::chrono::datetime")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// `created_at + retention_days`. The table's `TTL expires_at DELETE`
    /// drops the row after it, independently of the 90-day row TTL on
    /// `request_events`.
    #[serde(with = "clickhouse::serde::chrono::datetime")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub encrypted: bool,
    pub raw_prompt: Option<String>,
    pub raw_response: Option<String>,
    pub restored_response: Option<String>,
}

impl RequestContentCaptureRow {
    /// `None` when the event carries no captured content — i.e. whenever the
    /// workspace has not opted in, which is the default.
    ///
    /// `created_at` is the SAME instant the writer stamps on the
    /// `request_events` row, so `dateDiff('day', created_at, expires_at)`
    /// equals the workspace's configured `retention_days` exactly rather than
    /// drifting by the time between the two.
    pub fn from_event(e: &RequestEvent, created_at: chrono::DateTime<chrono::Utc>) -> Option<Self> {
        let captured = e.captured()?;
        let expires_at = created_at
            + chrono::Duration::try_days(i64::from(captured.retention_days))
                .unwrap_or_else(|| chrono::Duration::days(30));
        Some(Self {
            request_id: e.request_id.0,
            workspace_id: e.workspace_id.0,
            created_at,
            expires_at,
            encrypted: captured.encrypted,
            raw_prompt: captured.raw_prompt.clone(),
            raw_response: captured.raw_response.clone(),
            restored_response: captured.restored_response.clone(),
        })
    }
}

/// WS3-6 — one row per (request, entity class) in `detection_class_counts`
/// (ClickHouse migration 008).
///
/// Field order MUST match the CREATE TABLE column order.
///
/// `model`, `user_id` and `api_key_name` are DENORMALISED from the same event
/// rather than joined from `request_events` at read time. See the migration
/// header for why; the short version is that a join would silently drop whole
/// classes out of a compliance report whenever the `request_events` row was
/// lost, and the writer can lose one independently.
///
/// `model` is NOT the event's raw string. It goes through
/// [`crate::analytics::detection_counts::canonicalize_model`] for the same
/// reason `entity_class` goes through `canonicalize`: this table is read by a
/// compliance attestation, and a caller must not be able to choose bytes that
/// land in one.
#[derive(Row, Serialize)]
pub struct DetectionClassCountRow {
    #[serde(with = "clickhouse::serde::uuid")]
    pub request_id: uuid::Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    pub workspace_id: uuid::Uuid,
    #[serde(with = "clickhouse::serde::chrono::datetime")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Always a name an administrator registered in `models`, or the literal
    /// `unregistered` — never a string the caller put in the request body.
    pub model: String,
    #[serde(with = "clickhouse::serde::uuid::option")]
    pub user_id: Option<uuid::Uuid>,
    pub api_key_name: Option<String>,
    /// Always one of `detection_counts::CANONICAL_CLASSES` or the literal
    /// `other` — never a string that came off the ML sidecar's wire.
    pub entity_class: String,
    /// DISTINCT `(class, value)` pairs, so it matches the number of
    /// placeholders a reader of the redacted prompt would see.
    pub entity_count: u32,
}

impl DetectionClassCountRow {
    /// One row per class. EMPTY when the request produced no detections, so a
    /// clean request writes nothing at all and `count()` on this table is a
    /// count of detections, never of requests.
    ///
    /// `created_at` is the SAME instant the writer stamps on the
    /// `request_events` row, so a report window that includes one includes the
    /// other.
    pub fn from_event(e: &RequestEvent, created_at: chrono::DateTime<chrono::Utc>) -> Vec<Self> {
        e.detection_counts()
            .iter()
            .map(|(class, count)| Self {
                request_id: e.request_id.0,
                workspace_id: e.workspace_id.0,
                created_at,
                model: crate::analytics::detection_counts::canonicalize_model(
                    &e.model,
                    e.model_registered,
                ),
                user_id: e.user_id,
                api_key_name: e.api_key_name.clone(),
                entity_class: (*class).to_owned(),
                entity_count: *count,
            })
            .collect()
    }
}

#[derive(Row, Serialize)]
pub struct PolicyEventRow {
    #[serde(with = "clickhouse::serde::uuid")]
    pub request_id: uuid::Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    pub workspace_id: uuid::Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    pub rule_id: uuid::Uuid,
    pub rule_name: String,
    pub action: String,
    pub dry_run: bool,
    #[serde(with = "clickhouse::serde::chrono::datetime")]
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl PolicyEventRow {
    pub fn from_policy_event(
        pe: &secureprompt_common::types::PolicyEvent,
        request_id: uuid::Uuid,
        workspace_id: uuid::Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        Self {
            request_id,
            workspace_id,
            rule_id: pe.rule_id,
            rule_name: pe.rule_name.clone(),
            action: pe.action.clone(),
            dry_run: pe.dry_run,
            created_at,
        }
    }
}

#[derive(Row, Serialize)]
pub struct LatencySampleRow {
    #[serde(with = "clickhouse::serde::uuid")]
    pub request_id: uuid::Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    pub workspace_id: uuid::Uuid,
    pub model: String,
    pub latency_ms: u32,
    #[serde(with = "clickhouse::serde::chrono::datetime")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    // ── Migration 003: time-to-first-byte from upstream ────────────────────
    // Nullable because debug mode and adapters that don't issue a real
    // HTTP call (stubs, embeddings emitted from cached models) cannot
    // measure TTFT. Column order MUST match the ALTER TABLE order.
    pub ttft_ms: Option<u32>,
}

#[derive(Row, Serialize)]
pub struct TokenUsageRow {
    #[serde(with = "clickhouse::serde::uuid")]
    pub workspace_id: uuid::Uuid,
    pub model: String,
    // Column is `Date` (i16 days since epoch) — must use the `date` adapter,
    // not `date32` (i32). Mismatch produces:
    //   "attempting to (de)serialize ClickHouse type Date as i32"
    // and the row write fails silently in the analytics writer, leaving the
    // dashboard analytics queries with no rows to read.
    #[serde(with = "clickhouse::serde::chrono::date")]
    pub date: chrono::NaiveDate,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_usd: f64,
}

impl TokenUsageRow {
    pub fn from_event(e: &RequestEvent, date: chrono::NaiveDate) -> Self {
        Self {
            workspace_id: e.workspace_id.0,
            model: e.model.clone(),
            date,
            input_tokens: e.input_tokens.unwrap_or(0) as u64,
            output_tokens: e.output_tokens.unwrap_or(0) as u64,
            cost_usd: e.cost_usd,
        }
    }
}
