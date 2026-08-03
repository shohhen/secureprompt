//! WS3-4 — `retention.purge`, for real.
//!
//! # What it replaced
//!
//! ```text
//! task_types::RETENTION_PURGE => {
//!     tracing::debug!("retention.purge — no-op stub (Phase 7 implementation)");
//!     metrics.record_task(task_types::RETENTION_PURGE, "stub");
//! }
//! ```
//!
//! So the 24-hour `expires_at` that migration 008 puts on every
//! `token_vault_entries` row — and that `TokenVaultRepository::get` filters
//! on, giving every reader the impression it means something — was enforced
//! by nothing. The rows accumulated forever. Before WS3-3 that meant
//! plaintext PII accumulating forever.
//!
//! # Coverage
//!
//! * **`token_vault_entries`** (Postgres). Deletes rows whose `expires_at`
//!   has passed. This is the store whose retention had NO enforcement of any
//!   kind.
//! * **`request_content_captures`** (`ClickHouse`). The table carries
//!   `TTL expires_at DELETE`, which covers the ordinary case, but
//!   `expires_at` is stamped at INSERT time from the workspace's
//!   `retention_days`. An operator who LOWERS retention therefore does not
//!   shorten rows already on disk — WS3-2's author deferred that case to
//!   here. This job re-derives the boundary from the workspace's CURRENT
//!   retention on every run, so lowering takes effect at the next purge.
//! * **`refresh_tokens.device_context`** (Postgres, FU4). The IP address and
//!   client descriptor that migration 027 records on each sign-in so that a
//!   session listing can tell one device from another. Erased once the session
//!   is over. This scope SCRUBS COLUMNS rather than deleting rows — see
//!   [`scrub_session_device_context`] for why the row has to survive — so its
//!   `rows_deleted` is a count of rows whose personal data was erased.
//!
//! Direction matters and is asymmetric on purpose: the purge can only ever
//! bring the boundary IN. Raising `retention_days` does not resurrect rows
//! and does not extend rows whose stamped `expires_at` the engine's TTL is
//! about to collect. TTL is the ceiling, this job is the floor.
//!
//! # Failure policy
//!
//! Each scope is independent. A `ClickHouse` outage must not stop the vault
//! purge, and neither must abort the run silently: a failed scope still
//! writes an audit row, with `status = 'error'` and the message, so the gap
//! is visible in the same place the successes are.
//!
//! # "Nothing to do" and "I could not see anything" are different answers
//!
//! Migration 030 armed `workspace_raw_capture` and migration 033 made an
//! unscoped read of an armed table INVISIBLE — `Ok(vec![])`, not `22P02`. The
//! capture sweep read that table on a bare pool, so under a NOSUPERUSER /
//! NOBYPASSRLS role it saw no settings at all, built one record PER SETTINGS
//! ROW and therefore built NONE, and [`PurgeOutcome::all_ok`] — an `all(...)`
//! over the empty set — was vacuously true. The job reported success, the
//! captured plaintext was never purged, and the trail did not even mention the
//! scope.
//!
//! Two things fix that and both are load-bearing. A sweep enumerates
//! `workspaces` (not policed, and it CHECKS that before trusting it) and does
//! its work per workspace inside a transaction armed to that workspace and read
//! back, so `nothing to do` is a fact rather than a blind spot. And it writes
//! ONE global census record per run, always, whose `status` says whether it
//! could see — so a run that swept zero workspaces because it was blind records
//! `error` and makes `all_ok()` false, while a run that swept them and found
//! nothing to do records `ok`. Each sweeping scope has that pair under the
//! runner role:
//! `a_capture_sweep_with_nothing_to_do_still_records_the_scope` /
//! `a_capture_sweep_that_cannot_enumerate_workspaces_fails_loudly`, and
//! `a_device_context_scrub_with_nothing_to_do_still_records_the_scope` /
//! `a_device_context_scrub_that_cannot_enumerate_workspaces_fails_loudly`.
//!
//! # What `rows_remaining_past_cutoff` is, now that it has been wrong
//!
//! `refresh_tokens` is armed too, and migration 032 gave it the same `NULLIF`
//! treatment, so the device-context scrub had the identical defect with one
//! extra turn of the screw: BOTH its statements ran on a bare pool, so the
//! post-delete recount — the field migration 023 offers as the one an auditor
//! re-derives — was recomputed through the SAME filter that produced the zero
//! it was checking, and AGREED. The record emitted was byte-identical to a
//! genuine no-op's while two ended sessions kept their IP addresses.
//!
//! The number is a SELF-RECOUNT and is documented as one on
//! [`PurgeRecord::rows_remaining_past_cutoff`]. It catches a job that miscounted
//! what it deleted; it cannot catch a job that could not see. What covers that
//! is `status` and the census. What the per-workspace records buy is that the
//! number is now re-derivable by anyone who can arm that workspace's scope —
//! the tenant included — instead of only by someone who can see every tenant at
//! once.

use chrono::{DateTime, Duration, Utc};
use sqlx::{PgPool, Row as _};
use uuid::Uuid;

/// Scope name for the Postgres token vault.
pub const SCOPE_TOKEN_VAULT: &str = "token_vault_entries";
/// Scope name for `ClickHouse` captured request content.
pub const SCOPE_CONTENT_CAPTURES: &str = "request_content_captures";
/// FU4 — scope name for the device context on ended sessions.
///
/// Named for COLUMNS rather than a table, because that is what it acts on and
/// the distinction matters to whoever reads the audit trail: the rows are not
/// deleted and never will be. `GET /v1/data-inventory` declares a
/// `session_device_context` class citing this scope.
pub const SCOPE_SESSION_DEVICE_CONTEXT: &str = "refresh_tokens.device_context";

/// One scope of one purge run — the in-memory shape of a
/// `retention_purge_audit` row (migration 023).
#[derive(Debug, Clone)]
pub struct PurgeRecord {
    pub scope: String,
    pub workspace_id: Option<Uuid>,
    /// The policy boundary. Everything at or before this instant, in the
    /// dimension the scope is purged on, was eligible.
    pub cutoff: DateTime<Utc>,
    pub rows_deleted: i64,
    /// Range of what was deleted, in the SAME dimension as `cutoff`
    /// (`expires_at` for the vault, `created_at` for captures), so
    /// `newest_deleted <= cutoff` is a meaningful check rather than a
    /// comparison across two different clocks.
    pub oldest_deleted: Option<DateTime<Utc>>,
    pub newest_deleted: Option<DateTime<Utc>>,
    /// Recomputed AFTER deleting, with the same cutoff. Should be 0.
    ///
    /// WHAT IT IS AND IS NOT, because getting this wrong is what made P1J's
    /// defect self-confirming. It is a SELF-RECOUNT: the same process, on the
    /// same connection, through the same row-level-security filter as the
    /// delete. It therefore catches a job that MISCOUNTED what it deleted, and
    /// it cannot catch a job that could not SEE the rows — a filter that hides
    /// them hides them from both statements, and the two then agree on zero.
    ///
    /// Two things make it worth recording anyway. Every read that produces it
    /// now happens inside a scope that is armed and READ BACK, so a scope that
    /// did not take raises instead of answering nothing; and the per-workspace
    /// records are re-derivable by anyone who can arm that workspace's scope —
    /// the tenant included — rather than only by a DBA. What covers "could not
    /// see" is `status` and the per-run census record, not this number.
    pub rows_remaining_past_cutoff: i64,
    pub status: String,
    pub error: Option<String>,
    pub started_at: DateTime<Utc>,
}

impl PurgeRecord {
    fn failure(
        scope: &str,
        workspace_id: Option<Uuid>,
        cutoff: DateTime<Utc>,
        started_at: DateTime<Utc>,
        error: &str,
    ) -> Self {
        Self {
            scope: scope.to_owned(),
            workspace_id,
            cutoff,
            rows_deleted: 0,
            oldest_deleted: None,
            newest_deleted: None,
            rows_remaining_past_cutoff: -1,
            status: "error".to_owned(),
            error: Some(error.to_owned()),
            started_at,
        }
    }
}

/// Result of one purge run.
#[derive(Debug, Clone)]
pub struct PurgeOutcome {
    pub run_id: Uuid,
    pub records: Vec<PurgeRecord>,
}

impl PurgeOutcome {
    #[must_use]
    pub fn total_deleted(&self) -> i64 {
        self.records.iter().map(|r| r.rows_deleted).sum()
    }

    #[must_use]
    pub fn all_ok(&self) -> bool {
        self.records.iter().all(|r| r.status == "ok")
    }
}

/// Run one purge across every store with an enforceable retention window,
/// then persist a proof-of-purge record per scope.
///
/// `now` is captured ONCE and reused as the basis for every cutoff, for both
/// the delete and the post-delete re-check. Re-reading the clock between
/// those two would let a row become eligible in between and show up as a
/// phantom `rows_remaining_past_cutoff`.
pub async fn run(pg: &PgPool, ch: &clickhouse::Client) -> PurgeOutcome {
    let run_id = Uuid::new_v4();
    let now = Utc::now();
    let mut records = Vec::new();

    records.push(purge_token_vault(pg, now).await);
    records.extend(purge_content_captures(pg, ch, now).await);
    records.extend(scrub_session_device_context(pg, now).await);

    for record in &records {
        if let Err(e) = write_audit(pg, run_id, record).await {
            // The purge itself already happened; failing to record it is bad
            // but must be loud rather than fatal.
            tracing::error!(
                alert = "retention_purge_audit_write_failed",
                %run_id,
                scope = %record.scope,
                error = %e,
                "purge ran but its proof-of-purge record could not be written"
            );
        }
    }

    tracing::info!(
        %run_id,
        scopes = records.len(),
        rows_deleted = records.iter().map(|r| r.rows_deleted).sum::<i64>(),
        "retention.purge complete"
    );

    PurgeOutcome { run_id, records }
}

// ── (a) Postgres: expired token vault entries ─────────────────────────────

async fn purge_token_vault(pg: &PgPool, now: DateTime<Utc>) -> PurgeRecord {
    let started_at = Utc::now();

    // Delete and measure in ONE statement. Doing `SELECT count()` first and
    // `DELETE` second would report a count for a set that could have changed
    // in between; `RETURNING` measures exactly the rows this statement
    // removed.
    let deleted = sqlx::query(
        "WITH deleted AS (
             DELETE FROM token_vault_entries
             WHERE expires_at <= $1
             RETURNING expires_at
         )
         SELECT COUNT(*)::BIGINT AS n,
                MIN(expires_at)   AS oldest,
                MAX(expires_at)   AS newest
         FROM deleted",
    )
    .bind(now)
    .fetch_one(pg)
    .await;

    let row = match deleted {
        Ok(row) => row,
        Err(e) => {
            tracing::error!(
                alert = "retention_purge_failed",
                scope = SCOPE_TOKEN_VAULT,
                error = %e,
                "token vault purge failed"
            );
            return PurgeRecord::failure(SCOPE_TOKEN_VAULT, None, now, started_at, &e.to_string());
        }
    };

    let rows_deleted: i64 = row.get("n");
    let oldest: Option<DateTime<Utc>> = row.get("oldest");
    let newest: Option<DateTime<Utc>> = row.get("newest");

    // Re-derive the post-state against the SAME cutoff. This is the number an
    // auditor recomputes.
    let remaining: Result<i64, _> = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM token_vault_entries WHERE expires_at <= $1",
    )
    .bind(now)
    .fetch_one(pg)
    .await;

    match remaining {
        Ok(rows_remaining_past_cutoff) => PurgeRecord {
            scope: SCOPE_TOKEN_VAULT.to_owned(),
            workspace_id: None,
            cutoff: now,
            rows_deleted,
            oldest_deleted: oldest,
            newest_deleted: newest,
            rows_remaining_past_cutoff,
            status: "ok".to_owned(),
            error: None,
            started_at,
        },
        Err(e) => PurgeRecord::failure(SCOPE_TOKEN_VAULT, None, now, started_at, &e.to_string()),
    }
}

// ── (c) FU4: device context on sessions that have ended ───────────────────

/// Erase `client_ip` and `client_descriptor` from every session that is over.
///
/// # Why this scope exists
///
/// Migration 027 put an IP address and a client descriptor on the sign-in row
/// of each session, because a listing an administrator cannot tell apart does
/// not answer "which of these is the laptop I lost". Both are personal data on
/// a table whose rows are never deleted, so without this job the product would
/// accumulate one address per sign-in, per person, forever — and
/// `GET /v1/data-inventory` would have to say so.
///
/// # Why it is a SCRUB and not a DELETE
///
/// Deleting the rows would be simpler and would be wrong. Migration 002's
/// single-use rotation detects a replayed refresh token by finding the REVOKED
/// row it hashes to; a row that has been deleted is indistinguishable from a
/// token that never existed, so `rotate` would answer `NotFound` and threat
/// T-05-03's detection would quietly stop working. The row is the evidence.
/// The personal data on it is not evidence of anything, and it goes.
///
/// # The boundary is session liveness, not a clock
///
/// The other two scopes purge on a timestamp. This one purges on a FACT — the
/// session is over — which is `NOT EXISTS (a live row in this chain)`. The
/// decision is per CHAIN and not per row, and that is load-bearing rather than
/// tidy: the row that carries the device context is the sign-in row, and it is
/// itself `revoked_at IS NOT NULL` from the moment the session first rotates.
/// A per-row predicate would therefore erase the device of every session about
/// fifteen minutes into its life, leaving the listing full of unidentifiable
/// entries. `a_rotated_but_live_session_keeps_its_device_context` is that test.
///
/// # Why a loop over workspaces, and why the recount is a SECOND transaction
///
/// `refresh_tokens` has been under FORCE ROW LEVEL SECURITY since migration
/// 002, and migration 032 rewrote its `workspace_isolation` policy with
/// `NULLIF` so that an unscoped statement FILTERS rather than raising. Both of
/// this function's statements used to run on a bare pool. MEASURED under
/// `secureprompt_runner`, before this change, with two ended sessions carrying
/// an address: the UPDATE matched zero rows — not an error — the recount
/// answered zero through the same filter, and the record written was
/// `rows_deleted = 0`, `rows_remaining_past_cutoff = 0`, `status = 'ok'`:
/// byte-identical to the record a genuine no-op writes, with the field an
/// auditor is invited to re-derive AGREEING with the wrong answer.
///
/// So this takes `tasks::api_key_rotation::run`'s shape and
/// [`purge_content_captures`]'s, and rejects the same two shortcuts for the
/// same reasons: a policy admitting a cross-tenant sweep would hang off a GUC
/// any holder of the connection can set, widening the table for every statement
/// in the process rather than this one; and a `BYPASSRLS` worker role removes
/// the boundary from every query the worker makes, including ones written later
/// by someone who does not know the role is privileged.
///
/// The RECOUNT runs in its own armed transaction, after the scrub has
/// COMMITTED. It costs one round-trip and buys two things: the number describes
/// committed state — what someone re-deriving it would actually see — rather
/// than the scrub's own in-flight snapshot, and it arms and reads back a second
/// time, so it cannot inherit a scope the first transaction established.
///
/// `cutoff` is recorded as `now` because that is the instant the liveness
/// question was asked; `rows_deleted` counts rows SCRUBBED.
async fn scrub_session_device_context(pg: &PgPool, now: DateTime<Utc>) -> Vec<PurgeRecord> {
    let started_at = Utc::now();

    let workspaces = match enumerate_workspaces(pg).await {
        Ok(ids) => ids,
        Err(e) => {
            tracing::error!(
                alert = "retention_purge_failed",
                scope = SCOPE_SESSION_DEVICE_CONTEXT,
                error = %e,
                "could not enumerate workspaces; no session device context was \
                 erased anywhere and this run is recorded as FAILED"
            );
            return vec![census_record(
                SweepCensus::new(SCOPE_SESSION_DEVICE_CONTEXT, DEVICE_CONTEXT_CONSEQUENCE),
                now,
                started_at,
                Some(&e.to_string()),
            )];
        }
    };

    let mut census = SweepCensus {
        enumerated: workspaces.len(),
        ..SweepCensus::new(SCOPE_SESSION_DEVICE_CONTEXT, DEVICE_CONTEXT_CONSEQUENCE)
    };
    let mut records = Vec::new();
    for workspace_id in workspaces {
        match scrub_one_workspace_device_context(pg, workspace_id, now, started_at).await {
            Ok(record) => {
                census.swept += 1;
                // A workspace with nothing scrubbed and nothing left over has
                // nothing to say, and the census already records that it WAS
                // visited — so it gets no record of its own, exactly as an
                // unconfigured workspace gets none from the capture sweep.
                // `rows_remaining_past_cutoff > 0` is in the condition because
                // a row that arrived between the UPDATE and the recount is the
                // one case an auditor most needs in the trail.
                if record.rows_deleted > 0 || record.rows_remaining_past_cutoff > 0 {
                    records.push(record);
                }
            }
            Err(e) => {
                census.unreadable += 1;
                tracing::error!(
                    alert = "retention_purge_failed",
                    scope = SCOPE_SESSION_DEVICE_CONTEXT,
                    %workspace_id,
                    error = %e,
                    "could not scrub this workspace's session device context; \
                     the IP addresses on its ended sessions are still on disk"
                );
                records.push(PurgeRecord::failure(
                    SCOPE_SESSION_DEVICE_CONTEXT,
                    Some(workspace_id),
                    now,
                    started_at,
                    &e.to_string(),
                ));
            }
        }
    }

    tracing::info!(
        scope = SCOPE_SESSION_DEVICE_CONTEXT,
        enumerated = census.enumerated,
        swept = census.swept,
        unreadable = census.unreadable,
        "retention.purge device-context scrub"
    );
    records.push(census_record(census, now, started_at, None));
    records
}

/// One workspace's ended sessions, scrubbed inside that workspace's armed
/// scope.
///
/// The `workspace_id = $2` predicates are NOT redundant with the policy, and
/// leaving them out was measured to be wrong in the direction that reads as
/// success. A SUPERUSER bypasses row-level security, so without them the first
/// workspace's UPDATE would scrub the whole deployment and every later
/// workspace would report zero — one tenant's record claiming another tenant's
/// rows. With them the statement means the same thing under both roles, which
/// is also what lets the superuser test suites measure anything.
///
/// `live.workspace_id = r.workspace_id` is there for the same reason: a session
/// chain never spans workspaces, so the join is semantically identical either
/// way, but under a bypassing role the subquery would otherwise scan the whole
/// table and the two roles would be evaluating different statements.
async fn scrub_one_workspace_device_context(
    pg: &PgPool,
    workspace_id: Uuid,
    now: DateTime<Utc>,
    started_at: DateTime<Utc>,
) -> Result<PurgeRecord, sqlx::Error> {
    // ── Transaction 1: scrub and measure in ONE statement, for the reason
    // `purge_token_vault` gives — a separate count would report on a set that
    // could have changed.
    let mut tx = begin_armed(pg, workspace_id, DEVICE_CONTEXT_SCOPE_NOT_ARMED).await?;
    let row = sqlx::query(
        "WITH scrubbed AS (
             UPDATE refresh_tokens r
             SET client_ip = NULL, client_descriptor = NULL
             WHERE r.workspace_id = $2
               AND (r.client_ip IS NOT NULL OR r.client_descriptor IS NOT NULL)
               AND NOT EXISTS (
                   SELECT 1 FROM refresh_tokens live
                   WHERE live.session_id = r.session_id
                     AND live.workspace_id = r.workspace_id
                     AND live.revoked_at IS NULL
                     AND live.expires_at > $1
               )
             RETURNING r.created_at
         )
         SELECT COUNT(*)::BIGINT AS n,
                MIN(created_at)  AS oldest,
                MAX(created_at)  AS newest
         FROM scrubbed",
    )
    .bind(now)
    .bind(workspace_id)
    .fetch_one(&mut *tx)
    .await?;
    let rows_deleted: i64 = row.get("n");
    let oldest: Option<DateTime<Utc>> = row.get("oldest");
    let newest: Option<DateTime<Utc>> = row.get("newest");
    tx.commit().await?;

    // ── Transaction 2: re-derive the post-state with the SAME predicate, over
    // COMMITTED state, in a scope armed and read back again.
    let mut tx = begin_armed(pg, workspace_id, DEVICE_CONTEXT_SCOPE_NOT_ARMED).await?;
    let rows_remaining_past_cutoff: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM refresh_tokens r
         WHERE r.workspace_id = $2
           AND (r.client_ip IS NOT NULL OR r.client_descriptor IS NOT NULL)
           AND NOT EXISTS (
               SELECT 1 FROM refresh_tokens live
               WHERE live.session_id = r.session_id
                 AND live.workspace_id = r.workspace_id
                 AND live.revoked_at IS NULL
                 AND live.expires_at > $1
           )",
    )
    .bind(now)
    .bind(workspace_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(PurgeRecord {
        scope: SCOPE_SESSION_DEVICE_CONTEXT.to_owned(),
        workspace_id: Some(workspace_id),
        cutoff: now,
        rows_deleted,
        oldest_deleted: oldest,
        newest_deleted: newest,
        rows_remaining_past_cutoff,
        status: "ok".to_owned(),
        error: None,
        started_at,
    })
}

// ── (b) ClickHouse: captured content past the CURRENT retention ───────────

#[derive(serde::Deserialize, clickhouse::Row)]
struct CaptureStats {
    n: u64,
    /// `toUnixTimestamp(min(created_at))`. Zero when `n == 0`, which is why
    /// the range is only read when `n > 0`.
    oldest: u32,
    newest: u32,
}

/// The refusal recorded when the sweep's ONE bare-pool read is itself policed.
///
/// The enumeration below is sound only because `workspaces` is not under row
/// level security. If a migration ever arms it, the enumeration stops being a
/// list of every tenant and becomes a silent empty set — the same shape as the
/// defect this whole function was rewritten to remove, one level up. So the
/// precondition is CHECKED rather than commented, and its failure is recorded.
const WORKSPACES_ARE_POLICED: &str =
    "row security is active on `workspaces` for this connection, so enumerating \
     it would return a filtered list and any sweep built on it would silently \
     skip every workspace it cannot see";

/// The refusal recorded when one workspace's settings transaction did not take
/// the scope. Same shape and the same reason as [`SCOPE_NOT_ARMED`] below and
/// `tasks::api_key_rotation`'s constant of that name.
const SETTINGS_SCOPE_NOT_ARMED: &str =
    "the retention-settings transaction could not be scoped to this workspace, \
     so its captured content was not purged";

/// The refusal recorded when one workspace's device-context transaction did not
/// take the scope. Same shape and reason as [`SETTINGS_SCOPE_NOT_ARMED`].
const DEVICE_CONTEXT_SCOPE_NOT_ARMED: &str =
    "the device-context transaction could not be scoped to this workspace, so \
     the IP addresses on its ended sessions were not erased";

/// What a workspace the capture sweep could not reach did not get.
const CAPTURES_CONSEQUENCE: &str = "their captured content was not purged";

/// What a workspace the device-context scrub could not reach did not get.
const DEVICE_CONTEXT_CONSEQUENCE: &str = "the IP addresses on their ended sessions were not erased";

/// What one sweep SAW, as opposed to what it deleted.
///
/// This is the answer to "was there nothing to do, or could I not see
/// anything?", and it exists because the two used to be the same observation.
///
/// Both sweeping scopes share this type rather than each growing one of their
/// own: `refresh_tokens.device_context` has exactly the shape
/// `request_content_captures` has, and two mechanisms that only look alike are
/// how the second drifts from the first.
#[derive(Debug, Clone, Copy)]
struct SweepCensus {
    /// The scope this census is about — one of the `SCOPE_*` constants.
    scope: &'static str,
    /// What a workspace this sweep could not reach did NOT get, in the words
    /// the audit row will carry.
    consequence: &'static str,
    /// Workspaces the sweep enumerated and looked at.
    enumerated: usize,
    /// Of those, the ones the sweep actually acted on — read from a transaction
    /// armed to that workspace, so `nothing to do` means nothing to do.
    swept: usize,
    /// Workspaces the sweep could not reach at all. Any non-zero value makes
    /// the census record `status = 'error'`, which makes
    /// [`PurgeOutcome::all_ok`] false and the job record itself as FAILED.
    unreadable: usize,
}

impl SweepCensus {
    const fn new(scope: &'static str, consequence: &'static str) -> Self {
        Self {
            scope,
            consequence,
            enumerated: 0,
            swept: 0,
            unreadable: 0,
        }
    }
}

/// Open a transaction, arm it to `workspace_id`, and READ THE SETTING BACK
/// before handing it over.
///
/// The read-back is the whole point and it is not ceremony. `set_config`
/// succeeding does not prove the GUC holds the value the policy will filter by,
/// and since migration 033 a statement whose scope did not take does not raise
/// — it answers the empty set, or reports `UPDATE 0`. `not_armed` is the
/// refusal recorded when it did not take; each caller supplies its own so the
/// audit row says which sweep lost which workspace.
async fn begin_armed<'p>(
    pg: &'p PgPool,
    workspace_id: Uuid,
    not_armed: &'static str,
) -> Result<sqlx::Transaction<'p, sqlx::Postgres>, sqlx::Error> {
    let mut tx = pg.begin().await?;
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
        .bind(workspace_id.to_string())
        .execute(&mut *tx)
        .await?;
    let armed: Option<String> =
        sqlx::query_scalar("SELECT current_setting('app.current_workspace_id', true)")
            .fetch_one(&mut *tx)
            .await?;
    if armed.as_deref() != Some(workspace_id.to_string().as_str()) {
        return Err(sqlx::Error::Protocol(not_armed.to_owned()));
    }
    Ok(tx)
}

/// Enumerate every tenant, refusing to do so blind.
///
/// `workspaces` carries no `workspace_id` and no policy, which is what lets the
/// one cross-tenant read this job needs stay on a bare pool. MEASURED both
/// ways: `SELECT row_security_active('public.workspaces')` answers `false` for
/// the runner role on the current schema, and `true` in
/// `a_capture_sweep_that_cannot_enumerate_workspaces_fails_loudly`, which arms
/// the table and requires the run to fail.
async fn enumerate_workspaces(pg: &PgPool) -> Result<Vec<Uuid>, sqlx::Error> {
    let policed: bool = sqlx::query_scalar("SELECT row_security_active('public.workspaces')")
        .fetch_one(pg)
        .await?;
    if policed {
        return Err(sqlx::Error::Protocol(WORKSPACES_ARE_POLICED.to_owned()));
    }
    sqlx::query_scalar::<_, Uuid>("SELECT id FROM workspaces")
        .fetch_all(pg)
        .await
}

/// One workspace's CURRENT retention, read inside a transaction armed to that
/// workspace and READ BACK before the SELECT runs.
///
/// The read-back is the difference between this and the bare-pool read it
/// replaces. `set_config` succeeding does not prove the GUC holds the value the
/// policy will filter by — and if it does not, migration 030's
/// `workspace_isolation` predicate is NULL for every row and the SELECT
/// answers `Ok(None)`, indistinguishable from a workspace that never switched
/// capture on. `Ok(None)` from this function means the row is genuinely absent.
async fn read_capture_retention(
    pg: &PgPool,
    workspace_id: Uuid,
) -> Result<Option<i32>, sqlx::Error> {
    let mut tx = begin_armed(pg, workspace_id, SETTINGS_SCOPE_NOT_ARMED).await?;
    let retention_days: Option<i32> = sqlx::query_scalar(
        "SELECT retention_days FROM workspace_raw_capture WHERE workspace_id = $1",
    )
    .bind(workspace_id)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(retention_days)
}

/// The CENSUS row: one global record per run saying whether the sweep could
/// see, written whether or not any workspace had work.
///
/// It is `workspace_id IS NULL` on purpose, and that is load-bearing twice
/// over. Migration 030's `workspace_isolation_or_global` policy admits a NULL
/// row with nothing armed, so this is the one record of this scope that can
/// always be written — including on the runs where arming a scope is exactly
/// what failed. And it is the record whose ABSENCE used to be the symptom:
/// `purge_content_captures` built one record per settings row, so a read that
/// returned nothing produced nothing, `PurgeOutcome::all_ok` was
/// `all(...)` over the empty set — true — and the trail simply omitted the
/// scope for that run.
///
/// `rows_deleted` is 0 by construction: the census deletes nothing itself and
/// the per-workspace records carry the counts, so
/// [`PurgeOutcome::total_deleted`] must not double-count them.
/// `rows_remaining_past_cutoff` is 0 for the same reason — the census has no
/// cutoff of its own to re-derive against, and the per-workspace records carry
/// the number an auditor recomputes. The workspace counts live in the
/// `retention.purge capture sweep` log line, not in columns that mean rows.
fn census_record(
    census: SweepCensus,
    now: DateTime<Utc>,
    started_at: DateTime<Utc>,
    enumeration_error: Option<&str>,
) -> PurgeRecord {
    if let Some(error) = enumeration_error {
        return PurgeRecord::failure(census.scope, None, now, started_at, error);
    }
    if census.unreadable > 0 {
        return PurgeRecord::failure(
            census.scope,
            None,
            now,
            started_at,
            &format!(
                "{} of {} workspaces could not be swept, so {}",
                census.unreadable, census.enumerated, census.consequence
            ),
        );
    }
    PurgeRecord {
        scope: census.scope.to_owned(),
        workspace_id: None,
        cutoff: now,
        rows_deleted: 0,
        oldest_deleted: None,
        newest_deleted: None,
        rows_remaining_past_cutoff: 0,
        status: "ok".to_owned(),
        error: None,
        started_at,
    }
}

/// Sweep captured content in every workspace, once per workspace, with that
/// workspace's scope armed.
///
/// # Why a loop and not one statement, and why not a wider policy
///
/// The sweep is cross-tenant by design — it is one nightly job for the whole
/// deployment — but "cross-tenant" is not a reason to give the job a
/// cross-tenant VIEW of `workspace_raw_capture`.
/// `tasks::api_key_rotation::run` solved the identical shape and rejected the
/// same two shortcuts for the same reasons: a policy admitting the sweep would
/// hang off a GUC that any holder of the same connection can set, widening the
/// table for every statement in the process rather than this one; and a
/// `BYPASSRLS` worker role removes the boundary from every query the worker
/// makes, including ones written later by someone who does not know the role is
/// privileged. This does neither. The widest read it adds is
/// `SELECT id FROM workspaces` — a list of tenant UUIDs the worker already
/// holds the credentials to obtain.
///
/// # Failure is per workspace and it is LOUD
///
/// One workspace erroring does not abort the others; it produces that
/// workspace's own `status = 'error'` record AND increments the census's
/// `unreadable`, which turns the census record into a failure and makes
/// [`PurgeOutcome::all_ok`] false. The silent-success path this replaces is the
/// whole defect.
///
/// It also fails CLOSED with respect to deletion, which is the older invariant
/// and still holds: an unreadable settings row must never be interpreted as
/// "retention is zero, delete everything", so a workspace whose settings could
/// not be read is SKIPPED, not purged with a default.
async fn purge_content_captures(
    pg: &PgPool,
    ch: &clickhouse::Client,
    now: DateTime<Utc>,
) -> Vec<PurgeRecord> {
    let started_at = Utc::now();

    let workspaces = match enumerate_workspaces(pg).await {
        Ok(ids) => ids,
        Err(e) => {
            tracing::error!(
                alert = "retention_purge_failed",
                scope = SCOPE_CONTENT_CAPTURES,
                error = %e,
                "could not enumerate workspaces; captured content was not purged \
                 anywhere and this run is recorded as FAILED"
            );
            return vec![census_record(
                SweepCensus::new(SCOPE_CONTENT_CAPTURES, CAPTURES_CONSEQUENCE),
                now,
                started_at,
                Some(&e.to_string()),
            )];
        }
    };

    let mut census = SweepCensus {
        enumerated: workspaces.len(),
        ..SweepCensus::new(SCOPE_CONTENT_CAPTURES, CAPTURES_CONSEQUENCE)
    };
    let mut records = Vec::new();
    for workspace_id in workspaces {
        // The retention this workspace has configured RIGHT NOW — not the
        // value that was in force when the rows were written. That difference
        // is the entire point of this scope.
        match read_capture_retention(pg, workspace_id).await {
            // Capture was never switched on here. Nothing to purge, and — read
            // back from an armed transaction — that is a fact rather than a
            // blind spot, so it gets no record of its own.
            Ok(None) => {}
            Ok(Some(retention_days)) => {
                census.swept += 1;
                records.push(
                    purge_one_workspace_captures(ch, workspace_id, retention_days, now, started_at)
                        .await,
                );
            }
            Err(e) => {
                census.unreadable += 1;
                tracing::error!(
                    alert = "retention_purge_failed",
                    scope = SCOPE_CONTENT_CAPTURES,
                    %workspace_id,
                    error = %e,
                    "could not read this workspace's retention settings; its \
                     captured content was NOT purged"
                );
                records.push(PurgeRecord::failure(
                    SCOPE_CONTENT_CAPTURES,
                    Some(workspace_id),
                    now,
                    started_at,
                    &e.to_string(),
                ));
            }
        }
    }

    tracing::info!(
        scope = SCOPE_CONTENT_CAPTURES,
        enumerated = census.enumerated,
        swept = census.swept,
        unreadable = census.unreadable,
        "retention.purge capture sweep"
    );
    records.push(census_record(census, now, started_at, None));
    records
}

async fn purge_one_workspace_captures(
    ch: &clickhouse::Client,
    workspace_id: Uuid,
    retention_days: i32,
    now: DateTime<Utc>,
    started_at: DateTime<Utc>,
) -> PurgeRecord {
    let cutoff = now - Duration::days(i64::from(retention_days));
    let cutoff_unix = cutoff.timestamp();

    // UUIDs are interpolated rather than bound. They come from a Postgres
    // UUID column, so they are structurally hex-and-dashes and cannot carry
    // SQL — and `toUUID('...')` would reject anything else outright.
    let scope_sql = format!(
        "workspace_id = toUUID('{workspace_id}') AND created_at < toDateTime({cutoff_unix})"
    );

    // Measure BEFORE deleting: ClickHouse deletes do not report a row count.
    let stats: Result<CaptureStats, _> = ch
        .query(&format!(
            "SELECT count() AS n,
                    toUnixTimestamp(min(created_at)) AS oldest,
                    toUnixTimestamp(max(created_at)) AS newest
             FROM request_content_captures WHERE {scope_sql}"
        ))
        .fetch_one()
        .await;

    let stats = match stats {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                alert = "retention_purge_failed",
                scope = SCOPE_CONTENT_CAPTURES,
                %workspace_id,
                error = %e,
                "could not measure captured content before purge"
            );
            return PurgeRecord::failure(
                SCOPE_CONTENT_CAPTURES,
                Some(workspace_id),
                cutoff,
                started_at,
                &e.to_string(),
            );
        }
    };

    if let Err(e) = ch
        .query(&format!(
            "DELETE FROM request_content_captures WHERE {scope_sql}"
        ))
        .execute()
        .await
    {
        tracing::error!(
            alert = "retention_purge_failed",
            scope = SCOPE_CONTENT_CAPTURES,
            %workspace_id,
            error = %e,
            "captured content delete failed"
        );
        return PurgeRecord::failure(
            SCOPE_CONTENT_CAPTURES,
            Some(workspace_id),
            cutoff,
            started_at,
            &e.to_string(),
        );
    }

    // Post-state, same cutoff.
    let remaining: Result<u64, _> = ch
        .query(&format!(
            "SELECT count() FROM request_content_captures WHERE {scope_sql}"
        ))
        .fetch_one()
        .await;

    let rows_remaining_past_cutoff = match remaining {
        Ok(n) => i64::try_from(n).unwrap_or(i64::MAX),
        Err(e) => {
            return PurgeRecord::failure(
                SCOPE_CONTENT_CAPTURES,
                Some(workspace_id),
                cutoff,
                started_at,
                &e.to_string(),
            )
        }
    };

    let (oldest, newest) = if stats.n == 0 {
        (None, None)
    } else {
        (unix_to_utc(stats.oldest), unix_to_utc(stats.newest))
    };

    PurgeRecord {
        scope: SCOPE_CONTENT_CAPTURES.to_owned(),
        workspace_id: Some(workspace_id),
        cutoff,
        rows_deleted: i64::try_from(stats.n).unwrap_or(i64::MAX),
        oldest_deleted: oldest,
        newest_deleted: newest,
        rows_remaining_past_cutoff,
        status: "ok".to_owned(),
        error: None,
        started_at,
    }
}

fn unix_to_utc(secs: u32) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(i64::from(secs), 0)
}

// ── proof-of-purge ────────────────────────────────────────────────────────

/// The refusal recorded when the tenancy GUC did not take, matching
/// `tasks::audit_export`'s constant of the same name.
const SCOPE_NOT_ARMED: &str =
    "the proof-of-purge transaction could not be scoped to the record's workspace, so \
     nothing was written";

/// Append one scope's proof-of-purge row.
///
/// Migration 030 put FORCE ROW LEVEL SECURITY on `retention_purge_audit` with
/// a policy that admits `workspace_id IS NULL OR workspace_id =
/// current_setting('app.current_workspace_id', true)::uuid`. That shape is
/// what this function has to satisfy, and the two row shapes need different
/// things from it:
///
///   * GLOBAL records carry `workspace_id IS NULL`, which the policy admits
///     with nothing armed. They go straight onto the pool. Both
///     `token_vault_entries` and `refresh_tokens.device_context` are wholly of
///     this shape, and so is the ONE census record
///     [`purge_content_captures`] writes per run — deliberately, because it is
///     the record that has to survive a run in which arming a scope is what
///     failed.
///   * PER-WORKSPACE records (the rest of `request_content_captures`, one per
///     configured workspace) are rejected unless the GUC is armed to THAT
///     row's workspace. A single run covers many workspaces, so the scope is
///     armed per record rather than per run.
///
/// The scope is armed and READ BACK, for the same reason
/// `db::scope::begin_scoped` does it on the API side: an unarmed transaction
/// must fail loudly. Here the loud failure is real either way — an unarmed
/// INSERT is refused with 42501 — but the read-back names the cause instead of
/// leaving the caller to infer it from a policy violation.
///
/// MEASURED before 030 was accompanied by this change: with the table armed
/// and the write left on a bare pool, the per-workspace INSERT failed
/// `42501 new row violates row-level security policy for table
/// "retention_purge_audit"`, while both global INSERTs succeeded. `run()`
/// logs that failure as `retention_purge_audit_write_failed` and CONTINUES —
/// so the purge would have happened and its evidence would not exist.
async fn write_audit(pg: &PgPool, run_id: Uuid, record: &PurgeRecord) -> Result<(), sqlx::Error> {
    let Some(workspace_id) = record.workspace_id else {
        // Global scope. `workspace_id IS NULL` satisfies the policy on its
        // own, and there is no workspace to arm the GUC to.
        return insert_audit_row(pg, run_id, record).await;
    };

    let mut tx = pg.begin().await?;
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
        .bind(workspace_id.to_string())
        .execute(&mut *tx)
        .await?;
    let armed: Option<String> =
        sqlx::query_scalar("SELECT current_setting('app.current_workspace_id', true)")
            .fetch_one(&mut *tx)
            .await?;
    if armed.as_deref() != Some(workspace_id.to_string().as_str()) {
        return Err(sqlx::Error::Protocol(SCOPE_NOT_ARMED.to_owned()));
    }

    insert_audit_row(&mut *tx, run_id, record).await?;
    tx.commit().await
}

/// The INSERT itself, over whichever executor [`write_audit`] chose — the pool
/// for a global scope, the scoped transaction for a per-workspace one. One
/// copy of the column list, so the two paths cannot drift.
async fn insert_audit_row<'e, E>(
    executor: E,
    run_id: Uuid,
    record: &PurgeRecord,
) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query(
        "INSERT INTO retention_purge_audit
             (id, run_id, scope, workspace_id, cutoff, rows_deleted,
              oldest_deleted, newest_deleted, rows_remaining_past_cutoff,
              status, error, started_at, completed_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())",
    )
    .bind(Uuid::new_v4())
    .bind(run_id)
    .bind(&record.scope)
    .bind(record.workspace_id)
    .bind(record.cutoff)
    .bind(record.rows_deleted)
    .bind(record.oldest_deleted)
    .bind(record.newest_deleted)
    .bind(record.rows_remaining_past_cutoff)
    .bind(&record.status)
    .bind(record.error.as_deref())
    .bind(record.started_at)
    .execute(executor)
    .await
    .map(|_| ())
}

#[cfg(test)]
mod tests;
