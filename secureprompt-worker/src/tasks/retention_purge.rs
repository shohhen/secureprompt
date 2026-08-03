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

use chrono::{DateTime, Duration, Utc};
use sqlx::{PgPool, Row as _};
use uuid::Uuid;

/// Scope name for the Postgres token vault.
pub const SCOPE_TOKEN_VAULT: &str = "token_vault_entries";
/// Scope name for `ClickHouse` captured request content.
pub const SCOPE_CONTENT_CAPTURES: &str = "request_content_captures";

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
    /// Recomputed AFTER deleting, with the same cutoff. The field an auditor
    /// can independently re-derive. Should be 0.
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

// ── (b) ClickHouse: captured content past the CURRENT retention ───────────

#[derive(serde::Deserialize, clickhouse::Row)]
struct CaptureStats {
    n: u64,
    /// `toUnixTimestamp(min(created_at))`. Zero when `n == 0`, which is why
    /// the range is only read when `n > 0`.
    oldest: u32,
    newest: u32,
}

async fn purge_content_captures(
    pg: &PgPool,
    ch: &clickhouse::Client,
    now: DateTime<Utc>,
) -> Vec<PurgeRecord> {
    let started_at = Utc::now();

    // The retention each workspace has configured RIGHT NOW — not the value
    // that was in force when the rows were written. That difference is the
    // entire point of this scope.
    let settings = sqlx::query("SELECT workspace_id, retention_days FROM workspace_raw_capture")
        .fetch_all(pg)
        .await;

    let settings = match settings {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(
                alert = "retention_purge_failed",
                scope = SCOPE_CONTENT_CAPTURES,
                error = %e,
                "could not read workspace retention settings; skipping capture purge"
            );
            // Fail CLOSED with respect to deletion: an unreadable settings
            // table must never be interpreted as "retention is zero, delete
            // everything".
            return vec![PurgeRecord::failure(
                SCOPE_CONTENT_CAPTURES,
                None,
                now,
                started_at,
                &e.to_string(),
            )];
        }
    };

    let mut records = Vec::with_capacity(settings.len());
    for row in settings {
        let workspace_id: Uuid = row.get("workspace_id");
        let retention_days: i32 = row.get("retention_days");
        records.push(
            purge_one_workspace_captures(ch, workspace_id, retention_days, now, started_at).await,
        );
    }
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

async fn write_audit(pg: &PgPool, run_id: Uuid, record: &PurgeRecord) -> Result<(), sqlx::Error> {
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
    .execute(pg)
    .await
    .map(|_| ())
}

#[cfg(test)]
mod tests;
