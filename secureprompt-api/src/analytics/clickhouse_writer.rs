use crate::{
    analytics::events::{LatencySampleRow, PolicyEventRow, RequestEvent, RequestEventRow, TokenUsageRow},
    observability::metrics::MetricsRegistry,
};
use clickhouse::{Client, Row};
use serde::Deserialize;
use std::{sync::Arc, time::Duration};
use tokio::sync::mpsc;

/// Every column `RequestEventRow` writes. Kept in lock-step with that struct
/// (and therefore with `clickhouse/migrations/*`) — the probe below reports
/// any that the live table is missing.
const REQUEST_EVENTS_COLUMNS: &[&str] = &[
    "request_id",
    "workspace_id",
    "provider",
    "model",
    "final_action",
    "input_tokens",
    "output_tokens",
    "reasoning_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
    "estimated_usage",
    "cost_usd",
    "created_at",
    "user_id",
    "api_key_id",
    "api_key_name",
    "ip_address",
    "user_agent",
    "redacted_prompt",
    "restored_response",
    "raw_prompt",
    "raw_response",
    "floor_only",
];

#[derive(Row, Deserialize)]
struct ColumnNameRow {
    name: String,
}

/// One-shot startup check that the live `request_events` table has every
/// column the writer serialises. Logs an alert-keyed error and bumps
/// `secureprompt_clickhouse_schema_mismatch_total` when it does not.
///
/// Deliberately non-fatal: a ClickHouse that is merely slow to come up must
/// not take the gateway down with it, and the analytics path is best-effort
/// by design. The point is that "analytics silently dropping 100% of events
/// because the worker has not run its migrations" becomes a visible,
/// alertable condition rather than an inference from an empty dashboard.
async fn verify_request_events_schema(client: &Client, metrics: &Arc<MetricsRegistry>) {
    let found = match client
        .query(
            "SELECT name FROM system.columns \
             WHERE database = currentDatabase() AND table = 'request_events'",
        )
        .fetch_all::<ColumnNameRow>()
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "could not read request_events schema from ClickHouse; skipping startup schema check"
            );
            return;
        }
    };

    if found.is_empty() {
        tracing::error!(
            alert = "clickhouse_schema_stale",
            table = "request_events",
            "request_events does not exist — ClickHouse migrations have not run \
             (they are applied by secureprompt-worker at startup). EVERY analytics \
             event will be dropped until it does."
        );
        metrics.record_clickhouse_schema_mismatch();
        return;
    }

    let missing: Vec<&str> = REQUEST_EVENTS_COLUMNS
        .iter()
        .filter(|want| !found.iter().any(|c| c.name == **want))
        .copied()
        .collect();
    if !missing.is_empty() {
        tracing::error!(
            alert = "clickhouse_schema_stale",
            table = "request_events",
            missing = %missing.join(","),
            "request_events is missing columns the writer serialises — run the ClickHouse \
             migrations (secureprompt-worker applies them at startup). Until then EVERY \
             analytics event is dropped wholesale, across all four tables."
        );
        metrics.record_clickhouse_schema_mismatch();
    }
}

pub const CLICKHOUSE_INSERT_SETTINGS: &str = "async_insert=1&wait_for_async_insert=1";
const BATCH_MAX_ROWS: u64 = 100;
const BATCH_PERIOD_SECS: u64 = 1;
const INSERT_TIMEOUT_SECS: u64 = 5;
const INSERT_SEND_TIMEOUT_SECS: u64 = 20;
/// Wall-clock bound on the one-shot startup schema probe. Must exist: the
/// probe runs before the consumer loop starts draining the channel.
const SCHEMA_PROBE_TIMEOUT_SECS: u64 = 10;

pub fn build_clickhouse_client(url: &str, database: &str) -> Client {
    Client::default()
        .with_url(url)
        .with_database(database)
        .with_setting("async_insert", "1")
        .with_setting("wait_for_async_insert", "1")
}

#[derive(Debug, Clone)]
pub struct AnalyticsHandle {
    sender: mpsc::Sender<RequestEvent>,
}

impl AnalyticsHandle {
    #[must_use]
    pub fn new(metrics: Arc<MetricsRegistry>, ch_url: &str, ch_database: &str) -> Self {
        let (sender, mut receiver) = mpsc::channel::<RequestEvent>(256);
        let ch_client = build_clickhouse_client(ch_url, ch_database);
        let metrics_task = metrics.clone();

        tokio::spawn(async move {
            // WS2-3 fix round 1 — schema probe BEFORE the first insert.
            //
            // The API writes `request_events` but the ClickHouse migrations
            // run in the WORKER. On an API-first startup (or a partial
            // rollout where the worker has not been upgraded), every row
            // fails the RowBinary schema check and the loop's `continue`
            // abandons the whole event — all four tables, not just the table
            // whose column is missing. That used to surface only as a
            // `warn!`/`error!` per event, which looks like transient noise.
            //
            // Probe once, loudly, and expose it as a counter so an alert can
            // fire instead of an operator noticing an empty audit log a week
            // later.
            // Bounded: the probe runs AHEAD of the consumer loop, so a hung
            // or blackholed ClickHouse would block the receiver forever, the
            // 256-slot channel would fill, and `enqueue`'s `try_send` would
            // then drop every event — the same total analytics loss this
            // probe exists to make visible, with a wider trigger. A refused
            // connection errors immediately; a hung one needs this.
            if tokio::time::timeout(
                Duration::from_secs(SCHEMA_PROBE_TIMEOUT_SECS),
                verify_request_events_schema(&ch_client, &metrics_task),
            )
            .await
            .is_err()
            {
                tracing::warn!(
                    timeout_secs = SCHEMA_PROBE_TIMEOUT_SECS,
                    "ClickHouse schema probe timed out; continuing without it"
                );
            }

            let mut req_inserter = ch_client
                .inserter::<RequestEventRow>("request_events")
                .with_timeouts(
                    Some(Duration::from_secs(INSERT_TIMEOUT_SECS)),
                    Some(Duration::from_secs(INSERT_SEND_TIMEOUT_SECS)),
                )
                .with_max_rows(BATCH_MAX_ROWS)
                .with_period(Some(Duration::from_secs(BATCH_PERIOD_SECS)));

            let mut pol_inserter = ch_client
                .inserter::<PolicyEventRow>("policy_events")
                .with_timeouts(
                    Some(Duration::from_secs(INSERT_TIMEOUT_SECS)),
                    Some(Duration::from_secs(INSERT_SEND_TIMEOUT_SECS)),
                )
                .with_max_rows(BATCH_MAX_ROWS)
                .with_period(Some(Duration::from_secs(BATCH_PERIOD_SECS)));

            let mut lat_inserter = ch_client
                .inserter::<LatencySampleRow>("latency_samples")
                .with_timeouts(
                    Some(Duration::from_secs(INSERT_TIMEOUT_SECS)),
                    Some(Duration::from_secs(INSERT_SEND_TIMEOUT_SECS)),
                )
                .with_max_rows(BATCH_MAX_ROWS)
                .with_period(Some(Duration::from_secs(BATCH_PERIOD_SECS)));

            let mut tok_inserter = ch_client
                .inserter::<TokenUsageRow>("token_usage")
                .with_timeouts(
                    Some(Duration::from_secs(INSERT_TIMEOUT_SECS)),
                    Some(Duration::from_secs(INSERT_SEND_TIMEOUT_SECS)),
                )
                .with_max_rows(BATCH_MAX_ROWS)
                .with_period(Some(Duration::from_secs(BATCH_PERIOD_SECS)));

            while let Some(event) = receiver.recv().await {
                let now = chrono::Utc::now();
                let req_row = RequestEventRow::from_event(&event, now);

                if let Err(e) = req_inserter.write(&req_row).await {
                    tracing::warn!(error = %e, "request_events write error; retrying once");

                    metrics_task.record_clickhouse_insert_retry();
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    if let Err(e2) = req_inserter.write(&req_row).await {
                        tracing::error!(error = %e2, "request_events write failed after retry; dropping");
                        metrics_task.record_clickhouse_insert_failure();
                        // Retry exhausted: this event (request_events row +
                        // everything downstream in this loop iteration —
                        // policy_events/latency_samples/token_usage — is
                        // abandoned wholesale via `continue`. Distinct from
                        // `record_analytics_drop()` (buffer-full backpressure
                        // in `enqueue`, event never entered the channel):
                        // this event WAS dequeued but a real, non-retryable
                        // write failure abandoned it.
                        metrics_task.record_analytics_failure();
                        continue;
                    }
                }

                // The startup probe latches a schema-mismatch flag. A write
                // that actually lands proves the schema is now good (the
                // worker migrated, or the probe raced startup), so clear it —
                // otherwise `ClickHouseSchemaStale` would keep firing after
                // the system had self-healed, until someone restarted the API.
                metrics_task.clear_clickhouse_schema_mismatch();

                for pe in &event.policy_events {
                    let pol_row = PolicyEventRow::from_policy_event(
                        pe,
                        event.request_id.0,
                        event.workspace_id.0,
                        now,
                    );
                    if let Err(e) = pol_inserter.write(&pol_row).await {
                        tracing::error!(error = %e, "policy_events write error; dropping");
                        metrics_task.record_clickhouse_insert_failure();
                    }
                }

                if let Some(latency_ms) = event.latency_ms {
                    let lat_row = LatencySampleRow {
                        request_id: event.request_id.0,
                        workspace_id: event.workspace_id.0,
                        model: event.model.clone(),
                        latency_ms,
                        created_at: now,
                        ttft_ms: event.ttft_ms,
                    };
                    if let Err(e) = lat_inserter.write(&lat_row).await {
                        tracing::error!(error = %e, "latency_samples write error; dropping");
                        metrics_task.record_clickhouse_insert_failure();
                    }
                }

                let tok_row = TokenUsageRow::from_event(&event, now.date_naive());
                if let Err(e) = tok_inserter.write(&tok_row).await {
                    tracing::error!(error = %e, "token_usage write error; dropping");
                    metrics_task.record_clickhouse_insert_failure();
                }

                if let Err(e) = req_inserter.commit().await {
                    tracing::error!(error = %e, "request_events inserter commit error");
                    metrics_task.record_clickhouse_insert_failure();
                }
                if let Err(e) = pol_inserter.commit().await {
                    tracing::error!(error = %e, "policy_events inserter commit error");
                    metrics_task.record_clickhouse_insert_failure();
                }
                if let Err(e) = lat_inserter.commit().await {
                    tracing::error!(error = %e, "latency_samples inserter commit error");
                    metrics_task.record_clickhouse_insert_failure();
                }
                if let Err(e) = tok_inserter.commit().await {
                    tracing::error!(error = %e, "token_usage inserter commit error");
                    metrics_task.record_clickhouse_insert_failure();
                }
            }

            let _ = req_inserter.end().await;
            let _ = pol_inserter.end().await;
            let _ = lat_inserter.end().await;
            let _ = tok_inserter.end().await;
        });

        Self { sender }
    }

    pub async fn enqueue(&self, event: RequestEvent, metrics: &MetricsRegistry) {
        if self.sender.try_send(event).is_err() {
            metrics.record_analytics_drop();
            tracing::warn!("analytics buffer full; dropping request event");
        }
    }
}

#[cfg(test)]
mod schema_probe_tests {
    use super::{build_clickhouse_client, verify_request_events_schema, REQUEST_EVENTS_COLUMNS};
    use crate::observability::metrics::MetricsRegistry;
    use std::sync::Arc;

    fn ch_url() -> String {
        std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://localhost:8123".to_owned())
    }

    /// Raw HTTP so the fixture setup does not depend on the very client the
    /// probe uses.
    async fn exec(sql: &str) {
        let response = reqwest::Client::new()
            .post(format!("{}/", ch_url()))
            .body(sql.to_owned())
            .send()
            .await
            .expect("ClickHouse must be reachable — see CLICKHOUSE_URL in the task env");
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        assert!(status.is_success(), "clickhouse ddl failed ({status}): {body}\nsql: {sql}");
    }

    /// The probe must flag a table that is missing a column the writer
    /// serialises — that is the state in which EVERY analytics event is
    /// dropped wholesale because the worker has not run its migrations.
    ///
    /// Positive control is the second half: the SAME probe against a table
    /// that has every column must leave the gauge at 0. Without it, "the
    /// gauge is 1" would be satisfied by a probe that flags unconditionally.
    #[tokio::test]
    async fn probe_flags_a_stale_schema_and_passes_a_complete_one() {
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let stale_db = format!("sp_probe_stale_{suffix}");
        let good_db = format!("sp_probe_good_{suffix}");

        // A complete table, and a copy with one required column removed.
        let all_columns = REQUEST_EVENTS_COLUMNS
            .iter()
            .map(|c| format!("{c} String"))
            .collect::<Vec<_>>()
            .join(", ");
        let missing_floor_only = REQUEST_EVENTS_COLUMNS
            .iter()
            .filter(|c| **c != "floor_only")
            .map(|c| format!("{c} String"))
            .collect::<Vec<_>>()
            .join(", ");

        for (db, cols) in [(&good_db, &all_columns), (&stale_db, &missing_floor_only)] {
            exec(&format!("CREATE DATABASE IF NOT EXISTS {db}")).await;
            exec(&format!(
                "CREATE TABLE IF NOT EXISTS {db}.request_events ({cols}) \
                 ENGINE = MergeTree ORDER BY tuple()"
            ))
            .await;
        }

        // Stale schema -> flagged.
        let stale_metrics = Arc::new(MetricsRegistry::default());
        assert_eq!(
            stale_metrics.clickhouse_schema_mismatch_count(),
            0,
            "premise: a fresh registry starts clean"
        );
        verify_request_events_schema(
            &build_clickhouse_client(&ch_url(), &stale_db),
            &stale_metrics,
        )
        .await;
        assert_eq!(
            stale_metrics.clickhouse_schema_mismatch_count(),
            1,
            "a table missing floor_only must be flagged"
        );

        // POSITIVE CONTROL: complete schema -> not flagged.
        let good_metrics = Arc::new(MetricsRegistry::default());
        verify_request_events_schema(&build_clickhouse_client(&ch_url(), &good_db), &good_metrics)
            .await;
        assert_eq!(
            good_metrics.clickhouse_schema_mismatch_count(),
            0,
            "a table with every required column must NOT be flagged"
        );

        // The gauge clears when an insert proves the schema is fine.
        stale_metrics.clear_clickhouse_schema_mismatch();
        assert_eq!(stale_metrics.clickhouse_schema_mismatch_count(), 0);

        for db in [&stale_db, &good_db] {
            exec(&format!("DROP DATABASE IF EXISTS {db}")).await;
        }
    }

    /// A missing table is the "migrations never ran at all" case.
    #[tokio::test]
    async fn probe_flags_a_missing_table() {
        let db = format!("sp_probe_empty_{}", uuid::Uuid::new_v4().simple());
        exec(&format!("CREATE DATABASE IF NOT EXISTS {db}")).await;

        let metrics = Arc::new(MetricsRegistry::default());
        verify_request_events_schema(&build_clickhouse_client(&ch_url(), &db), &metrics).await;
        assert_eq!(
            metrics.clickhouse_schema_mismatch_count(),
            1,
            "no request_events table at all must be flagged"
        );

        exec(&format!("DROP DATABASE IF EXISTS {db}")).await;
    }

    /// The probe is bounded. It runs AHEAD of the consumer loop, so an
    /// unbounded await against a hung ClickHouse blocks the receiver, fills
    /// the 256-slot channel and makes `enqueue` drop every event — the exact
    /// total-analytics-loss the probe exists to surface.
    ///
    /// Driven against a listener that accepts and then never replies, with a
    /// short timeout so the test itself stays fast.
    #[tokio::test]
    async fn probe_is_bounded_against_a_hung_clickhouse() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        // Accept and hold the connection open, answering nothing.
        std::thread::spawn(move || {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept() {
                held.push(stream);
            }
        });

        let metrics = Arc::new(MetricsRegistry::default());
        let started = std::time::Instant::now();
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            verify_request_events_schema(
                &build_clickhouse_client(&format!("http://{addr}"), "default"),
                &metrics,
            ),
        )
        .await;

        assert!(
            outcome.is_err(),
            "premise: this ClickHouse really does hang (probe returned in {:?})",
            started.elapsed()
        );
        // The production call site wraps the same future in a
        // `tokio::time::timeout`, so a hang there is bounded exactly as it is
        // bounded here rather than stalling the analytics consumer forever.
    }
}
