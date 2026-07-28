use crate::{
    analytics::events::{
        LatencySampleRow, PolicyEventRow, RequestEvent, RequestEventRow, TokenUsageRow,
    },
    observability::metrics::MetricsRegistry,
};
use clickhouse::{Client, Row};
use serde::Deserialize;
use std::{sync::Arc, time::Duration};
use tokio::sync::mpsc;

/// Every column `RequestEventRow` writes. Kept in lock-step with that struct
/// (and therefore with `clickhouse/migrations/*`) — the probe below reports
/// any that the live table is missing.
pub const REQUEST_EVENTS_COLUMNS: &[&str] = &[
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
/// column the writer serialises.
///
/// Runs in a SPAWNED task, concurrently with the consumer loop — never ahead
/// of it. It is an early-warning that costs nothing on the request path, not
/// the primary detector: it compares column NAMES only, so a type-level drift
/// passes it and is caught at `write` instead. Logs an alert-keyed error and raises the
/// `secureprompt_clickhouse_schema_mismatch` gauge when it does not; the
/// gauge is lowered again by the first commit that actually inserts rows.
///
/// Deliberately non-fatal: a ClickHouse that is merely slow to come up must
/// not take the gateway down with it, and the analytics path is best-effort
/// by design. The point is that "analytics silently dropping 100% of events
/// because the worker has not run its migrations" becomes a visible,
/// alertable condition rather than an inference from an empty dashboard.
pub async fn verify_request_events_schema(client: &Client, metrics: &Arc<MetricsRegistry>) {
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
/// Wall-clock bound on the one-shot startup schema probe.
///
/// The probe is spawned, not awaited, so it no longer gates the consumer
/// loop. This bound remains so a blackholed ClickHouse cannot leak the probe
/// task for the lifetime of the process.
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
            // The probe must never sit between this task starting and the
            // `recv()` loop below. Awaited inline - even with a timeout - a
            // hung or blackholed ClickHouse stalls the receiver for the whole
            // timeout, the 256-slot channel fills, and `enqueue`'s `try_send`
            // drops events: at more than ~26 events/s a 10s stall alone loses
            // traffic. That is the same total-analytics-loss the probe exists
            // to surface.
            //
            // So: spawned, not awaited. The consumer loop starts draining
            // immediately and the probe reports whenever it finishes. The
            // timeout stays so a blackholed connection cannot leak the task
            // forever.
            {
                let probe_client = ch_client.clone();
                let probe_metrics = Arc::clone(&metrics_task);
                tokio::spawn(async move {
                    if tokio::time::timeout(
                        Duration::from_secs(SCHEMA_PROBE_TIMEOUT_SECS),
                        verify_request_events_schema(&probe_client, &probe_metrics),
                    )
                    .await
                    .is_err()
                    {
                        tracing::warn!(
                            timeout_secs = SCHEMA_PROBE_TIMEOUT_SECS,
                            "ClickHouse schema probe timed out; continuing without it"
                        );
                    }
                });
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
                // Counted BEFORE any ClickHouse work: this is the signal that
                // the receive loop is running, independent of whether
                // ClickHouse is healthy, slow or unreachable.
                metrics_task.record_analytics_consumed();
                let now = chrono::Utc::now();
                let req_row = RequestEventRow::from_event(&event, now);

                // Schema-staleness gauge lives on THIS path, because this is
                // where a stale schema actually surfaces.
                //
                // `build_clickhouse_client` does not call
                // `.with_validation(false)`, and clickhouse 0.15 defaults
                // validation to ON. So the first `write` of each batch runs
                // `init_insert` -> `Client::insert_unescaped` ->
                // `get_insert_metadata` (a DESCRIBE round-trip) ->
                // `to_row::<T>()`, and a table whose layout does not match
                // `RequestEventRow` fails HERE with `Error::SchemaMismatch` —
                // never reaching the commit below, because the retry path
                // `continue`s past it.
                //
                // If validation is ever disabled, this detection disappears
                // silently: writes would buffer without contacting the server
                // and the mismatch would only appear at commit. Keep the two
                // together.
                match req_inserter.write(&req_row).await {
                    Ok(()) => {
                        // With validation ON, a successful write means the
                        // server described the table and our row layout was
                        // accepted. That is the only positive proof of schema
                        // compatibility available, so it is what lowers the
                        // gauge (including one raised by the startup probe).
                        metrics_task.clear_clickhouse_schema_mismatch();
                    }
                    Err(e) => {
                        let schema_mismatch =
                            matches!(e, clickhouse::error::Error::SchemaMismatch(_));
                        if schema_mismatch {
                            tracing::error!(
                                alert = "clickhouse_schema_stale",
                                table = "request_events",
                                error = %e,
                                "request_events rejected our row layout — run the ClickHouse \
                                 migrations (secureprompt-worker applies them at startup); \
                                 analytics events are being dropped until then"
                            );
                            metrics_task.record_clickhouse_schema_mismatch();
                            // `InsertMetadata` is cached per table for the
                            // lifetime of the client. Without this the writer
                            // keeps validating against the schema it fetched
                            // the first time and can NEVER notice the worker's
                            // migration — the gauge, and the outage, would
                            // persist until an API restart.
                            ch_client.clear_cached_metadata().await;
                        } else {
                            // Transport error, timeout, ClickHouse overload.
                            // Deliberately NOT a schema signal: raising the
                            // CRITICAL "run your migrations" alert for a
                            // connection reset is a false page.
                            tracing::warn!(error = %e, "request_events write error; retrying once");
                        }

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
                        // The retry succeeded: whatever it was, we are writing
                        // again, so the schema is compatible.
                        metrics_task.clear_clickhouse_schema_mismatch();
                    }
                }

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

                // Commit failures are counted, not diagnosed. A commit error
                // is far more often a timeout / reset / overload than a schema
                // problem, and the schema signal is now taken from the write
                // path where `SchemaMismatch` is actually distinguishable.
                // Raising a CRITICAL "run your migrations" alert from here
                // would page an operator for a transient blip.
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
