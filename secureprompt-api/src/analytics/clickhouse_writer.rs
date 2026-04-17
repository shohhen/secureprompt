use crate::{
    analytics::events::{LatencySampleRow, PolicyEventRow, RequestEvent, RequestEventRow, TokenUsageRow},
    observability::metrics::MetricsRegistry,
};
use clickhouse::Client;
use std::{sync::Arc, time::Duration};
use tokio::sync::mpsc;

pub const CLICKHOUSE_INSERT_SETTINGS: &str = "async_insert=1&wait_for_async_insert=1";
const BATCH_MAX_ROWS: u64 = 100;
const BATCH_PERIOD_SECS: u64 = 1;
const INSERT_TIMEOUT_SECS: u64 = 5;
const INSERT_SEND_TIMEOUT_SECS: u64 = 20;

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
                        continue;
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
