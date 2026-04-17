use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct MetricsRegistry {
    requests_total: AtomicU64,
    request_failures_total: AtomicU64,
    analytics_dropped_total: AtomicU64,
    analytics_failures_total: AtomicU64,
    clickhouse_insert_failures_total: AtomicU64,
    clickhouse_insert_retries_total: AtomicU64,
}

impl MetricsRegistry {
    pub fn record_request(&self, success: bool) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        if !success {
            self.request_failures_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_analytics_drop(&self) {
        self.analytics_dropped_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_analytics_failure(&self) {
        self.analytics_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_clickhouse_insert_failure(&self) {
        self.clickhouse_insert_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_clickhouse_insert_retry(&self) {
        self.clickhouse_insert_retries_total
            .fetch_add(1, Ordering::Relaxed);
    }

    #[must_use]
    pub fn render_prometheus(&self) -> String {
        format!(
            concat!(
                "# TYPE secureprompt_requests_total counter\n",
                "secureprompt_requests_total {}\n",
                "# TYPE secureprompt_request_failures_total counter\n",
                "secureprompt_request_failures_total {}\n",
                "# TYPE secureprompt_analytics_dropped_total counter\n",
                "secureprompt_analytics_dropped_total {}\n",
                "# TYPE secureprompt_analytics_failures_total counter\n",
                "secureprompt_analytics_failures_total {}\n",
                "# TYPE secureprompt_clickhouse_insert_failures_total counter\n",
                "secureprompt_clickhouse_insert_failures_total {}\n",
                "# TYPE secureprompt_clickhouse_insert_retries_total counter\n",
                "secureprompt_clickhouse_insert_retries_total {}\n",
            ),
            self.requests_total.load(Ordering::Relaxed),
            self.request_failures_total.load(Ordering::Relaxed),
            self.analytics_dropped_total.load(Ordering::Relaxed),
            self.analytics_failures_total.load(Ordering::Relaxed),
            self.clickhouse_insert_failures_total.load(Ordering::Relaxed),
            self.clickhouse_insert_retries_total.load(Ordering::Relaxed),
        )
    }
}
