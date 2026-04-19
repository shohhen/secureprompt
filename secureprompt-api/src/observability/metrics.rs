use std::{
    fmt::Write as _,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
    time::Duration,
};

/// Budget event label matrix, keyed by `(behavior, outcome)`.
/// Plan 05-05 VALIDATION 5-07-06 asserts these labels appear in the
/// Prometheus scrape output.
#[derive(Debug, Default)]
struct BudgetEventCounters {
    /// `(behavior_label, outcome_label)` monotonic counter.
    /// `Mutex<Vec<_>>` keeps the type simple without pulling in `dashmap`
    /// for a handful of label pairs.
    counters: Mutex<Vec<(String, String, u64)>>,
}

impl BudgetEventCounters {
    fn incr(&self, behavior: &'static str, outcome: &'static str) {
        let mut guard = self.counters.lock().expect("budget counters mutex");
        if let Some(row) = guard
            .iter_mut()
            .find(|(b, o, _)| b == behavior && o == outcome)
        {
            row.2 += 1;
        } else {
            guard.push((behavior.to_owned(), outcome.to_owned(), 1));
        }
    }

    fn render_into(&self, out: &mut String) {
        let guard = self.counters.lock().expect("budget counters mutex");
        if guard.is_empty() {
            return;
        }
        out.push_str("# TYPE secureprompt_dashboard_budget_events_total counter\n");
        for (behavior, outcome, value) in guard.iter() {
            let _ = write!(
                out,
                "secureprompt_dashboard_budget_events_total{{behavior=\"{behavior}\",outcome=\"{outcome}\"}} {value}"
            );
            out.push('\n');
        }
    }
}

#[derive(Debug, Default)]
pub struct MetricsRegistry {
    requests_total: AtomicU64,
    request_failures_total: AtomicU64,
    analytics_dropped_total: AtomicU64,
    analytics_failures_total: AtomicU64,
    clickhouse_insert_failures_total: AtomicU64,
    clickhouse_insert_retries_total: AtomicU64,
    /// Phase 5 / Plan 05-05 — budget enforcement events by `(behavior, outcome)`.
    budget_events: BudgetEventCounters,
    /// Total budget check invocations (used by the histogram surrogate:
    /// we report count + sum of elapsed microseconds rather than a real
    /// bucketed histogram to keep the zero-dep Prometheus exposition
    /// surface in sync with the rest of this module).
    budget_check_count: AtomicU64,
    budget_check_sum_us: AtomicU64,
    /// Redis outage fail-open counter (D-25).
    budget_redis_failure_total: AtomicU64,

    // ── Plan 05-03 — dashboard analytics metrics ──────────────────────────

    /// Histogram surrogate for `secureprompt_dashboard_request_duration_seconds`
    /// (count + sum in microseconds, labelled by endpoint). Stored as
    /// `(endpoint, outcome, count, sum_us)` tuples.
    dashboard_request_duration: Mutex<Vec<(String, String, u64, u64)>>,
    /// Error counter `secureprompt_dashboard_errors_total{endpoint, code}`.
    dashboard_errors: Mutex<Vec<(String, String, u64)>>,
    /// Histogram surrogate for `secureprompt_dashboard_mart_query_duration_seconds{mart}`.
    dashboard_mart_duration: Mutex<Vec<(String, u64, u64)>>,
    /// Counter `secureprompt_dashboard_client_errors_total{component}`.
    /// Incremented by POST /v1/telemetry/client-error (Plan 05-06).
    dashboard_client_errors: Mutex<Vec<(String, u64)>>,
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

    /// Record a budget enforcement event.
    /// `behavior ∈ {block, warn, flag}`, `outcome ∈ {allow, warn, flag, exceeded}`.
    pub fn record_budget_event(&self, behavior: &'static str, outcome: &'static str) {
        self.budget_events.incr(behavior, outcome);
    }

    /// Record the duration of a single `budget_check` call.
    pub fn time_budget_check(&self, elapsed: std::time::Duration) {
        self.budget_check_count.fetch_add(1, Ordering::Relaxed);
        let micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        self.budget_check_sum_us
            .fetch_add(micros, Ordering::Relaxed);
    }

    /// Increment the Redis fail-open counter (D-25).
    pub fn record_budget_redis_failure(&self) {
        self.budget_redis_failure_total
            .fetch_add(1, Ordering::Relaxed);
    }

    // ── Plan 05-03 — dashboard analytics metrics ──────────────────────────

    /// Record duration + outcome for a dashboard analytics request.
    ///
    /// `endpoint` is e.g. `"usage-daily"`, `outcome` is `"success"` or `"error"`.
    ///
    /// # Panics
    /// Panics if the internal `Mutex` is poisoned (only possible after a panic
    /// on another thread while holding the lock — not expected in normal operation).
    pub fn record_dashboard_request(&self, endpoint: &str, elapsed: Duration, outcome: &str) {
        let micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        let mut guard = self
            .dashboard_request_duration
            .lock()
            .expect("dashboard_request_duration mutex");
        if let Some(row) = guard
            .iter_mut()
            .find(|(e, o, _, _)| e == endpoint && o == outcome)
        {
            row.2 += 1;
            row.3 = row.3.saturating_add(micros);
        } else {
            guard.push((endpoint.to_owned(), outcome.to_owned(), 1, micros));
        }
    }

    /// Increment the error counter for a dashboard endpoint + HTTP status code.
    ///
    /// # Panics
    /// Panics if the internal `Mutex` is poisoned.
    pub fn inc_dashboard_error(&self, endpoint: &str, code: &str) {
        let mut guard = self
            .dashboard_errors
            .lock()
            .expect("dashboard_errors mutex");
        if let Some(row) = guard
            .iter_mut()
            .find(|(e, c, _)| e == endpoint && c == code)
        {
            row.2 += 1;
        } else {
            guard.push((endpoint.to_owned(), code.to_owned(), 1));
        }
    }

    /// Record how long a single mart query took.
    ///
    /// `mart` is e.g. `"mart_usage_daily"`.
    ///
    /// # Panics
    /// Panics if the internal `Mutex` is poisoned.
    pub fn record_mart_query_duration(&self, mart: &str, elapsed: Duration) {
        let micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        let mut guard = self
            .dashboard_mart_duration
            .lock()
            .expect("dashboard_mart_duration mutex");
        if let Some(row) = guard.iter_mut().find(|(m, _, _)| m == mart) {
            row.1 += 1;
            row.2 = row.2.saturating_add(micros);
        } else {
            guard.push((mart.to_owned(), 1, micros));
        }
    }

    /// Increment the client-error counter for a given component.
    ///
    /// Called by `POST /v1/telemetry/client-error` (Plan 05-06).
    ///
    /// # Panics
    /// Panics if the internal `Mutex` is poisoned.
    pub fn inc_client_error(&self, component: &str) {
        let mut guard = self
            .dashboard_client_errors
            .lock()
            .expect("dashboard_client_errors mutex");
        if let Some(row) = guard.iter_mut().find(|(c, _)| c == component) {
            row.1 += 1;
        } else {
            guard.push((component.to_owned(), 1));
        }
    }

    /// Return the client-error count for a given component.
    ///
    /// Used by integration tests.
    ///
    /// # Panics
    /// Panics if the internal `Mutex` is poisoned.
    #[must_use]
    pub fn client_error_count(&self, component: &str) -> u64 {
        let guard = self
            .dashboard_client_errors
            .lock()
            .expect("dashboard_client_errors mutex");
        guard
            .iter()
            .find(|(c, _)| c == component)
            .map_or(0, |(_, count)| *count)
    }

    /// Return the query count for the named mart.
    ///
    /// Used by integration tests to assert Prometheus counters are non-zero.
    ///
    /// # Panics
    /// Panics if the internal `Mutex` is poisoned.
    #[must_use]
    pub fn mart_query_count(&self, mart: &str) -> u64 {
        let guard = self
            .dashboard_mart_duration
            .lock()
            .expect("dashboard_mart_duration mutex");
        guard
            .iter()
            .find(|(m, _, _)| m == mart)
            .map_or(0, |(_, count, _)| *count)
    }

    /// Return the request count for a given `endpoint`+`outcome` pair.
    ///
    /// Used by integration tests to assert dashboard request counters are non-zero.
    ///
    /// # Panics
    /// Panics if the internal `Mutex` is poisoned.
    #[must_use]
    pub fn dashboard_request_count(&self, endpoint: &str, outcome: &str) -> u64 {
        let guard = self
            .dashboard_request_duration
            .lock()
            .expect("dashboard_request_duration mutex");
        guard
            .iter()
            .find(|(e, o, _, _)| e == endpoint && o == outcome)
            .map_or(0, |(_, _, count, _)| *count)
    }

    /// Render all counters in Prometheus text exposition format.
    ///
    /// # Panics
    /// Panics if any internal `Mutex` is poisoned (only possible after a panic
    /// on another thread while holding the lock).
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn render_prometheus(&self) -> String {
        let mut out = format!(
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
        );

        // Phase 5 / Plan 05-05 — budget metrics.
        self.budget_events.render_into(&mut out);
        out.push_str(
            "# TYPE secureprompt_dashboard_budget_check_duration_seconds summary\n",
        );
        let count = self.budget_check_count.load(Ordering::Relaxed);
        let sum_us = self.budget_check_sum_us.load(Ordering::Relaxed);
        // Report sum in seconds (µs / 1_000_000).
        #[allow(clippy::cast_precision_loss)]
        let sum_secs = sum_us as f64 / 1_000_000.0;
        let _ = write!(
            out,
            "secureprompt_dashboard_budget_check_duration_seconds_count {count}\n\
             secureprompt_dashboard_budget_check_duration_seconds_sum {sum_secs}"
        );
        out.push('\n');
        out.push_str("# TYPE secureprompt_budget_redis_failure_total counter\n");
        let redis_fail = self.budget_redis_failure_total.load(Ordering::Relaxed);
        let _ = write!(out, "secureprompt_budget_redis_failure_total {redis_fail}");
        out.push('\n');

        // Plan 05-03 — dashboard request duration histogram surrogate.
        {
            let guard = self
                .dashboard_request_duration
                .lock()
                .expect("dashboard_request_duration mutex");
            if !guard.is_empty() {
                out.push_str(
                    "# TYPE secureprompt_dashboard_request_duration_seconds summary\n",
                );
                for (endpoint, outcome, count, sum_us) in guard.iter() {
                    #[allow(clippy::cast_precision_loss)]
                    let sum_secs = *sum_us as f64 / 1_000_000.0;
                    let _ = writeln!(
                        out,
                        "secureprompt_dashboard_request_duration_seconds_count{{endpoint=\"{endpoint}\",outcome=\"{outcome}\"}} {count}"
                    );
                    let _ = writeln!(
                        out,
                        "secureprompt_dashboard_request_duration_seconds_sum{{endpoint=\"{endpoint}\",outcome=\"{outcome}\"}} {sum_secs}"
                    );
                }
            }
        }

        // Plan 05-03 — dashboard errors counter.
        {
            let guard = self
                .dashboard_errors
                .lock()
                .expect("dashboard_errors mutex");
            if !guard.is_empty() {
                out.push_str("# TYPE secureprompt_dashboard_errors_total counter\n");
                for (endpoint, code, value) in guard.iter() {
                    let _ = writeln!(
                        out,
                        "secureprompt_dashboard_errors_total{{endpoint=\"{endpoint}\",code=\"{code}\"}} {value}"
                    );
                }
            }
        }

        // Plan 05-03 — mart query duration histogram surrogate.
        {
            let guard = self
                .dashboard_mart_duration
                .lock()
                .expect("dashboard_mart_duration mutex");
            if !guard.is_empty() {
                out.push_str(
                    "# TYPE secureprompt_dashboard_mart_query_duration_seconds summary\n",
                );
                for (mart, count, sum_us) in guard.iter() {
                    #[allow(clippy::cast_precision_loss)]
                    let sum_secs = *sum_us as f64 / 1_000_000.0;
                    let _ = writeln!(
                        out,
                        "secureprompt_dashboard_mart_query_duration_seconds_count{{mart=\"{mart}\"}} {count}"
                    );
                    let _ = writeln!(
                        out,
                        "secureprompt_dashboard_mart_query_duration_seconds_sum{{mart=\"{mart}\"}} {sum_secs}"
                    );
                }
            }
        }

        // Plan 05-06 — client-error counter.
        {
            let guard = self
                .dashboard_client_errors
                .lock()
                .expect("dashboard_client_errors mutex");
            if !guard.is_empty() {
                out.push_str(
                    "# TYPE secureprompt_dashboard_client_errors_total counter\n",
                );
                for (component, value) in guard.iter() {
                    let _ = writeln!(
                        out,
                        "secureprompt_dashboard_client_errors_total{{component=\"{component}\"}} {value}"
                    );
                }
            }
        }

        out
    }
}
