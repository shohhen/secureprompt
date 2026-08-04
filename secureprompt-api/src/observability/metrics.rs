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

/// Bucket boundaries (seconds) for every API duration histogram in this
/// module. Fixed per the KPI-2 monitoring plan's Global Constraints — do not
/// make this per-metric-configurable without updating the plan.
const HISTOGRAM_BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// A single Prometheus histogram series (one label combination).
///
/// Storage: `buckets[i]` holds the *non-cumulative* count of observations
/// with `HISTOGRAM_BUCKETS[i - 1] < value <= HISTOGRAM_BUCKETS[i]` (and
/// `buckets[0]` holds `value <= HISTOGRAM_BUCKETS[0]`); the extra slot at
/// `HISTOGRAM_BUCKETS.len()` is the `+Inf` overflow bucket for values above
/// the largest bound. `observe` therefore only ever increments a single
/// bucket; the running (cumulative) totals Prometheus expects are computed
/// once, at render time, in [`Histogram::render_into`]. `sum_micros` mirrors
/// the microsecond-precision sum convention already used elsewhere in this
/// file (e.g. `record_dashboard_request`) and is converted to seconds only
/// when rendered.
#[derive(Debug)]
struct Histogram {
    buckets: [AtomicU64; HISTOGRAM_BUCKETS.len() + 1],
    sum_micros: AtomicU64,
    count: AtomicU64,
}

impl Default for Histogram {
    fn default() -> Self {
        Self {
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            sum_micros: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }
}

impl Histogram {
    /// Record one observation of `secs` seconds.
    fn observe(&self, secs: f64) {
        let idx = HISTOGRAM_BUCKETS
            .iter()
            .position(|&bound| secs <= bound)
            .unwrap_or(HISTOGRAM_BUCKETS.len());
        self.buckets[idx].fetch_add(1, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let micros = (secs * 1_000_000.0).max(0.0).round() as u64;
        self.sum_micros.fetch_add(micros, Ordering::Relaxed);
    }

    /// Total observation count across all buckets. Used by the
    /// `mart_query_count` / `dashboard_request_count` test accessors.
    fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    /// Append this series' `_bucket{le}` / `_sum` / `_count` lines to `out`.
    ///
    /// `labels` is the label body *without* surrounding braces (e.g.
    /// `endpoint="x",outcome="y"`), or an empty string for an unlabelled
    /// series. Does not print the `# TYPE ... histogram` line — callers
    /// print that once per metric family, before iterating series.
    fn render_into(&self, out: &mut String, name: &str, labels: &str) {
        let mut cumulative = 0u64;
        for (bound, bucket) in HISTOGRAM_BUCKETS.iter().zip(self.buckets.iter()) {
            cumulative += bucket.load(Ordering::Relaxed);
            Self::write_bucket_line(out, name, labels, &format!("{bound}"), cumulative);
        }
        cumulative += self.buckets[HISTOGRAM_BUCKETS.len()].load(Ordering::Relaxed);
        Self::write_bucket_line(out, name, labels, "+Inf", cumulative);

        #[allow(clippy::cast_precision_loss)]
        let sum_secs = self.sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        let count = self.count.load(Ordering::Relaxed);
        if labels.is_empty() {
            let _ = writeln!(out, "{name}_sum {sum_secs}");
            let _ = writeln!(out, "{name}_count {count}");
        } else {
            let _ = writeln!(out, "{name}_sum{{{labels}}} {sum_secs}");
            let _ = writeln!(out, "{name}_count{{{labels}}} {count}");
        }
    }

    fn write_bucket_line(out: &mut String, name: &str, labels: &str, le: &str, value: u64) {
        if labels.is_empty() {
            let _ = writeln!(out, "{name}_bucket{{le=\"{le}\"}} {value}");
        } else {
            let _ = writeln!(out, "{name}_bucket{{{labels},le=\"{le}\"}} {value}");
        }
    }
}

#[derive(Debug, Default)]
pub struct MetricsRegistry {
    requests_total: AtomicU64,
    request_failures_total: AtomicU64,
    analytics_dropped_total: AtomicU64,
    /// `secureprompt_analytics_consumed_total` — events taken off the
    /// analytics channel by the writer task, counted the moment `recv()`
    /// yields one and BEFORE any ClickHouse work.
    ///
    /// Pairs with `analytics_dropped_total`: dropped/(dropped+consumed) is the
    /// analytics loss rate. It is also the only externally visible proof that
    /// the writer's receive loop is running at all, which is what the startup
    /// schema probe must not be allowed to delay.
    analytics_consumed_total: AtomicU64,
    analytics_failures_total: AtomicU64,
    clickhouse_insert_failures_total: AtomicU64,
    clickhouse_insert_retries_total: AtomicU64,
    /// Phase 5 / Plan 05-05 — budget enforcement events by `(behavior, outcome)`.
    budget_events: BudgetEventCounters,
    /// `secureprompt_dashboard_budget_check_duration_seconds` — real bucketed
    /// histogram (KPI-2 monitoring, Task 1) for a single unlabelled series.
    budget_check_duration: Histogram,
    /// Redis outage fail-open counter (D-25).
    budget_redis_failure_total: AtomicU64,

    // ── Plan 05-03 — dashboard analytics metrics ──────────────────────────
    /// `secureprompt_dashboard_request_duration_seconds{endpoint,outcome}` —
    /// real bucketed histogram (KPI-2 monitoring, Task 1), one series per
    /// `(endpoint, outcome)` pair.
    dashboard_request_duration: Mutex<Vec<(String, String, Histogram)>>,
    /// Error counter `secureprompt_dashboard_errors_total{endpoint, code}`.
    dashboard_errors: Mutex<Vec<(String, String, u64)>>,
    /// `secureprompt_dashboard_mart_query_duration_seconds{mart}` — real
    /// bucketed histogram (KPI-2 monitoring, Task 1), one series per `mart`.
    dashboard_mart_duration: Mutex<Vec<(String, Histogram)>>,
    /// Counter `secureprompt_dashboard_client_errors_total{component}`.
    /// Incremented by POST /v1/telemetry/client-error (Plan 05-06).
    dashboard_client_errors: Mutex<Vec<(String, u64)>>,

    // ── KPI-2 monitoring, Task 2 ───────────────────────────────────────────
    /// `secureprompt_request_duration_seconds{model}` — real bucketed
    /// histogram, one series per resolved provider `model` (fallback
    /// `"unknown"` when no provider was resolved, e.g. a policy-denied
    /// request short-circuited before target selection).
    request_duration: Mutex<Vec<(String, Histogram)>>,
    /// Counter `secureprompt_policy_violations_total{action}`. `action` is a
    /// bounded label — one of `block`/`redact`/`flag`/`warn` — never a
    /// free-text rule name or id.
    policy_violations: Mutex<Vec<(String, u64)>>,

    // ── WS2-3 ─ ML sidecar coverage loss ────────────────────────────────
    /// Counter `secureprompt_sidecar_unavailable_total{reason,action}`.
    /// `reason` is a bounded
    /// [`crate::ml_sidecar::types::CoverageLoss::as_str`] label — the four
    /// `SidecarOutage` spellings `unconfigured`/`disabled`/`circuit_open`/
    /// `all_calls_failed` PLUS `partial_coverage` — and `action` is the
    /// workspace policy that was applied (`block`/`degrade_with_alert`).
    /// This is the alert signal for a gateway running with no ML detection
    /// coverage.
    ///
    /// MR1 review M1: this used to say `reason` was a `SidecarOutage` label
    /// and enumerate only the four. Both call sites pass `CoverageLoss`, so
    /// `partial_coverage` — a document that tiled into chunks and lost one —
    /// was an undocumented fifth value. Still bounded, so there was never a
    /// cardinality risk; the label domain a dashboard or alert rule is
    /// written against was simply wrong. Pinned by
    /// `sidecar_unavailable_reason_label_domain` below.
    sidecar_unavailable: Mutex<Vec<(String, String, u64)>>,

    // ── WS4-4 ─ license gate ────────────────────────────────────────────
    /// Counter `secureprompt_license_gate_engaged_total{reason,action}`.
    /// `reason` is a bounded
    /// [`crate::http::middleware::license_gate::LicenseOutage`] label
    /// (`license_revoked`/`license_revalidation_lost`) and `action` is what
    /// the gate did about it (`block`/`degrade_with_alert` — the same two
    /// strings as `sidecar_unavailable`, bound to
    /// `SidecarUnavailablePolicy::as_str` at compile time). This is the
    /// alert signal for a gateway whose license has left good standing.
    ///
    /// Deliberately a separate series from `sidecar_unavailable`: same
    /// vocabulary, different subsystem and different remedy (renew/re-license
    /// vs. restore the ML sidecar).
    license_gate_engaged: Mutex<Vec<(String, String, u64)>>,

    // ── FU3 ─ JWT auth under a session-store outage ─────────────────────
    /// Counter `secureprompt_auth_gate_engaged_total{reason,action}`.
    /// `reason` is a bounded
    /// [`crate::http::middleware::jwt_auth::AuthOutage`] label and `action` is
    /// what the gate did about it (`block`/`degrade_with_alert` — the same two
    /// strings as `sidecar_unavailable` and `license_gate_engaged`, bound to
    /// `SidecarUnavailablePolicy::as_str` at compile time).
    ///
    /// This is the ONLY signal that the gateway answered an authenticated
    /// request without having read the session gates. Every increment means
    /// Redis was unreachable on the request path; a
    /// `reason="logout_unverifiable"` increment additionally means a request
    /// was SERVED in that state.
    auth_gate_engaged: Mutex<Vec<(String, String, u64)>>,
    /// GAUGE `secureprompt_clickhouse_schema_mismatch` — 1 when the live
    /// `request_events` table cannot take the row the writer serialises (the
    /// worker's ClickHouse migrations have not run, and every analytics event
    /// is being dropped), 0 otherwise.
    ///
    /// TWO paths raise it, not one. This comment used to name only the startup
    /// probe, which is the WS2-3 R4 residual: `alerts.yml` carried the same
    /// claim and was corrected in 45b741b, this copy was not.
    ///
    /// * The **startup probe** (`clickhouse_writer::probe_request_events_schema`),
    ///   for a missing table or missing columns.
    /// * The **write path**, when the server itself rejects the row layout with
    ///   `clickhouse::error::Error::SchemaMismatch`. That arm catches type-level
    ///   drift the probe cannot see, and it fires after the probe has already
    ///   passed — including on a cache that was warm when the drift appeared.
    ///
    /// A gauge, not a counter, because it describes a STATE that can heal: the
    /// first insert the server validates and accepts clears it, whichever path
    /// raised it. As a monotonic counter the alert would keep firing after the
    /// worker migrated and inserts recovered, until an API restart.
    ///
    /// Executed, not asserted: `tests/clickhouse_schema_probe.rs` —
    /// `stale_schema_raises_the_gauge_from_the_write_path`,
    /// `drift_after_a_warm_cache_still_raises_the_gauge` and
    /// `a_successful_write_lowers_a_probe_raised_gauge` are the three that hold
    /// each clause above, and all three were run against a live ClickHouse for
    /// this edit.
    clickhouse_schema_mismatch: AtomicU64,
}

impl MetricsRegistry {
    pub fn record_request(&self, success: bool) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        if !success {
            self.request_failures_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// One event taken off the channel by the writer task.
    pub fn record_analytics_consumed(&self) {
        self.analytics_consumed_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Events consumed so far. Read by `tests/clickhouse_schema_probe.rs`.
    #[must_use]
    pub fn analytics_consumed_count(&self) -> u64 {
        self.analytics_consumed_total.load(Ordering::Relaxed)
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
        self.budget_check_duration.observe(elapsed.as_secs_f64());
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
        let secs = elapsed.as_secs_f64();
        let mut guard = self
            .dashboard_request_duration
            .lock()
            .expect("dashboard_request_duration mutex");
        if let Some((_, _, hist)) = guard
            .iter_mut()
            .find(|(e, o, _)| e == endpoint && o == outcome)
        {
            hist.observe(secs);
        } else {
            let hist = Histogram::default();
            hist.observe(secs);
            guard.push((endpoint.to_owned(), outcome.to_owned(), hist));
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
        let secs = elapsed.as_secs_f64();
        let mut guard = self
            .dashboard_mart_duration
            .lock()
            .expect("dashboard_mart_duration mutex");
        if let Some((_, hist)) = guard.iter_mut().find(|(m, _)| m == mart) {
            hist.observe(secs);
        } else {
            let hist = Histogram::default();
            hist.observe(secs);
            guard.push((mart.to_owned(), hist));
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
            .find(|(m, _)| m == mart)
            .map_or(0, |(_, hist)| hist.count())
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
            .find(|(e, o, _)| e == endpoint && o == outcome)
            .map_or(0, |(_, _, hist)| hist.count())
    }

    // ── KPI-2 monitoring, Task 2 ────────────────────────────────────────────

    /// Record one upstream request's total duration, labelled by the
    /// resolved provider `model`.
    ///
    /// Called at every request-completion site in
    /// `pipeline::service::PipelineService` (buffered, streaming, and the
    /// policy-denied short-circuit) alongside `record_request`. Callers pass
    /// `"unknown"` for `model` when no provider target was resolved yet
    /// (e.g. the request was denied by policy before target selection).
    ///
    /// # Panics
    /// Panics if the internal `Mutex` is poisoned.
    pub fn observe_request_duration(&self, model: &str, elapsed: Duration) {
        let secs = elapsed.as_secs_f64();
        let mut guard = self
            .request_duration
            .lock()
            .expect("request_duration mutex");
        if let Some((_, hist)) = guard.iter_mut().find(|(m, _)| m == model) {
            hist.observe(secs);
        } else {
            let hist = Histogram::default();
            hist.observe(secs);
            guard.push((model.to_owned(), hist));
        }
    }

    /// Return the request-duration observation count for a given `model`.
    ///
    /// Used by tests to assert the histogram was touched.
    ///
    /// # Panics
    /// Panics if the internal `Mutex` is poisoned.
    #[must_use]
    pub fn request_duration_count(&self, model: &str) -> u64 {
        let guard = self
            .request_duration
            .lock()
            .expect("request_duration mutex");
        guard
            .iter()
            .find(|(m, _)| m == model)
            .map_or(0, |(_, hist)| hist.count())
    }

    /// Record one policy-enforcement violation. `action` must be one of the
    /// bounded label set `block`/`redact`/`flag`/`warn` — never a free-text
    /// rule name, id, or workspace/user identifier (unbounded cardinality).
    ///
    /// Called from `pipeline::service::PipelineService::prepare` wherever a
    /// policy rule's (or secure-mode override's) action is enforced against
    /// a request and that action is not `allow`.
    ///
    /// # Panics
    /// Panics if the internal `Mutex` is poisoned.
    pub fn record_policy_violation(&self, action: &str) {
        let mut guard = self
            .policy_violations
            .lock()
            .expect("policy_violations mutex");
        if let Some(row) = guard.iter_mut().find(|(a, _)| a == action) {
            row.1 += 1;
        } else {
            guard.push((action.to_owned(), 1));
        }
    }

    /// Flag that the live ClickHouse schema is behind the writer.
    pub fn record_clickhouse_schema_mismatch(&self) {
        self.clickhouse_schema_mismatch.store(1, Ordering::Relaxed);
    }

    /// Clear the flag — called when an insert actually lands, which proves
    /// the schema is now compatible.
    pub fn clear_clickhouse_schema_mismatch(&self) {
        self.clickhouse_schema_mismatch.store(0, Ordering::Relaxed);
    }

    /// Number of events dropped because the analytics channel was full.
    ///
    /// Read by `tests/clickhouse_schema_probe.rs` to prove the writer keeps
    /// draining while ClickHouse is unresponsive; exported as
    /// `secureprompt_analytics_dropped_total`.
    #[must_use]
    pub fn analytics_dropped_count(&self) -> u64 {
        self.analytics_dropped_total.load(Ordering::Relaxed)
    }

    /// ClickHouse insert failures so far.
    ///
    /// Read by `tests/clickhouse_schema_probe.rs` to assert the premise that
    /// writes really are failing before concluding anything about WHY.
    #[must_use]
    pub fn clickhouse_insert_failure_count(&self) -> u64 {
        self.clickhouse_insert_failures_total
            .load(Ordering::Relaxed)
    }

    /// 1 when the schema is known-stale, 0 otherwise.
    ///
    /// Read by `tests/clickhouse_schema_probe.rs`; the gauge is also exported
    /// through `render_prometheus` as
    /// `secureprompt_clickhouse_schema_mismatch`.
    #[must_use]
    pub fn clickhouse_schema_mismatch_count(&self) -> u64 {
        self.clickhouse_schema_mismatch.load(Ordering::Relaxed)
    }

    /// WS2-3 — record one request for which the ML sidecar produced no
    /// detection coverage. Both labels are bounded: `reason` is
    /// [`crate::ml_sidecar::types::CoverageLoss::as_str`] — NOT
    /// `SidecarOutage::as_str`, which is only four of its five values; the
    /// fifth is `partial_coverage` — and `action` is the workspace's
    /// `sidecar_unavailable` policy. Never a workspace id.
    ///
    /// # Panics
    /// Panics if the internal `Mutex` is poisoned.
    pub fn record_sidecar_unavailable(&self, reason: &str, action: &str) {
        let mut guard = self
            .sidecar_unavailable
            .lock()
            .expect("sidecar_unavailable mutex");
        if let Some(row) = guard
            .iter_mut()
            .find(|(r, a, _)| r == reason && a == action)
        {
            row.2 += 1;
        } else {
            guard.push((reason.to_owned(), action.to_owned(), 1));
        }
    }

    /// Return the sidecar-coverage-loss count for a `(reason, action)` pair.
    ///
    /// Used by tests to assert the counter was touched.
    ///
    /// # Panics
    /// Panics if the internal `Mutex` is poisoned.
    #[must_use]
    pub fn sidecar_unavailable_count(&self, reason: &str, action: &str) -> u64 {
        let guard = self
            .sidecar_unavailable
            .lock()
            .expect("sidecar_unavailable mutex");
        guard
            .iter()
            .find(|(r, a, _)| r == reason && a == action)
            .map_or(0, |(_, _, count)| *count)
    }

    /// WS4-4 — record one request the license gate acted on. Both labels are
    /// bounded: `reason` is
    /// [`crate::http::middleware::license_gate::LicenseOutage::as_str`],
    /// `action` is `block` or `degrade_with_alert`. Never a path or a `lic_id`.
    ///
    /// # Panics
    /// Panics if the internal `Mutex` is poisoned.
    pub fn record_license_gate_engaged(&self, reason: &str, action: &str) {
        let mut guard = self
            .license_gate_engaged
            .lock()
            .expect("license_gate_engaged mutex");
        if let Some(row) = guard
            .iter_mut()
            .find(|(r, a, _)| r == reason && a == action)
        {
            row.2 += 1;
        } else {
            guard.push((reason.to_owned(), action.to_owned(), 1));
        }
    }

    /// Return the license-gate count for a `(reason, action)` pair.
    ///
    /// Used by tests to assert the counter was touched.
    ///
    /// # Panics
    /// Panics if the internal `Mutex` is poisoned.
    #[must_use]
    pub fn license_gate_engaged_count(&self, reason: &str, action: &str) -> u64 {
        let guard = self
            .license_gate_engaged
            .lock()
            .expect("license_gate_engaged mutex");
        guard
            .iter()
            .find(|(r, a, _)| r == reason && a == action)
            .map_or(0, |(_, _, count)| *count)
    }

    /// FU3 — record one authenticated request the JWT auth gate acted on
    /// because the session store was unreachable. Both labels are bounded:
    /// `reason` is
    /// [`crate::http::middleware::jwt_auth::AuthOutage::as_str`], `action` is
    /// `block` or `degrade_with_alert`. Never a user id or a path.
    ///
    /// # Panics
    /// Panics if the internal `Mutex` is poisoned.
    pub fn record_auth_gate_engaged(&self, reason: &str, action: &str) {
        let mut guard = self
            .auth_gate_engaged
            .lock()
            .expect("auth_gate_engaged mutex");
        if let Some(row) = guard
            .iter_mut()
            .find(|(r, a, _)| r == reason && a == action)
        {
            row.2 += 1;
        } else {
            guard.push((reason.to_owned(), action.to_owned(), 1));
        }
    }

    /// Return the auth-gate count for a `(reason, action)` pair.
    ///
    /// Used by tests to assert the counter was touched.
    ///
    /// # Panics
    /// Panics if the internal `Mutex` is poisoned.
    #[must_use]
    pub fn auth_gate_engaged_count(&self, reason: &str, action: &str) -> u64 {
        let guard = self
            .auth_gate_engaged
            .lock()
            .expect("auth_gate_engaged mutex");
        guard
            .iter()
            .find(|(r, a, _)| r == reason && a == action)
            .map_or(0, |(_, _, count)| *count)
    }

    /// Return the policy-violation count for a given `action`.
    ///
    /// Used by tests to assert the counter was touched.
    ///
    /// # Panics
    /// Panics if the internal `Mutex` is poisoned.
    #[must_use]
    pub fn policy_violation_count(&self, action: &str) -> u64 {
        let guard = self
            .policy_violations
            .lock()
            .expect("policy_violations mutex");
        guard
            .iter()
            .find(|(a, _)| a == action)
            .map_or(0, |(_, count)| *count)
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
                "# TYPE secureprompt_analytics_consumed_total counter\n",
                "secureprompt_analytics_consumed_total {}\n",
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
            self.analytics_consumed_total.load(Ordering::Relaxed),
            self.analytics_failures_total.load(Ordering::Relaxed),
            self.clickhouse_insert_failures_total
                .load(Ordering::Relaxed),
            self.clickhouse_insert_retries_total.load(Ordering::Relaxed),
        );

        // Phase 5 / Plan 05-05 — budget metrics.
        self.budget_events.render_into(&mut out);
        out.push_str("# TYPE secureprompt_dashboard_budget_check_duration_seconds histogram\n");
        self.budget_check_duration.render_into(
            &mut out,
            "secureprompt_dashboard_budget_check_duration_seconds",
            "",
        );
        out.push_str("# TYPE secureprompt_budget_redis_failure_total counter\n");
        let redis_fail = self.budget_redis_failure_total.load(Ordering::Relaxed);
        let _ = write!(out, "secureprompt_budget_redis_failure_total {redis_fail}");
        out.push('\n');

        // Plan 05-03 — dashboard request duration histogram (KPI-2 Task 1).
        {
            let guard = self
                .dashboard_request_duration
                .lock()
                .expect("dashboard_request_duration mutex");
            if !guard.is_empty() {
                out.push_str("# TYPE secureprompt_dashboard_request_duration_seconds histogram\n");
                for (endpoint, outcome, hist) in guard.iter() {
                    let labels = format!("endpoint=\"{endpoint}\",outcome=\"{outcome}\"");
                    hist.render_into(
                        &mut out,
                        "secureprompt_dashboard_request_duration_seconds",
                        &labels,
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

        // Plan 05-03 — mart query duration histogram (KPI-2 Task 1).
        {
            let guard = self
                .dashboard_mart_duration
                .lock()
                .expect("dashboard_mart_duration mutex");
            if !guard.is_empty() {
                out.push_str(
                    "# TYPE secureprompt_dashboard_mart_query_duration_seconds histogram\n",
                );
                for (mart, hist) in guard.iter() {
                    let labels = format!("mart=\"{mart}\"");
                    hist.render_into(
                        &mut out,
                        "secureprompt_dashboard_mart_query_duration_seconds",
                        &labels,
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
                out.push_str("# TYPE secureprompt_dashboard_client_errors_total counter\n");
                for (component, value) in guard.iter() {
                    let _ = writeln!(
                        out,
                        "secureprompt_dashboard_client_errors_total{{component=\"{component}\"}} {value}"
                    );
                }
            }
        }

        // KPI-2 monitoring, Task 2 — request-duration histogram.
        {
            let guard = self
                .request_duration
                .lock()
                .expect("request_duration mutex");
            if !guard.is_empty() {
                out.push_str("# TYPE secureprompt_request_duration_seconds histogram\n");
                for (model, hist) in guard.iter() {
                    let labels = format!("model=\"{model}\"");
                    hist.render_into(&mut out, "secureprompt_request_duration_seconds", &labels);
                }
            }
        }

        // KPI-2 monitoring, Task 2 — policy-violation counter.
        {
            let guard = self
                .policy_violations
                .lock()
                .expect("policy_violations mutex");
            if !guard.is_empty() {
                out.push_str("# TYPE secureprompt_policy_violations_total counter\n");
                for (action, value) in guard.iter() {
                    let _ = writeln!(
                        out,
                        "secureprompt_policy_violations_total{{action=\"{action}\"}} {value}"
                    );
                }
            }
        }

        out.push_str("# TYPE secureprompt_clickhouse_schema_mismatch gauge\n");
        let _ = writeln!(
            out,
            "secureprompt_clickhouse_schema_mismatch {}",
            self.clickhouse_schema_mismatch.load(Ordering::Relaxed)
        );

        // WS2-3 — ML sidecar coverage-loss counter.
        {
            let guard = self
                .sidecar_unavailable
                .lock()
                .expect("sidecar_unavailable mutex");
            if !guard.is_empty() {
                out.push_str("# TYPE secureprompt_sidecar_unavailable_total counter\n");
                for (reason, action, value) in guard.iter() {
                    let _ = writeln!(
                        out,
                        "secureprompt_sidecar_unavailable_total{{reason=\"{reason}\",action=\"{action}\"}} {value}"
                    );
                }
            }
        }

        // WS4-4 — license-gate counter.
        {
            let guard = self
                .license_gate_engaged
                .lock()
                .expect("license_gate_engaged mutex");
            if !guard.is_empty() {
                out.push_str("# TYPE secureprompt_license_gate_engaged_total counter\n");
                for (reason, action, value) in guard.iter() {
                    let _ = writeln!(
                        out,
                        "secureprompt_license_gate_engaged_total{{reason=\"{reason}\",action=\"{action}\"}} {value}"
                    );
                }
            }
        }

        // FU3 — JWT auth gate under a session-store outage.
        {
            let guard = self
                .auth_gate_engaged
                .lock()
                .expect("auth_gate_engaged mutex");
            if !guard.is_empty() {
                out.push_str("# TYPE secureprompt_auth_gate_engaged_total counter\n");
                for (reason, action, value) in guard.iter() {
                    let _ = writeln!(
                        out,
                        "secureprompt_auth_gate_engaged_total{{reason=\"{reason}\",action=\"{action}\"}} {value}"
                    );
                }
            }
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MR1 review M1 — the `reason` label domain of
    /// `secureprompt_sidecar_unavailable_total`, pinned against the type the
    /// call sites actually pass.
    ///
    /// The finding was that the doc named `SidecarOutage::as_str` while both
    /// call sites (`pipeline::service::alert_sidecar_unavailable` and
    /// `http::sidecar_coverage::alert`) pass `CoverageLoss::as_str`, which
    /// emits a fifth value, `partial_coverage`. A corrected comment with
    /// nothing holding it true is how the first one got written, so:
    ///
    /// * the `match` is a COMPILE-TIME exhaustiveness guard — add a
    ///   `CoverageLoss` or `SidecarOutage` variant and this stops compiling
    ///   until the documented domain is extended. Written out by hand on
    ///   purpose; deriving it from a production slice would mean the test can
    ///   never notice a case production forgot (same argument as
    ///   `pipeline::tests::assert_outage_list_is_exhaustive`).
    /// * the render assertion is the RUNTIME half: it drives the real
    ///   `record_sidecar_unavailable` + `render_prometheus` path, so a change
    ///   that stops a value reaching the series reddens it.
    ///
    /// FALSIFIER, in the direction that matters: drop `Self::Partial` from
    /// `CoverageLoss::as_str`'s match (or make it return an outage spelling)
    /// and the `partial_coverage` line disappears from the render.
    #[test]
    fn sidecar_unavailable_reason_label_domain() {
        use crate::ml_sidecar::types::{CoverageLoss, SidecarOutage};

        // Compile-time: every variant must be named here.
        fn domain_of(loss: CoverageLoss) -> &'static str {
            match loss {
                CoverageLoss::Outage(SidecarOutage::Unconfigured) => "unconfigured",
                CoverageLoss::Outage(SidecarOutage::Disabled) => "disabled",
                CoverageLoss::Outage(SidecarOutage::CircuitOpen) => "circuit_open",
                CoverageLoss::Outage(SidecarOutage::AllCallsFailed) => "all_calls_failed",
                CoverageLoss::Partial => "partial_coverage",
            }
        }

        let all = [
            CoverageLoss::Outage(SidecarOutage::Unconfigured),
            CoverageLoss::Outage(SidecarOutage::Disabled),
            CoverageLoss::Outage(SidecarOutage::CircuitOpen),
            CoverageLoss::Outage(SidecarOutage::AllCallsFailed),
            CoverageLoss::Partial,
        ];

        let metrics = MetricsRegistry::default();
        for loss in all {
            assert_eq!(
                loss.as_str(),
                domain_of(loss),
                "CoverageLoss::as_str drifted from the documented label domain"
            );
            metrics.record_sidecar_unavailable(loss.as_str(), "block");
        }

        let rendered = metrics.render_prometheus();
        for loss in all {
            let expected = format!(
                "secureprompt_sidecar_unavailable_total{{reason=\"{}\",action=\"block\"}} 1",
                loss.as_str()
            );
            assert!(
                rendered.contains(&expected),
                "reason={:?} never reached the series; the metric's documented \
                 label domain is wrong again. Looked for {expected:?} in:\n{rendered}",
                loss.as_str()
            );
        }

        // The value M1 was about, named literally so a reader of the failure
        // sees the finding rather than a generic missing-label message.
        assert!(
            rendered.contains("reason=\"partial_coverage\""),
            "partial_coverage is the fifth reason value the doc used to omit"
        );
    }

    /// Step 1 (KPI-2 histogram conversion) — failing unit test written before
    /// `Histogram` exists. Observing `[0.02, 0.2, 2.0]` on a single
    /// (unlabelled) series must render a cumulative, monotonic-non-decreasing
    /// `histogram` family with the exact bucket/count/sum values below.
    #[test]
    fn histogram_render_produces_cumulative_buckets() {
        let hist = Histogram::default();
        for v in [0.02, 0.2, 2.0] {
            hist.observe(v);
        }

        let mut out = String::new();
        out.push_str("# TYPE x histogram\n");
        hist.render_into(&mut out, "x", "");

        assert!(
            out.contains("# TYPE x histogram"),
            "missing TYPE line; got:\n{out}"
        );
        assert!(
            out.contains("x_bucket{le=\"0.025\"} 1"),
            "expected cumulative count 1 at le=0.025; got:\n{out}"
        );
        assert!(
            out.contains("x_bucket{le=\"0.25\"} 2"),
            "expected cumulative count 2 at le=0.25; got:\n{out}"
        );
        assert!(
            out.contains("x_bucket{le=\"+Inf\"} 3"),
            "expected cumulative count 3 at le=+Inf; got:\n{out}"
        );
        assert!(out.contains("x_count 3"), "expected x_count 3; got:\n{out}");
        assert!(
            out.contains("x_sum 2.22"),
            "expected x_sum 2.22; got:\n{out}"
        );

        // Buckets must be cumulative and monotonic non-decreasing.
        let mut last = 0u64;
        for line in out.lines().filter(|l| l.starts_with("x_bucket")) {
            let value: u64 = line
                .rsplit(' ')
                .next()
                .expect("bucket line has a trailing value")
                .parse()
                .expect("bucket value is a u64");
            assert!(
                value >= last,
                "bucket counts must be monotonic non-decreasing, got {value} after {last} in line {line:?}"
            );
            last = value;
        }
        assert_eq!(
            last, 3,
            "final (+Inf) bucket must equal total observation count"
        );
    }
}
