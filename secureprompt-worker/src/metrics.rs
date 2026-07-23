//! Prometheus metrics registry for `secureprompt-worker`.
//!
//! Before this module existed, `secureprompt-worker` bound no HTTP server at
//! all, so Prometheus had nothing to scrape for the worker's cron jobs or
//! its Redis task-drain loop. `secureprompt-api` already exposes its own
//! `/metrics` endpoint via `observability::metrics::MetricsRegistry` — this
//! is the worker's equivalent. It is a deliberate, minimal, standalone copy
//! (same `AtomicU64` + `Mutex<Vec<(label.., ..)>>` shape, same histogram
//! bucket boundaries) rather than a shared crate, per the KPI-2 monitoring
//! plan's "no shared crate" constraint — the two binaries' metric sets are
//! different enough (and small enough) that sharing isn't worth the coupling.
//!
//! Exposed series (all prefixed `secureprompt_worker_`):
//!   - `scheduled_job_runs_total{job}`             (counter)
//!   - `scheduled_job_failures_total{job}`         (counter)
//!   - `scheduled_job_duration_seconds{job}`       (histogram)
//!   - `tasks_processed_total{task_type,outcome}`  (counter)
//!   - `queue_drain_errors_total`                  (counter, unlabelled)
//!   - `up`                                        (gauge, always 1)
//!
//! `job`, `task_type`, and `outcome` are all bounded label values (fixed
//! strings / the `secureprompt_common::tasks::task_types` constants) —
//! callers must never pass free text or ids into these recorders.

use axum::{extract::State, http::header, response::IntoResponse, routing::get, Router};
use std::{
    fmt::Write as _,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

/// Bucket boundaries (seconds). Matches `secureprompt-api`'s
/// `observability::metrics::HISTOGRAM_BUCKETS` convention exactly, but is
/// kept as an independent copy here (see module docs).
const HISTOGRAM_BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// A single Prometheus histogram series (one label combination).
///
/// `buckets[i]` holds the *non-cumulative* count of observations with
/// `HISTOGRAM_BUCKETS[i - 1] < value <= HISTOGRAM_BUCKETS[i]` (and
/// `buckets[0]` holds `value <= HISTOGRAM_BUCKETS[0]`); the extra slot at
/// `HISTOGRAM_BUCKETS.len()` is the `+Inf` overflow bucket. `observe`
/// therefore only ever touches one bucket; the cumulative totals Prometheus
/// expects are computed once, at render time, in [`Histogram::render_into`].
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

    /// Append this series' `_bucket{le}` / `_sum` / `_count` lines to `out`.
    ///
    /// `labels` is the label body *without* surrounding braces (e.g.
    /// `job="optimize_final"`), or an empty string for an unlabelled series.
    /// Does not print the `# TYPE ... histogram` line — callers print that
    /// once per metric family, before iterating series.
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

/// Worker-side Prometheus registry. Cheap to `Default::default()`; build one
/// instance in `main()`, wrap it in an `Arc`, and clone that `Arc` into the
/// cron closures, the queue-drain loop, and the `/metrics` HTTP handler.
#[derive(Debug, Default)]
pub struct WorkerMetrics {
    /// `scheduled_job_runs_total{job}` — bumped on every cron tick,
    /// regardless of outcome.
    job_runs: Mutex<Vec<(String, u64)>>,
    /// `scheduled_job_failures_total{job}` — bumped only when the job body
    /// reports failure.
    job_failures: Mutex<Vec<(String, u64)>>,
    /// `scheduled_job_duration_seconds{job}` — wall-clock time of the job
    /// body, recorded on every run (success or failure).
    job_duration: Mutex<Vec<(String, Histogram)>>,
    /// `tasks_processed_total{task_type,outcome}` — one counter series per
    /// dispatched `(task_type, outcome)` pair.
    tasks_processed: Mutex<Vec<(String, String, u64)>>,
    /// `queue_drain_errors_total` — unlabelled counter. Bumped on
    /// Redis-checkout failures and unparseable task-envelope JSON in the
    /// queue-drain loop.
    queue_drain_errors: AtomicU64,
}

impl WorkerMetrics {
    /// Record one cron-job execution: always increments
    /// `scheduled_job_runs_total{job}`, increments
    /// `scheduled_job_failures_total{job}` when `ok` is `false`, and
    /// observes `scheduled_job_duration_seconds{job}` regardless of outcome.
    ///
    /// `job` must be a fixed string (e.g. `"optimize_final"`,
    /// `"rotation_cleanup"`) — never free text.
    ///
    /// # Panics
    /// Panics if an internal `Mutex` is poisoned (only possible after a
    /// panic on another thread while holding the lock).
    pub fn record_job(&self, job: &str, dur: Duration, ok: bool) {
        Self::incr(&self.job_runs, job);
        if !ok {
            Self::incr(&self.job_failures, job);
        }

        let secs = dur.as_secs_f64();
        let mut guard = self.job_duration.lock().expect("job_duration mutex");
        if let Some((_, hist)) = guard.iter_mut().find(|(j, _)| j == job) {
            hist.observe(secs);
        } else {
            let hist = Histogram::default();
            hist.observe(secs);
            guard.push((job.to_owned(), hist));
        }
    }

    /// Record one dispatched task's outcome. `task_type` should be one of
    /// the `secureprompt_common::tasks::task_types` constants (or the fixed
    /// string `"unknown"` for an unrecognized type — never the raw,
    /// attacker/bug-controlled `task.task_type` string itself, to keep
    /// cardinality bounded). `outcome` is one of `ok`/`error`/`unknown`/
    /// `stub`.
    ///
    /// # Panics
    /// Panics if the internal `Mutex` is poisoned.
    pub fn record_task(&self, task_type: &str, outcome: &str) {
        let mut guard = self
            .tasks_processed
            .lock()
            .expect("tasks_processed mutex");
        if let Some(row) = guard
            .iter_mut()
            .find(|(t, o, _)| t == task_type && o == outcome)
        {
            row.2 += 1;
        } else {
            guard.push((task_type.to_owned(), outcome.to_owned(), 1));
        }
    }

    /// Increment `queue_drain_errors_total`. Call on Redis-checkout failure
    /// or unparseable task-envelope JSON in the drain loop.
    pub fn record_drain_error(&self) {
        self.queue_drain_errors.fetch_add(1, Ordering::Relaxed);
    }

    fn incr(counters: &Mutex<Vec<(String, u64)>>, key: &str) {
        let mut guard = counters.lock().expect("counter mutex");
        if let Some(row) = guard.iter_mut().find(|(k, _)| k == key) {
            row.1 += 1;
        } else {
            guard.push((key.to_owned(), 1));
        }
    }

    /// Render the full registry in Prometheus text-exposition format.
    ///
    /// # Panics
    /// Panics if any internal `Mutex` is poisoned.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();

        // `up` always renders — it's the scrape-liveness signal, so it must
        // not depend on anything else in the registry having been touched.
        out.push_str("# TYPE secureprompt_worker_up gauge\n");
        out.push_str("secureprompt_worker_up 1\n");

        {
            let guard = self.job_runs.lock().expect("job_runs mutex");
            if !guard.is_empty() {
                out.push_str("# TYPE secureprompt_worker_scheduled_job_runs_total counter\n");
                for (job, value) in guard.iter() {
                    let _ = writeln!(
                        out,
                        "secureprompt_worker_scheduled_job_runs_total{{job=\"{job}\"}} {value}"
                    );
                }
            }
        }

        {
            let guard = self.job_failures.lock().expect("job_failures mutex");
            if !guard.is_empty() {
                out.push_str(
                    "# TYPE secureprompt_worker_scheduled_job_failures_total counter\n",
                );
                for (job, value) in guard.iter() {
                    let _ = writeln!(
                        out,
                        "secureprompt_worker_scheduled_job_failures_total{{job=\"{job}\"}} {value}"
                    );
                }
            }
        }

        {
            let guard = self.job_duration.lock().expect("job_duration mutex");
            if !guard.is_empty() {
                out.push_str(
                    "# TYPE secureprompt_worker_scheduled_job_duration_seconds histogram\n",
                );
                for (job, hist) in guard.iter() {
                    let labels = format!("job=\"{job}\"");
                    hist.render_into(
                        &mut out,
                        "secureprompt_worker_scheduled_job_duration_seconds",
                        &labels,
                    );
                }
            }
        }

        {
            let guard = self
                .tasks_processed
                .lock()
                .expect("tasks_processed mutex");
            if !guard.is_empty() {
                out.push_str("# TYPE secureprompt_worker_tasks_processed_total counter\n");
                for (task_type, outcome, value) in guard.iter() {
                    let _ = writeln!(
                        out,
                        "secureprompt_worker_tasks_processed_total{{task_type=\"{task_type}\",outcome=\"{outcome}\"}} {value}"
                    );
                }
            }
        }

        out.push_str("# TYPE secureprompt_worker_queue_drain_errors_total counter\n");
        let _ = writeln!(
            out,
            "secureprompt_worker_queue_drain_errors_total {}",
            self.queue_drain_errors.load(Ordering::Relaxed)
        );

        out
    }
}

/// Build the `/metrics` Axum router. Split out from `main()` so tests can
/// serve it directly (via `axum::serve` on an ephemeral port) without
/// duplicating route wiring.
pub fn router(metrics: Arc<WorkerMetrics>) -> Router {
    Router::new()
        .route("/metrics", get(metrics_handler))
        .with_state(metrics)
}

async fn metrics_handler(State(metrics): State<Arc<WorkerMetrics>>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        metrics.render(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_render_contains_up_gauge() {
        let metrics = WorkerMetrics::default();
        let out = metrics.render();
        assert!(out.contains("secureprompt_worker_up 1"), "got:\n{out}");
    }

    #[test]
    fn record_job_success_updates_runs_and_duration_without_failures() {
        let metrics = WorkerMetrics::default();
        metrics.record_job("optimize_final", Duration::from_millis(5), true);
        let out = metrics.render();

        assert!(
            out.contains(
                r#"secureprompt_worker_scheduled_job_runs_total{job="optimize_final"} 1"#
            ),
            "got:\n{out}"
        );
        assert!(
            out.contains(
                r#"secureprompt_worker_scheduled_job_duration_seconds_bucket{job="optimize_final",le="+Inf"} 1"#
            ),
            "got:\n{out}"
        );
        assert!(
            !out.contains("scheduled_job_failures_total"),
            "a successful run must not touch the failures counter; got:\n{out}"
        );
    }

    #[test]
    fn record_job_failure_bumps_failures_total() {
        let metrics = WorkerMetrics::default();
        metrics.record_job("rotation_cleanup", Duration::from_millis(1), false);
        let out = metrics.render();

        assert!(
            out.contains(
                r#"secureprompt_worker_scheduled_job_runs_total{job="rotation_cleanup"} 1"#
            ),
            "got:\n{out}"
        );
        assert!(
            out.contains(
                r#"secureprompt_worker_scheduled_job_failures_total{job="rotation_cleanup"} 1"#
            ),
            "got:\n{out}"
        );
    }

    #[test]
    fn record_task_and_drain_error() {
        let metrics = WorkerMetrics::default();
        metrics.record_task("policy.index_rule", "ok");
        metrics.record_task("policy.index_rule", "ok");
        metrics.record_task("policy.index_rule", "error");
        metrics.record_drain_error();
        metrics.record_drain_error();
        let out = metrics.render();

        assert!(
            out.contains(
                r#"secureprompt_worker_tasks_processed_total{task_type="policy.index_rule",outcome="ok"} 2"#
            ),
            "got:\n{out}"
        );
        assert!(
            out.contains(
                r#"secureprompt_worker_tasks_processed_total{task_type="policy.index_rule",outcome="error"} 1"#
            ),
            "got:\n{out}"
        );
        assert!(
            out.contains("secureprompt_worker_queue_drain_errors_total 2"),
            "got:\n{out}"
        );
    }

    /// Step 5 of the KPI-2 Task 4 plan — serve the real router on an
    /// ephemeral port and hit it over HTTP, rather than only calling the
    /// handler function directly, so the routing + `with_state` wiring is
    /// covered too.
    #[tokio::test]
    async fn metrics_route_serves_ok_with_up_gauge() {
        let metrics = Arc::new(WorkerMetrics::default());
        metrics.record_job("optimize_final", Duration::from_millis(2), true);
        let app = router(metrics);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local_addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve /metrics");
        });

        let resp = reqwest::get(format!("http://{addr}/metrics"))
            .await
            .expect("GET /metrics");
        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        let body = resp.text().await.expect("response body");
        assert!(body.contains("secureprompt_worker_up 1"), "got:\n{body}");
        assert!(
            body.contains(
                r#"secureprompt_worker_scheduled_job_runs_total{job="optimize_final"} 1"#
            ),
            "got:\n{body}"
        );
    }
}
