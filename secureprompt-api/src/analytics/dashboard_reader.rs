//! Phase 5 / Plan 05-03 — Read-only `ClickHouse` facade over the four dbt mart tables.
//!
//! `DashboardReader` wraps a dedicated `clickhouse::Client` (separate from the
//! write-path `AnalyticsHandle` — RESEARCH A5 / Pitfall #4). It exposes four typed
//! query methods, one per mart. Each method:
//!   1. Guards the date range (to >= from, span <= 366 days).
//!   2. Binds `workspace_id` + dates using positional `?` placeholders.
//!   3. Maps `Table ... doesn't exist` errors to `ApiError::NotFound`
//!      so the UI can show "Marts not yet populated. Run dbt build." (RESEARCH A6).
//!   4. Records `MetricsRegistry::record_mart_query_duration`.

use crate::observability::metrics::MetricsRegistry;
use clickhouse::Row;
use secureprompt_common::errors::ApiError;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use uuid::Uuid;

// ── Row structs ─────────────────────────────────────────────────────────────

/// Columns from `mart_usage_daily`
/// (see `secureprompt-analytics/models/marts/mart_usage_daily.sql`).
#[derive(Row, Deserialize, Serialize, Clone, Debug)]
pub struct UsageDailyRow {
    #[serde(with = "clickhouse::serde::uuid")]
    pub workspace_id: Uuid,
    pub model: String,
    #[serde(with = "crate::analytics::serde_helpers::date")]
    pub usage_date: chrono::NaiveDate,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_reasoning_tokens: u64,
    pub total_cost_usd: f64,
    pub request_count: u64,
    pub estimated_request_count: u64,
}

/// Columns from `mart_cost_by_model`
/// (see `secureprompt-analytics/models/marts/mart_cost_by_model.sql`).
#[derive(Row, Deserialize, Serialize, Clone, Debug)]
pub struct CostByModelRow {
    pub model: String,
    #[serde(with = "crate::analytics::serde_helpers::date")]
    pub usage_date: chrono::NaiveDate,
    pub daily_cost_usd: f64,
    pub daily_request_count: u64,
    pub rolling_7d_cost_usd: f64,
    pub rolling_30d_cost_usd: f64,
}

/// Columns from `mart_policy_violations`
/// (see `secureprompt-analytics/models/marts/mart_policy_violations.sql`).
#[derive(Row, Deserialize, Serialize, Clone, Debug)]
pub struct PolicyViolationsRow {
    #[serde(with = "clickhouse::serde::uuid")]
    pub workspace_id: Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    pub rule_id: Uuid,
    pub rule_name: String,
    pub action: String,
    #[serde(with = "crate::analytics::serde_helpers::date")]
    pub violation_date: chrono::NaiveDate,
    pub violation_count: u64,
    pub dry_run_count: u64,
    pub enforced_count: u64,
}

/// Columns from `mart_latency_pctiles`
/// (see `secureprompt-analytics/models/marts/mart_latency_pctiles.sql`).
#[derive(Row, Deserialize, Serialize, Clone, Debug)]
pub struct LatencyPctilesRow {
    #[serde(with = "clickhouse::serde::uuid")]
    pub workspace_id: Uuid,
    pub model: String,
    #[serde(with = "crate::analytics::serde_helpers::date")]
    pub usage_date: chrono::NaiveDate,
    pub p50_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub p99_latency_ms: f64,
    /// TTFT (time-to-first-byte) percentiles; `0.0` when no samples in the
    /// bucket carried a TTFT measurement (debug mode, embedding stubs).
    /// `ttft_sample_count` exposes the underlying sample count so the UI
    /// can render "—" instead of "0ms" for empty buckets.
    pub p50_ttft_ms: f64,
    pub p95_ttft_ms: f64,
    pub p99_ttft_ms: f64,
    pub ttft_sample_count: u64,
    pub sample_count: u64,
}

/// Hourly bucket row for the latency chart's intra-day view.
///
/// Returned when the analytics endpoint is called with `bucket=hour`.
/// `bucket_ts` is the UTC start of the hour bucket, suitable for direct
/// rendering on a Recharts time axis after JS Date parsing.
#[derive(Row, Deserialize, Serialize, Clone, Debug)]
pub struct LatencyPctilesHourlyRow {
    #[serde(with = "clickhouse::serde::uuid")]
    pub workspace_id: Uuid,
    pub model: String,
    #[serde(with = "crate::analytics::serde_helpers::datetime")]
    pub bucket_ts: chrono::DateTime<chrono::Utc>,
    pub p50_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub p99_latency_ms: f64,
    pub p50_ttft_ms: f64,
    pub p95_ttft_ms: f64,
    pub p99_ttft_ms: f64,
    pub ttft_sample_count: u64,
    pub sample_count: u64,
}

// ── DashboardReader ──────────────────────────────────────────────────────────

/// Read-only facade over the `ClickHouse` mart tables.
///
/// Constructed once in `AppState::try_new` from a **separate** `clickhouse::Client`
/// (not the async-insert client used by `AnalyticsHandle`). This prevents the
/// interactive read path from competing with write batching (RESEARCH A5).
#[derive(Clone)]
pub struct DashboardReader {
    client: clickhouse::Client,
}

impl DashboardReader {
    /// Wrap a dedicated reader `clickhouse::Client`.
    #[must_use]
    pub const fn new(client: clickhouse::Client) -> Self {
        Self { client }
    }

    /// Expose the raw `clickhouse::Client` for handlers that need to run
    /// ad-hoc queries against raw tables (e.g. `requests.rs` in Plan 05-04).
    /// The mart-only CI gate applies only to `analytics.rs`, not to callers
    /// of this accessor.
    #[must_use]
    pub const fn client(&self) -> &clickhouse::Client {
        &self.client
    }

    /// Query `mart_usage_daily` for a workspace in the given date window.
    ///
    /// `model` is an optional filter; when `None` all models are returned.
    ///
    /// # Errors
    /// Returns `ApiError::NotFound` when the mart table does not yet exist
    /// (dbt not run). Returns `ApiError::Internal` for other `ClickHouse` errors.
    pub async fn query_usage_daily(
        &self,
        metrics: &MetricsRegistry,
        ws: Uuid,
        from: chrono::NaiveDate,
        to: chrono::NaiveDate,
        model: Option<&str>,
    ) -> Result<Vec<UsageDailyRow>, ApiError> {
        validate_date_range(from, to)?;
        let start = Instant::now();
        let sql = if model.is_some() {
            "SELECT workspace_id, model, usage_date, total_input_tokens, \
             total_output_tokens, total_reasoning_tokens, total_cost_usd, \
             request_count, estimated_request_count \
             FROM mart_usage_daily \
             WHERE workspace_id = ? AND usage_date >= ? AND usage_date <= ? AND model = ?"
        } else {
            "SELECT workspace_id, model, usage_date, total_input_tokens, \
             total_output_tokens, total_reasoning_tokens, total_cost_usd, \
             request_count, estimated_request_count \
             FROM mart_usage_daily \
             WHERE workspace_id = ? AND usage_date >= ? AND usage_date <= ?"
        };

        let result = if let Some(m) = model {
            self.client
                .query(sql)
                .bind(ws)
                .bind(from)
                .bind(to)
                .bind(m)
                .fetch_all::<UsageDailyRow>()
                .await
        } else {
            self.client
                .query(sql)
                .bind(ws)
                .bind(from)
                .bind(to)
                .fetch_all::<UsageDailyRow>()
                .await
        };

        metrics.record_mart_query_duration("mart_usage_daily", start.elapsed());
        match result {
            Ok(rows) if !rows.is_empty() => Ok(rows),
            // Mart missing OR empty → fall back to raw aggregation. Empty
            // is treated the same as missing because dbt typically runs on
            // a schedule (e.g. hourly), so just-ingested rows aren't yet in
            // the mart and the dashboard would still render empty.
            Ok(_) => self.query_usage_daily_raw_fallback(ws, from, to, model).await,
            Err(e) if is_missing_table_err(&e) => {
                self.query_usage_daily_raw_fallback(ws, from, to, model).await
            }
            Err(e) => Err(ApiError::Internal(format!(
                "ClickHouse query error on mart_usage_daily: {e}"
            ))),
        }
    }

    /// Fallback aggregation against the raw `request_events` table — used
    /// when the dbt-built `mart_usage_daily` is missing or empty. Mirrors
    /// the mart's GROUP BY exactly so the dashboard renders the same shape
    /// of data whether dbt has run or not.
    async fn query_usage_daily_raw_fallback(
        &self,
        ws: Uuid,
        from: chrono::NaiveDate,
        to: chrono::NaiveDate,
        model: Option<&str>,
    ) -> Result<Vec<UsageDailyRow>, ApiError> {
        let sql = if model.is_some() {
            "SELECT workspace_id, model, toDate(created_at) AS usage_date, \
             sum(coalesce(input_tokens, toUInt32(0)))      AS total_input_tokens, \
             sum(coalesce(output_tokens, toUInt32(0)))     AS total_output_tokens, \
             sum(coalesce(reasoning_tokens, toUInt32(0)))  AS total_reasoning_tokens, \
             sum(cost_usd)                                 AS total_cost_usd, \
             count()                                       AS request_count, \
             countIf(estimated_usage)                      AS estimated_request_count \
             FROM request_events \
             WHERE workspace_id = ? AND toDate(created_at) >= ? AND toDate(created_at) <= ? AND model = ? \
             GROUP BY workspace_id, model, usage_date \
             ORDER BY usage_date"
        } else {
            "SELECT workspace_id, model, toDate(created_at) AS usage_date, \
             sum(coalesce(input_tokens, toUInt32(0)))      AS total_input_tokens, \
             sum(coalesce(output_tokens, toUInt32(0)))     AS total_output_tokens, \
             sum(coalesce(reasoning_tokens, toUInt32(0)))  AS total_reasoning_tokens, \
             sum(cost_usd)                                 AS total_cost_usd, \
             count()                                       AS request_count, \
             countIf(estimated_usage)                      AS estimated_request_count \
             FROM request_events \
             WHERE workspace_id = ? AND toDate(created_at) >= ? AND toDate(created_at) <= ? \
             GROUP BY workspace_id, model, usage_date \
             ORDER BY usage_date"
        };
        let result = if let Some(m) = model {
            self.client.query(sql).bind(ws).bind(from).bind(to).bind(m)
                .fetch_all::<UsageDailyRow>().await
        } else {
            self.client.query(sql).bind(ws).bind(from).bind(to)
                .fetch_all::<UsageDailyRow>().await
        };
        result.map_err(|e| ApiError::Internal(format!(
            "ClickHouse fallback query error on request_events: {e}"
        )))
    }

    /// Query `mart_cost_by_model` for one workspace in the given date window.
    ///
    /// WS1-2: this method previously filtered by date only, and the endpoint
    /// relied on a handler-level guard that fired only when the caller
    /// supplied an explicit `workspace_id` — so omitting the parameter
    /// returned every tenant's costs. Tenancy is now enforced in the query
    /// itself, which is the only layer every caller must pass through.
    ///
    /// # Errors
    /// Falls back to a workspace-scoped `request_events` aggregation when the
    /// mart is missing, empty, or predates the `workspace_id` column (see
    /// `is_stale_mart_err`). Returns `ApiError::Internal` for other
    /// `ClickHouse` errors.
    pub async fn query_cost_by_model(
        &self,
        metrics: &MetricsRegistry,
        ws: Uuid,
        from: chrono::NaiveDate,
        to: chrono::NaiveDate,
    ) -> Result<Vec<CostByModelRow>, ApiError> {
        validate_date_range(from, to)?;
        let start = Instant::now();
        let result = self
            .client
            .query(
                "SELECT model, usage_date, daily_cost_usd, daily_request_count, \
                 rolling_7d_cost_usd, rolling_30d_cost_usd \
                 FROM mart_cost_by_model \
                 WHERE workspace_id = ? AND usage_date >= ? AND usage_date <= ?",
            )
            .bind(ws)
            .bind(from)
            .bind(to)
            .fetch_all::<CostByModelRow>()
            .await;
        metrics.record_mart_query_duration("mart_cost_by_model", start.elapsed());
        match result {
            Ok(rows) if !rows.is_empty() => Ok(rows),
            Ok(_) => self.query_cost_by_model_raw_fallback(ws, from, to).await,
            Err(e) if is_stale_mart_err(&e) => {
                self.query_cost_by_model_raw_fallback(ws, from, to).await
            }
            Err(e) => Err(ApiError::Internal(format!(
                "ClickHouse query error on mart_cost_by_model: {e}"
            ))),
        }
    }

    /// Fallback for `query_cost_by_model` against raw `request_events`.
    /// We omit the rolling-window columns (mart-only enrichment from dbt
    /// window functions) — set them equal to the daily figures so the
    /// chart renders without 7d/30d trend lines until dbt runs.
    async fn query_cost_by_model_raw_fallback(
        &self,
        ws: Uuid,
        from: chrono::NaiveDate,
        to: chrono::NaiveDate,
    ) -> Result<Vec<CostByModelRow>, ApiError> {
        let sql = "SELECT model, toDate(created_at) AS usage_date, \
             sum(cost_usd) AS daily_cost_usd, \
             count()       AS daily_request_count, \
             sum(cost_usd) AS rolling_7d_cost_usd, \
             sum(cost_usd) AS rolling_30d_cost_usd \
             FROM request_events \
             WHERE workspace_id = ? \
               AND toDate(created_at) >= ? AND toDate(created_at) <= ? \
             GROUP BY model, usage_date \
             ORDER BY usage_date, model";
        self.client.query(sql).bind(ws).bind(from).bind(to)
            .fetch_all::<CostByModelRow>().await
            .map_err(|e| ApiError::Internal(format!(
                "ClickHouse fallback query error on request_events: {e}"
            )))
    }

    /// Query `mart_policy_violations` for a workspace in the given date window.
    ///
    /// # Errors
    /// Falls back to a raw `policy_events` aggregation when the mart is
    /// missing or empty — same pattern as `query_usage_daily`. Without
    /// the fallback, on-prem deployments that hadn't yet run dbt rendered
    /// the policy chart blank even when violations were logged. Returns
    /// `ApiError::Internal` only for other `ClickHouse` errors.
    pub async fn query_policy_violations(
        &self,
        metrics: &MetricsRegistry,
        ws: Uuid,
        from: chrono::NaiveDate,
        to: chrono::NaiveDate,
    ) -> Result<Vec<PolicyViolationsRow>, ApiError> {
        validate_date_range(from, to)?;
        let start = Instant::now();
        let result = self
            .client
            .query(
                "SELECT workspace_id, rule_id, rule_name, action, violation_date, \
                 violation_count, dry_run_count, enforced_count \
                 FROM mart_policy_violations \
                 WHERE workspace_id = ? AND violation_date >= ? AND violation_date <= ?",
            )
            .bind(ws)
            .bind(from)
            .bind(to)
            .fetch_all::<PolicyViolationsRow>()
            .await;
        metrics.record_mart_query_duration("mart_policy_violations", start.elapsed());
        match result {
            Ok(rows) if !rows.is_empty() => Ok(rows),
            Ok(_) => self.query_policy_violations_raw_fallback(ws, from, to).await,
            Err(e) if is_missing_table_err(&e) => {
                self.query_policy_violations_raw_fallback(ws, from, to).await
            }
            Err(e) => Err(ApiError::Internal(format!(
                "ClickHouse query error on mart_policy_violations: {e}"
            ))),
        }
    }

    /// Fallback aggregation against the raw `policy_events` table — used
    /// when the dbt-built `mart_policy_violations` is missing or empty.
    /// Mirrors the mart's GROUP BY exactly so the dashboard renders the
    /// same shape regardless of whether dbt has run.
    async fn query_policy_violations_raw_fallback(
        &self,
        ws: Uuid,
        from: chrono::NaiveDate,
        to: chrono::NaiveDate,
    ) -> Result<Vec<PolicyViolationsRow>, ApiError> {
        let sql = "SELECT workspace_id, rule_id, any(rule_name) AS rule_name, \
             any(action) AS action, toDate(created_at) AS violation_date, \
             count()                       AS violation_count, \
             countIf(dry_run)              AS dry_run_count, \
             countIf(NOT dry_run)          AS enforced_count \
             FROM policy_events \
             WHERE workspace_id = ? AND toDate(created_at) >= ? AND toDate(created_at) <= ? \
             GROUP BY workspace_id, rule_id, violation_date \
             ORDER BY violation_date, rule_id";
        self.client
            .query(sql)
            .bind(ws)
            .bind(from)
            .bind(to)
            .fetch_all::<PolicyViolationsRow>()
            .await
            .map_err(|e| {
                ApiError::Internal(format!(
                    "ClickHouse fallback query error on policy_events: {e}"
                ))
            })
    }

    /// Query `mart_latency_pctiles` for a workspace in the given date window.
    ///
    /// `model` is an optional filter.
    ///
    /// # Errors
    /// Returns `Ok(Vec::new())` when the mart table does not yet exist
    /// (dbt not run); the dashboard renders an empty state. Returns
    /// `ApiError::Internal` only for other `ClickHouse` errors.
    pub async fn query_latency_pctiles(
        &self,
        metrics: &MetricsRegistry,
        ws: Uuid,
        from: chrono::NaiveDate,
        to: chrono::NaiveDate,
        model: Option<&str>,
    ) -> Result<Vec<LatencyPctilesRow>, ApiError> {
        validate_date_range(from, to)?;
        let start = Instant::now();
        let sql = if model.is_some() {
            "SELECT workspace_id, model, usage_date, p50_latency_ms, \
             p95_latency_ms, p99_latency_ms, p50_ttft_ms, p95_ttft_ms, \
             p99_ttft_ms, ttft_sample_count, sample_count \
             FROM mart_latency_pctiles \
             WHERE workspace_id = ? AND usage_date >= ? AND usage_date <= ? AND model = ?"
        } else {
            "SELECT workspace_id, model, usage_date, p50_latency_ms, \
             p95_latency_ms, p99_latency_ms, p50_ttft_ms, p95_ttft_ms, \
             p99_ttft_ms, ttft_sample_count, sample_count \
             FROM mart_latency_pctiles \
             WHERE workspace_id = ? AND usage_date >= ? AND usage_date <= ?"
        };

        let result = if let Some(m) = model {
            self.client
                .query(sql)
                .bind(ws)
                .bind(from)
                .bind(to)
                .bind(m)
                .fetch_all::<LatencyPctilesRow>()
                .await
        } else {
            self.client
                .query(sql)
                .bind(ws)
                .bind(from)
                .bind(to)
                .fetch_all::<LatencyPctilesRow>()
                .await
        };

        metrics.record_mart_query_duration("mart_latency_pctiles", start.elapsed());
        match result {
            Ok(rows) if !rows.is_empty() => Ok(rows),
            Ok(_) => self.query_latency_pctiles_raw_fallback(ws, from, to, model).await,
            Err(e) if is_missing_table_err(&e) => {
                self.query_latency_pctiles_raw_fallback(ws, from, to, model).await
            }
            Err(e) => Err(ApiError::Internal(format!(
                "ClickHouse query error on mart_latency_pctiles: {e}"
            ))),
        }
    }

    /// Fallback aggregation against `latency_samples` when
    /// `mart_latency_pctiles` is missing/empty.
    async fn query_latency_pctiles_raw_fallback(
        &self,
        ws: Uuid,
        from: chrono::NaiveDate,
        to: chrono::NaiveDate,
        model: Option<&str>,
    ) -> Result<Vec<LatencyPctilesRow>, ApiError> {
        // Fallback aggregates from raw `latency_samples`. TTFT columns are
        // Nullable (added by migration 003); rows pre-migration carry NULL.
        // We use quantileIf + assumeNotNull rather than quantile-over-Nullable
        // because some ClickHouse versions silently coerce NULLs to 0 and
        // bias the percentile downward.
        let sql = if model.is_some() {
            "SELECT workspace_id, model, toDate(created_at) AS usage_date, \
             quantile(0.5)(latency_ms)  AS p50_latency_ms, \
             quantile(0.95)(latency_ms) AS p95_latency_ms, \
             quantile(0.99)(latency_ms) AS p99_latency_ms, \
             quantileIf(0.5)(assumeNotNull(ttft_ms),  ttft_ms IS NOT NULL) AS p50_ttft_ms, \
             quantileIf(0.95)(assumeNotNull(ttft_ms), ttft_ms IS NOT NULL) AS p95_ttft_ms, \
             quantileIf(0.99)(assumeNotNull(ttft_ms), ttft_ms IS NOT NULL) AS p99_ttft_ms, \
             countIf(ttft_ms IS NOT NULL) AS ttft_sample_count, \
             count() AS sample_count \
             FROM latency_samples \
             WHERE workspace_id = ? AND toDate(created_at) >= ? AND toDate(created_at) <= ? AND model = ? \
             GROUP BY workspace_id, model, usage_date \
             ORDER BY usage_date, model"
        } else {
            "SELECT workspace_id, model, toDate(created_at) AS usage_date, \
             quantile(0.5)(latency_ms)  AS p50_latency_ms, \
             quantile(0.95)(latency_ms) AS p95_latency_ms, \
             quantile(0.99)(latency_ms) AS p99_latency_ms, \
             quantileIf(0.5)(assumeNotNull(ttft_ms),  ttft_ms IS NOT NULL) AS p50_ttft_ms, \
             quantileIf(0.95)(assumeNotNull(ttft_ms), ttft_ms IS NOT NULL) AS p95_ttft_ms, \
             quantileIf(0.99)(assumeNotNull(ttft_ms), ttft_ms IS NOT NULL) AS p99_ttft_ms, \
             countIf(ttft_ms IS NOT NULL) AS ttft_sample_count, \
             count() AS sample_count \
             FROM latency_samples \
             WHERE workspace_id = ? AND toDate(created_at) >= ? AND toDate(created_at) <= ? \
             GROUP BY workspace_id, model, usage_date \
             ORDER BY usage_date, model"
        };
        let result = if let Some(m) = model {
            self.client.query(sql).bind(ws).bind(from).bind(to).bind(m)
                .fetch_all::<LatencyPctilesRow>().await
        } else {
            self.client.query(sql).bind(ws).bind(from).bind(to)
                .fetch_all::<LatencyPctilesRow>().await
        };
        result.map_err(|e| ApiError::Internal(format!(
            "ClickHouse fallback query error on latency_samples: {e}"
        )))
    }

    /// Hourly aggregation of latency + TTFT off the raw `latency_samples`
    /// table. Used by the analytics endpoint when `bucket=hour` is set
    /// (typically a 24h or 7d range — bigger ranges should stay daily for
    /// chart legibility). Time bounds are inclusive on the `from` day and
    /// exclusive on `to + 1 day` so the entire `to` day is included.
    pub async fn query_latency_pctiles_hourly(
        &self,
        metrics: &MetricsRegistry,
        ws: Uuid,
        from: chrono::NaiveDate,
        to: chrono::NaiveDate,
        model: Option<&str>,
    ) -> Result<Vec<LatencyPctilesHourlyRow>, ApiError> {
        validate_date_range(from, to)?;
        // Hourly buckets blow up sample count for wide ranges; cap at 31
        // days so a `bucket=hour&from=2024-01-01&to=2024-12-31` request
        // doesn't return ~9k rows.
        let span = (to - from).num_days();
        if span > 31 {
            return Err(ApiError::Forbidden(format!(
                "hourly bucket: range too large ({span} days, max 31)"
            )));
        }
        let start = Instant::now();
        let sql = if model.is_some() {
            "SELECT workspace_id, model, toStartOfHour(created_at) AS bucket_ts, \
             quantile(0.5)(latency_ms)  AS p50_latency_ms, \
             quantile(0.95)(latency_ms) AS p95_latency_ms, \
             quantile(0.99)(latency_ms) AS p99_latency_ms, \
             quantileIf(0.5)(assumeNotNull(ttft_ms),  ttft_ms IS NOT NULL) AS p50_ttft_ms, \
             quantileIf(0.95)(assumeNotNull(ttft_ms), ttft_ms IS NOT NULL) AS p95_ttft_ms, \
             quantileIf(0.99)(assumeNotNull(ttft_ms), ttft_ms IS NOT NULL) AS p99_ttft_ms, \
             countIf(ttft_ms IS NOT NULL) AS ttft_sample_count, \
             count() AS sample_count \
             FROM latency_samples \
             WHERE workspace_id = ? AND toDate(created_at) >= ? AND toDate(created_at) <= ? AND model = ? \
             GROUP BY workspace_id, model, bucket_ts \
             ORDER BY bucket_ts, model"
        } else {
            "SELECT workspace_id, model, toStartOfHour(created_at) AS bucket_ts, \
             quantile(0.5)(latency_ms)  AS p50_latency_ms, \
             quantile(0.95)(latency_ms) AS p95_latency_ms, \
             quantile(0.99)(latency_ms) AS p99_latency_ms, \
             quantileIf(0.5)(assumeNotNull(ttft_ms),  ttft_ms IS NOT NULL) AS p50_ttft_ms, \
             quantileIf(0.95)(assumeNotNull(ttft_ms), ttft_ms IS NOT NULL) AS p95_ttft_ms, \
             quantileIf(0.99)(assumeNotNull(ttft_ms), ttft_ms IS NOT NULL) AS p99_ttft_ms, \
             countIf(ttft_ms IS NOT NULL) AS ttft_sample_count, \
             count() AS sample_count \
             FROM latency_samples \
             WHERE workspace_id = ? AND toDate(created_at) >= ? AND toDate(created_at) <= ? \
             GROUP BY workspace_id, model, bucket_ts \
             ORDER BY bucket_ts, model"
        };
        let result = if let Some(m) = model {
            self.client.query(sql).bind(ws).bind(from).bind(to).bind(m)
                .fetch_all::<LatencyPctilesHourlyRow>().await
        } else {
            self.client.query(sql).bind(ws).bind(from).bind(to)
                .fetch_all::<LatencyPctilesHourlyRow>().await
        };
        metrics.record_mart_query_duration("latency_samples_hourly", start.elapsed());
        result.map_err(|e| ApiError::Internal(format!(
            "ClickHouse hourly query error on latency_samples: {e}"
        )))
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Validate that `from <= to` and the range is at most 366 days.
fn validate_date_range(from: chrono::NaiveDate, to: chrono::NaiveDate) -> Result<(), ApiError> {
    if to < from {
        return Err(ApiError::Forbidden(
            "invalid date range: 'to' must be >= 'from'".into(),
        ));
    }
    let span = (to - from).num_days();
    if span > 366 {
        return Err(ApiError::Forbidden(format!(
            "date range too large: {span} days (max 366)"
        )));
    }
    Ok(())
}

/// Map a `ClickHouse` error to an `ApiError`.
///
/// `Table ... doesn't exist` (returned when dbt has not been run yet) is
/// converted to `Ok(vec![])` so the dashboard renders its "no data yet"
/// empty state instead of breaking on a 404. The underlying condition is
/// still observable via `tracing::warn!` + the `dashboard_errors_total`
/// metric, so operators can see that dbt hasn't been run.
/// Detect "table doesn't exist" / "unknown table" error variants so the
/// caller can transparently fall back to a raw-table aggregation.
/// True when a mart query failed because the mart is absent *or* predates a
/// column the query now requires.
///
/// WS1-2 added `workspace_id` to `mart_cost_by_model`. A deployment that has
/// not re-run dbt still has the old, workspace-less table, and querying the
/// new column yields `UNKNOWN_IDENTIFIER` rather than `UNKNOWN_TABLE`. Both
/// mean "this mart cannot answer the question", and both must degrade to the
/// workspace-scoped raw fallback — never to an unfiltered read.
///
/// Deliberately separate from `is_missing_table_err` so widening the
/// stale-schema case cannot change behaviour for the other mart endpoints.
fn is_stale_mart_err(e: &clickhouse::error::Error) -> bool {
    if is_missing_table_err(e) {
        return true;
    }
    if let clickhouse::error::Error::BadResponse(msg) = e {
        msg.contains("UNKNOWN_IDENTIFIER")
            || msg.contains("Unknown expression identifier")
            || msg.contains("There's no column")
            || msg.contains("Missing columns")
    } else {
        false
    }
}

fn is_missing_table_err(e: &clickhouse::error::Error) -> bool {
    if let clickhouse::error::Error::BadResponse(msg) = e {
        msg.contains("doesn't exist")
            || msg.contains("UNKNOWN_TABLE")
            || msg.contains("UNKNOWN_DATABASE")
            || msg.contains("Unknown table expression identifier")
    } else {
        false
    }
}

fn map_ch_error<T>(
    result: Result<Vec<T>, clickhouse::error::Error>,
    mart_name: &str,
) -> Result<Vec<T>, ApiError> {
    match result {
        Ok(rows) => Ok(rows),
        Err(clickhouse::error::Error::BadResponse(msg))
            if msg.contains("doesn't exist")
                || msg.contains("UNKNOWN_TABLE")
                || msg.contains("UNKNOWN_DATABASE")
                || msg.contains("Unknown table expression identifier") =>
        {
            tracing::warn!(
                mart = mart_name,
                "mart table missing — returning empty result (run dbt build to populate)"
            );
            Ok(Vec::new())
        }
        Err(e) => Err(ApiError::Internal(format!(
            "ClickHouse query error on {mart_name}: {e}"
        ))),
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn validate_date_range_ok() {
        let from = chrono::NaiveDate::from_ymd_opt(2024, 1, 1).unwrap();
        let to = chrono::NaiveDate::from_ymd_opt(2024, 1, 7).unwrap();
        assert!(validate_date_range(from, to).is_ok());
    }

    #[test]
    fn validate_date_range_same_day() {
        let d = chrono::NaiveDate::from_ymd_opt(2024, 6, 15).unwrap();
        assert!(validate_date_range(d, d).is_ok());
    }

    #[test]
    fn validate_date_range_reversed_is_err() {
        let from = chrono::NaiveDate::from_ymd_opt(2024, 1, 7).unwrap();
        let to = chrono::NaiveDate::from_ymd_opt(2024, 1, 1).unwrap();
        let err = validate_date_range(from, to).unwrap_err();
        assert!(matches!(err, ApiError::Forbidden(_)));
    }

    #[test]
    fn validate_date_range_too_large_is_err() {
        let from = chrono::NaiveDate::from_ymd_opt(2024, 1, 1).unwrap();
        let to = chrono::NaiveDate::from_ymd_opt(2025, 2, 28).unwrap(); // > 366 days
        let err = validate_date_range(from, to).unwrap_err();
        assert!(matches!(err, ApiError::Forbidden(_)));
    }

    #[test]
    fn map_ch_error_table_doesnt_exist_returns_empty() {
        let result: Result<Vec<UsageDailyRow>, _> = Err(clickhouse::error::Error::BadResponse(
            "Table sp_analytics.mart_usage_daily doesn't exist".into(),
        ));
        let rows = map_ch_error(result, "mart_usage_daily").expect("empty vec on missing mart");
        assert!(rows.is_empty());
    }

    #[test]
    fn map_ch_error_unknown_table_returns_empty() {
        let result: Result<Vec<CostByModelRow>, _> = Err(clickhouse::error::Error::BadResponse(
            "Code: 60. DB::Exception: UNKNOWN_TABLE".into(),
        ));
        let rows = map_ch_error(result, "mart_cost_by_model").expect("empty vec on missing mart");
        assert!(rows.is_empty());
    }

    #[test]
    fn map_ch_error_other_is_internal() {
        let result: Result<Vec<PolicyViolationsRow>, _> = Err(
            clickhouse::error::Error::BadResponse("some other DB error".into()),
        );
        let err = map_ch_error(result, "mart_policy_violations").unwrap_err();
        assert!(matches!(err, ApiError::Internal(_)));
    }
}
