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
    #[serde(with = "clickhouse::serde::chrono::date32")]
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
    #[serde(with = "clickhouse::serde::chrono::date32")]
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
    #[serde(with = "clickhouse::serde::chrono::date32")]
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
    #[serde(with = "clickhouse::serde::chrono::date32")]
    pub usage_date: chrono::NaiveDate,
    pub p50_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub p99_latency_ms: f64,
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
        map_ch_error(result, "mart_usage_daily")
    }

    /// Query `mart_cost_by_model` for the given date window.
    ///
    /// Note: `mart_cost_by_model` is aggregated across all workspaces (no
    /// `workspace_id` column per the mart SQL). The IDOR guard is enforced at
    /// the handler level; this method returns data filtered by date only.
    ///
    /// # Errors
    /// Returns `ApiError::NotFound` when the mart table does not yet exist.
    /// Returns `ApiError::Internal` for other `ClickHouse` errors.
    pub async fn query_cost_by_model(
        &self,
        metrics: &MetricsRegistry,
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
                 WHERE usage_date >= ? AND usage_date <= ?",
            )
            .bind(from)
            .bind(to)
            .fetch_all::<CostByModelRow>()
            .await;
        metrics.record_mart_query_duration("mart_cost_by_model", start.elapsed());
        map_ch_error(result, "mart_cost_by_model")
    }

    /// Query `mart_policy_violations` for a workspace in the given date window.
    ///
    /// # Errors
    /// Returns `ApiError::NotFound` when the mart table does not yet exist.
    /// Returns `ApiError::Internal` for other `ClickHouse` errors.
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
        map_ch_error(result, "mart_policy_violations")
    }

    /// Query `mart_latency_pctiles` for a workspace in the given date window.
    ///
    /// `model` is an optional filter.
    ///
    /// # Errors
    /// Returns `ApiError::NotFound` when the mart table does not yet exist.
    /// Returns `ApiError::Internal` for other `ClickHouse` errors.
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
             p95_latency_ms, p99_latency_ms, sample_count \
             FROM mart_latency_pctiles \
             WHERE workspace_id = ? AND usage_date >= ? AND usage_date <= ? AND model = ?"
        } else {
            "SELECT workspace_id, model, usage_date, p50_latency_ms, \
             p95_latency_ms, p99_latency_ms, sample_count \
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
        map_ch_error(result, "mart_latency_pctiles")
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
/// `Table ... doesn't exist` (returned when dbt has not been run yet) maps to
/// `ApiError::NotFound` so the UI can show the RESEARCH A6 empty state.
fn map_ch_error<T>(
    result: Result<Vec<T>, clickhouse::error::Error>,
    mart_name: &str,
) -> Result<Vec<T>, ApiError> {
    match result {
        Ok(rows) => Ok(rows),
        Err(clickhouse::error::Error::BadResponse(msg))
            if msg.contains("doesn't exist") || msg.contains("UNKNOWN_TABLE") =>
        {
            Err(ApiError::NotFound(format!(
                "mart '{mart_name}' not populated; run dbt build"
            )))
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
    fn map_ch_error_table_doesnt_exist() {
        let result: Result<Vec<UsageDailyRow>, _> = Err(clickhouse::error::Error::BadResponse(
            "Table sp_analytics.mart_usage_daily doesn't exist".into(),
        ));
        let err = map_ch_error(result, "mart_usage_daily").unwrap_err();
        assert!(matches!(err, ApiError::NotFound(ref msg) if msg.contains("run dbt build")));
    }

    #[test]
    fn map_ch_error_unknown_table() {
        let result: Result<Vec<CostByModelRow>, _> = Err(clickhouse::error::Error::BadResponse(
            "Code: 60. DB::Exception: UNKNOWN_TABLE".into(),
        ));
        let err = map_ch_error(result, "mart_cost_by_model").unwrap_err();
        assert!(matches!(err, ApiError::NotFound(_)));
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
