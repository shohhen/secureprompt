{{ config(
    materialized='table',
    engine='MergeTree()',
    order_by='(workspace_id, model, usage_date)',
    partition_by='toYYYYMM(usage_date)'
) }}

-- mart_cost_by_model: cumulative cost per workspace+model with 7-day and 30-day
-- rolling windows. Used by /usage cost breakdown panels in the dashboard.
--
-- WS1-2: this mart previously grouped by (model, usage_date) only, dropping the
-- workspace_id carried by mart_usage_daily. That made it cross-tenant by
-- construction, and the reading endpoint had no way to scope it. workspace_id is
-- now part of the grain and of every rolling-window correlation predicate.
--
-- IMPORTANT: Rolling windows are computed via a self-join on a date range subquery.
-- The OVER clause approach (sum(sum()) OVER ROWS BETWEEN) is NOT used because
-- dbt-clickhouse 1.9.6 window function support on table materialization is unverified
-- and may produce incorrect results on ClickHouse 24.8 partitioned tables.
-- The self-join pattern is reliable across all ClickHouse versions.

WITH daily AS (
    SELECT
        workspace_id,
        model,
        usage_date,
        sum(total_cost_usd)   AS daily_cost_usd,
        sum(request_count)    AS daily_request_count
    FROM {{ ref('mart_usage_daily') }}
    GROUP BY workspace_id, model, usage_date
)

SELECT
    d.workspace_id,
    d.model,
    d.usage_date,
    d.daily_cost_usd,
    d.daily_request_count,
    (
        SELECT sum(w7.daily_cost_usd)
        FROM daily AS w7
        WHERE w7.workspace_id = d.workspace_id
          AND w7.model = d.model
          AND w7.usage_date >= toDate(d.usage_date) - toIntervalDay(6)
          AND w7.usage_date <= d.usage_date
    )  AS rolling_7d_cost_usd,
    (
        SELECT sum(w30.daily_cost_usd)
        FROM daily AS w30
        WHERE w30.workspace_id = d.workspace_id
          AND w30.model = d.model
          AND w30.usage_date >= toDate(d.usage_date) - toIntervalDay(29)
          AND w30.usage_date <= d.usage_date
    )  AS rolling_30d_cost_usd
FROM daily AS d
