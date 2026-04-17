{{ config(
    materialized='table',
    engine='MergeTree()',
    order_by='(workspace_id, model, usage_date)',
    partition_by='toYYYYMM(usage_date)'
) }}

-- mart_latency_pctiles: p50/p95/p99 latency by model + workspace, daily.
-- Used by /usage latency panels in the dashboard.
-- Note: ClickHouse quantile() operates on Float64; cast latency_ms accordingly.

SELECT
    workspace_id,
    model,
    toDate(created_at)              AS usage_date,
    quantile(0.50)(latency_ms)      AS p50_latency_ms,
    quantile(0.95)(latency_ms)      AS p95_latency_ms,
    quantile(0.99)(latency_ms)      AS p99_latency_ms,
    count()                         AS sample_count
FROM {{ source('secureprompt', 'latency_samples') }}
GROUP BY workspace_id, model, usage_date
