{{ config(
    materialized='table',
    engine='MergeTree()',
    order_by='(workspace_id, toDate(created_at), rule_id)',
    partition_by='toYYYYMM(created_at)'
) }}

-- mart_policy_violations: policy rule matches grouped by rule and day.
-- Used by /policy violations stream in the dashboard.

SELECT
    workspace_id,
    rule_id,
    rule_name,
    action,
    toDate(created_at)   AS violation_date,
    count()              AS violation_count,
    countIf(dry_run)     AS dry_run_count,
    countIf(NOT dry_run) AS enforced_count
FROM {{ ref('stg_policy_events') }}
GROUP BY workspace_id, rule_id, rule_name, action, violation_date
