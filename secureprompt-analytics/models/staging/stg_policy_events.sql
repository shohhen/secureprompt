{{ config(materialized='view') }}

-- Staging layer: 1:1 with policy_events source table

SELECT
    request_id,
    workspace_id,
    rule_id,
    rule_name,
    action,
    dry_run,
    created_at
FROM {{ source('secureprompt', 'policy_events') }}
