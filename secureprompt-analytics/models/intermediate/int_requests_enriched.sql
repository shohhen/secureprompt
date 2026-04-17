{{ config(
    materialized='table',
    engine='MergeTree()',
    order_by='(workspace_id, model, created_at)',
    partition_by='toYYYYMM(created_at)'
) }}

-- Intermediate layer: enriches request_events with computed fields.
-- workspace_id is denormalized (Phase 4); workspace name lookup is deferred to Phase 5 API.

SELECT
    request_id,
    workspace_id,
    provider,
    model,
    final_action,
    input_tokens,
    output_tokens,
    reasoning_tokens,
    cache_read_tokens,
    cache_write_tokens,
    estimated_usage,
    cost_usd,
    toDate(created_at)         AS usage_date,
    toStartOfHour(created_at)  AS usage_hour,
    created_at
FROM {{ ref('stg_request_events') }}
