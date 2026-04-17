{{ config(materialized='view') }}

-- Staging layer: 1:1 with request_events source table
-- Coalesces nullable token columns to 0 for downstream aggregation.
-- IMPORTANT: workspace_id and request_id remain as UUID strings — do NOT cast.

SELECT
    request_id,
    workspace_id,
    provider,
    model,
    final_action,
    coalesce(input_tokens, 0)       AS input_tokens,
    coalesce(output_tokens, 0)      AS output_tokens,
    coalesce(reasoning_tokens, 0)   AS reasoning_tokens,
    coalesce(cache_read_tokens, 0)  AS cache_read_tokens,
    coalesce(cache_write_tokens, 0) AS cache_write_tokens,
    estimated_usage,
    cost_usd,
    created_at
FROM {{ source('secureprompt', 'request_events') }}
