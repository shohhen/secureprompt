{{ config(
    materialized='table',
    engine='MergeTree()',
    order_by='(workspace_id, model, usage_date)',
    partition_by='toYYYYMM(usage_date)'
) }}

-- mart_usage_daily: daily token + cost breakdown by workspace and model.
-- Primary mart for the /usage dashboard page.

SELECT
    workspace_id,
    model,
    usage_date,
    sum(input_tokens)        AS total_input_tokens,
    sum(output_tokens)       AS total_output_tokens,
    sum(reasoning_tokens)    AS total_reasoning_tokens,
    sum(cost_usd)            AS total_cost_usd,
    count()                  AS request_count,
    countIf(estimated_usage) AS estimated_request_count
FROM {{ ref('int_requests_enriched') }}
GROUP BY workspace_id, model, usage_date
