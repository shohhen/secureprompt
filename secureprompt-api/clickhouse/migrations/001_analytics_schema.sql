-- Phase 4: Analytics schema migration
-- Applied by secureprompt-worker at startup via _schema_migrations table.

-- 1. Migration tracking (must come first — worker checks this before applying)
CREATE TABLE IF NOT EXISTS _schema_migrations (
    version     String,
    applied_at  DateTime DEFAULT now()
) ENGINE = MergeTree()
ORDER BY version;

-- 2. dbt single-run lock (D-10)
-- ReplacingMergeTree deduplicates on lock_key — INSERT-then-check pattern.
CREATE TABLE IF NOT EXISTS _dbt_lock (
    lock_key   String,
    locked_at  DateTime DEFAULT now(),
    locked_by  String
) ENGINE = ReplacingMergeTree(locked_at)
ORDER BY lock_key;

-- 3. Pre-create analytics databases with Atomic engine (required for dbt +database override, D-07 / Pitfall 3)
CREATE DATABASE IF NOT EXISTS secureprompt_staging ENGINE = Atomic;
CREATE DATABASE IF NOT EXISTS secureprompt_intermediate ENGINE = Atomic;
CREATE DATABASE IF NOT EXISTS secureprompt_marts ENGINE = Atomic;

-- 4. request_events (MergeTree, TTL 90 days, D-04)
CREATE TABLE IF NOT EXISTS request_events (
    request_id          UUID,
    workspace_id        UUID,
    provider            String,
    model               String,
    final_action        String,
    input_tokens        Nullable(UInt32),
    output_tokens       Nullable(UInt32),
    reasoning_tokens    Nullable(UInt32),
    cache_read_tokens   Nullable(UInt32),
    cache_write_tokens  Nullable(UInt32),
    estimated_usage     Bool,
    cost_usd            Float64,
    created_at          DateTime
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(created_at)
ORDER BY (workspace_id, created_at, request_id)
TTL created_at + INTERVAL 90 DAY;

-- 5. policy_events (MergeTree, TTL 90 days, D-04)
CREATE TABLE IF NOT EXISTS policy_events (
    request_id   UUID,
    workspace_id UUID,
    rule_id      UUID,
    rule_name    String,
    action       String,
    dry_run      Bool,
    created_at   DateTime
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(created_at)
ORDER BY (workspace_id, created_at, request_id)
TTL created_at + INTERVAL 90 DAY;

-- 6. token_usage (SummingMergeTree, TTL 365 days, D-04)
-- Query pattern: always GROUP BY workspace_id, model, date with sum() -- never SELECT * (Pitfall 5)
CREATE TABLE IF NOT EXISTS token_usage (
    workspace_id  UUID,
    model         String,
    date          Date,
    input_tokens  UInt64,
    output_tokens UInt64,
    cost_usd      Float64
) ENGINE = SummingMergeTree((input_tokens, output_tokens, cost_usd))
PARTITION BY toYYYYMM(date)
ORDER BY (workspace_id, model, date)
TTL date + INTERVAL 365 DAY;

-- 7. latency_samples (MergeTree, TTL 30 days, D-04)
CREATE TABLE IF NOT EXISTS latency_samples (
    request_id   UUID,
    workspace_id UUID,
    model        String,
    latency_ms   UInt32,
    created_at   DateTime
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(created_at)
ORDER BY (workspace_id, model, created_at)
TTL created_at + INTERVAL 30 DAY;

-- 8. mv_hourly_cost target table (AggregatingMergeTree, D-05)
CREATE TABLE IF NOT EXISTS mv_hourly_cost_agg (
    workspace_id UUID,
    model        String,
    hour         DateTime,
    cost_usd_sum AggregateFunction(sum, Float64)
) ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (workspace_id, model, hour);

-- 9. mv_hourly_cost materialized view (D-05)
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_hourly_cost
TO mv_hourly_cost_agg AS
SELECT
    workspace_id,
    model,
    toStartOfHour(created_at) AS hour,
    sumState(cost_usd)        AS cost_usd_sum
FROM request_events
GROUP BY workspace_id, model, hour;

-- 10. mv_p95_latency target table (AggregatingMergeTree, D-05)
CREATE TABLE IF NOT EXISTS mv_p95_latency_agg (
    workspace_id  UUID,
    model         String,
    hour          DateTime,
    latency_p95   AggregateFunction(quantile(0.95), UInt32)
) ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (workspace_id, model, hour);

-- 11. mv_p95_latency materialized view (D-05)
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_p95_latency
TO mv_p95_latency_agg AS
SELECT
    workspace_id,
    model,
    toStartOfHour(created_at)         AS hour,
    quantileState(0.95)(latency_ms)   AS latency_p95
FROM latency_samples
GROUP BY workspace_id, model, hour;
