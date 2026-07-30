-- 008 (WS3-6): per-request, per-CLASS detection counts.
--
-- WHY THIS TABLE HAS TO EXIST AT ALL
--
-- The shadow-mode leak report — "for a pilot window, show what WOULD have
-- leaked to a cloud LLM, by entity class, by destination model" — had no
-- source. Nothing in the product persisted a per-class count:
--
--   * `policy_events` is RULE-level (rule_id, rule_name, action, dry_run). It
--     answers "which rule fired", not "how many PINFLs were in the prompt",
--     and a workspace with no rules produces no rows at all while its
--     detections are still redacted by the default-redact safety net.
--   * `request_events` holds ONE row per request with no detection breakdown.
--   * The tokenize endpoint computes an `entity_counts` map
--     (`http/routes/dashboard/secure_mode.rs`) purely to put in its HTTP
--     RESPONSE. It is never written anywhere.
--
-- So the report needed a source, and the source has to be recorded on the
-- request path, from the SAME detection set the pipeline acted on. A report
-- that re-scanned stored text later would (a) require storing the text, which
-- WS3-1 exists to stop, and (b) measure a different model version than the one
-- that actually served the request.
--
-- WHY IT NEEDS NO OPT-IN GATE (unlike migration 007)
--
-- 007 is opt-in, encrypted and off by default because it stores CONTENT. This
-- table stores a CLASS NAME and an INTEGER. `PINFL` is a type, not a value:
-- knowing a prompt contained three PINFLs discloses nothing about whose. The
-- class names are not free text either — `RequestEvent::record_detections`
-- maps every incoming class through a compile-time allowlist
-- (`analytics::detection_counts::CANONICAL_CLASSES`) and buckets anything
-- unrecognised as the literal `other`, so the only strings that can ever reach
-- this column are string literals from the SecurePrompt binary.
--
-- That last part is load-bearing and was NOT true of the obvious
-- implementation. A detection's `class` for ML-found entities is
-- `MlDetection::entity_type`, which is `String` deserialised from the ML
-- sidecar's JSON — it is a network value, not a compile-time constant. Writing
-- it through verbatim would mean a compromised, misconfigured or simply
-- retrained sidecar could put arbitrary bytes into a table this migration
-- advertises as content-free. The allowlist is what makes the claim in the
-- paragraph above a property of the code rather than a hope about the model.
--
-- TTL: 90 DAYS, DELIBERATELY THE SAME AS `request_events`
--
-- WS3-5 found that `mv_hourly_cost_agg`, `mv_p95_latency_agg` and the four dbt
-- marts carry NO TTL, so aggregates of a workspace's traffic outlive the
-- 90-day window on the rows they were derived from — permanently. This table
-- is derived from the same requests as `request_events` and expires on exactly
-- the same schedule, so "everything about a request is gone after 90 days"
-- stays true with this table added. Do not raise it to make a longer pilot
-- window reportable; run the report before the window expires, or export it.
--
-- DENORMALISED, NOT JOINED
--
-- `model`, `user_id` and `api_key_name` are copied onto every row rather than
-- joined from `request_events` on `request_id`. Three reasons:
--   1. The report is then a single-table GROUP BY. A join would silently DROP
--      whole classes from a compliance report whenever the `request_events`
--      row was lost — and the analytics writer can lose one independently
--      (see `clickhouse_writer.rs`, which retries once and then abandons).
--   2. Both tables expire on the same 90-day TTL by construction, so the join
--      can never half-expire.
--   3. None of the three is new data: all three already exist in the clear on
--      `request_events`. This adds no data class, which is why the
--      `/v1/data-inventory` entry for it can honestly say "derived metadata".
--
-- `api_key_name` is operator-chosen free text and may name a person ("Anvar's
-- laptop"). It is NOT detected PII and it is not what the no-content rule
-- covers — but it is personal data for an erasure request, and the inventory
-- entry says so.
--
-- ROWS ARE ONLY WRITTEN WHEN SOMETHING WAS DETECTED. A request with no
-- detections produces no row here, so `count()` on this table is not a request
-- count. The report takes its denominator from `request_events`.
--
-- NOTE to migration authors: the worker splits this file on raw semicolons
-- after stripping line comments, so do not put a bare semicolon inside a
-- parenthetical on a comment line.

CREATE TABLE IF NOT EXISTS detection_class_counts (
    request_id   UUID,
    workspace_id UUID,
    created_at   DateTime,
    model        String,
    user_id      Nullable(UUID),
    api_key_name Nullable(String),
    entity_class String,
    entity_count UInt32
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(created_at)
ORDER BY (workspace_id, created_at, entity_class)
TTL created_at + INTERVAL 90 DAY DELETE;
