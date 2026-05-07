-- 003: Time-to-first-byte (TTFT) on latency_samples.
--
-- Captured by provider adapters at the moment upstream response headers
-- arrive (i.e. before the body is read). `latency_ms` remains the total
-- end-to-end time including the gateway's own pre-flight work
-- (policy + redaction + provider invocation setup), so:
--   gateway_overhead_ms = latency_ms - ttft_ms
-- when both are present.
--
-- Nullable so older rows written before this migration stay readable and
-- the writer can emit a row even when the adapter cannot measure TTFT
-- (debug mode and embeddings served by stub adapters).
-- NOTE: the worker splits this file on raw semicolons, so do not use a
-- bare `;` inside SQL comments — it'll truncate the statement and the
-- ALTER will fail with a syntax error on the orphaned tail.

ALTER TABLE latency_samples
    ADD COLUMN IF NOT EXISTS ttft_ms Nullable(UInt32);
