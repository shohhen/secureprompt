-- 002: Per-request actor + transport context for the audit detail page.
--
-- These columns are populated by the chat-completions handler at request time:
--   * user_id / api_key_id — who issued the request (api_keys.assigned_user_id)
--   * api_key_name         — display label for the key
--   * ip_address           — client IP (X-Forwarded-For-aware)
--   * user_agent           — raw User-Agent header (the dashboard parses it)
--   * redacted_prompt      — placeholder-safe prompt body (PII tokenized)
--
-- All Nullable so older rows written before this migration remain readable
-- and the writer can still emit a row when one of the inputs is missing
-- (e.g. unassigned legacy API keys → user_id stays NULL).

ALTER TABLE request_events
    ADD COLUMN IF NOT EXISTS user_id          Nullable(UUID),
    ADD COLUMN IF NOT EXISTS api_key_id       Nullable(UUID),
    ADD COLUMN IF NOT EXISTS api_key_name     Nullable(String),
    ADD COLUMN IF NOT EXISTS ip_address       Nullable(String),
    ADD COLUMN IF NOT EXISTS user_agent       Nullable(String),
    ADD COLUMN IF NOT EXISTS redacted_prompt  Nullable(String);
