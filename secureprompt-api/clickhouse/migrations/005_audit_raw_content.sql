-- 005: Capture raw user input + raw upstream response on request_events.
--
-- Why we keep both:
--   * `redacted_prompt` (migration 002): the latest user message
--     post-tokenization — what was forwarded upstream (or what we DID
--     check). Safe to display widely.
--   * `raw_prompt` (this migration): the latest user message pre-
--     tokenization. Stored so the audit detail page can show the
--     reviewer the raw text alongside the redaction. Subject to the
--     same 90-day TTL as the rest of `request_events`; do not surface
--     it on read paths that don't already require admin/owner access.
--   * `restored_response` (migration 004): what we returned to the
--     client after placeholder restoration.
--   * `raw_response` (this migration): what the upstream provider
--     actually returned, before any restoration. Useful when debugging
--     why a placeholder leaked or got mangled.
--
-- Both are Nullable so historical rows stay readable. Worker splits this
-- file on raw `;` after stripping comments — no bare `;` inside any
-- parenthetical on a comment line.

ALTER TABLE request_events
    ADD COLUMN IF NOT EXISTS raw_prompt    Nullable(String),
    ADD COLUMN IF NOT EXISTS raw_response  Nullable(String);
