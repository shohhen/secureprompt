-- 004: Capture the AI response on request_events for the audit log.
--
-- The audit page previously showed only one row per request and only the
-- redacted user prompt. Operators couldn't see what was actually returned
-- to the client (post-placeholder-restoration), so a single prompt looked
-- like an isolated event with no answer trail.
--
-- We now persist the restored response (what we sent back to the client
-- after detokenizing placeholders), and the dashboard fans each request
-- out into two audit rows: a User row with redacted_prompt, and an AI row
-- with restored_response.
--
-- Nullable so older rows stay readable. NOTE to migration authors: the
-- worker splits this file on raw semicolons after stripping line comments,
-- so do not put a bare ; inside a parenthetical comment.

ALTER TABLE request_events
    ADD COLUMN IF NOT EXISTS restored_response Nullable(String);
