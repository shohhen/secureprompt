-- 007 (WS3-1 / WS3-2): captured raw request content moves OUT of
-- request_events and into its own table, opt-in, encrypted, independently
-- expirable.
--
-- WHY A SEPARATE TABLE AND NOT COLUMNS ON request_events
--
-- Migrations 004 and 005 put restored_response, raw_prompt and raw_response
-- directly on request_events. That inherits request_events' row-level
-- TTL created_at + INTERVAL 90 DAY, which has three consequences that make
-- per-workspace retention unimplementable there:
--
--   1. 90 days is a CEILING, not a default. A row TTL deletes the whole row,
--      so no workspace could ever retain captured content for longer than
--      the analytics row it hangs off, no matter what it configured. The
--      retention knob would silently lie above 90 days.
--   2. A row TTL is a single table-level constant expression. Expiring
--      workspace A's content after 7 days and workspace B's after 180 needs
--      a per-ROW expiry, and a per-row expiry that also has to keep the
--      surrounding analytics row alive means a column TTL. Column TTLs reset
--      the column to its type default during a merge, which is lazy, part-
--      local and unobservable to a caller. "Your prompts are gone after 30
--      days" would rest on a background merge having happened.
--   3. Deleting captured content on demand — a workspace turning capture
--      off, an erasure request, an incident — would be an ALTER TABLE
--      UPDATE mutation rewriting parts of the analytics table that also
--      backs the cost and latency dashboards.
--
-- Splitting the sensitive payload into its own table makes all three
-- disappear: TTL expires_at DELETE drops whole rows on a per-row expiry
-- computed from the WORKSPACE's retention_days at write time, retention is
-- free to be shorter OR longer than 90 days, and purging a workspace is one
-- DELETE against a table nothing else reads.
--
-- It also matches where this is going. Once capture is opt-in, off by default
-- and encrypted, the analytics row keeps the non-sensitive shape of a request
-- (counts, classes, actions) while the ciphertext blob lives here — so a
-- future leak report can aggregate over request_events and policy_events
-- without ever touching, or being able to touch, this table.
--
-- The columns on request_events are NOT dropped: historical rows written
-- before this migration still carry plaintext, and the audit read path still
-- reads them for those rows. Going forward the writer always sends NULL.
--
-- ENCRYPTION. raw_prompt / raw_response / restored_response hold whatever
-- AppState.kms produced, not plaintext. For the default FileKms that is
-- base64url(nonce || AES-256-GCM ciphertext) as UTF-8 bytes, for VaultKms it
-- is a Vault Transit "vault:v1:..." string. The `encrypted` flag exists so a
-- reader can tell an unencrypted historical row from a ciphertext one without
-- guessing from the bytes.
--
-- NOTE to migration authors: the worker splits this file on raw semicolons
-- after stripping line comments, so do not put a bare semicolon inside a
-- parenthetical on a comment line.

CREATE TABLE IF NOT EXISTS request_content_captures (
    request_id        UUID,
    workspace_id      UUID,
    created_at        DateTime,
    expires_at        DateTime,
    encrypted         Bool,
    raw_prompt        Nullable(String),
    raw_response      Nullable(String),
    restored_response Nullable(String)
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(created_at)
ORDER BY (workspace_id, request_id)
TTL expires_at DELETE;
