-- WS3-1 / WS3-2 — per-workspace opt-in for storing RAW request content, and
-- the retention window for whatever it stores.
--
-- THE DEFECT THIS CLOSES
-- `pipeline/service.rs` wrote `raw_prompt` (the un-redacted user message),
-- `raw_response` (the un-restored upstream reply) and `restored_response`
-- (the reply with PII put back) into ClickHouse `request_events` in
-- PLAINTEXT, on EVERY request, UNCONDITIONALLY, under a fixed 90-day TTL,
-- with no opt-out anywhere: `grep -rniE "capture_raw|store_raw|raw_capture"`
-- returned zero hits across the whole repository. SecurePrompt is sold on
-- "your prompts never leave your building"; it was keeping a plaintext copy
-- of every prompt and every answer in its own warehouse.
--
-- Shape deliberately mirrors migration 007's `workspace_secure_mode` and
-- 018's `workspace_sidecar_policy`: one row per workspace, PK = workspace_id,
-- ON DELETE CASCADE, upserted on PUT, and the repository returns the default
-- when no row exists.
--
-- EXISTING WORKSPACES ARE NOT BACKFILLED, BY DESIGN. There is no
-- INSERT ... SELECT here, for the same two reasons migration 018 gives:
--   1. Safe by ABSENCE. `RawCaptureRepository::get_effective` returns
--      "capture disabled, 30-day retention" when no row exists, so there is
--      no window — not at migration time, not at signup, not in a test
--      fixture — in which a workspace captures raw content without somebody
--      having explicitly asked for it.
--   2. A backfilled row is indistinguishable from an operator's decision.
--      Every row in this table represents a real, attributable choice.
--
-- NO ROW-LEVEL SECURITY, matching `workspace_secure_mode` (007) and
-- `workspace_sidecar_policy` (018). See the header of
-- `src/db/raw_capture_repo.rs` for the honest version of that reasoning —
-- it lives there rather than here so it can be revised without changing a
-- migration checksum. Both the read and the write below bind the
-- authenticated workspace_id explicitly.

CREATE TABLE workspace_raw_capture (
    workspace_id   UUID PRIMARY KEY REFERENCES workspaces(id) ON DELETE CASCADE,
    -- OFF. This is the whole point of the migration.
    enabled        BOOL NOT NULL DEFAULT false,
    -- WS3-2. Days of retention for captured content, counted from the
    -- request. Default 30, independent of the 90-day row TTL on
    -- `request_events` because captured content lives in its own ClickHouse
    -- table with its own TTL.
    retention_days INT  NOT NULL DEFAULT 30
        CHECK (retention_days >= 1 AND retention_days <= 3650),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Who last changed it. Deliberately NOT a foreign key to `users` — see
    -- the note on `raw_capture_audit.actor_user_id` below. The immutable
    -- trail is that table.
    updated_by     UUID
);

CREATE INDEX idx_workspace_raw_capture ON workspace_raw_capture(workspace_id);

-- WS3-1 acceptance criterion: "enabling requires admin role AND the enabling
-- action is itself audited".
--
-- Append-only. One row per accepted change, carrying both the before and the
-- after state so a reviewer can reconstruct when capture was on without
-- diffing backups.
--
-- NO FOREIGN KEY ON `actor_user_id`, AND `actor_email` IS DENORMALISED.
-- Both are deliberate and they are the same decision. A referential
-- constraint on an audit table lets history mutate: ON DELETE SET NULL
-- erases the actor when the account is closed, and ON DELETE CASCADE erases
-- the record entirely — in either case deleting a user rewrites the evidence
-- that they switched plaintext prompt retention on. The actor is therefore
-- recorded as an identifier PLUS the email as it read at the time, and
-- neither is reachable from a later DELETE.
CREATE TABLE raw_capture_audit (
    id                    UUID PRIMARY KEY,
    workspace_id          UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    actor_user_id         UUID,
    actor_email           TEXT,
    enabled_before        BOOL NOT NULL,
    enabled_after         BOOL NOT NULL,
    retention_days_before INT  NOT NULL,
    retention_days_after  INT  NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_raw_capture_audit_workspace
    ON raw_capture_audit(workspace_id, created_at DESC);

-- Re-execute role grants for the new tables (GRANT ON ALL TABLES applies only
-- to tables that exist at the time it runs — same reason migrations 002, 003
-- and 018 repeat it).
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO secureprompt_app;
