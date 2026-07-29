-- WS3-4 — proof-of-purge records for the `retention.purge` job.
--
-- WHY THIS TABLE EXISTS
--
-- Before WS3-4 the purge handler was literally
--     tracing::debug!("retention.purge — no-op stub (Phase 7 implementation)")
-- so the 24-hour `expires_at` on `token_vault_entries` was enforced by
-- nothing at all. "We delete your data after N days" was, in the strict
-- sense, unfalsifiable: there was no artifact anyone could point at, and no
-- artifact anyone could check.
--
-- WHAT A ROW HERE IS FOR
--
-- Each row is one scope of one purge run. The columns are chosen so that an
-- auditor can RE-DERIVE the claim rather than believe it:
--
--   * `cutoff` is the exact instant the run used as its policy boundary,
--     captured once at the top of the run and reused for the delete AND for
--     the post-check, so the two cannot disagree across a slow run.
--   * `rows_deleted` + `oldest_deleted` / `newest_deleted` are the counts and
--     the time RANGE the PRD asks for.
--   * `rows_remaining_past_cutoff` is the load-bearing one. After deleting,
--     the job re-runs the same "what still violates the policy" query and
--     records the answer. An auditor runs that query themselves against the
--     live store and compares. A job that lied about `rows_deleted` still has
--     to face a `rows_remaining_past_cutoff` that anyone can recompute.
--
-- A row is written even when `rows_deleted = 0`. That is deliberate: if the
-- job only recorded non-empty purges, "no row for Tuesday" would be
-- ambiguous between "nothing needed purging" and "the job never ran". With a
-- row every run, a GAP in the series is itself the signal.
--
-- NO FOREIGN KEY ON `workspace_id`, for the same reason `raw_capture_audit`
-- (021) has none: a referential constraint lets history mutate. ON DELETE
-- CASCADE would erase the evidence that a workspace's data was purged at the
-- moment the workspace is deleted — precisely when that evidence matters
-- most. `workspace_id` is NULL for scopes that are not per-workspace.
--
-- WHAT THIS TABLE DOES NOT PROVE — read `docs`/the WS3-4 report before
-- citing it at anyone. In short: it is self-attestation written by the same
-- process, into the same database, under a role that can also modify it; and
-- a logical DELETE is not an assurance that the bytes are irrecoverable.

CREATE TABLE retention_purge_audit (
    id                         UUID PRIMARY KEY,
    -- Groups every scope of a single run, so "what did the 04:00 run do"
    -- is one query rather than a timestamp-range guess.
    run_id                     UUID        NOT NULL,
    -- Which store was purged, e.g. 'token_vault_entries' or
    -- 'request_content_captures'. Free text rather than an enum so a new
    -- scope does not need a migration to become auditable.
    scope                      TEXT        NOT NULL,
    -- NULL for scopes that are not per-workspace.
    workspace_id               UUID,
    -- The policy boundary this scope was purged against.
    cutoff                     TIMESTAMPTZ NOT NULL,
    rows_deleted               BIGINT      NOT NULL,
    -- Time range of what was deleted. NULL when nothing was deleted, which
    -- is why they are nullable and `rows_deleted` is not.
    oldest_deleted             TIMESTAMPTZ,
    newest_deleted             TIMESTAMPTZ,
    -- Independently recomputable. Should be 0; a non-zero value is the job
    -- reporting its own incomplete run rather than hiding it.
    rows_remaining_past_cutoff BIGINT      NOT NULL,
    status                     TEXT        NOT NULL,
    error                      TEXT,
    started_at                 TIMESTAMPTZ NOT NULL,
    completed_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_retention_purge_audit_run
    ON retention_purge_audit(run_id);

CREATE INDEX idx_retention_purge_audit_scope_time
    ON retention_purge_audit(scope, completed_at DESC);

CREATE INDEX idx_retention_purge_audit_workspace
    ON retention_purge_audit(workspace_id, completed_at DESC);

-- GRANT ON ALL TABLES applies only to tables that exist when it runs — same
-- reason migrations 002, 003, 018 and 021 repeat it.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO secureprompt_app;
