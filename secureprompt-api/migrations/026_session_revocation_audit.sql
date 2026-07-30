-- WS4-3 — the record of who cut off whose access.
--
-- WHY THIS TABLE EXISTS
--
-- Before WS4-3 an administrator had no way to terminate a session. The only
-- lever was waiting for the access token to expire, and the refresh chain
-- behind it kept minting replacements for as long as it was valid. A lost
-- laptop, a departing employee and a token suspected stolen all had the same
-- remedy, which was none.
--
-- `DELETE /v1/users/{id}/sessions` is that lever, and this table is the other
-- half of the acceptance criterion: the action is audited. One row per
-- accepted revocation, written in the SAME TRANSACTION as the refresh-token
-- revocation it records, so "the session was cut off" and "somebody is on the
-- hook for cutting it off" commit together or not at all.
--
-- WHY NOT `request_events`, WHICH `audit.export` ALREADY SHIPS TO AUDITORS
--
-- This is the trade WS4-3 had to make deliberately, so it is written down.
-- `request_events` is the table WS4-1's `audit.export` reads, so a row there
-- would reach an auditor with a signature over it. It is the wrong home for
-- three reasons, each of which would make the record worse:
--
--   1. It is the DATA-PLANE request log. Every column that gives a row there
--      meaning — provider, model, input/output tokens, cost_usd,
--      final_action, floor_only, engines — describes an LLM call. A session
--      revocation is not one. Writing it there means fabricating those values
--      or writing empty strings and zeros, and either way the row becomes
--      visible to `/v1/requests`, `/v1/analytics/*`, the budget counters, the
--      leak report and the dbt marts as a request that never happened.
--   2. `request_events` carries a NINETY-DAY ClickHouse TTL. An audit record
--      of who terminated whose access that evaporates after 90 days is what
--      `raw_capture_audit` (021) refuses in its own header: an audit trail
--      with a retention window is an audit trail with a deadline.
--   3. Writes to it are batched through the analytics writer and are
--      best-effort. A dropped batch loses the record silently. The claim
--      "the action is audited" has to commit with the action.
--
-- CONSEQUENCE, STATED RATHER THAN HIDDEN: revocation events are therefore NOT
-- carried by `audit.export`. They are reachable through `GET
-- /v1/data-inventory`, which declares this table, and through Postgres. That
-- is a real gap in what a signed export contains, and it is disclosed here
-- and in the WS4-3 report rather than discovered later.
--
-- WHAT IS DELIBERATELY *NOT* RECORDED
--
-- No `ip_address`, no `user_agent`, and no free-text reason. WS4-1 disclosed
-- that `audit_export_pages` copies actor columns verbatim into an
-- indefinitely-retained table, and the same discipline applies to a table
-- that is itself never purged: nothing goes in here that we would not want
-- kept forever. "Who revoked whose access, and when" is fully answered by the
-- columns below. An IP address and a User-Agent describe the actor's device
-- rather than the action, and a free-text reason is an unbounded channel for
-- exactly the personal data ("lost his laptop at the clinic") that a
-- never-purged table must not accumulate. The trade is explicit: this table
-- answers WHO, WHAT and WHEN forever, and does not attempt WHY.
--
-- NO FOREIGN KEYS, for the reason `raw_capture_audit` (021),
-- `retention_purge_audit` (023) and `audit_exports` (025) all give: a
-- referential constraint lets history mutate. ON DELETE CASCADE would erase
-- the evidence that an account's sessions were terminated at the moment the
-- account is deleted, which is precisely when that evidence matters. The
-- actor and the target are therefore recorded as identifiers PLUS the email
-- and role as they read at the time, and none of it is reachable from a later
-- DELETE.

CREATE TABLE session_revocation_audit (
    id                     UUID PRIMARY KEY,
    workspace_id           UUID        NOT NULL,
    -- Who performed it. `actor_user_id` comes from the authenticated context,
    -- never from a request body. `actor_email` / `actor_role` are
    -- denormalised copies as at the time of the action.
    actor_user_id          UUID        NOT NULL,
    actor_email            TEXT,
    actor_role             TEXT        NOT NULL,
    -- Whose sessions were terminated. Equal to the actor on a self-revocation,
    -- which is allowed and needs no separate column to be legible.
    target_user_id         UUID        NOT NULL,
    target_email           TEXT,
    target_role            TEXT        NOT NULL,
    -- The revocation watermark, in UNIX seconds: every access token for
    -- `target_user_id` whose `iat` is <= this value is refused by
    -- `jwt_auth::require`. Recorded so an auditor can say exactly which
    -- tokens this row killed without reading Redis, which has since expired
    -- the key.
    revoked_before_unix    BIGINT      NOT NULL,
    -- How many active `refresh_tokens` rows this revocation closed. The
    -- EFFECT, not the intent — a revocation that killed nothing is a
    -- different fact from one that killed four sessions, and both are worth
    -- being able to tell apart later.
    refresh_tokens_revoked BIGINT      NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_session_revocation_audit_workspace
    ON session_revocation_audit(workspace_id, created_at DESC);
CREATE INDEX idx_session_revocation_audit_target
    ON session_revocation_audit(target_user_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- ROW-LEVEL SECURITY, same shape as migration 025.
--
-- The API sets `app.current_workspace_id` inside its transaction before
-- touching this table. That is not bookkeeping: `current_setting(..., true)`
-- yields NULL when the GUC is unset, the policy predicate is then NULL for
-- every row, and a SELECT returns the EMPTY SET while an INSERT is REJECTED.
-- The compose role is a SUPERUSER today and bypasses all of it, so no
-- `#[sqlx::test]` can observe a mistake here — which is why
-- `tests/dashboard/session_revocation_tests.rs` opens its own
-- NOSUPERUSER/NOBYPASSRLS connection to assert the policy is armed.
--
-- The policy is stated with USING only. For a policy created without a
-- command, PostgreSQL uses the USING expression as the WITH CHECK expression
-- too, so this governs INSERT as well as SELECT.
-- ---------------------------------------------------------------------------
DO $$ DECLARE t TEXT;
BEGIN
    FOR t IN SELECT unnest(ARRAY['session_revocation_audit'])
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);

        IF NOT EXISTS (
            SELECT 1
            FROM pg_policies
            WHERE schemaname = 'public'
              AND tablename = t
              AND policyname = 'workspace_isolation'
        ) THEN
            EXECUTE format(
                'CREATE POLICY workspace_isolation ON %I USING (workspace_id = current_setting(''app.current_workspace_id'', true)::uuid)',
                t
            );
        END IF;
    END LOOP;
END $$;

-- GRANT ON ALL TABLES applies only to tables that exist when it runs — same
-- reason migrations 002, 003, 018, 021, 023 and 025 repeat it.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO secureprompt_app;
