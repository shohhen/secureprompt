-- Correct the record: migration 018's header states two things about this
-- table that are no longer true, and one of them is the thing an auditor
-- checks first.
--
-- Same shape and same reason as `037_correct_026_export_coverage_note.sql` and
-- `038_correct_030_and_033_residual_notes.sql`. `sqlx::migrate!` validates
-- checksums and `db/migrations.rs` says so in as many words -- "a checksum
-- divergence means a historical migration file was edited after being applied,
-- which `MIGRATOR.run` already refuses" -- so a correction is appended, never
-- backdated. 018's text was accurate on the day it was written.
--
-- ===========================================================================
-- CORRECTION 1 -- "NO ROW-LEVEL SECURITY" is false; 030 armed this table
-- ===========================================================================
--
-- `018_sidecar_failure_policy.sql:33-39` says, in full:
--
--   NO ROW-LEVEL SECURITY, matching `workspace_secure_mode` (007) and unlike
--   `workspace_budgets` (003). The RLS policy used elsewhere keys off
--   `current_setting('app.current_workspace_id')`, which the pooled gateway
--   connection does not set on the request path; adding FORCE RLS here would
--   make every read return zero rows, i.e. every workspace would silently
--   revert to 'block' regardless of what it chose. Both the repository read
--   and write are parameterised by the authenticated workspace_id.
--
-- Every clause of that is now wrong or misleading:
--
--   * "NO ROW-LEVEL SECURITY" -- `030_arm_rls_on_capture_and_purge_tables.sql`
--     ENABLEs and FORCEs RLS on `workspace_sidecar_policy` and creates the
--     standard `workspace_isolation` policy on it. The assertion below fails
--     this migration if that ever stops being true.
--
--   * "matching `workspace_secure_mode` (007)" -- 031 armed that table too, so
--     the analogy now points the other way: BOTH are armed.
--
--   * "the pooled gateway connection does not set [the GUC] on the request
--     path" -- it does. Every method of `db/sidecar_policy_repo.rs` runs
--     through `db::scope::begin_scoped`, which sets
--     `app.current_workspace_id` transaction-locally AND READS IT BACK, so an
--     unarmed transaction fails loudly instead of answering nothing.
--
--   * "adding FORCE RLS here would make every read return zero rows" -- true
--     of FORCE RLS *alone*, which is not what shipped. It is also precisely
--     why the read-back exists: without it, an unset GUC would silently
--     revert a workspace that chose `degrade_with_alert` back to `block`.
--     Fail-closed, so nothing pages, and the gateway quietly stops honouring
--     a choice its operator made.
--
--   * "Both the repository read and write are parameterised by the
--     authenticated workspace_id" -- true, and it was measured NOT to be
--     sufficient. From a NOSUPERUSER/NOBYPASSRLS role armed to another
--     workspace the table was readable and its rows overwritable across
--     tenants: binding `workspace_id` in those queries protected those
--     queries and nothing else. That measurement is what motivated 030.
--
-- WHY THIS MATTERS BEYOND TIDINESS: 018 is the file a reader opens to answer
-- "is this table tenant-isolated?". It answers "no, and here is why that is
-- fine". Both halves are now false, and the correction that exists today
-- lives in `src/db/sidecar_policy_repo.rs` -- a Rust module an auditor
-- reviewing the schema has no reason to open.
--
-- ===========================================================================
-- CORRECTION 2 -- the trailing GRANT is not what makes this table reachable
-- ===========================================================================
--
-- `018:50-51` ends with:
--
--   -- Re-execute role grants for the new table (same as migration 003).
--   GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public
--       TO secureprompt_app;
--
-- `GRANT ... ON ALL TABLES IN SCHEMA public` only grants on tables the
-- executing role owns or has GRANT OPTION on. Executed by a role that is not
-- the owner, Postgres emits `WARNING: no privileges were granted for "<table>"`
-- once per table and the statement still succeeds -- the same "looks like it
-- worked, did nothing" shape that made migration 017 a silent no-op. The
-- pattern is repeated in 002, 003, 021, 023, 025, 026 and 028.
--
-- It is harmless TODAY for a specific reason worth writing down rather than
-- relying on: the DB role split (034 + `secureprompt-api --migrate-only`)
-- makes the migration step run as the owner by construction, and
-- `db/migrations.rs` refuses to apply migrations from any role that lacks
-- CREATE on schema public. So the GRANT always runs as a role that can
-- actually grant. What makes FUTURE tables reachable is not this line at all,
-- it is 034's `ALTER DEFAULT PRIVILEGES`.
--
-- ===========================================================================
-- WHAT THIS MIGRATION CHANGES
-- ===========================================================================
--
-- No schema change. It (1) asserts the state 018's header denies, so the
-- correction cannot rot the way the original did, and (2) writes the
-- correction into the table's own catalog comment, so `\d+
-- workspace_sidecar_policy` and any `pg_dump` carry it to a reader who never
-- opens the migration directory. `COMMENT ON` is idempotent.

-- ---------------------------------------------------------------------------
-- ASSERTION -- the correction below must be true when it is written.
--
-- This is the falsifier for CORRECTION 1. Disarm RLS on this table (or drop
-- the `workspace_isolation` policy) and this migration RAISEs on any database
-- that has not yet applied it, rather than silently recording a comment that
-- says the opposite of the catalog. Same shape as 034 section 5.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    rls_enabled  BOOLEAN;
    rls_forced   BOOLEAN;
    policy_count INT;
BEGIN
    SELECT c.relrowsecurity, c.relforcerowsecurity
      INTO rls_enabled, rls_forced
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND c.relname = 'workspace_sidecar_policy';

    SELECT count(*)
      INTO policy_count
      FROM pg_policies
     WHERE schemaname = 'public'
       AND tablename  = 'workspace_sidecar_policy'
       AND policyname = 'workspace_isolation';

    IF rls_enabled IS DISTINCT FROM TRUE
       OR rls_forced IS DISTINCT FROM TRUE
       OR policy_count <> 1
    THEN
        RAISE EXCEPTION
            '039 refuses to record that workspace_sidecar_policy is RLS-armed '
            'while it is not: relrowsecurity=%, relforcerowsecurity=%, '
            'workspace_isolation policies=%. Migration 030 arms this table; if '
            'it was deliberately disarmed, migration 018''s original header is '
            'true again and THIS migration is the thing that must change.',
            rls_enabled, rls_forced, policy_count;
    END IF;
END $$;

COMMENT ON TABLE workspace_sidecar_policy IS
    'WS2-3. One row per workspace that has made an explicit choice about what '
    'happens when the ML sidecar produces no detection coverage: ''block'' '
    '(reject with 503 before forwarding) or ''degrade_with_alert''. Absence of '
    'a row means ''block'' -- see 018 for why there is no backfill. '
    'ROW-LEVEL SECURITY: ARMED. ENABLE + FORCE + the standard '
    '`workspace_isolation` policy, by migration 030. Migration 018''s header '
    'says this table has none and that arming it would break every read; both '
    'were true of FORCE RLS alone and neither is true of what shipped -- '
    '`db/sidecar_policy_repo.rs` goes through `db::scope::begin_scoped`, which '
    'sets `app.current_workspace_id` transaction-locally and reads it back, so '
    'an unarmed transaction fails loudly instead of answering zero rows. 018 '
    'cannot be edited because sqlx validates migration checksums.';
