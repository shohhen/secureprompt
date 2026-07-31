-- WS1-P1C — arm row-level security on the four tables that never had it.
--
-- WHAT WAS WRONG
--
-- RLS in this schema is armed by an `EXECUTE format('ALTER TABLE %I
-- ENABLE/FORCE ROW LEVEL SECURITY', t)` loop over an explicit table list.
-- Migrations 001, 002, 003, 025, 026 and 028 each arm the tables they create.
-- Migrations 018, 021 and 023 contain no such loop, so these four tables
-- carried a `workspace_id` column and NO row-level security of any kind:
--
--     workspace_sidecar_policy     (018)
--     workspace_raw_capture        (021)
--     raw_capture_audit            (021)
--     retention_purge_audit        (023)
--
-- Both migration headers argue the omission is deliberate. 018's reasoning is
-- that FORCE RLS alone would make every read return zero rows — true, and the
-- half of the picture `src/db/sidecar_policy_repo.rs` already corrects: the
-- codebase's actual pattern is RLS PLUS `set_config` on the same transaction.
-- This migration supplies the RLS; the repositories were changed in the same
-- commit to supply the `set_config`.
--
-- MEASURED before this migration, from a NOSUPERUSER/NOBYPASSRLS role armed to
-- workspace A, with `policy_rules` as a positive control on the same
-- connection (it WAS isolated, so the results below are properties of these
-- tables and not of the connection):
--
--   * `raw_capture_audit`: cross-tenant INSERT attributed to workspace B was
--     accepted, `rows_affected: 1`. A forged audit row.
--   * `retention_purge_audit`: cross-tenant INSERT for workspace B accepted,
--     `rows_affected: 1`. A forged proof-of-purge.
--   * `workspace_raw_capture`: cross-tenant UPDATE affected 1 row and
--     `enabled` read back `true` — one tenant could switch PLAINTEXT PROMPT
--     CAPTURE ON for another tenant.
--   * reads: workspace A's scope read workspace B's rows in all four tables,
--     including the actor email on B's `raw_capture_audit` row.
--
-- `raw_capture_audit` is a SOURCE of the signed compliance export
-- (`secureprompt-worker/src/tasks/audit_export.rs::fetch_control_rows`), whose
-- comment described it as "the RLS-armed table". It was not armed. The only
-- thing keeping one tenant's audit rows out of another tenant's
-- cryptographically signed attestation was that query's own
-- `WHERE workspace_id = $1`.
--
-- WHY A NEW MIGRATION RATHER THAN A FIX TO 018/021/023
--
-- Those three have run on real deployments. Editing them changes the recorded
-- checksum without changing any deployed database, so the databases that have
-- the defect would keep it and the ones that do not would fail to migrate.
--
-- ENABLE **AND** FORCE, on every table below. ENABLE alone exempts the table
-- OWNER, and under the DB role-split on this project's backlog the owner is
-- the migration role — so ENABLE-only would leave the policy off for exactly
-- the role most likely to run an ad-hoc statement.
--
-- Stated with USING only: for a policy created without a command, PostgreSQL
-- uses the USING expression as the WITH CHECK expression too, so this governs
-- INSERT and UPDATE as well as SELECT. Same as 025, 026 and 028.
--
-- The compose role is a SUPERUSER today and bypasses all of this, so no
-- `#[sqlx::test]` can observe a mistake here — which is why
-- `tests/migration_017_023_rls.rs` opens its own NOSUPERUSER/NOBYPASSRLS
-- connection and asserts the role's powerlessness on the wire first.
-- ---------------------------------------------------------------------------
DO $$ DECLARE t TEXT;
BEGIN
    FOR t IN SELECT unnest(ARRAY[
        'workspace_sidecar_policy',
        'workspace_raw_capture',
        'raw_capture_audit'
    ])
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

-- ---------------------------------------------------------------------------
-- `retention_purge_audit` GETS A DIFFERENT POLICY, DELIBERATELY.
--
-- Its `workspace_id` is NULLABLE by design: the token vault and the session
-- device-context scrub are purged globally, not per workspace, and 023's
-- header says so. The standard predicate above is
-- `workspace_id = current_setting(...)::uuid`, which for a NULL
-- `workspace_id` evaluates to NULL — never true. Giving this table the
-- standard policy would therefore:
--
--   1. REJECT the purge job's global rows on write (loud — measured: `new row
--      violates row-level security policy for table "retention_purge_audit"`),
--      silently discarding half the purge audit trail if the job's error
--      handler swallows it, which it does: `run()` logs
--      `retention_purge_audit_write_failed` and continues; and
--   2. HIDE the global rows on read (silent). That one matters most:
--      `fetch_control_rows` counts them with
--      `WHERE workspace_id IS NULL` and publishes the number in the signed
--      manifest as `excluded_rows`, so an auditor can see how many records
--      were deliberately left out. Under the standard policy that count
--      becomes 0 and the disclosure becomes a lie.
--
-- So the predicate admits NULL. The policy is NAMED differently from the other
-- three on purpose: anyone grepping `workspace_isolation` to learn what a
-- tenant can reach must not be shown a predicate that is not that one.
--
-- WHAT THIS POLICY DOES NOT DO. Because USING supplies WITH CHECK, a tenant
-- holding a connection to this database can still INSERT a row with
-- `workspace_id IS NULL` — i.e. forge a GLOBAL purge record. It cannot forge
-- or read ANOTHER TENANT's record, which is the cross-tenant boundary this
-- migration exists to draw, and the export never exports global rows — it only
-- counts them. Narrowing that last gap needs the DB role-split (a writer role
-- for the worker, a reader role for the API), which is a separate backlog item
-- and cannot be done from a migration alone.
--
-- The tripwire for anyone who later "tidies" this into one uniform policy is
-- `tests/migration_017_023_rls.rs::
-- retention_purge_audit_cannot_adopt_the_standard_workspace_policy`.
-- ---------------------------------------------------------------------------
ALTER TABLE retention_purge_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE retention_purge_audit FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'retention_purge_audit'
          AND policyname = 'workspace_isolation_or_global'
    ) THEN
        CREATE POLICY workspace_isolation_or_global ON retention_purge_audit
            USING (
                workspace_id IS NULL
                OR workspace_id = current_setting('app.current_workspace_id', true)::uuid
            );
    END IF;
END $$;

-- GRANT ON ALL TABLES applies only to tables that exist when it runs — same
-- reason migrations 002, 003, 018, 021, 023, 025, 026 and 028 repeat it.
-- Repeated here because RLS is a filter ON TOP of privileges, not a
-- replacement for them: a role with no GRANT sees nothing regardless of policy.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO secureprompt_app;
