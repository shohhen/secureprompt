-- WS1-P1D — arm row-level security on `workspace_secure_mode`, and record, in
-- the one place a future reader will look, why `users` is NOT armed with it.
--
-- ===========================================================================
-- PART 1 — `workspace_secure_mode` (migration 007)
-- ===========================================================================
--
-- WHAT WAS WRONG
--
-- 007 created this table with a `workspace_id` primary key and no row-level
-- security, and gave NO reason. The reason a reader finds instead is
-- circular: 018 (`workspace_sidecar_policy`) says "NO ROW-LEVEL SECURITY,
-- matching `workspace_secure_mode` (007)", and 021 (`workspace_raw_capture`)
-- says "matching `workspace_secure_mode` (007) and `workspace_sidecar_policy`
-- (018)". Three tables, one argument, and its root is an empty cell. Migration
-- 030 has since armed both 018's and 021's tables after measuring that they
-- were readable AND writable across tenants, which leaves 007 as the last
-- table in the schema whose only justification for having no policy is a
-- citation from two tables that no longer lack one.
--
-- 018's version of the argument was at least falsifiable, so it is worth
-- saying what was wrong with it: "adding FORCE RLS here would make every read
-- return zero rows, because the pooled gateway connection does not set
-- `app.current_workspace_id` on the request path". That is true of the
-- connection as it was, and it is an argument for setting the GUC, not for
-- leaving the table unarmed. 030 supplied the RLS and changed the repositories
-- to supply the `set_config` in the same commit. This migration does the same
-- for 007: `SecureModeRepository::get` moves onto `db::scope::begin_scoped` in
-- this commit.
--
-- MEASURED before this migration, from a NOSUPERUSER/NOBYPASSRLS role armed to
-- workspace A, with `policy_rules` as a positive control on the SAME
-- connection (the control was isolated, so the result below is a property of
-- this table and not of the connection):
--
--   * workspace A's scope read workspace B's secure-mode row and got back
--     `level = 'strict'`. `(relrowsecurity, relforcerowsecurity)` was
--     `(false, false)`.
--
-- WHY THIS TABLE IS WORTH ARMING. `workspace_secure_mode` is not a
-- preference; it is the redaction control. `enabled`, `level`,
-- `block_on_pii_detection`, `block_on_injection_detection` and
-- `redact_pii_in_responses` are read on the request path by
-- `pipeline::service` to decide whether PII is redacted and whether a
-- detection blocks the call. Cross-tenant READ discloses another tenant's
-- security posture — which is itself the reconnaissance step for choosing a
-- tenant to attack. Cross-tenant WRITE, which `USING`-supplies-`WITH CHECK`
-- also closes here, would let one tenant turn another tenant's redaction off.
--
-- THE SILENT ZERO, which is why the repository change ships with this file.
-- `SecureModeRepository::get` resolves "no row" to `SecureModeRow::default()`,
-- and that default is `enabled: false` — secure mode OFF. With the GUC unset,
-- `current_setting('app.current_workspace_id', true)` is NULL, the policy
-- predicate is NULL for every row, and the SELECT returns the EMPTY SET
-- without error. So on this table an unarmed read does not merely hide data:
-- it silently switches redaction off for a workspace that switched it on, and
-- `pipeline::service` would proceed with policy-only behaviour having logged
-- nothing. That is migration 017's failure mode pointed at the product's
-- central control, and it is the reason arming the table without moving the
-- read onto `begin_scoped` would have been worse than leaving it unarmed.
--
-- CORRECTION (MR5 C1 / MR6 F3). The paragraph above is right about the
-- HAZARD and was wrong about the REMEDY: moving the read onto `begin_scoped`
-- turns the silent zero into an `Err`, and nothing more. Until the fix that
-- carries this note, `pipeline::service` — the only consumer — resolved that
-- `Err` back to `SecureModeRow::default()`, i.e. to `enabled: false`, at HTTP
-- 200. The outcome was byte-for-byte the outcome described above; the only
-- difference was one `warn!` line, so "having logged nothing" became "having
-- logged something and done the same thing". The read-back is a NECESSARY
-- half of the control, not the whole of it. The caller now refuses the
-- request with 503 on any error from `SecureModeRepository::get`, which is
-- what makes this migration's argument true. Pinned by
-- `secureprompt-api/tests/secure_mode_read_failure.rs`.
--
-- IF THIS FILE'S CHECKSUM NOW MISMATCHES ON YOUR DATABASE. The note above was
-- added after 031 had been applied on developer databases, so `sqlx migrate
-- run` reports `migration 31 was previously applied but has been modified`.
-- Every statement below is idempotent (`ENABLE`/`FORCE ROW LEVEL SECURITY`
-- are no-ops when already set, the policy is created behind an
-- `IF NOT EXISTS` probe, and `GRANT` is repeatable), so the repair is:
--     DELETE FROM _sqlx_migrations WHERE version = 31;
-- and re-run. Same procedure, and same reason, as the note in 034.
--
-- WHY A NEW MIGRATION RATHER THAN A FIX TO 007. 007 has run on real
-- deployments. Editing it changes the recorded checksum without changing any
-- deployed database, so databases that have the defect would keep it and
-- databases that do not would fail to migrate.
--
-- ENABLE **AND** FORCE, matching 001, 025, 026, 028 and 030. ENABLE alone
-- exempts the table OWNER, and under the DB role-split on this project's
-- backlog the owner is the migration role — so ENABLE-only would leave the
-- policy off for exactly the role most likely to run an ad-hoc statement.
--
-- Stated with USING only: for a policy created without a command, PostgreSQL
-- uses the USING expression as the WITH CHECK expression too, so this governs
-- INSERT and UPDATE as well as SELECT.
-- ---------------------------------------------------------------------------
ALTER TABLE workspace_secure_mode ENABLE ROW LEVEL SECURITY;
ALTER TABLE workspace_secure_mode FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'workspace_secure_mode'
          AND policyname = 'workspace_isolation'
    ) THEN
        CREATE POLICY workspace_isolation ON workspace_secure_mode
            USING (workspace_id = current_setting('app.current_workspace_id', true)::uuid);
    END IF;
END $$;

-- GRANT ON ALL TABLES applies only to tables that exist when it runs — same
-- reason migrations 002, 003, 018, 021, 023, 025, 026, 028 and 030 repeat it.
-- Repeated here because RLS is a filter ON TOP of privileges, not a
-- replacement for them: a role with no GRANT sees nothing regardless of policy.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO secureprompt_app;

-- ===========================================================================
-- PART 2 — `users` IS DELIBERATELY NOT ARMED HERE. This is the reason.
-- ===========================================================================
--
-- This is a statement of a known, measured, OPEN defect. It is not a
-- justification for the defect, and it must not be cited the way 018 and 021
-- cited 007.
--
-- THE DEFECT, measured the same way as Part 1 and recorded in
-- `tests/migration_031_rls.rs`: from a NOSUPERUSER/NOBYPASSRLS role armed to
-- workspace A, with the `policy_rules` positive control isolated on the same
-- connection, workspace B's `users` row was returned in full — `email` and
-- `password_hash` together. `users` carries a NOT NULL `workspace_id` and
-- appears in no RLS arming list in any of the thirty migrations before this
-- one. The only tenancy control on the table holding every dashboard
-- credential is whatever `WHERE workspace_id = $n` each individual query
-- happens to carry.
--
-- WHY THE ONE-LINE FIX IS WRONG. `users` is the one table in this schema that
-- has a genuine unscoped read. Login looks a user up BY EMAIL, before any
-- workspace is known — `UserRepository::find_by_email_with_role`, called from
-- `POST /v1/auth/token` and from the OIDC callback. There is no
-- `app.current_workspace_id` to set at that moment; the lookup is what
-- DISCOVERS the workspace. Under the standard policy that query returns zero
-- rows, and a zero-row credential lookup is indistinguishable from a wrong
-- password. Arming this table naively does not fail loudly — it silently
-- turns every login in the deployment into an authentication failure.
--
-- Two further reads are unscoped BY DESIGN and cannot be workspace-scoped at
-- all, because a per-workspace answer is the wrong answer:
--
--   * `UserRepository::count_total_users` — deployment-wide seat count for
--     LICENSE ENFORCEMENT. Under the standard policy it counts one workspace,
--     so the seat cap is evaded by creating workspaces.
--   * `http/routes/internal.rs::build_signed_attestation` —
--     `SELECT COUNT(*) FROM users` for `active_seats` in the SIGNED
--     attestation, on an UNAUTHENTICATED route with no workspace in context
--     at all. Under the standard policy this reports 0 and the signature
--     makes the zero look authoritative. Same class as the `excluded_rows`
--     disclosure 030 protected on `retention_purge_audit`.
--
-- And roughly twenty further sites — `/v1/users`, `/v1/me/profile`, session
-- revocation, admin-audit actor attribution, the 2FA enroll/verify/challenge
-- state machine, and the `device_mac` write on the openai data plane — already
-- carry a correct `WHERE workspace_id = $n` but run on the BARE POOL with no
-- GUC set. RLS filters independently of the WHERE clause, so every one of them
-- becomes a silent zero the moment the table is armed, whatever their SQL says.
--
-- THE DESIGN THIS POINTS TO, and its open question. The standard PostgreSQL
-- answer for the pre-auth path is a narrow SECURITY DEFINER function — fixed
-- `search_path`, returning only the columns login needs — with the table armed
-- and direct SELECT revoked from the application role. The open question is
-- OWNERSHIP, and it is not answerable from a migration: FORCE ROW LEVEL
-- SECURITY applies to the table owner too, so a SECURITY DEFINER function is
-- filtered by the policy unless its owner holds BYPASSRLS. Today's compose
-- role is a SUPERUSER, so such a function would appear to work and would break
-- when the DB role-split lands. Which role owns the function, and whether it
-- carries BYPASSRLS, is a role-split decision.
--
-- Arming `users` therefore belongs WITH the role-split, as one change, and not
-- in this migration. Landing it here would arm a table whose ~22 access paths
-- are not ready for it, which is how 017 happened.
--
-- The tripwire for anyone who arms this table without doing that work is
-- `tests/migration_031_rls.rs::
-- users_is_not_armed_and_this_is_the_open_defect`, which fails the moment
-- `users` gains a policy and names the call sites that must move first.
