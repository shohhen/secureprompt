-- WS1-P1F — make an UNSCOPED read of an armed table INVISIBLE rather than an
-- ERROR, on every table that is armed, not just `refresh_tokens`.
--
-- ===========================================================================
-- THE DEFECT
-- ===========================================================================
--
-- `set_config('app.current_workspace_id', …, true)` is TRANSACTION-LOCAL, and
-- when that transaction ends the setting does NOT go back to unset. It reverts
-- to the EMPTY STRING and stays that way for the life of the connection.
-- `current_setting(…, true)` therefore returns `''`, not NULL, and `''::uuid`
-- is not a cast that yields NULL: it raises.
--
-- MEASURED, PostgreSQL 16.14, one session as a NOSUPERUSER/NOBYPASSRLS role:
--
--   SELECT current_setting('app.current_workspace_id', true) IS NULL;  -- t
--   BEGIN;
--     SELECT set_config('app.current_workspace_id', '<uuid>', true);
--   COMMIT;
--   SELECT current_setting('app.current_workspace_id', true) IS NULL;  -- f
--   SELECT '['||current_setting('app.current_workspace_id', true)||']'; -- []
--   SELECT count(*) FROM admin_audit;
--     ERROR:  22P02 invalid input syntax for type uuid: ""
--
-- Migration 032 recorded exactly this and fixed `refresh_tokens` with `NULLIF`,
-- saying in its own header that "the same landmine is in every other
-- `workspace_isolation` policy in this schema". This file is that sweep.
--
-- ===========================================================================
-- WHY IT IS WORSE THAN A WRONG ERROR MESSAGE
-- ===========================================================================
--
-- Connections are POOLED, so an unscoped statement on an armed table has TWO
-- outcomes and pool checkout decides which:
--
--   * on a connection that has NEVER served a scoped transaction → the GUC is
--     NULL, the predicate is NULL for every row, the answer is the empty set
--     and nothing is raised;
--   * on a connection that HAS → 22P02.
--
-- One defect, two faces, neither of them the invisibility `001_init.sql` wrote
-- `workspace_isolation` to provide. It is also not theoretical:
-- `cargo test -p secureprompt-api --test admin_audit` under
-- `secureprompt_runner` produced exactly 13 occurrences of
-- `22P02 invalid input syntax for type uuid: ""` before this migration.
--
-- ===========================================================================
-- EXACTLY WHAT CHANGES, EVERY LINE MEASURED
-- ===========================================================================
--
-- Fixture: `admin_audit` with 2 rows in workspace W1 and 1 in W2;
-- `retention_purge_audit` with one GLOBAL row (`workspace_id IS NULL`) and one
-- owned by W1. All reads as `secureprompt_runner`, `rolsuper = f`,
-- `rolbypassrls = f`.
--
--                                                    BEFORE        AFTER
--   never-scoped conn, SELECT admin_audit            0 rows        0 rows
--   never-scoped conn, SELECT retention_purge_audit  1 row         1 row
--   never-scoped conn, INSERT admin_audit            42501         42501
--   never-scoped conn, INSERT global rpa row         OK            OK
--   SCOPED to W1, SELECT admin_audit                 2             2
--   SCOPED to W2, SELECT admin_audit                 1             1
--   SCOPED to W1, SELECT retention_purge_audit       2             2
--   RELEASED conn, SELECT admin_audit                22P02         0 rows
--   RELEASED conn, SELECT retention_purge_audit      22P02         1 row
--   RELEASED conn, INSERT admin_audit                22P02         42501
--   RELEASED conn, INSERT global rpa row             OK            OK
--   RELEASED conn, UPDATE admin_audit                22P02         UPDATE 0
--   RELEASED conn, DELETE admin_audit                22P02         DELETE 0
--
-- So: NO correctly scoped read changes, in either direction, on any table.
-- What changes is only the released-empty-string column, and it changes from
-- an exception to the behaviour a never-scoped connection already had.
--
-- The INSERT direction stays LOUD. `USING` supplies `WITH CHECK` for a policy
-- created without one, so an unscoped INSERT is now checked against a NULL
-- predicate and rejected with
-- `42501 new row violates row-level security policy` — a different SQLSTATE
-- from the 22P02 it raised before, and still an error the caller cannot miss.
-- `an_unscoped_insert_is_still_rejected_loudly` in
-- `tests/rls_unscoped_read_is_invisible.rs` pins that, with the same INSERT
-- succeeding once the scope is armed as its positive control.
--
-- ===========================================================================
-- WHAT STOPS SHOUTING — read this before assuming the sweep is free
-- ===========================================================================
--
-- `NULLIF` turns a RAISING policy into a FILTERING one, which in the "no error"
-- sense is strictly MORE PERMISSIVE. An unscoped UPDATE or DELETE that used to
-- abort now reports `UPDATE 0` and commits. That is the migration-017
-- silent-no-op shape, deliberately reintroduced, and there is exactly one
-- place in this repository where the raise was doing real work by accident:
--
--   `secureprompt-worker/src/tasks/retention_purge.rs:384`
--     `SELECT workspace_id, retention_days FROM workspace_raw_capture` on the
--     BARE POOL — cross-tenant by design, listed as a REAL DEFECT in
--     `tests/rls_call_site_guard.rs`. Under a non-bypassing role on a RELEASED
--     connection this raised, and the `Err(e)` arm immediately below it logs
--     `alert = "retention_purge_failed"` and returns `PurgeRecord::failure`,
--     i.e. it FAILS CLOSED and pages someone. After this migration the same
--     read returns `Ok(vec![])`, the loop over settings runs zero times, and
--     the function returns an EMPTY record list: no alert, no failure record,
--     job status `ok`, and captured PLAINTEXT PROMPTS are never purged.
--     The defect is the bare-pool read, not this migration — but this
--     migration is what removes the accident that was hiding it, so it is
--     named here rather than discovered later.
--
-- Everything else that runs on a bare pool against an armed table is either
-- already fixed or unaffected:
--
--   * `retention_purge.rs` / `refresh_tokens` (2 statements) — migration 032
--     already converted this table, so this file does not change it.
--   * `retention_purge.rs` / `retention_purge_audit` — the GLOBAL audit INSERT.
--     Unchanged and still succeeds: for a `workspace_id IS NULL` row the
--     `workspace_id IS NULL` operand of `workspace_isolation_or_global` is
--     TRUE, the OR short-circuits and the cast is never reached. MEASURED both
--     before and after, on a released connection: `OK`.
--     The corresponding global READ was NOT fine before — a SELECT evaluates
--     the predicate against workspace-owned rows too, where the first operand
--     is false and the cast IS reached, so on a released connection it raised
--     22P02. After this file it returns the global rows. That is a repair, not
--     a loosening: it is what the allowlist entry already claimed was true.
--   * `api_key_rotation.rs` / `api_keys` — the nightly rotation cleanup no
--     longer reads or writes `api_keys` on a bare pool; it enumerates
--     `workspaces` (not armed) and sweeps each inside a scoped, read-back
--     transaction.
--
-- No code anywhere in `secureprompt-api/src`, `secureprompt-worker/src` or
-- `secureprompt-mcp/src` matches on SQLSTATE 22P02 — `grep -rn '22P02'` over
-- those three trees returns nothing — so nothing depends on the exception
-- programmatically. Every dependency on it was a human noticing a stack trace.
--
-- ===========================================================================
-- THE COMPENSATING CONTROL, AND WHERE IT IS ABSENT
-- ===========================================================================
--
-- The control that makes quiet invisibility acceptable is `begin_scoped`'s
-- read-back (`db::scope::scope_is_armed`): it sets the GUC and then READS IT
-- BACK inside the same transaction, so an unarmed transaction fails at the
-- application layer instead of answering nothing. Measured coverage across the
-- three application crates, counted by grep and not assumed:
--
--   * 36 call sites go through `db::scope::begin_scoped` / `arm_scope`, or the
--     worker's three local equivalents in `api_key_rotation.rs`,
--     `audit_export.rs` and `retention_purge.rs`. All of these read back.
--   * 31 call sites, in 8 files, arm the scope with a hand-written
--     `SELECT set_config('app.current_workspace_id', $1, true)` on a
--     transaction and DO NOT read it back:
--       secureprompt-api/src/db/provider_repo.rs                     (11)
--       secureprompt-api/src/db/policy_repo.rs                        (8)
--       secureprompt-api/src/db/api_key_repo.rs                       (6)
--       secureprompt-api/src/db/budget_repo.rs                        (2)
--       secureprompt-api/src/http/routes/dashboard/audit_export.rs    (1)
--       secureprompt-api/src/http/routes/dashboard/data_inventory.rs  (1)
--       secureprompt-api/src/http/routes/dashboard/keys.rs            (1)
--       secureprompt-api/src/http/routes/dashboard/leak_report.rs     (1)
--     In each of these the `set_config` and the statement are executed on the
--     SAME transaction handle, so the scope is in fact armed and the read is
--     correct today. What they lack is the guard: if a future edit dropped the
--     `set_config`, or moved the statement onto the pool, the raise was what
--     would have caught it and after this file the answer is a plausible zero.
--     Adopting `begin_scoped` at those 31 sites is the follow-on this migration
--     does not own; it is recorded here so the trade is on the record.
--
-- So the honest statement is: the read-back covers the paths that were
-- converted to it, and 31 paths across 8 files rely on being correct rather
-- than on being checked.
--
-- ===========================================================================
-- HOW THE TABLE SET IS ESTABLISHED
-- ===========================================================================
--
-- From `pg_class.relforcerowsecurity`, never from a list written here — the
-- same choice `tests/rls_call_site_guard.rs` makes, for the same reason: a
-- future migration that arms a seventeenth table is covered without anyone
-- remembering. `relforcerowsecurity` and not `relrowsecurity` because ENABLE
-- alone exempts the table owner and the application role owns its tables.
--
-- The predicate is rewritten by exact TEXT SUBSTITUTION on
-- `pg_get_expr(polqual, polrelid)`, so a policy whose shape this file has not
-- seen is either left alone (its qual does not contain the raising fragment)
-- or reproduced faithfully around the one fragment that is replaced. That is
-- what lets `retention_purge_audit`'s `workspace_isolation_or_global` — the
-- one policy in the schema that is not plain `workspace_isolation` — be swept
-- by the same loop without being special-cased, and it is why
-- `refresh_tokens`' `refresh_token_possession` (keyed on
-- `app.refresh_token_probe`, no uuid cast) and its already-rewritten
-- `workspace_isolation` are both skipped: neither contains the fragment.
--
-- The loop REFUSES rather than guesses on anything it was not derived against:
-- a RESTRICTIVE policy, a policy granted to named roles instead of PUBLIC, or
-- an unrecognised `polcmd` each raise. `polpermissive` and `polroles` were
-- verified to be PERMISSIVE / `{0}` (PUBLIC) for all 17 policies on the 16
-- armed tables before this was written.
--
-- Applied to a database migrated through 032 this rewrites exactly 15 policies
-- and the count is asserted, so a loop that silently matched nothing fails the
-- migration instead of reporting success — the same failure mode migration 017
-- shipped with. The second block then re-reads the catalog and fails if ANY
-- armed policy still casts the released empty string, which is the assertion
-- that would catch a substitution that did not take.
--
-- No `GRANT` tail here, unlike 002/003/018/021/023/025/026/028/030/031/032:
-- those repeat it because they CREATE tables and `GRANT ON ALL TABLES` only
-- covers tables that existed when it ran. This file creates none and
-- DROP/CREATE POLICY does not touch privileges.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    -- The fragment every armed `workspace_isolation` policy contains, spelled
    -- as `pg_get_expr` renders it — that is the text being matched, so it is
    -- the text written here.
    RAISING constant text :=
        '(current_setting(''app.current_workspace_id''::text, true))::uuid';
    FILTERING constant text :=
        '(NULLIF(current_setting(''app.current_workspace_id''::text, true), ''''::text))::uuid';
    p          record;
    new_qual   text;
    new_check  text;
    cmd_clause text;
    rewritten  int := 0;
BEGIN
    FOR p IN
        SELECT c.relname                                   AS tbl,
               pol.polname                                 AS name,
               pol.polcmd                                  AS cmd,
               pol.polpermissive                           AS permissive,
               pol.polroles                                AS roles,
               pg_get_expr(pol.polqual, pol.polrelid)      AS qual,
               pg_get_expr(pol.polwithcheck, pol.polrelid) AS wcheck
        FROM pg_policy pol
        JOIN pg_class c     ON c.oid = pol.polrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
          AND c.relforcerowsecurity
          AND (coalesce(pg_get_expr(pol.polqual, pol.polrelid), '') LIKE '%' || RAISING || '%'
            OR coalesce(pg_get_expr(pol.polwithcheck, pol.polrelid), '') LIKE '%' || RAISING || '%')
        ORDER BY c.relname, pol.polname
    LOOP
        IF NOT p.permissive THEN
            RAISE EXCEPTION
                'policy %.% is RESTRICTIVE. This migration only knows how to '
                'recreate PERMISSIVE policies and refuses to silently convert '
                'one, which would change what every other policy on the table '
                'admits.', p.tbl, p.name;
        END IF;
        IF p.roles IS DISTINCT FROM '{0}'::oid[] THEN
            RAISE EXCEPTION
                'policy %.% is granted to specific roles (%). This migration '
                'recreates policies TO PUBLIC and refuses to drop a role list.',
                p.tbl, p.name, p.roles;
        END IF;

        cmd_clause := CASE p.cmd
            WHEN '*' THEN 'ALL'
            WHEN 'r' THEN 'SELECT'
            WHEN 'a' THEN 'INSERT'
            WHEN 'w' THEN 'UPDATE'
            WHEN 'd' THEN 'DELETE'
        END;
        IF cmd_clause IS NULL THEN
            RAISE EXCEPTION 'policy %.% has an unrecognised polcmd %',
                p.tbl, p.name, p.cmd;
        END IF;

        -- `replace` and not a regex: the fragment is a fixed string produced by
        -- `pg_get_expr`, and everything around it is reproduced byte for byte.
        new_qual  := replace(p.qual,   RAISING, FILTERING);
        new_check := replace(p.wcheck, RAISING, FILTERING);

        EXECUTE format('DROP POLICY %I ON public.%I', p.name, p.tbl);
        EXECUTE format(
            'CREATE POLICY %I ON public.%I FOR %s USING (%s)%s',
            p.name, p.tbl, cmd_clause, new_qual,
            CASE
                WHEN new_check IS NULL THEN ''
                ELSE format(' WITH CHECK (%s)', new_check)
            END);

        rewritten := rewritten + 1;
    END LOOP;

    IF rewritten <> 15 THEN
        RAISE EXCEPTION
            'migration 033 rewrote % policies; 15 were expected — 16 tables are '
            'under FORCE ROW LEVEL SECURITY as of migration 031, and '
            'refresh_tokens was already rewritten by migration 032. A different '
            'number means the armed set moved and this sweep was derived '
            'against a schema that no longer exists.', rewritten;
    END IF;
    RAISE NOTICE 'migration 033: rewrote % workspace-isolation policies', rewritten;
END $$;

-- The independent re-read. The loop above could report 15 and still have left
-- a policy raising if `replace` matched a prefix; this asks the catalog
-- directly and is what fails if the substitution did not take.
DO $$
DECLARE
    RAISING constant text :=
        '(current_setting(''app.current_workspace_id''::text, true))::uuid';
    leftover text[];
BEGIN
    SELECT array_agg(c.relname || '.' || pol.polname ORDER BY c.relname, pol.polname)
    INTO leftover
    FROM pg_policy pol
    JOIN pg_class c     ON c.oid = pol.polrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND c.relforcerowsecurity
      AND (coalesce(pg_get_expr(pol.polqual, pol.polrelid), '') LIKE '%' || RAISING || '%'
        OR coalesce(pg_get_expr(pol.polwithcheck, pol.polrelid), '') LIKE '%' || RAISING || '%');

    IF leftover IS NOT NULL THEN
        RAISE EXCEPTION
            'migration 033 left % armed policies still casting the released '
            'empty string to uuid: %. An unscoped read of those tables still '
            'raises 22P02 on a pooled connection.',
            array_length(leftover, 1), leftover;
    END IF;
END $$;
