-- Correct the record: migrations 030 and 033 each state a residual that the
-- branch has since closed, and one of them states work that had not been done
-- at the time it claimed it.
--
-- Same shape and same reason as `037_correct_026_export_coverage_note.sql`.
-- `sqlx::migrate!` validates checksums and `db/migrations.rs` says so in as
-- many words -- "a checksum divergence means a historical migration file was
-- edited after being applied, which `MIGRATOR.run` already refuses" -- so a
-- correction is appended, never backdated.
--
-- ===========================================================================
-- CORRECTION 1 -- migration 030's header claims callers it did not change
-- ===========================================================================
--
-- `030_arm_rls_on_capture_and_purge_tables.sql` says:
--
--   018's reasoning is that FORCE RLS alone would make every read return zero
--   rows -- true, and the half of the picture `src/db/sidecar_policy_repo.rs`
--   already corrects: the codebase's actual pattern is RLS PLUS `set_config`
--   on the same transaction. This migration supplies the RLS; the
--   repositories were changed in the same commit to supply the `set_config`.
--
-- That last clause was not true of the commit it describes (`9920cee`). 030
-- armed FOUR tables; exactly ONE of the four had its caller converted in that
-- commit:
--
--   workspace_sidecar_policy  -> db/sidecar_policy_repo.rs   ARMED in 9920cee
--   workspace_raw_capture     -> db/raw_capture_repo.rs      bare `.begin()`
--   raw_capture_audit         -> db/raw_capture_repo.rs      bare `.begin()`
--   retention_purge_audit     -> worker retention_purge.rs   bare pool, no tx
--
-- `raw_capture_repo.rs` did not appear in that commit's diffstat at all. The
-- claim mattered because the DB role-split is the next branch: under a
-- NOSUPERUSER/NOBYPASSRLS runtime the `workspace_raw_capture` read is a SILENT
-- zero (the gateway reads "capture disabled" for every workspace and logs
-- nothing) and the `retention_purge_audit` INSERT raises into a failure the
-- purge job logs and continues past -- data deleted, proof-of-purge missing.
-- A header stating the work was done is exactly what would let the role-split
-- land on the assumption that it was.
--
-- WHERE IT STANDS NOW -- all three remaining callers are converted, and each
-- READS THE SCOPE BACK rather than only setting it:
--
--   * `db/raw_capture_repo.rs` -- all three methods on
--     `crate::db::scope::begin_scoped`, in `be62f01`.
--   * worker `retention_purge.rs` -- `begin_armed(...)` + `SETTINGS_SCOPE_NOT_ARMED`
--     for the settings read (`9ef100a`, `180ea52`) and for `write_audit`,
--     with a global census row that is written even when arming is what
--     failed.
--   * The invariant is now enforced, not just performed:
--     `tests/rls_call_site_guard.rs` fails on a statement that touches an
--     armed table from a bare pool, and `tests/rls_scope_arming_guard.rs`
--     fails on an arming with no read-back near it.
--
-- ===========================================================================
-- CORRECTION 2 -- migration 033's "31 unprotected call sites" was closed by
--                 the same merge request that shipped the claim
-- ===========================================================================
--
-- `033_nullif_workspace_scope_sweep.sql`, under "THE COMPENSATING CONTROL, AND
-- WHERE IT IS ABSENT", enumerates:
--
--   31 call sites, in 8 files, arm the scope with a hand-written
--   `SELECT set_config('app.current_workspace_id', $1, true)` on a transaction
--   and DO NOT read it back
--
-- and names the eight files (provider_repo 11, policy_repo 8, api_key_repo 6,
-- budget_repo 2, dashboard/{audit_export,data_inventory,keys,leak_report} 1
-- each), concluding "31 paths across 8 files rely on being correct rather than
-- on being checked".
--
-- By the tip of that same merge request the number is ZERO. `a55961d` converted
-- 26 of them and `cf7f3fe` the last 3 (the count differs from 31 because
-- several sites shared one helper). MEASURED at this migration:
-- `grep -rn "set_config('app.current_workspace_id'"` over
-- `secureprompt-{api,worker,mcp}/src` returns FIVE armings in application code
-- -- `db/scope.rs:107`, `worker/tasks/retention_purge.rs:608` and `:974`,
-- `worker/tasks/audit_export.rs:697`, `worker/tasks/api_key_rotation.rs:209`
-- -- every one of them followed by its own `current_setting` read-back, plus
-- one DOC COMMENT in `dashboard/keys.rs:13`. None of the eight named files
-- contains a hand-written arming any more. There are 60 `begin_scoped(` call
-- sites.
--
-- The error is conservative -- it overstates the risk -- but it is a false
-- statement in the most permanent documentation this repository has, and an
-- operator reading 033 is told a third of the tenancy arming in the codebase
-- is unchecked. It is not.
--
-- The claim also cannot silently go stale again in the other direction:
-- `tests/rls_scope_arming_guard.rs` flags any arming without a read-back
-- within its proximity window, so reintroducing one of the 31 shapes reddens
-- the gate rather than quietly restoring the residual.
--
-- ===========================================================================
-- WHAT THIS MIGRATION CHANGES
-- ===========================================================================
--
-- Nothing about the schema, and nothing about any policy. It writes correction
-- 1 into the catalog comments of the three tables whose callers 030 misstated,
-- so `\d+ workspace_raw_capture` and any schema dump carry it to a reader who
-- never opens the migration directory -- which is the reader the DB role-split
-- puts at risk. Correction 2 concerns Rust call sites and has no catalog
-- object to hang on; it lives in this header, one file after the one it
-- corrects. `COMMENT ON` is idempotent and re-running it is a no-op.

COMMENT ON TABLE workspace_raw_capture IS
    'WS3-1. Per-workspace opt-in to storing plaintext prompt/response content, '
    'with its retention window. FORCE ROW LEVEL SECURITY since migration 030. '
    'Its caller, `src/db/raw_capture_repo.rs`, reads and writes it through '
    '`db::scope::begin_scoped`, which arms `app.current_workspace_id` and '
    'READS IT BACK -- an unarmed read of this table is not an error, it is an '
    'empty set that means "no workspace ever enabled capture". Migration 030''s '
    'header says the caller was converted in the same commit as the arming; it '
    'was not, it was converted later in `be62f01`, and 030 cannot be edited '
    'because sqlx validates migration checksums.';

COMMENT ON TABLE raw_capture_audit IS
    'WS3-1. One row per change to `workspace_raw_capture`, naming the actor and '
    'both the before and after state. A SOURCE of the signed compliance export '
    '(`audit.export`). FORCE ROW LEVEL SECURITY since migration 030; before '
    'that a cross-tenant INSERT was accepted, which is a forged audit row. '
    'Written through `db::scope::begin_scoped` (arm plus read-back) since '
    '`be62f01` -- NOT in the same commit as the arming, contrary to migration '
    '030''s header, which cannot be edited because sqlx validates checksums.';

COMMENT ON TABLE retention_purge_audit IS
    'Proof-of-purge, one row per retention sweep scope per run, plus a global '
    '`workspace_id IS NULL` census row that is written even when arming a '
    'workspace scope is what failed. FORCE ROW LEVEL SECURITY since migration '
    '030, under `workspace_isolation_or_global` so the census row survives an '
    'unarmed connection. The worker writes it through `begin_armed(...)`, which '
    'arms and reads back; that conversion landed in `9ef100a`/`180ea52`, not in '
    'the same commit as the arming as migration 030''s header states. An '
    'unarmed per-workspace INSERT RAISES rather than vanishing, and `run()` '
    'logs `retention_purge_audit_write_failed` and continues -- so the census '
    'row is what tells an auditor a sweep ran blind.';
