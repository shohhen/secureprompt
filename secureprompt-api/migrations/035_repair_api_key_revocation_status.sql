-- Repair migration 006's `api_keys` status back-fill, RLS-safely.
--
-- ===========================================================================
-- READ 020's HEADER FIRST. This is the same defect, five migrations earlier,
-- on a table that ADMITS rather than one that leaks.
--
-- ROW LEVEL SECURITY MAKES A BARE `UPDATE` SILENTLY DO NOTHING.
--
-- `api_keys` has FORCE ROW LEVEL SECURITY with
--
--     USING (workspace_id = current_setting('app.current_workspace_id', true)::uuid)
--
-- armed by `001_init.sql:78-95` — FIVE migrations before 006. The `true`
-- second argument is `missing_ok`: with the GUC unset `current_setting`
-- returns NULL rather than raising, the predicate is NULL for every row, every
-- row is invisible, and an UPDATE that matches zero rows is NOT an error. It
-- reports `UPDATE 0`, exits 0, and `sqlx migrate run` records the migration as
-- applied.
--
-- `006_api_key_rotation.sql:16` is exactly that statement:
--
--     UPDATE api_keys SET status = 'revoked'
--      WHERE revoked_at IS NOT NULL AND status = 'active';
--
-- Measured, on a database with all migrations applied, replaying 006 as a
-- NOSUPERUSER/NOBYPASSRLS role against a row with `revoked_at` set and
-- `status = 'active'`:
--
--     exit=0, status unchanged ('active')
--
-- ...and the identical file replayed as superuser flips it to 'revoked'.
-- See `secureprompt-api/tests/migration_006_rls.rs::
-- migration_006_backfill_is_a_silent_no_op_under_rls`, which asserts both
-- halves so the "nothing changed" reading cannot be a mis-typed fixture.
--
-- It looks correct on every developer machine today only because the compose
-- `secureprompt` role is a SUPERUSER (`rolsuper = t`, `rolbypassrls = t`).
-- Under the DB role-split that stops being true.
-- ===========================================================================
--
-- WHY THIS ONE MATTERS MORE THAN 017's
--
-- 017's no-op leaks: an Uzbek identifier is detected and forwarded. 006's
-- no-op ADMITS. `status` is the column 006 adds with `DEFAULT 'active'`, and
-- this back-fill is the ONLY thing that carries a pre-006 revocation
-- (`revoked_at IS NOT NULL`) across into the lifecycle column. And
-- `ApiKeyRepository::authenticate_api_key` decides on `status`:
--
--     status = 'active'
--       OR (status = 'rotating' AND rotated_at + grace > NOW())
--
-- its own comment saying "Reject: status = 'revoked' (even if revoked_at IS
-- NULL from pre-migration data)". So on a database where 006 no-opped, a key
-- an administrator revoked keeps `status = 'active'` and KEEPS
-- AUTHENTICATING, with the revocation timestamp sitting in the same row.
--
-- 006 is deliberately NOT edited. It is applied on real databases and
-- changing a byte breaks the sqlx checksum — the same reason 020 superseded
-- 017 rather than repairing it in place.
--
-- WHAT ELSE CHANGED ALONGSIDE THIS
--
-- `authenticate_api_key` gained `AND revoked_at IS NULL`, so the bypass is
-- closed by the query too and does not depend on any operator having run this
-- migration. Only `ApiKeyRepository::revoke` ever writes `revoked_at`, and it
-- writes `status = 'revoked'` in the same statement; `rotate` never touches
-- it. So `revoked_at IS NOT NULL` implies "must not authenticate"
-- unconditionally, and the two fixes are independent rather than redundant:
-- this migration also makes the row READ correctly in the dashboard, the
-- rotation sweep and the admin-audit trail, which the query predicate does
-- not.
--
-- SAFETY
-- Deliberately conservative and idempotent. Only ever promotes
-- `'active' -> 'revoked'`, and only for rows that ALREADY carry a
-- `revoked_at` timestamp, so a key nobody revoked cannot be revoked by this.
-- `'rotating'` rows are untouched: a rotation does not set `revoked_at`, so
-- such a row cannot match, and the grace-window predicate in
-- `authenticate_api_key` remains the only thing that decides them.

DO $$
DECLARE
    ws UUID;
BEGIN
    -- `workspaces` is NOT RLS-protected, so it is safe to read unscoped; this
    -- is the same driver 019 and 020 use.
    FOR ws IN SELECT id FROM workspaces
    LOOP
        -- The GUC the RLS predicate reads. `is_local = true` scopes it to this
        -- migration's transaction.
        PERFORM set_config('app.current_workspace_id', ws::text, true);

        UPDATE api_keys
        SET status = 'revoked'
        WHERE workspace_id = ws
          AND revoked_at IS NOT NULL
          AND status = 'active';
    END LOOP;
    -- The GUC is intentionally NOT reset. It was set with is_local = true, so
    -- it dies with this migration's transaction. Resetting it to '' would be
    -- actively worse: the RLS predicate casts it with `::uuid`, and ''::uuid
    -- raises `invalid input syntax for type uuid` rather than yielding NULL,
    -- which would break any later statement in the same transaction.
END $$;
