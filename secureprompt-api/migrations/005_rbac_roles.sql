-- Phase 6 / Plan 06-01 — Extend role enum: member→developer, add owner (AUTH-06, D-08, D-09).
--
-- Safe to run on Phase 5 data: existing 'member' rows become 'developer'.
-- Existing 'admin' and 'viewer' rows are unchanged.
-- The CHECK constraint is DROP+ADD because Postgres cannot ALTER a CHECK in-place.

BEGIN;

-- 1. Drop the old CHECK constraint from migration 004.
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;

-- 2. Rename existing 'member' rows before adding the new constraint.
UPDATE users SET role = 'developer' WHERE role = 'member';

-- 3. Add new CHECK constraint with 4 allowed values.
ALTER TABLE users
    ADD CONSTRAINT users_role_check
    CHECK (role IN ('owner', 'admin', 'developer', 'viewer'));

COMMIT;
