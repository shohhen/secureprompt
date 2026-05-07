-- 010: Personal info on users + add `employee` role for own-data-only access.
--
-- Adds three optional profile fields surfaced on the dashboard:
--   * first_name + last_name — display name across the UI
--   * position             — free-text job title shown on the profile card
--
-- Adds an `employee` role distinct from `viewer`. Semantically:
--   owner     → full read+write across the workspace
--   developer → full read across the workspace, no write
--   employee  → read only own audit rows (filtered by user_id), no write
--
-- The Rust UserRole enum continues to accept `admin`/`viewer` for
-- backwards compatibility; this migration just unlocks `employee` at
-- the DB layer. Existing rows keep their current role unchanged.

BEGIN;

ALTER TABLE users ADD COLUMN IF NOT EXISTS first_name TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_name  TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS position   TEXT;

ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE users
    ADD CONSTRAINT users_role_check
    CHECK (role IN ('owner', 'admin', 'developer', 'viewer', 'employee'));

COMMIT;
