-- Phase 6 / Plan 06-01 — API key rotation support (AUTH-08, D-17, D-18).
--
-- Adds status lifecycle column and rotation metadata columns to api_keys.
-- Backfills status from existing revoked_at values for Phase 5 compatibility.
-- The worker cleanup cron uses idx_api_keys_rotating to expire grace-window keys.

BEGIN;

-- Add status column with lifecycle states.
-- DEFAULT 'active' covers all existing rows.
ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'rotating', 'revoked'));

-- Backfill: rows with revoked_at non-null are already revoked (Phase 5 pattern).
UPDATE api_keys SET status = 'revoked' WHERE revoked_at IS NOT NULL AND status = 'active';

-- Rotation metadata columns.
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS rotated_at TIMESTAMPTZ;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS rotation_grace_secs INTEGER NOT NULL DEFAULT 86400;
-- successor_key_hash: SHA-256 hex of the replacement key (NULL until rotation initiated).
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS successor_key_hash TEXT;
-- successor_key_prefix: first 12 chars of new plaintext key for idempotent rotate response (D-18).
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS successor_key_prefix TEXT;

-- Partial index used by the worker cleanup cron (D-17, D-19).
CREATE INDEX IF NOT EXISTS idx_api_keys_rotating
    ON api_keys(status, rotated_at)
    WHERE status = 'rotating';

COMMIT;
