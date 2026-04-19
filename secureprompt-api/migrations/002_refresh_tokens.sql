-- Phase 5 / Plan 05-01 — Refresh-token persistence for dashboard JWT auth.
--
-- Refresh tokens are stored as SHA-256 hashes (NOT Argon2id). Per CONTEXT D-06
-- + RESEARCH A7, Argon2 is too slow for every-request lookup; the refresh
-- rotation path looks up token_hash on every /v1/auth/refresh.
--
-- Single-use rotation: the `rotate()` method updates `revoked_at = now()` and
-- sets `replaced_by` to the new row's id. A second presentation of the same
-- raw token finds a row with `revoked_at IS NOT NULL` → replay detected →
-- revoke_all_for_user triggered.

CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    replaced_by UUID REFERENCES refresh_tokens(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_refresh_tokens_user_active
    ON refresh_tokens(user_id)
    WHERE revoked_at IS NULL;

CREATE INDEX idx_refresh_tokens_hash
    ON refresh_tokens(token_hash);

-- Enable RLS using the same workspace_isolation policy as migration 001.
DO $$ DECLARE t TEXT;
BEGIN
    FOR t IN SELECT unnest(ARRAY['refresh_tokens'])
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

-- Re-execute the role grants so the new table is covered for `secureprompt_app`.
-- (Per 05-PATTERNS pitfall #16: GRANT ON ALL TABLES applies only at the time
-- it's run; new tables do not inherit without ALTER DEFAULT PRIVILEGES.)
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO secureprompt_app;
