-- Phase 5 / Plan 05-01 — Workspace budget limits (LIM-02, LIM-03).
--
-- Single row per workspace_id per CONTEXT D-23 (authoritative over the older
-- VALIDATION draft that proposed a `scope enum daily|monthly` multi-row shape).
-- NULL limit = unlimited. `behavior` enum matches the pipeline enforcement
-- triplet consumed by Plan 05's budget_check in rate_limit.rs
-- (block → 402, warn → 200 + X-SecurePrompt-Budget-Warning header, flag → 200 + analytics event only).

CREATE TABLE workspace_budgets (
    workspace_id UUID PRIMARY KEY REFERENCES workspaces(id) ON DELETE CASCADE,
    daily_token_limit BIGINT,
    monthly_token_limit BIGINT,
    behavior TEXT NOT NULL CHECK (behavior IN ('block','warn','flag')),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Enable RLS using the same workspace_isolation policy as migration 001.
DO $$ DECLARE t TEXT;
BEGIN
    FOR t IN SELECT unnest(ARRAY['workspace_budgets'])
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

-- Re-execute role grants for the new table.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO secureprompt_app;
