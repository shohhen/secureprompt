CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE workspaces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

CREATE TABLE providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    provider_type TEXT NOT NULL,
    encrypted_credential TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE models (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    provider_id UUID NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE policy_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    priority INT NOT NULL DEFAULT 100,
    conditions JSONB NOT NULL DEFAULT '[]',
    action TEXT NOT NULL CHECK (action IN ('deny','allow','redact','transform','flag')),
    action_params JSONB NOT NULL DEFAULT '{}',
    enabled BOOL NOT NULL DEFAULT true,
    dry_run BOOL NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE audit_events_meta (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    request_id UUID NOT NULL,
    event_type TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_keys_workspace ON api_keys(workspace_id);
CREATE INDEX idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX idx_providers_workspace ON providers(workspace_id);
CREATE INDEX idx_models_workspace ON models(workspace_id);
CREATE INDEX idx_policy_rules_workspace_priority ON policy_rules(workspace_id, priority ASC, id ASC);
CREATE INDEX idx_policy_rules_enabled ON policy_rules(workspace_id, enabled) WHERE enabled = true;
CREATE INDEX idx_audit_events_meta_workspace ON audit_events_meta(workspace_id, created_at DESC);

DO $$ DECLARE t TEXT;
BEGIN
    FOR t IN SELECT unnest(ARRAY['api_keys', 'providers', 'models', 'policy_rules', 'audit_events_meta'])
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

DO $$
BEGIN
    BEGIN
        CREATE ROLE secureprompt_app
            LOGIN
            PASSWORD 'change_in_production'
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOINHERIT
            NOREPLICATION;
    EXCEPTION
        WHEN duplicate_object THEN
            NULL;
        WHEN unique_violation THEN
            -- Role exists cluster-wide (shared Postgres instance across #[sqlx::test]
            -- per-test databases). pg_authid is cluster-scoped; a concurrent or prior
            -- test may have created the role, which surfaces as SQLSTATE 23505 on the
            -- pg_authid_rolname_index rather than SQLSTATE 42710.
            NULL;
    END;
END $$;

GRANT USAGE ON SCHEMA public TO secureprompt_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO secureprompt_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO secureprompt_app;

DO $$
BEGIN
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO secureprompt_app', current_database());
END $$;
