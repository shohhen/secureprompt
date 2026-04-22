-- Per-workspace secure mode configuration.
-- One row per workspace; upserted on PUT /v1/secure-mode.
-- GET /v1/secure-mode returns defaults when no row exists.

CREATE TABLE workspace_secure_mode (
    workspace_id UUID PRIMARY KEY REFERENCES workspaces(id) ON DELETE CASCADE,
    enabled BOOL NOT NULL DEFAULT false,
    level TEXT NOT NULL DEFAULT 'standard'
        CHECK (level IN ('permissive', 'standard', 'strict')),
    block_on_pii_detection BOOL NOT NULL DEFAULT false,
    block_on_injection_detection BOOL NOT NULL DEFAULT false,
    redact_pii_in_responses BOOL NOT NULL DEFAULT false,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_workspace_secure_mode ON workspace_secure_mode(workspace_id);
