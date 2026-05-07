-- Token vault for /v1/secure-mode/tokenize + /v1/secure-mode/detokenize.
--
-- Each row is one `tokenize` response. The JSONB `mapping` is a
-- {placeholder → original_text} object produced by `apply_redaction`.
-- Entries expire 24 hours after creation to bound the window in which a
-- stored original can be recovered.
--
-- IMPORTANT: originals live in plain JSONB here. Production deployments
-- should encrypt `mapping` via the configured KMS before inserting — the
-- repository layer reads the backend from `KMS_BACKEND_KIND` env var so
-- swapping in an encryption helper is a localized change.

CREATE TABLE IF NOT EXISTS token_vault_entries (
    id UUID PRIMARY KEY,
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    mapping JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '24 hours'
);

CREATE INDEX IF NOT EXISTS idx_token_vault_workspace
    ON token_vault_entries(workspace_id);

CREATE INDEX IF NOT EXISTS idx_token_vault_expires
    ON token_vault_entries(expires_at);
