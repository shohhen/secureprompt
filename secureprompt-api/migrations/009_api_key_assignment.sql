-- 009. Per-user API key assignment + retrievable plaintext for the LibreChat
--     proxy path. Builds on 001 (api_keys, users) and 005 (RBAC roles).
--
--     Required so that:
--       1. Admins can issue an API key to a *specific* workspace member
--          (not just an unassigned workspace-scoped key).
--       2. The LibreChat backend can fetch a user's plaintext key
--          server-to-server (via JWT-authenticated `GET /v1/me/api-key`)
--          without ever leaking it to the user. The plaintext is
--          encrypted-at-rest with the provider AES-256-GCM key
--          (`SECUREPROMPT_PROVIDER_KEY`) — same crypto used for
--          provider_credentials.encrypted_credential.
--
--     Both columns are nullable so legacy unassigned workspace-scoped
--     keys continue to authenticate normally; only newly-assigned keys
--     carry the plaintext for retrieval.

ALTER TABLE api_keys
    ADD COLUMN assigned_user_id UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN key_ciphertext   TEXT NULL;

-- Helps the per-user lookup `WHERE workspace_id = $1 AND assigned_user_id = $2`
-- used by `GET /v1/me/api-key` (one row per user expected, but the index
-- still matters for the RLS-scoped scan).
CREATE INDEX IF NOT EXISTS idx_api_keys_workspace_assignee
    ON api_keys (workspace_id, assigned_user_id)
    WHERE assigned_user_id IS NOT NULL;
