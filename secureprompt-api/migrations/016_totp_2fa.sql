-- 016_totp_2fa.sql — TOTP 2FA (RFC 6238) enrollment + backup codes.
ALTER TABLE users
    ADD COLUMN totp_secret_encrypted BYTEA,
    ADD COLUMN totp_confirmed_at     TIMESTAMPTZ,
    ADD COLUMN totp_last_timestep    BIGINT,
    ADD COLUMN totp_failed_attempts  INT NOT NULL DEFAULT 0,
    ADD COLUMN totp_locked_until     TIMESTAMPTZ;

CREATE TABLE user_backup_codes (
    id         UUID PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_user_backup_codes_user ON user_backup_codes(user_id);
