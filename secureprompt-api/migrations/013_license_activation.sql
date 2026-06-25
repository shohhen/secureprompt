-- 013_license_activation.sql — single-row table holding the console-activated license token.
CREATE TABLE IF NOT EXISTS license_activation (
    id           smallint    PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    token        text        NOT NULL,
    activated_by uuid        REFERENCES users(id),
    updated_at   timestamptz NOT NULL DEFAULT now()
);
