-- 012_license_freshness.sql
-- Per-license freshness bookkeeping for the offline-revalidation overlay (spec §4.3).
-- One row per license. Timestamps stored as timestamptz; the gateway converts to epoch.
CREATE TABLE IF NOT EXISTS license_freshness (
    lic_id            uuid        PRIMARY KEY,
    last_assertion_at timestamptz NOT NULL,
    highwater_at      timestamptz NOT NULL,
    updated_at        timestamptz NOT NULL DEFAULT now()
);
