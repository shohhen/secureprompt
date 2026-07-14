-- Soft-delete flag so admin-curated model removals survive upstream re-syncs.
--
-- Before this, `persist_synced_models` (auto-sync on credential save/rotate and
-- the "Sync from upstream" button) re-imported the FULL upstream catalog and
-- re-inserted every model the admin had deleted — curating a provider down to a
-- few models never stuck. `excluded = TRUE` marks a model the admin removed;
-- sync now skips re-adding excluded names, listings/discovery hide them, and a
-- manual "Add model" un-excludes (brings it back).
ALTER TABLE models ADD COLUMN IF NOT EXISTS excluded BOOLEAN NOT NULL DEFAULT FALSE;

-- Sync and listing both filter on (provider_id, excluded); index it.
CREATE INDEX IF NOT EXISTS idx_models_provider_excluded
    ON models (provider_id, excluded);
