-- Per-provider settings that aren't a single credential string. Vertex uses
-- {"region": "...", "project": "..."}; other provider types leave it '{}'.
ALTER TABLE providers ADD COLUMN IF NOT EXISTS config JSONB NOT NULL DEFAULT '{}'::jsonb;
