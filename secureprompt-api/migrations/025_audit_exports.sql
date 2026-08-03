-- WS4-1 / Task 19 — persistence for the `audit.export` control.
--
-- WHY THESE TABLES EXIST
--
-- Before WS4-1 the audit-export handler was literally
--     tracing::debug!("audit.export — no-op stub (Phase 7 implementation)")
-- so "an auditor can pull the audit trail for a time range and prove it was
-- not altered after export" was backed by nothing. These two tables hold the
-- artifact that makes the claim checkable.
--
-- WHY THE PAGE BYTES ARE STORED RATHER THAN REGENERATED
--
-- The obvious cheaper design is to re-run the ClickHouse query at download
-- time and stream the rows out. It cannot work here, and not for a
-- performance reason: `request_events` carries a 90-day TTL, so rows can
-- disappear BETWEEN signing and download. A regenerated page would then hash
-- to something the manifest does not contain, and every honest export would
-- eventually fail its own verification. The signature covers exact bytes, so
-- the exact bytes are what gets stored.
--
-- That is also why `body` is TEXT and why the worker enforces a row cap: an
-- export is a materialised artifact with real storage cost, and the honest
-- failure for an over-large window is a REFUSAL naming the cap, never a
-- silent truncation. A truncated export that still verifies is precisely the
-- "short result that looks complete" failure this control exists to prevent.
--
-- WHY `manifest_json` IS TEXT AND NOT JSONB
--
-- Load-bearing. The Ed25519 signature covers the manifest's EXACT bytes.
-- JSONB does not preserve key order or whitespace — it normalises on the way
-- in — so a round-trip through JSONB would produce a document that no longer
-- verifies against its own signature. It is stored, and served, verbatim.
--
-- NO FOREIGN KEY ON `workspace_id`, for the reason `raw_capture_audit` (021)
-- and `retention_purge_audit` (023) give: ON DELETE CASCADE would erase the
-- audit artifact at the exact moment a workspace is deleted, which is when it
-- matters most. `audit_export_pages` DOES cascade from `audit_exports`,
-- because a page without its manifest is not evidence of anything.

CREATE TABLE audit_exports (
    id             UUID PRIMARY KEY,
    workspace_id   UUID        NOT NULL,
    -- The dashboard user who asked. NULL only if the row predates attribution.
    requested_by   UUID,
    -- Half-open: rows with created_at >= window_from AND < window_to.
    window_from    TIMESTAMPTZ NOT NULL,
    window_to      TIMESTAMPTZ NOT NULL,
    format         TEXT        NOT NULL,
    page_size      INTEGER     NOT NULL,
    -- queued | running | complete | failed
    status         TEXT        NOT NULL,
    total_rows     BIGINT,
    total_pages    INTEGER,
    -- The EXACT bytes the signature covers. See the header.
    manifest_json  TEXT,
    signature_b64  TEXT,
    -- Published so a caller can fetch key + signature + manifest in one round
    -- trip. It is NOT the auditor's trust root: the key must be obtained out
    -- of band, because whoever can rewrite an export can also re-sign it and
    -- publish the matching key here. See `audit_export`'s module docs.
    public_key_b64 TEXT,
    signing_key_id TEXT,
    -- Bounded failure reason. Never a store's own message and never any part
    -- of the signing key — see `KeyError`'s docs.
    error          TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at     TIMESTAMPTZ,
    completed_at   TIMESTAMPTZ
);

CREATE TABLE audit_export_pages (
    export_id    UUID    NOT NULL REFERENCES audit_exports(id) ON DELETE CASCADE,
    -- Denormalised so RLS can be keyed on this table directly rather than
    -- through a join the policy would have to re-evaluate per row.
    workspace_id UUID    NOT NULL,
    -- 1-based, matching `manifest.pages[i].page`.
    page_number  INTEGER NOT NULL,
    row_count    INTEGER NOT NULL,
    -- Lowercase hex SHA-256 of `body`'s bytes, so an operator can spot
    -- at-rest corruption without recomputing the whole chain.
    sha256       TEXT    NOT NULL,
    body         TEXT    NOT NULL,
    PRIMARY KEY (export_id, page_number)
);

CREATE INDEX idx_audit_exports_workspace
    ON audit_exports(workspace_id, created_at DESC);

CREATE INDEX idx_audit_export_pages_workspace
    ON audit_export_pages(workspace_id);

-- ---------------------------------------------------------------------------
-- Row level security.
--
-- An audit export is a whole tenant's request trail in one downloadable file;
-- a cross-tenant read here is the worst-shaped leak in the product. The WHERE
-- clause in the handler is still the filter — this is defence in depth
-- (Global Constraint 3), the same posture `models` has.
--
-- BOTH the worker (which INSERTs) and the API (which SELECTs) set
-- `app.current_workspace_id` inside their transaction before touching these
-- tables. That is not optional bookkeeping: `current_setting(..., true)`
-- yields NULL when the GUC is unset, the policy predicate is then NULL for
-- every row, and a SELECT returns the EMPTY SET while an INSERT is REJECTED.
-- Today the compose role is a SUPERUSER and bypasses all of it, so no
-- `#[sqlx::test]` can observe a mistake here — which is exactly why
-- `tests/audit_export.rs` opens its own NOSUPERUSER/NOBYPASSRLS connection to
-- assert the policy is armed.
--
-- The policy is stated with USING only. For a policy created without a
-- command, PostgreSQL uses the USING expression as the WITH CHECK expression
-- too, so this governs INSERT as well as SELECT.
-- ---------------------------------------------------------------------------
DO $$ DECLARE t TEXT;
BEGIN
    FOR t IN SELECT unnest(ARRAY['audit_exports', 'audit_export_pages'])
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

-- GRANT ON ALL TABLES applies only to tables that exist when it runs — same
-- reason migrations 002, 003, 018, 021 and 023 repeat it.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO secureprompt_app;
