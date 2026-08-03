-- FU5 — one table for the administrative audit trail.
--
-- WHY THIS TABLE EXISTS
--
-- At commit f2de9f3 exactly three administrative actions were audited
-- anywhere in this product: `raw_capture_audit` (021), `retention_purge_audit`
-- (023) and `session_revocation_audit` (026). FU1 then built a signed export
-- that carries a CONTROL-PLANE section alongside the data plane. That pipe
-- works correctly and was very nearly empty: an auditor could obtain "what
-- requests passed through the gateway" and could not answer "who created this
-- API key", "who changed this redaction policy", "who was granted admin" —
-- which are the first questions asked in a real audit.
--
-- WHY ONE TABLE AND NOT MORE TABLES IN THE STYLE OF 021/023/026
--
-- This was the design decision of FU5 and it is written down rather than
-- assumed. The three existing tables are per-action, each with its own column
-- list, and FU1 has to teach the exporter every one of them: a source list, a
-- windowing column, a bespoke SELECT and a bespoke `detail` construction. Each
-- new per-action table is therefore a new export source and a fresh chance to
-- forget one — and "shipped a table the compliance artifact does not carry" is
-- exactly the defect the WS4-1 data-inventory drift guard caught.
--
-- A single table inverts that. `audit_export::ControlRow` is ALREADY a
-- normalised shape — `event_type` plus a JSONB `detail` — chosen by FU1
-- "because the auditor's question is 'who did what, when' across the whole
-- administrative surface". This table is that shape at rest. The exporter reads
-- it with ONE unfiltered query and passes `action` through verbatim as
-- `event_type`, so there is NO per-action code anywhere in the export path and
-- consequently nothing for a future action to be missing from.
--
-- The three existing tables are deliberately NOT migrated into this one.
-- Composition, not replacement: they are append-only records that auditors and
-- `latest_watermark` already read, and rewriting history to tidy a schema is
-- the one thing an audit trail must never do.
--
-- WHY THE `action` CHECK CONSTRAINT IS NOT DECORATION
--
-- It is the structural guarantee that the export's vocabulary is COMPLETE. The
-- export carries every row of this table regardless of `action`, so a new
-- action reaches an auditor automatically; the risk is the opposite one, that
-- the manifest DOCUMENTS a vocabulary which no longer matches what is stored.
-- With this constraint a row whose action is not in the list below cannot be
-- stored at all, so "these are the audited actions" is enforced by the database
-- rather than promised by a comment.
-- `tests/admin_audit.rs::the_action_vocabulary_is_pinned_in_three_places`
-- reconciles this list against `AdminAuditAction::ALL` and against the coverage
-- prose the manifest ships, so adding a variant in Rust without adding it here
-- fails a test rather than a production INSERT.
--
-- WHAT IS DELIBERATELY *NOT* RECORDED
--
-- No `ip_address`, no `user_agent`, no free-text reason, and no secret of any
-- kind. WS4-3 (026) set this discipline for a never-purged table and FU4
-- followed it by storing only a `{browser} on {os}` reduction from a closed
-- vocabulary rather than a raw User-Agent: NO INPUT BYTE REACHES THE DATABASE.
-- The same rule holds here with one stated exception — `target_label` — below.
--
-- `detail` is JSONB and therefore looks like an unbounded channel. It is not:
-- every value in it is built by `admin_audit_repo` from typed columns the
-- product already stores (a priority integer, an enabled boolean, a provider
-- type, a timestamp) or from a boolean saying WHETHER something changed. A
-- credential, a password, a TOTP secret or an API key never appears, and
-- `tests/admin_audit.rs::no_secret_reaches_the_admin_audit_trail` dumps every
-- column of every row to text — `detail` included — and searches it, with a
-- positive control so a clean result is evidence rather than a broken haystack.
--
-- THE ONE STATED EXCEPTION: `target_label`
--
-- It holds the acted-on object's OWN name — an API key called "nightly-batch",
-- a policy rule called "mask-emails" — which is administrator-supplied text and
-- so is a departure from "no input byte". It is taken deliberately, because
-- without it the record does not read alone: `DELETE /v1/providers/{id}` erases
-- the row the id pointed at, and an audit line naming only a UUID that resolves
-- to nothing months later fails the one job it has. The exposure is bounded
-- rather than argued away: the value is truncated to 200 characters by the
-- writer, and the CHECK below REFUSES anything longer, so a writer that forgets
-- to truncate fails loudly instead of accumulating unbounded text in a table
-- that is never purged.
--
-- RETENTION: NONE, AND OUTSIDE `retention.purge`
--
-- Append-only and never purged, exactly like 021, 023 and 026, and for the
-- reason 021's header gives: an audit trail with a retention window is an audit
-- trail with a deadline. The WS3-4 purge job does not cover this table and is
-- not intended to. That decision is why the paragraphs above are strict about
-- what may enter: everything written here is kept forever.
--
-- NO FOREIGN KEYS, for the reason 021, 023, 025 and 026 all give: a referential
-- constraint lets history mutate, and ON DELETE CASCADE would erase the record
-- that an account was created at the moment that account is deleted — precisely
-- when the record matters. Actor and target are recorded as identifiers PLUS
-- the email/role/name as they read AT THE TIME, reachable from no later DELETE.

CREATE TABLE admin_audit (
    id             UUID PRIMARY KEY,
    -- The tenant the action was performed in. NOT NULL: every action this
    -- table records is taken by an authenticated administrator inside one
    -- workspace, and the RLS policy below keys on this column.
    workspace_id   UUID        NOT NULL,
    -- What was done. Closed vocabulary — see the header.
    action         TEXT        NOT NULL,
    -- Who did it. From the authenticated context, NEVER from a request body.
    -- Nullable so the column can carry a future scheduler-initiated action the
    -- way `retention_purge_audit` does, where a NULL is a FACT about the event
    -- rather than a lost attribution. Every action written today sets it.
    actor_user_id  UUID,
    -- Denormalised copies as at the time of the action, for the reason 026
    -- gives: a foreign key would let deleting a user rewrite the evidence.
    actor_email    TEXT,
    actor_role     TEXT,
    -- WHAT was acted on. `target_type` names the kind of object so `target_id`
    -- is interpretable without knowing which action wrote the row.
    target_type    TEXT        NOT NULL,
    target_id      UUID,
    -- The object's own name as it read at the time. See the header for why this
    -- single administrator-supplied string is admitted, and how it is bounded.
    target_label   TEXT,
    -- Populated when the target IS a workspace member, so these rows land in
    -- the export's existing `target_user_id` / `target_email` / `target_role`
    -- columns rather than being buried in `detail`.
    target_user_id UUID,
    target_email   TEXT,
    target_role    TEXT,
    -- The action-specific facts. Bounded values only — see the header.
    detail         JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT admin_audit_action_known CHECK (action IN (
        'api_key.created',
        'api_key.revoked',
        'api_key.rotated',
        'provider_credential.created',
        'provider_credential.updated',
        'provider_credential.deleted',
        'policy_rule.created',
        'policy_rule.updated',
        'policy_rule.deleted',
        'policy_rule.enabled_changed',
        'policy_rule.dry_run_changed',
        'user.created'
    )),
    -- The bound on the one administrator-supplied string this table accepts.
    CONSTRAINT admin_audit_target_label_bounded
        CHECK (target_label IS NULL OR char_length(target_label) <= 200),
    -- `detail` must be an OBJECT. A bare JSON scalar or array would still be
    -- valid JSONB and would render into the export as a `detail` column the
    -- documented per-action key list cannot describe.
    CONSTRAINT admin_audit_detail_is_object
        CHECK (jsonb_typeof(detail) = 'object')
);

-- The export reads by workspace and orders by instant; the dashboard and an
-- investigator read the history of one object.
CREATE INDEX idx_admin_audit_workspace ON admin_audit(workspace_id, created_at DESC);
CREATE INDEX idx_admin_audit_target ON admin_audit(target_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- ROW-LEVEL SECURITY, same shape and same reason as migrations 025 and 026.
--
-- `current_setting(..., true)` yields NULL when `app.current_workspace_id` is
-- unset, the policy predicate is then NULL for every row, and the two halves
-- fail DIFFERENTLY: an INSERT is REJECTED (loud) while a SELECT returns the
-- EMPTY SET and reports no error (silent). The silent half is the dangerous one
-- — on a compliance export it reads as "this workspace's administrators did
-- nothing", and the product would sign that. `db::scope::begin_scoped` sets the
-- GUC and READS IT BACK for exactly this reason, and every write below goes
-- through it.
--
-- The compose role is a SUPERUSER today and bypasses all of this, so no
-- `#[sqlx::test]` can observe a mistake here — which is why
-- `tests/admin_audit.rs` opens its own NOSUPERUSER/NOBYPASSRLS connection.
--
-- Stated with USING only: for a policy created without a command, PostgreSQL
-- uses the USING expression as the WITH CHECK expression too, so this governs
-- INSERT as well as SELECT.
-- ---------------------------------------------------------------------------
DO $$ DECLARE t TEXT;
BEGIN
    FOR t IN SELECT unnest(ARRAY['admin_audit'])
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
-- reason migrations 002, 003, 018, 021, 023, 025 and 026 repeat it.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO secureprompt_app;
