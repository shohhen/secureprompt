-- WS4-2 — one more action in the vocabulary 028 opened and 029 extended:
-- `file_scan.requested`.
--
-- WHY THIS IS A NEW MIGRATION AND NOT AN EDIT TO 028 OR 029
--
-- `sqlx migrate` records a checksum per migration, so editing either in place
-- would make every already-migrated deployment refuse to start. The CHECK
-- constraint is DROPPED and re-added here under the SAME NAME for the reason
-- 029 gives: `tests/admin_audit.rs::the_action_vocabulary_is_pinned_in_three_
-- places` and `worker/tasks/audit_export/tests.rs::every_audited_action_
-- reaches_the_signed_export` both read the vocabulary out of
-- `pg_get_constraintdef(oid) WHERE conname = 'admin_audit_action_known'`, so a
-- rename would silently disarm two tests rather than fail one.
--
-- WHAT THIS ACTION IS
--
-- A file scan: a user uploads a document into the chat or the dashboard and
-- the gateway hands its bytes to the ML sidecar for OCR, extraction and PII
-- detection. Before WS4-2 the chat backend POSTed those bytes to the sidecar
-- itself, holding `ML_SIDECAR_INTERNAL_TOKEN` — a SERVICE credential. Nothing
-- recorded that a scan happened, so the one question an incident starts from,
-- "who put that document through this system", had no answer anywhere in the
-- product. `POST /v1/scan-file` on the gateway is the door that answers it, and
-- this is the record it writes.
--
-- WHY `requested` AND NOT `performed`
--
-- The row is committed BEFORE the bytes are forwarded, so no file reaches the
-- sidecar without a committed record of who sent it. The cost is stated rather
-- than hidden: a scan the sidecar then refuses (413, 503, a timeout) still has
-- a row. That is the same trade `auth.login_succeeded` takes and the same
-- direction — over-reporting an attempt is a trail that is complete about what
-- was sent, and the alternative, committing afterwards, loses the record of
-- exactly the scan that failed halfway. The verb says which of the two this is.
--
-- WHAT REACHES THE ROW, AND WHAT DELIBERATELY DOES NOT
--
-- `detail` carries `mode` (`sync` or `async` — which endpoint served it),
-- `request_bytes` (an integer the gateway measured) and `api_key_id` (a UUID).
-- Every one is a bounded value the product already holds.
--
-- THE UPLOADED FILENAME IS NOT RECORDED, and this is the decision worth
-- writing down. 028 admits exactly one administrator-supplied string,
-- `target_label`, and admits it because a policy rule called "mask-emails"
-- needs its own name to read alone. An uploaded filename is not that: it is
-- END-USER content, chosen by whoever dragged the file into a chat window, and
-- in this product's own corpus filenames read like `Каримов_паспорт.pdf`. A
-- table that is never purged is the last place that belongs.
-- `tests/file_scan_routing.rs::the_uploaded_filename_never_reaches_the_audit_
-- trail` searches the stored row for it, with a positive control on the search
-- itself.
--
-- `target_id` is the request id — the same UUID the gateway returns in
-- `x-request-id` and writes into its access log — so a row here joins to the
-- request that produced it.
--
-- WHAT THE EXPORT NEEDED: NOTHING
--
-- 028's central claim, tested again here. The exporter selects every row of
-- `admin_audit` with no `action` predicate and passes the column through
-- verbatim as `event_type`, so this action reaches the signed artifact with no
-- change to `secureprompt-worker/src/tasks/audit_export.rs`. Only the
-- vocabulary moved: this constraint, `AdminAuditAction::ALL`, and the manifest
-- prose in `audit_export::CONTROL_COVERAGE`.
--
-- WHAT IS STILL NOT AUDITED HERE, AND IS NOT AN OVERSIGHT
--
--   * The RESULT of the scan. How many detections a document produced, and of
--     what class, is a statement about the document's contents; putting it in
--     a never-purged table would make the trail a summary of everyone's files.
--   * Polling a running async scan (`GET /v1/scan-file/tasks/{id}`). It starts
--     no work and moves no bytes — the kickoff that did is already recorded.
--   * A scan the gateway REFUSED. A viewer's rejected upload, an unauthenticated
--     one, or one over the body ceiling writes nothing, for 029's failed-login
--     reason: refusals must leave the trail in the same state whatever they
--     were refused for, or absence becomes an oracle.

ALTER TABLE admin_audit DROP CONSTRAINT admin_audit_action_known;

ALTER TABLE admin_audit ADD CONSTRAINT admin_audit_action_known CHECK (action IN (
    -- FU5 (migration 028), unchanged.
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
    'user.created',
    -- P1A (migration 029), unchanged.
    'two_factor.enrollment_started',
    'two_factor.enabled',
    'two_factor.disabled',
    'license.activated',
    'license.cleared',
    'budget.updated',
    'secure_mode.updated',
    'sidecar_policy.updated',
    'auth.login_succeeded',
    'auth.second_factor_verified',
    -- WS4-2.
    'file_scan.requested'
));
