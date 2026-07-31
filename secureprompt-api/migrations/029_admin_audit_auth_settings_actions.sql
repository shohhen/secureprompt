-- P1A — ten more actions in the vocabulary migration 028 closed.
--
-- WHY THIS IS A NEW MIGRATION AND NOT AN EDIT TO 028
--
-- `sqlx migrate` records a checksum per migration. Editing 028 in place would
-- make every already-migrated deployment refuse to start, so the CHECK
-- constraint is DROPPED and re-added here under the SAME NAME. The name is
-- load-bearing: `tests/admin_audit.rs::the_action_vocabulary_is_pinned_in_three
-- _places` and `worker/tasks/audit_export/tests.rs::every_audited_action_reaches
-- _the_signed_export` both read the vocabulary out of
-- `pg_get_constraintdef(oid) WHERE conname = 'admin_audit_action_known'`, so
-- renaming it would silently disarm two tests rather than fail one.
--
-- WHAT THESE TEN ACTIONS ARE
--
-- 028's header and `audit_export::CONTROL_COVERAGE` both listed, by name, the
-- administrative surfaces FU5 had NOT reached. This closes four of them:
--
--   * 2FA — `two_factor.enrollment_started`, `two_factor.enabled`,
--     `two_factor.disabled`. Three events and not one, because until a code
--     verifies the account is still password-only: a trail that said "2FA
--     enabled" when the QR code was displayed would be wrong. There is no
--     separate backup-code regeneration endpoint in this product — `/enroll`
--     re-issues the codes, and `two_factor.enrollment_started` carries
--     `backup_codes_issued` because how many recovery credentials now exist IS
--     the auditable fact.
--   * License — `license.activated`, `license.cleared`. Which license this
--     deployment runs under decides what the product will do, and the console
--     lets an administrator change it by pasting a string.
--   * Settings — `budget.updated`, `secure_mode.updated`,
--     `sidecar_policy.updated`. Three actions and not one, even though the last
--     two share a single PUT, because they answer different auditor questions:
--     "was redaction on?" and "what did this gateway do when the redactor was
--     down?". One combined row would make the second unanswerable.
--   * Login — `auth.login_succeeded`, `auth.second_factor_verified`. See below.
--
-- WHAT THE EXPORT NEEDED: NOTHING
--
-- This is 028's central claim, and P1A is the first test of it. The exporter
-- selects every row of `admin_audit` with no `action` predicate and passes the
-- column through verbatim as `event_type`, so these ten actions reached the
-- signed artifact with no change to
-- `secureprompt-worker/src/tasks/audit_export.rs` at all. The only thing that
-- had to move was the vocabulary — this constraint, `AdminAuditAction::ALL`,
-- and the manifest prose — which is exactly the drift the pinning test exists
-- to catch.
--
-- WHY `auth.login_succeeded` IS RECORDED FOR OUTCOMES THAT ISSUED NO SESSION
--
-- The row is written the moment the FIRST factor verifies, and `detail.outcome`
-- says what happened next: `session_issued`, `second_factor_required` or
-- `enrolment_required`. A login stopped at the 2FA gate is a real event —
-- somebody had the correct password — and recording it as a completed login
-- would be a lie while recording nothing would lose the fact. Clearing the
-- challenge is `auth.second_factor_verified`, a second event, because the
-- challenge token carries no memory of HOW the first factor was proven and
-- folding the two together would mean storing an unknown.
--
-- WHAT IS STILL NOT AUDITED, AND WHY IT IS NOT AN OVERSIGHT
--
-- A FAILED login writes nothing, for the reason FU5 gave when it declined the
-- case: `workspace_id` is NOT NULL under FORCE RLS and an attempt against an
-- unknown email has no tenant. Inventing one would put the row in a real
-- tenant's signed export; recording the submitted identifier would be an
-- enumeration surface; and auditing ONLY the attempts that resolve would make
-- row-absence MEAN "no such account" — an oracle built out of an audit trail,
-- which is worse than the gap. `tests/admin_audit.rs::a_failed_login_is_
-- indistinguishable_from_a_login_for_an_account_that_does_not_exist` pins the
-- two refusals as leaving the trail in the SAME state, so a later partial
-- implementation goes red instead of shipping the oracle. Failed-login
-- auditing needs a store that is not tenant-scoped and an export treatment of
-- its own; it is its own task.
--
-- NO NEW COLUMN, AND IN PARTICULAR NO ADDRESS AND NO DEVICE
--
-- A login is the one audited action whose request carries a User-Agent and an
-- `X-Forwarded-For`, so it is the obvious place to start storing them. This
-- table does not, and the reason is stronger than 028's general discipline:
-- FU4 records the device on the SESSION row and ERASES it when that session
-- ends (commit f2de9f3). A copy here would undo that erasure permanently,
-- because this table is never purged. `tests/admin_audit.rs::a_successful_
-- password_login_is_audited_without_the_device_or_the_address` sends both
-- headers and asserts that neither the raw string, nor FU4's `{browser} on
-- {os}` reduction of it, nor the parsed address appears in any column.

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
    -- P1A.
    'two_factor.enrollment_started',
    'two_factor.enabled',
    'two_factor.disabled',
    'license.activated',
    'license.cleared',
    'budget.updated',
    'secure_mode.updated',
    'sidecar_policy.updated',
    'auth.login_succeeded',
    'auth.second_factor_verified'
));
