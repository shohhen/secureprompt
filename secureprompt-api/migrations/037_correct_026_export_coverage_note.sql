-- Correct the record: migration 026's header states a gap that FU1 closed.
--
-- WHAT IS WRONG WHERE
--
-- `026_session_revocation_audit.sql` ends its "WHY NOT request_events"
-- argument with:
--
--   CONSEQUENCE, STATED RATHER THAN HIDDEN: revocation events are therefore
--   NOT carried by `audit.export`. ... That is a real gap in what a signed
--   export contains, and it is disclosed here and in the WS4-3 report rather
--   than discovered later.
--
-- That was true when 026 was written and stopped being true two commits later,
-- in the same merge request. `session_revocation_audit` is listed in
-- `CONTROL_SOURCE_TABLES` (`secureprompt-common/src/audit_export.rs`), the
-- `control_plane_events` section carries every row of it, and
-- `docs/audit-export-format.md` documents it that way. An operator reading 026
-- is told a signed export omits revocation events. It does not.
--
-- WHY THIS IS A NEW MIGRATION AND NOT AN EDIT TO 026
--
-- `sqlx::migrate!` validates checksums, and `db/migrations.rs` says so in as
-- many words: "a checksum divergence means a historical migration file was
-- edited after being applied, which `MIGRATOR.run` already refuses". Editing
-- 026 in place would refuse to start on every deployment that has applied it.
-- So the correction is appended rather than backdated, which is also the
-- honest shape: the original disclosure was accurate on the day it was made.
--
-- WHAT THIS MIGRATION CHANGES
--
-- Nothing about the schema. It writes the correction into the table's own
-- catalog comment, so `\d+ session_revocation_audit` and any schema dump
-- carry it to the next reader — including one who never opens the migration
-- directory. `COMMENT ON` is idempotent and re-running it is a no-op.

COMMENT ON TABLE session_revocation_audit IS
    'WS4-3. One row per accepted session revocation, written in the same '
    'transaction as the refresh-token revocation it records. '
    'CARRIED BY `audit.export`: yes, in the `control_plane_events` section, '
    'as one of the CONTROL_SOURCE_TABLES. Migration 026''s header says the '
    'opposite — it predates FU1, which added the control-plane section, and '
    'cannot be edited because sqlx validates migration checksums. '
    'Never purged; no ip_address, no user_agent, no free-text reason, by '
    'design (see 026).';
