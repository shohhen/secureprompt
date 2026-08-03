-- WS1 — reconcile every seeded "Redact common PII" rule against the CURRENT
-- default class list, RLS-safely.
--
-- ===========================================================================
-- READ THIS BEFORE WRITING ANY MIGRATION THAT TOUCHES A TENANT TABLE.
--
-- ROW LEVEL SECURITY MAKES A BARE `UPDATE` SILENTLY DO NOTHING.
--
-- `policy_rules` (and `api_keys`, `providers`, `models`, `audit_events_meta`)
-- has FORCE ROW LEVEL SECURITY with
--
--     USING (workspace_id = current_setting('app.current_workspace_id', true)::uuid)
--
-- see `001_init.sql:78-95`. The `true` second argument is `missing_ok`: when
-- the GUC is unset, `current_setting` returns NULL rather than raising, so the
-- predicate is NULL for every row, so every row is invisible. An `UPDATE` that
-- matches zero rows is NOT an error — it reports `UPDATE 0` and exits 0, and
-- `sqlx migrate run` records the migration as applied. The back-fill ships as
-- a no-op and nothing anywhere reports a problem.
--
-- Measured, on a database with all migrations applied and two seeded
-- workspaces, running `017_uzbek_identifier_policy_classes.sql` (a bare
-- UPDATE) as a NOSUPERUSER/NOBYPASSRLS role:
--
--     UPDATE 0
--     exit=0
--
-- ...and the rows were unchanged. It looks correct on every developer machine
-- today only because the compose `secureprompt` role is a SUPERUSER
-- (`rolsuper = t`, `rolbypassrls = t`) and superusers bypass RLS
-- unconditionally. Under the DB role-split on this project's backlog, that
-- stops being true.
--
-- THE FIX, and the pattern to copy: drive the update from a loop over
-- `workspaces` (which is NOT RLS-protected, so it is safe to read), setting
-- `app.current_workspace_id` for each one. `019_credential_policy_classes.sql`
-- was written this way and is verified to work under a non-superuser role;
-- `017` was not. Guarded by `secureprompt-api/tests/migration_020_rls.rs`,
-- which executes this file as an explicitly NOSUPERUSER/NOBYPASSRLS role.
-- ===========================================================================
--
-- WHAT THIS REPAIRS
-- 017 back-filled the six Uzbek / CIS identifier classes (PINFL, STIR, MFO,
-- PASSPORT_NUMBER, UZCARD, HUMO) with a bare UPDATE. On any database migrated
-- by a role without BYPASSRLS it did nothing. 019 back-filled the credential
-- classes and WAS written RLS-safely — but its candidate list contains none of
-- the six, so such a database ends up with the original nine defaults plus
-- credentials and still no Uzbek identifiers. The deterministic Uzbek
-- detection floor then fires and the policy layer DISCARDS the detections,
-- because `policy/engine.rs::matching_detections` only falls back to "redact
-- everything" when the class filter matches NOTHING — and on a prompt that
-- also contains a name or an email it matches something.
--
-- Rather than back-fill another delta (which is how 017 and 019 drifted apart
-- in the first place), this migration reconciles against the FULL current
-- default list. Whichever earlier back-fill no-opped, this one closes the gap.
-- It is a superset of both 017's and 019's candidate lists, so it supersedes
-- both; neither is edited, because both are already applied on developer
-- databases and changing a byte breaks the sqlx checksum.
--
-- KEEPING THE LIST HONEST
-- `DEFAULT_POLICY_CLASSES` in `secureprompt-api/src/db/workspace_repo.rs` is
-- the source of truth, and SQL cannot read a Rust const, so it is enumerated
-- again below. The marker comments around it are load-bearing:
-- `policy::failclosed_tests::migration_class_list_drift_tests` parses the
-- block between them and FAILS THE BUILD if it is not exactly equal to
-- `DEFAULT_POLICY_CLASSES`. Add a class to the Rust const without adding it
-- here (which is what happened with the six Uzbek classes) and the test says
-- so. Keep the list inside the markers, and keep it in one place only.
--
-- SAFETY (unchanged from 017 / 019 — deliberately conservative)
-- Only ever ADDS classes, and only to rules that still look like the
-- untouched seed:
--   * name = 'Redact common PII' (the seeded rule, not an admin's own rule);
--   * conditions[0] is a `detection_class in [...]` condition;
--   * that array is still a SUPERSET of the original nine defaults, so a rule
--     an admin deliberately NARROWED is left alone (an admin who removed
--     CREDIT_CARD meant it, and we do not second-guess that);
--   * at least one default class is missing, which makes it idempotent.
-- An admin who ADDED classes still gets the back-fill, since a superset test
-- passes for them, and their own additions survive.
--
-- Only the classes actually MISSING are appended, so no duplicates.
--
-- `GCP_KEY` / `AZURE_KEY` appear in the seed guard but NOT in the back-fill
-- list. They are DEAD NAMES — nothing any detector emits matches them (the
-- registry emits `google_api_key` and `azure_storage_connection_string`) — so
-- they were removed from `DEFAULT_POLICY_CLASSES`. They stay in the guard
-- because the guard's job is to recognise the legacy shape, and the legacy
-- shape contains them. Rows that already carry them keep them: they match
-- nothing, so removing them would change no behaviour while risking one.
--
-- Workspaces whose rule was narrowed, renamed, or replaced are intentionally
-- untouched and must be updated by the operator from the policy UI.

DO $$
DECLARE
    ws UUID;
    default_classes JSONB :=
-- >>> BACKFILL CLASS LIST — must equal DEFAULT_POLICY_CLASSES (drift-guarded) >>>
        '[
            "PERSON",
            "EMAIL_ADDRESS",
            "PHONE_NUMBER",
            "CREDIT_CARD",
            "US_SSN",
            "SSN",
            "IBAN_CODE",
            "IBAN",
            "PINFL",
            "STIR",
            "MFO",
            "PASSPORT_NUMBER",
            "UZCARD",
            "HUMO",
            "AWS_ACCESS_KEY",
            "GOOGLE_API_KEY",
            "GCP_SERVICE_ACCOUNT_EMAIL",
            "AZURE_STORAGE_CONNECTION_STRING",
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "STRIPE_SECRET_KEY",
            "STRIPE_PUBLISHABLE_KEY",
            "GITHUB_PAT",
            "GITHUB_FINE_GRAINED_PAT",
            "GITHUB_OAUTH_TOKEN",
            "GITHUB_REFRESH_TOKEN",
            "SLACK_BOT_TOKEN",
            "SLACK_USER_TOKEN",
            "SLACK_APP_TOKEN",
            "PRIVATE_KEY_PEM",
            "RSA_PRIVATE_KEY",
            "OPENSSH_PRIVATE_KEY",
            "POSTGRESQL_URI",
            "MONGODB_URI",
            "WEBHOOK_URL",
            "BEARER_TOKEN",
            "BASIC_AUTH_HEADER",
            "PASSWORD_ASSIGNMENT",
            "OAUTH_CLIENT_SECRET",
            "API_TOKEN_GENERIC",
            "JWT"
        ]'::jsonb;
-- <<< END BACKFILL CLASS LIST <<<
BEGIN
    FOR ws IN SELECT id FROM workspaces
    LOOP
        -- The GUC the RLS predicate reads. `is_local = true` scopes it to this
        -- migration's transaction.
        PERFORM set_config('app.current_workspace_id', ws::text, true);

        UPDATE policy_rules
        SET conditions = jsonb_set(
                conditions,
                '{0,value}',
                (conditions -> 0 -> 'value') || (
                    SELECT COALESCE(jsonb_agg(candidate.class), '[]'::jsonb)
                    FROM jsonb_array_elements(default_classes) AS candidate(class)
                    WHERE NOT (policy_rules.conditions -> 0 -> 'value')
                              @> jsonb_build_array(candidate.class)
                )
            ),
            updated_at = NOW()
        WHERE workspace_id = ws
          AND name = 'Redact common PII'
          AND jsonb_typeof(conditions) = 'array'
          AND jsonb_array_length(conditions) > 0
          AND conditions -> 0 ->> 'field' = 'detection_class'
          AND conditions -> 0 ->> 'op' = 'in'
          AND jsonb_typeof(conditions -> 0 -> 'value') = 'array'
          -- Still the untouched seed? The original nine, dead names included.
          AND conditions -> 0 -> 'value' @> '[
                "PERSON",
                "EMAIL_ADDRESS",
                "PHONE_NUMBER",
                "CREDIT_CARD",
                "US_SSN",
                "IBAN_CODE",
                "AWS_ACCESS_KEY",
                "GCP_KEY",
                "AZURE_KEY"
              ]'::jsonb
          -- Idempotence: only fire when something is actually missing.
          AND NOT (conditions -> 0 -> 'value' @> default_classes);
    END LOOP;
    -- The GUC is intentionally NOT reset. It was set with is_local = true, so
    -- it dies with this migration's transaction. Resetting it to '' would be
    -- actively worse: the RLS predicate casts it with `::uuid`, and ''::uuid
    -- raises `invalid input syntax for type uuid` rather than yielding NULL,
    -- which would break any later statement in the same transaction.
END $$;
