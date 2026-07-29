-- FIX-WAVE — back-fill the seeded "Redact common PII" rule with EVERY
-- CREDENTIAL class the detection registry emits.
--
-- WHY A MIGRATION AND NOT A DOCUMENTED OPERATOR ACTION
-- Identical reasoning to `017_uzbek_identifier_policy_classes.sql`, which
-- this deliberately mirrors statement-for-statement — read that file first.
-- The short version: detection is not redaction. `DEFAULT_POLICY_CLASSES`
-- carried 15 classes while `detection/registry.rs` emits 37, and NOT ONE of
-- the 15 was a credential. Because the seeded rule exists,
-- `rules_evaluated == 1`, which suppressed the `redact_when_no_rules` safety
-- net in `pipeline/service.rs`; and `policy/engine.rs::matching_detections`
-- only falls back to "redact everything" when the class filter matches
-- NOTHING. So on any prompt that ALSO contained a covered class — a name, an
-- email, a phone — every detected credential was forwarded in the clear.
-- A prompt with an email and a bearer token redacted the email and shipped
-- the token.
--
-- Leaving that to an operator action would mean every existing customer stays
-- unprotected until someone notices and hand-edits a JSON array in the policy
-- UI, while new workspaces are protected automatically. For the product's
-- flagship security control that is not an acceptable default.
--
-- DEAD NAMES
-- `GCP_KEY` and `AZURE_KEY` in the pre-existing list match NOTHING the
-- registry ever emits (it emits `google_api_key`, `gcp_service_account_email`
-- and `azure_storage_connection_string`). The real spellings are appended
-- below. The dead strings are left in place: they match nothing, so removing
-- them changes no behaviour, and the superset guard below is keyed on them —
-- rewriting the array would break the "is this still the untouched seed?"
-- test for the very rows this is trying to fix.
--
-- `SSN` / `IBAN` are appended alongside `US_SSN` / `IBAN_CODE` because BOTH
-- spellings are live: the Rust regex floor emits `ssn` / `iban` (only
-- upper-cased by `normalize_class`), the Python sidecar emits Presidio's
-- `US_SSN` / `IBAN_CODE`.
--
-- ROW LEVEL SECURITY
-- `policy_rules` has FORCE ROW LEVEL SECURITY with
-- `USING (workspace_id = current_setting('app.current_workspace_id', true)::uuid)`
-- (see `001_init.sql`). `current_setting(..., true)` returns NULL when the
-- GUC is unset, so a bare `UPDATE policy_rules ...` in a migration matches
-- ZERO rows and silently succeeds — which is how a back-fill can look like it
-- shipped while touching nothing. Every workspace is therefore visited
-- explicitly with the GUC set. `workspaces` itself is not RLS-protected, so
-- it is safe to drive the loop from.
--
-- SAFETY (identical to 017)
-- Deliberately conservative — it only ever ADDS classes, and only to rules
-- that still look like the untouched seed:
--   * name = 'Redact common PII' (the seeded rule, not an admin's own rule);
--   * conditions[0] is a `detection_class in [...]` condition;
--   * that array is still a SUPERSET of the original nine defaults, so a rule
--     an admin deliberately NARROWED is left alone (an admin who removed
--     CREDIT_CARD meant it, and we do not second-guess that);
--   * at least one of the new classes is missing, which makes the statement
--     idempotent.
-- An admin who ADDED classes still gets the back-fill, since a superset test
-- passes for them.
--
-- Only the classes actually MISSING are appended, so an admin who had already
-- added, say, JWT by hand does not end up with a duplicate entry.
--
-- Workspaces whose rule was narrowed, renamed, or replaced are intentionally
-- untouched and must be updated by the operator from the policy UI.

DO $$
DECLARE
    ws UUID;
BEGIN
    FOR ws IN SELECT id FROM workspaces
    LOOP
        PERFORM set_config('app.current_workspace_id', ws::text, true);

        UPDATE policy_rules
        SET conditions = jsonb_set(
                conditions,
                '{0,value}',
                (conditions -> 0 -> 'value') || (
                    SELECT COALESCE(jsonb_agg(candidate.class), '[]'::jsonb)
                    FROM jsonb_array_elements('[
                             "SSN",
                             "IBAN",
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
                         ]'::jsonb) AS candidate(class)
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
          AND NOT (conditions -> 0 -> 'value' @> '[
                "SSN",
                "IBAN",
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
              ]'::jsonb);
    END LOOP;
    -- The GUC is intentionally NOT reset. It was set with is_local = true, so
    -- it dies with this migration's transaction. Resetting it to '' would be
    -- actively worse: the RLS predicate casts it with `::uuid`, and ''::uuid
    -- raises `invalid input syntax for type uuid` rather than yielding NULL,
    -- which would break any later statement in the same transaction.
END $$;
