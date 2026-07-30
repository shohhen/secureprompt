-- WS1 — demote `SSN` / `US_SSN` from default-on to OPT-IN on every workspace
-- that was already seeded or back-filled with them, RLS-safely.
--
-- ===========================================================================
-- ROW LEVEL SECURITY MAKES A BARE `UPDATE` SILENTLY DO NOTHING.
--
-- `policy_rules` has FORCE ROW LEVEL SECURITY with
--
--     USING (workspace_id = current_setting('app.current_workspace_id', true)::uuid)
--
-- (`001_init.sql:78-95`). The `true` second argument is `missing_ok`: when the
-- GUC is unset, `current_setting` returns NULL rather than raising, so the
-- predicate is NULL for every row and every row is invisible. An `UPDATE` that
-- matches zero rows is NOT an error — it reports `UPDATE 0` and exits 0, and
-- `sqlx migrate run` records the migration as applied. That is exactly how
-- `017_uzbek_identifier_policy_classes.sql` shipped as a no-op; see the header
-- of `020_reconcile_default_policy_classes.sql` for the measured evidence.
--
-- This file copies 020's shape: drive the update from a loop over
-- `workspaces` (which is NOT RLS-protected, so it is safe to read), setting
-- `app.current_workspace_id` for each one.
-- ===========================================================================
--
-- WHY
-- SecurePrompt is an Uzbekistan-market product and the US Social Security
-- Number is not a supported default class. `SOCIAL_SECURITY_NUMBER` appears
-- zero times across every active dataset under `data/**`; its only occurrences
-- are in the abandoned v4 corpus under `docs/backup_v4/`, where the generator
-- hallucinated a Cyrillic "ССН" into Uzbek HR documents. The deployed v8 model
-- has no training support for it. `secureprompt-api/src/db/workspace_repo.rs`
-- carries the full decision record on `OPT_IN_ONLY_CLASSES`.
--
-- DEMOTED, NOT DELETED. `Matcher::Ssn` and its `DetectorSpec` stay, so the
-- class is still DETECTED. This migration only stops it being REDACTED by the
-- seeded default rule. An admin re-enables it from the policy UI by adding the
-- class back to that rule.
--
-- 017 / 019 / 020 all back-filled `SSN` / `US_SSN` into existing workspaces, so
-- without this file the demotion would apply to newly created workspaces only
-- and every existing one would keep redacting a class the product no longer
-- supports by default. 020 is NOT edited: it is already applied on developer
-- and customer databases and changing a byte breaks the sqlx checksum. It
-- therefore still back-fills both spellings and this migration removes them
-- again, which is why
-- `policy::failclosed_tests::migration_class_list_drift_tests` compares 020's
-- surplus against `OPT_IN_ONLY_CLASSES` instead of asserting equality.
--
-- ── SAFETY: THE OPPOSITE POSTURE TO 020 ───────────────────────────────────
-- 020 only ever ADDS classes, so it could afford to be liberal and back-fill
-- any rule that was a SUPERSET of the original seed — an admin's own additions
-- survived an addition. THIS migration REMOVES, so being liberal is not
-- available: silently stripping a class from a rule an admin customised would
-- be the same class of defect as the back-fill that created this situation. A
-- customised rule may name SSN deliberately.
--
-- So a rule is touched only when its class set STILL EXACTLY MATCHES an
-- untouched seed. Exactly two shapes qualify, and set equality is tested with
-- `@>` in both directions so element ORDER and duplicates cannot matter:
--
--   1. the seed `create_with_owner` wrote immediately before the demotion,
--      which is also 020's back-fill list verbatim; and
--   2. that same list plus the two DEAD NAMES `GCP_KEY` / `AZURE_KEY`, which
--      is what 020 leaves on a workspace seeded before those were replaced.
--      They match nothing any detector emits, so they are preserved rather
--      than tidied away — removing them would change no behaviour while
--      risking one.
--
-- Anything else — narrowed, widened, renamed, replaced, or already demoted —
-- is left exactly as it is. A workspace whose rule was customised and which
-- genuinely wants the demotion must be updated by the operator from the
-- policy UI.
--
-- KEEPING THE LISTS HONEST
-- SQL cannot read a Rust `const`, so both lists are enumerated again below
-- between marker comments. The markers are load-bearing:
-- `policy::failclosed_tests::migration_024_drift_tests` parses each block and
-- FAILS THE BUILD unless
--   * PRE-DEMOTION SEED SHAPE == DEFAULT_POLICY_CLASSES + OPT_IN_ONLY_CLASSES
--   * OPT-IN ONLY CLASSES     == OPT_IN_ONLY_CLASSES
-- `GCP_KEY` / `AZURE_KEY` are deliberately OUTSIDE both blocks, so a parse
-- that over-reached would be caught by the guard's own premise test.

DO $$
DECLARE
    ws UUID;
    target_ids UUID[];
    candidates INT;
    updated INT;
    leftover INT;
    visible INT;
    total_workspaces INT := 0;
    total_visible INT := 0;
    total_updated INT := 0;

    -- The untouched seed as it stood immediately BEFORE the demotion. Equal
    -- to 020's back-fill list, which is what that migration leaves behind.
    pre_demotion_seed JSONB :=
-- >>> PRE-DEMOTION SEED SHAPE — must equal DEFAULT_POLICY_CLASSES + OPT_IN_ONLY_CLASSES (drift-guarded) >>>
        '[
            "PERSON",
            "EMAIL_ADDRESS",
            "PHONE_NUMBER",
            "CREDIT_CARD",
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
            "JWT",
            "SSN",
            "US_SSN"
        ]'::jsonb;
-- <<< END PRE-DEMOTION SEED SHAPE <<<

    -- The classes this migration strips.
    opt_in_only JSONB :=
-- >>> OPT-IN ONLY CLASSES — must equal OPT_IN_ONLY_CLASSES (drift-guarded) >>>
        '["SSN", "US_SSN"]'::jsonb;
-- <<< END OPT-IN ONLY CLASSES <<<

    -- Shape 2: what 020 leaves on a workspace seeded before the dead names
    -- were replaced. Assembled here so the dead names stay outside the
    -- drift-guarded blocks above.
    reconciled_legacy JSONB;
BEGIN
    reconciled_legacy := pre_demotion_seed || '["GCP_KEY", "AZURE_KEY"]'::jsonb;

    FOR ws IN SELECT id FROM workspaces
    LOOP
        total_workspaces := total_workspaces + 1;

        -- The GUC the RLS predicate reads. `is_local = true` scopes it to
        -- this migration's transaction.
        PERFORM set_config('app.current_workspace_id', ws::text, true);

        SELECT count(*) INTO visible FROM policy_rules WHERE workspace_id = ws;
        total_visible := total_visible + visible;

        -- Collect the target rows ONCE, so the count, the update and the
        -- post-condition below are provably about the same rows rather than
        -- about three copies of a predicate that could drift apart.
        SELECT array_agg(id) INTO target_ids
        FROM policy_rules
        WHERE workspace_id = ws
          AND name = 'Redact common PII'
          AND jsonb_typeof(conditions) = 'array'
          AND jsonb_array_length(conditions) > 0
          AND conditions -> 0 ->> 'field' = 'detection_class'
          AND conditions -> 0 ->> 'op' = 'in'
          AND jsonb_typeof(conditions -> 0 -> 'value') = 'array'
          -- Set equality in BOTH directions, so element order and duplicates
          -- cannot decide whether a rule is the untouched seed.
          --
          -- The parentheses around the right-hand `->` chains are REQUIRED,
          -- not style. `@>` and `->` share a precedence class in Postgres and
          -- associate LEFT, so `seed @> conditions -> 0 -> 'value'` parses as
          -- `((seed @> conditions) -> 0) -> 'value'` and fails at plan time
          -- with `operator does not exist: boolean -> integer`. The
          -- left-hand form needs no parentheses for the same reason.
          AND (
                   (conditions -> 0 -> 'value' @> pre_demotion_seed
                    AND pre_demotion_seed @> (conditions -> 0 -> 'value'))
                OR (conditions -> 0 -> 'value' @> reconciled_legacy
                    AND reconciled_legacy @> (conditions -> 0 -> 'value'))
              );

        candidates := COALESCE(array_length(target_ids, 1), 0);

        -- Rebuild the class array keeping everything that is NOT demoted,
        -- rather than deleting by index: index arithmetic would depend on
        -- element ORDER, and the seed match above deliberately does not.
        UPDATE policy_rules
        SET conditions = jsonb_set(
                conditions,
                '{0,value}',
                (
                    SELECT COALESCE(jsonb_agg(kept.class), '[]'::jsonb)
                    FROM jsonb_array_elements(policy_rules.conditions -> 0 -> 'value')
                        AS kept(class)
                    WHERE NOT opt_in_only @> jsonb_build_array(kept.class)
                )
            ),
            updated_at = NOW()
        WHERE id = ANY(target_ids);

        GET DIAGNOSTICS updated = ROW_COUNT;
        total_updated := total_updated + updated;

        IF updated <> candidates THEN
            RAISE EXCEPTION
                'demote-ssn: workspace % matched % candidate rule(s) but the UPDATE touched %',
                ws, candidates, updated;
        END IF;

        -- THE ASSERTION THAT MATTERS. `UPDATE n` proves rows were written, not
        -- that the right bytes were written: a `jsonb_set` addressing the wrong
        -- path reports the same `n` and changes nothing. Re-read the rows just
        -- written and fail if any still carries a demoted class.
        SELECT count(*) INTO leftover
        FROM policy_rules
        WHERE id = ANY(target_ids)
          AND EXISTS (
                SELECT 1
                FROM jsonb_array_elements(conditions -> 0 -> 'value') AS remaining(class)
                WHERE opt_in_only @> jsonb_build_array(remaining.class)
              );

        IF leftover > 0 THEN
            RAISE EXCEPTION
                'demote-ssn: % rule(s) in workspace % still carry an opt-in-only class after the UPDATE reported % row(s) written',
                leftover, ws, updated;
        END IF;
    END LOOP;

    -- The 017 signature: workspaces exist but not one policy rule was visible
    -- from inside the loop, which is what RLS blindness looks like. A WARNING
    -- rather than an EXCEPTION because a deployment whose rules were all
    -- deleted would produce the same reading, and aborting an upgrade on that
    -- ambiguity is worse than reporting it.
    IF total_workspaces > 0 AND total_visible = 0 THEN
        RAISE WARNING
            'demote-ssn: % workspace(s) exist but NO policy_rules row was visible — if this database was migrated by a role without BYPASSRLS the back-fill has silently done nothing; see the header of 020',
            total_workspaces;
    END IF;

    RAISE NOTICE
        'demote-ssn: % workspace(s), % visible policy rule(s), % rule(s) demoted',
        total_workspaces, total_visible, total_updated;

    -- The GUC is intentionally NOT reset. It was set with is_local = true, so
    -- it dies with this migration's transaction. Resetting it to '' would be
    -- actively worse: the RLS predicate casts it with `::uuid`, and ''::uuid
    -- raises `invalid input syntax for type uuid` rather than yielding NULL.
END $$;
