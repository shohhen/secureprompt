-- WS2-1 — back-fill the seeded "Redact common PII" rule with the Uzbek /
-- CIS identifier classes.
--
-- WHY A MIGRATION AND NOT A DOCUMENTED OPERATOR ACTION
-- The Rust floor now detects PINFL / STIR / MFO / passport / Uzcard / Humo,
-- but detection is not redaction. Every workspace created before this change
-- carries a `detection_class in [...]` redact rule listing only the nine
-- original classes. Because that rule exists, `rules_evaluated == 1`, which
-- suppresses the `redact_when_no_rules` safety net in `pipeline/service.rs`;
-- and `policy/engine.rs::matching_detections` only falls back to "redact
-- everything" when the class filter matches NOTHING. So on any prompt that
-- also contains a covered class — a name, an email, a phone — the Uzbek
-- identifiers were detected and then forwarded in the clear.
--
-- Leaving that to an operator action would mean every existing customer stays
-- unprotected until someone notices and hand-edits a JSON array in the policy
-- UI, while new workspaces are protected automatically. For the product's
-- flagship security control that is not an acceptable default, so the
-- back-fill ships here.
--
-- SAFETY
-- Deliberately conservative — it only ever ADDS classes, and only to rules
-- that still look like the untouched seed:
--   * name = 'Redact common PII' (the seeded rule, not an admin's own rule);
--   * conditions[0] is a `detection_class in [...]` condition;
--   * that array is still a SUPERSET of the original nine defaults, so a rule
--     an admin deliberately NARROWED is left alone (an admin who removed
--     CREDIT_CARD meant it, and we do not second-guess that);
--   * at least one of the six new classes is missing, which makes the
--     statement idempotent.
-- An admin who ADDED classes still gets the back-fill, since a superset test
-- passes for them.
--
-- Only the classes actually MISSING are appended, so an admin who had already
-- added, say, STIR by hand does not end up with a duplicate entry.
--
-- Workspaces whose rule was narrowed, renamed, or replaced are intentionally
-- untouched and must be updated by the operator from the policy UI.

UPDATE policy_rules
SET conditions = jsonb_set(
        conditions,
        '{0,value}',
        (conditions -> 0 -> 'value') || (
            SELECT COALESCE(jsonb_agg(candidate.class), '[]'::jsonb)
            FROM jsonb_array_elements('[
                     "PINFL",
                     "STIR",
                     "MFO",
                     "PASSPORT_NUMBER",
                     "UZCARD",
                     "HUMO"
                 ]'::jsonb) AS candidate(class)
            WHERE NOT (policy_rules.conditions -> 0 -> 'value')
                      @> jsonb_build_array(candidate.class)
        )
    ),
    updated_at = NOW()
WHERE name = 'Redact common PII'
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
        "PINFL",
        "STIR",
        "MFO",
        "PASSPORT_NUMBER",
        "UZCARD",
        "HUMO"
      ]'::jsonb);
