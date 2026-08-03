//! Fix-wave tests for the four policy defects (FIX 1-4).
//!
//! Kept in their own file rather than appended to `tests.rs` so the
//! pre-existing WS1-8 / WS2-1 suites stay readable.

/// FIX 1 — the seeded default policy discarded EVERY credential detection.
///
/// `DEFAULT_POLICY_CLASSES` listed 15 classes while the registry emits ~37;
/// not one of the 15 was a credential. Because the seeded rule exists,
/// `rules_evaluated == 1` suppresses the `redact_when_no_rules` safety net,
/// and `matching_detections` falls back to "redact everything" ONLY when the
/// class filter matches nothing. So a prompt carrying an email AND a bearer
/// token redacted the email and SHIPPED the credential.
///
/// The headline test goes through `evaluate` AND through the real detector
/// registry on purpose: a fixture that hand-builds
/// `Detection { class: "BEARER_TOKEN" }` would still pass if the registry
/// actually emitted some other spelling — which is exactly how the dead
/// `GCP_KEY` / `AZURE_KEY` entries survived for so long.
#[cfg(test)]
mod credential_policy_path_tests {
    use crate::db::{PolicyRepository, WorkspaceRepository};
    use crate::detection::{detect_content, merge::merge_detections};
    use crate::policy::engine::{evaluate, PolicyEvaluationInput, PolicyEvaluationOutcome};
    use secureprompt_common::types::{Detection, RequestId, TokenVault, WorkspaceId};
    use sqlx::PgPool;
    use std::collections::HashMap;
    use uuid::Uuid;

    /// Synthetic throughout. The email is load-bearing: without a detection
    /// whose class IS in the seeded list, `matching_detections` falls back to
    /// redacting everything and the bug hides.
    const EMAIL: &str = "qa-fixture@example.invalid";
    const BEARER: &str = "skfixtureabcdefghijklmnopqrstuvwxyz012345";
    const CITY: &str = "Tashkent";

    async fn eval_default_policy(
        pool: &PgPool,
        content: &str,
        detections: &[Detection],
        fail_closed: bool,
    ) -> PolicyEvaluationOutcome {
        let hash = crate::db::user_repo::hash_password("pw-for-test-only").unwrap();
        let (workspace, _) = WorkspaceRepository::new(pool.clone())
            .create_with_owner(
                "Credential Path Co",
                &format!("cred-path-{}@example.invalid", Uuid::new_v4()),
                &hash,
            )
            .await
            .expect("workspace + seeded rule must be created");

        let mut vault = TokenVault::default();
        let mut redaction_map: HashMap<String, String> = HashMap::new();
        let outcome = evaluate(
            &PolicyRepository::new(pool.clone()),
            PolicyEvaluationInput {
                request_id: RequestId::new(),
                workspace_id: WorkspaceId(workspace.id),
                provider_name: "none",
                model: "none",
                content,
                detections,
                fail_closed,
            },
            &mut vault,
            &mut redaction_map,
        )
        .await
        .expect("policy evaluation must succeed");

        assert_eq!(
            outcome.rules_evaluated, 1,
            "premise: the seeded rule must be the one and only rule — at 0 the \
             redact_when_no_rules net would mask the bug under test"
        );
        outcome
    }

    /// Two hand-built detections: one class the seeded rule names, one it
    /// deliberately does not. `LOCATION` is the natural "not named" class —
    /// the curated list leaves out LOCATION/ORGANIZATION/GPE so that
    /// "tell me about Apple" is not mangled.
    fn mixed_fixture() -> (String, Vec<Detection>) {
        let content = format!("Contact {EMAIL} in {CITY}");
        let email_at = content.find(EMAIL).unwrap();
        let city_at = content.find(CITY).unwrap();
        let detections = vec![
            Detection {
                class: "EMAIL_ADDRESS".to_owned(),
                confidence: 0.99,
                span: Some((email_at, email_at + EMAIL.len())),
                value: EMAIL.to_owned(),
            },
            Detection {
                class: "LOCATION".to_owned(),
                confidence: 0.99,
                span: Some((city_at, city_at + CITY.len())),
                value: CITY.to_owned(),
            },
        ];
        (content, detections)
    }

    /// THE defect: an email plus a bearer token through the POLICY path.
    ///
    /// Runs with `fail_closed: false` so the ONLY thing that can redact the
    /// credential is `DEFAULT_POLICY_CLASSES` naming its class.
    ///
    /// Deletion check: remove `"BEARER_TOKEN"` from `DEFAULT_POLICY_CLASSES`
    /// in `db/workspace_repo.rs` — this test reddens, its sibling does not.
    #[sqlx::test]
    async fn default_policy_redacts_a_bearer_token_alongside_an_email(pool: PgPool) {
        let content = format!("Contact {EMAIL}\nAuthorization: Bearer {BEARER}\n");
        let detections = merge_detections(detect_content(&content), vec![]);

        // PREMISE. Both assertions below are about an ABSENCE, so first prove
        // the detector actually produced the two classes at issue. Without
        // this the test passes just as happily against a detector that found
        // nothing at all.
        let classes: Vec<&str> = detections.iter().map(|d| d.class.as_str()).collect();
        assert!(
            classes.contains(&"EMAIL_ADDRESS"),
            "premise: the email must be detected, got {classes:?}"
        );
        assert!(
            classes.contains(&"BEARER_TOKEN"),
            "premise: the bearer token must be detected, got {classes:?}"
        );

        let outcome = eval_default_policy(&pool, &content, &detections, false).await;
        assert_eq!(outcome.result.final_action, "redact");

        assert!(
            !outcome.content.contains(EMAIL),
            "email leaked: {:?}",
            outcome.content
        );
        assert!(
            !outcome.content.contains(BEARER),
            "CREDENTIAL LEAKED — detected and then forwarded in the clear by \
             the default policy: {:?}",
            outcome.content
        );
    }

    /// POSITIVE CONTROL for the test above, and the premise that its
    /// `!contains` assertions are capable of failing at all.
    ///
    /// Same code path, same shape of assertion, DIFFERENT expected result: a
    /// class the seeded rule does not name is still forwarded when
    /// `fail_closed` is off. If this ever starts redacting, the test above
    /// proves nothing — everything would be redacted regardless of the list.
    #[sqlx::test]
    async fn unlisted_class_is_forwarded_when_not_fail_closed(pool: PgPool) {
        let (content, detections) = mixed_fixture();
        let outcome = eval_default_policy(&pool, &content, &detections, false).await;

        assert!(
            !outcome.content.contains(EMAIL),
            "premise: the listed class must be redacted, otherwise the rule \
             never fired and this proves nothing: {:?}",
            outcome.content
        );
        assert!(
            outcome.content.contains(CITY),
            "control: an unlisted class must still be forwarded when \
             fail_closed is off, otherwise the sibling tests are vacuous: {:?}",
            outcome.content
        );
    }

    /// FIX 1, second layer. With `fail_closed` on (the production default,
    /// `config.redact_when_no_rules`), a firing `redact` rule must cover
    /// EVERY detection in the request, not only the classes it names. This is
    /// what stops `DEFAULT_POLICY_CLASSES` from silently rotting the next
    /// time a detector class is added.
    ///
    /// Same fixture as the control above, opposite expected result.
    ///
    /// Deletion check: revert the `if input.fail_closed` branch in
    /// `engine.rs`'s `"redact"` arm back to `&matching` — this reddens, the
    /// control above does not.
    #[sqlx::test]
    async fn fail_closed_redacts_a_class_the_rule_does_not_name(pool: PgPool) {
        let (content, detections) = mixed_fixture();
        let outcome = eval_default_policy(&pool, &content, &detections, true).await;

        assert!(
            !outcome.content.contains(CITY),
            "fail_closed: a detection the rule does not name must still be \
             redacted once the rule fires: {:?}",
            outcome.content
        );
        assert!(
            !outcome.content.contains(EMAIL),
            "the named class must obviously still be redacted: {:?}",
            outcome.content
        );
    }
}

/// FIX 2 (WS1-8 fails OPEN) + FIX 3 (WS1-6a policy redaction fail-open).
///
/// An enabled rule that does not match — or CANNOT match — still counts
/// toward `rules_evaluated`, which suppressed the `redact_when_no_rules`
/// safety net. At `secure_mode.level = permissive`,
/// `apply_secure_mode_override` is a no-op unless policy denied, so nothing
/// else redacts and raw PII goes to the provider.
///
/// These tests compose the REAL production functions in the real order the
/// request path runs them — `evaluate` → `apply_secure_mode_override` →
/// `apply_fallback_redaction` — rather than re-implementing the gate.
#[cfg(test)]
mod permissive_fail_open_tests {
    use crate::db::secure_mode_repo::SecureModeRow;
    use crate::db::{PolicyRepository, WorkspaceRepository};
    use crate::ml_sidecar::types::InjectionResponse;
    use crate::pipeline::service::{apply_fallback_redaction, apply_secure_mode_override};
    use crate::policy::engine::{evaluate, PolicyEvaluationInput, PolicyEvaluationOutcome};
    use secureprompt_common::pipeline::PipelineState;
    use secureprompt_common::types::{Detection, RequestId, TokenVault, WorkspaceId};
    use sqlx::PgPool;
    use std::collections::HashMap;
    use uuid::Uuid;

    const EMAIL: &str = "qa-fixture@example.invalid";

    /// Run the permissive request path over a workspace whose ONLY enabled
    /// rule is the one supplied, and return the outcome plus the content that
    /// would go to the provider.
    async fn permissive_path(
        pool: &PgPool,
        conditions: serde_json::Value,
        action: &str,
    ) -> (PolicyEvaluationOutcome, String) {
        let hash = crate::db::user_repo::hash_password("pw-for-test-only").unwrap();
        let (workspace, _) = WorkspaceRepository::new(pool.clone())
            .create_with_owner(
                "Permissive Co",
                &format!("permissive-{}@example.invalid", Uuid::new_v4()),
                &hash,
            )
            .await
            .expect("workspace must be created");

        sqlx::query("DELETE FROM policy_rules WHERE workspace_id = $1")
            .bind(workspace.id)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO policy_rules
                (id, workspace_id, name, priority, conditions, action, action_params,
                 enabled, dry_run, created_at, updated_at)
             VALUES ($1, $2, 'Rule under test', 100, $3, $4, '{}'::jsonb,
                     true, false, NOW(), NOW())",
        )
        .bind(Uuid::new_v4())
        .bind(workspace.id)
        .bind(&conditions)
        .bind(action)
        .execute(pool)
        .await
        .unwrap();

        let content = format!("Please email {EMAIL} about the invoice");
        let at = content.find(EMAIL).unwrap();
        let detections = vec![Detection {
            class: "EMAIL_ADDRESS".to_owned(),
            confidence: 0.99,
            span: Some((at, at + EMAIL.len())),
            value: EMAIL.to_owned(),
        }];

        let mut pipeline_state = PipelineState {
            vault: TokenVault::default(),
            detections: detections.clone(),
            policy_events: Vec::new(),
            redaction_map: HashMap::new(),
        };

        let mut outcome = evaluate(
            &PolicyRepository::new(pool.clone()),
            PolicyEvaluationInput {
                request_id: RequestId::new(),
                workspace_id: WorkspaceId(workspace.id),
                provider_name: "none",
                model: "none",
                content: &content,
                detections: &detections,
                fail_closed: true,
            },
            &mut pipeline_state.vault,
            &mut pipeline_state.redaction_map,
        )
        .await
        .expect("policy evaluation must succeed");

        assert_eq!(
            outcome.rules_evaluated, 1,
            "premise: the rule under test must be enabled and counted — at 0 \
             the old `rules_evaluated == 0` gate would rescue the request all \
             by itself and the test would prove nothing"
        );

        // `secure_mode.level = permissive`, called exactly as the request
        // path calls it.
        let secure_mode = SecureModeRow {
            workspace_id: workspace.id,
            enabled: true,
            level: "permissive".to_owned(),
            ..SecureModeRow::default()
        };
        apply_secure_mode_override(
            &secure_mode,
            &detections,
            InjectionResponse {
                is_injection: false,
                score: 0.0,
            },
            &mut outcome,
            &mut pipeline_state,
        );

        apply_fallback_redaction(
            /* chat_debug_mode */ false,
            /* redact_when_no_rules */ true,
            &mut outcome,
            &mut pipeline_state,
        );

        let final_content = outcome.content.clone();
        (outcome, final_content)
    }

    /// FIX 3 (WS1-6a): an enabled rule whose condition simply does not match
    /// this request must not disable protection.
    ///
    /// Deletion check: restore `outcome.rules_evaluated == 0` in
    /// `pipeline/service.rs::apply_fallback_redaction` — this reddens.
    #[sqlx::test]
    async fn non_matching_rule_does_not_leave_pii_unredacted_at_permissive(pool: PgPool) {
        let conditions = serde_json::json!([
            { "field": "detection_class", "op": "eq", "value": "US_SSN" }
        ]);
        let (outcome, final_content) = permissive_path(&pool, conditions, "redact").await;

        assert!(
            outcome.unprotected,
            "premise: no rule matched, so nothing protected this request"
        );
        assert!(
            !final_content.contains(EMAIL),
            "PII was detected and then forwarded raw because an enabled rule \
             failed to match: {final_content:?}"
        );
    }

    /// FIX 2 (WS1-8): a rule with TWO `detection_class` conditions can never
    /// be satisfied by any single detection, so it never fires — while still
    /// counting toward `rules_evaluated`. `engine.rs` called that "safe
    /// (fails closed)". It was not: at permissive nothing else redacts.
    ///
    /// Deletion check: restore `outcome.rules_evaluated == 0` in
    /// `pipeline/service.rs::apply_fallback_redaction` — this reddens.
    #[sqlx::test]
    async fn rule_that_can_never_match_does_not_leave_pii_unredacted_at_permissive(pool: PgPool) {
        let conditions = serde_json::json!([
            { "field": "detection_class", "op": "eq", "value": "EMAIL_ADDRESS" },
            { "field": "detection_class", "op": "eq", "value": "PERSON" }
        ]);
        let (outcome, final_content) = permissive_path(&pool, conditions, "redact").await;

        assert!(
            outcome.unprotected,
            "premise: a two-`detection_class` rule cannot be satisfied by any \
             single detection, so it never fires"
        );
        assert!(
            !final_content.contains(EMAIL),
            "PII was detected and then forwarded raw because the only enabled \
             rule was unsatisfiable: {final_content:?}"
        );
    }

    /// POSITIVE CONTROL: the fail-closed net must NOT be "redact everything,
    /// always". An admin's explicit, MATCHING `allow` rule is a deliberate
    /// choice and still passes the request through untouched.
    ///
    /// Same harness, same assertion shape, opposite expected result — if this
    /// ever reddens, the two tests above are proving nothing.
    #[sqlx::test]
    async fn matching_allow_rule_is_still_honoured_at_permissive(pool: PgPool) {
        let conditions = serde_json::json!([
            { "field": "detection_class", "op": "in", "value": ["EMAIL_ADDRESS"] }
        ]);
        let (outcome, final_content) = permissive_path(&pool, conditions, "allow").await;

        assert!(
            !outcome.unprotected,
            "an explicitly matching allow rule DID decide this request"
        );
        assert!(
            final_content.contains(EMAIL),
            "an admin's explicit allow must not be overridden by the safety \
             net: {final_content:?}"
        );
    }
}

/// FIX 4 (WS1-6b) — `content_regex` was `input.content.contains(needle)`, a
/// substring test. Any operator who wrote `^sk-[A-Za-z0-9]{32}$` had a rule
/// that silently matched nothing and believed they were protected.
#[cfg(test)]
mod content_regex_tests {
    use crate::db::PolicyRuleRow;
    use crate::policy::engine::{rule_matches, PolicyEvaluationInput};
    use chrono::Utc;
    use secureprompt_common::types::{Detection, RequestId, WorkspaceId};
    use uuid::Uuid;

    fn regex_rule(pattern: &str) -> PolicyRuleRow {
        PolicyRuleRow {
            id: Uuid::new_v4(),
            workspace_id: Uuid::new_v4(),
            name: "content-regex-rule".to_owned(),
            priority: 100,
            conditions: serde_json::json!([
                { "field": "content_regex", "op": "matches", "value": pattern }
            ]),
            action: "redact".to_owned(),
            action_params: serde_json::json!({}),
            enabled: true,
            dry_run: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn input<'a>(content: &'a str, detections: &'a [Detection]) -> PolicyEvaluationInput<'a> {
        PolicyEvaluationInput {
            request_id: RequestId::new(),
            workspace_id: WorkspaceId::new(),
            provider_name: "test-provider",
            model: "test-model",
            content,
            detections,
            fail_closed: false,
        }
    }

    /// The pattern is chosen so the two implementations disagree: a substring
    /// test for the literal characters `tok_[0-9]{4}` finds nothing in this
    /// content, while the regex matches `tok_4821`.
    #[test]
    fn content_regex_is_compiled_as_a_regex_not_substring_matched() {
        let content = "deploy key tok_4821 rotated";
        // PREMISE: prove the two semantics really do differ on this fixture,
        // so the test cannot pass under the old `contains` implementation.
        assert!(
            !content.contains("tok_[0-9]{4}"),
            "premise: a literal substring test must NOT match this content"
        );

        let no_detections: Vec<Detection> = Vec::new();
        assert!(
            rule_matches(&regex_rule("tok_[0-9]{4}"), &input(content, &no_detections)),
            "content_regex must be evaluated as a regular expression"
        );
    }

    /// POSITIVE CONTROL: same rule, same code path, content the regex
    /// genuinely does not match — must NOT fire. Without this, an
    /// implementation returning `true` unconditionally would pass the test
    /// above.
    #[test]
    fn content_regex_does_not_match_when_the_pattern_does_not_apply() {
        let content = "deploy key tok_abcd rotated";
        let no_detections: Vec<Detection> = Vec::new();
        assert!(
            !rule_matches(&regex_rule("tok_[0-9]{4}"), &input(content, &no_detections)),
            "a non-matching regex must not fire the rule"
        );
    }

    /// Anchors must work — the operator's `^sk-...$` case from the brief.
    #[test]
    fn anchored_content_regex_behaves_as_an_anchor() {
        let no_detections: Vec<Detection> = Vec::new();
        let rule = regex_rule("^sk-[A-Za-z0-9]{8}$");
        assert!(
            rule_matches(&rule, &input("sk-abcd1234", &no_detections)),
            "anchored pattern must match a whole-content candidate"
        );
        assert!(
            !rule_matches(&rule, &input("prefix sk-abcd1234 suffix", &no_detections)),
            "anchored pattern must not match when the anchors are violated"
        );
    }

    /// A malformed pattern ALREADY in the database (saved before validation
    /// shipped, or written straight to Postgres) must not panic, and must not
    /// be treated as a match.
    #[test]
    fn malformed_content_regex_does_not_panic_and_does_not_match() {
        // Assembled at runtime rather than written as a literal. Clippy's
        // `invalid_regex` lint is deny-level here and rejects a malformed
        // literal passed straight to `Regex::new` at BUILD time — a
        // genuinely useful lint, and the reason production code cannot ship
        // one — so the fixture has to reach the constructor as a value, the
        // same way a pattern loaded from a `policy_rules` row does.
        let malformed = String::from("([") + "unclosed";

        // PREMISE: prove the fixture pattern really is invalid, otherwise
        // this only asserts that a valid regex failed to match.
        assert!(
            regex::Regex::new(&malformed).is_err(),
            "premise: the fixture pattern must actually be an invalid regex"
        );

        let no_detections: Vec<Detection> = Vec::new();
        let content = format!("{malformed} literally present");
        assert!(
            !rule_matches(&regex_rule(&malformed), &input(&content, &no_detections)),
            "a malformed pattern must not match — not even content that \
             contains it literally, which is what the old substring \
             implementation did"
        );
    }
}

/// FIX 2 + FIX 4, save-time half: reject rule shapes the engine cannot
/// honour, instead of letting them sit in the database looking enforced.
#[cfg(test)]
mod condition_validation_tests {
    use crate::http::routes::dashboard::policy_rules::validate_conditions;
    use secureprompt_common::errors::ApiError;

    fn err_message(conditions: serde_json::Value) -> String {
        match validate_conditions(&conditions) {
            Err(ApiError::BadRequest(message)) => message,
            other => panic!("expected ApiError::BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn rejects_a_malformed_content_regex_naming_the_field_and_the_error() {
        let message = err_message(serde_json::json!([
            { "field": "content_regex", "op": "matches", "value": "([unclosed" }
        ]));
        assert!(
            message.contains("content_regex"),
            "the 4xx must name the offending field: {message}"
        );
        assert!(
            message.contains("unclosed"),
            "the 4xx must carry the underlying regex error: {message}"
        );
    }

    /// POSITIVE CONTROL: a valid pattern of the same shape must be accepted,
    /// so the rejection above is about validity and not about the field name.
    #[test]
    fn accepts_a_valid_content_regex() {
        assert!(validate_conditions(&serde_json::json!([
            { "field": "content_regex", "op": "matches", "value": "^sk-[A-Za-z0-9]{32}$" }
        ]))
        .is_ok());
    }

    #[test]
    fn rejects_two_detection_class_conditions_on_one_rule() {
        let message = err_message(serde_json::json!([
            { "field": "detection_class", "op": "eq", "value": "EMAIL_ADDRESS" },
            { "field": "detection_class", "op": "eq", "value": "PERSON" }
        ]));
        assert!(
            message.contains("detection_class"),
            "the 4xx must name the offending field: {message}"
        );
    }

    /// POSITIVE CONTROL: one `detection_class` condition — including the
    /// multi-valued `in` form the seeded default rule uses, which is ONE
    /// condition listing several classes, not several conditions — must
    /// still be accepted, alongside an unrelated second condition.
    #[test]
    fn accepts_a_single_detection_class_condition() {
        assert!(validate_conditions(&serde_json::json!([
            { "field": "detection_class", "op": "in", "value": ["EMAIL_ADDRESS", "PERSON"] },
            { "field": "confidence_gte", "op": "gte", "value": 0.9 }
        ]))
        .is_ok());
    }
}

/// FIX 1, drift guard — `DEFAULT_POLICY_CLASSES` vs the detector registry.
///
/// The list carried two DEAD NAMES (`GCP_KEY`, `AZURE_KEY`) that matched
/// nothing the registry emits, and omitted every credential class, for long
/// enough that five review rounds of credential-detection work shipped with
/// zero effect on the real chat path. Nobody noticed because nothing
/// compared the two lists.
///
/// The registry's class names are `&'static str` literals inside a private
/// `DetectorSpec` struct with no public accessor, and `detection/registry.rs`
/// is off-limits to this change, so the source is scanned directly. That is
/// deliberately the same evidence a human audit would use.
#[cfg(test)]
mod registry_drift_tests {
    use crate::db::workspace_repo::{DEFAULT_POLICY_CLASSES, OPT_IN_ONLY_CLASSES};
    use std::collections::BTreeSet;

    const REGISTRY_SRC: &str = include_str!("../detection/registry.rs");

    /// Classes emitted ONLY by the Python ML sidecar
    /// (`secureprompt-ml/app/detection/*.py` — Presidio and XLM-R label
    /// maps), never by the Rust registry. A statement of fact about the
    /// sidecar, independent of which list a class currently sits on, so that
    /// both consumers below can rely on it:
    ///
    ///   * `default_policy_classes_contains_no_dead_names` — their absence
    ///     from the registry scan is expected and is not a dead name;
    ///   * `opt_in_only_classes_contains_no_dead_names` — same question,
    ///     asked of the exclusion list.
    ///
    /// `US_SSN` no longer reaches the first consumer, because it left
    /// `DEFAULT_POLICY_CLASSES` in the opt-in demotion; it is load-bearing
    /// for the second. Removing it would make the exclusion list's own
    /// dead-name guard reject the very entry the demotion added.
    const ML_ONLY: &[&str] = &["PERSON", "US_SSN", "IBAN_CODE"];

    /// Every `class: "..."` literal in the registry, normalized the way
    /// `detection::merge::normalize_class` normalizes it before the class
    /// ever reaches policy evaluation (upper-case, plus the two synonym
    /// rewrites). Getting this wrong in either direction is the bug.
    fn registry_classes() -> BTreeSet<String> {
        let mut classes = BTreeSet::new();
        for (index, _) in REGISTRY_SRC.match_indices("class: \"") {
            let rest = &REGISTRY_SRC[index + "class: \"".len()..];
            let Some(end) = rest.find('"') else { continue };
            let raw = &rest[..end];
            let normalized = match raw.to_uppercase().as_str() {
                "PHONE" => "PHONE_NUMBER".to_owned(),
                "EMAIL" => "EMAIL_ADDRESS".to_owned(),
                other => other.to_owned(),
            };
            classes.insert(normalized);
        }
        classes
    }

    /// PREMISE for both tests below: the scan must actually find the
    /// registry. A `include_str!` that silently picked up an empty or moved
    /// file would make `registry_classes()` empty, and an empty set is a
    /// subset of everything — the drift test would pass forever while
    /// checking nothing.
    #[test]
    fn registry_scan_finds_the_expected_shape_of_class_list() {
        let classes = registry_classes();
        assert!(
            classes.len() > 30,
            "premise: the registry scan must find the real class list, found \
             {} entries: {classes:?}",
            classes.len()
        );
        for expected in [
            "BEARER_TOKEN",
            "GITHUB_PAT",
            "EMAIL_ADDRESS",
            "PHONE_NUMBER",
            "PINFL",
        ] {
            assert!(
                classes.contains(expected),
                "premise: scan must find {expected}: {classes:?}"
            );
        }
        // Normalization really happened — the raw literals are lower-case
        // `phone` / `email`, so finding the normalized spellings above AND
        // not the raw ones proves the mapping ran.
        assert!(!classes.contains("PHONE"), "{classes:?}");
        assert!(!classes.contains("EMAIL"), "{classes:?}");
    }

    /// The audit, as a PURE FUNCTION of its three inputs, so the guard's
    /// logic can be exercised against a synthetic omission instead of only
    /// against whatever today's real lists happen to contain. Returns the
    /// registry classes that are neither seeded nor consciously excluded.
    fn unaccounted_classes(
        registry: &BTreeSet<String>,
        listed: &BTreeSet<&str>,
        excused: &[&str],
    ) -> Vec<String> {
        registry
            .iter()
            .filter(|class| !listed.contains(class.as_str()) && !excused.contains(&class.as_str()))
            .cloned()
            .collect()
    }

    /// The audit that was never run. Every class the registry can emit must
    /// be a deliberate decision in `DEFAULT_POLICY_CLASSES` — present, or
    /// consciously excluded by name in `OPT_IN_ONLY_CLASSES`.
    ///
    /// Until the SSN demotion this doc comment claimed an "allow-list below"
    /// that the body did not have: the filter consulted `listed` alone, so
    /// the only way to satisfy the guard was to seed the class. The
    /// exclusion list is that allow-list, and the two tests underneath this
    /// one are what make the claim checkable rather than asserted.
    #[test]
    fn default_policy_classes_cover_every_registry_class() {
        let listed: BTreeSet<&str> = DEFAULT_POLICY_CLASSES.iter().copied().collect();
        let missing = unaccounted_classes(&registry_classes(), &listed, OPT_IN_ONLY_CLASSES);

        assert!(
            missing.is_empty(),
            "these detector classes are emitted by the registry but are NOT in \
             DEFAULT_POLICY_CLASSES, so a new workspace detects them and then \
             forwards them in the clear whenever another listed class is also \
             present: {missing:?}. Add them here AND in a back-fill migration \
             — or, if the omission is DELIBERATE, name them in \
             OPT_IN_ONLY_CLASSES with the reason."
        );
    }

    /// The exclusion list must not turn the guard above into a rubber stamp:
    /// a class in NEITHER list is still an accidental omission and must
    /// still fail. Proved on a synthetic omission of a class that really is
    /// seeded today, because the real lists are (correctly) consistent and
    /// therefore cannot demonstrate the failure path.
    #[test]
    fn the_exclusion_list_does_not_excuse_an_accidental_omission() {
        let registry = registry_classes();
        // PREMISE: the class used to simulate the omission must actually be
        // emitted by the registry, else the test simulates nothing.
        assert!(
            registry.contains("BEARER_TOKEN"),
            "premise: the registry must emit BEARER_TOKEN: {registry:?}"
        );

        let with_an_accidental_omission: BTreeSet<&str> = DEFAULT_POLICY_CLASSES
            .iter()
            .copied()
            .filter(|class| *class != "BEARER_TOKEN")
            .collect();

        assert_eq!(
            unaccounted_classes(&registry, &with_an_accidental_omission, OPT_IN_ONLY_CLASSES),
            vec!["BEARER_TOKEN".to_owned()],
            "an omission the exclusion list does NOT name must still be \
             reported — otherwise adding the list disarmed the audit"
        );
    }

    /// POSITIVE CONTROL, which must differ from the test above: a class the
    /// exclusion list DOES name is excused. The second assertion is the
    /// deletion check, run inline on the same inputs — with the exclusion
    /// list emptied, the identical call reports `SSN`.
    #[test]
    fn a_class_named_on_the_exclusion_list_is_excused() {
        let registry = registry_classes();
        let listed: BTreeSet<&str> = DEFAULT_POLICY_CLASSES.iter().copied().collect();

        // PREMISE: `ssn` is still a live registry class (demoted, not
        // deleted) and is genuinely absent from the seeded defaults, so the
        // excuse below is doing real work.
        assert!(
            registry.contains("SSN"),
            "premise: `Matcher::Ssn` must still be registered: {registry:?}"
        );
        assert!(
            !listed.contains("SSN"),
            "premise: SSN must be absent from DEFAULT_POLICY_CLASSES"
        );

        assert!(
            unaccounted_classes(&registry, &listed, OPT_IN_ONLY_CLASSES).is_empty(),
            "a class named on the exclusion list must be excused"
        );
        assert_eq!(
            unaccounted_classes(&registry, &listed, &[]),
            vec!["SSN".to_owned()],
            "deletion check: with the exclusion list emptied the SAME inputs \
             must fail, else the excuse was never load-bearing"
        );
    }

    /// The exclusion list's own rot. An entry naming a class no detector
    /// emits excuses nothing and merely widens the hole in the audit above —
    /// the same defect `GCP_KEY` / `AZURE_KEY` were in `DEFAULT_POLICY_CLASSES`.
    #[test]
    fn opt_in_only_classes_contains_no_dead_names() {
        let registry = registry_classes();

        // PREMISE: an empty exclusion list would pass the loop below
        // vacuously, and would also silently disarm
        // `a_class_named_on_the_exclusion_list_is_excused`.
        assert_eq!(
            OPT_IN_ONLY_CLASSES,
            ["SSN", "US_SSN"],
            "premise: the exclusion list must hold exactly the two SSN \
             spellings — the Rust floor's and Presidio's"
        );

        let dead: Vec<&str> = OPT_IN_ONLY_CLASSES
            .iter()
            .copied()
            .filter(|class| !registry.contains(*class) && !ML_ONLY.contains(class))
            .collect();

        assert!(
            dead.is_empty(),
            "these OPT_IN_ONLY_CLASSES entries name nothing any detector \
             emits, so they excuse an omission that was never possible: \
             {dead:?}"
        );
    }

    /// A class cannot be both seeded and opt-in-only. The two lists are a
    /// partition of "decided about", and an overlap would mean the exclusion
    /// list is excusing something that is present anyway — a demotion that
    /// silently did not happen.
    #[test]
    fn the_two_lists_do_not_overlap() {
        let listed: BTreeSet<&str> = DEFAULT_POLICY_CLASSES.iter().copied().collect();
        let both: Vec<&str> = OPT_IN_ONLY_CLASSES
            .iter()
            .copied()
            .filter(|class| listed.contains(class))
            .collect();

        assert!(
            both.is_empty(),
            "these classes are marked opt-in-only AND seeded by default, so \
             the demotion did not happen: {both:?}"
        );
    }

    /// The other direction: an entry naming a class nothing ever emits is a
    /// DEAD NAME. It looks like protection in the policy UI and is not.
    /// `GCP_KEY` and `AZURE_KEY` were exactly this.
    #[test]
    fn default_policy_classes_contains_no_dead_names() {
        let registry = registry_classes();

        let dead: Vec<&str> = DEFAULT_POLICY_CLASSES
            .iter()
            .copied()
            .filter(|class| !registry.contains(*class) && !ML_ONLY.contains(class))
            .collect();

        assert!(
            dead.is_empty(),
            "these DEFAULT_POLICY_CLASSES entries match nothing any detector \
             emits — they are dead names that look like protection: {dead:?}"
        );
    }
}

/// FIX 1, migration half — `019_credential_policy_classes.sql` back-fills
/// workspaces that were already seeded with the pre-credential class list.
///
/// Mirrors `migration_backfill_tests` in `tests.rs` for migration 017.
/// `#[sqlx::test]` runs every migration before the test body, so the seeded
/// rule a test creates is already new-shaped; to prove the migration itself
/// does anything, these write a LEGACY-shaped rule and then execute the
/// migration file's own SQL against it.
#[cfg(test)]
mod migration_019_tests {
    use crate::db::WorkspaceRepository;
    use sqlx::{PgPool, Row};
    use uuid::Uuid;

    const MIGRATION_SQL: &str = include_str!("../../migrations/019_credential_policy_classes.sql");

    /// The class list as it stood after migration 017 and before this fix
    /// wave: nine originals (including the two dead names) plus the six
    /// Uzbek identifiers. No credential among them.
    const POST_017_CLASSES: &str = r#"["PERSON","EMAIL_ADDRESS","PHONE_NUMBER","CREDIT_CARD","US_SSN","IBAN_CODE","AWS_ACCESS_KEY","GCP_KEY","AZURE_KEY","PINFL","STIR","MFO","PASSPORT_NUMBER","UZCARD","HUMO"]"#;

    async fn seed_legacy_rule(pool: &PgPool, name: &str, classes: &str) -> Uuid {
        let hash = crate::db::user_repo::hash_password("pw-for-test-only").unwrap();
        let (workspace, _) = WorkspaceRepository::new(pool.clone())
            .create_with_owner(
                "Legacy Credential Co",
                &format!("legacy-cred-{}@example.invalid", Uuid::new_v4()),
                &hash,
            )
            .await
            .expect("workspace must be created");

        sqlx::query("DELETE FROM policy_rules WHERE workspace_id = $1")
            .bind(workspace.id)
            .execute(pool)
            .await
            .unwrap();

        let rule_id = Uuid::new_v4();
        let conditions: serde_json::Value = serde_json::from_str(&format!(
            r#"[{{"field":"detection_class","op":"in","value":{classes}}}]"#
        ))
        .unwrap();

        sqlx::query(
            "INSERT INTO policy_rules
                (id, workspace_id, name, priority, conditions, action, action_params,
                 enabled, dry_run, created_at, updated_at)
             VALUES ($1, $2, $3, 100, $4, 'redact', '{}'::jsonb, true, false, NOW(), NOW())",
        )
        .bind(rule_id)
        .bind(workspace.id)
        .bind(name)
        .bind(&conditions)
        .execute(pool)
        .await
        .unwrap();

        rule_id
    }

    async fn classes_of(pool: &PgPool, rule_id: Uuid) -> Vec<String> {
        let row = sqlx::query("SELECT conditions FROM policy_rules WHERE id = $1")
            .bind(rule_id)
            .fetch_one(pool)
            .await
            .unwrap();
        let conditions: serde_json::Value = row.get("conditions");
        conditions[0]["value"]
            .as_array()
            .expect("value array")
            .iter()
            .filter_map(|value| value.as_str().map(ToOwned::to_owned))
            .collect()
    }

    /// The headline: a post-017 workspace gains the credential classes.
    ///
    /// This is also the test that would have caught the RLS trap. A bare
    /// `UPDATE policy_rules ...` matches ZERO rows under FORCE ROW LEVEL
    /// SECURITY when `app.current_workspace_id` is unset, and succeeds
    /// silently — the migration would "ship" and change nothing.
    #[sqlx::test]
    async fn backfills_credential_classes_into_a_post_017_rule(pool: PgPool) {
        let rule_id = seed_legacy_rule(&pool, "Redact common PII", POST_017_CLASSES).await;

        // PREMISE: the classes must be absent BEFORE the migration, else a
        // no-op migration would pass this test.
        let before = classes_of(&pool, rule_id).await;
        assert!(!before.contains(&"BEARER_TOKEN".to_owned()), "{before:?}");
        assert!(!before.contains(&"GITHUB_PAT".to_owned()), "{before:?}");

        sqlx::raw_sql(MIGRATION_SQL).execute(&pool).await.unwrap();

        let classes = classes_of(&pool, rule_id).await;
        for expected in [
            "BEARER_TOKEN",
            "BASIC_AUTH_HEADER",
            "GITHUB_PAT",
            "SLACK_BOT_TOKEN",
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "PRIVATE_KEY_PEM",
            "POSTGRESQL_URI",
            "JWT",
            "SSN",
            "IBAN",
            "GOOGLE_API_KEY",
            "AZURE_STORAGE_CONNECTION_STRING",
        ] {
            assert!(
                classes.contains(&expected.to_owned()),
                "{expected} missing after back-fill: {classes:?}"
            );
        }
        // Nothing may be dropped — including what 017 added.
        assert!(classes.contains(&"PERSON".to_owned()), "{classes:?}");
        assert!(classes.contains(&"PINFL".to_owned()), "{classes:?}");
    }

    #[sqlx::test]
    async fn backfill_is_idempotent(pool: PgPool) {
        let rule_id = seed_legacy_rule(&pool, "Redact common PII", POST_017_CLASSES).await;

        sqlx::raw_sql(MIGRATION_SQL).execute(&pool).await.unwrap();
        let once = classes_of(&pool, rule_id).await;
        sqlx::raw_sql(MIGRATION_SQL).execute(&pool).await.unwrap();
        let twice = classes_of(&pool, rule_id).await;

        assert_eq!(once, twice, "re-running the migration must not duplicate");
    }

    /// POSITIVE CONTROL for the two tests above: the migration is selective,
    /// not "update every row". An admin who NARROWED the seed meant it.
    #[sqlx::test]
    async fn does_not_touch_a_rule_an_admin_narrowed(pool: PgPool) {
        let narrowed = r#"["PERSON","EMAIL_ADDRESS"]"#;
        let rule_id = seed_legacy_rule(&pool, "Redact common PII", narrowed).await;

        sqlx::raw_sql(MIGRATION_SQL).execute(&pool).await.unwrap();

        assert_eq!(
            classes_of(&pool, rule_id).await,
            vec!["PERSON".to_owned(), "EMAIL_ADDRESS".to_owned()],
            "a narrowed rule must be left exactly as the admin left it"
        );
    }

    #[sqlx::test]
    async fn backfills_a_rule_an_admin_widened(pool: PgPool) {
        let widened = POST_017_CLASSES.replace("\"HUMO\"]", "\"HUMO\",\"LOCATION\"]");
        let rule_id = seed_legacy_rule(&pool, "Redact common PII", &widened).await;

        sqlx::raw_sql(MIGRATION_SQL).execute(&pool).await.unwrap();

        let classes = classes_of(&pool, rule_id).await;
        assert!(classes.contains(&"BEARER_TOKEN".to_owned()), "{classes:?}");
        assert!(
            classes.contains(&"LOCATION".to_owned()),
            "the admin's own addition must survive: {classes:?}"
        );
    }

    /// An admin who had already added one of the new classes by hand must not
    /// end up with a duplicate entry.
    #[sqlx::test]
    async fn backfill_does_not_duplicate_a_class_the_admin_already_added(pool: PgPool) {
        let with_jwt = POST_017_CLASSES.replace("\"HUMO\"]", "\"HUMO\",\"JWT\"]");
        let rule_id = seed_legacy_rule(&pool, "Redact common PII", &with_jwt).await;

        sqlx::raw_sql(MIGRATION_SQL).execute(&pool).await.unwrap();

        let classes = classes_of(&pool, rule_id).await;
        assert_eq!(
            classes.iter().filter(|c| *c == "JWT").count(),
            1,
            "JWT must appear exactly once: {classes:?}"
        );
        assert!(classes.contains(&"BEARER_TOKEN".to_owned()), "{classes:?}");
    }

    #[sqlx::test]
    async fn does_not_touch_an_unrelated_rule(pool: PgPool) {
        let rule_id = seed_legacy_rule(&pool, "Block secrets", POST_017_CLASSES).await;

        sqlx::raw_sql(MIGRATION_SQL).execute(&pool).await.unwrap();

        assert!(
            !classes_of(&pool, rule_id)
                .await
                .contains(&"BEARER_TOKEN".to_owned()),
            "only the seeded 'Redact common PII' rule may be back-filled"
        );
    }

    /// Multi-workspace: the RLS loop must visit EVERY workspace, not just
    /// the first. A `set_config` outside the loop, or a loop that exits
    /// early, would back-fill one and leave the rest exposed.
    #[sqlx::test]
    async fn backfills_every_workspace_not_just_the_first(pool: PgPool) {
        let first = seed_legacy_rule(&pool, "Redact common PII", POST_017_CLASSES).await;
        let second = seed_legacy_rule(&pool, "Redact common PII", POST_017_CLASSES).await;
        let third = seed_legacy_rule(&pool, "Redact common PII", POST_017_CLASSES).await;

        sqlx::raw_sql(MIGRATION_SQL).execute(&pool).await.unwrap();

        for (label, rule_id) in [("first", first), ("second", second), ("third", third)] {
            let classes = classes_of(&pool, rule_id).await;
            assert!(
                classes.contains(&"BEARER_TOKEN".to_owned()),
                "{label} workspace was not back-filled: {classes:?}"
            );
        }
    }
}

/// DRIFT GUARD — the SQL back-fill list vs `DEFAULT_POLICY_CLASSES`.
///
/// The default class list is duplicated between Rust and the migrations
/// because SQL cannot read a Rust `const`. That duplication has ALREADY
/// drifted twice, both times silently:
///
///   1. `GCP_KEY` / `AZURE_KEY` sat in the Rust list as DEAD NAMES matching
///      nothing the registry emits (it emits `google_api_key` and
///      `azure_storage_connection_string`). Guarded by
///      `default_policy_classes_contains_no_dead_names` above.
///   2. The six Uzbek classes 017 introduced never reached 019's candidate
///      list, so a database where 017 no-opped under RLS ended up with the
///      original nine plus credentials and none of the six. That is the gap
///      `020_reconcile_default_policy_classes.sql` closes, and it is the gap
///      THIS module is here to stop reopening.
///
/// 020 is the reconciling migration: it carries the FULL default list rather
/// than a delta, so equality with `DEFAULT_POLICY_CLASSES` is the right
/// assertion. Add a class to the Rust const without adding it to 020 and this
/// fails; add one to 020 that Rust does not seed and it fails the other way.
#[cfg(test)]
mod migration_class_list_drift_tests {
    use crate::db::workspace_repo::{DEFAULT_POLICY_CLASSES, OPT_IN_ONLY_CLASSES};
    use std::collections::BTreeSet;

    const MIGRATION_020: &str =
        include_str!("../../migrations/020_reconcile_default_policy_classes.sql");

    const LIST_BEGIN: &str = "-- >>> BACKFILL CLASS LIST";
    const LIST_END: &str = "-- <<< END BACKFILL CLASS LIST";

    /// Extract the quoted class names from the marker-delimited block in 020.
    ///
    /// The markers exist so this parse cannot drift with SQL formatting, and
    /// so the list appears exactly ONCE in the migration — a second copy is
    /// how 017 and 019 became inconsistent with each other in the first place.
    fn migration_backfill_classes() -> BTreeSet<String> {
        let start = MIGRATION_020
            .find(LIST_BEGIN)
            .expect("020 must carry the `-- >>> BACKFILL CLASS LIST` marker");
        let end = MIGRATION_020[start..]
            .find(LIST_END)
            .expect("020 must carry the `-- <<< END BACKFILL CLASS LIST` marker")
            + start;

        let block = &MIGRATION_020[start..end];
        let mut classes = BTreeSet::new();
        let mut rest = block;
        while let Some(open) = rest.find('"') {
            let after = &rest[open + 1..];
            let Some(close) = after.find('"') else { break };
            classes.insert(after[..close].to_owned());
            rest = &after[close + 1..];
        }
        classes
    }

    /// PREMISE: the parse must actually find a class list. An extraction that
    /// silently returned an empty set would make the equality test below
    /// compare nothing to nothing on one side and fail loudly on the other —
    /// but a future refactor to a subset check would turn it vacuous, so the
    /// shape is asserted explicitly.
    #[test]
    fn migration_class_list_parse_finds_the_expected_shape() {
        let parsed = migration_backfill_classes();
        assert!(
            parsed.len() > 30,
            "premise: the marker block in 020 must contain the real class \
             list, parsed {} entries: {parsed:?}",
            parsed.len()
        );
        for expected in ["PINFL", "BEARER_TOKEN", "EMAIL_ADDRESS"] {
            assert!(
                parsed.contains(expected),
                "premise: parse must find {expected}: {parsed:?}"
            );
        }
        // The parse must read the marker block ONLY. `GCP_KEY` / `AZURE_KEY`
        // appear elsewhere in 020 (in the "is this still the untouched seed?"
        // guard) and are deliberately NOT part of the back-fill list, so
        // finding them here would mean the extraction over-reached.
        assert!(
            !parsed.contains("GCP_KEY"),
            "premise: the parse leaked outside the marker block: {parsed:?}"
        );
    }

    /// The audit that was never run for 019.
    ///
    /// NO LONGER BIDIRECTIONAL EQUALITY, and the asymmetry is the point.
    /// 020 is already applied on developer and customer databases, and
    /// changing a byte of it breaks the sqlx checksum, so it still
    /// back-fills `SSN` / `US_SSN`. The demotion is expressed by a LATER
    /// migration (024) that removes them again, not by editing 020.
    ///
    /// So the surplus side is allowed to be exactly `OPT_IN_ONLY_CLASSES`
    /// and nothing else. Compared with `assert_eq!` rather than "subtract
    /// and check empty": a class dropped from `DEFAULT_POLICY_CLASSES`
    /// WITHOUT being named opt-in still fails here, which is the original
    /// defect this guard exists for.
    #[test]
    fn migration_020_backfills_default_policy_classes_plus_the_opt_ins() {
        let listed: BTreeSet<String> = DEFAULT_POLICY_CLASSES
            .iter()
            .map(|class| (*class).to_owned())
            .collect();
        let opt_in: BTreeSet<String> = OPT_IN_ONLY_CLASSES
            .iter()
            .map(|class| (*class).to_owned())
            .collect();
        let migration = migration_backfill_classes();

        let missing_from_migration: Vec<&String> = listed.difference(&migration).collect();
        let surplus_in_migration: BTreeSet<String> =
            migration.difference(&listed).cloned().collect();

        assert!(
            missing_from_migration.is_empty(),
            "these classes are in DEFAULT_POLICY_CLASSES but NOT in the \
             back-fill list of 020, so every workspace created before the \
             class was added detects them and then forwards them in the \
             clear: {missing_from_migration:?}"
        );
        assert_eq!(
            surplus_in_migration, opt_in,
            "020 back-fills exactly these classes that DEFAULT_POLICY_CLASSES \
             does not seed. Only the OPT_IN_ONLY_CLASSES demotion may appear \
             here — 020 is frozen (already applied; editing it breaks the \
             sqlx checksum) and migration 024 removes them again. Anything \
             ELSE in this set means a class was dropped from the Rust list \
             without being demoted, so existing workspaces would be better \
             protected than new ones."
        );
    }
}

/// WS1 — `SSN` / `US_SSN` demoted from default-on to OPT-IN.
///
/// SecurePrompt is an Uzbekistan-market product and the US Social Security
/// Number is not a supported default class:
///
///   * `SOCIAL_SECURITY_NUMBER` appears zero times across every ACTIVE
///     dataset under `data/**` (v5, v7, `v7_corpus_v2`/v3, `v7_hardened`,
///     `v8_corpus`, `spy_ruz`, `aug_*`). Its only occurrences are in the abandoned
///     v4 corpus under `docs/backup_v4/`, where the generator hallucinated a
///     Cyrillic "ССН" into Uzbek HR documents. The deployed v8 model has no
///     training support for the class.
///   * `SOCIAL_SECURITY_NUMBER` survives only as a dead entry in
///     `_V2_RAW_LABELS` (`secureprompt-ml/app/detection/xlmr_ner.py:129`).
///
/// DEMOTED, NOT DELETED. `Matcher::Ssn` and its `DetectorSpec` stay, so the
/// class is still detected and can be re-enabled from the policy UI by
/// adding it back to the seeded rule — `demoting_ssn_is_reversible_from_the_policy_ui`
/// below executes that path rather than asserting it.
///
/// SEQUENCING. This change was only safe once `fa880be` moved the
/// bare-nine-digit backstop off `ssn` and onto `stir`. Before that commit
/// `ssn` was the ONLY detector that redacted an UNLABELLED Uzbek tax number
/// — `Matcher::Stir` is keyword-gated and needs a nearby `ИНН`/`STIR` label
/// — so demoting the class would have turned a mislabel into a real leak.
/// `a_bare_nine_digit_stir_survives_the_demotion` is that property, asserted
/// on the redacted output of the real policy path.
#[cfg(test)]
mod ssn_opt_in_tests {
    use crate::db::{PolicyRepository, WorkspaceRepository};
    use crate::detection::{detect_content, merge::merge_detections};
    use crate::policy::engine::{evaluate, PolicyEvaluationInput, PolicyEvaluationOutcome};
    use secureprompt_common::types::{Detection, RequestId, TokenVault, WorkspaceId};
    use sqlx::PgPool;
    use std::collections::HashMap;
    use uuid::Uuid;

    /// Synthetic. The email is load-bearing in every fixture below: without a
    /// detection whose class the seeded rule DOES name, the rule never fires,
    /// `matching_detections` falls through to its "redact everything"
    /// fallback, and every assertion here passes for the wrong reason.
    const EMAIL: &str = "qa-fixture@example.invalid";
    /// A bare nine-digit run. In Uzbekistan this is a STIR; `fa880be` is what
    /// made it one. Not a real taxpayer.
    const BARE_NINE: &str = "300111222";
    /// The 3-2-4 form the US Social Security Administration prints. Not a
    /// real SSN — the 900 area is permanently unassigned.
    const US_SSN: &str = "900-45-6789";

    async fn seed_workspace(pool: &PgPool) -> Uuid {
        let hash = crate::db::user_repo::hash_password("pw-for-test-only").unwrap();
        let (workspace, _) = WorkspaceRepository::new(pool.clone())
            .create_with_owner(
                "SSN Demotion Co",
                &format!("ssn-optin-{}@example.invalid", Uuid::new_v4()),
                &hash,
            )
            .await
            .expect("workspace + seeded rule must be created");
        workspace.id
    }

    async fn eval_seeded(
        pool: &PgPool,
        workspace_id: Uuid,
        content: &str,
        detections: &[Detection],
        fail_closed: bool,
    ) -> PolicyEvaluationOutcome {
        let mut vault = TokenVault::default();
        let mut redaction_map: HashMap<String, String> = HashMap::new();
        let outcome = evaluate(
            &PolicyRepository::new(pool.clone()),
            PolicyEvaluationInput {
                request_id: RequestId::new(),
                workspace_id: WorkspaceId(workspace_id),
                provider_name: "none",
                model: "none",
                content,
                detections,
                fail_closed,
            },
            &mut vault,
            &mut redaction_map,
        )
        .await
        .expect("policy evaluation must succeed");

        assert_eq!(
            outcome.rules_evaluated, 1,
            "premise: the seeded rule must be the one and only rule — at 0 the \
             redact_when_no_rules net would mask everything under test"
        );
        outcome
    }

    fn classes_of(detections: &[Detection]) -> Vec<&str> {
        detections.iter().map(|d| d.class.as_str()).collect()
    }

    /// THE NO-LEAK PROPERTY. An unlabelled Uzbek tax number is still redacted
    /// by the seeded default rule after `SSN` leaves it, because `fa880be`
    /// moved that input's class to `stir` and `STIR` remains a default.
    ///
    /// Runs with `fail_closed: false` on purpose: with it on, a firing
    /// `redact` rule covers every detection regardless of the class list, so
    /// the test would pass no matter what `DEFAULT_POLICY_CLASSES` said.
    ///
    /// Deletion check: remove `"STIR"` from `DEFAULT_POLICY_CLASSES` — this
    /// reddens on the `BARE_NINE` assertion and its email premise does not.
    #[sqlx::test]
    async fn a_bare_nine_digit_stir_survives_the_demotion(pool: PgPool) {
        let content = format!("Contact {EMAIL} about order {BARE_NINE}");
        let detections = merge_detections(detect_content(&content), vec![]);

        // PREMISE. Both assertions below are about an ABSENCE, so first prove
        // the detector produced the classes at issue — and that the bare nine
        // is `stir` rather than `ssn`, which is the whole reason this task was
        // sequenced after the registry change.
        let classes = classes_of(&detections);
        assert!(
            classes.contains(&"EMAIL_ADDRESS"),
            "premise: the email must be detected, got {classes:?}"
        );
        assert!(
            classes.contains(&"STIR"),
            "premise: a bare nine-digit run must be detected as STIR — this is \
             `fa880be`, the prerequisite for this change, got {classes:?}"
        );
        assert!(
            !classes.contains(&"SSN"),
            "premise: the bare nine must NOT also be an SSN, got {classes:?}"
        );

        let workspace_id = seed_workspace(&pool).await;
        let outcome = eval_seeded(&pool, workspace_id, &content, &detections, false).await;
        assert_eq!(outcome.result.final_action, "redact");

        assert!(
            !outcome.content.contains(EMAIL),
            "premise: the email must be redacted, else the rule never fired \
             and this test proves nothing: {:?}",
            outcome.content
        );
        assert!(
            !outcome.content.contains(BARE_NINE),
            "NO-LEAK BROKEN: an unlabelled Uzbek tax number was redacted \
             before the SSN demotion and is now forwarded in the clear: {:?}",
            outcome.content
        );
    }

    /// THE DEMOTION, on behaviour. With `fail_closed` off — the only
    /// configuration in which `DEFAULT_POLICY_CLASSES` decides anything at
    /// all — a US SSN alongside an email is now forwarded.
    ///
    /// This test asserts a DELIBERATE reduction in coverage, which is what
    /// "opt-in" means, and it is the honest scope of the change: see
    /// `fail_closed_still_redacts_a_us_ssn` for the production default and
    /// `demoting_ssn_is_reversible_from_the_policy_ui` for the way back.
    #[sqlx::test]
    async fn a_us_ssn_is_forwarded_by_the_seeded_default_once_demoted(pool: PgPool) {
        let content = format!("Contact {EMAIL}, SSN {US_SSN}");
        let detections = merge_detections(detect_content(&content), vec![]);

        // PREMISE: the floor still DETECTS the SSN. Demoted, not deleted —
        // if this ever fails, `Matcher::Ssn` was removed and the opt-in path
        // below has nothing to switch back on.
        let classes = classes_of(&detections);
        assert!(
            classes.contains(&"SSN"),
            "premise: `Matcher::Ssn` must still detect the 3-2-4 form — the \
             class is demoted, not deleted, got {classes:?}"
        );
        assert!(
            classes.contains(&"EMAIL_ADDRESS"),
            "premise: the email must be detected, got {classes:?}"
        );

        let workspace_id = seed_workspace(&pool).await;
        let outcome = eval_seeded(&pool, workspace_id, &content, &detections, false).await;

        assert!(
            !outcome.content.contains(EMAIL),
            "premise: the listed class must still be redacted, else the rule \
             never fired: {:?}",
            outcome.content
        );
        assert!(
            outcome.content.contains(US_SSN),
            "the demotion is not real — the seeded default still redacts a US \
             SSN: {:?}",
            outcome.content
        );
    }

    /// SCOPE LIMIT, and the reason the test above is not a regression: with
    /// `fail_closed` on — `config.redact_when_no_rules`, the production
    /// default — a firing `redact` rule covers EVERY detection in the
    /// request, so the demoted class is still redacted.
    ///
    /// Same fixture as the test above, opposite expected result. If this ever
    /// starts forwarding, the demotion has become a real leak on the default
    /// configuration rather than an opt-in.
    #[sqlx::test]
    async fn fail_closed_still_redacts_a_us_ssn(pool: PgPool) {
        let content = format!("Contact {EMAIL}, SSN {US_SSN}");
        let detections = merge_detections(detect_content(&content), vec![]);

        let workspace_id = seed_workspace(&pool).await;
        let outcome = eval_seeded(&pool, workspace_id, &content, &detections, true).await;

        assert!(
            !outcome.content.contains(US_SSN),
            "on the PRODUCTION default (redact_when_no_rules on) a demoted \
             class must still be redacted once any rule fires: {:?}",
            outcome.content
        );
    }

    /// "Opt-in" is only a real offer if the way back works. The brief asserts
    /// that `DEFAULT_POLICY_CLASSES` is consumed in exactly one place — the
    /// seeded rule's `detection_class in [...]` condition — and that an admin
    /// re-enables the class by editing that rule. This EXECUTES that path
    /// instead of asserting it: the `UPDATE` below is what
    /// `PUT /v1/dashboard/policy-rules/{id}` writes.
    ///
    /// Runs with `fail_closed: false` throughout, so the class list is the
    /// only thing that can decide the outcome.
    #[sqlx::test]
    async fn demoting_ssn_is_reversible_from_the_policy_ui(pool: PgPool) {
        let content = format!("Contact {EMAIL}, SSN {US_SSN}");
        let detections = merge_detections(detect_content(&content), vec![]);
        let workspace_id = seed_workspace(&pool).await;

        // PREMISE: forwarded before the admin opts in. Without this the
        // "redacted after" assertion below would pass against a build where
        // SSN never left the defaults.
        let before = eval_seeded(&pool, workspace_id, &content, &detections, false).await;
        assert!(
            before.content.contains(US_SSN),
            "premise: the demoted class must be forwarded BEFORE the opt-in: {:?}",
            before.content
        );

        // What the policy UI does: append the class to the seeded rule.
        let updated = sqlx::query(
            "UPDATE policy_rules
             SET conditions = jsonb_set(conditions, '{0,value}',
                     (conditions -> 0 -> 'value') || '[\"SSN\"]'::jsonb)
             WHERE workspace_id = $1 AND name = 'Redact common PII'",
        )
        .bind(workspace_id)
        .execute(&pool)
        .await
        .expect("the opt-in edit must succeed")
        .rows_affected();
        assert_eq!(
            updated, 1,
            "premise: exactly one seeded rule must be edited"
        );

        let after = eval_seeded(&pool, workspace_id, &content, &detections, false).await;
        assert!(
            !after.content.contains(US_SSN),
            "OPT-IN IS NOT REAL: re-adding `SSN` to the seeded rule did not \
             restore redaction, so the class cannot be turned back on from \
             the policy UI: {:?}",
            after.content
        );
    }

    /// The demotion itself, asserted on the const rather than on behaviour so
    /// the failure names the exact edit required.
    #[test]
    fn default_policy_classes_omits_both_ssn_spellings() {
        let listed = crate::db::workspace_repo::DEFAULT_POLICY_CLASSES;
        assert!(
            !listed.contains(&"SSN"),
            "`SSN` (the Rust floor's spelling, upper-cased by \
             `merge::normalize_class`) is still a seeded default"
        );
        assert!(
            !listed.contains(&"US_SSN"),
            "`US_SSN` (Presidio's spelling, emitted by the ML sidecar's \
             `_map_label`) is still a seeded default — leaving either \
             spelling in makes the demotion cosmetic"
        );
    }
}

/// WS1, migration half — `024_demote_ssn_to_opt_in.sql`.
///
/// 017 / 019 / 020 all back-filled `SSN` / `US_SSN` into every workspace, so
/// removing them from `DEFAULT_POLICY_CLASSES` changes NEW workspaces only.
/// Without this migration the demotion would leave every existing deployment
/// redacting a class the product no longer supports by default.
///
/// `#[sqlx::test]` runs every migration before the test body, so a workspace
/// a test creates is already new-shaped; to prove the migration itself does
/// anything, these write a PRE-DEMOTION-shaped rule and then execute the
/// migration file's own SQL against it. Same technique as
/// `migration_019_tests` above.
#[cfg(test)]
mod migration_024_tests {
    use crate::db::workspace_repo::{DEFAULT_POLICY_CLASSES, OPT_IN_ONLY_CLASSES};
    use crate::db::WorkspaceRepository;
    use sqlx::{PgPool, Row};
    use uuid::Uuid;

    const MIGRATION_SQL: &str = include_str!("../../migrations/024_demote_ssn_to_opt_in.sql");

    /// The untouched seed as it stood immediately BEFORE the demotion.
    ///
    /// Built from the two consts rather than hard-coded, so it cannot drift
    /// when a class is added later — and deliberately in an order matching
    /// NEITHER the Rust const nor migration 020, which is what proves the
    /// migration's set-equality test really is order-independent.
    fn pre_demotion_seed() -> Vec<String> {
        DEFAULT_POLICY_CLASSES
            .iter()
            .chain(OPT_IN_ONLY_CLASSES.iter())
            .map(|class| (*class).to_owned())
            .collect()
    }

    fn as_json_array(classes: &[String]) -> String {
        serde_json::to_string(classes).unwrap()
    }

    async fn seed_rule(pool: &PgPool, name: &str, classes: &[String]) -> Uuid {
        let hash = crate::db::user_repo::hash_password("pw-for-test-only").unwrap();
        let (workspace, _) = WorkspaceRepository::new(pool.clone())
            .create_with_owner(
                "SSN Demotion Migration Co",
                &format!("ssn-migration-{}@example.invalid", Uuid::new_v4()),
                &hash,
            )
            .await
            .expect("workspace must be created");

        sqlx::query("DELETE FROM policy_rules WHERE workspace_id = $1")
            .bind(workspace.id)
            .execute(pool)
            .await
            .unwrap();

        let rule_id = Uuid::new_v4();
        let conditions: serde_json::Value = serde_json::from_str(&format!(
            r#"[{{"field":"detection_class","op":"in","value":{}}}]"#,
            as_json_array(classes)
        ))
        .unwrap();

        sqlx::query(
            "INSERT INTO policy_rules
                (id, workspace_id, name, priority, conditions, action, action_params,
                 enabled, dry_run, created_at, updated_at)
             VALUES ($1, $2, $3, 100, $4, 'redact', '{}'::jsonb, true, false, NOW(), NOW())",
        )
        .bind(rule_id)
        .bind(workspace.id)
        .bind(name)
        .bind(&conditions)
        .execute(pool)
        .await
        .unwrap();

        rule_id
    }

    async fn classes_of(pool: &PgPool, rule_id: Uuid) -> Vec<String> {
        let row = sqlx::query("SELECT conditions FROM policy_rules WHERE id = $1")
            .bind(rule_id)
            .fetch_one(pool)
            .await
            .unwrap();
        let conditions: serde_json::Value = row.get("conditions");
        conditions[0]["value"]
            .as_array()
            .expect("value array")
            .iter()
            .filter_map(|value| value.as_str().map(ToOwned::to_owned))
            .collect()
    }

    /// THE HEADLINE. Both spellings leave an untouched seeded rule and
    /// nothing else does.
    #[sqlx::test]
    async fn demotes_both_spellings_from_an_untouched_seeded_rule(pool: PgPool) {
        let rule_id = seed_rule(&pool, "Redact common PII", &pre_demotion_seed()).await;

        // PREMISE: both classes must be present BEFORE, else a migration that
        // did nothing at all would pass the assertions below.
        let before = classes_of(&pool, rule_id).await;
        assert!(before.contains(&"SSN".to_owned()), "{before:?}");
        assert!(before.contains(&"US_SSN".to_owned()), "{before:?}");

        sqlx::raw_sql(MIGRATION_SQL).execute(&pool).await.unwrap();

        let after = classes_of(&pool, rule_id).await;
        assert!(
            !after.contains(&"SSN".to_owned()),
            "the floor's `SSN` spelling survived the demotion: {after:?}"
        );
        assert!(
            !after.contains(&"US_SSN".to_owned()),
            "Presidio's `US_SSN` spelling survived the demotion — leaving \
             either one makes the demotion cosmetic: {after:?}"
        );

        // NOTHING ELSE MOVED. Asserted as full set equality, not spot checks:
        // a migration that emptied the array would satisfy the two assertions
        // above and destroy the workspace's protection.
        let mut sorted = after.clone();
        sorted.sort();
        let mut expected: Vec<String> = DEFAULT_POLICY_CLASSES
            .iter()
            .map(|class| (*class).to_owned())
            .collect();
        expected.sort();
        assert_eq!(
            sorted, expected,
            "the demoted rule must be exactly DEFAULT_POLICY_CLASSES: {after:?}"
        );
    }

    /// The second untouched shape: what 020 leaves on a workspace that was
    /// seeded before `GCP_KEY` / `AZURE_KEY` were replaced. The dead names
    /// must SURVIVE — they match nothing, so removing them would change no
    /// behaviour while risking one.
    #[sqlx::test]
    async fn demotes_the_020_reconciled_legacy_shape(pool: PgPool) {
        let mut classes = pre_demotion_seed();
        classes.push("GCP_KEY".to_owned());
        classes.push("AZURE_KEY".to_owned());
        let rule_id = seed_rule(&pool, "Redact common PII", &classes).await;

        sqlx::raw_sql(MIGRATION_SQL).execute(&pool).await.unwrap();

        let after = classes_of(&pool, rule_id).await;
        assert!(
            !after.contains(&"SSN".to_owned()) && !after.contains(&"US_SSN".to_owned()),
            "the 020-reconciled legacy shape must be demoted too, otherwise \
             every workspace older than the dead-name fix keeps redacting \
             SSN: {after:?}"
        );
        assert!(
            after.contains(&"GCP_KEY".to_owned()) && after.contains(&"AZURE_KEY".to_owned()),
            "the dead names must survive — this migration demotes, it does not \
             tidy: {after:?}"
        );
    }

    /// THE CONSERVATIVE HALF, and the opposite posture to 020. An admin who
    /// customised the rule may name SSN deliberately; silently stripping it
    /// would be the same class of defect as the back-fill that created this
    /// situation.
    ///
    /// Widened, unlike in 020 — which back-filled widened rules because ADDING
    /// a class to someone's customised rule is safe and REMOVING one is not.
    #[sqlx::test]
    async fn leaves_a_rule_an_admin_widened_alone(pool: PgPool) {
        let mut classes = pre_demotion_seed();
        classes.push("LOCATION".to_owned());
        let rule_id = seed_rule(&pool, "Redact common PII", &classes).await;

        sqlx::raw_sql(MIGRATION_SQL).execute(&pool).await.unwrap();

        let after = classes_of(&pool, rule_id).await;
        assert!(
            after.contains(&"SSN".to_owned()) && after.contains(&"US_SSN".to_owned()),
            "a rule the admin customised must be left exactly as they left \
             it — they may have named SSN deliberately: {after:?}"
        );
        assert!(after.contains(&"LOCATION".to_owned()), "{after:?}");
    }

    /// The same rule from the other direction. An admin who removed a class
    /// meant it, and this migration must not treat their rule as a seed.
    #[sqlx::test]
    async fn leaves_a_rule_an_admin_narrowed_alone(pool: PgPool) {
        let narrowed = vec![
            "PERSON".to_owned(),
            "EMAIL_ADDRESS".to_owned(),
            "SSN".to_owned(),
        ];
        let rule_id = seed_rule(&pool, "Redact common PII", &narrowed).await;

        sqlx::raw_sql(MIGRATION_SQL).execute(&pool).await.unwrap();

        assert_eq!(
            classes_of(&pool, rule_id).await,
            narrowed,
            "a narrowed rule must be left byte for byte as the admin left it"
        );
    }

    /// Only the SEEDED rule is in scope. An admin's own rule that happens to
    /// carry the same class list is theirs.
    #[sqlx::test]
    async fn leaves_an_unrelated_rule_alone(pool: PgPool) {
        let rule_id = seed_rule(&pool, "Block secrets", &pre_demotion_seed()).await;

        sqlx::raw_sql(MIGRATION_SQL).execute(&pool).await.unwrap();

        let after = classes_of(&pool, rule_id).await;
        assert!(
            after.contains(&"SSN".to_owned()),
            "only the seeded 'Redact common PII' rule may be demoted: {after:?}"
        );
    }

    /// A workspace created AFTER the demotion already carries the new shape.
    /// The migration must be a no-op on it rather than an error — and in
    /// particular must not match it against the pre-demotion seed and then
    /// trip its own post-condition.
    #[sqlx::test]
    async fn leaves_an_already_demoted_rule_alone(pool: PgPool) {
        let current: Vec<String> = DEFAULT_POLICY_CLASSES
            .iter()
            .map(|class| (*class).to_owned())
            .collect();
        let rule_id = seed_rule(&pool, "Redact common PII", &current).await;

        sqlx::raw_sql(MIGRATION_SQL).execute(&pool).await.unwrap();

        assert_eq!(
            classes_of(&pool, rule_id).await,
            current,
            "an already-demoted rule must be untouched"
        );
    }

    #[sqlx::test]
    async fn is_idempotent(pool: PgPool) {
        let rule_id = seed_rule(&pool, "Redact common PII", &pre_demotion_seed()).await;

        sqlx::raw_sql(MIGRATION_SQL).execute(&pool).await.unwrap();
        let once = classes_of(&pool, rule_id).await;
        sqlx::raw_sql(MIGRATION_SQL).execute(&pool).await.unwrap();
        let twice = classes_of(&pool, rule_id).await;

        assert_eq!(once, twice, "re-running the migration must change nothing");
    }

    /// Multi-workspace: the RLS loop must visit EVERY workspace, not just the
    /// first. A `set_config` hoisted out of the loop, or a loop that exits
    /// early, would demote one and leave the rest redacting SSN.
    #[sqlx::test]
    async fn demotes_every_workspace_not_just_the_first(pool: PgPool) {
        let seed = pre_demotion_seed();
        let first = seed_rule(&pool, "Redact common PII", &seed).await;
        let second = seed_rule(&pool, "Redact common PII", &seed).await;
        let third = seed_rule(&pool, "Redact common PII", &seed).await;

        sqlx::raw_sql(MIGRATION_SQL).execute(&pool).await.unwrap();

        for (label, rule_id) in [("first", first), ("second", second), ("third", third)] {
            let after = classes_of(&pool, rule_id).await;
            assert!(
                !after.contains(&"SSN".to_owned()),
                "{label} workspace was not demoted: {after:?}"
            );
        }
    }

    /// Set equality, not sequence equality. A rule whose classes are in a
    /// different order — which `jsonb` does not normalise and an admin's
    /// round-trip through the policy UI can easily produce — is still the
    /// untouched seed and must still be demoted.
    #[sqlx::test]
    async fn recognises_the_seed_regardless_of_element_order(pool: PgPool) {
        let mut shuffled = pre_demotion_seed();
        shuffled.reverse();
        let rule_id = seed_rule(&pool, "Redact common PII", &shuffled).await;

        sqlx::raw_sql(MIGRATION_SQL).execute(&pool).await.unwrap();

        let after = classes_of(&pool, rule_id).await;
        assert!(
            !after.contains(&"SSN".to_owned()) && !after.contains(&"US_SSN".to_owned()),
            "element order must not decide whether a rule is the seed: {after:?}"
        );
    }
}

/// DRIFT GUARD — `024_demote_ssn_to_opt_in.sql` vs the two Rust consts.
///
/// Same duplication hazard as 020, and the same remedy: SQL cannot read a
/// Rust `const`, so both lists are enumerated again in the migration between
/// marker comments and parsed back out here.
///
/// 024 carries TWO lists and both can rot independently:
///   * the PRE-DEMOTION SEED SHAPE decides which rules are recognised as an
///     untouched seed. If a class is added to `DEFAULT_POLICY_CLASSES` and
///     not here, every workspace seeded after that point stops matching and
///     is silently skipped.
///   * the OPT-IN ONLY CLASSES decide what is stripped. If a class is demoted
///     in Rust and not here, new workspaces are seeded without it while
///     existing ones keep it.
#[cfg(test)]
mod migration_024_drift_tests {
    use crate::db::workspace_repo::{DEFAULT_POLICY_CLASSES, OPT_IN_ONLY_CLASSES};
    use std::collections::BTreeSet;

    const MIGRATION_024: &str = include_str!("../../migrations/024_demote_ssn_to_opt_in.sql");

    const SEED_BEGIN: &str = "-- >>> PRE-DEMOTION SEED SHAPE";
    const SEED_END: &str = "-- <<< END PRE-DEMOTION SEED SHAPE";
    const OPT_IN_BEGIN: &str = "-- >>> OPT-IN ONLY CLASSES";
    const OPT_IN_END: &str = "-- <<< END OPT-IN ONLY CLASSES";

    /// Extract the quoted class names from a marker-delimited block.
    fn block_classes(begin: &str, end: &str) -> BTreeSet<String> {
        let start = MIGRATION_024
            .find(begin)
            .unwrap_or_else(|| panic!("024 must carry the `{begin}` marker"));
        let stop = MIGRATION_024[start..]
            .find(end)
            .unwrap_or_else(|| panic!("024 must carry the `{end}` marker"))
            + start;

        let mut classes = BTreeSet::new();
        let mut rest = &MIGRATION_024[start..stop];
        while let Some(open) = rest.find('"') {
            let after = &rest[open + 1..];
            let Some(close) = after.find('"') else { break };
            classes.insert(after[..close].to_owned());
            rest = &after[close + 1..];
        }
        classes
    }

    /// PREMISE for both tests below. An extraction that silently returned an
    /// empty set would make an equality assertion fail loudly on one side and
    /// prove nothing on the other; the shapes are asserted explicitly.
    #[test]
    fn the_marker_blocks_parse_to_the_expected_shape() {
        let seed = block_classes(SEED_BEGIN, SEED_END);
        assert!(
            seed.len() > 30,
            "premise: the seed block must hold the real class list, parsed {} \
             entries: {seed:?}",
            seed.len()
        );
        for expected in ["PINFL", "BEARER_TOKEN", "EMAIL_ADDRESS", "SSN"] {
            assert!(
                seed.contains(expected),
                "premise: the seed block must contain {expected}: {seed:?}"
            );
        }

        // The parse must read its OWN block only. `GCP_KEY` / `AZURE_KEY`
        // appear elsewhere in 024 (assembling the legacy shape) and are
        // deliberately NOT inside either block, so finding one here would
        // mean the extraction over-reached.
        assert!(
            !seed.contains("GCP_KEY"),
            "premise: the seed parse leaked outside its marker block: {seed:?}"
        );

        let opt_in = block_classes(OPT_IN_BEGIN, OPT_IN_END);
        assert_eq!(
            opt_in.len(),
            2,
            "premise: the opt-in block must hold exactly the two SSN \
             spellings: {opt_in:?}"
        );
    }

    /// The seed shape the migration recognises must be exactly what a
    /// workspace carried immediately before the demotion: everything seeded
    /// today, plus everything demoted.
    #[test]
    fn migration_024_seed_shape_equals_the_defaults_plus_the_opt_ins() {
        let expected: BTreeSet<String> = DEFAULT_POLICY_CLASSES
            .iter()
            .chain(OPT_IN_ONLY_CLASSES.iter())
            .map(|class| (*class).to_owned())
            .collect();

        assert_eq!(
            block_classes(SEED_BEGIN, SEED_END),
            expected,
            "024's PRE-DEMOTION SEED SHAPE must equal DEFAULT_POLICY_CLASSES \
             + OPT_IN_ONLY_CLASSES. It is what the migration compares a rule \
             against to decide the rule is an untouched seed, so a class \
             missing here means every workspace seeded after that class was \
             added no longer matches and is silently skipped."
        );
    }

    /// What the migration strips must be exactly what Rust demoted.
    #[test]
    fn migration_024_strips_exactly_the_opt_in_only_classes() {
        let expected: BTreeSet<String> = OPT_IN_ONLY_CLASSES
            .iter()
            .map(|class| (*class).to_owned())
            .collect();

        assert_eq!(
            block_classes(OPT_IN_BEGIN, OPT_IN_END),
            expected,
            "024 strips a different set of classes than OPT_IN_ONLY_CLASSES \
             demotes, so new workspaces and existing ones would disagree \
             about which classes are opt-in"
        );
    }
}

/// `024_demote_ssn_to_opt_in.sql` executed by a NON-SUPERUSER, NOBYPASSRLS
/// role.
///
/// WHY THIS MODULE EXISTS, measured rather than assumed. Deleting the
/// `PERFORM set_config('app.current_workspace_id', ...)` line from 024
/// entirely — the exact mutation that reproduces the `017` defect — left
/// `migration_024_tests` above at 12 passed / 0 failed. Those tests connect
/// through the `#[sqlx::test]` pool, whose role is a SUPERUSER
/// (`rolsuper = t`, `rolbypassrls = t`), and superusers bypass RLS
/// unconditionally. A migration test that only ever runs as superuser cannot
/// observe an RLS defect at all, so without this module 024's whole
/// RLS-safety claim would be a comment nobody had executed.
///
/// Same technique and the same role as `tests/migration_020_rls.rs`: FIXTURE
/// setup goes through the ordinary superuser pool (the application itself
/// still depends on connecting as a BYPASSRLS role — the DB role-split is a
/// separate backlog item), and only the MIGRATION runs on the low-privilege
/// connection.
#[cfg(test)]
mod migration_024_rls_tests {
    use sqlx::postgres::PgConnectOptions;
    use sqlx::{Connection, PgConnection, PgPool, Row};
    use uuid::Uuid;

    const MIGRATION_SQL: &str = include_str!("../../migrations/024_demote_ssn_to_opt_in.sql");

    const RLS_ROLE: &str = "secureprompt_runner";
    const RLS_PASSWORD: &str = "secureprompt";

    /// The pre-demotion seed, built from the two consts so it cannot drift.
    fn pre_demotion_seed() -> String {
        let classes: Vec<&str> = crate::db::workspace_repo::DEFAULT_POLICY_CLASSES
            .iter()
            .chain(crate::db::workspace_repo::OPT_IN_ONLY_CLASSES.iter())
            .copied()
            .collect();
        serde_json::to_string(&classes).unwrap()
    }

    /// Raw inserts through the privileged pool, deliberately not through
    /// `create_with_owner`: the low-privilege role cannot insert into
    /// `policy_rules` at all, and this suite is about the migration, not the
    /// seeding path.
    async fn seed_rule(pool: &PgPool, rule_name: &str, classes: &str) -> Uuid {
        let workspace_id = Uuid::new_v4();
        sqlx::query("INSERT INTO workspaces (id, name) VALUES ($1, $2)")
            .bind(workspace_id)
            .bind("RLS Demotion Co")
            .execute(pool)
            .await
            .expect("workspace insert");

        let rule_id = Uuid::new_v4();
        let conditions: serde_json::Value = serde_json::from_str(&format!(
            r#"[{{"field":"detection_class","op":"in","value":{classes}}}]"#
        ))
        .expect("fixture class list is valid JSON");

        sqlx::query(
            "INSERT INTO policy_rules
                (id, workspace_id, name, priority, conditions, action, action_params,
                 enabled, dry_run, created_at, updated_at)
             VALUES ($1, $2, $3, 100, $4, 'redact', '{}'::jsonb, true, false, NOW(), NOW())",
        )
        .bind(rule_id)
        .bind(workspace_id)
        .bind(rule_name)
        .bind(&conditions)
        .execute(pool)
        .await
        .expect("policy rule insert");

        rule_id
    }

    async fn classes_of(pool: &PgPool, rule_id: Uuid) -> Vec<String> {
        let row = sqlx::query("SELECT conditions FROM policy_rules WHERE id = $1")
            .bind(rule_id)
            .fetch_one(pool)
            .await
            .expect("rule must still exist");
        let conditions: serde_json::Value = row.get("conditions");
        conditions[0]["value"]
            .as_array()
            .expect("conditions[0].value must be an array")
            .iter()
            .filter_map(|value| value.as_str().map(ToOwned::to_owned))
            .collect()
    }

    /// Create the role if absent, then hand this test database's tables to
    /// it. Idempotent and concurrency-safe: roles are cluster-global while
    /// `#[sqlx::test]` databases are per-test, so several tests race here.
    async fn ensure_low_privilege_role(pool: &PgPool) {
        sqlx::raw_sql(&format!(
            "DO $$
             BEGIN
                 CREATE ROLE {RLS_ROLE}
                     LOGIN PASSWORD '{RLS_PASSWORD}'
                     NOSUPERUSER CREATEDB CREATEROLE NOBYPASSRLS;
             EXCEPTION
                 WHEN duplicate_object THEN NULL;
             END $$;"
        ))
        .execute(pool)
        .await
        .unwrap_or_else(|e| {
            panic!(
                "could not create the {RLS_ROLE} role ({e}). In CI this role \
                 is created by scripts/ci/create-nonsuperuser-role.sh; \
                 locally the connecting role needs CREATEROLE. This module \
                 refuses to fall back to the superuser connection, because a \
                 migration test that runs as superuser cannot observe an RLS \
                 defect at all."
            )
        });

        sqlx::raw_sql(&format!(
            "GRANT USAGE ON SCHEMA public TO {RLS_ROLE};
             GRANT ALL ON ALL TABLES IN SCHEMA public TO {RLS_ROLE};
             GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO {RLS_ROLE};"
        ))
        .execute(pool)
        .await
        .expect("grants on the test database");
    }

    /// Open a connection to the SAME `#[sqlx::test]` database as `RLS_ROLE`
    /// and assert ON THE WIRE that it really is powerless. Without these
    /// premise assertions the module is worthless: if a base image or a stray
    /// `ALTER ROLE` handed this role SUPERUSER or BYPASSRLS, both tests below
    /// would keep passing while exercising no RLS at all.
    async fn low_privilege_connection(pool: &PgPool) -> PgConnection {
        ensure_low_privilege_role(pool).await;

        let options: PgConnectOptions = (*pool.connect_options())
            .clone()
            .username(RLS_ROLE)
            .password(RLS_PASSWORD);

        let mut conn = PgConnection::connect_with(&options)
            .await
            .expect("low-privilege connection to the test database");

        let row = sqlx::query(
            "SELECT current_user::text AS who, rolsuper, rolbypassrls
             FROM pg_roles WHERE rolname = current_user",
        )
        .fetch_one(&mut conn)
        .await
        .expect("identity probe");

        let who: String = row.get("who");
        let superuser: bool = row.get("rolsuper");
        let bypassrls: bool = row.get("rolbypassrls");

        assert_eq!(who, RLS_ROLE, "premise: connected as the wrong role");
        assert!(
            !superuser,
            "premise: {who} is a SUPERUSER, so it bypasses RLS and this test \
             proves nothing"
        );
        assert!(
            !bypassrls,
            "premise: {who} has BYPASSRLS, so it bypasses RLS and this test \
             proves nothing"
        );

        conn
    }

    /// CHARACTERISATION + PREMISE for the test below: prove this harness can
    /// actually SEE the defect. A bare `UPDATE policy_rules ...` — the shape
    /// 017 ships, and what 024 would degrade to if its `set_config` were
    /// hoisted out of the loop — reports ZERO rows affected and does NOT
    /// error, even though the row is right there and the superuser pool reads
    /// it fine.
    #[sqlx::test]
    async fn a_bare_update_silently_matches_zero_rows_under_rls(pool: PgPool) {
        let rule_id = seed_rule(&pool, "Redact common PII", &pre_demotion_seed()).await;

        // PREMISE: the row exists and is visible to the privileged pool, so a
        // zero row count below is about RLS and not about an empty table.
        let before = classes_of(&pool, rule_id).await;
        assert!(
            before.contains(&"SSN".to_owned()),
            "premise: the fixture rule must exist and carry SSN: {before:?}"
        );

        let mut conn = low_privilege_connection(&pool).await;
        let affected = sqlx::query("UPDATE policy_rules SET updated_at = NOW()")
            .execute(&mut conn)
            .await
            .expect("a bare UPDATE under RLS SUCCEEDS — that is the defect")
            .rows_affected();

        assert_eq!(
            affected, 0,
            "premise: a bare UPDATE must be invisible to this role, otherwise \
             the connection is not actually RLS-constrained and the test \
             below proves nothing"
        );
    }

    /// THE PROPERTY: 024's loop-over-`workspaces` shape survives a role that
    /// cannot bypass RLS. This is the assertion behind the migration header's
    /// RLS-safety claim.
    #[sqlx::test]
    async fn demotion_applies_under_a_nonsuperuser_role(pool: PgPool) {
        let rule_id = seed_rule(&pool, "Redact common PII", &pre_demotion_seed()).await;

        let before = classes_of(&pool, rule_id).await;
        assert!(
            before.contains(&"SSN".to_owned()) && before.contains(&"US_SSN".to_owned()),
            "premise: both spellings must be present before: {before:?}"
        );

        let mut conn = low_privilege_connection(&pool).await;
        sqlx::raw_sql(MIGRATION_SQL)
            .execute(&mut conn)
            .await
            .expect("024 must apply cleanly as a NOSUPERUSER/NOBYPASSRLS role");

        let after = classes_of(&pool, rule_id).await;
        assert!(
            !after.contains(&"SSN".to_owned()) && !after.contains(&"US_SSN".to_owned()),
            "024 SHIPPED AS A NO-OP under RLS — the same defect as 017. The \
             loop over `workspaces` with `set_config` per workspace is what \
             prevents this: {after:?}"
        );
        assert!(
            after.contains(&"PERSON".to_owned()) && after.contains(&"STIR".to_owned()),
            "nothing but the demoted classes may be removed: {after:?}"
        );
    }
}
