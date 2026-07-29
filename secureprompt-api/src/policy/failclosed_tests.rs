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
    use crate::db::workspace_repo::DEFAULT_POLICY_CLASSES;
    use std::collections::BTreeSet;

    const REGISTRY_SRC: &str = include_str!("../detection/registry.rs");

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

    /// The audit that was never run. Every class the registry can emit must
    /// be a deliberate decision in `DEFAULT_POLICY_CLASSES` — present, or
    /// consciously excluded on the allow-list below.
    #[test]
    fn default_policy_classes_cover_every_registry_class() {
        let listed: BTreeSet<&str> = DEFAULT_POLICY_CLASSES.iter().copied().collect();
        let missing: Vec<String> = registry_classes()
            .into_iter()
            .filter(|class| !listed.contains(class.as_str()))
            .collect();

        assert!(
            missing.is_empty(),
            "these detector classes are emitted by the registry but are NOT in \
             DEFAULT_POLICY_CLASSES, so a new workspace detects them and then \
             forwards them in the clear whenever another listed class is also \
             present: {missing:?}. Add them here AND in a back-fill migration."
        );
    }

    /// The other direction: an entry naming a class nothing ever emits is a
    /// DEAD NAME. It looks like protection in the policy UI and is not.
    /// `GCP_KEY` and `AZURE_KEY` were exactly this.
    #[test]
    fn default_policy_classes_contains_no_dead_names() {
        let registry = registry_classes();
        // ML-sidecar-only classes. These are emitted by
        // `secureprompt-ml/app/detection/*.py` (Presidio / XLM-R label maps),
        // never by the Rust registry, so their absence from the scan is
        // expected and not a dead name.
        const ML_ONLY: &[&str] = &["PERSON", "US_SSN", "IBAN_CODE"];

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
    use crate::db::workspace_repo::DEFAULT_POLICY_CLASSES;
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
    #[test]
    fn migration_020_backfills_exactly_default_policy_classes() {
        let listed: BTreeSet<String> = DEFAULT_POLICY_CLASSES
            .iter()
            .map(|class| (*class).to_owned())
            .collect();
        let migration = migration_backfill_classes();

        let missing_from_migration: Vec<&String> = listed.difference(&migration).collect();
        let missing_from_rust: Vec<&String> = migration.difference(&listed).collect();

        assert!(
            missing_from_migration.is_empty(),
            "these classes are in DEFAULT_POLICY_CLASSES but NOT in the \
             back-fill list of 020, so every workspace created before the \
             class was added detects them and then forwards them in the \
             clear: {missing_from_migration:?}"
        );
        assert!(
            missing_from_rust.is_empty(),
            "these classes are back-filled by 020 but are NOT in \
             DEFAULT_POLICY_CLASSES, so a NEW workspace would be seeded \
             without them — existing workspaces would be better protected \
             than new ones: {missing_from_rust:?}"
        );
    }
}
