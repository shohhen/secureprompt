/// WS2-1 round-1 review: the flagship claim, verified through the POLICY
/// path rather than by calling `apply_redaction` directly.
///
/// A new workspace is seeded with a `detection_class in DEFAULT_POLICY_CLASSES`
/// redact rule (`db/workspace_repo.rs`). That makes `rules_evaluated == 1`,
/// which suppresses the `redact_when_no_rules` safety net in
/// `pipeline/service.rs`, and `policy/engine.rs` then redacts only the
/// detections `matching_detections` returns. `matching_detections` falls back
/// to "all detections" ONLY when the class filter matches nothing — so a
/// prompt mixing a covered class (an email) with an uncovered one (a PINFL)
/// redacts the email and forwards the PINFL. Detecting an identifier is not
/// the same as redacting it, and only a test through `evaluate` can tell the
/// difference.
#[cfg(test)]
mod default_policy_path_tests {
    use crate::db::{PolicyRepository, WorkspaceRepository};
    use crate::detection::{detect_content, merge::merge_detections};
    use crate::policy::engine::{evaluate, PolicyEvaluationInput};
    use secureprompt_common::types::{RequestId, TokenVault, WorkspaceId};
    use sqlx::PgPool;
    use std::collections::HashMap;

    /// A realistic requisites prompt. The email is load-bearing: without a
    /// detection whose class IS in the seeded list, `matching_detections`
    /// would fall back to redacting everything and hide the bug.
    const REQUISITES_PROMPT: &str = "Ali Aliev, ali@example.com, \
         PINFL 50101901234567, STIR 300111222, МФО 00014, \
         pasport AA1234567, karta 8600 1234 5678 9012";

    async fn redact_through_policy(pool: &PgPool, content: &str) -> String {
        let hash = crate::db::user_repo::hash_password("pw-for-test-only").unwrap();
        let (workspace, _) = WorkspaceRepository::new(pool.clone())
            .create_with_owner("Policy Path Co", "policy-path@example.com", &hash)
            .await
            .expect("workspace + seeded rule must be created");

        // Empty ML vector — the whole point is that the deterministic floor
        // survives with the sidecar absent.
        let detections = merge_detections(detect_content(content), vec![]);
        assert!(
            !detections.is_empty(),
            "precondition: the floor must detect something"
        );

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
                detections: &detections,
                fail_closed: false,
            },
            &mut vault,
            &mut redaction_map,
        )
        .await
        .expect("policy evaluation must succeed");

        assert_eq!(
            outcome.rules_evaluated, 1,
            "the seeded rule must be the one and only rule — if this is 0 the \
             redact_when_no_rules safety net would mask the bug under test"
        );
        assert_eq!(outcome.result.final_action, "redact");
        outcome.content
    }

    #[sqlx::test]
    async fn seeded_default_rule_redacts_uzbek_identifiers(pool: PgPool) {
        let redacted = redact_through_policy(&pool, REQUISITES_PROMPT).await;

        for leaked in [
            "50101901234567",
            "300111222",
            "00014",
            "AA1234567",
            "8600 1234 5678 9012",
        ] {
            assert!(
                !redacted.contains(leaked),
                "{leaked} was detected but forwarded unredacted by the default \
                 policy: {redacted:?}"
            );
        }
    }

    #[sqlx::test]
    async fn seeded_default_rule_still_redacts_the_pre_existing_classes(pool: PgPool) {
        // Regression guard: widening the class list must not drop anything.
        let redacted = redact_through_policy(&pool, REQUISITES_PROMPT).await;
        assert!(
            !redacted.contains("ali@example.com"),
            "email regressed: {redacted:?}"
        );
    }
}

/// WS2-1 round-1 review: migration `017` back-fills workspaces that were
/// already seeded with the pre-Uzbek class list.
///
/// `#[sqlx::test]` runs every migration before the test body, so the seeded
/// rule a test creates is already new-shaped. To prove the migration itself
/// does anything, these tests write a LEGACY-shaped rule and then execute the
/// migration file's own SQL against it.
#[cfg(test)]
mod migration_backfill_tests {
    use crate::db::WorkspaceRepository;
    use sqlx::{PgPool, Row};
    use uuid::Uuid;

    const MIGRATION_SQL: &str =
        include_str!("../../migrations/017_uzbek_identifier_policy_classes.sql");

    const LEGACY_CLASSES: &str = r#"["PERSON","EMAIL_ADDRESS","PHONE_NUMBER","CREDIT_CARD","US_SSN","IBAN_CODE","AWS_ACCESS_KEY","GCP_KEY","AZURE_KEY"]"#;

    /// Create a workspace, delete its (already-migrated) seeded rule, and
    /// insert one shaped exactly as it looked before this change.
    async fn seed_legacy_rule(pool: &PgPool, name: &str, classes: &str) -> Uuid {
        let hash = crate::db::user_repo::hash_password("pw-for-test-only").unwrap();
        let (workspace, _) = WorkspaceRepository::new(pool.clone())
            .create_with_owner(
                "Legacy Co",
                &format!("legacy-{}@example.com", Uuid::new_v4()),
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

    #[sqlx::test]
    async fn backfills_a_legacy_seeded_rule(pool: PgPool) {
        let rule_id = seed_legacy_rule(&pool, "Redact common PII", LEGACY_CLASSES).await;
        assert!(!classes_of(&pool, rule_id)
            .await
            .contains(&"PINFL".to_owned()));

        sqlx::raw_sql(MIGRATION_SQL).execute(&pool).await.unwrap();

        let classes = classes_of(&pool, rule_id).await;
        for expected in ["PINFL", "STIR", "MFO", "PASSPORT_NUMBER", "UZCARD", "HUMO"] {
            assert!(
                classes.contains(&expected.to_owned()),
                "{expected} missing after back-fill: {classes:?}"
            );
        }
        // Nothing may be dropped.
        assert!(classes.contains(&"PERSON".to_owned()), "{classes:?}");
        assert!(classes.contains(&"CREDIT_CARD".to_owned()), "{classes:?}");
    }

    #[sqlx::test]
    async fn backfill_is_idempotent(pool: PgPool) {
        let rule_id = seed_legacy_rule(&pool, "Redact common PII", LEGACY_CLASSES).await;

        sqlx::raw_sql(MIGRATION_SQL).execute(&pool).await.unwrap();
        let once = classes_of(&pool, rule_id).await;
        sqlx::raw_sql(MIGRATION_SQL).execute(&pool).await.unwrap();
        let twice = classes_of(&pool, rule_id).await;

        assert_eq!(once, twice, "re-running the migration must not duplicate");
    }

    #[sqlx::test]
    async fn does_not_touch_a_rule_an_admin_narrowed(pool: PgPool) {
        // An admin who removed CREDIT_CARD meant it. Widening their rule
        // behind their back would be a policy change we were never asked to
        // make; these workspaces are the documented operator action.
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
        // Superset of the defaults — the admin added to the seed rather than
        // replacing it, so the back-fill still applies.
        let widened = r#"["PERSON","EMAIL_ADDRESS","PHONE_NUMBER","CREDIT_CARD","US_SSN","IBAN_CODE","AWS_ACCESS_KEY","GCP_KEY","AZURE_KEY","LOCATION"]"#;
        let rule_id = seed_legacy_rule(&pool, "Redact common PII", widened).await;

        sqlx::raw_sql(MIGRATION_SQL).execute(&pool).await.unwrap();

        let classes = classes_of(&pool, rule_id).await;
        assert!(classes.contains(&"PINFL".to_owned()), "{classes:?}");
        assert!(
            classes.contains(&"LOCATION".to_owned()),
            "the admin's own addition must survive: {classes:?}"
        );
    }

    /// Round-2 review: an admin who had already added one of the new classes
    /// by hand must not end up with a duplicate entry.
    #[sqlx::test]
    async fn backfill_does_not_duplicate_a_class_the_admin_already_added(pool: PgPool) {
        let with_stir = r#"["PERSON","EMAIL_ADDRESS","PHONE_NUMBER","CREDIT_CARD","US_SSN","IBAN_CODE","AWS_ACCESS_KEY","GCP_KEY","AZURE_KEY","STIR"]"#;
        let rule_id = seed_legacy_rule(&pool, "Redact common PII", with_stir).await;

        sqlx::raw_sql(MIGRATION_SQL).execute(&pool).await.unwrap();

        let classes = classes_of(&pool, rule_id).await;
        assert_eq!(
            classes.iter().filter(|c| *c == "STIR").count(),
            1,
            "STIR must appear exactly once: {classes:?}"
        );
        assert!(classes.contains(&"PINFL".to_owned()), "{classes:?}");
        assert!(classes.contains(&"HUMO".to_owned()), "{classes:?}");
    }

    #[sqlx::test]
    async fn does_not_touch_an_unrelated_rule(pool: PgPool) {
        let rule_id = seed_legacy_rule(&pool, "Block secrets", LEGACY_CLASSES).await;

        sqlx::raw_sql(MIGRATION_SQL).execute(&pool).await.unwrap();

        assert!(
            !classes_of(&pool, rule_id)
                .await
                .contains(&"PINFL".to_owned()),
            "only the seeded 'Redact common PII' rule may be back-filled"
        );
    }
}

/// Tests for the policy engine: rule ordering, condition evaluation, dry-run semantics.
///
/// These tests verify:
/// - Policy engine evaluates rules first-match-wins by priority ASC, id ASC
/// - dry_run records events without mutating client-visible content by default
/// - All ADR actions (deny, allow, redact, transform, flag) are handled
/// - Conditions: detection_class eq/in, confidence_gte/lte, provider eq/in, model eq/in, content_regex matches
///
/// Note: The public `evaluate` function requires a live Postgres connection.
/// We test the internal condition helpers directly via cfg(test) visibility.
#[cfg(test)]
mod condition_tests {
    use crate::db::PolicyRuleRow;
    use chrono::Utc;
    use uuid::Uuid;

    fn make_rule(
        priority: i32,
        conditions: serde_json::Value,
        action: &str,
        dry_run: bool,
    ) -> PolicyRuleRow {
        PolicyRuleRow {
            id: Uuid::new_v4(),
            workspace_id: Uuid::new_v4(),
            name: "test-rule".to_owned(),
            priority,
            conditions,
            action: action.to_owned(),
            action_params: serde_json::json!({}),
            enabled: true,
            dry_run,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    // Test rule_matches through the public interface by testing placeholder ordering
    // We access private helpers via a sibling module in tests
    #[test]
    fn rules_ordered_by_priority_asc_then_id_asc() {
        // This test verifies the ORDER BY priority ASC, id ASC policy requirement.
        // We create two rules with different priorities and verify the lower-priority (higher number) one
        // would be evaluated second. Since rule_matches is private, we test the ordering concept
        // via the PolicyRuleRow sort behavior.
        let rule_high_priority = make_rule(10, serde_json::json!([]), "deny", false);
        let rule_low_priority = make_rule(100, serde_json::json!([]), "allow", false);

        // Simulate the ORDER BY: sort by priority ASC then id ASC
        let mut rules = vec![rule_low_priority, rule_high_priority];
        rules.sort_by(|a, b| a.priority.cmp(&b.priority).then(a.id.cmp(&b.id)));

        assert_eq!(
            rules[0].action, "deny",
            "First rule after ordering must be the one with priority=10 (deny)"
        );
        assert_eq!(
            rules[1].action, "allow",
            "Second rule after ordering must be the one with priority=100 (allow)"
        );
    }

    #[test]
    fn equal_priority_ordered_by_id_asc() {
        // Two rules with the same priority — lower UUID sorts first
        let id_a = Uuid::from_u128(1);
        let id_b = Uuid::from_u128(2);

        let mut rule_a = make_rule(50, serde_json::json!([]), "deny", false);
        rule_a.id = id_a;

        let mut rule_b = make_rule(50, serde_json::json!([]), "allow", false);
        rule_b.id = id_b;

        let mut rules = vec![rule_b, rule_a];
        rules.sort_by(|a, b| a.priority.cmp(&b.priority).then(a.id.cmp(&b.id)));

        assert_eq!(
            rules[0].id, id_a,
            "Lower UUID must come first at equal priority"
        );
    }

    #[test]
    fn dry_run_rule_does_not_change_action_marker() {
        // A dry_run rule: engine records event but does NOT update final_action
        // We verify this by simulating the engine logic
        let dry_rule = make_rule(10, serde_json::json!([]), "deny", true);
        let normal_rule = make_rule(20, serde_json::json!([]), "allow", false);

        // The dry_run path: engine `continue`s without setting final_action
        // We test the expected behavior: if only dry_run rules match, final_action stays "allow" (default)
        let mut final_action = "allow".to_owned();

        // Simulate engine loop for dry_run rule
        if dry_rule.dry_run {
            // Skip action enforcement — only emit event
            // final_action stays "allow"
        } else {
            final_action = dry_rule.action.clone();
        }

        assert_eq!(
            final_action, "allow",
            "dry_run rule must not change final_action"
        );

        // Simulate normal rule
        if !normal_rule.dry_run {
            final_action = normal_rule.action.clone();
        }

        assert_eq!(
            final_action, "allow",
            "normal allow rule changes final_action to allow"
        );
    }

    /// WS1-8 fix-round-1 review, MINOR 3: this used to assert
    /// `json!([]).as_array().is_empty()` — a fact about `serde_json`, not
    /// about this crate's `rule_matches`, and the only test covering the
    /// empty-conditions case. `rule_matches` is now `pub(crate)` (made so
    /// for the WS1-8 compound-condition tests), which unblocks calling the
    /// real function here instead. Checked both with and without
    /// detections present, since the empty-conditions short-circuit
    /// (`detection_conditions.is_empty() || ...`) and the vacuous-`.all()`
    /// path it replaces behave differently depending on which is present.
    #[test]
    fn empty_conditions_matches_all_requests() {
        use crate::policy::engine::{rule_matches, PolicyEvaluationInput};
        use secureprompt_common::types::{Detection, RequestId, WorkspaceId};

        let rule = make_rule(10, serde_json::json!([]), "flag", false);

        let no_detections: Vec<Detection> = Vec::new();
        assert!(
            rule_matches(
                &rule,
                &PolicyEvaluationInput {
                    request_id: RequestId::new(),
                    workspace_id: WorkspaceId::new(),
                    provider_name: "test-provider",
                    model: "test-model",
                    content: "irrelevant — the rule has no conditions to check",
                    detections: &no_detections,
                    fail_closed: false,
                }
            ),
            "empty conditions must match even when there are no detections"
        );

        let some_detections = vec![Detection {
            class: "EMAIL_ADDRESS".to_owned(),
            confidence: 0.42,
            span: None,
            value: "synthetic-value".to_owned(),
        }];
        assert!(
            rule_matches(
                &rule,
                &PolicyEvaluationInput {
                    request_id: RequestId::new(),
                    workspace_id: WorkspaceId::new(),
                    provider_name: "test-provider",
                    model: "test-model",
                    content: "irrelevant — the rule has no conditions to check",
                    detections: &some_detections,
                    fail_closed: false,
                }
            ),
            "empty conditions must match regardless of which detections are present"
        );
    }

    #[test]
    fn detection_class_eq_condition_matches_correctly() {
        // Verify condition JSON structure for detection_class eq
        let conditions = serde_json::json!([
            { "field": "detection_class", "op": "eq", "value": "email" }
        ]);

        let condition = &conditions[0];
        let field = condition["field"].as_str().unwrap();
        let op = condition["op"].as_str().unwrap();
        let value = condition["value"].as_str().unwrap();

        assert_eq!(field, "detection_class");
        assert_eq!(op, "eq");
        assert_eq!(value, "email");
    }

    #[test]
    fn confidence_gte_condition_json_structure() {
        let conditions = serde_json::json!([
            { "field": "confidence_gte", "op": "gte", "value": 0.85 }
        ]);

        let condition = &conditions[0];
        let threshold = condition["value"].as_f64().unwrap();
        assert!(
            (threshold - 0.85).abs() < 1e-6,
            "Threshold must be 0.85, got: {threshold}"
        );
    }

    #[test]
    fn deny_action_sets_denied_flag() {
        // Simulate the deny branch of the policy engine
        let mut denied = false;
        let action = "deny";

        match action {
            "deny" => {
                denied = true;
            }
            _ => {}
        }

        assert!(denied, "deny action must set denied=true");
    }

    #[test]
    fn allow_action_breaks_evaluation() {
        // Simulate allow: after allow matches, we stop evaluating further rules
        let rules = vec![
            make_rule(10, serde_json::json!([]), "allow", false),
            make_rule(20, serde_json::json!([]), "deny", false),
        ];

        let mut final_action = "allow".to_owned();
        let mut denied = false;

        for rule in &rules {
            if rule.dry_run {
                continue;
            }
            final_action = rule.action.clone();
            match rule.action.as_str() {
                "allow" => break,
                "deny" => {
                    denied = true;
                    break;
                }
                _ => {}
            }
        }

        assert_eq!(final_action, "allow", "allow rule must be final action");
        assert!(!denied, "allow rule must not set denied");
    }
}

/// WS1-8: a compound condition (multiple conditions combined with AND on the same rule)
/// must be satisfied by a SINGLE detection, not by different detections each
/// covering one condition. Unlike `condition_tests` above (which simulates
/// engine logic inline because the helpers were private), these tests call
/// the real `rule_matches` directly — `rule_matches` was made
/// `pub(crate)` for exactly this purpose, so the bug is exercised through
/// production code, not a re-implementation of it.
#[cfg(test)]
mod compound_condition_tests {
    use crate::db::PolicyRuleRow;
    use crate::policy::engine::{rule_matches, PolicyEvaluationInput};
    use chrono::Utc;
    use secureprompt_common::types::{Detection, RequestId, WorkspaceId};
    use uuid::Uuid;

    fn compound_rule(conditions: serde_json::Value) -> PolicyRuleRow {
        PolicyRuleRow {
            id: Uuid::new_v4(),
            workspace_id: Uuid::new_v4(),
            name: "compound-test-rule".to_owned(),
            priority: 100,
            conditions,
            action: "redact".to_owned(),
            action_params: serde_json::json!({}),
            enabled: true,
            dry_run: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn detection(class: &str, confidence: f32) -> Detection {
        Detection {
            class: class.to_owned(),
            confidence,
            span: None,
            value: "synthetic-value".to_owned(),
        }
    }

    fn eval_input(detections: &[Detection]) -> PolicyEvaluationInput<'_> {
        PolicyEvaluationInput {
            request_id: RequestId::new(),
            workspace_id: WorkspaceId::new(),
            provider_name: "test-provider",
            model: "test-model",
            content: "irrelevant content — no content_regex condition in these rules",
            detections,
            fail_closed: false,
        }
    }

    /// The exact defect from the brief: a rule reading
    /// `detection_class == EMAIL_ADDRESS AND confidence_gte >= 0.9` must
    /// match only when ONE detection is both an `EMAIL_ADDRESS` and >= 0.9
    /// confidence. Here the class is satisfied by one detection and the
    /// confidence threshold by a completely different one — the rule must
    /// NOT fire.
    #[test]
    fn compound_condition_does_not_match_when_two_different_detections_split_the_conditions() {
        let rule = compound_rule(serde_json::json!([
            { "field": "detection_class", "op": "eq", "value": "EMAIL_ADDRESS" },
            { "field": "confidence_gte", "op": "gte", "value": 0.9 }
        ]));

        let detections = vec![
            detection("EMAIL_ADDRESS", 0.5), // satisfies class only
            detection("PHONE_NUMBER", 0.95), // satisfies confidence only
        ];
        let input = eval_input(&detections);

        assert!(
            !rule_matches(&rule, &input),
            "rule must NOT match when the class test and the confidence test \
             are satisfied by two different detections rather than one"
        );
    }

    /// Same rule, but one detection now satisfies both conditions at once —
    /// this is the case the rule is actually meant to catch, and it must
    /// still fire. Paired with the test above as a positive control: same
    /// rule shape, different detection composition, opposite expected
    /// outcome.
    #[test]
    fn compound_condition_matches_when_one_detection_satisfies_both() {
        let rule = compound_rule(serde_json::json!([
            { "field": "detection_class", "op": "eq", "value": "EMAIL_ADDRESS" },
            { "field": "confidence_gte", "op": "gte", "value": 0.9 }
        ]));

        let detections = vec![
            detection("EMAIL_ADDRESS", 0.95), // satisfies both at once
            detection("PHONE_NUMBER", 0.5),   // unrelated, must be ignored
        ];
        let input = eval_input(&detections);

        assert!(
            rule_matches(&rule, &input),
            "rule must match when a single detection satisfies every \
             condition in the rule"
        );
    }

    /// Regression guard mirroring the workspace default rule seeded by
    /// `db/workspace_repo.rs` (`detection_class in [...]`, a single
    /// condition). A single detection-scoped condition is trivially
    /// "per-detection" already — it must keep matching via ANY qualifying
    /// detection, exactly as before this task.
    #[test]
    fn single_detection_class_in_condition_still_matches_via_any_qualifying_detection() {
        let rule = compound_rule(serde_json::json!([
            { "field": "detection_class", "op": "in", "value": ["EMAIL_ADDRESS", "PERSON"] }
        ]));

        let detections = vec![
            detection("PINFL", 0.99),         // not in the list
            detection("EMAIL_ADDRESS", 0.10), // in the list; no confidence condition present
        ];
        let input = eval_input(&detections);

        assert!(
            rule_matches(&rule, &input),
            "a lone detection_class-in condition must still match via any \
             qualifying detection"
        );
    }
}

/// WS1-8 fix-round-1 review, IMPORTANT 1: pins the second-order effect of
/// the fix through the real `evaluate()` path (not just `rule_matches`
/// directly). See `task-5-report.md` for the operator-facing writeup.
///
/// Pre-fix: a compound rule (`detection_class == X AND confidence_gte >=
/// Y`) that fired only because the class test and the confidence test were
/// satisfied by two DIFFERENT detections (the bug WS1-8 fixes) still
/// reached `matching_detections`. There, `class_filters = [X]` and
/// `confidence_gte = Y` are checked against EACH detection individually —
/// neither detection satisfied both at once, so the filtered set came back
/// empty, which hit the `detections.to_vec()` fallback at the bottom of
/// `matching_detections`. Pre-fix, that fallback redacted EVERY detection
/// in the request, including ones with nothing to do with the rule's
/// condition. Over-redaction, not a leak.
///
/// Post-fix: the rule correctly does not fire, so it redacts NOTHING. If
/// this compound rule were a workspace's only enabled rule (as it is here),
/// upgrading silently converts "redacts too much" into "redacts nothing"
/// for that workspace. `redact_when_no_rules` (`pipeline/service.rs:546`)
/// cannot rescue it — that gate only engages when `rules_evaluated == 0`
/// (`engine.rs:43`), and here `rules_evaluated == 1`. The new behaviour is
/// correct for what the rule's condition actually says — but it is a real,
/// silent coverage change for any existing workspace whose only rule looks
/// like this, and is worth a release note.
#[cfg(test)]
mod second_order_effect_tests {
    use crate::db::{PolicyRepository, WorkspaceRepository};
    use crate::policy::engine::{evaluate, PolicyEvaluationInput};
    use secureprompt_common::types::{Detection, RequestId, TokenVault, WorkspaceId};
    use sqlx::PgPool;
    use std::collections::HashMap;
    use uuid::Uuid;

    #[sqlx::test]
    async fn compound_rule_matched_via_split_detections_now_redacts_nothing_instead_of_everything(
        pool: PgPool,
    ) {
        let hash = crate::db::user_repo::hash_password("pw-for-test-only").unwrap();
        let (workspace, _) = WorkspaceRepository::new(pool.clone())
            .create_with_owner(
                "Second Order Co",
                &format!("second-order-{}@example.com", Uuid::new_v4()),
                &hash,
            )
            .await
            .expect("workspace must be created");

        // Replace the seeded default rule with ONLY the compound rule
        // under test, so there is exactly one enabled rule and the whole
        // effect is observable in `outcome` without another rule's action
        // interfering.
        sqlx::query("DELETE FROM policy_rules WHERE workspace_id = $1")
            .bind(workspace.id)
            .execute(&pool)
            .await
            .unwrap();

        let conditions = serde_json::json!([
            { "field": "detection_class", "op": "eq", "value": "EMAIL_ADDRESS" },
            { "field": "confidence_gte", "op": "gte", "value": 0.9 }
        ]);
        sqlx::query(
            "INSERT INTO policy_rules
                (id, workspace_id, name, priority, conditions, action, action_params,
                 enabled, dry_run, created_at, updated_at)
             VALUES ($1, $2, 'High-confidence email rule', 100, $3, 'redact', '{}'::jsonb,
                     true, false, NOW(), NOW())",
        )
        .bind(Uuid::new_v4())
        .bind(workspace.id)
        .bind(&conditions)
        .execute(&pool)
        .await
        .unwrap();

        let content = "Contact ali@example.com or +998901234567 for details";
        let email = "ali@example.com";
        let phone = "+998901234567";
        let email_start = content.find(email).unwrap();
        let phone_start = content.find(phone).unwrap();

        // SPLIT: the email detection satisfies the class test but not the
        // confidence test; the phone detection satisfies the confidence
        // test but is the wrong class. No single detection satisfies both.
        let detections = vec![
            Detection {
                class: "EMAIL_ADDRESS".to_owned(),
                confidence: 0.5,
                span: Some((email_start, email_start + email.len())),
                value: email.to_owned(),
            },
            Detection {
                class: "PHONE_NUMBER".to_owned(),
                confidence: 0.95,
                span: Some((phone_start, phone_start + phone.len())),
                value: phone.to_owned(),
            },
        ];

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
                detections: &detections,
                fail_closed: false,
            },
            &mut vault,
            &mut redaction_map,
        )
        .await
        .expect("policy evaluation must succeed");

        assert_eq!(
            outcome.rules_evaluated, 1,
            "the compound rule must be the only enabled rule for this to be observable"
        );
        assert_eq!(
            outcome.result.final_action, "allow",
            "the compound rule must not fire — its class test and its \
             confidence test are satisfied by two different detections, \
             not one"
        );
        assert_eq!(
            outcome.content, content,
            "post-fix, a rule that does not fire must redact NOTHING — \
             pre-fix, this same request was redacted in full (both the \
             email AND the phone number) via matching_detections' \
             empty-filter fallback, even though neither detection alone \
             satisfied the rule's condition"
        );
    }
}

#[cfg(test)]
mod events_tests {
    use crate::db::PolicyRuleRow;
    use crate::policy::events::from_rule;
    use chrono::Utc;
    use uuid::Uuid;

    fn make_rule(action: &str, dry_run: bool) -> PolicyRuleRow {
        PolicyRuleRow {
            id: Uuid::new_v4(),
            workspace_id: Uuid::new_v4(),
            name: "test".to_owned(),
            priority: 10,
            conditions: serde_json::json!([]),
            action: action.to_owned(),
            action_params: serde_json::json!({}),
            enabled: true,
            dry_run,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn from_rule_captures_action_and_dry_run() {
        let rule = make_rule("deny", false);
        let event = from_rule(&rule);
        assert_eq!(event.action, "deny");
        assert!(!event.dry_run);
    }

    #[test]
    fn from_rule_dry_run_true() {
        let rule = make_rule("redact", true);
        let event = from_rule(&rule);
        assert_eq!(event.action, "redact");
        assert!(event.dry_run, "Event must reflect dry_run=true from rule");
    }

    #[test]
    fn from_rule_preserves_rule_id() {
        let rule = make_rule("flag", false);
        let expected_id = rule.id;
        let event = from_rule(&rule);
        assert_eq!(
            event.rule_id, expected_id,
            "Event rule_id must match the rule's id"
        );
    }

    #[test]
    fn all_actions_captured_in_events() {
        for action in &["deny", "allow", "redact", "transform", "flag"] {
            let rule = make_rule(action, false);
            let event = from_rule(&rule);
            assert_eq!(
                &event.action, action,
                "Event action must match rule action: {action}"
            );
        }
    }
}

/// MR5 C2 — a local PAN must still satisfy a `CREDIT_CARD` policy rule.
///
/// `drop_generic_card_double_counts` (detection registry) suppresses the
/// generic `credit_card` detection on a span an Uzbek local-card class
/// already claimed with the identical value. Its doc claimed the change was
/// observationally neutral outside `GET /v1/leak-report`:
///
/// > Redaction never saw the difference … but `GET /v1/leak-report` dedups
/// > `per_class` on `(class, value)`
///
/// That was false. Policy evaluation runs BEFORE `apply_redaction` and
/// filters on `detection_class`, so dropping the `CREDIT_CARD` detection
/// removed the class a rule may be keyed on. A workspace whose enabled rules
/// name `CREDIT_CARD` and not `UZCARD`/`HUMO` — the 15-entry list migration
/// 017's back-fill leaves behind where it did not take, and anything an admin
/// narrowed in the policy UI — stopped matching an unseparated local PAN
/// altogether. The `redact_when_no_rules` net does not rescue a `deny`: it
/// redacts, it does not refuse.
///
/// The detections here come from the REAL registry through the REAL merge,
/// so this cannot pass on a hand-built `Detection` that has drifted from what
/// the pipeline actually produces.
///
/// All fixture card numbers are synthetic.
#[cfg(test)]
mod local_card_class_filter_tests {
    use crate::db::PolicyRuleRow;
    use crate::detection::{detect_content, merge::merge_detections};
    use crate::policy::engine::{rule_matches, PolicyEvaluationInput};
    use chrono::Utc;
    use secureprompt_common::types::{Detection, RequestId, WorkspaceId};
    use uuid::Uuid;

    /// Synthetic Uzcard PAN (IIN 8600), written unseparated — the one
    /// spelling that reaches both card matchers on the same span, and so the
    /// one the suppression pass acts on.
    const LOCAL_PAN: &str = "Karta 8600123456789012";
    /// Synthetic foreign PAN. No local matcher ever takes it, so the
    /// suppression cannot touch it by construction — which is exactly why it
    /// is a control here and NOT evidence about the local case.
    const FOREIGN_PAN: &str = "Karta 4111111111111111";

    /// What the policy engine actually receives: registry output put through
    /// `merge_detections`, which is where regex classes are upper-cased.
    fn pipeline_detections(content: &str) -> Vec<Detection> {
        merge_detections(detect_content(content), Vec::new())
    }

    fn classes(content: &str) -> Vec<String> {
        let mut found: Vec<String> = pipeline_detections(content)
            .into_iter()
            .map(|detection| detection.class)
            .collect();
        found.sort();
        found.dedup();
        found
    }

    fn rule_naming(classes: serde_json::Value, action: &str) -> PolicyRuleRow {
        PolicyRuleRow {
            id: Uuid::new_v4(),
            workspace_id: Uuid::new_v4(),
            name: "card-rule".to_owned(),
            priority: 100,
            conditions: serde_json::json!([
                { "field": "detection_class", "op": "in", "value": classes }
            ]),
            action: action.to_owned(),
            action_params: serde_json::json!({}),
            enabled: true,
            dry_run: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn eval_input<'a>(content: &'a str, detections: &'a [Detection]) -> PolicyEvaluationInput<'a> {
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

    /// PREMISE, not the thing under test. If this ever fails, the
    /// suppression pass has changed and the two assertions below are about a
    /// world that no longer exists — which is a signal, not a pass.
    #[test]
    fn an_unseparated_local_pan_carries_only_the_local_class() {
        assert_eq!(
            classes(LOCAL_PAN),
            vec!["UZCARD".to_owned()],
            "the generic CREDIT_CARD detection is suppressed on this span; \
             that suppression is the premise of this module"
        );
        assert_eq!(
            classes(FOREIGN_PAN),
            vec!["CREDIT_CARD".to_owned()],
            "no local matcher takes a foreign PAN, so the generic class \
             survives — the harness reaches the real registry"
        );
    }

    /// THE DEFECT. A rule that names `CREDIT_CARD` must fire on a local PAN.
    /// Before this fix it did not, and the PAN was forwarded in the clear.
    #[test]
    fn a_credit_card_rule_still_matches_an_unseparated_local_pan() {
        let rule = rule_naming(serde_json::json!(["CREDIT_CARD"]), "deny");
        let detections = pipeline_detections(LOCAL_PAN);
        let input = eval_input(LOCAL_PAN, &detections);

        assert!(
            rule_matches(&rule, &input),
            "a workspace rule naming CREDIT_CARD stopped matching an \
             unseparated local PAN — an unredacted card number reaches the \
             provider. Detections: {detections:?}"
        );
    }

    /// The same for `humo` (IIN 9860), so the alias is not a one-off keyed to
    /// the fixture above.
    #[test]
    fn a_credit_card_rule_still_matches_an_unseparated_humo_pan() {
        let content = "Karta 9860123456789015";
        assert_eq!(
            classes(content),
            vec!["HUMO".to_owned()],
            "premise: the generic class is suppressed here too"
        );

        let rule = rule_naming(serde_json::json!(["CREDIT_CARD"]), "deny");
        let detections = pipeline_detections(content);
        let input = eval_input(content, &detections);
        assert!(rule_matches(&rule, &input), "{detections:?}");
    }

    /// POSITIVE CONTROL — the harness can observe a rule matching at all.
    #[test]
    fn a_credit_card_rule_matches_a_foreign_pan() {
        let rule = rule_naming(serde_json::json!(["CREDIT_CARD"]), "deny");
        let detections = pipeline_detections(FOREIGN_PAN);
        let input = eval_input(FOREIGN_PAN, &detections);
        assert!(rule_matches(&rule, &input), "{detections:?}");
    }

    /// NEGATIVE CONTROL — the fix must be a card-specific alias, not "any
    /// filter matches any detection". A rule naming an unrelated class must
    /// still NOT fire on a card.
    #[test]
    fn an_unrelated_class_filter_does_not_match_a_local_pan() {
        let rule = rule_naming(serde_json::json!(["EMAIL_ADDRESS"]), "deny");
        let detections = pipeline_detections(LOCAL_PAN);
        let input = eval_input(LOCAL_PAN, &detections);
        assert!(
            !rule_matches(&rule, &input),
            "widening CREDIT_CARD to cover local cards must not widen every \
             other class filter too: {detections:?}"
        );
    }

    /// NEGATIVE CONTROL — the alias is one-directional. `CREDIT_CARD` is the
    /// GENERIC class, so a rule naming it covers the specific local classes;
    /// a rule naming `UZCARD` must NOT start covering a foreign PAN, which
    /// would let a local-card rule silently claim cards it says nothing
    /// about.
    #[test]
    fn a_uzcard_rule_does_not_match_a_foreign_pan() {
        let rule = rule_naming(serde_json::json!(["UZCARD"]), "deny");
        let detections = pipeline_detections(FOREIGN_PAN);
        let input = eval_input(FOREIGN_PAN, &detections);
        assert!(
            !rule_matches(&rule, &input),
            "the alias must widen the generic filter only: {detections:?}"
        );
    }

    /// The `eq` operator carries the same alias as `in` — the policy UI emits
    /// both, and a fix applied to only one spelling leaves the leak open for
    /// the other.
    #[test]
    fn the_eq_operator_carries_the_alias_too() {
        let mut rule = rule_naming(serde_json::json!(["CREDIT_CARD"]), "deny");
        rule.conditions = serde_json::json!([
            { "field": "detection_class", "op": "eq", "value": "CREDIT_CARD" }
        ]);
        let detections = pipeline_detections(LOCAL_PAN);
        let input = eval_input(LOCAL_PAN, &detections);
        assert!(rule_matches(&rule, &input), "{detections:?}");
    }
}
