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

/// Tests for the policy engine's CONDITION evaluation.
///
/// # What this module used to claim, and what it actually did (MR1 review I16)
///
/// The header here listed "detection_class eq/in, confidence_gte/lte,
/// provider eq/in, model eq/in, content_regex matches" as covered, and
/// finished with "We test the internal condition helpers directly via
/// cfg(test) visibility". Neither half was true. `content_regex`, `provider`
/// and `model` had no test at all — which is how C2 shipped: `content_regex`
/// was evaluated as `str::contains` for the whole of MR1, so every real regex
/// an operator wrote produced a rule that silently never fired. And the
/// module did not call the helpers; it re-implemented them inline, so
/// `detection_class_eq_condition_matches_correctly` asserted that a `json!`
/// literal round-trips and `confidence_gte_condition_json_structure` asserted
/// `0.85 == 0.85`.
///
/// Every condition field the engine supports is now driven through the real
/// `rule_matches`, with a negative case for each so a helper that returned
/// `true` unconditionally would redden.
///
/// Ordering, dry-run and the action arms need the real `evaluate`, which needs
/// Postgres; they are `#[sqlx::test]`s at the bottom of this module rather
/// than simulations of the engine loop.
#[cfg(test)]
mod condition_tests {
    use crate::db::PolicyRuleRow;
    use chrono::Utc;
    use uuid::Uuid;

    use crate::db::WorkspaceRepository;
    use crate::policy::engine::{rule_matches, PolicyEvaluationInput};
    use secureprompt_common::types::{Detection, RequestId, WorkspaceId};
    use sqlx::PgPool;

    /// One place that builds a `PolicyEvaluationInput`, so every condition
    /// test below differs only in the field under test.
    fn matches(rule: &PolicyRuleRow, provider: &str, model: &str, content: &str) -> bool {
        let detections: Vec<Detection> = Vec::new();
        rule_matches(
            rule,
            &PolicyEvaluationInput {
                request_id: RequestId::new(),
                workspace_id: WorkspaceId::new(),
                provider_name: provider,
                model,
                content,
                detections: &detections,
                fail_closed: false,
            },
        )
    }

    /// As `matches`, but with detections — for the detection-scoped fields.
    fn matches_with(rule: &PolicyRuleRow, detections: &[Detection]) -> bool {
        rule_matches(
            rule,
            &PolicyEvaluationInput {
                request_id: RequestId::new(),
                workspace_id: WorkspaceId::new(),
                provider_name: "none",
                model: "none",
                content: "irrelevant",
                detections,
                fail_closed: false,
            },
        )
    }

    fn detection(class: &str, confidence: f32) -> Detection {
        Detection {
            class: class.to_owned(),
            confidence,
            span: None,
            value: "synthetic-value".to_owned(),
        }
    }

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

    // ── Ordering, dry-run and the action arms, through the real `evaluate` ──
    //
    // MR1 review I16: the four tests that used to sit here re-implemented the
    // engine loop in the test body. `rules_ordered_by_priority_asc_then_id_asc`
    // sorted a `Vec` and asserted the result — i.e. it tested `i32::cmp`,
    // while production ordering is a SQL `ORDER BY` in
    // `policy_repo::list_enabled_rules`. `equal_priority_ordered_by_id_asc`
    // tested `Uuid::cmp`. `dry_run_rule_does_not_change_action_marker`,
    // `deny_action_sets_denied_flag` and `allow_action_breaks_evaluation`
    // each wrote the branch they were checking and then checked it. No
    // production line's deletion reddened any of them.
    //
    // They are replaced by `#[sqlx::test]`s that seed real rows and call the
    // real `evaluate`. That needs Postgres, which the old header gave as the
    // reason for simulating instead — but `default_policy_path_tests` at the
    // top of this file has been driving `evaluate` against a live pool all
    // along, so the constraint was never real.

    /// Seed a workspace with NO rules, then insert exactly the ones a test
    /// wants. `create_with_owner` seeds a default `Redact common PII` rule
    /// (`db/workspace_repo.rs`), which would otherwise take part in ordering.
    async fn seed_empty_workspace(pool: &PgPool) -> Uuid {
        let hash = crate::db::user_repo::hash_password("pw-for-test-only").unwrap();
        let (workspace, _) = WorkspaceRepository::new(pool.clone())
            .create_with_owner(
                "Ordering Co",
                &format!("ordering-{}@example.invalid", Uuid::new_v4()),
                &hash,
            )
            .await
            .expect("workspace must be created");

        sqlx::query("DELETE FROM policy_rules WHERE workspace_id = $1")
            .bind(workspace.id)
            .execute(pool)
            .await
            .unwrap();

        workspace.id
    }

    async fn insert_rule(
        pool: &PgPool,
        workspace_id: Uuid,
        id: Uuid,
        priority: i32,
        action: &str,
        dry_run: bool,
    ) {
        sqlx::query(
            "INSERT INTO policy_rules
                (id, workspace_id, name, priority, conditions, action, action_params,
                 enabled, dry_run, created_at, updated_at)
             VALUES ($1, $2, $3, $4, '[]'::jsonb, $5, '{}'::jsonb, true, $6, NOW(), NOW())",
        )
        .bind(id)
        .bind(workspace_id)
        .bind(format!("{action}-p{priority}"))
        .bind(priority)
        .bind(action)
        .bind(dry_run)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn eval(
        pool: &PgPool,
        workspace_id: Uuid,
    ) -> crate::policy::engine::PolicyEvaluationOutcome {
        let detections: Vec<Detection> = Vec::new();
        let mut vault = secureprompt_common::types::TokenVault::default();
        let mut redaction_map: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        crate::policy::engine::evaluate(
            &crate::db::PolicyRepository::new(pool.clone()),
            PolicyEvaluationInput {
                request_id: RequestId::new(),
                workspace_id: WorkspaceId(workspace_id),
                provider_name: "none",
                model: "none",
                content: "no conditions, so every rule below matches",
                detections: &detections,
                fail_closed: false,
            },
            &mut vault,
            &mut redaction_map,
        )
        .await
        .expect("policy evaluation must succeed")
    }

    /// First match wins by `priority ASC`. Both rules match (empty
    /// conditions), so the outcome is decided entirely by the order the
    /// repository returns them in — a SQL `ORDER BY`, not a sort in this
    /// test.
    ///
    /// Falsifier (verified): change `ORDER BY priority ASC, id ASC` to
    /// `priority DESC` in `policy_repo::list_enabled_rules` — this reddens
    /// with `denied = false`, because the `allow` rule is reached first.
    #[sqlx::test]
    async fn rules_are_evaluated_in_priority_order(pool: PgPool) {
        let workspace_id = seed_empty_workspace(&pool).await;
        // Inserted allow-first so insertion order cannot be what decides.
        insert_rule(&pool, workspace_id, Uuid::new_v4(), 100, "allow", false).await;
        insert_rule(&pool, workspace_id, Uuid::new_v4(), 10, "deny", false).await;

        let outcome = eval(&pool, workspace_id).await;

        assert_eq!(outcome.rules_evaluated, 2, "premise: both rules are live");
        assert_eq!(
            outcome.result.final_action, "deny",
            "the priority-10 deny rule must be reached before the priority-100 \
             allow rule"
        );
        assert!(outcome.denied, "a matched deny rule must set denied");
    }

    /// The tie-break half: same priority, so `id ASC` decides. Ids are fixed
    /// rather than random, or the assertion would be a coin flip.
    ///
    /// Falsifier (verified): drop `, id ASC` from the same `ORDER BY` — with
    /// two equal priorities Postgres is then free to return either first and
    /// this becomes non-deterministic; forcing `id DESC` reddens it outright.
    #[sqlx::test]
    async fn equal_priority_is_broken_by_id_ascending(pool: PgPool) {
        let workspace_id = seed_empty_workspace(&pool).await;
        let lower = Uuid::from_u128(1);
        let higher = Uuid::from_u128(2);
        insert_rule(&pool, workspace_id, higher, 50, "allow", false).await;
        insert_rule(&pool, workspace_id, lower, 50, "deny", false).await;

        let outcome = eval(&pool, workspace_id).await;

        assert_eq!(outcome.rules_evaluated, 2, "premise: both rules are live");
        assert_eq!(
            outcome.result.final_action, "deny",
            "at equal priority the lower id must be evaluated first"
        );
    }

    /// A `dry_run` rule records its event and does not decide the request.
    ///
    /// The positive control is the second half: the SAME rule with
    /// `dry_run = false` must produce `deny`. Without it, "final_action is
    /// allow" would also hold for a rule that simply never matched.
    ///
    /// Falsifier (verified): delete the `if rule.dry_run { continue; }` arm
    /// in `evaluate` — the first half reddens with `deny`.
    #[sqlx::test]
    async fn a_dry_run_rule_records_an_event_without_deciding(pool: PgPool) {
        let workspace_id = seed_empty_workspace(&pool).await;
        insert_rule(&pool, workspace_id, Uuid::new_v4(), 10, "deny", true).await;

        let outcome = eval(&pool, workspace_id).await;
        assert_eq!(
            outcome.result.final_action, "allow",
            "a dry_run deny must not change the final action"
        );
        assert!(!outcome.denied, "a dry_run deny must not deny");
        assert_eq!(
            outcome.result.events.len(),
            1,
            "a dry_run rule must still record its event — otherwise the mode \
             is indistinguishable from disabling the rule"
        );

        // Positive control: the same rule, enforcing.
        let enforcing = seed_empty_workspace(&pool).await;
        insert_rule(&pool, enforcing, Uuid::new_v4(), 10, "deny", false).await;
        let enforced = eval(&pool, enforcing).await;
        assert_eq!(enforced.result.final_action, "deny");
        assert!(enforced.denied);
    }

    /// An `allow` rule ends evaluation: a lower-priority `deny` behind it
    /// never runs.
    ///
    /// Falsifier (verified): remove the `break` from the `"allow"` arm of
    /// `evaluate` — the priority-20 deny then overwrites `final_action` and
    /// this reddens with `denied = true`.
    #[sqlx::test]
    async fn an_allow_rule_stops_evaluation(pool: PgPool) {
        let workspace_id = seed_empty_workspace(&pool).await;
        insert_rule(&pool, workspace_id, Uuid::new_v4(), 10, "allow", false).await;
        insert_rule(&pool, workspace_id, Uuid::new_v4(), 20, "deny", false).await;

        let outcome = eval(&pool, workspace_id).await;

        assert_eq!(outcome.rules_evaluated, 2, "premise: the deny rule is live");
        assert_eq!(outcome.result.final_action, "allow");
        assert!(
            !outcome.denied,
            "the deny rule behind the allow must never be reached"
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

    /// Was: `assert_eq!(conditions[0]["field"].as_str().unwrap(),
    /// "detection_class")` — a `serde_json` round-trip, never a call into
    /// this crate. Now driven through `rule_matches`, both directions.
    #[test]
    fn detection_class_eq_condition_matches_correctly() {
        let rule = make_rule(
            10,
            serde_json::json!([
                { "field": "detection_class", "op": "eq", "value": "EMAIL_ADDRESS" }
            ]),
            "redact",
            false,
        );

        assert!(
            matches_with(&rule, &[detection("EMAIL_ADDRESS", 0.9)]),
            "a detection of the named class must satisfy `detection_class eq`"
        );
        assert!(
            !matches_with(&rule, &[detection("PHONE_NUMBER", 0.9)]),
            "a detection of a DIFFERENT class must not satisfy it — without \
             this the assertion above would hold for a helper that always \
             returned true"
        );
        assert!(
            !matches_with(&rule, &[]),
            "no detections at all must not satisfy a detection-scoped condition"
        );
    }

    /// Was: `assert!((0.85 - 0.85).abs() < 1e-6)`. Now the real threshold
    /// comparison, on both sides of the boundary and ON it.
    #[test]
    fn confidence_gte_condition_matches_at_and_above_the_threshold() {
        let rule = make_rule(
            10,
            serde_json::json!([
                { "field": "confidence_gte", "op": "gte", "value": 0.85 }
            ]),
            "redact",
            false,
        );

        assert!(
            matches_with(&rule, &[detection("EMAIL_ADDRESS", 0.9)]),
            "0.90 is above the 0.85 threshold"
        );
        assert!(
            matches_with(&rule, &[detection("EMAIL_ADDRESS", 0.85)]),
            "`gte` includes the threshold itself — a `>` would redden here"
        );
        assert!(
            !matches_with(&rule, &[detection("EMAIL_ADDRESS", 0.80)]),
            "0.80 is below the threshold and must not satisfy it"
        );
    }

    /// MR1 review I16 / C2. `content_regex` had NO test, which is how it
    /// shipped as `input.content.contains(needle)` — a substring test on a
    /// field named, documented and presented in the dashboard as a regex.
    ///
    /// The first assertion is the exact discriminator: `\d{3}-\d{2}-\d{4}` is
    /// not a substring of `123-45-6789`, so a `contains` implementation
    /// answers `false` and this test reddens. That is the assertion whose
    /// absence let C2 through.
    #[test]
    fn content_regex_is_evaluated_as_a_regex_not_a_substring() {
        let rule = make_rule(
            10,
            serde_json::json!([
                { "field": "content_regex", "op": "matches", "value": r"\d{3}-\d{2}-\d{4}" }
            ]),
            "deny",
            false,
        );

        assert!(
            matches(&rule, "openai", "gpt-4o", "ssn is 123-45-6789 here"),
            "a real regex must match the text it describes — `str::contains` \
             on the pattern itself answers false, which is exactly the defect \
             this asserts against"
        );
        assert!(
            !matches(&rule, "openai", "gpt-4o", "no identifiers in this text"),
            "the pattern must not match text it does not describe"
        );

        // Anchors are the other half of "this is a regex": a substring
        // implementation cannot express them at all.
        let anchored = make_rule(
            10,
            serde_json::json!([
                { "field": "content_regex", "op": "matches", "value": r"^sk-[A-Za-z0-9]{8}$" }
            ]),
            "deny",
            false,
        );
        assert!(matches(&anchored, "openai", "gpt-4o", "sk-ABCD1234"));
        assert!(
            !matches(&anchored, "openai", "gpt-4o", "prefix sk-ABCD1234 suffix"),
            "`^`/`$` must anchor — a substring test would match here"
        );
    }

    /// The other branch of the `content_regex` arm: a pattern that does not
    /// compile. A rule row can carry one (written before `validate_conditions`
    /// shipped, or inserted straight into Postgres), and the engine must treat
    /// the condition as UNSATISFIED rather than panicking or matching
    /// everything.
    ///
    /// `false` is the safe answer under both `deny` and `redact`: the rule
    /// does not fire, `PolicyEvaluationOutcome::unprotected` is set, and the
    /// fail-closed net takes over. Returning `true` would make a broken
    /// pattern deny every request.
    #[test]
    fn an_invalid_content_regex_is_unsatisfied_rather_than_fatal() {
        let rule = make_rule(
            10,
            // Unclosed group — `regex::Regex::new` rejects it.
            serde_json::json!([
                { "field": "content_regex", "op": "matches", "value": "(unclosed" }
            ]),
            "deny",
            false,
        );

        assert!(
            !matches(&rule, "openai", "gpt-4o", "(unclosed"),
            "an uncompilable pattern must leave the condition unsatisfied — \
             note the content here CONTAINS the pattern verbatim, so a \
             `str::contains` implementation would answer true"
        );
    }

    /// `provider` and `model` are request-scoped conditions and neither had a
    /// test (MR1 review I16). Both operators, both directions, for each.
    #[test]
    fn provider_and_model_conditions_match_the_request() {
        let provider_eq = make_rule(
            10,
            serde_json::json!([{ "field": "provider", "op": "eq", "value": "anthropic" }]),
            "deny",
            false,
        );
        assert!(matches(&provider_eq, "anthropic", "any", "text"));
        assert!(!matches(&provider_eq, "openai", "any", "text"));

        let provider_in = make_rule(
            10,
            serde_json::json!([
                { "field": "provider", "op": "in", "value": ["anthropic", "azure"] }
            ]),
            "deny",
            false,
        );
        assert!(matches(&provider_in, "azure", "any", "text"));
        assert!(!matches(&provider_in, "openai", "any", "text"));

        let model_eq = make_rule(
            10,
            serde_json::json!([{ "field": "model", "op": "eq", "value": "gpt-4o" }]),
            "deny",
            false,
        );
        assert!(matches(&model_eq, "any", "gpt-4o", "text"));
        assert!(
            !matches(&model_eq, "any", "gpt-4o-mini", "text"),
            "`eq` is exact — a prefix or substring comparison would match here"
        );

        let model_in = make_rule(
            10,
            serde_json::json!([
                { "field": "model", "op": "in", "value": ["gpt-4o", "claude-3-opus"] }
            ]),
            "deny",
            false,
        );
        assert!(matches(&model_in, "any", "claude-3-opus", "text"));
        assert!(!matches(&model_in, "any", "gemini-pro", "text"));
    }

    /// An unknown field or operator falls through `matches_condition`'s `_`
    /// arm to `false`. Worth pinning next to the arms above: it is what makes
    /// a typo in the policy UI fail closed rather than matching everything.
    #[test]
    fn an_unrecognised_field_or_operator_does_not_match() {
        let bad_field = make_rule(
            10,
            serde_json::json!([{ "field": "provder", "op": "eq", "value": "openai" }]),
            "deny",
            false,
        );
        assert!(!matches(&bad_field, "openai", "gpt-4o", "text"));

        let bad_op = make_rule(
            10,
            serde_json::json!([{ "field": "provider", "op": "equals", "value": "openai" }]),
            "deny",
            false,
        );
        assert!(!matches(&bad_op, "openai", "gpt-4o", "text"));
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
             that suppression is the premise of this module. If this now \
             reports [\"CREDIT_CARD\", \"UZCARD\"] the suppression pass was \
             reverted — the class alias in policy/engine.rs is then redundant \
             but harmless, and this premise is what should be updated"
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

    /// Pins the SECOND half of the fix: the alias in `matching_detections`,
    /// not just in `rule_matches`.
    ///
    /// Driven through `evaluate`, because the two halves are only
    /// distinguishable there. With the alias in `rule_matches` alone the rule
    /// fires and then selects NOTHING (no detection's class is literally
    /// `CREDIT_CARD`), which falls through `matching_detections`' "empty
    /// filter → return everything" escape and redacts the whole prompt. The
    /// card would be protected by accident, and every other entity in the
    /// request over-redacted — a narrow rule silently behaving like a total
    /// one. So the assertion is a PAIR: the card is redacted AND the email,
    /// which this rule says nothing about, is not.
    ///
    /// `fail_closed` is false on purpose. With it on, the `redact` arm
    /// bypasses `matching_detections` entirely and this test would pass
    /// without the alias.
    #[sqlx::test]
    async fn a_credit_card_rule_redacts_the_local_card_and_leaves_the_rest(pool: sqlx::PgPool) {
        use crate::db::{PolicyRepository, WorkspaceRepository};
        use crate::policy::engine::evaluate;
        use secureprompt_common::types::TokenVault;
        use std::collections::HashMap;

        const PROMPT: &str = "Ali Aliev, ali@example.com, karta 8600123456789012";

        let hash = crate::db::user_repo::hash_password("pw-for-test-only").unwrap();
        let (workspace, _) = WorkspaceRepository::new(pool.clone())
            .create_with_owner(
                "Card Rule Co",
                &format!("card-rule-{}@example.com", Uuid::new_v4()),
                &hash,
            )
            .await
            .expect("workspace must be created");

        // Replace the seeded default rule (which names UZCARD explicitly and
        // so cannot show this) with the narrow, reachable shape: a rule that
        // names the GENERIC card class only.
        sqlx::query("DELETE FROM policy_rules WHERE workspace_id = $1")
            .bind(workspace.id)
            .execute(&pool)
            .await
            .expect("clear the seeded rule");
        sqlx::query(
            "INSERT INTO policy_rules
                (id, workspace_id, name, priority, conditions, action, action_params,
                 enabled, dry_run, created_at, updated_at)
             VALUES ($1, $2, 'Redact cards', 100, $3, 'redact', '{}'::jsonb,
                     true, false, NOW(), NOW())",
        )
        .bind(Uuid::new_v4())
        .bind(workspace.id)
        .bind(serde_json::json!([
            { "field": "detection_class", "op": "in", "value": ["CREDIT_CARD"] }
        ]))
        .execute(&pool)
        .await
        .expect("insert the CREDIT_CARD-only rule");

        let detections = pipeline_detections(PROMPT);
        let found: Vec<&str> = detections.iter().map(|d| d.class.as_str()).collect();
        assert!(
            found.contains(&"UZCARD") && found.contains(&"EMAIL_ADDRESS"),
            "premise: the prompt must carry both a local card and an entity \
             the rule says nothing about, got {found:?}"
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
                content: PROMPT,
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
            "premise: exactly one rule, or the redact_when_no_rules net would \
             mask what is under test"
        );
        assert_eq!(
            outcome.result.final_action, "redact",
            "the CREDIT_CARD rule did not fire on a local PAN at all"
        );
        assert!(
            !outcome.content.contains("8600123456789012"),
            "the card the rule names was forwarded in the clear: {:?}",
            outcome.content
        );
        assert!(
            outcome.content.contains("ali@example.com"),
            "the rule names CREDIT_CARD and nothing else, but the whole prompt \
             was redacted — `matching_detections` selected nothing and fell \
             through its empty-filter escape: {:?}",
            outcome.content
        );
    }
}
