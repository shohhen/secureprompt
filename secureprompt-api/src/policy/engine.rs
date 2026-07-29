use crate::{
    db::{PolicyRepository, PolicyRuleRow},
    observability::tracing::log_policy_event,
    policy::events::from_rule,
    vault::{apply_redaction, apply_transform},
};
use secureprompt_common::{
    errors::ApiError,
    types::{Detection, PolicyResult, RequestId, TokenVault, WorkspaceId},
};
use serde_json::Value;
use std::collections::HashMap;

pub struct PolicyEvaluationInput<'a> {
    pub request_id: RequestId,
    pub workspace_id: WorkspaceId,
    pub provider_name: &'a str,
    pub model: &'a str,
    pub content: &'a str,
    pub detections: &'a [Detection],
    /// Fail-closed switch, wired from `config.redact_when_no_rules`.
    ///
    /// When a `redact` rule fires, `matching_detections` narrows the set to
    /// the classes the rule's own condition names — and every OTHER detection
    /// in the same request is then forwarded to the provider in the clear.
    /// That makes protection NON-MONOTONIC: adding a class to the rule can
    /// *reduce* coverage, because a class filter that previously matched
    /// nothing fell through to `matching_detections`' "redact everything"
    /// fallback and now matches something. With `fail_closed` set, a firing
    /// `redact` rule redacts every detection in the request, so widening a
    /// rule can never expose an entity that a narrower rule protected.
    pub fail_closed: bool,
}

pub struct PolicyEvaluationOutcome {
    pub content: String,
    pub result: PolicyResult,
    pub denied: bool,
    /// Total number of enabled policy rules visible to this evaluation.
    /// Zero means the workspace has no policy yet (or every rule is
    /// disabled). The pipeline uses this to decide whether to engage the
    /// `redact_when_no_rules` safety net — distinguishing "workspace has
    /// rules but they explicitly chose `allow`" from "workspace forgot
    /// to define any rules."
    pub rules_evaluated: usize,
    /// True when NO enabled, non-dry-run rule both MATCHED this request and
    /// applied a recognised action.
    ///
    /// `rules_evaluated` counts rules the engine *looked at*; this counts
    /// rules that actually *decided* something. The difference is the whole
    /// WS1-6a / WS1-8 failure mode: a workspace whose only enabled rule has
    /// a condition that does not match (or, worse, a condition that CANNOT
    /// match — two `detection_class` conditions on one rule) has
    /// `rules_evaluated == 1`, which suppressed the `redact_when_no_rules`
    /// safety net in `pipeline/service.rs`, while nothing had in fact
    /// protected the request. At `secure_mode.level = permissive` — where
    /// `apply_secure_mode_override` is a no-op unless policy denied — that
    /// left raw PII on the wire to the provider.
    ///
    /// An explicit `allow` or `flag` rule that DOES match sets this to
    /// `false`: the admin looked at the request and chose to pass it, which
    /// the safety net must not override.
    pub unprotected: bool,
}

pub async fn evaluate(
    repo: &PolicyRepository,
    input: PolicyEvaluationInput<'_>,
    vault: &mut TokenVault,
    redaction_map: &mut HashMap<String, String>,
) -> Result<PolicyEvaluationOutcome, ApiError> {
    let rules = repo.list_enabled_rules(input.workspace_id).await?;
    let rules_evaluated = rules.len();
    let mut content = input.content.to_owned();
    let mut events = Vec::new();
    let mut final_action = "allow".to_owned();
    let mut denied = false;
    // Set only by an action arm that actually decided something. An
    // unrecognised action string leaves it false so the caller's fail-closed
    // net still engages — a rule reading `action: "redakt"` must not be
    // mistaken for protection.
    let mut applied = false;

    for rule in rules {
        if !rule_matches(&rule, &input) {
            continue;
        }

        let event = from_rule(&rule);
        log_policy_event(
            input.request_id,
            input.workspace_id,
            event.rule_id,
            &event.action,
            event.dry_run,
        );
        events.push(event);

        if rule.dry_run {
            continue;
        }

        final_action = rule.action.clone();
        let matching = matching_detections(&rule, input.detections);

        match rule.action.as_str() {
            "deny" => {
                applied = true;
                denied = true;
                break;
            }
            "allow" => {
                applied = true;
                break;
            }
            "redact" => {
                applied = true;
                // FIX-WAVE (FIX 1): under `fail_closed`, a firing `redact`
                // rule covers EVERY detection in the request, not only the
                // classes its own condition names.
                //
                // `matching_detections` narrows to the named classes and
                // everything else was then forwarded to the provider in the
                // clear. That made protection NON-MONOTONIC: a class filter
                // matching NOTHING falls through to the "redact everything"
                // fallback at the bottom of `matching_detections`, so ADDING
                // a class to a rule could REDUCE coverage. It is why a
                // prompt with an email plus a bearer token redacted the
                // email and shipped the credential.
                //
                // Redacting the union cannot be less safe than redacting the
                // subset, and it makes `DEFAULT_POLICY_CLASSES` unable to rot
                // into a leak: a detector class nobody remembered to list is
                // still redacted the moment any rule fires.
                //
                // NOTE the deliberate asymmetry with `transform` below,
                // which still applies only to `matching`. Widening it would
                // not help — the default template is `{value}`, which emits
                // the value verbatim — so a `transform` rule's residual
                // detections remain a separate, pre-existing hazard.
                let to_redact: &[Detection] = if input.fail_closed {
                    input.detections
                } else {
                    &matching
                };
                content = apply_redaction(&content, to_redact, vault, redaction_map);
                break;
            }
            "transform" => {
                applied = true;
                let template = rule
                    .action_params
                    .get("template")
                    .and_then(Value::as_str)
                    .unwrap_or("{value}");
                content = apply_transform(&content, &matching, template);
                break;
            }
            "flag" => {
                applied = true;
                break;
            }
            _ => {}
        }
    }

    Ok(PolicyEvaluationOutcome {
        content,
        result: PolicyResult {
            final_action,
            events,
        },
        denied,
        rules_evaluated,
        unprotected: !applied,
    })
}

pub(crate) fn rule_matches(rule: &PolicyRuleRow, input: &PolicyEvaluationInput<'_>) -> bool {
    let Some(conditions) = rule.conditions.as_array() else {
        return true;
    };

    // `detection_class` and `confidence_gte` describe a property of ONE
    // detection. Every other field (`provider`, `model`, `content_regex`)
    // describes a property of the request as a whole and is evaluated
    // independently, exactly as before. Detection-scoped conditions are
    // collected separately below so they can be checked against a single
    // detection together, instead of each being satisfied by whichever
    // detection happens to qualify.
    let mut detection_conditions: Vec<&Value> = Vec::new();
    for condition in conditions {
        if is_detection_scoped(condition) {
            detection_conditions.push(condition);
        } else if !matches_condition(condition, input) {
            return false;
        }
    }

    // A compound condition such as `detection_class == X AND
    // confidence_gte >= Y` must match only when a SINGLE detection
    // satisfies every detection-scoped condition in the rule — not when
    // one detection covers the class test and a different detection
    // covers the confidence test. Requiring `.all()` over
    // `detection_conditions` for the SAME `detection` on each iteration of
    // `.any()` is what enforces that; evaluating each condition against
    // "any detection" independently (the previous behavior) is exactly the
    // bug this replaces.
    //
    // UNSATISFIABLE RULE SHAPE: a rule with TWO OR MORE `detection_class`
    // conditions (two `eq`s, or `eq` + `in`) requires ONE detection whose
    // class satisfies ALL of them simultaneously — which no single
    // detection's `class: String` field ever can, since a detection has
    // exactly one class. Such a rule can never fire.
    //
    // The previous comment here claimed this was "safe (fails closed — the
    // rule simply stops matching rather than matching too broadly)". THAT
    // WAS FALSE, and the WS1-6a/WS1-8 fix wave was raised on it. Not
    // matching is not the same as failing closed: the rule still counts
    // toward `rules_evaluated`, which is what the `redact_when_no_rules`
    // safety net in `pipeline/service.rs` used to key off, so the net
    // stayed disengaged; and at `secure_mode.level = permissive`
    // `apply_secure_mode_override` is a no-op unless policy denied. The net
    // result was raw PII forwarded to the provider on a request the
    // pre-WS1-8 code redacted.
    //
    // What actually makes it safe now is `PolicyEvaluationOutcome::
    // unprotected`: no rule applied an action, so `apply_fallback_redaction`
    // engages and redacts. The shape is ALSO rejected at save time by
    // `http/routes/dashboard/policy_rules.rs::validate_conditions`, so no
    // new rule can be written this way; the warning below is for rows that
    // predate that validation.
    //
    // Evaluation semantics are deliberately NOT relaxed to OR here even
    // though the operator almost certainly meant OR, and even though
    // `matching_detections` below does OR-union multiple `detection_class`
    // filters. Making an unsatisfiable rule fire would be a security
    // regression for `action: "allow"` — a rule that today protects the
    // request by not firing would start waving it through. Failing closed
    // and rejecting at save time is strictly safer than guessing intent.
    if detection_conditions
        .iter()
        .filter(|condition| {
            condition.get("field").and_then(Value::as_str) == Some("detection_class")
        })
        .count()
        > 1
    {
        tracing::warn!(
            rule_id = %rule.id,
            rule_name = %rule.name,
            "policy rule has more than one `detection_class` condition and can \
             never match any single detection; it will never fire. Combine the \
             classes into ONE `detection_class in [...]` condition. The request \
             is protected by the fail-closed net, not by this rule."
        );
    }

    detection_conditions.is_empty()
        || input.detections.iter().any(|detection| {
            detection_conditions
                .iter()
                .copied()
                .all(|condition| matches_detection_condition(condition, detection))
        })
}

/// Conditions whose field names a property of an individual detection
/// (as opposed to the request as a whole).
fn is_detection_scoped(condition: &Value) -> bool {
    matches!(
        condition.get("field").and_then(Value::as_str),
        Some("detection_class" | "confidence_gte")
    )
}

/// Evaluate one detection-scoped condition against a single detection.
/// Used by `rule_matches` to require that ALL detection-scoped conditions
/// in a rule are satisfied by the SAME detection.
fn matches_detection_condition(condition: &Value, detection: &Detection) -> bool {
    let Some(field) = condition.get("field").and_then(Value::as_str) else {
        return false;
    };
    let Some(operator) = condition.get("op").and_then(Value::as_str) else {
        return false;
    };
    let Some(value) = condition.get("value") else {
        return false;
    };

    match (field, operator) {
        ("detection_class", "eq") => value.as_str() == Some(detection.class.as_str()),
        ("detection_class", "in") => value.as_array().is_some_and(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .any(|candidate| candidate == detection.class)
        }),
        ("confidence_gte", "gte") => value
            .as_f64()
            .is_some_and(|threshold| f64::from(detection.confidence) >= threshold),
        ("confidence_gte", "lte") => value
            .as_f64()
            .is_some_and(|threshold| f64::from(detection.confidence) <= threshold),
        _ => false,
    }
}

/// Evaluate one request-scoped (non-detection) condition. `detection_class`
/// and `confidence_gte` are handled by `matches_detection_condition`
/// instead, so a rule combining them with e.g. `provider` still requires
/// the detection-scoped half to be satisfied by a single detection.
fn matches_condition(condition: &Value, input: &PolicyEvaluationInput<'_>) -> bool {
    let Some(field) = condition.get("field").and_then(Value::as_str) else {
        return false;
    };
    let Some(operator) = condition.get("op").and_then(Value::as_str) else {
        return false;
    };
    let Some(value) = condition.get("value") else {
        return false;
    };

    match (field, operator) {
        ("provider", "eq") => value.as_str() == Some(input.provider_name),
        ("provider", "in") => value.as_array().is_some_and(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .any(|candidate| candidate == input.provider_name)
        }),
        ("model", "eq") => value.as_str() == Some(input.model),
        ("model", "in") => value.as_array().is_some_and(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .any(|candidate| candidate == input.model)
        }),
        // FIX-WAVE (FIX 4): this was `input.content.contains(needle)` — a
        // SUBSTRING test on a field named `content_regex`. Any operator who
        // wrote `^sk-[A-Za-z0-9]{32}$` had a rule that silently matched
        // nothing and believed they were protected.
        //
        // A malformed pattern already in the database (written before
        // `validate_conditions` shipped, or straight into Postgres) must not
        // take the gateway down, so compilation failure logs and yields
        // `false` — the condition is unsatisfied, the rule does not fire,
        // and `PolicyEvaluationOutcome::unprotected` then routes the request
        // through the fail-closed net. Returning `true` on a broken pattern
        // would be the opposite of what an operator writing a `deny` rule
        // wants; returning `false` is the shape that stays safe under both
        // `deny` and `redact`.
        //
        // `regex` is compiled per evaluation rather than cached. Rust's
        // `regex` crate is linear-time (no catastrophic backtracking), rule
        // counts per workspace are small, and the ML sidecar round trip on
        // this same request path costs milliseconds — several orders of
        // magnitude more than compiling a short pattern.
        ("content_regex", "matches") => {
            value
                .as_str()
                .is_some_and(|pattern| match regex::Regex::new(pattern) {
                    Ok(compiled) => compiled.is_match(input.content),
                    Err(error) => {
                        tracing::warn!(
                            %error,
                            pattern,
                            "policy rule has an invalid `content_regex` pattern; \
                             treating the condition as unsatisfied. Fix the rule \
                             in the policy UI — it is enforcing nothing."
                        );
                        false
                    }
                })
        }
        _ => false,
    }
}

/// NOTE on divergence from `rule_matches`: multiple `detection_class`
/// conditions on the same rule are combined with OR into a single
/// `class_filters` list below — a detection is included if its class is in
/// ANY of them. `rule_matches` (see the comment at its detection-scoped
/// check) requires ONE detection to satisfy ALL `detection_class`
/// conditions simultaneously, which an ordinary single-valued `class`
/// field can only do if the rule has at most one such condition. So a rule
/// with two or more `detection_class` conditions never reaches this
/// function at all (it fails to match up front) — this OR-union path is
/// effectively dead for that shape of rule, though it still applies
/// normally to `confidence_gte` bounds and to the single-condition case
/// (including the `in` operator, which is one condition listing several
/// classes, not multiple conditions).
///
/// The divergence is now contained rather than merely documented: that rule
/// shape is rejected at save time by `validate_conditions`, and a request it
/// leaves unmatched is caught by the fail-closed net instead of being
/// forwarded raw. See the `UNSATISFIABLE RULE SHAPE` comment in
/// `rule_matches` for why the two functions are NOT being reconciled by
/// making this one AND, or that one OR.
///
/// Also note the "empty filter → return everything" fallback at the bottom.
/// It is what made protection non-monotonic (a filter that matched nothing
/// protected MORE than a filter that matched something), and it is why the
/// `"redact"` arm of `evaluate` bypasses this function entirely under
/// `fail_closed`.
fn matching_detections(rule: &PolicyRuleRow, detections: &[Detection]) -> Vec<Detection> {
    let mut class_filters = Vec::new();
    let mut confidence_gte = None;
    let mut confidence_lte = None;

    if let Some(conditions) = rule.conditions.as_array() {
        for condition in conditions {
            let field = condition.get("field").and_then(Value::as_str);
            let operator = condition.get("op").and_then(Value::as_str);
            let value = condition.get("value");

            match (field, operator, value) {
                (Some("detection_class"), Some("eq"), Some(value)) => {
                    if let Some(class) = value.as_str() {
                        class_filters.push(class.to_owned());
                    }
                }
                (Some("detection_class"), Some("in"), Some(value)) => {
                    if let Some(values) = value.as_array() {
                        class_filters.extend(
                            values
                                .iter()
                                .filter_map(Value::as_str)
                                .map(ToOwned::to_owned),
                        );
                    }
                }
                (Some("confidence_gte"), Some("gte"), Some(value)) => {
                    confidence_gte = value.as_f64();
                }
                (Some("confidence_gte"), Some("lte"), Some(value)) => {
                    confidence_lte = value.as_f64();
                }
                _ => {}
            }
        }
    }

    let filtered: Vec<_> = detections
        .iter()
        .filter(|detection| {
            (class_filters.is_empty()
                || class_filters.iter().any(|class| class == &detection.class))
                && confidence_gte
                    .is_none_or(|threshold| f64::from(detection.confidence) >= threshold)
                && confidence_lte
                    .is_none_or(|threshold| f64::from(detection.confidence) <= threshold)
        })
        .cloned()
        .collect();

    if filtered.is_empty() {
        detections.to_vec()
    } else {
        filtered
    }
}
