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
                denied = true;
                break;
            }
            "allow" => break,
            "redact" => {
                content = apply_redaction(&content, &matching, vault, redaction_map);
                break;
            }
            "transform" => {
                let template = rule
                    .action_params
                    .get("template")
                    .and_then(Value::as_str)
                    .unwrap_or("{value}");
                content = apply_transform(&content, &matching, template);
                break;
            }
            "flag" => break,
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
    // KNOWN DIVERGENCE (pre-existing, widened by this change — not fixed
    // here, see WS1-8 fix-round-1 review): a rule with TWO OR MORE
    // `detection_class` conditions (e.g. two `eq` conditions, or `eq` +
    // `in`) requires ONE detection whose class satisfies ALL of them
    // simultaneously here — which no single detection's `class: String`
    // field ever can, since a detection has exactly one class. Such a rule
    // now never fires. `matching_detections` below still combines
    // (with OR) multiple `detection_class` filters into one
    // `class_filters` list, which is a different, looser semantics. This
    // is safe (fails closed — the rule simply stops matching rather than
    // matching too broadly) but the two functions now disagree on what a
    // multi-`detection_class`-condition rule means; don't assume they
    // agree if you touch either.
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
        ("content_regex", "matches") => value
            .as_str()
            .is_some_and(|needle| input.content.contains(needle)),
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
