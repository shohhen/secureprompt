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
}

pub async fn evaluate(
    repo: &PolicyRepository,
    input: PolicyEvaluationInput<'_>,
    vault: &mut TokenVault,
    redaction_map: &mut HashMap<String, String>,
) -> Result<PolicyEvaluationOutcome, ApiError> {
    let rules = repo.list_enabled_rules(input.workspace_id).await?;
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
    })
}

fn rule_matches(rule: &PolicyRuleRow, input: &PolicyEvaluationInput<'_>) -> bool {
    rule.conditions.as_array().map_or(true, |conditions| {
        conditions
            .iter()
            .all(|condition| matches_condition(condition, input))
    })
}

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
        ("detection_class", "eq") => input
            .detections
            .iter()
            .any(|detection| value.as_str() == Some(detection.class.as_str())),
        ("detection_class", "in") => value.as_array().is_some_and(|values| {
            input.detections.iter().any(|detection| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|candidate| candidate == detection.class)
            })
        }),
        ("confidence_gte", "gte") => value.as_f64().is_some_and(|threshold| {
            input
                .detections
                .iter()
                .any(|detection| f64::from(detection.confidence) >= threshold)
        }),
        ("confidence_gte", "lte") => value.as_f64().is_some_and(|threshold| {
            input
                .detections
                .iter()
                .any(|detection| f64::from(detection.confidence) <= threshold)
        }),
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
