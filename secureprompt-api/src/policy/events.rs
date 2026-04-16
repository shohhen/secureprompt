use crate::db::PolicyRuleRow;
use secureprompt_common::types::PolicyEvent;

#[must_use]
pub fn from_rule(rule: &PolicyRuleRow) -> PolicyEvent {
    PolicyEvent {
        rule_id: rule.id,
        action: rule.action.clone(),
        dry_run: rule.dry_run,
    }
}
