use secureprompt_common::types::{RequestId, WorkspaceId};
use uuid::Uuid;

pub fn log_request_start(request_id: RequestId, workspace_id: WorkspaceId, model: &str) {
    tracing::info!(
        request_id = %request_id,
        workspace_id = %workspace_id,
        model,
        "gateway request started"
    );
}

pub fn log_request_finish(
    request_id: RequestId,
    workspace_id: WorkspaceId,
    final_action: &str,
    success: bool,
) {
    tracing::info!(
        request_id = %request_id,
        workspace_id = %workspace_id,
        final_action,
        success,
        "gateway request finished"
    );
}

pub fn log_policy_event(
    request_id: RequestId,
    workspace_id: WorkspaceId,
    rule_id: Uuid,
    action: &str,
    dry_run: bool,
) {
    tracing::info!(
        request_id = %request_id,
        workspace_id = %workspace_id,
        rule_id = %rule_id,
        action,
        dry_run,
        "policy event emitted"
    );
}
