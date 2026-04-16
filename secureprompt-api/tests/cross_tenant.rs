//! Cross-tenant isolation integration tests.
//!
//! These tests are the standing AUTH-05 CI gate.

use secureprompt_api::db::{ApiKeyRepository, PolicyRepository};
use secureprompt_common::types::WorkspaceId;
use sqlx::PgPool;
use uuid::Uuid;

const WS_A_UUID: &str = "aaaaaaaa-0000-0000-0000-000000000000";
const WS_B_UUID: &str = "bbbbbbbb-0000-0000-0000-000000000000";

fn ws_a() -> WorkspaceId {
    WorkspaceId(Uuid::parse_str(WS_A_UUID).expect("WS_A_UUID is valid"))
}

fn ws_b() -> WorkspaceId {
    WorkspaceId(Uuid::parse_str(WS_B_UUID).expect("WS_B_UUID is valid"))
}

#[sqlx::test(fixtures("workspace_a", "workspace_b"))]
async fn api_keys_list_is_workspace_scoped(pool: PgPool) -> sqlx::Result<()> {
    let repo = ApiKeyRepository::new(pool);

    let keys_a = repo
        .list_api_keys(ws_a())
        .await
        .expect("workspace A api_keys query must succeed");
    let keys_b = repo
        .list_api_keys(ws_b())
        .await
        .expect("workspace B api_keys query must succeed");

    assert!(
        !keys_a.is_empty(),
        "workspace A must have api_keys (fixture not loaded?)"
    );
    assert!(
        !keys_b.is_empty(),
        "workspace B must have api_keys (fixture not loaded?)"
    );

    let ws_a_uuid = Uuid::parse_str(WS_A_UUID).unwrap();
    let ws_b_uuid = Uuid::parse_str(WS_B_UUID).unwrap();

    for key in &keys_a {
        assert_eq!(
            key.workspace_id, ws_a_uuid,
            "key {} in workspace A result has wrong workspace_id — RLS may be disabled",
            key.id
        );
    }

    for key in &keys_b {
        assert_eq!(
            key.workspace_id, ws_b_uuid,
            "key {} in workspace B result has wrong workspace_id — RLS may be disabled",
            key.id
        );
    }

    let a_ids: std::collections::HashSet<Uuid> = keys_a.iter().map(|key| key.id).collect();
    let b_ids: std::collections::HashSet<Uuid> = keys_b.iter().map(|key| key.id).collect();

    assert!(
        a_ids.is_disjoint(&b_ids),
        "CROSS-TENANT LEAK DETECTED: key IDs appear in both workspace A and B results"
    );

    Ok(())
}

#[sqlx::test(fixtures("workspace_a", "workspace_b"))]
async fn policy_rules_list_is_workspace_scoped(pool: PgPool) -> sqlx::Result<()> {
    let repo = PolicyRepository::new(pool);

    let rules_a = repo
        .list_rules(ws_a())
        .await
        .expect("workspace A policy_rules query must succeed");
    let rules_b = repo
        .list_rules(ws_b())
        .await
        .expect("workspace B policy_rules query must succeed");

    assert!(
        !rules_a.is_empty(),
        "workspace A must have policy_rules (fixture not loaded?)"
    );
    assert!(
        !rules_b.is_empty(),
        "workspace B must have policy_rules (fixture not loaded?)"
    );

    let ws_a_uuid = Uuid::parse_str(WS_A_UUID).unwrap();
    let ws_b_uuid = Uuid::parse_str(WS_B_UUID).unwrap();

    for rule in &rules_a {
        assert_eq!(
            rule.workspace_id, ws_a_uuid,
            "rule {} in workspace A result has wrong workspace_id",
            rule.id
        );
    }

    for rule in &rules_b {
        assert_eq!(
            rule.workspace_id, ws_b_uuid,
            "rule {} in workspace B result has wrong workspace_id",
            rule.id
        );
    }

    let a_ids: std::collections::HashSet<Uuid> = rules_a.iter().map(|rule| rule.id).collect();
    let b_ids: std::collections::HashSet<Uuid> = rules_b.iter().map(|rule| rule.id).collect();

    assert!(
        a_ids.is_disjoint(&b_ids),
        "CROSS-TENANT LEAK DETECTED: rule IDs appear in both workspace A and B results"
    );

    Ok(())
}

#[sqlx::test(fixtures("workspace_a", "workspace_b"))]
async fn workspace_a_cannot_see_workspace_b_keys(pool: PgPool) -> sqlx::Result<()> {
    let repo = ApiKeyRepository::new(pool);
    let keys_a = repo
        .list_api_keys(ws_a())
        .await
        .expect("workspace A query must succeed");

    let ws_b_uuid = Uuid::parse_str(WS_B_UUID).unwrap();
    let b_keys_in_a_result: Vec<_> = keys_a
        .iter()
        .filter(|key| key.workspace_id == ws_b_uuid)
        .collect();

    assert!(
        b_keys_in_a_result.is_empty(),
        "workspace A result contains {} keys belonging to workspace B — CROSS-TENANT LEAK",
        b_keys_in_a_result.len()
    );

    Ok(())
}
