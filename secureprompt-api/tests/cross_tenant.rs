//! Cross-tenant isolation integration tests.
//!
//! These tests are the standing AUTH-05 CI gate.

use secureprompt_api::db::scope::begin_scoped;
use secureprompt_api::db::{
    ApiKeyRepository, PolicyRepository, RevocationRecord, SessionRevocationRepository,
};
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

    // PREMISE: the list is not empty. Without this the filter below is taken
    // over nothing and `is_empty()` is satisfied by a repository that returned
    // no rows at all — which is exactly what an unarmed read of an RLS-armed
    // table does under a role that cannot bypass RLS. The claim this test
    // makes is "A's result contains no B rows", and that is only a claim about
    // tenancy if A's result contains A's rows.
    assert!(
        !keys_a.is_empty(),
        "premise: workspace A must have api_keys of its own, or the \
         leak check below is taken over an empty list"
    );

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

// ── WS4-3: session revocation must not reach across workspaces ────────────

/// `SessionRevocationRepository` is the repo behind
/// `DELETE /v1/users/{user_id}/sessions`. The HTTP-level control lives in
/// `tests/dashboard/session_revocation_tests.rs`; this is the same assertion
/// one layer down, where the SQL is, so a handler-only guard cannot be
/// mistaken for tenancy (Global Constraint 3).
#[sqlx::test(fixtures("workspace_a", "workspace_b"))]
async fn session_revocation_target_lookup_is_workspace_scoped(pool: PgPool) -> sqlx::Result<()> {
    let user_a = seed_user(&pool, ws_a().0, "revoke-a@example.com", "viewer").await?;
    let user_b = seed_user(&pool, ws_b().0, "revoke-b@example.com", "viewer").await?;
    let repo = SessionRevocationRepository::new(pool);

    // PREMISE: each user really is findable inside their OWN workspace, so a
    // `None` below is tenancy and not a broken query.
    assert!(
        repo.find_target(ws_a().0, user_a)
            .await
            .expect("query must succeed")
            .is_some(),
        "premise: workspace A's own user must be findable"
    );
    assert!(
        repo.find_target(ws_b().0, user_b)
            .await
            .expect("query must succeed")
            .is_some(),
        "premise: workspace B's own user must be findable"
    );

    assert!(
        repo.find_target(ws_a().0, user_b)
            .await
            .expect("query must succeed")
            .is_none(),
        "CROSS-TENANT LEAK: workspace A resolved a workspace B user as a \
         revocation target"
    );
    assert!(
        repo.find_target(ws_b().0, user_a)
            .await
            .expect("query must succeed")
            .is_none(),
        "CROSS-TENANT LEAK: workspace B resolved a workspace A user as a \
         revocation target"
    );
    Ok(())
}

/// And the write half: revoking inside workspace A must not close workspace
/// B's refresh tokens, even for a user id supplied by the caller.
#[sqlx::test(fixtures("workspace_a", "workspace_b"))]
async fn session_revocation_write_cannot_close_another_workspaces_refresh_rows(
    pool: PgPool,
) -> sqlx::Result<()> {
    let user_a = seed_user(&pool, ws_a().0, "write-a@example.com", "viewer").await?;
    let user_b = seed_user(&pool, ws_b().0, "write-b@example.com", "viewer").await?;
    let admin_a = seed_user(&pool, ws_a().0, "write-admin-a@example.com", "admin").await?;
    seed_refresh_row(&pool, ws_a().0, user_a).await?;
    seed_refresh_row(&pool, ws_b().0, user_b).await?;

    let repo = SessionRevocationRepository::new(pool.clone());
    let target = repo
        .find_target(ws_a().0, user_a)
        .await
        .expect("query")
        .expect("workspace A's own user");
    let outcome = repo
        .revoke(&RevocationRecord {
            workspace_id: ws_a().0,
            actor_user_id: admin_a,
            actor_email: Some("write-admin-a@example.com"),
            actor_role: "admin",
            target: &target,
            revoked_before_unix: 1_800_000_000,
            // WS4-3's user-wide lever. FU4's narrow one sets `Some(session_id)`
            // and is covered by
            // `dashboard::session_listing::sessions_cannot_be_read_or_ended_across_workspaces`.
            session_id: None,
        })
        .await
        .expect("revoke must succeed");
    assert_eq!(
        outcome.refresh_tokens_revoked, 1,
        "premise: the revocation must actually have closed workspace A's row, \
         or the assertion below passes vacuously"
    );

    // BOTH verification reads go through workspace B's OWN armed scope.
    //
    // On a bare pool under a non-bypassing role these are filtered to zero, and
    // that turns the second assertion into a vacuous pass: `b_audit == 0` would
    // be satisfied by RLS hiding the row rather than by the revocation having
    // correctly declined to write one. Reading from inside B's scope is the
    // only way the count means what the assertion says it means.
    let mut b_scope = begin_scoped(&pool, ws_b().0)
        .await
        .expect("an armed scope for workspace B");

    let b_active: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user_b)
    .fetch_one(&mut *b_scope)
    .await?;
    assert_eq!(
        b_active, 1,
        "CROSS-TENANT LEAK: a workspace A revocation closed workspace B's \
         refresh token"
    );

    let b_audit: i64 =
        sqlx::query_scalar("SELECT count(*) FROM session_revocation_audit WHERE workspace_id = $1")
            .bind(ws_b().0)
            .fetch_one(&mut *b_scope)
            .await?;
    assert_eq!(b_audit, 0, "no audit row may be written for workspace B");
    Ok(())
}

async fn seed_user(
    pool: &PgPool,
    workspace_id: Uuid,
    email: &str,
    role: &str,
) -> sqlx::Result<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, workspace_id, email, password_hash, role, created_at, updated_at)
         VALUES ($1, $2, $3, 'x', $4, NOW(), NOW())",
    )
    .bind(id)
    .bind(workspace_id)
    .bind(email)
    .bind(role)
    .execute(pool)
    .await?;
    Ok(id)
}

/// Seed a refresh row THROUGH AN ARMED SCOPE.
///
/// `refresh_tokens` has been under FORCE ROW LEVEL SECURITY since migration
/// 002, so this INSERT is refused with
/// `42501 new row violates row-level security policy for table
/// "refresh_tokens"` whenever the connecting role cannot bypass RLS.
///
/// A previous version of this comment blamed the `.sql` fixtures for leaving a
/// SESSION-level `app.current_workspace_id` on a pooled connection. READ AND
/// MEASURED: that is not what happens. `sqlx-core-0.8.6`'s `setup_test_db`
/// applies fixtures on a DEDICATED connection and calls `conn.close()` before
/// the test's pool is constructed, so no fixture setting ever reaches the
/// pool. This INSERT was simply unarmed, and only worked because the compose
/// role bypasses RLS. `begin_scoped` names the workspace explicitly and reads
/// it back, so it is correct under both roles.
async fn seed_refresh_row(pool: &PgPool, workspace_id: Uuid, user_id: Uuid) -> sqlx::Result<()> {
    let mut tx = begin_scoped(pool, workspace_id)
        .await
        .expect("an armed scope for the workspace being seeded");
    sqlx::query(
        "INSERT INTO refresh_tokens (id, user_id, workspace_id, token_hash, expires_at, created_at)
         VALUES ($1, $2, $3, $4, NOW() + INTERVAL '1 hour', NOW())",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(workspace_id)
    .bind(format!("hash-{}", Uuid::new_v4().simple()))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}
