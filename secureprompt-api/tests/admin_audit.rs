//! FU5 — the administrative audit trail.
//!
//! Before FU5 exactly three administrative actions were audited anywhere in the
//! product: `raw_capture_audit` (WS3-1), `retention_purge_audit` (WS3-4) and
//! `session_revocation_audit` (WS4-3). FU1 then built a signed export that
//! carries a CONTROL-PLANE section alongside the data plane — a pipe that
//! worked correctly and was very nearly empty. An auditor could obtain "what
//! requests passed through the gateway" and could not answer "who created this
//! API key", "who changed this redaction policy", "who was given admin".
//!
//! Every test in this file failed at commit `f2de9f3`, before `admin_audit`
//! existed, with `relation "admin_audit" does not exist` — the RED transcript
//! is in the FU5 report.
//!
//! # What these tests hold to
//!
//! Each audited action gets one test that asserts the row's FIELDS BY VALUE,
//! in the shape WS4-3's `revocation_writes_an_audit_row_that_reads_alone`
//! established: "an audit row exists" is not a claim worth making, because a
//! row full of NULLs satisfies it. A record has to READ ALONE months later to
//! somebody with no system access — who acted, on what, what changed, when, in
//! which workspace.
//!
//! Every absence-claim carries a PREMISE assertion (the thing really was absent
//! beforehand) and every refusal carries a POSITIVE CONTROL in the same body
//! (the same call, changed in one dimension, that must succeed). Without them a
//! green run proves nothing about the mechanism under test.
//!
//! All fixture data is synthetic.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use secureprompt_api::db::admin_audit_repo::AdminAuditAction;
use secureprompt_api::{
    app_state::AppState, http::build_router, http::middleware::jwt_auth::Claims,
    ml_sidecar::MlSidecarClient,
};
use secureprompt_common::config::{
    AppConfig, ClickhouseConfig, DatabaseConfig, JwtConfig, LicenseConfig, RedisConfig,
    ServerConfig, TelemetryConfig,
};
use serde_json::{json, Value};
use sqlx::{postgres::PgConnectOptions, Connection, PgConnection, PgPool, Row};
use std::collections::BTreeSet;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

const TEST_JWT_SECRET: &str = "fu5-admin-audit-test-secret";

// ── Harness ───────────────────────────────────────────────────────────────

fn redis_url() -> String {
    std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".into())
}

fn test_config() -> AppConfig {
    AppConfig {
        database: DatabaseConfig {
            url: "postgres://unused".into(),
            max_connections: 1,
        },
        redis: RedisConfig {
            url: redis_url(),
            max_connections: 4,
        },
        telemetry: TelemetryConfig {
            otel_enabled: false,
            prometheus_enabled: false,
            log_level: "error".into(),
        },
        server: ServerConfig {
            host: "127.0.0.1".into(),
            port: 0,
        },
        clickhouse: ClickhouseConfig {
            url: "http://localhost:8123".into(),
            database: "sp_analytics".into(),
        },
        jwt: JwtConfig {
            secret: TEST_JWT_SECRET.into(),
            access_ttl_secs: 900,
            refresh_ttl_secs: 3600,
        },
        public_signup_enabled: false,
        chat_debug_mode: false,
        redact_when_no_rules: false,
        sidecar_unavailable_default: "block".to_owned(),
        license: LicenseConfig::default(),
    }
}

/// The provider credential key must exist before `AppState::new` builds the KMS
/// backend, or provider creation cannot encrypt and the audit test would be
/// measuring a 500 instead of an audit row.
fn set_provider_key() {
    std::env::set_var(
        "SECUREPROMPT_PROVIDER_KEY",
        "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
    );
}

fn build_app(pool: PgPool) -> axum::Router {
    let ml = Arc::new(MlSidecarClient::new(String::new(), 100));
    build_router(AppState::new(
        pool,
        test_config(),
        ml,
        Arc::new(secureprompt_api::license::LicenseState::unlicensed()),
    ))
}

fn make_jwt(workspace_id: Uuid, user_id: Uuid, role: &str) -> String {
    let now = chrono::Utc::now();
    let claims = Claims {
        sub: user_id,
        ws: workspace_id,
        role: role.to_owned(),
        jti: Uuid::new_v4().to_string(),
        exp: (now + chrono::Duration::seconds(900)).timestamp(),
        iat: now.timestamp(),
        purpose: None,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(TEST_JWT_SECRET.as_bytes()),
    )
    .expect("jwt encode")
}

struct Workspace {
    id: Uuid,
    admin: Uuid,
    admin_email: String,
    viewer: Uuid,
}

async fn seed_workspace(pool: &PgPool) -> Workspace {
    let id = Uuid::new_v4();
    let suffix = Uuid::new_v4().simple().to_string();
    sqlx::query(
        "INSERT INTO workspaces (id, name, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(id)
    .bind(format!("fu5 {suffix}"))
    .execute(pool)
    .await
    .expect("seed workspace");

    let mut ids = Vec::new();
    for role in ["admin", "viewer"] {
        let user_id = Uuid::new_v4();
        let email = format!("{role}-{suffix}@example.invalid");
        sqlx::query(
            "INSERT INTO users (id, workspace_id, email, password_hash, role, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, NOW(), NOW())",
        )
        .bind(user_id)
        .bind(id)
        .bind(&email)
        .bind("$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .bind(role)
        .execute(pool)
        .await
        .expect("seed user");
        ids.push((user_id, email));
    }
    Workspace {
        id,
        admin: ids[0].0,
        admin_email: ids[0].1.clone(),
        viewer: ids[1].0,
    }
}

async fn send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    token: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"));
    let request = match body {
        Some(value) => builder
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&value).expect("encode body")))
            .expect("request"),
        None => builder.body(Body::empty()).expect("request"),
    };
    let response = app.clone().oneshot(request).await.expect("router runs");
    let status = response.status();
    use http_body_util::BodyExt;
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}

/// One `admin_audit` row, read back with every column a test asserts on.
struct AuditRow {
    workspace_id: Uuid,
    action: String,
    actor_user_id: Option<Uuid>,
    actor_email: Option<String>,
    actor_role: Option<String>,
    target_type: String,
    target_id: Option<Uuid>,
    target_label: Option<String>,
    target_user_id: Option<Uuid>,
    target_email: Option<String>,
    target_role: Option<String>,
    detail: Value,
}

/// Every audit row for one workspace, oldest first. Reads through the
/// `#[sqlx::test]` superuser pool on purpose — RLS is proved separately, from a
/// connection that cannot bypass it.
async fn audit_rows(pool: &PgPool, workspace_id: Uuid) -> Vec<AuditRow> {
    sqlx::query(
        "SELECT workspace_id, action, actor_user_id, actor_email, actor_role, target_type, \
                target_id, target_label, target_user_id, target_email, target_role, detail \
         FROM admin_audit WHERE workspace_id = $1 ORDER BY created_at, action",
    )
    .bind(workspace_id)
    .fetch_all(pool)
    .await
    .expect("read admin_audit")
    .into_iter()
    .map(|row| AuditRow {
        workspace_id: row.get("workspace_id"),
        action: row.get("action"),
        actor_user_id: row.get("actor_user_id"),
        actor_email: row.get("actor_email"),
        actor_role: row.get("actor_role"),
        target_type: row.get("target_type"),
        target_id: row.get("target_id"),
        target_label: row.get("target_label"),
        target_user_id: row.get("target_user_id"),
        target_email: row.get("target_email"),
        target_role: row.get("target_role"),
        detail: row.get("detail"),
    })
    .collect()
}

/// The single row for one action, failing loudly when the count is not one —
/// "some row exists" is the vacuous version of this assertion.
async fn only_row_for(pool: &PgPool, workspace_id: Uuid, action: &str) -> AuditRow {
    let mut matching: Vec<AuditRow> = audit_rows(pool, workspace_id)
        .await
        .into_iter()
        .filter(|row| row.action == action)
        .collect();
    assert_eq!(
        matching.len(),
        1,
        "expected exactly one `{action}` audit row for this workspace"
    );
    matching.remove(0)
}

/// PREMISE helper: the table really is empty for this workspace, so a row found
/// after the action was written BY the action.
async fn assert_no_audit_yet(pool: &PgPool, workspace_id: Uuid) {
    let rows = audit_rows(pool, workspace_id).await;
    assert!(
        rows.is_empty(),
        "premise: this workspace's audit trail must start empty, found {} row(s)",
        rows.len()
    );
}

/// Assert the actor columns name the human who acted. Every audited action
/// shares these, and an id with no email does not read alone months later.
fn assert_actor_is(row: &AuditRow, ws: &Workspace) {
    assert_eq!(row.workspace_id, ws.id, "the tenant the action happened in");
    assert_eq!(
        row.actor_user_id,
        Some(ws.admin),
        "the acting user, from the authenticated context and never a request body"
    );
    assert_eq!(
        row.actor_email.as_deref(),
        Some(ws.admin_email.as_str()),
        "the actor's email as it read AT THE TIME — an id alone is unreadable later"
    );
    assert_eq!(row.actor_role.as_deref(), Some("admin"));
}

// ── API keys ──────────────────────────────────────────────────────────────

/// The headline case. An API key is a credential; "who issued this credential"
/// is among the first questions asked in a real audit and had no answer at all.
#[sqlx::test]
async fn creating_an_api_key_writes_an_audit_row_that_reads_alone(pool: PgPool) {
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());
    let admin = make_jwt(ws.id, ws.admin, "admin");
    assert_no_audit_yet(&pool, ws.id).await;

    let (status, body) = send(
        &app,
        "POST",
        "/v1/keys",
        &admin,
        Some(json!({"name": "nightly-batch"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create key: {body}");
    let key_id = Uuid::parse_str(body["id"].as_str().expect("id")).expect("uuid");

    let row = only_row_for(&pool, ws.id, "api_key.created").await;
    assert_actor_is(&row, &ws);
    assert_eq!(row.target_type, "api_key");
    assert_eq!(
        row.target_id,
        Some(key_id),
        "the row must name WHICH key was created"
    );
    assert_eq!(
        row.target_label.as_deref(),
        Some("nightly-batch"),
        "the key's own name, so the record reads alone after the key is deleted"
    );
    assert_eq!(
        row.detail["assigned_user_id"],
        Value::Null,
        "an unassigned workspace key records that fact rather than omitting it"
    );
}

/// Revocation and rotation are separate facts from creation and each needs its
/// own row: "this key was issued and later rotated" is a different history from
/// "this key was issued".
#[sqlx::test]
async fn revoking_and_rotating_a_key_are_each_audited_against_that_key(pool: PgPool) {
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());
    let admin = make_jwt(ws.id, ws.admin, "admin");

    let (_, created) = send(
        &app,
        "POST",
        "/v1/keys",
        &admin,
        Some(json!({"name": "to-rotate"})),
    )
    .await;
    let rotate_id = Uuid::parse_str(created["id"].as_str().expect("id")).expect("uuid");
    let (_, created2) = send(
        &app,
        "POST",
        "/v1/keys",
        &admin,
        Some(json!({"name": "to-revoke"})),
    )
    .await;
    let revoke_id = Uuid::parse_str(created2["id"].as_str().expect("id")).expect("uuid");

    let (status, body) = send(
        &app,
        "POST",
        &format!("/v1/keys/{rotate_id}/rotate"),
        &admin,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "rotate: {body}");
    let (status, body) = send(
        &app,
        "DELETE",
        &format!("/v1/keys/{revoke_id}"),
        &admin,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "revoke: {body}");

    let rotated = only_row_for(&pool, ws.id, "api_key.rotated").await;
    assert_actor_is(&rotated, &ws);
    assert_eq!(rotated.target_id, Some(rotate_id));
    assert_eq!(rotated.target_label.as_deref(), Some("to-rotate"));
    assert!(
        rotated.detail["grace_expires_at"].is_string(),
        "rotation leaves the old key valid for a grace window; the record must \
         say until when, because that window is the residual risk"
    );

    let revoked = only_row_for(&pool, ws.id, "api_key.revoked").await;
    assert_actor_is(&revoked, &ws);
    assert_eq!(
        revoked.target_id,
        Some(revoke_id),
        "the revocation must name the key it revoked, not the one it rotated"
    );
    assert_eq!(revoked.target_label.as_deref(), Some("to-revoke"));
}

/// A failed action must NOT be audited as though it happened. Revoking a key
/// that does not exist is a 404, and a trail that records it claims an event
/// that never occurred.
#[sqlx::test]
async fn a_refused_action_writes_no_audit_row(pool: PgPool) {
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());
    let admin = make_jwt(ws.id, ws.admin, "admin");

    let absent = Uuid::new_v4();
    let (status, _) = send(&app, "DELETE", &format!("/v1/keys/{absent}"), &admin, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "premise: the key is absent");
    assert!(
        audit_rows(&pool, ws.id)
            .await
            .iter()
            .all(|row| row.action != "api_key.revoked"),
        "a 404 must leave no `api_key.revoked` row behind"
    );

    // POSITIVE CONTROL: the same call against a key that DOES exist writes the
    // row, so the absence above is the refusal and not a missing writer.
    let (_, created) = send(
        &app,
        "POST",
        "/v1/keys",
        &admin,
        Some(json!({"name": "control"})),
    )
    .await;
    let real = Uuid::parse_str(created["id"].as_str().expect("id")).expect("uuid");
    let (status, _) = send(&app, "DELETE", &format!("/v1/keys/{real}"), &admin, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let row = only_row_for(&pool, ws.id, "api_key.revoked").await;
    assert_eq!(
        row.target_id,
        Some(real),
        "control: the real revocation IS audited"
    );
}

// ── Provider credentials ──────────────────────────────────────────────────

/// Adding a provider credential is the act of giving the gateway the ability to
/// spend money and ship prompts to a third party. It was unaudited.
#[sqlx::test]
async fn creating_a_provider_credential_is_audited(pool: PgPool) {
    set_provider_key();
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());
    let admin = make_jwt(ws.id, ws.admin, "admin");
    assert_no_audit_yet(&pool, ws.id).await;

    let (status, body) = send(
        &app,
        "POST",
        "/v1/providers",
        &admin,
        Some(json!({
            "name": "openai-prod",
            "provider_type": "openai",
            "credential": "sk-fu5-create-secret-value"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create provider: {body}");
    let provider_id = Uuid::parse_str(body["id"].as_str().expect("id")).expect("uuid");

    let row = only_row_for(&pool, ws.id, "provider_credential.created").await;
    assert_actor_is(&row, &ws);
    assert_eq!(row.target_type, "provider");
    assert_eq!(row.target_id, Some(provider_id));
    assert_eq!(row.target_label.as_deref(), Some("openai-prod"));
    assert_eq!(
        row.detail["provider_type"],
        json!("openai"),
        "which upstream this credential reaches"
    );
    assert_eq!(
        row.detail["credential_present"],
        json!(true),
        "WHETHER a credential was supplied is auditable; its value never is"
    );
}

/// "The provider was updated" is not an audit record. Which fields moved, and
/// from what to what, is.
#[sqlx::test]
async fn updating_a_provider_records_which_fields_changed(pool: PgPool) {
    set_provider_key();
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());
    let admin = make_jwt(ws.id, ws.admin, "admin");

    let (_, created) = send(
        &app,
        "POST",
        "/v1/providers",
        &admin,
        Some(json!({"name": "before-name", "provider_type": "openai"})),
    )
    .await;
    let provider_id = Uuid::parse_str(created["id"].as_str().expect("id")).expect("uuid");

    let (status, body) = send(
        &app,
        "PUT",
        &format!("/v1/providers/{provider_id}"),
        &admin,
        Some(json!({"name": "after-name", "credential": "sk-fu5-rotated-secret"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "update provider: {body}");

    let row = only_row_for(&pool, ws.id, "provider_credential.updated").await;
    assert_actor_is(&row, &ws);
    assert_eq!(row.target_id, Some(provider_id));
    assert_eq!(
        row.detail["changed"]["name"]["before"],
        json!("before-name"),
        "the record must carry the value that was replaced, or it cannot be \
         read as a change"
    );
    assert_eq!(row.detail["changed"]["name"]["after"], json!("after-name"));
    assert_eq!(
        row.detail["credential_replaced"],
        json!(true),
        "replacing a credential is the security-relevant half of this edit"
    );
}

/// Deleting a provider destroys the object, so the audit row is the only
/// surviving description of what was deleted.
#[sqlx::test]
async fn deleting_a_provider_is_audited_after_the_object_is_gone(pool: PgPool) {
    set_provider_key();
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());
    let admin = make_jwt(ws.id, ws.admin, "admin");

    let (_, created) = send(
        &app,
        "POST",
        "/v1/providers",
        &admin,
        Some(json!({"name": "doomed", "provider_type": "anthropic"})),
    )
    .await;
    let provider_id = Uuid::parse_str(created["id"].as_str().expect("id")).expect("uuid");

    let (status, _) = send(
        &app,
        "DELETE",
        &format!("/v1/providers/{provider_id}"),
        &admin,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // PREMISE: the object really is gone, so the audit row is genuinely the
    // only remaining record and the label below is load-bearing.
    let survivors: i64 = sqlx::query_scalar("SELECT count(*) FROM providers WHERE id = $1")
        .bind(provider_id)
        .fetch_one(&pool)
        .await
        .expect("count providers");
    assert_eq!(survivors, 0, "premise: the provider row was really deleted");

    let row = only_row_for(&pool, ws.id, "provider_credential.deleted").await;
    assert_actor_is(&row, &ws);
    assert_eq!(row.target_id, Some(provider_id));
    assert_eq!(
        row.target_label.as_deref(),
        Some("doomed"),
        "the deleted object's name, captured before the DELETE — a UUID alone \
         names nothing once the row it pointed at is gone"
    );
    assert_eq!(row.detail["provider_type"], json!("anthropic"));
}

// ── Policy rules ──────────────────────────────────────────────────────────

/// The redaction policy IS the product's security control. An unaudited edit to
/// it is the single most consequential gap FU5 closes: a rule silently
/// disabled for an afternoon leaves no trace that it ever was.
#[sqlx::test]
async fn the_policy_rule_lifecycle_is_audited_with_what_changed(pool: PgPool) {
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());
    let admin = make_jwt(ws.id, ws.admin, "admin");
    assert_no_audit_yet(&pool, ws.id).await;

    let (status, created) = send(
        &app,
        "POST",
        "/v1/policy-rules",
        &admin,
        Some(json!({
            "name": "mask-emails",
            "priority": 10,
            "action": "redact",
            "enabled": true,
            "dry_run": false
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create rule: {created}");
    let rule_id = Uuid::parse_str(created["id"].as_str().expect("id")).expect("uuid");

    let row = only_row_for(&pool, ws.id, "policy_rule.created").await;
    assert_actor_is(&row, &ws);
    assert_eq!(row.target_type, "policy_rule");
    assert_eq!(row.target_id, Some(rule_id));
    assert_eq!(row.target_label.as_deref(), Some("mask-emails"));
    assert_eq!(row.detail["priority"], json!(10));
    assert_eq!(row.detail["rule_action"], json!("redact"));
    assert_eq!(row.detail["enabled"], json!(true));
    assert_eq!(row.detail["dry_run"], json!(false));

    // An edit that moves priority and the enforcement action.
    let (status, body) = send(
        &app,
        "PUT",
        &format!("/v1/policy-rules/{rule_id}"),
        &admin,
        Some(json!({
            "name": "mask-emails",
            "priority": 20,
            "action": "deny",
            "enabled": true,
            "dry_run": false
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "update rule: {body}");

    let updated = only_row_for(&pool, ws.id, "policy_rule.updated").await;
    assert_eq!(updated.detail["changed"]["priority"]["before"], json!(10));
    assert_eq!(updated.detail["changed"]["priority"]["after"], json!(20));
    assert_eq!(
        updated.detail["changed"]["rule_action"]["before"],
        json!("redact")
    );
    assert_eq!(
        updated.detail["changed"]["rule_action"]["after"],
        json!("deny"),
        "an enforcement action moving from redact to deny is the whole point \
         of auditing policy edits"
    );
    assert!(
        updated.detail["changed"].get("name").is_none(),
        "a field that did not move must not appear in the diff, or every edit \
         reads as though it changed everything"
    );

    // Disabling the rule.
    let (status, _) = send(
        &app,
        "PATCH",
        &format!("/v1/policy-rules/{rule_id}/enabled"),
        &admin,
        Some(json!({"value": false})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let toggled = only_row_for(&pool, ws.id, "policy_rule.enabled_changed").await;
    assert_eq!(toggled.target_id, Some(rule_id));
    assert_eq!(toggled.detail["before"], json!(true));
    assert_eq!(
        toggled.detail["after"],
        json!(false),
        "which direction the control moved is the fact being recorded"
    );

    // Putting the rule into dry-run, which silently stops it enforcing.
    let (status, _) = send(
        &app,
        "PATCH",
        &format!("/v1/policy-rules/{rule_id}/dry-run"),
        &admin,
        Some(json!({"value": true})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let dry = only_row_for(&pool, ws.id, "policy_rule.dry_run_changed").await;
    assert_eq!(dry.detail["before"], json!(false));
    assert_eq!(dry.detail["after"], json!(true));

    // And the deletion.
    let (status, _) = send(
        &app,
        "DELETE",
        &format!("/v1/policy-rules/{rule_id}"),
        &admin,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let deleted = only_row_for(&pool, ws.id, "policy_rule.deleted").await;
    assert_eq!(deleted.target_id, Some(rule_id));
    assert_eq!(
        deleted.target_label.as_deref(),
        Some("mask-emails"),
        "the deleted rule's name, captured before the DELETE"
    );
}

// ── Users ─────────────────────────────────────────────────────────────────

/// Creating a user is granting access, and the role granted is the whole
/// security content of the event.
#[sqlx::test]
async fn creating_a_user_records_the_principal_and_the_role_granted(pool: PgPool) {
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());
    let admin = make_jwt(ws.id, ws.admin, "admin");
    assert_no_audit_yet(&pool, ws.id).await;

    let (status, body) = send(
        &app,
        "POST",
        "/v1/users",
        &admin,
        Some(json!({
            "email": "newcomer@example.invalid",
            "password": "correct-horse-battery-staple",
            "role": "admin"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create user: {body}");
    let new_id = Uuid::parse_str(body["id"].as_str().expect("id")).expect("uuid");

    let row = only_row_for(&pool, ws.id, "user.created").await;
    assert_actor_is(&row, &ws);
    assert_eq!(row.target_type, "user");
    assert_eq!(row.target_id, Some(new_id));
    assert_eq!(
        row.target_user_id,
        Some(new_id),
        "a user-targeted action fills the target_user_id column the export \
         already carries, not only the generic target_id"
    );
    assert_eq!(
        row.target_email.as_deref(),
        Some("newcomer@example.invalid")
    );
    assert_eq!(
        row.target_role.as_deref(),
        Some("admin"),
        "the role granted — the security content of the event"
    );
}

// ── Secrets ───────────────────────────────────────────────────────────────

/// No secret may reach the audit trail, INCLUDING inside the JSONB detail.
///
/// This repository has had three separate rounds of a backend's own error text
/// reaching a response body. A credential in a never-purged audit row is the
/// same class of defect with worse consequences, so it is proved rather than
/// commented: every column of every row is cast to text and searched.
#[sqlx::test]
async fn no_secret_reaches_the_admin_audit_trail(pool: PgPool) {
    set_provider_key();
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());
    let admin = make_jwt(ws.id, ws.admin, "admin");

    const PROVIDER_SECRET: &str = "sk-fu5-do-not-store-this-anywhere";
    const NEW_PROVIDER_SECRET: &str = "sk-fu5-replacement-also-secret";
    const USER_PASSWORD: &str = "fu5-user-password-do-not-store";

    let (status, created) = send(
        &app,
        "POST",
        "/v1/providers",
        &admin,
        Some(json!({
            "name": "secret-holder",
            "provider_type": "openai",
            "credential": PROVIDER_SECRET
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create provider: {created}");
    let provider_id = Uuid::parse_str(created["id"].as_str().expect("id")).expect("uuid");

    let (status, _) = send(
        &app,
        "PUT",
        &format!("/v1/providers/{provider_id}"),
        &admin,
        Some(json!({"credential": NEW_PROVIDER_SECRET})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, key_body) = send(
        &app,
        "POST",
        "/v1/keys",
        &admin,
        Some(json!({"name": "secret-key"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let api_key_plaintext = key_body["api_key"]
        .as_str()
        .expect("the plaintext key is returned exactly once")
        .to_owned();

    let (status, _) = send(
        &app,
        "POST",
        "/v1/users",
        &admin,
        Some(json!({
            "email": "secret-user@example.invalid",
            "password": USER_PASSWORD,
            "role": "viewer"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // PREMISE: the actions above really did produce audit rows, so a search
    // that finds no secret is searching something rather than nothing.
    let rows = audit_rows(&pool, ws.id).await;
    assert!(
        rows.len() >= 4,
        "premise: the four actions above must have written audit rows, found {}",
        rows.len()
    );

    // Every column of every row, as text — the JSONB `detail` included, which
    // is where a careless diff would hide a credential.
    let dumped: String = sqlx::query_scalar(
        "SELECT coalesce(string_agg(t::text, ' '), '') FROM admin_audit t WHERE workspace_id = $1",
    )
    .bind(ws.id)
    .fetch_one(&pool)
    .await
    .expect("dump admin_audit as text");

    // POSITIVE CONTROL: the search really does find a string that IS present,
    // so a clean result below is evidence and not a broken haystack.
    assert!(
        dumped.contains("secret-holder"),
        "control: the provider's NAME is recorded and must be findable by this \
         same search, or the searches below prove nothing"
    );

    for (label, secret) in [
        ("the provider credential", PROVIDER_SECRET),
        ("the replacement provider credential", NEW_PROVIDER_SECRET),
        ("the API key plaintext", api_key_plaintext.as_str()),
        ("the new user's password", USER_PASSWORD),
    ] {
        assert!(
            !dumped.contains(secret),
            "{label} reached the admin audit trail, which is never purged"
        );
    }

    // A partial secret is still a secret: the plaintext API key's first eight
    // characters are shown in the dashboard, and must still not be stored here.
    let prefix: String = api_key_plaintext.chars().take(8).collect();
    assert!(
        !dumped.contains(&prefix),
        "an eight-character prefix of the live API key reached the audit trail"
    );
}

// ── Tenancy ───────────────────────────────────────────────────────────────

/// One tenant's administrative history must not appear in another's. The audit
/// trail feeds a signed compliance export, so a leak here is a leak into a
/// document the customer hands to their regulator.
#[sqlx::test]
async fn an_audit_row_is_written_only_for_the_acting_workspace(pool: PgPool) {
    let a = seed_workspace(&pool).await;
    let b = seed_workspace(&pool).await;
    let app = build_app(pool.clone());

    let (status, _) = send(
        &app,
        "POST",
        "/v1/keys",
        &make_jwt(a.id, a.admin, "admin"),
        Some(json!({"name": "belongs-to-a"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let in_b = audit_rows(&pool, b.id).await;
    assert!(
        in_b.is_empty(),
        "workspace B must have no audit rows from workspace A's action"
    );

    // POSITIVE CONTROL: B's own action IS audited under B, so the emptiness
    // above is tenancy and not a writer that never runs for B.
    let (status, _) = send(
        &app,
        "POST",
        "/v1/keys",
        &make_jwt(b.id, b.admin, "admin"),
        Some(json!({"name": "belongs-to-b"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let row = only_row_for(&pool, b.id, "api_key.created").await;
    assert_eq!(row.target_label.as_deref(), Some("belongs-to-b"));
    assert_eq!(row.workspace_id, b.id);

    // And A still has exactly its own.
    let row_a = only_row_for(&pool, a.id, "api_key.created").await;
    assert_eq!(row_a.target_label.as_deref(), Some("belongs-to-a"));
}

/// A viewer cannot perform these actions at all, so no audit row is written for
/// an attempt that was refused — with the admin control proving the route works.
#[sqlx::test]
async fn a_refused_role_writes_nothing_where_an_admin_writes_a_row(pool: PgPool) {
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());

    let (status, _) = send(
        &app,
        "POST",
        "/v1/keys",
        &make_jwt(ws.id, ws.viewer, "viewer"),
        Some(json!({"name": "viewer-attempt"})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "premise: a viewer is refused"
    );
    assert!(
        audit_rows(&pool, ws.id).await.is_empty(),
        "a refused attempt must not be recorded as an action that happened"
    );

    // POSITIVE CONTROL.
    let (status, _) = send(
        &app,
        "POST",
        "/v1/keys",
        &make_jwt(ws.id, ws.admin, "admin"),
        Some(json!({"name": "admin-succeeds"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        audit_rows(&pool, ws.id).await.len(),
        1,
        "control: the admin's identical call IS audited"
    );
}

// ── The audit write and the action are one transaction ────────────────────

/// The claim `admin_audit_repo` makes in its header, proved rather than
/// asserted: if the audit write fails, the administrative action does NOT take
/// effect.
///
/// A trail that can fail independently of the control it records is a trail
/// that lies — the action would have happened with nothing saying so. The
/// failure is induced the only honest way available from outside the code, by
/// removing the table the writer needs; `#[sqlx::test]` gives this test its own
/// database, so the DROP reaches nothing else.
#[sqlx::test]
async fn when_the_audit_write_fails_the_action_does_not_take_effect(pool: PgPool) {
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());
    let admin = make_jwt(ws.id, ws.admin, "admin");

    // POSITIVE CONTROL first: with the trail intact the call succeeds and the
    // key exists. Without this the failure below could be any 500 at all.
    let (status, _) = send(
        &app,
        "POST",
        "/v1/keys",
        &admin,
        Some(json!({"name": "control-key"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let control_keys: i64 =
        sqlx::query_scalar("SELECT count(*) FROM api_keys WHERE workspace_id = $1")
            .bind(ws.id)
            .fetch_one(&pool)
            .await
            .expect("count keys");
    assert_eq!(control_keys, 1, "control: the key really was created");

    sqlx::query("DROP TABLE admin_audit")
        .execute(&pool)
        .await
        .expect("drop the audit table to force the audit write to fail");

    let (status, _) = send(
        &app,
        "POST",
        "/v1/keys",
        &admin,
        Some(json!({"name": "must-not-exist"})),
    )
    .await;
    assert!(
        status.is_server_error() || status.is_client_error(),
        "an action whose audit write failed must not report success; got {status}"
    );

    let keys: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM api_keys WHERE workspace_id = $1 AND name = 'must-not-exist'",
    )
    .bind(ws.id)
    .fetch_one(&pool)
    .await
    .expect("count keys");
    assert_eq!(
        keys, 0,
        "the API key was created even though its audit row could not be \
         written — the action and its record must commit together or not at all"
    );
}

// ── The vocabulary is pinned, so a new action cannot drift ────────────────

/// Extract the string literals from a CHECK constraint's definition.
fn literals_in(def: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut rest = def;
    while let Some(open) = rest.find('\'') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('\'') else { break };
        out.insert(after[..close].to_owned());
        rest = &after[close + 1..];
    }
    out
}

/// The action vocabulary exists in three places that can drift apart, and this
/// test is what makes adding an action a chain of failures rather than a
/// convention.
///
///   1. `AdminAuditAction::ALL` — the Rust enum the writers use.
///   2. migration 028's `admin_audit_action_known` CHECK — what the database
///      will accept, so an undocumented action cannot even be stored.
///   3. `audit_export::CONTROL_COVERAGE` — the prose copied verbatim into every
///      signed manifest, which is what an auditor actually reads.
///
/// The export itself needs no entry: it selects every row of `admin_audit`
/// without an `action` predicate, so a new action reaches the artifact with no
/// export change at all. What can still go wrong is the DOCUMENT falling behind
/// the code, and that is what this pins.
#[sqlx::test]
async fn the_action_vocabulary_is_pinned_in_three_places(pool: PgPool) {
    let in_rust: BTreeSet<String> = AdminAuditAction::ALL
        .iter()
        .map(|a| a.as_str().to_owned())
        .collect();

    // PREMISE: there really is a vocabulary to compare, so three empty sets
    // cannot agree with each other and pass.
    assert!(
        in_rust.len() >= 12,
        "premise: the enum must carry the audited actions, found {}",
        in_rust.len()
    );

    let def: String = sqlx::query_scalar(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint \
         WHERE conname = 'admin_audit_action_known'",
    )
    .fetch_one(&pool)
    .await
    .expect("migration 028 must install the action CHECK constraint");
    let in_database = literals_in(&def);
    assert_eq!(
        in_database, in_rust,
        "migration 028's CHECK constraint and `AdminAuditAction::ALL` disagree. \
         A variant added in Rust without a migration entry would be REFUSED by \
         the database at the moment an administrator performed it."
    );

    let missing_from_prose: Vec<&String> = in_rust
        .iter()
        .filter(|action| {
            !secureprompt_common::audit_export::CONTROL_COVERAGE.contains(action.as_str())
        })
        .collect();
    assert!(
        missing_from_prose.is_empty(),
        "these audited actions are not named in `CONTROL_COVERAGE`, the text \
         copied into every signed manifest, so the auditor's own document does \
         not know they exist: {missing_from_prose:?}"
    );
}

// ── RLS, proved from a role that cannot bypass it ─────────────────────────

const RLS_ROLE: &str = "secureprompt_runner";
const RLS_PASSWORD: &str = "secureprompt";

async fn ensure_low_privilege_role(pool: &PgPool) {
    sqlx::raw_sql(&format!(
        "DO $$
         BEGIN
             CREATE ROLE {RLS_ROLE}
                 LOGIN PASSWORD '{RLS_PASSWORD}'
                 NOSUPERUSER CREATEDB CREATEROLE NOBYPASSRLS;
         EXCEPTION
             WHEN duplicate_object THEN NULL;
         END $$;"
    ))
    .execute(pool)
    .await
    .unwrap_or_else(|e| {
        panic!(
            "could not create the {RLS_ROLE} role ({e}). In CI this role is \
             created by scripts/ci/create-nonsuperuser-role.sh; locally the \
             connecting role needs CREATEROLE."
        )
    });

    sqlx::raw_sql(&format!(
        "GRANT USAGE ON SCHEMA public TO {RLS_ROLE};
         GRANT ALL ON ALL TABLES IN SCHEMA public TO {RLS_ROLE};
         GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO {RLS_ROLE};"
    ))
    .execute(pool)
    .await
    .expect("grants on the test database");
}

/// Open a connection to the SAME `#[sqlx::test]` database as `RLS_ROLE`, and
/// assert on the wire that it really is powerless. The `#[sqlx::test]` pool is
/// a BYPASSRLS superuser, so without these premise assertions the test below
/// would keep passing while exercising no RLS at all.
async fn low_privilege_connection(pool: &PgPool) -> PgConnection {
    ensure_low_privilege_role(pool).await;
    let options: PgConnectOptions = (*pool.connect_options())
        .clone()
        .username(RLS_ROLE)
        .password(RLS_PASSWORD);
    let mut conn = PgConnection::connect_with(&options)
        .await
        .expect("low-privilege connection");

    let row = sqlx::query(
        "SELECT current_user::text AS who, rolsuper, rolbypassrls \
         FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&mut conn)
    .await
    .expect("identity probe");
    assert_eq!(row.get::<String, _>("who"), RLS_ROLE);
    assert!(
        !row.get::<bool, _>("rolsuper"),
        "premise: the probe role is a SUPERUSER, so this test proves nothing"
    );
    assert!(
        !row.get::<bool, _>("rolbypassrls"),
        "premise: the probe role has BYPASSRLS, so this test proves nothing"
    );
    conn
}

/// Migration 028's RLS policy is ARMED, and the silent-zero trap is real.
///
/// This is the layer no other test in the repository can see: the application
/// connects as a BYPASSRLS superuser today, so a missing, malformed or
/// wrong-column policy would leave every `#[sqlx::test]` green while one
/// tenant's administrative history sat readable by another.
#[sqlx::test]
async fn migration_028_rls_isolates_the_admin_trail_from_a_nonsuperuser(pool: PgPool) {
    let a = seed_workspace(&pool).await;
    let b = seed_workspace(&pool).await;
    let app = build_app(pool.clone());

    for ws in [&a, &b] {
        let (status, _) = send(
            &app,
            "POST",
            "/v1/keys",
            &make_jwt(ws.id, ws.admin, "admin"),
            Some(json!({"name": "rls-probe"})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
    }

    // PREMISE: the superuser pool sees both, so anything the low-privilege
    // connection cannot see is RLS and not an empty table.
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM admin_audit")
        .fetch_one(&pool)
        .await
        .expect("premise count");
    assert_eq!(total, 2, "premise: two audit rows exist across two tenants");

    let mut conn = low_privilege_connection(&pool).await;

    // THE SILENT HALF OF THE TRAP: with the GUC unset the read SUCCEEDS and
    // returns nothing. On an export this reads as "these administrators did
    // nothing", which is why `scope::begin_scoped` reads the setting back.
    let unscoped: i64 = sqlx::query_scalar("SELECT count(*) FROM admin_audit")
        .fetch_one(&mut conn)
        .await
        .expect("an unscoped SELECT must SUCCEED — that is the trap");
    assert_eq!(
        unscoped, 0,
        "with `app.current_workspace_id` unset the policy predicate is NULL \
         for every row, so this must be a silent zero rather than an error"
    );

    // Scoped to A: exactly A's row, and never B's.
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, false)")
        .bind(a.id.to_string())
        .execute(&mut conn)
        .await
        .expect("arm the scope");
    let seen_a: Vec<Uuid> = sqlx::query_scalar("SELECT workspace_id FROM admin_audit")
        .fetch_all(&mut conn)
        .await
        .expect("scoped read");
    assert_eq!(
        seen_a,
        vec![a.id],
        "scoped to A, a non-superuser must see exactly A's administrative trail"
    );

    // POSITIVE CONTROL: the same connection scoped to B sees exactly B's row,
    // so the result above is the policy filtering and not a broken connection.
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, false)")
        .bind(b.id.to_string())
        .execute(&mut conn)
        .await
        .expect("re-arm the scope");
    let seen_b: Vec<Uuid> = sqlx::query_scalar("SELECT workspace_id FROM admin_audit")
        .fetch_all(&mut conn)
        .await
        .expect("scoped read");
    assert_eq!(seen_b, vec![b.id], "control: scoped to B it sees B's row");
}
