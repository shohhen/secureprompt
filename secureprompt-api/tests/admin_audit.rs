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
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::SigningKey;
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
use sp_license::{
    envelope_to_token,
    sign::sign_license,
    token::{Customer, Deployment, Entitlements, Integrity, License, ModelGrant},
};
use sqlx::{postgres::PgConnectOptions, Connection, PgConnection, PgPool, Row};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

const TEST_JWT_SECRET: &str = "fu5-admin-audit-test-secret";

/// The plaintext password every seeded account carries, so the login tests can
/// drive `POST /v1/auth/token` for real rather than minting a JWT around it.
const SEED_PASSWORD: &str = "p1a-seed-password-correct-horse";

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

/// P1A — the KMS key `AppState::new` builds `state.kms` from.
///
/// 2FA enrollment encrypts the TOTP secret through it, so without this the 2FA
/// audit tests would be measuring a 500 from `kms.encrypt` rather than an audit
/// row. Set in-process rather than read from `.env` so the suite does not
/// depend on the developer's shell.
fn set_kms_key() {
    // 32 zero bytes, base64-standard — `FileKms::from_env` requires exactly 32
    // decoded bytes and nothing about this suite depends on the value.
    std::env::set_var(
        "KMS_FILE_KEY",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    );
}

fn build_app(pool: PgPool) -> axum::Router {
    build_app_with_state(pool).1
}

/// The same router `build_app` returns, plus the `AppState` behind it.
///
/// P1A needs the state itself for the OIDC login case: `oidc_callback` cannot
/// be driven end-to-end without a live identity provider, so the test calls the
/// shared tail it delegates to — one line below the code under test — and that
/// function takes `&AppState`.
fn build_app_with_state(pool: PgPool) -> (AppState, axum::Router) {
    let ml = Arc::new(MlSidecarClient::new(String::new(), 100));
    let state = AppState::new(
        pool,
        test_config(),
        ml,
        Arc::new(secureprompt_api::license::LicenseState::unlicensed()),
    );
    (state.clone(), build_router(state))
}

/// A router whose configured vendor public key matches `sk`, so a token this
/// suite signs verifies. Mirrors `tests/license_routes.rs::build_app_with_keys`.
fn build_app_with_license_key(pool: PgPool, sk: &SigningKey) -> axum::Router {
    let mut config = test_config();
    config.license.pubkey_b64 = B64.encode(sk.verifying_key().to_bytes());
    let ml = Arc::new(MlSidecarClient::new(String::new(), 100));
    build_router(AppState::new(
        pool,
        config,
        ml,
        Arc::new(secureprompt_api::license::LicenseState::unlicensed()),
    ))
}

/// Sign a license token for `customer_name`. Copied in shape from
/// `tests/license_routes.rs::make_token` — the fields are the minimum
/// `decode_verified_token` and `load_and_verify_token` accept.
fn make_license_token(sk: &SigningKey, customer_name: &str) -> (String, String) {
    let lic_id = Uuid::new_v4().to_string();
    let lic = License {
        v: 1,
        lic_id: lic_id.clone(),
        customer: Customer {
            id: "p1a-customer".into(),
            name: customer_name.into(),
        },
        deployment: Deployment {
            scope: "single-node".into(),
            max_nodes: 1,
            sign_pubkey: "p".into(),
            wrapped_attestation_key: String::new(),
        },
        entitlements: Entitlements {
            not_before: "2000-01-01T00:00:00Z".into(),
            expires_at: "2099-01-01T00:00:00Z".into(),
            seats: 10,
            features: vec!["secure_mode".to_owned()],
            components: vec![],
            revalidate_soft_secs: None,
            revalidate_hard_secs: None,
        },
        model: ModelGrant {
            wrapped_key: "w".into(),
            models: vec![],
        },
        integrity: Integrity {
            image_digests: BTreeMap::new(),
        },
        iss: "sp-admin".into(),
        iat: "2000-01-01T00:00:00Z".into(),
    };
    let envelope = sign_license(&lic, sk).expect("sign license");
    (envelope_to_token(&envelope).expect("encode token"), lic_id)
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
    viewer_email: String,
}

/// A real Argon2id hash of `SEED_PASSWORD`.
///
/// P1A replaced a hard-coded placeholder hash here. The placeholder was never
/// verifiable, so `POST /v1/auth/token` could not be driven against a seeded
/// account at all and the login tests below would have had nothing to log into.
fn seed_password_hash() -> String {
    use argon2::{
        password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
        Argon2,
    };
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(SEED_PASSWORD.as_bytes(), &salt)
        .expect("argon2 hash")
        .to_string()
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

    let hash = seed_password_hash();
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
        .bind(&hash)
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
        viewer_email: ids[1].1.clone(),
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

/// A request with NO bearer, carrying a User-Agent and an `X-Forwarded-For`.
///
/// The two headers are load-bearing rather than decoration: the login tests
/// below assert that NEITHER reaches an audit row, and an absence-claim about a
/// header the request never sent proves nothing.
async fn send_unauthenticated(
    app: &axum::Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
    user_agent: &str,
    forwarded_for: &str,
) -> (StatusCode, Value) {
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("user-agent", user_agent)
        .header("x-forwarded-for", forwarded_for);
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

/// Log in with the seeded password, from a browser and an address.
async fn login(app: &axum::Router, email: &str, password: &str) -> (StatusCode, Value) {
    send_unauthenticated(
        app,
        "POST",
        "/v1/auth/token",
        Some(json!({"email": email, "password": password})),
        CHROME_MAC_UA,
        LOGIN_IP,
    )
    .await
}

/// A real Chrome-on-macOS User-Agent. FU4 reduces this to `Chrome on macOS`
/// for a SESSION row; the login audit row must carry neither form.
const CHROME_MAC_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
                             AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 \
                             Safari/537.36";
/// A documentation-range address (RFC 5737), so it parses and is not routable.
const LOGIN_IP: &str = "203.0.113.7";

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
    //
    // MR4 F8: this floor said 12 while the vocabulary was 22 — a premise that
    // has drifted ten below the truth stops being a premise. It tracks the
    // count now; raise it with the vocabulary.
    assert!(
        in_rust.len() >= 22,
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

// ══════════════════════════════════════════════════════════════════════════
// P1A — the four administrative surfaces FU5 left unaudited.
//
// FU5 audited twelve actions and named, in `CONTROL_COVERAGE` and in
// `docs/audit-export-format.md`, exactly what it had NOT reached: every
// dashboard login and OIDC sign-in; 2FA enrolment, reset and backup-code
// regeneration; license activation; and the secure-mode, sidecar-failure and
// budget settings. Those are the gaps these tests close.
//
// Nothing below extends the EXPORT. That is the claim the single-table design
// makes and it is checked rather than assumed: the exporter selects every row
// of `admin_audit` with no `action` predicate, so the only thing a new action
// has to reach is the vocabulary — which
// `the_action_vocabulary_is_pinned_in_three_places` already reconciles across
// the enum, migration 028's CHECK constraint and the manifest's prose. If a
// change to `secureprompt-worker/src/tasks/audit_export.rs` had been needed to
// make these actions exportable, the structural guarantee would have failed.
// ══════════════════════════════════════════════════════════════════════════

// ── TOTP helpers (an independent RFC 6238 implementation) ─────────────────

/// Build a verifier from the base32 secret `/enroll` returned, using
/// `totp-rs` directly rather than the server's own (private) helper — so a
/// passing test proves the server accepts a code an INDEPENDENT implementation
/// produced. Same shape as `tests/twofactor.rs::build_verifier`.
fn totp_verifier(secret_b32: &str) -> totp_rs::TOTP {
    let bytes = totp_rs::Secret::Encoded(secret_b32.to_owned())
        .to_bytes()
        .expect("the enroll response must return a valid base32 secret");
    totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        0,
        30,
        bytes,
        None,
        String::new(),
    )
    .expect("valid TOTP parameters")
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs()
}

/// A code guaranteed not to collide with the timestep already consumed for
/// `user_id`. Two `generate(now)` calls inside one test land in the SAME
/// 30-second step and the second is correctly refused as a replay, so a test
/// needing two successful TOTP uses must step past the persisted watermark.
async fn fresh_totp_code(pool: &PgPool, user_id: Uuid, secret_b32: &str) -> String {
    let last: Option<i64> =
        sqlx::query_scalar("SELECT totp_last_timestep FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(pool)
            .await
            .expect("read totp_last_timestep");
    let now_step = i64::try_from(unix_now() / 30).unwrap_or(i64::MAX);
    let step = match last {
        Some(previous) if previous >= now_step => previous + 1,
        _ => now_step,
    };
    totp_verifier(secret_b32).generate(u64::try_from(step).unwrap_or(0) * 30)
}

// ── 2FA lifecycle ─────────────────────────────────────────────────────────

/// Turning 2FA on, and turning it off again, are the two events an
/// investigator asks about after an account compromise, and neither left any
/// trace. "The attacker reset the victim's second factor at 03:12" is the
/// single most useful line an audit trail can hold, and it did not exist.
///
/// One test walks the whole lifecycle because the three actions are only
/// meaningful in sequence: an enrolment that is never confirmed is not 2FA, and
/// a reset of an account that never had it is nothing at all.
#[sqlx::test]
async fn the_two_factor_lifecycle_is_audited_from_enrolment_to_reset(pool: PgPool) {
    set_kms_key();
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());
    // The VIEWER, not the admin: a viewer is not forced into 2FA, so this is
    // the opt-in path, and it also proves the audit does not depend on the
    // actor being an administrator.
    let viewer = make_jwt(ws.id, ws.viewer, "viewer");
    assert_no_audit_yet(&pool, ws.id).await;

    let (status, enrolled) = send(&app, "POST", "/v1/auth/2fa/enroll", &viewer, None).await;
    assert_eq!(status, StatusCode::OK, "enroll: {enrolled}");
    let secret_b32 = enrolled["secret_b32"].as_str().expect("secret").to_owned();
    let backup_codes: Vec<String> = enrolled["backup_codes"]
        .as_array()
        .expect("backup codes")
        .iter()
        .map(|code| code.as_str().expect("code").to_owned())
        .collect();

    let started = only_row_for(&pool, ws.id, "two_factor.enrollment_started").await;
    assert_eq!(started.workspace_id, ws.id);
    assert_eq!(started.actor_user_id, Some(ws.viewer));
    assert_eq!(
        started.actor_email.as_deref(),
        Some(ws.viewer_email.as_str())
    );
    assert_eq!(started.target_type, "user");
    assert_eq!(
        started.target_user_id,
        Some(ws.viewer),
        "2FA is self-service: the actor IS the target, and the row must say so \
         in the column the export already carries"
    );
    assert_eq!(
        started.detail["backup_codes_issued"],
        json!(backup_codes.len()),
        "the count of single-use codes handed out — this endpoint IS the \
         backup-code regeneration path, and how many recovery credentials now \
         exist is the auditable fact"
    );
    assert_eq!(
        started.detail["reenrollment"],
        json!(false),
        "a first enrolment is not a reset of an existing second factor"
    );

    // Confirming is a SEPARATE event: until a code verifies, the account is
    // still password-only, and an audit trail that says "2FA enabled" at the
    // moment the QR code was shown would be wrong.
    let code = fresh_totp_code(&pool, ws.viewer, &secret_b32).await;
    let (status, body) = send(
        &app,
        "POST",
        "/v1/auth/2fa/verify",
        &viewer,
        Some(json!({"code": code})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "verify: {body}");

    let enabled = only_row_for(&pool, ws.id, "two_factor.enabled").await;
    assert_eq!(enabled.actor_user_id, Some(ws.viewer));
    assert_eq!(enabled.target_user_id, Some(ws.viewer));
    assert_eq!(
        enabled.target_role.as_deref(),
        Some("viewer"),
        "the principal's role at the time, so the row reads alone"
    );

    // And the reset. Disabling with a BACKUP CODE rather than a TOTP code, so
    // `verified_with` is asserted against the branch that is NOT the default.
    let (status, body) = send(
        &app,
        "POST",
        "/v1/auth/2fa/disable",
        &viewer,
        Some(json!({"code": backup_codes[0]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "disable: {body}");

    let disabled = only_row_for(&pool, ws.id, "two_factor.disabled").await;
    assert_eq!(disabled.actor_user_id, Some(ws.viewer));
    assert_eq!(disabled.target_user_id, Some(ws.viewer));
    assert_eq!(
        disabled.detail["verified_with"],
        json!("backup_code"),
        "WHICH factor authorised the reset is the security content: a reset \
         driven by a printed recovery code is a different event from one \
         driven by the authenticator app"
    );

    // PREMISE for the whole sequence: 2FA really is off again, so the last row
    // describes a state change that happened rather than one that was refused.
    let confirmed: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT totp_confirmed_at FROM users WHERE id = $1")
            .bind(ws.viewer)
            .fetch_one(&pool)
            .await
            .expect("read totp_confirmed_at");
    assert!(
        confirmed.is_none(),
        "premise: the account must really be back to password-only"
    );
}

/// A TOTP secret or a backup code in a never-purged audit row is a second
/// factor that is no longer a second factor.
///
/// Same shape as `no_secret_reaches_the_admin_audit_trail`, which covers the
/// provider credential, the API key and the password: dump every column of
/// every row as text — `detail` included — and search it, with a positive
/// control so a clean result is evidence rather than a broken haystack.
#[sqlx::test]
async fn no_totp_secret_or_backup_code_reaches_the_admin_audit_trail(pool: PgPool) {
    set_kms_key();
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());
    let viewer = make_jwt(ws.id, ws.viewer, "viewer");

    let (status, enrolled) = send(&app, "POST", "/v1/auth/2fa/enroll", &viewer, None).await;
    assert_eq!(status, StatusCode::OK, "enroll: {enrolled}");
    let secret_b32 = enrolled["secret_b32"].as_str().expect("secret").to_owned();
    let provisioning_uri = enrolled["provisioning_uri"]
        .as_str()
        .expect("uri")
        .to_owned();
    let backup_codes: Vec<String> = enrolled["backup_codes"]
        .as_array()
        .expect("backup codes")
        .iter()
        .map(|code| code.as_str().expect("code").to_owned())
        .collect();

    let code = fresh_totp_code(&pool, ws.viewer, &secret_b32).await;
    let (status, _) = send(
        &app,
        "POST",
        "/v1/auth/2fa/verify",
        &viewer,
        Some(json!({"code": code})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // PREMISE: both actions really wrote rows, so a search that finds nothing
    // is searching something.
    let rows = audit_rows(&pool, ws.id).await;
    assert!(
        rows.len() >= 2,
        "premise: enrolment and confirmation must have written audit rows, found {}",
        rows.len()
    );

    let dumped: String = sqlx::query_scalar(
        "SELECT coalesce(string_agg(t::text, ' '), '') FROM admin_audit t WHERE workspace_id = $1",
    )
    .bind(ws.id)
    .fetch_one(&pool)
    .await
    .expect("dump admin_audit as text");

    // POSITIVE CONTROL: the account's email IS recorded and must be findable
    // by this same search.
    assert!(
        dumped.contains(&ws.viewer_email),
        "control: the acting user's email is recorded and must be findable by \
         this same search, or the searches below prove nothing"
    );

    assert!(
        !dumped.contains(&secret_b32),
        "the TOTP secret reached the admin audit trail, which is never purged"
    );
    assert!(
        !dumped.contains(&provisioning_uri),
        "the provisioning URI embeds the same secret as a `secret=` query \
         parameter, so storing it leaks the secret by another name"
    );
    for code in &backup_codes {
        assert!(
            !dumped.contains(code.as_str()),
            "a backup code reached the admin audit trail"
        );
        let raw: String = code.chars().filter(|c| *c != '-').collect();
        assert!(
            !dumped.contains(&raw),
            "a backup code reached the trail in its stored, un-formatted form"
        );
    }
    // A partial secret is still a secret.
    let prefix: String = secret_b32.chars().take(8).collect();
    assert!(
        !dumped.contains(&prefix),
        "an eight-character prefix of the live TOTP secret reached the trail"
    );
}

// ── License activation ────────────────────────────────────────────────────

/// Which license this deployment is running under, and who installed it,
/// decides what the product will do — and the console lets an administrator
/// change it by pasting a string. That was unaudited.
#[sqlx::test]
async fn activating_and_clearing_a_license_are_audited_without_the_token(pool: PgPool) {
    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let ws = seed_workspace(&pool).await;
    let app = build_app_with_license_key(pool.clone(), &signing_key);
    let admin = make_jwt(ws.id, ws.admin, "admin");
    assert_no_audit_yet(&pool, ws.id).await;

    let (token, lic_id) = make_license_token(&signing_key, "P1A Test Co");
    let (status, body) = send(
        &app,
        "PUT",
        "/v1/license",
        &admin,
        Some(json!({"token": token})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "activate: {body}");

    let activated = only_row_for(&pool, ws.id, "license.activated").await;
    assert_actor_is(&activated, &ws);
    assert_eq!(activated.target_type, "license");
    assert_eq!(
        activated.target_label.as_deref(),
        Some(lic_id.as_str()),
        "WHICH license was installed. The id is the only identifier that \
         survives a later replacement, and revocation is a verdict about it"
    );
    assert_eq!(
        activated.detail["status"],
        json!("Valid"),
        "what the gateway concluded about the token it was handed"
    );
    assert_eq!(
        activated.detail["source_before"],
        json!("none"),
        "an install that had no stored license is a different event from a \
         replacement of one that did"
    );
    assert_eq!(activated.detail["source_after"], json!("db"));

    // Removing the license is the more consequential half — it can take a
    // running deployment back to Unlicensed.
    let (status, body) = send(&app, "DELETE", "/v1/license", &admin, None).await;
    assert_eq!(status, StatusCode::OK, "clear: {body}");
    let cleared = only_row_for(&pool, ws.id, "license.cleared").await;
    assert_actor_is(&cleared, &ws);
    assert_eq!(
        cleared.target_label.as_deref(),
        Some(lic_id.as_str()),
        "the id of the license that was REMOVED, captured before the delete — \
         afterwards there is nothing left to name it"
    );
    assert_eq!(cleared.detail["status_after"], json!("Unlicensed"));

    // The token itself is a bearer entitlement. It is stored in
    // `license_activation` — a declared artifact — and must not be copied into
    // a table that is never purged.
    let dumped: String = sqlx::query_scalar(
        "SELECT coalesce(string_agg(t::text, ' '), '') FROM admin_audit t WHERE workspace_id = $1",
    )
    .bind(ws.id)
    .fetch_one(&pool)
    .await
    .expect("dump admin_audit as text");
    assert!(
        dumped.contains(&lic_id),
        "control: the license id IS recorded and must be findable by this \
         same search, or the assertion below proves nothing"
    );
    assert!(
        !dumped.contains(&token),
        "the signed license token reached the admin audit trail"
    );
    let token_prefix: String = token.chars().take(24).collect();
    assert!(
        !dumped.contains(&token_prefix),
        "a 24-character prefix of the signed license token reached the trail"
    );
}

// ── Settings ──────────────────────────────────────────────────────────────

/// A budget is the spend control. Raising a limit or switching enforcement from
/// `block` to `warn` is the change that shows up on an invoice three weeks
/// later with nobody's name on it.
#[sqlx::test]
async fn budget_changes_are_audited_with_what_moved_and_a_no_op_writes_nothing(pool: PgPool) {
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());
    let admin = make_jwt(ws.id, ws.admin, "admin");
    assert_no_audit_yet(&pool, ws.id).await;

    let uri = format!("/v1/workspaces/{}/budgets", ws.id);
    let (status, body) = send(
        &app,
        "PUT",
        &uri,
        &admin,
        Some(json!({
            "daily_token_limit": 1000,
            "monthly_token_limit": 50000,
            "behavior": "warn"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "set budget: {body}");

    let created = only_row_for(&pool, ws.id, "budget.updated").await;
    assert_actor_is(&created, &ws);
    assert_eq!(created.target_type, "workspace");
    assert_eq!(
        created.target_id,
        Some(ws.id),
        "the budget has no id of its own — the workspace IS the object"
    );
    assert_eq!(
        created.detail["changed"]["daily_token_limit"]["before"],
        Value::Null,
        "no budget at all is a different starting point from a budget of zero, \
         and the record must distinguish them"
    );
    assert_eq!(
        created.detail["changed"]["daily_token_limit"]["after"],
        json!(1000)
    );
    assert_eq!(
        created.detail["changed"]["behavior"]["after"],
        json!("warn")
    );

    // The identical PUT again. Nothing moved, so nothing happened, so nothing
    // is recorded — the same rule `api_key.rotated` follows inside its grace
    // window. Without this a dashboard that re-saves on every page load would
    // bury the real changes.
    let (status, _) = send(
        &app,
        "PUT",
        &uri,
        &admin,
        Some(json!({
            "daily_token_limit": 1000,
            "monthly_token_limit": 50000,
            "behavior": "warn"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        audit_rows(&pool, ws.id)
            .await
            .iter()
            .filter(|row| row.action == "budget.updated")
            .count(),
        1,
        "a PUT that changed nothing must not add a second row"
    );

    // POSITIVE CONTROL: a PUT that DOES move a field writes the second row, so
    // the absence above is the no-op rule and not a writer that stopped.
    let (status, _) = send(
        &app,
        "PUT",
        &uri,
        &admin,
        Some(json!({
            "daily_token_limit": 1000,
            "monthly_token_limit": 50000,
            "behavior": "block"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let mut rows: Vec<AuditRow> = audit_rows(&pool, ws.id)
        .await
        .into_iter()
        .filter(|row| row.action == "budget.updated")
        .collect();
    assert_eq!(rows.len(), 2, "control: a real change IS audited");
    let second = rows.remove(1);
    assert_eq!(
        second.detail["changed"]["behavior"]["before"],
        json!("warn")
    );
    assert_eq!(
        second.detail["changed"]["behavior"]["after"],
        json!("block")
    );
    assert!(
        second.detail["changed"].get("daily_token_limit").is_none(),
        "a field that did not move must not appear in the diff, or every edit \
         reads as though it changed everything"
    );
}

/// Secure mode and the sidecar-failure policy are two different controls that
/// share one PUT, and they answer two different auditor questions: "was
/// redaction on?" and "what did this gateway do when the redactor was down?".
/// One combined row would make the second unanswerable.
#[sqlx::test]
async fn secure_mode_and_the_sidecar_failure_policy_are_audited_as_separate_controls(pool: PgPool) {
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());
    let admin = make_jwt(ws.id, ws.admin, "admin");
    assert_no_audit_yet(&pool, ws.id).await;

    let (status, body) = send(
        &app,
        "PUT",
        "/v1/secure-mode",
        &admin,
        Some(json!({
            "enabled": true,
            "level": "strict",
            "sidecar_unavailable": "degrade_with_alert"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "put secure mode: {body}");

    let secure = only_row_for(&pool, ws.id, "secure_mode.updated").await;
    assert_actor_is(&secure, &ws);
    assert_eq!(secure.target_type, "workspace");
    assert_eq!(secure.target_id, Some(ws.id));
    assert_eq!(secure.detail["changed"]["enabled"]["before"], json!(false));
    assert_eq!(secure.detail["changed"]["enabled"]["after"], json!(true));
    assert_eq!(
        secure.detail["changed"]["level"]["before"],
        json!("standard")
    );
    assert_eq!(secure.detail["changed"]["level"]["after"], json!("strict"));
    assert!(
        secure.detail["changed"]
            .get("block_on_pii_detection")
            .is_none(),
        "a field the request never mentioned did not move and must not appear"
    );

    let sidecar = only_row_for(&pool, ws.id, "sidecar_policy.updated").await;
    assert_actor_is(&sidecar, &ws);
    assert_eq!(
        sidecar.detail["before"],
        json!("block"),
        "the deployment default this workspace was inheriting"
    );
    assert_eq!(
        sidecar.detail["after"],
        json!("degrade_with_alert"),
        "the direction is the whole record: this workspace now forwards \
         prompts the PII detector never saw"
    );

    // Re-submitting the same values changes neither control, so neither is
    // recorded a second time.
    let (status, _) = send(
        &app,
        "PUT",
        "/v1/secure-mode",
        &admin,
        Some(json!({
            "enabled": true,
            "level": "strict",
            "sidecar_unavailable": "degrade_with_alert"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let after_noop = audit_rows(&pool, ws.id).await;
    assert_eq!(
        after_noop
            .iter()
            .filter(|row| row.action == "secure_mode.updated")
            .count(),
        1,
        "a PUT that moved no secure-mode field must not add a second row"
    );
    assert_eq!(
        after_noop
            .iter()
            .filter(|row| row.action == "sidecar_policy.updated")
            .count(),
        1,
        "re-submitting the same sidecar policy is not a change to it"
    );

    // POSITIVE CONTROL: moving the sidecar policy BACK is audited, so the
    // absence above is the no-op rule rather than a writer that ran once.
    let (status, _) = send(
        &app,
        "PUT",
        "/v1/secure-mode",
        &admin,
        Some(json!({"sidecar_unavailable": "block"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let mut sidecar_rows: Vec<AuditRow> = audit_rows(&pool, ws.id)
        .await
        .into_iter()
        .filter(|row| row.action == "sidecar_policy.updated")
        .collect();
    assert_eq!(sidecar_rows.len(), 2, "control: a real change IS audited");
    let back = sidecar_rows.remove(1);
    assert_eq!(back.detail["before"], json!("degrade_with_alert"));
    assert_eq!(back.detail["after"], json!("block"));
}

// ── Login ─────────────────────────────────────────────────────────────────

/// "Who logged in, and when" is the first question of every access review, and
/// it had no answer at all.
///
/// The row is written the moment the FIRST factor verifies, and it says what
/// happened NEXT rather than pretending a session was issued: a login that
/// stopped at the 2FA gate is a real event and a different one.
#[sqlx::test]
async fn a_successful_password_login_is_audited_without_the_device_or_the_address(pool: PgPool) {
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());
    assert_no_audit_yet(&pool, ws.id).await;

    // The viewer, so the login completes in one step (an admin is forced into
    // 2FA enrolment — that path is the next test).
    let (status, body) = login(&app, &ws.viewer_email, SEED_PASSWORD).await;
    assert_eq!(status, StatusCode::OK, "login: {body}");
    assert!(
        body["access_token"].is_string(),
        "premise: a session really was issued"
    );

    let row = only_row_for(&pool, ws.id, "auth.login_succeeded").await;
    assert_eq!(
        row.workspace_id, ws.id,
        "the login is recorded in the tenant that OWNS the account — there is \
         no other tenant it could honestly belong to"
    );
    assert_eq!(row.actor_user_id, Some(ws.viewer));
    assert_eq!(row.actor_email.as_deref(), Some(ws.viewer_email.as_str()));
    assert_eq!(row.actor_role.as_deref(), Some("viewer"));
    assert_eq!(row.target_user_id, Some(ws.viewer));
    assert_eq!(row.detail["method"], json!("password"));
    assert_eq!(
        row.detail["outcome"],
        json!("session_issued"),
        "a login that produced a session is a different event from one that \
         stopped at the second factor"
    );

    // PREMISE for the absence-claims: the request really did carry both
    // headers, and FU4's reduction really would have had something to store.
    assert_eq!(
        secureprompt_api::http::routes::dashboard::device::client_descriptor(CHROME_MAC_UA)
            .as_deref(),
        Some("Chrome on macOS"),
        "premise: this User-Agent reduces to a storable descriptor, so the \
         absence below is a decision and not an unrecognised client"
    );

    // NEITHER the address nor the device reaches this table. FU4 stores both on
    // the SESSION row and ERASES them when the session ends; a copy in a table
    // that is never purged would undo that erasure permanently.
    let dumped: String = sqlx::query_scalar(
        "SELECT coalesce(string_agg(t::text, ' '), '') FROM admin_audit t WHERE workspace_id = $1",
    )
    .bind(ws.id)
    .fetch_one(&pool)
    .await
    .expect("dump admin_audit as text");
    assert!(
        dumped.contains(&ws.viewer_email),
        "control: the email IS recorded and findable by this same search"
    );
    for (label, needle) in [
        ("the raw User-Agent", "Mozilla/5.0"),
        ("FU4's device reduction", "Chrome on macOS"),
        ("the client address", LOGIN_IP),
    ] {
        assert!(
            !dumped.contains(needle),
            "{label} reached the never-purged admin audit trail, undoing the \
             erasure FU4 performs when a session ends"
        );
    }
}

/// A login that stops at the 2FA gate is not a login, and a login that clears
/// it is a second event with its own facts.
#[sqlx::test]
async fn a_login_that_stops_at_the_second_factor_says_so_and_completing_it_is_its_own_event(
    pool: PgPool,
) {
    set_kms_key();
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());

    // An admin with no 2FA yet: `decide_2fa` forces enrolment before any
    // access token is minted.
    let (status, body) = login(&app, &ws.admin_email, SEED_PASSWORD).await;
    assert_eq!(status, StatusCode::ACCEPTED, "forced enrolment: {body}");
    let enrollment_token = body["enrollment_token"].as_str().expect("token").to_owned();

    let forced = only_row_for(&pool, ws.id, "auth.login_succeeded").await;
    assert_eq!(forced.actor_user_id, Some(ws.admin));
    assert_eq!(
        forced.detail["outcome"],
        json!("enrolment_required"),
        "the password verified but no session was issued; recording this as a \
         completed login would be a lie, and recording nothing would lose the \
         fact that the credentials were correct"
    );

    // Enrol, so the NEXT login is challenged rather than forced.
    let (status, enrolled) =
        send(&app, "POST", "/v1/auth/2fa/enroll", &enrollment_token, None).await;
    assert_eq!(status, StatusCode::OK, "enroll: {enrolled}");
    let secret_b32 = enrolled["secret_b32"].as_str().expect("secret").to_owned();
    let code = fresh_totp_code(&pool, ws.admin, &secret_b32).await;
    let (status, _) = send(
        &app,
        "POST",
        "/v1/auth/2fa/verify",
        &enrollment_token,
        Some(json!({"code": code})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = login(&app, &ws.admin_email, SEED_PASSWORD).await;
    assert_eq!(status, StatusCode::ACCEPTED, "challenge: {body}");
    let challenge_token = body["challenge_token"].as_str().expect("token").to_owned();

    let mut logins: Vec<AuditRow> = audit_rows(&pool, ws.id)
        .await
        .into_iter()
        .filter(|row| row.action == "auth.login_succeeded")
        .collect();
    assert_eq!(logins.len(), 2, "both logins are recorded");
    let challenged = logins.remove(1);
    assert_eq!(
        challenged.detail["outcome"],
        json!("second_factor_required"),
        "an enrolled account's password step is complete but the login is not"
    );

    // Clearing the challenge issues the session, and is its own event: the
    // challenge token carries no memory of HOW the first factor was proven, so
    // folding this into the login row would mean recording an unknown.
    let code = fresh_totp_code(&pool, ws.admin, &secret_b32).await;
    let (status, body) = send(
        &app,
        "POST",
        "/v1/auth/2fa/challenge",
        &challenge_token,
        Some(json!({"code": code})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "challenge: {body}");

    let verified = only_row_for(&pool, ws.id, "auth.second_factor_verified").await;
    assert_eq!(verified.actor_user_id, Some(ws.admin));
    assert_eq!(verified.target_user_id, Some(ws.admin));
    assert_eq!(
        verified.detail["verified_with"],
        json!("totp"),
        "a session opened with the authenticator app is a different event from \
         one opened with a printed recovery code"
    );
}

/// The deliberate gap, pinned so it stays uniform.
///
/// FU5 declined to audit failed logins and the reason is binding: `workspace_id`
/// is NOT NULL under FORCE RLS and an attempt against an unknown email has no
/// tenant, so recording only the RESOLVABLE failures would make row-absence
/// MEAN "no such account" — an enumeration oracle built out of an audit trail.
///
/// P1A ships the successful case and leaves failures to their own task. This
/// test is what keeps that honest: a wrong password for a REAL account and a
/// login for an account that does not exist must leave the trail in the SAME
/// state, so nothing can be read off the difference. If somebody later audits
/// failures for resolvable accounts only, this test goes red.
#[sqlx::test]
async fn a_failed_login_is_indistinguishable_from_a_login_for_an_account_that_does_not_exist(
    pool: PgPool,
) {
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());

    let (status, _) = login(&app, &ws.viewer_email, "not-the-seeded-password").await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "premise: a wrong password is refused"
    );
    let after_real_account: usize = audit_rows(&pool, ws.id).await.len();

    let (status, _) = login(&app, "nobody-at-all@example.invalid", SEED_PASSWORD).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "premise: an unknown email is refused the same way"
    );

    // Across EVERY tenant, not only this one — an unknown email has no tenant,
    // so a row for it could only have landed somewhere it does not belong.
    let everywhere: i64 = sqlx::query_scalar("SELECT count(*) FROM admin_audit")
        .fetch_one(&pool)
        .await
        .expect("count admin_audit");
    assert_eq!(
        i64::try_from(after_real_account).expect("small count"),
        everywhere,
        "the two refusals must leave the trail in the same state; any \
         difference is an account-existence oracle"
    );
    assert_eq!(
        everywhere, 0,
        "neither refusal may be recorded as an action that happened"
    );

    // POSITIVE CONTROL: the same call with the right password IS audited, so
    // the emptiness above is the refusal and not a writer that never runs.
    let (status, _) = login(&app, &ws.viewer_email, SEED_PASSWORD).await;
    assert_eq!(status, StatusCode::OK);
    let row = only_row_for(&pool, ws.id, "auth.login_succeeded").await;
    assert_eq!(row.actor_user_id, Some(ws.viewer));
}

/// An OIDC sign-in is a login and must be recorded as one, distinguishable
/// from a password login because the two rest on different trust.
///
/// `oidc_callback` cannot be driven without a live identity provider — it does
/// discovery, a code exchange and a userinfo fetch before it reaches any code
/// P1A touched. So this drives the shared tail the callback delegates to, one
/// line below the network work: the same function, called the same way, with
/// the same `AppState`.
#[sqlx::test]
async fn an_oidc_sign_in_is_audited_as_oidc_through_the_tail_the_callback_delegates_to(
    pool: PgPool,
) {
    let ws = seed_workspace(&pool).await;
    let (state, _app) = build_app_with_state(pool.clone());
    assert_no_audit_yet(&pool, ws.id).await;

    // The row the callback would have looked up after the identity provider
    // returned this email — read through the real repository rather than
    // constructed, so the role and 2FA state are the stored ones.
    let creds = secureprompt_api::db::user_repo::UserRepository::new(pool.clone())
        .find_by_email_with_role(&ws.viewer_email)
        .await
        .expect("lookup")
        .expect("premise: the seeded account is findable by email");

    let response = secureprompt_api::http::routes::dashboard::oidc::issue_token_or_2fa_response(
        &state,
        &creds,
        &secureprompt_api::http::routes::dashboard::device::DeviceContext::default(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "premise: this account signs in without a second factor, so the tail \
         issues a session and the audited outcome is the completed one"
    );

    let row = only_row_for(&pool, ws.id, "auth.login_succeeded").await;
    assert_eq!(row.actor_user_id, Some(ws.viewer));
    assert_eq!(
        row.detail["method"],
        json!("oidc"),
        "an identity the deployment accepted from an external provider is not \
         the same evidence as a password this product verified itself"
    );
    assert_eq!(row.detail["outcome"], json!("session_issued"));
}

// ── MR4 F5 — the OTHER direction of the coverage claim ────────────────────

/// The control-plane route surface this guard governs, relative to the repo
/// root. The dashboard router directory plus `license.rs`, which lives outside
/// it and carries two audited actions.
///
/// Deliberately NOT the data plane. `/v1/chat/completions`, `/v1/redact`,
/// `/v1/vault/stash` and the MCP routes are covered by `REQUEST_COVERAGE`,
/// which names its own absences; mixing the two planes into one guard would
/// make each half's allowlist unreadable.
const CONTROL_PLANE_ROUTE_FILES: &[&str] = &[
    "secureprompt-api/src/http/routes/dashboard",
    "secureprompt-api/src/http/routes/license.rs",
];

/// A mutating route and why the signed manifest is entitled not to mention it.
enum Coverage {
    /// It writes a control-plane row. The value is the action string, which
    /// must therefore appear in `CONTROL_COVERAGE` — the direction
    /// `the_action_vocabulary_is_pinned_in_three_places` already checks.
    Audited(&'static str),
    /// It writes nothing an auditor can read, and `CONTROL_COVERAGE` NAMES it
    /// as a gap. The value is the exact phrase that must appear in that string.
    DeclaredGap(&'static str),
}

/// Every mutating control-plane route, classified. `.0` is
/// `<file basename> <PATH> <VERB>`, which is what the scanner below produces.
///
/// This table is the second direction of the coverage claim, and it is the one
/// that was missing. `the_action_vocabulary_is_pinned_in_three_places` checks
/// that every audited action is named in the manifest; nothing checked that
/// every mutating route is either audited or named as a gap. MR4 F5 found four
/// that were neither — including `POST /v1/secure-mode/detokenize`, which
/// returns the ORIGINAL PII in the clear to any authenticated role, while the
/// manifest told the auditor the gap list was exhaustive ("named
/// individually").
const MUTATING_ROUTE_COVERAGE: &[(&str, Coverage)] = &[
    // twofactor.rs registers the same three paths on two routers (`routes()`
    // and `build_router()`), so the scanner sees each twice; the key is the
    // same and the table entry covers both.
    (
        "twofactor.rs /enroll POST",
        Coverage::Audited("two_factor.enrollment_started"),
    ),
    (
        "twofactor.rs /verify POST",
        Coverage::Audited("two_factor.enabled"),
    ),
    (
        "twofactor.rs /challenge POST",
        Coverage::Audited("auth.second_factor_verified"),
    ),
    (
        "twofactor.rs /disable POST",
        Coverage::Audited("two_factor.disabled"),
    ),
    ("keys.rs / POST", Coverage::Audited("api_key.created")),
    ("keys.rs /{id} DELETE", Coverage::Audited("api_key.revoked")),
    (
        "keys.rs /{id}/rotate POST",
        Coverage::Audited("api_key.rotated"),
    ),
    // One PUT, three audited actions: `secure_mode.updated`,
    // `sidecar_policy.updated` and `raw_capture.changed` all move through it.
    (
        "secure_mode.rs / PUT",
        Coverage::Audited("secure_mode.updated"),
    ),
    (
        "secure_mode.rs /tokenize POST",
        Coverage::DeclaredGap("tokenising content into the vault"),
    ),
    (
        "secure_mode.rs /detokenize POST",
        Coverage::DeclaredGap("RESTORING TOKENISED CONTENT TO THE ORIGINAL VALUES"),
    ),
    (
        "me.rs /profile PUT",
        Coverage::DeclaredGap("a member editing their own name or position"),
    ),
    (
        "policy_rules.rs / POST",
        Coverage::Audited("policy_rule.created"),
    ),
    (
        "policy_rules.rs /{id} PUT",
        Coverage::Audited("policy_rule.updated"),
    ),
    (
        "policy_rules.rs /{id} DELETE",
        Coverage::Audited("policy_rule.deleted"),
    ),
    (
        "policy_rules.rs /{id}/enabled PATCH",
        Coverage::Audited("policy_rule.enabled_changed"),
    ),
    (
        "policy_rules.rs /{id}/dry-run PATCH",
        Coverage::Audited("policy_rule.dry_run_changed"),
    ),
    ("users.rs / POST", Coverage::Audited("user.created")),
    (
        "users.rs /{user_id}/sessions DELETE",
        Coverage::Audited("session.revoked"),
    ),
    (
        "users.rs /{user_id}/sessions/{session_id} DELETE",
        Coverage::Audited("session.revoked"),
    ),
    (
        "auth.rs /token POST",
        Coverage::Audited("auth.login_succeeded"),
    ),
    (
        "auth.rs /refresh POST",
        Coverage::DeclaredGap("refreshing an access token"),
    ),
    (
        "auth.rs /register POST",
        Coverage::DeclaredGap("creating a workspace through public signup"),
    ),
    ("auth.rs /logout POST", Coverage::DeclaredGap("logging out")),
    (
        "budgets.rs /{id}/budgets PUT",
        Coverage::Audited("budget.updated"),
    ),
    (
        "providers.rs / POST",
        Coverage::Audited("provider_credential.created"),
    ),
    (
        "providers.rs /{id} PUT",
        Coverage::Audited("provider_credential.updated"),
    ),
    (
        "providers.rs /{id} DELETE",
        Coverage::Audited("provider_credential.deleted"),
    ),
    (
        "providers.rs /test-connection POST",
        Coverage::DeclaredGap("testing a provider connection"),
    ),
    (
        "providers.rs /{id}/test-connection POST",
        Coverage::DeclaredGap("testing a provider connection"),
    ),
    (
        "providers.rs /{id}/models POST",
        Coverage::DeclaredGap("adding, removing or excluding a provider's models"),
    ),
    (
        "providers.rs /{id}/models/sync POST",
        Coverage::DeclaredGap("adding, removing or excluding a provider's models"),
    ),
    (
        "providers.rs /{id}/models/bulk-delete POST",
        Coverage::DeclaredGap("adding, removing or excluding a provider's models"),
    ),
    (
        "providers.rs /{id}/models/{name} DELETE",
        Coverage::DeclaredGap("adding, removing or excluding a provider's models"),
    ),
    (
        "audit_export.rs / POST",
        Coverage::DeclaredGap("requesting a signed export"),
    ),
    ("license.rs / PUT", Coverage::Audited("license.activated")),
    ("license.rs / DELETE", Coverage::Audited("license.cleared")),
];

/// Pull `(path, verbs)` out of every `.route(...)` call in `source`.
///
/// A line-oriented scan will not do: `http/mod.rs` and several route files wrap
/// `.route(` across three lines, and a scanner that silently sees fewer routes
/// than exist is the shape of guard this whole review is about. So this walks
/// to the matching close paren and takes the first string literal as the path
/// and every `post(`/`put(`/`patch(`/`delete(` inside as a verb.
fn routes_in(source: &str) -> Vec<(String, Vec<&'static str>)> {
    let mut found = Vec::new();
    let bytes: Vec<char> = source.chars().collect();
    let mut idx = 0usize;
    let needle: Vec<char> = ".route(".chars().collect();
    while idx + needle.len() <= bytes.len() {
        if bytes[idx..idx + needle.len()] != needle[..] {
            idx += 1;
            continue;
        }
        let mut depth = 1i32;
        let mut cursor = idx + needle.len();
        let start = cursor;
        while cursor < bytes.len() && depth > 0 {
            match bytes[cursor] {
                '(' => depth += 1,
                ')' => depth -= 1,
                _ => {}
            }
            cursor += 1;
        }
        let call: String = bytes[start..cursor.saturating_sub(1)].iter().collect();
        idx = cursor;

        let Some(open) = call.find('"') else { continue };
        let Some(close) = call[open + 1..].find('"') else {
            continue;
        };
        let path = call[open + 1..open + 1 + close].to_owned();

        let mut verbs = Vec::new();
        for (frag, verb) in [
            ("post(", "POST"),
            ("put(", "PUT"),
            ("patch(", "PATCH"),
            ("delete(", "DELETE"),
        ] {
            // `axum::routing::delete(` also ends in `delete(`; both match.
            if call.contains(frag) {
                verbs.push(verb);
            }
        }
        if !verbs.is_empty() {
            found.push((path, verbs));
        }
    }
    found
}

fn control_plane_route_sources() -> Vec<(String, String)> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("secureprompt-api must have a parent")
        .to_path_buf();
    let mut sources = Vec::new();
    for entry in CONTROL_PLANE_ROUTE_FILES {
        let path = root.join(entry);
        if path.is_dir() {
            let mut files: Vec<_> = std::fs::read_dir(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
                .filter_map(Result::ok)
                .map(|d| d.path())
                .filter(|p| p.extension().is_some_and(|e| e == "rs"))
                .collect();
            files.sort();
            for file in files {
                let name = file
                    .file_name()
                    .and_then(|n| n.to_str())
                    .expect("utf-8 file name")
                    .to_owned();
                if name == "mod.rs" {
                    continue;
                }
                sources.push((
                    name,
                    std::fs::read_to_string(&file)
                        .unwrap_or_else(|e| panic!("read {}: {e}", file.display())),
                ));
            }
        } else {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .expect("utf-8 file name")
                .to_owned();
            sources.push((
                name,
                std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("read {}: {e}", path.display())),
            ));
        }
    }
    sources
}

/// MR4 F5 — every mutating control-plane route is either audited or NAMED in
/// the signed manifest as a gap, and the phrase that names it really is in
/// there.
///
/// `CONTROL_COVERAGE` is copied verbatim into every signed compliance manifest
/// and tells the auditor its gap list is exhaustive: "the remaining gaps are
/// named individually rather than summarised". Until this test, that half was a
/// convention. `the_action_vocabulary_is_pinned_in_three_places` only checks
/// `ALL ⊆ CONTROL_COVERAGE` — that an action the product DOES audit is
/// mentioned. Nothing checked that a route the product does NOT audit is
/// mentioned, which is the direction an auditor actually relies on.
///
/// Adding a mutating route now fails this test until it is classified, and
/// classifying it as a gap fails until `CONTROL_COVERAGE` says so.
#[test]
fn every_mutating_control_plane_route_is_audited_or_named_as_a_gap() {
    use secureprompt_common::audit_export::CONTROL_COVERAGE;

    let table: BTreeMap<&str, &Coverage> = MUTATING_ROUTE_COVERAGE
        .iter()
        .map(|(key, coverage)| (*key, coverage))
        .collect();
    assert_eq!(
        table.len(),
        MUTATING_ROUTE_COVERAGE.len(),
        "duplicate key in MUTATING_ROUTE_COVERAGE; one entry is shadowing another"
    );

    let mut scanned: BTreeSet<String> = BTreeSet::new();
    for (file, source) in control_plane_route_sources() {
        for (path, verbs) in routes_in(&source) {
            for verb in verbs {
                scanned.insert(format!("{file} {path} {verb}"));
            }
        }
    }

    // PREMISE: the scanner found a route surface. A parser that silently
    // matched nothing would make every assertion below vacuously true — the
    // exact failure this test exists to prevent elsewhere.
    assert!(
        scanned.len() >= 25,
        "premise: the scanner must find the control-plane route surface, found \
         {} routes: {scanned:?}",
        scanned.len()
    );

    let unclassified: Vec<&String> = scanned
        .iter()
        .filter(|key| !table.contains_key(key.as_str()))
        .collect();
    assert!(
        unclassified.is_empty(),
        "these mutating control-plane routes are neither audited nor named as a \
         gap in `CONTROL_COVERAGE`, the text copied into every signed \
         compliance manifest. The manifest tells the auditor its gap list is \
         exhaustive, so an unclassified route is the manifest making a false \
         statement. Either audit it, or name it in `CONTROL_COVERAGE` and add \
         it here: {unclassified:?}"
    );

    // A gap is only declared if the manifest ACTUALLY says so. Without this the
    // table would be a second place to write prose that nothing compares.
    let mut undeclared = Vec::new();
    for (key, coverage) in MUTATING_ROUTE_COVERAGE {
        match coverage {
            Coverage::Audited(action) => {
                assert!(
                    CONTROL_COVERAGE.contains(action),
                    "{key} is classified as audited via `{action}`, which the \
                     manifest does not name"
                );
            }
            Coverage::DeclaredGap(phrase) => {
                if !CONTROL_COVERAGE.contains(phrase) {
                    undeclared.push((key, phrase));
                }
            }
        }
    }
    assert!(
        undeclared.is_empty(),
        "these routes are classified as DECLARED gaps but `CONTROL_COVERAGE` \
         does not contain the phrase that names them: {undeclared:?}"
    );

    // The table may not name a route that does not exist. MR4 F5's other half:
    // the gap list claimed "reassigning an API key to a different member",
    // which `keys.rs` has never had a route for — a gap describing an
    // operation the product does not have.
    let phantom: Vec<&&str> = table
        .keys()
        .filter(|key| !scanned.contains(**key))
        .collect();
    assert!(
        phantom.is_empty(),
        "MUTATING_ROUTE_COVERAGE names routes that do not exist. A gap list \
         that describes operations the product does not have is as misleading \
         as one that omits operations it does: {phantom:?}"
    );

    assert!(
        !CONTROL_COVERAGE.contains("reassigning an API key"),
        "`CONTROL_COVERAGE` still names API-key reassignment as a gap. \
         `keys.rs` exposes POST /, DELETE /{{id}} and POST /{{id}}/rotate — \
         there is no reassignment endpoint, so that gap describes nothing"
    );
}
