//! Phase 5 / Plan 05-04 — Keys, Providers, PolicyRules integration tests.
//!
//! These tests use `#[sqlx::test]` for a fresh per-test Postgres database.
//! A real deadpool-redis pool is used (REDIS_URL env, default redis://localhost:6379).
//!
//! Test matrix:
//!   keys_one_time_reveal     — POST returns api_key; GET list has no api_key field
//!   keys_role_gate           — viewer → 403 on POST
//!   keys_rls_isolation       — workspace B cannot see workspace A keys
//!   providers_encryption     — POST "sk-test" → stored value differs; GET has no ciphertext
//!   providers_role_gate      — viewer → 403 on POST
//!   policy_crud_happy        — POST/PUT/PATCH/DELETE happy path
//!   policy_priority_conflict — same priority → 409
//!   policy_role_gate         — viewer POST → 403
//!   no_dangerous_html_gate   — bash script exits 0

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use secureprompt_api::{app_state::AppState, http::build_router, ml_sidecar::MlSidecarClient};
use secureprompt_common::config::{
    AppConfig, ClickhouseConfig, DatabaseConfig, JwtConfig, LicenseConfig,
    RedisConfig as AppRedisConfig, ServerConfig, TelemetryConfig,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

use super::fixtures::seed_two_workspaces;

// ── Harness ───────────────────────────────────────────────────────────────────

const TEST_JWT_SECRET: &str = "dashboard-settings-test-secret";

fn redis_url() -> String {
    std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".into())
}

fn test_config() -> AppConfig {
    AppConfig {
        database: DatabaseConfig {
            url: "postgres://unused".into(),
            max_connections: 1,
        },
        redis: AppRedisConfig {
            url: redis_url(),
            max_connections: 8,
        },
        telemetry: TelemetryConfig {
            otel_enabled: false,
            prometheus_enabled: false,
            log_level: "info".into(),
        },
        server: ServerConfig {
            host: "127.0.0.1".into(),
            port: 0,
        },
        clickhouse: ClickhouseConfig {
            url: "http://localhost:8123".into(),
            database: "default".into(),
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

fn build_app(pool: PgPool) -> (AppState, Router) {
    let config = test_config();
    let ml = Arc::new(MlSidecarClient::new(String::new(), 100));
    let state = AppState::new(
        pool,
        config,
        ml,
        Arc::new(secureprompt_api::license::LicenseState::unlicensed()),
    );
    let router = build_router(state.clone());
    (state, router)
}

async fn read_json(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let value = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).unwrap_or(Value::Null)
    };
    (status, value)
}

/// Issue a JWT access token for the given workspace + role using the test secret.
fn mint_jwt(workspace_id: Uuid, user_id: Uuid, role: &str) -> String {
    use chrono::{Duration, Utc};
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct Claims {
        sub: Uuid,
        ws: Uuid,
        role: String,
        iat: i64,
        exp: i64,
        jti: String,
    }

    let now = Utc::now();
    let claims = Claims {
        sub: user_id,
        ws: workspace_id,
        role: role.to_owned(),
        iat: now.timestamp(),
        exp: (now + Duration::hours(1)).timestamp(),
        jti: Uuid::new_v4().to_string(),
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(TEST_JWT_SECRET.as_bytes()),
    )
    .expect("mint test JWT")
}

async fn get_json(router: &Router, path: &str, token: &str) -> (StatusCode, Value) {
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(path)
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    read_json(resp).await
}

async fn post_json(router: &Router, path: &str, body: Value, token: &str) -> (StatusCode, Value) {
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    read_json(resp).await
}

async fn delete_req(router: &Router, path: &str, token: &str) -> StatusCode {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(path)
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

async fn patch_json(
    router: &Router,
    path: &str,
    body: Value,
    token: &str,
) -> (StatusCode, Value) {
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(path)
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    read_json(resp).await
}

async fn put_json(router: &Router, path: &str, body: Value, token: &str) -> (StatusCode, Value) {
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(path)
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    read_json(resp).await
}

// ── keys tests ────────────────────────────────────────────────────────────────

/// POST returns `api_key` (plaintext); GET list has no `api_key` field.
#[sqlx::test]
async fn keys_one_time_reveal(pool: PgPool) {
    let seeds = seed_two_workspaces(&pool).await.unwrap();
    let (_, router) = build_app(pool);

    let admin_token = mint_jwt(seeds.workspace_a, seeds.admin_a, "admin");

    // POST — create key
    let (status, body) =
        post_json(&router, "/v1/keys", json!({"name": "test-key"}), &admin_token).await;
    assert_eq!(status, StatusCode::CREATED, "create key: {body}");
    assert!(
        body["api_key"].is_string(),
        "POST response must include api_key"
    );
    let key_str = body["api_key"].as_str().unwrap();
    assert!(key_str.starts_with("sp_"), "api_key must start with 'sp_'");
    assert_eq!(key_str.len(), 51, "api_key must be 51 chars (sp_ + 48)");

    // GET list — must NOT include api_key
    let (status, list) = get_json(&router, "/v1/keys", &admin_token).await;
    assert_eq!(status, StatusCode::OK, "list keys: {list}");
    for item in list.as_array().unwrap() {
        assert!(
            item.get("api_key").is_none(),
            "GET list must NOT include api_key field"
        );
    }
}

/// Viewer → 403 on POST /v1/keys.
#[sqlx::test]
async fn keys_role_gate(pool: PgPool) {
    let seeds = seed_two_workspaces(&pool).await.unwrap();
    let (_, router) = build_app(pool);

    let viewer_token = mint_jwt(seeds.workspace_a, seeds.viewer_a, "viewer");
    let (status, _) = post_json(
        &router,
        "/v1/keys",
        json!({"name": "forbidden"}),
        &viewer_token,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "viewer must be forbidden");
}

/// Workspace B cannot see workspace A keys (RLS isolation).
#[sqlx::test]
async fn keys_rls_isolation(pool: PgPool) {
    let seeds = seed_two_workspaces(&pool).await.unwrap();
    let (_, router) = build_app(pool);

    // Create an extra key in workspace A
    let admin_a_token = mint_jwt(seeds.workspace_a, seeds.admin_a, "admin");
    let (status, _) =
        post_json(&router, "/v1/keys", json!({"name": "ws-a-key"}), &admin_a_token).await;
    assert_eq!(status, StatusCode::CREATED);

    // Workspace B lists keys — should only see its own (fixture seeded 1 key each)
    let admin_b_token = mint_jwt(seeds.workspace_b, seeds.admin_b, "admin");
    let (status, list) = get_json(&router, "/v1/keys", &admin_b_token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        list.as_array().unwrap().len(),
        1,
        "workspace B should see only its own 1 seeded key"
    );
}

// ── providers tests ───────────────────────────────────────────────────────────

/// POST with credential → stored value is encrypted; GET has no ciphertext field.
#[sqlx::test]
async fn providers_encryption(pool: PgPool) {
    // Set a test provider key distinct from JWT secret.
    std::env::set_var(
        "SECUREPROMPT_PROVIDER_KEY",
        "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
    );

    let seeds = seed_two_workspaces(&pool).await.unwrap();
    let (state, router) = build_app(pool);
    let admin_token = mint_jwt(seeds.workspace_a, seeds.admin_a, "admin");
    let plaintext = "sk-test-secret-value";

    let (status, body) = post_json(
        &router,
        "/v1/providers",
        json!({"name": "openai-test", "provider_type": "openai", "credential": plaintext}),
        &admin_token,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create provider: {body}");

    // Response must NOT contain plaintext or ciphertext field
    assert!(
        !body.to_string().contains(plaintext),
        "POST response must not include plaintext credential"
    );
    assert!(
        body["has_credential"].as_bool().unwrap_or(false),
        "has_credential must be true"
    );
    assert!(
        body.get("encrypted_credential").is_none(),
        "ciphertext must not appear in response"
    );

    // Verify DB row is encrypted (not plaintext)
    let provider_id = Uuid::parse_str(body["id"].as_str().unwrap()).unwrap();
    let repo =
        secureprompt_api::db::provider_repo::ProviderRepository::new(state.db.clone());
    let rows = repo
        .list_providers(secureprompt_common::types::WorkspaceId(seeds.workspace_a))
        .await
        .unwrap();
    let stored = rows
        .iter()
        .find(|r| r.id == provider_id)
        .and_then(|r| r.encrypted_credential.as_deref())
        .unwrap_or("");
    assert_ne!(stored, plaintext, "stored value must not equal plaintext");
    assert!(!stored.is_empty(), "stored encrypted credential must not be empty");

    // GET list — no ciphertext
    let (status, list) = get_json(&router, "/v1/providers", &admin_token).await;
    assert_eq!(status, StatusCode::OK);
    for item in list.as_array().unwrap() {
        assert!(
            item.get("encrypted_credential").is_none(),
            "GET response must not include encrypted_credential"
        );
    }

    std::env::remove_var("SECUREPROMPT_PROVIDER_KEY");
}

/// Viewer → 403 on POST /v1/providers.
#[sqlx::test]
async fn providers_role_gate(pool: PgPool) {
    let seeds = seed_two_workspaces(&pool).await.unwrap();
    let (_, router) = build_app(pool);
    let viewer_token = mint_jwt(seeds.workspace_a, seeds.viewer_a, "viewer");

    let (status, _) = post_json(
        &router,
        "/v1/providers",
        json!({"name": "x", "provider_type": "openai"}),
        &viewer_token,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ── policy tests ──────────────────────────────────────────────────────────────

/// POST/PUT/PATCH/DELETE happy path.
#[sqlx::test]
async fn policy_crud_happy(pool: PgPool) {
    let seeds = seed_two_workspaces(&pool).await.unwrap();
    let (_, router) = build_app(pool);
    let admin_token = mint_jwt(seeds.workspace_a, seeds.admin_a, "admin");

    // POST
    let (status, body) = post_json(
        &router,
        "/v1/policy-rules",
        json!({
            "name": "block-ssn",
            "priority": 10,
            "conditions": [{"field": "content", "op": "contains", "value": "SSN"}],
            "action": "deny",
            "enabled": true,
            "dry_run": false
        }),
        &admin_token,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create rule: {body}");
    let rule_id = body["id"].as_str().unwrap().to_owned();
    assert_eq!(body["action"].as_str().unwrap(), "deny");
    assert!(body["enabled"].as_bool().unwrap());

    // PUT
    let (status, updated) = put_json(
        &router,
        &format!("/v1/policy-rules/{rule_id}"),
        json!({"name": "block-ssn-updated", "priority": 10, "action": "redact",
               "enabled": true, "dry_run": false}),
        &admin_token,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "update rule: {updated}");
    assert_eq!(updated["action"].as_str().unwrap(), "redact");

    // PATCH enabled → false
    let (status, patched) = patch_json(
        &router,
        &format!("/v1/policy-rules/{rule_id}/enabled"),
        json!({"value": false}),
        &admin_token,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "patch enabled: {patched}");
    assert!(!patched["enabled"].as_bool().unwrap());

    // PATCH dry_run → true
    let (status, patched) = patch_json(
        &router,
        &format!("/v1/policy-rules/{rule_id}/dry-run"),
        json!({"value": true}),
        &admin_token,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "patch dry_run: {patched}");
    assert!(patched["dry_run"].as_bool().unwrap());

    // DELETE
    let status = delete_req(
        &router,
        &format!("/v1/policy-rules/{rule_id}"),
        &admin_token,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "delete rule");

    // GET after delete → 404
    let (status, _) = get_json(
        &router,
        &format!("/v1/policy-rules/{rule_id}"),
        &admin_token,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Same priority → 409 with `code: "priority_conflict"`.
#[sqlx::test]
async fn policy_priority_conflict(pool: PgPool) {
    let seeds = seed_two_workspaces(&pool).await.unwrap();
    let (_, router) = build_app(pool);
    let admin_token = mint_jwt(seeds.workspace_a, seeds.admin_a, "admin");

    let (status, _) = post_json(
        &router,
        "/v1/policy-rules",
        json!({"name": "rule-1", "priority": 50, "action": "deny"}),
        &admin_token,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = post_json(
        &router,
        "/v1/policy-rules",
        json!({"name": "rule-2", "priority": 50, "action": "allow"}),
        &admin_token,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "duplicate priority must be 409: {body}"
    );
    assert_eq!(body["code"].as_str().unwrap_or(""), "priority_conflict");
}

/// Viewer POST → 403.
#[sqlx::test]
async fn policy_role_gate(pool: PgPool) {
    let seeds = seed_two_workspaces(&pool).await.unwrap();
    let (_, router) = build_app(pool);
    let viewer_token = mint_jwt(seeds.workspace_a, seeds.viewer_a, "viewer");

    let (status, _) = post_json(
        &router,
        "/v1/policy-rules",
        json!({"name": "x", "priority": 1, "action": "deny"}),
        &viewer_token,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ── CI gate tests ─────────────────────────────────────────────────────────────

/// Verify check-no-dangerous-html.sh exits 0 (no violations in our src).
#[test]
fn no_dangerous_html_gate() {
    let script = std::path::Path::new("scripts/ci/check-no-dangerous-html.sh");
    if !script.exists() {
        eprintln!("SKIP: check-no-dangerous-html.sh not found");
        return;
    }

    match std::process::Command::new("bash").arg(script).output() {
        Ok(out) => {
            assert!(
                out.status.success(),
                "check-no-dangerous-html.sh failed:\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        Err(e) => {
            eprintln!("SKIP: could not run bash: {e}");
        }
    }
}
