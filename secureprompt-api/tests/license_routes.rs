//! Task 3 — `GET/PUT/DELETE /v1/license` integration tests.
//!
//! Each test spins up a fresh Postgres (via `#[sqlx::test]`) and builds the app
//! with a test vendor keypair wired into `config.license.pubkey_b64` so that
//! `effective_vendor_pubkey` (which prefers the build-pin, absent in tests) falls
//! through to the runtime value we control.

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use secureprompt_api::{app_state::AppState, http::build_router, ml_sidecar::MlSidecarClient};
use secureprompt_common::config::{
    AppConfig, ClickhouseConfig, DatabaseConfig, JwtConfig, LicenseConfig,
    RedisConfig as AppRedisConfig, ServerConfig, TelemetryConfig,
};
use serde_json::{json, Value};
use sp_license::{
    envelope_to_token,
    sign::sign_license,
    token::{
        Customer, Deployment, Entitlements, Integrity, License, ModelGrant,
    },
};
use sqlx::PgPool;
use std::collections::BTreeMap;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

// ── Harness ───────────────────────────────────────────────────────────────────

const TEST_JWT_SECRET: &str = "license-routes-test-secret";

fn redis_url() -> String {
    std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".into())
}

/// Build a test app with a known vendor signing keypair wired in via
/// `config.license.pubkey_b64`. Returns `(AppState, Router, SigningKey)`.
///
/// The `SigningKey` is the keypair you sign test tokens with; the app verifies
/// against the matching `VerifyingKey` extracted from `pubkey_b64`.
fn build_app_with_keys(pool: PgPool, sk: &SigningKey) -> (AppState, Router) {
    let vk_b64 = B64.encode(sk.verifying_key().to_bytes());
    let config = AppConfig {
        database: DatabaseConfig {
            url: "postgres://unused".into(),
            max_connections: 1,
        },
        redis: AppRedisConfig {
            url: redis_url(),
            max_connections: 4,
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
        license: LicenseConfig {
            pubkey_b64: vk_b64,
            license_token: String::new(),
            attest_kek_b64: String::new(),
            internal_token: String::new(),
            recheck_secs: 3600,
            license_server_url: None,
            revocation_check_secs: 3600,
            attestation_interval_secs: 3600,
        },
    };
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

/// Build a test app with a known vendor signing keypair, a real internal token,
/// and a custom ML sidecar base URL (for mock-sidecar tests).
fn build_app_with_sidecar(
    pool: PgPool,
    sk: &SigningKey,
    ml_base_url: &str,
    internal_token: &str,
) -> (AppState, Router) {
    let vk_b64 = B64.encode(sk.verifying_key().to_bytes());
    let config = AppConfig {
        database: DatabaseConfig {
            url: "postgres://unused".into(),
            max_connections: 1,
        },
        redis: AppRedisConfig {
            url: redis_url(),
            max_connections: 4,
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
        license: LicenseConfig {
            pubkey_b64: vk_b64,
            license_token: String::new(),
            attest_kek_b64: String::new(),
            internal_token: internal_token.to_owned(),
            recheck_secs: 3600,
            license_server_url: None,
            revocation_check_secs: 3600,
            attestation_interval_secs: 3600,
        },
    };
    let ml = Arc::new(MlSidecarClient::new(ml_base_url.to_owned(), 5000));
    let state = AppState::new(
        pool,
        config,
        ml,
        Arc::new(secureprompt_api::license::LicenseState::unlicensed()),
    );
    let router = build_router(state.clone());
    (state, router)
}

/// Mint a compact license token valid from now until `2099-01-01` using the
/// given signing key.
fn mint_valid_token(sk: &SigningKey, customer_name: &str, features: &[&str]) -> String {
    let lic = License {
        v: 1,
        lic_id: Uuid::new_v4().to_string(),
        customer: Customer {
            id: "test-customer".into(),
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
            features: features.iter().map(|s| s.to_string()).collect(),
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
    let env = sign_license(&lic, sk).expect("sign license");
    envelope_to_token(&env).expect("encode token")
}

/// Issue a HS256 JWT for the given workspace + user + role using the test secret.
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

async fn read_json(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let value: Value = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).unwrap_or(Value::Null)
    };
    (status, value)
}

async fn get_req(router: &Router, path: &str, token: &str) -> axum::response::Response {
    router
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
        .unwrap()
}

async fn put_req(router: &Router, path: &str, body: Value, token: &str) -> axum::response::Response {
    router
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
        .unwrap()
}

async fn delete_req(router: &Router, path: &str, token: &str) -> axum::response::Response {
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
}

/// Seed a workspace with a single admin user. Returns (workspace_id, user_id).
async fn seed_admin(pool: &PgPool) -> sqlx::Result<(Uuid, Uuid)> {
    use argon2::{
        password_hash::{rand_core::OsRng as ArgonOsRng, PasswordHasher, SaltString},
        Argon2,
    };

    let workspace_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO workspaces (id, name, created_at, updated_at) VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(workspace_id)
    .bind("test-ws")
    .execute(pool)
    .await?;

    let salt = SaltString::generate(&mut ArgonOsRng);
    let hash = Argon2::default()
        .hash_password(b"test-pw", &salt)
        .unwrap()
        .to_string();

    sqlx::query(
        "INSERT INTO users (id, workspace_id, email, password_hash, role, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, NOW(), NOW())",
    )
    .bind(user_id)
    .bind(workspace_id)
    .bind(format!("admin-{}@example.com", workspace_id))
    .bind(&hash)
    .bind("admin")
    .execute(pool)
    .await?;

    Ok((workspace_id, user_id))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// `GET /v1/license` as admin → 200 with `status` and `source` fields.
#[sqlx::test]
async fn get_license_returns_status_and_source(pool: PgPool) -> sqlx::Result<()> {
    let sk = SigningKey::generate(&mut OsRng);
    let (ws, user) = seed_admin(&pool).await?;
    let (_, router) = build_app_with_keys(pool, &sk);
    let jwt = mint_jwt(ws, user, "admin");

    let resp = get_req(&router, "/v1/license", &jwt).await;
    let (status, body) = read_json(resp).await;

    assert_eq!(status, StatusCode::OK, "body={body}");
    assert!(body["status"].is_string(), "must have status field: {body}");
    assert!(body["source"].is_string(), "must have source field: {body}");
    // Fresh pool, no DB row, no env token → source="none"
    assert_eq!(body["source"], "none", "body={body}");
    Ok(())
}

/// Non-admin caller → 403.
#[sqlx::test]
async fn get_license_non_admin_403(pool: PgPool) -> sqlx::Result<()> {
    let sk = SigningKey::generate(&mut OsRng);
    let (ws, _) = seed_admin(&pool).await?;
    let (_, router) = build_app_with_keys(pool, &sk);

    // Mint a viewer token (user doesn't need to exist in DB for JWT validation)
    let viewer_id = Uuid::new_v4();
    let jwt = mint_jwt(ws, viewer_id, "viewer");

    // GET is admin-gated too (same gate as PUT/DELETE) — a viewer must get 403.
    let resp = get_req(&router, "/v1/license", &jwt).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "viewer GET must be 403");

    // PUT with viewer → 403
    let valid_token = mint_valid_token(&sk, "TestCo", &[]);
    let put_resp = put_req(
        &router,
        "/v1/license",
        json!({"token": valid_token}),
        &jwt,
    )
    .await;
    assert_eq!(put_resp.status(), StatusCode::FORBIDDEN, "viewer PUT must be 403");

    // DELETE with viewer → 403
    let del_resp = delete_req(&router, "/v1/license", &jwt).await;
    assert_eq!(del_resp.status(), StatusCode::FORBIDDEN, "viewer DELETE must be 403");
    Ok(())
}

/// `PUT /v1/license` with a valid signed token → 200; subsequent GET shows
/// `status: "Valid"`, `source: "db"`; the row is present in the DB.
#[sqlx::test]
async fn put_valid_token_activates_license(pool: PgPool) -> sqlx::Result<()> {
    let sk = SigningKey::generate(&mut OsRng);
    let (ws, user) = seed_admin(&pool).await?;
    let (state, router) = build_app_with_keys(pool.clone(), &sk);
    let jwt = mint_jwt(ws, user, "admin");

    let compact_token = mint_valid_token(&sk, "Acme Corp", &["pii.uz"]);

    let resp = put_req(
        &router,
        "/v1/license",
        json!({"token": compact_token}),
        &jwt,
    )
    .await;
    let (status, body) = read_json(resp).await;
    assert_eq!(status, StatusCode::OK, "PUT must return 200: {body}");
    assert_eq!(body["status"], "Valid", "license must be Valid: {body}");
    assert_eq!(body["source"], "db", "source must be db: {body}");
    assert_eq!(body["customer_name"], "Acme Corp");

    // Verify DB row was written.
    let row = secureprompt_api::db::license_repo::get(&pool).await?;
    assert!(row.is_some(), "DB row must exist after PUT");
    assert_eq!(row.unwrap().token, compact_token);

    // Verify in-memory state was live-swapped.
    assert_eq!(
        state.license.effective_status(),
        secureprompt_api::license::LicenseStatus::Valid
    );

    // Subsequent GET also shows valid+db.
    let get_resp = get_req(&router, "/v1/license", &jwt).await;
    let (get_status, get_body) = read_json(get_resp).await;
    assert_eq!(get_status, StatusCode::OK);
    assert_eq!(get_body["status"], "Valid");
    assert_eq!(get_body["source"], "db");

    Ok(())
}

/// `PUT /v1/license` with a garbage token → 400; no DB row written; state unchanged.
#[sqlx::test]
async fn put_garbage_token_returns_400_no_state_change(pool: PgPool) -> sqlx::Result<()> {
    let sk = SigningKey::generate(&mut OsRng);
    let (ws, user) = seed_admin(&pool).await?;
    let (state, router) = build_app_with_keys(pool.clone(), &sk);
    let jwt = mint_jwt(ws, user, "admin");

    let resp = put_req(
        &router,
        "/v1/license",
        json!({"token": "this.is.garbage"}),
        &jwt,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "garbage token must → 400");

    // No DB row.
    let row = secureprompt_api::db::license_repo::get(&pool).await?;
    assert!(row.is_none(), "no row must exist after bad PUT");

    // State still Unlicensed.
    assert_eq!(
        state.license.effective_status(),
        secureprompt_api::license::LicenseStatus::Unlicensed
    );
    Ok(())
}

/// `PUT` with a token signed by the WRONG key → 400; no state change.
#[sqlx::test]
async fn put_wrong_key_token_returns_400(pool: PgPool) -> sqlx::Result<()> {
    let sk = SigningKey::generate(&mut OsRng);
    let other_sk = SigningKey::generate(&mut OsRng); // signed with a different key
    let (ws, user) = seed_admin(&pool).await?;
    let (_, router) = build_app_with_keys(pool.clone(), &sk); // app configured with `sk`
    let jwt = mint_jwt(ws, user, "admin");

    let wrong_token = mint_valid_token(&other_sk, "Evil Corp", &[]); // signed with `other_sk`

    let resp = put_req(
        &router,
        "/v1/license",
        json!({"token": wrong_token}),
        &jwt,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "wrong key must → 400");

    let row = secureprompt_api::db::license_repo::get(&pool).await?;
    assert!(row.is_none(), "no DB row after wrong-key PUT");
    Ok(())
}

/// `DELETE /v1/license` removes the DB row; GET reverts to `source: "none"`.
#[sqlx::test]
async fn delete_reverts_source(pool: PgPool) -> sqlx::Result<()> {
    let sk = SigningKey::generate(&mut OsRng);
    let (ws, user) = seed_admin(&pool).await?;
    let (_, router) = build_app_with_keys(pool.clone(), &sk);
    let jwt = mint_jwt(ws, user, "admin");

    // First activate.
    let compact_token = mint_valid_token(&sk, "Acme Corp", &[]);
    let put_resp = put_req(
        &router,
        "/v1/license",
        json!({"token": compact_token}),
        &jwt,
    )
    .await;
    assert_eq!(put_resp.status(), StatusCode::OK);

    // Verify DB row exists.
    assert!(secureprompt_api::db::license_repo::get(&pool).await?.is_some());

    // DELETE.
    let del_resp = delete_req(&router, "/v1/license", &jwt).await;
    let (del_status, del_body) = read_json(del_resp).await;
    assert_eq!(del_status, StatusCode::OK, "DELETE must return 200: {del_body}");

    // DB row gone.
    assert!(secureprompt_api::db::license_repo::get(&pool).await?.is_none(), "DB row must be gone after DELETE");

    // Subsequent GET → source reverts.
    let get_resp = get_req(&router, "/v1/license", &jwt).await;
    let (_, get_body) = read_json(get_resp).await;
    // No env token in test config → "none".
    assert_eq!(get_body["source"], "none", "source must revert to none: {get_body}");
    Ok(())
}

/// Unauthenticated request → 401 (the JWT middleware fires before RBAC).
#[sqlx::test]
async fn unauthenticated_401(pool: PgPool) {
    let sk = SigningKey::generate(&mut OsRng);
    let (_, router) = build_app_with_keys(pool, &sk);

    let resp = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/license")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// Mint a compact license token with a specific wrapped_key blob and lic_id.
/// Returns `(compact_token, lic_id)`.
fn mint_valid_token_with_wrapped_key(sk: &SigningKey, wrapped_key: &str) -> (String, String) {
    let lic_id = Uuid::new_v4().to_string();
    let lic = License {
        v: 1,
        lic_id: lic_id.clone(),
        customer: Customer {
            id: "test-customer".into(),
            name: "Acme Corp".into(),
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
            features: vec![],
            components: vec![],
            revalidate_soft_secs: None,
            revalidate_hard_secs: None,
        },
        model: ModelGrant {
            wrapped_key: wrapped_key.to_owned(),
            models: vec![],
        },
        integrity: Integrity {
            image_digests: BTreeMap::new(),
        },
        iss: "sp-admin".into(),
        iat: "2000-01-01T00:00:00Z".into(),
    };
    let env = sign_license(&lic, sk).expect("sign license");
    let token = envelope_to_token(&env).expect("encode token");
    (token, lic_id)
}

/// Task 4: activating a Valid license relays `{wrapped_key, lic_id}` to the
/// sidecar — NOT plaintext and NOT `key_hex`. The gateway must never unwrap
/// the model blob; it forwards the opaque ciphertext as-is.
#[sqlx::test]
async fn activation_relays_wrapped_blob_not_plaintext(pool: PgPool) {
    use axum::{routing::post, Json as AxumJson};
    use std::sync::Mutex;
    use tokio::net::TcpListener as TokioTcpListener;

    // 1. Spawn a tiny mock sidecar that captures the POST body and returns 200.
    let captured_body: Arc<Mutex<Option<serde_json::Value>>> = Arc::new(Mutex::new(None));
    let captured_clone = Arc::clone(&captured_body);

    let mock_app = axum::Router::new().route(
        "/internal/model-key",
        post(move |AxumJson(body): AxumJson<serde_json::Value>| {
            let cap = Arc::clone(&captured_clone);
            async move {
                *cap.lock().unwrap() = Some(body);
                axum::http::StatusCode::OK
            }
        }),
    );

    let mock_listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_addr = mock_listener.local_addr().unwrap();
    let mock_base_url = format!("http://{mock_addr}");

    tokio::spawn(async move {
        axum::serve(mock_listener, mock_app).await.unwrap();
    });

    // Give the mock a moment to start.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // 2. Build the gateway app pointing its ML sidecar at the mock.
    let sk = SigningKey::generate(&mut OsRng);
    let (ws, user) = seed_admin(&pool).await.unwrap();
    let (_, router) = build_app_with_sidecar(pool.clone(), &sk, &mock_base_url, "test-token");
    let jwt = mint_jwt(ws, user, "admin");

    // 3. Mint a Valid token whose model.wrapped_key is a known opaque blob.
    let expected_wrapped = "c2VjcmV0LXdyYXBwZWQtYmxvYi1vcGFxdWU="; // base64 of some bytes
    let (compact_token, expected_lic_id) = mint_valid_token_with_wrapped_key(&sk, expected_wrapped);

    // PUT /v1/license to activate and trigger the relay.
    let resp = put_req(
        &router,
        "/v1/license",
        json!({"token": compact_token}),
        &jwt,
    )
    .await;
    let (status, body) = read_json(resp).await;
    assert_eq!(status, StatusCode::OK, "PUT must succeed: {body}");

    // Poll (bounded) for the async best_effort_push to reach the mock — a fixed
    // sleep is flaky under CI scheduler contention; this is deterministic.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let captured: serde_json::Value = loop {
        if let Some(body) = captured_body.lock().unwrap().clone() {
            break body;
        }
        if std::time::Instant::now() > deadline {
            panic!("mock sidecar never received a POST /internal/model-key");
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    };

    // Must have a non-empty wrapped_key equal to the blob from the token.
    assert!(
        captured.get("wrapped_key").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).is_some(),
        "relayed body must have a non-empty 'wrapped_key': {captured}"
    );
    assert_eq!(
        captured["wrapped_key"],
        serde_json::json!(expected_wrapped),
        "relayed wrapped_key must equal the token's model.wrapped_key: {captured}"
    );

    // Must have lic_id matching the token's lic_id.
    assert_eq!(
        captured["lic_id"],
        serde_json::json!(expected_lic_id),
        "relayed lic_id must match the token's lic_id: {captured}"
    );

    // Must NOT have key_hex — no plaintext key, no MODEL-KEK unwrap.
    assert!(
        captured.get("key_hex").is_none(),
        "relayed body must NOT contain 'key_hex' (no plaintext key): {captured}"
    );
}

// ── WS4-4 — the license gate must never brick its own recovery path ──────────
//
// A gateway whose license goes revoked or hard-stale used to 403 `/v1/license`
// itself — the one endpoint an operator needs in order to install a
// replacement. The recorded field recovery was "disable the env token, recreate
// the API container, reach Unlicensed, activate from the console". These tests
// pin that sequence out of existence.

/// Response header naming the license condition a request was served under.
/// Literal (not the crate constant) on purpose: if the constant is renamed, the
/// wire contract these tests assert must still be re-stated deliberately.
const LICENSE_DEGRADED_HEADER: &str = "x-secureprompt-license-degraded";

/// Mint a compact token carrying offline-revalidation budgets, so a test can
/// drive `LicenseState` into the hard-stale band deterministically.
/// Returns `(compact_token, lic_id)`.
fn mint_token_with_budgets(
    sk: &SigningKey,
    not_before: &str,
    expires_at: &str,
    soft_secs: u64,
    hard_secs: u64,
) -> (String, String) {
    let lic_id = Uuid::new_v4().to_string();
    let lic = License {
        v: 1,
        lic_id: lic_id.clone(),
        customer: Customer {
            id: "test-customer".into(),
            name: "Budgeted Co".into(),
        },
        deployment: Deployment {
            scope: "single-node".into(),
            max_nodes: 1,
            sign_pubkey: "p".into(),
            wrapped_attestation_key: String::new(),
        },
        entitlements: Entitlements {
            not_before: not_before.into(),
            expires_at: expires_at.into(),
            seats: 10,
            features: vec![],
            components: vec![],
            revalidate_soft_secs: Some(soft_secs),
            revalidate_hard_secs: Some(hard_secs),
        },
        model: ModelGrant {
            wrapped_key: "w".into(),
            models: vec![],
        },
        integrity: Integrity {
            image_digests: BTreeMap::new(),
        },
        iss: "sp-admin".into(),
        iat: not_before.into(),
    };
    let env = sign_license(&lic, sk).expect("sign license");
    let token = envelope_to_token(&env).expect("encode token");
    (token, lic_id)
}

/// `YYYY-MM-DDTHH:MM:SSZ` — the strict shape `sp_license::sign::parse_rfc3339`
/// accepts — for `offset_secs` before now.
fn rfc3339_secs_ago(offset_secs: i64) -> String {
    (chrono::Utc::now() - chrono::Duration::seconds(offset_secs))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

/// Drive the gateway into the hard-stale band with a REAL signed token: valid
/// signature, inside its validity window, but anchored at a `not_before` far
/// older than its hard revalidation budget and never credited with a freshness
/// assertion. Returns the token so a test can prove re-activating the SAME
/// license does not launder its staleness away.
fn force_hard_stale(state: &AppState, sk: &SigningKey) -> String {
    let (token, _lic_id) = mint_token_with_budgets(
        sk,
        "2020-01-01T00:00:00Z",
        "2099-01-01T00:00:00Z",
        60,
        120,
    );
    let snapshot = secureprompt_api::license::load_and_verify_token(
        &token,
        &sk.verifying_key(),
        chrono::Utc::now().timestamp(),
    );
    // Premise assertions: without these, "hard stale" could silently be
    // "Unlicensed because the fixture didn't verify", and every assertion
    // below would be about the wrong state.
    assert_eq!(
        snapshot.status,
        secureprompt_api::license::LicenseStatus::Valid,
        "premise: the hard-stale fixture must be a signature-valid, in-window license"
    );
    assert_eq!(
        snapshot.revalidate_hard_secs,
        Some(120),
        "premise: the fixture must carry a hard revalidation budget"
    );
    state.license.set(snapshot);
    assert!(
        state.license.is_hard_stale(),
        "premise: the fixture must actually put LicenseState into the hard-stale band"
    );
    assert!(
        !state.license.is_revoked(),
        "premise: hard-stale must not be the sticky revoked flag"
    );
    token
}

/// A signature-valid replacement license an operator would paste into the
/// console: budgets intact, anchored 60s ago so it is genuinely fresh against
/// its own 14d/30d policy rather than fresh because it has no policy at all.
fn mint_replacement_license(sk: &SigningKey) -> (String, String) {
    mint_token_with_budgets(
        sk,
        &rfc3339_secs_ago(60),
        "2099-01-01T00:00:00Z",
        1_209_600,
        2_592_000,
    )
}

/// HARD-STALE: `/v1/license` must answer, and a non-allowlisted route must
/// DEGRADE (serve + say so in a header) rather than 403 — the WS2-3
/// `degrade_with_alert` shape, not a second vocabulary.
#[sqlx::test]
async fn hard_stale_serves_recovery_route_and_degrades_the_rest(pool: PgPool) -> sqlx::Result<()> {
    let sk = SigningKey::generate(&mut OsRng);
    let (ws, user) = seed_admin(&pool).await?;
    let (state, router) = build_app_with_keys(pool.clone(), &sk);
    let jwt = mint_jwt(ws, user, "admin");

    // Positive control: a HEALTHY gateway serves both, with no degraded header.
    let healthy_license = get_req(&router, "/v1/license", &jwt).await;
    assert_eq!(healthy_license.status(), StatusCode::OK);
    let healthy_users = get_req(&router, "/v1/users", &jwt).await;
    assert_eq!(healthy_users.status(), StatusCode::OK);
    assert!(
        healthy_users.headers().get(LICENSE_DEGRADED_HEADER).is_none(),
        "premise: a healthy gateway must NOT mark responses degraded"
    );

    force_hard_stale(&state, &sk);

    // THE DEFECT: the recovery endpoint itself was 403-ed here.
    let resp = get_req(&router, "/v1/license", &jwt).await;
    let (status, body) = read_json(resp).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "hard-stale gateway must still answer its own recovery route: {body}"
    );

    // Hard-stale DEGRADES the rest of the surface instead of hard-403ing it.
    let degraded = get_req(&router, "/v1/users", &jwt).await;
    assert_eq!(
        degraded.status(),
        StatusCode::OK,
        "hard-stale must degrade, not block"
    );
    assert_eq!(
        degraded
            .headers()
            .get(LICENSE_DEGRADED_HEADER)
            .and_then(|v| v.to_str().ok()),
        Some("license_revalidation_lost"),
        "a degraded answer must name the bounded reason it was degraded for"
    );

    // "Loudly" means the Prometheus series `LicenseGateEngaged` fires on, with
    // the same bounded (reason, action) label shape WS2-3 uses.
    assert_eq!(
        state
            .metrics
            .license_gate_engaged_count("license_revalidation_lost", "degrade_with_alert"),
        1,
        "the one degraded request must be counted exactly once"
    );
    assert_eq!(
        state
            .metrics
            .license_gate_engaged_count("license_revoked", "block"),
        0,
        "hard-stale must not be reported as a revocation"
    );
    assert!(
        state.metrics.render_prometheus().contains(
            "secureprompt_license_gate_engaged_total{reason=\"license_revalidation_lost\",action=\"degrade_with_alert\"} 1"
        ),
        "the counter must be exposed on /metrics"
    );
    Ok(())
}

/// REVOKED: `/v1/license` must answer, and the rest of the surface must STILL
/// be 403. This is the control that must differ — it proves allowlisting the
/// recovery route did not disarm the gate.
#[sqlx::test]
async fn revoked_serves_recovery_route_but_still_blocks_everything_else(
    pool: PgPool,
) -> sqlx::Result<()> {
    let sk = SigningKey::generate(&mut OsRng);
    let (ws, user) = seed_admin(&pool).await?;
    let (state, router) = build_app_with_keys(pool.clone(), &sk);
    let jwt = mint_jwt(ws, user, "admin");

    // Premise: both routes work before the revocation.
    assert_eq!(
        get_req(&router, "/v1/users", &jwt).await.status(),
        StatusCode::OK,
        "premise: /v1/users must be reachable before revocation"
    );
    assert_eq!(
        state
            .metrics
            .license_gate_engaged_count("license_revoked", "block"),
        0,
        "premise: a healthy gateway engages the gate zero times"
    );

    state.license.mark_revoked("lic-under-test");
    assert!(state.license.is_revoked(), "premise: the sticky flag must be set");

    let resp = get_req(&router, "/v1/license", &jwt).await;
    let (status, body) = read_json(resp).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "revoked gateway must still answer its own recovery route: {body}"
    );

    assert_eq!(
        get_req(&router, "/v1/users", &jwt).await.status(),
        StatusCode::FORBIDDEN,
        "revoked must stay fail-closed everywhere except the recovery route"
    );
    assert_eq!(
        state
            .metrics
            .license_gate_engaged_count("license_revoked", "block"),
        1,
        "the blocked request is counted; the allowlisted one is not"
    );
    Ok(())
}

/// The trap: "above the license gate" must NOT become "above authentication".
/// `/v1/license` is admin-gated, and stays admin-gated in the blocked states.
#[sqlx::test]
async fn recovery_route_is_above_the_license_gate_not_above_auth(pool: PgPool) -> sqlx::Result<()> {
    let sk = SigningKey::generate(&mut OsRng);
    let (ws, _user) = seed_admin(&pool).await?;
    let (state, router) = build_app_with_keys(pool.clone(), &sk);

    state.license.mark_revoked("lic-under-test");

    // No credentials at all → 401, not 200 and not a license 403.
    let anon = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/license")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        anon.status(),
        StatusCode::UNAUTHORIZED,
        "the allowlisted recovery route must still require authentication"
    );

    // Authenticated but not admin → 403 from RBAC (GET, PUT and DELETE).
    let viewer_jwt = mint_jwt(ws, Uuid::new_v4(), "viewer");
    assert_eq!(
        get_req(&router, "/v1/license", &viewer_jwt).await.status(),
        StatusCode::FORBIDDEN,
        "viewer GET must still be RBAC-refused"
    );
    let (replacement, _) = mint_replacement_license(&sk);
    assert_eq!(
        put_req(&router, "/v1/license", json!({"token": replacement}), &viewer_jwt)
            .await
            .status(),
        StatusCode::FORBIDDEN,
        "viewer PUT must still be RBAC-refused — a non-admin cannot re-license the gateway"
    );
    assert_eq!(
        delete_req(&router, "/v1/license", &viewer_jwt).await.status(),
        StatusCode::FORBIDDEN,
        "viewer DELETE must still be RBAC-refused"
    );
    Ok(())
}

/// Acceptance: a simulated hard-stale gateway accepts a replacement license
/// with no DB surgery and no restart — the console PUT is sufficient.
#[sqlx::test]
async fn hard_stale_accepts_replacement_license_without_db_surgery(pool: PgPool) -> sqlx::Result<()> {
    let sk = SigningKey::generate(&mut OsRng);
    let (ws, user) = seed_admin(&pool).await?;
    let (state, router) = build_app_with_keys(pool.clone(), &sk);
    let jwt = mint_jwt(ws, user, "admin");

    let stale_token = force_hard_stale(&state, &sk);

    let (replacement, _lic_id) = mint_replacement_license(&sk);
    let resp = put_req(&router, "/v1/license", json!({"token": replacement}), &jwt).await;
    let (status, body) = read_json(resp).await;
    assert_eq!(status, StatusCode::OK, "replacement PUT must succeed: {body}");
    assert_eq!(body["status"], "Valid", "gateway must be Valid again: {body}");
    assert_eq!(body["source"], "db", "replacement must be persisted: {body}");
    assert!(
        !state.license.is_hard_stale(),
        "activating a fresh license must clear the hard-stale condition"
    );

    // And the surface recovers with no degraded marker.
    let recovered = get_req(&router, "/v1/users", &jwt).await;
    assert_eq!(recovered.status(), StatusCode::OK);
    assert!(
        recovered.headers().get(LICENSE_DEGRADED_HEADER).is_none(),
        "a re-licensed gateway must stop marking responses degraded"
    );

    // Control that must differ: re-activating the SAME stale license does not
    // launder its staleness — the anchor is the license's own not_before, and
    // pasting it again must not reset the offline countdown.
    let replay = put_req(&router, "/v1/license", json!({"token": stale_token}), &jwt).await;
    assert_eq!(replay.status(), StatusCode::OK, "replay PUT is accepted");
    assert!(
        state.license.is_hard_stale(),
        "re-pasting the stale license must NOT buy fresh offline budget"
    );
    Ok(())
}

/// Acceptance: a REVOKED gateway is superseded by a different license without a
/// restart — and re-pasting the revoked one changes nothing.
#[sqlx::test]
async fn revoked_is_superseded_by_a_different_license_but_not_by_itself(
    pool: PgPool,
) -> sqlx::Result<()> {
    let sk = SigningKey::generate(&mut OsRng);
    let (ws, user) = seed_admin(&pool).await?;
    let (state, router) = build_app_with_keys(pool.clone(), &sk);
    let jwt = mint_jwt(ws, user, "admin");

    // Activate license A, then have the vendor revoke exactly that lic_id.
    let (token_a, lic_a) = mint_replacement_license(&sk);
    assert_eq!(
        put_req(&router, "/v1/license", json!({"token": token_a}), &jwt).await.status(),
        StatusCode::OK
    );
    state.license.mark_revoked(&lic_a);
    assert!(state.license.is_revoked(), "premise: revoked");
    assert_eq!(
        state.license.revoked_lic_id().as_deref(),
        Some(lic_a.as_str()),
        "premise: the revocation names the license that was actually activated"
    );
    assert_eq!(
        get_req(&router, "/v1/users", &jwt).await.status(),
        StatusCode::FORBIDDEN,
        "premise: a revoked gateway is fail-closed"
    );

    // Re-pasting the SAME revoked license must not lift the revocation.
    assert_eq!(
        put_req(&router, "/v1/license", json!({"token": token_a}), &jwt).await.status(),
        StatusCode::OK,
        "the recovery route answers"
    );
    assert!(
        state.license.is_revoked(),
        "re-activating the revoked license {lic_a} must NOT clear the revocation"
    );
    assert_eq!(
        get_req(&router, "/v1/users", &jwt).await.status(),
        StatusCode::FORBIDDEN,
        "still fail-closed after replaying the revoked token"
    );

    // A DIFFERENT, vendor-signed license supersedes it — no restart, no SQL.
    let (token_b, _lic_b) = mint_replacement_license(&sk);
    assert_eq!(
        put_req(&router, "/v1/license", json!({"token": token_b}), &jwt).await.status(),
        StatusCode::OK
    );
    assert!(
        !state.license.is_revoked(),
        "a different, signature-valid license must supersede the revocation"
    );
    assert_eq!(
        get_req(&router, "/v1/users", &jwt).await.status(),
        StatusCode::OK,
        "the gateway must serve again after being re-licensed"
    );
    Ok(())
}
