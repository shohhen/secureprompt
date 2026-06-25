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
        license: LicenseConfig {
            pubkey_b64: vk_b64,
            license_token: String::new(),
            model_kek_b64: String::new(),
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

    let resp = get_req(&router, "/v1/license", &jwt).await;
    // GET does not require admin — only JWT. Viewer should still get 200.
    // However, PUT and DELETE need admin. This test verifies the viewer
    // cannot PUT.
    let (get_status, _) = read_json(resp).await;
    assert_eq!(get_status, StatusCode::OK, "GET should be 200 for any authenticated user");

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
