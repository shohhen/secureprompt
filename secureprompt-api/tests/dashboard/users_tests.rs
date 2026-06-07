//! TDD — user management: GET /v1/users, POST /v1/users.
//!
//! RED phase: these tests fail until the route + repo + migration exist.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use secureprompt_api::{
    app_state::AppState, http::build_router, ml_sidecar::MlSidecarClient,
};
use secureprompt_api::http::middleware::jwt_auth::Claims;
use secureprompt_common::config::{
    AppConfig, ClickhouseConfig, DatabaseConfig, JwtConfig, LicenseConfig, RedisConfig,
    ServerConfig, TelemetryConfig,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

const TEST_JWT_SECRET: &str = "users-test-jwt-secret-32-bytes!!";

fn test_config() -> AppConfig {
    AppConfig {
        database: DatabaseConfig {
            url: "postgres://unused".into(),
            max_connections: 1,
        },
        redis: RedisConfig {
            url: std::env::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://localhost:6379".into()),
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
        license: LicenseConfig::default(),
    }
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

fn build_app_with_seat_limit(pool: PgPool, seats: u32) -> axum::Router {
    use secureprompt_api::license::{LicenseSnapshot, LicenseState, LicenseStatus};
    let ml = Arc::new(MlSidecarClient::new(String::new(), 100));
    let license = LicenseState::new(LicenseSnapshot {
        status: LicenseStatus::Valid,
        max_seats: Some(seats),
        features: vec![],
        customer_name: Some("Test Customer".into()),
        expires_at: Some("2030-01-01T00:00:00Z".into()),
        wrapped_model_key: None,
        lic_id: None,
    });
    build_router(AppState::new(
        pool,
        test_config(),
        ml,
        Arc::new(license),
    ))
}

fn make_jwt(workspace_id: Uuid, user_id: Uuid, role: &str) -> String {
    let claims = Claims {
        sub: user_id,
        ws: workspace_id,
        role: role.to_owned(),
        jti: Uuid::new_v4().to_string(),
        exp: (chrono::Utc::now() + chrono::Duration::seconds(900)).timestamp(),
        iat: chrono::Utc::now().timestamp(),
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(TEST_JWT_SECRET.as_bytes()),
    )
    .expect("jwt encode")
}

async fn seed_workspace_with_admin(pool: &PgPool) -> (Uuid, Uuid, String) {
    let ws_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO workspaces (id, name, created_at, updated_at)
         VALUES ($1, 'test-workspace', NOW(), NOW())",
    )
    .bind(ws_id)
    .execute(pool)
    .await
    .unwrap();

    let hash = argon2_hash("adminpass");
    sqlx::query(
        "INSERT INTO users (id, workspace_id, email, password_hash, role, created_at, updated_at)
         VALUES ($1, $2, 'admin@example.com', $3, 'admin', NOW(), NOW())",
    )
    .bind(user_id)
    .bind(ws_id)
    .bind(hash)
    .execute(pool)
    .await
    .unwrap();

    let token = make_jwt(ws_id, user_id, "admin");
    (ws_id, user_id, token)
}

fn argon2_hash(pw: &str) -> String {
    use argon2::{
        password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
        Argon2,
    };
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(pw.as_bytes(), &salt)
        .unwrap()
        .to_string()
}

async fn json_body(resp: axum::response::Response) -> Value {
    use http_body_util::BodyExt;
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

// ── GET /v1/users ────────────────────────────────────────────────────────────

#[sqlx::test]
async fn list_users_requires_jwt(pool: PgPool) {
    let app = build_app(pool);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/users")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn list_users_returns_workspace_members(pool: PgPool) {
    let (ws_id, _user_id, token) = seed_workspace_with_admin(&pool).await;
    let app = build_app(pool);

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/users")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let users = body.as_array().expect("response must be an array");
    assert_eq!(users.len(), 1);
    assert_eq!(users[0]["email"], "admin@example.com");
    assert_eq!(users[0]["role"], "admin");
    assert_eq!(users[0]["workspace_id"], ws_id.to_string());
    // password_hash must never appear in the response
    assert!(users[0].get("password_hash").is_none());
}

// ── POST /v1/users ───────────────────────────────────────────────────────────

#[sqlx::test]
async fn create_user_requires_jwt(pool: PgPool) {
    let app = build_app(pool);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/users")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"email":"new@example.com","password":"pass123","role":"viewer"})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn create_user_requires_admin_role(pool: PgPool) {
    let (ws_id, user_id, _) = seed_workspace_with_admin(&pool).await;
    let viewer_token = make_jwt(ws_id, user_id, "viewer");
    let app = build_app(pool);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/users")
                .header("authorization", format!("Bearer {viewer_token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"email":"new@example.com","password":"pass123","role":"viewer"})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[sqlx::test]
async fn create_user_admin_can_invite(pool: PgPool) {
    let (_ws_id, _user_id, token) = seed_workspace_with_admin(&pool).await;
    let app = build_app(pool);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/users")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"email":"new@example.com","password":"correct-horse-staple","role":"viewer"})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = json_body(resp).await;
    assert_eq!(body["email"], "new@example.com");
    assert_eq!(body["role"], "viewer");
    assert!(body["id"].as_str().is_some());
    // password must not be exposed
    assert!(body.get("password_hash").is_none());
    assert!(body.get("password").is_none());
}

#[sqlx::test]
async fn create_user_duplicate_email_returns_409(pool: PgPool) {
    let (_ws_id, _user_id, token) = seed_workspace_with_admin(&pool).await;
    let app = build_app(pool);

    let body = Body::from(
        json!({"email":"admin@example.com","password":"pass123","role":"viewer"}).to_string(),
    );
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/users")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(body)
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[sqlx::test]
async fn create_user_rejects_invalid_role(pool: PgPool) {
    let (_ws_id, _user_id, token) = seed_workspace_with_admin(&pool).await;
    let app = build_app(pool);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/users")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"email":"x@example.com","password":"pass123","role":"superadmin"})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// With a Valid license of seats = 1 and 1 user already present,
/// `POST /v1/users` must return 403 Forbidden (seat limit enforced).
#[sqlx::test]
async fn create_user_blocked_when_seat_limit_reached(pool: PgPool) {
    // seed_workspace_with_admin inserts exactly 1 user (the admin itself).
    let (_ws_id, _user_id, token) = seed_workspace_with_admin(&pool).await;
    // Build app with seat limit = 1 (already reached).
    let app = build_app_with_seat_limit(pool, 1);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/users")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"email":"new@example.com","password":"pass123","role":"viewer"})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
