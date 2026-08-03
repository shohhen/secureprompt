//! Integration tests for POST /v1/auth/register (public signup).

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use secureprompt_api::{
    app_state::AppState, http::build_router, ml_sidecar::MlSidecarClient,
};
use secureprompt_common::config::{
    AppConfig, ClickhouseConfig, DatabaseConfig, JwtConfig, LicenseConfig, RedisConfig,
    ServerConfig, TelemetryConfig,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;

const TEST_JWT_SECRET: &str = "register-test-jwt-secret-32bytes!";

fn test_config(public_signup_enabled: bool) -> AppConfig {
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
        public_signup_enabled,
        chat_debug_mode: false,
        redact_when_no_rules: false,
        sidecar_unavailable_default: "block".to_owned(),
        license: LicenseConfig::default(),
    }
}

fn build_app(pool: PgPool, public_signup_enabled: bool) -> axum::Router {
    let ml = Arc::new(MlSidecarClient::new(String::new(), 100));
    build_router(AppState::new(
        pool,
        test_config(public_signup_enabled),
        ml,
        std::sync::Arc::new(secureprompt_api::license::LicenseState::unlicensed()),
    ))
}

async fn json_body(resp: axum::response::Response) -> Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

fn register_body(email: &str, password: &str, workspace_name: &str) -> Body {
    Body::from(
        json!({
            "email": email,
            "password": password,
            "workspace_name": workspace_name
        })
        .to_string(),
    )
}

fn post_register(body: Body) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/v1/auth/register")
        .header("content-type", "application/json")
        .header("x-forwarded-for", "10.0.0.1")
        .body(body)
        .unwrap()
}

// ── 1 ──────────────────────────────────────────────────────────────────────

#[sqlx::test]
async fn register_returns_403_when_flag_disabled(pool: PgPool) {
    let app = build_app(pool.clone(), false);
    let resp = app
        .oneshot(post_register(register_body(
            "new@example.com",
            "correct-horse-staple",
            "Acme",
        )))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let ws_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM workspaces")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(ws_count, 0, "no workspace should be created when disabled");
}

// ── 2 ──────────────────────────────────────────────────────────────────────

#[sqlx::test]
async fn register_creates_workspace_and_owner_user_when_enabled(pool: PgPool) {
    let app = build_app(pool.clone(), true);
    let resp = app
        .oneshot(post_register(register_body(
            "new@example.com",
            "correct-horse-staple",
            "Acme",
        )))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);

    let body = json_body(resp).await;
    assert!(body["access_token"].as_str().is_some());
    assert!(body["refresh_token"].as_str().is_some());
    assert_eq!(body["role"], "owner");
    assert_eq!(body["user"]["email"], "new@example.com");
    assert!(body["workspace_id"].as_str().is_some());
    // password must never be echoed
    assert!(body.get("password").is_none());
    assert!(body.get("password_hash").is_none());

    let ws_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM workspaces")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(ws_count, 1);

    let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(user_count, 1);

    let role: String = sqlx::query_scalar("SELECT role FROM users LIMIT 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(role, "owner");
}

// ── 3 ──────────────────────────────────────────────────────────────────────

#[sqlx::test]
async fn register_returns_token_pair_that_authenticates_subsequent_request(pool: PgPool) {
    let app = build_app(pool.clone(), true);

    let resp = app
        .clone()
        .oneshot(post_register(register_body(
            "me@example.com",
            "correct-horse-staple",
            "Acme",
        )))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = json_body(resp).await;
    let access_token = body["access_token"].as_str().unwrap().to_owned();

    // Use the freshly-issued access token to call a protected route.
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/users")
                .header("authorization", format!("Bearer {access_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ── 4 ──────────────────────────────────────────────────────────────────────

#[sqlx::test]
async fn register_rejects_short_password_with_400(pool: PgPool) {
    let app = build_app(pool.clone(), true);
    let resp = app
        .oneshot(post_register(register_body(
            "a@b.com",
            "short",
            "Acme",
        )))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let ws_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM workspaces")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(ws_count, 0);
}

// ── 5 ──────────────────────────────────────────────────────────────────────

#[sqlx::test]
async fn register_rejects_invalid_email_with_400(pool: PgPool) {
    let app = build_app(pool.clone(), true);
    let resp = app
        .oneshot(post_register(register_body(
            "notanemail",
            "correct-horse-staple",
            "Acme",
        )))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let ws_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM workspaces")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(ws_count, 0);
}

// ── 6 ──────────────────────────────────────────────────────────────────────

#[sqlx::test]
async fn register_rejects_blank_workspace_name_with_400(pool: PgPool) {
    let app = build_app(pool.clone(), true);
    let resp = app
        .oneshot(post_register(register_body(
            "a@b.com",
            "correct-horse-staple",
            "   ",
        )))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── 7 ──────────────────────────────────────────────────────────────────────

#[sqlx::test]
async fn register_rejects_duplicate_email_with_409_and_rolls_back_workspace(pool: PgPool) {
    let app = build_app(pool.clone(), true);

    // First registration succeeds.
    let resp = app
        .clone()
        .oneshot(post_register(register_body(
            "dup@example.com",
            "correct-horse-staple",
            "First Workspace",
        )))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let ws_count_after_first: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM workspaces")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(ws_count_after_first, 1);

    // Second registration with same email — must 409 AND not leave an orphan workspace.
    let resp = app
        .oneshot(post_register(register_body(
            "dup@example.com",
            "correct-horse-staple",
            "Second Workspace",
        )))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    let ws_count_after_second: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM workspaces")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        ws_count_after_second, 1,
        "failed register must not leave orphan workspace"
    );
}

// ── 8 ──────────────────────────────────────────────────────────────────────

#[sqlx::test]
async fn register_rate_limits_after_10_attempts_per_ip(pool: PgPool) {
    let app = build_app(pool.clone(), true);

    // 10 registrations with the same X-Forwarded-For must be allowed.
    // We use invalid-email payloads so each one returns 400 (not 201) —
    // this avoids the unique-email collision on attempt 2 while still
    // counting toward the limiter.
    for i in 0..10 {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/register")
                    .header("content-type", "application/json")
                    .header("x-forwarded-for", "10.0.0.99")
                    .body(register_body("notanemail", "correct-horse-staple", "W"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "request {i} should not be rate-limited yet"
        );
    }

    // 11th request from the same IP must be rate-limited.
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/register")
                .header("content-type", "application/json")
                .header("x-forwarded-for", "10.0.0.99")
                .body(register_body("notanemail", "correct-horse-staple", "W"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}
