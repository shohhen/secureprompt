//! TDD — secure mode: GET /v1/secure-mode, PUT /v1/secure-mode.
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

const TEST_JWT_SECRET: &str = "secure-mode-test-jwt-secret-32!!";

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

fn make_jwt(workspace_id: Uuid, role: &str) -> String {
    let claims = Claims {
        sub: Uuid::new_v4(),
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

async fn seed_workspace(pool: &PgPool) -> Uuid {
    let ws_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workspaces (id, name, created_at, updated_at)
         VALUES ($1, 'secure-mode-test-ws', NOW(), NOW())",
    )
    .bind(ws_id)
    .execute(pool)
    .await
    .unwrap();
    ws_id
}

async fn json_body(resp: axum::response::Response) -> Value {
    use http_body_util::BodyExt;
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

// ── GET /v1/secure-mode ───────────────────────────────────────────────────────

#[sqlx::test]
async fn get_secure_mode_requires_jwt(pool: PgPool) {
    let app = build_app(pool);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/secure-mode")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn get_secure_mode_returns_defaults_when_not_configured(pool: PgPool) {
    let ws_id = seed_workspace(&pool).await;
    let token = make_jwt(ws_id, "admin");
    let app = build_app(pool);

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/secure-mode")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    // Defaults: disabled, standard level
    assert_eq!(body["enabled"], false);
    assert_eq!(body["level"], "standard");
    assert_eq!(body["block_on_pii_detection"], false);
    assert_eq!(body["block_on_injection_detection"], false);
    assert_eq!(body["redact_pii_in_responses"], false);
    assert!(body["updated_at"].as_str().is_some());
}

// ── PUT /v1/secure-mode ───────────────────────────────────────────────────────

#[sqlx::test]
async fn put_secure_mode_requires_jwt(pool: PgPool) {
    let app = build_app(pool);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/secure-mode")
                .header("content-type", "application/json")
                .body(Body::from(json!({"enabled": true}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn put_secure_mode_requires_admin_role(pool: PgPool) {
    let ws_id = seed_workspace(&pool).await;
    let viewer_token = make_jwt(ws_id, "viewer");
    let app = build_app(pool);

    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/secure-mode")
                .header("authorization", format!("Bearer {viewer_token}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"enabled": true}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[sqlx::test]
async fn put_secure_mode_admin_can_enable(pool: PgPool) {
    let ws_id = seed_workspace(&pool).await;
    let token = make_jwt(ws_id, "admin");
    let app = build_app(pool);

    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/secure-mode")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "enabled": true,
                        "level": "strict",
                        "block_on_pii_detection": true,
                        "block_on_injection_detection": true,
                        "redact_pii_in_responses": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["enabled"], true);
    assert_eq!(body["level"], "strict");
    assert_eq!(body["block_on_pii_detection"], true);
    assert_eq!(body["block_on_injection_detection"], true);
    assert_eq!(body["redact_pii_in_responses"], true);
    assert!(body["updated_at"].as_str().is_some());
}

#[sqlx::test]
async fn get_secure_mode_reflects_put(pool: PgPool) {
    let ws_id = seed_workspace(&pool).await;
    let token = make_jwt(ws_id, "admin");

    // PUT to enable
    let app = build_app(pool.clone());
    app.oneshot(
        Request::builder()
            .method("PUT")
            .uri("/v1/secure-mode")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"enabled": true, "level": "permissive"}).to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    // GET should return updated value
    let app2 = build_app(pool);
    let resp = app2
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/secure-mode")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["enabled"], true);
    assert_eq!(body["level"], "permissive");
}

#[sqlx::test]
async fn put_secure_mode_rejects_invalid_level(pool: PgPool) {
    let ws_id = seed_workspace(&pool).await;
    let token = make_jwt(ws_id, "admin");
    let app = build_app(pool);

    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/secure-mode")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"enabled": true, "level": "maximum_power"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
