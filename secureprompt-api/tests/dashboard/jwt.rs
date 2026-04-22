//! Task 5-01-B / 5-01-C — JWT middleware tests.
//!
//! `tamper_detect` is the VALIDATION 5-01-06 gate for threat T-05-02 (JWT
//! tampering): mint a valid HS256 token, flip one byte of the signature,
//! send it to a trivial protected route, assert 401.
//!
//! `expired_refresh` lands in Task 5-01-C together with the refresh-token
//! repository.

use axum::{
    body::Body,
    extract::{Extension, State},
    http::{Request, StatusCode},
    middleware::from_fn_with_state,
    response::IntoResponse,
    routing::get,
    Router,
};
use chrono::{Duration, Utc};
use deadpool_redis::Config as RedisPoolConfig;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use secureprompt_api::{
    app_state::AppState,
    http::middleware::jwt_auth::{self, Claims, JwtAuthContext},
    ml_sidecar::MlSidecarClient,
};
use secureprompt_common::config::{
    AppConfig, ClickhouseConfig, DatabaseConfig, JwtConfig, RedisConfig, ServerConfig,
    TelemetryConfig,
};
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

/// Minimal handler that extracts the JWT context and echoes the user id.
async fn protected_echo(Extension(ctx): Extension<JwtAuthContext>) -> impl IntoResponse {
    (StatusCode::OK, ctx.user_id.to_string())
}

fn test_secret() -> &'static str {
    "dashboard-test-secret"
}

fn mint_token(encoding: &EncodingKey, ttl_secs: i64) -> (String, Claims) {
    let now = Utc::now();
    let claims = Claims {
        sub: Uuid::new_v4(),
        ws: Uuid::new_v4(),
        role: "admin".into(),
        iat: now.timestamp(),
        exp: (now + Duration::seconds(ttl_secs)).timestamp(),
        jti: Uuid::new_v4().to_string(),
    };
    let token = encode(&Header::new(Algorithm::HS256), &claims, encoding)
        .expect("encode test token");
    (token, claims)
}

fn build_state(pool: PgPool) -> AppState {
    let config = AppConfig {
        database: DatabaseConfig {
            url: "postgres://unused".into(),
            max_connections: 1,
        },
        redis: RedisConfig {
            // Redis is not exercised in the signature-tamper path because the
            // middleware short-circuits on signature failure before touching
            // Redis. A real URL is still required so `AppState::try_new`
            // succeeds.
            url: std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".into()),
            max_connections: 1,
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
            secret: test_secret().into(),
            access_ttl_secs: 900,
            refresh_ttl_secs: 2_592_000,
        },
        public_signup_enabled: false,
    };
    let ml_sidecar = Arc::new(MlSidecarClient::new(String::new(), 100));
    AppState::new(pool, config, ml_sidecar)
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/protected", get(protected_echo))
        .route_layer(from_fn_with_state(state.clone(), jwt_auth::require))
        .with_state(state)
}

/// VALIDATION 5-01-06 / Threat T-05-02: a JWT whose signature has been
/// tampered with must be rejected with 401 by the `jwt_auth::require`
/// middleware. The decode step happens before the Redis check, so this
/// test does not depend on Redis state.
#[sqlx::test]
async fn tamper_detect(pool: PgPool) -> sqlx::Result<()> {
    // Guard: the build_state helper constructs the real AppState and relies
    // on deadpool-redis::Config::from_url being parseable; skip the test if
    // Redis pool construction fails (CI environments without Redis would
    // otherwise see a misleading 500).
    let pool_ok = RedisPoolConfig::from_url(
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".into()),
    )
    .create_pool(Some(deadpool_redis::Runtime::Tokio1))
    .is_ok();
    assert!(pool_ok, "Redis pool init must succeed for the test harness");

    let state = build_state(pool);
    let app = router(state.clone());

    // Mint a valid token, then flip the final signature character.
    let (token, _claims) =
        mint_token(&EncodingKey::from_secret(test_secret().as_bytes()), 900);
    let mut tampered = token.clone();
    let last = tampered.pop().expect("non-empty token");
    let replacement = if last == 'A' { 'B' } else { 'A' };
    tampered.push(replacement);
    assert_ne!(token, tampered, "tampering must produce a different token");

    let request = Request::builder()
        .uri("/protected")
        .header("authorization", format!("Bearer {tampered}"))
        .body(Body::empty())
        .expect("valid request");

    let response = app.oneshot(request).await.expect("router runs");
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "tampered JWT must yield 401"
    );

    Ok(())
}

/// Sanity test: a valid token on the same protected route returns 200. This
/// makes the `tamper_detect` assertion meaningful (otherwise 401 could be
/// from some other path).
#[sqlx::test]
async fn happy_path_accepts_valid_token(pool: PgPool) -> sqlx::Result<()> {
    let state = build_state(pool);
    let app = router(state.clone());

    let (token, _claims) =
        mint_token(&EncodingKey::from_secret(test_secret().as_bytes()), 900);

    let request = Request::builder()
        .uri("/protected")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("valid request");

    let response = app.oneshot(request).await.expect("router runs");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "valid JWT must yield 200 on the protected route"
    );

    Ok(())
}

// Wire `State<AppState>` through the echo so clippy does not complain about
// unused extractors elsewhere in the test module. Currently unused but kept
// for Task 5-01-C to mount real handlers in this file.
#[allow(dead_code)]
async fn _echo_with_state(
    State(_state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
) -> impl IntoResponse {
    (StatusCode::OK, ctx.user_id.to_string())
}
