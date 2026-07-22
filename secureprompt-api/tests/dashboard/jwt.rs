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
    http::{
        middleware::jwt_auth::{self, Claims, JwtAuthContext},
        routes::dashboard::auth::{decode_purpose_token, encode_purpose_token},
    },
    ml_sidecar::MlSidecarClient,
};
use secureprompt_common::config::{
    AppConfig, ClickhouseConfig, DatabaseConfig, JwtConfig, LicenseConfig, RedisConfig,
    ServerConfig, TelemetryConfig,
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
        purpose: None,
    };
    let token = encode(&Header::new(Algorithm::HS256), &claims, encoding)
        .expect("encode test token");
    (token, claims)
}

/// 2FA (Task 4): mint a single-purpose token the way
/// `dashboard::auth::encode_purpose_token` does — same claim shape, just
/// with `purpose = Some(purpose)` set.
fn mint_purpose_token(encoding: &EncodingKey, purpose: &str, ttl_secs: i64) -> String {
    let now = Utc::now();
    let claims = Claims {
        sub: Uuid::new_v4(),
        ws: Uuid::new_v4(),
        role: String::new(),
        iat: now.timestamp(),
        exp: (now + Duration::seconds(ttl_secs)).timestamp(),
        jti: Uuid::new_v4().to_string(),
        purpose: Some(purpose.to_string()),
    };
    encode(&Header::new(Algorithm::HS256), &claims, encoding).expect("encode purpose token")
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
        chat_debug_mode: false,
        redact_when_no_rules: false,
        license: LicenseConfig::default(),
    };
    let ml_sidecar = Arc::new(MlSidecarClient::new(String::new(), 100));
    AppState::new(
        pool,
        config,
        ml_sidecar,
        Arc::new(secureprompt_api::license::LicenseState::unlicensed()),
    )
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

/// 2FA (Task 4) — the core security boundary: a challenge/enrollment token
/// (`purpose = Some(_)`) must be rejected by the normal JWT auth middleware
/// even though it is validly signed and unexpired. Only a purposeless
/// access token may reach a protected route.
#[sqlx::test]
async fn purpose_token_rejected_as_access_token(pool: PgPool) -> sqlx::Result<()> {
    let state = build_state(pool);
    let app = router(state.clone());

    for purpose in ["2fa_challenge", "2fa_enroll"] {
        let token =
            mint_purpose_token(&EncodingKey::from_secret(test_secret().as_bytes()), purpose, 300);

        let request = Request::builder()
            .uri("/protected")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("valid request");

        let response = app.clone().oneshot(request).await.expect("router runs");
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "a {purpose} token must NOT authorize a normal protected route"
        );
    }

    Ok(())
}

/// 2FA (Task 4 review fix) — happy path: `decode_purpose_token` round-trips
/// the exact `(user_id, workspace_id)` pair `encode_purpose_token` was given,
/// when the presented `expected_purpose` matches what was minted.
#[sqlx::test]
async fn decode_purpose_token_happy_path_round_trips_ids(pool: PgPool) -> sqlx::Result<()> {
    let state = build_state(pool);
    let user_id = Uuid::new_v4();
    let workspace_id = Uuid::new_v4();

    let token = encode_purpose_token(&state, user_id, workspace_id, "2fa_challenge", 300)
        .expect("encode purpose token");

    let (decoded_user, decoded_ws) = decode_purpose_token(&state, &token, "2fa_challenge")
        .expect("matching purpose must decode");

    assert_eq!(decoded_user, user_id);
    assert_eq!(decoded_ws, workspace_id);

    Ok(())
}

/// 2FA (Task 4 review fix) — the exact security case flagged in review: a
/// `2fa_enroll` token must NOT be redeemable where a `2fa_challenge` is
/// required, and vice versa. Without this check an attacker who completes
/// enrollment could replay the enrollment token at the challenge endpoint
/// (or skip straight from a stale enrollment token into a session).
#[sqlx::test]
async fn decode_purpose_token_rejects_purpose_mismatch(pool: PgPool) -> sqlx::Result<()> {
    let state = build_state(pool);

    let enroll_token = encode_purpose_token(&state, Uuid::new_v4(), Uuid::new_v4(), "2fa_enroll", 300)
        .expect("encode enroll token");
    assert!(
        decode_purpose_token(&state, &enroll_token, "2fa_challenge").is_err(),
        "an enroll token must not decode as a challenge token"
    );

    let challenge_token =
        encode_purpose_token(&state, Uuid::new_v4(), Uuid::new_v4(), "2fa_challenge", 300)
            .expect("encode challenge token");
    assert!(
        decode_purpose_token(&state, &challenge_token, "2fa_enroll").is_err(),
        "a challenge token must not decode as an enroll token"
    );

    Ok(())
}

/// 2FA (Task 4 review fix) — a normal access token (`purpose = None`, minted
/// the same way `encode_access`/`build_token_pair_body` do) must be rejected
/// by `decode_purpose_token` regardless of `expected_purpose`. This is the
/// mirror image of the `jwt_auth::require` guard: neither direction (access
/// token at a purpose endpoint, purpose token at a normal endpoint) may
/// cross the boundary.
#[sqlx::test]
async fn decode_purpose_token_rejects_normal_access_token(pool: PgPool) -> sqlx::Result<()> {
    let state = build_state(pool);

    let (access_token, _claims) =
        mint_token(&EncodingKey::from_secret(test_secret().as_bytes()), 900);

    assert!(
        decode_purpose_token(&state, &access_token, "2fa_challenge").is_err(),
        "a purposeless access token must not decode as any purpose token"
    );

    Ok(())
}

/// 2FA (Task 4 review fix) — an expired purpose token must be rejected even
/// when its `purpose` claim matches. `ttl_secs = -3600` mints a token whose
/// `exp` is an hour in the past, well outside the 60s `Validation` leeway
/// `decode_purpose_token` uses (matches the pattern `jwt_auth::tests::
/// expired_token_is_rejected` uses for the plain-access-token case).
#[sqlx::test]
async fn decode_purpose_token_rejects_expired_token(pool: PgPool) -> sqlx::Result<()> {
    let state = build_state(pool);

    let token = encode_purpose_token(&state, Uuid::new_v4(), Uuid::new_v4(), "2fa_challenge", -3600)
        .expect("encode already-expired purpose token");

    assert!(
        decode_purpose_token(&state, &token, "2fa_challenge").is_err(),
        "an expired purpose token must be rejected even with a matching purpose"
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
