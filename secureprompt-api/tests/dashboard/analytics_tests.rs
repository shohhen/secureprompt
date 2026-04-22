//! Phase 5 / Plan 05-03 — Analytics endpoint integration tests.
//!
//! Covers VALIDATION 5-03-01..5-03-04 (per-mart IDOR guard),
//! mart_not_populated (404 path), prometheus_counters, and the
//! mart_only CI gate.
//!
//! Tests use `#[sqlx::test]` for a fresh Postgres per test. ClickHouse is
//! accessed at `CLICKHOUSE_URL` / `CLICKHOUSE_DB`; when unreachable the
//! analytics calls return 404/500 — both are acceptable in most assertions.
//! Redis is accessed at `REDIS_URL` (default `redis://localhost:6379`).
//!
//! IDOR guard assertions (403 on `workspace_id` mismatch) require only
//! Postgres + Redis and do not depend on ClickHouse availability.

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use secureprompt_api::{
    app_state::AppState, http::build_router, ml_sidecar::MlSidecarClient,
};
use secureprompt_common::config::{
    AppConfig, ClickhouseConfig, DatabaseConfig, JwtConfig, RedisConfig as AppRedisConfig,
    ServerConfig, TelemetryConfig,
};
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

// ── Harness ──────────────────────────────────────────────────────────────────

const TEST_JWT_SECRET: &str = "analytics-test-secret-01";

fn redis_url() -> String {
    std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".into())
}

fn clickhouse_url() -> String {
    std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://localhost:8123".into())
}

fn clickhouse_db() -> String {
    std::env::var("CLICKHOUSE_DB").unwrap_or_else(|_| "sp_analytics".into())
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
            url: clickhouse_url(),
            database: clickhouse_db(),
        },
        jwt: JwtConfig {
            secret: TEST_JWT_SECRET.into(),
            access_ttl_secs: 900,
            refresh_ttl_secs: 3600,
        },
        public_signup_enabled: false,
    }
}

fn build_app(pool: PgPool) -> (AppState, Router) {
    let config = test_config();
    let ml_sidecar = Arc::new(MlSidecarClient::new(String::new(), 100));
    let state = AppState::new(pool, config, ml_sidecar);
    let router = build_router(state.clone());
    (state, router)
}

/// Issue a JWT for the given `workspace_id` using the test secret.
fn make_jwt(workspace_id: Uuid, role: &str) -> String {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use secureprompt_api::http::middleware::jwt_auth::Claims;
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
    .expect("JWT encode must succeed in tests")
}

// ── VALIDATION 5-03-01: usage-daily IDOR guard ────────────────────────────────

#[sqlx::test]
async fn usage_daily_idor_guard(pool: PgPool) {
    let ws_a = Uuid::new_v4();
    let ws_b = Uuid::new_v4();
    let token_a = make_jwt(ws_a, "admin");

    let (_state, app) = build_app(pool);

    // Request with workspace_id matching JWT → 200 or 404 (ClickHouse may be absent)
    let req = Request::builder()
        .uri(format!(
            "/v1/analytics/usage-daily?from=2024-01-01&to=2024-01-07&workspace_id={ws_a}"
        ))
        .header("Authorization", format!("Bearer {token_a}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert!(
        resp.status() == StatusCode::OK
            || resp.status() == StatusCode::NOT_FOUND
            || resp.status() == StatusCode::INTERNAL_SERVER_ERROR,
        "Expected 200/404/500, got {}",
        resp.status()
    );

    // Request with workspace_id = ws_b (mismatch) → 403 (T-05-05)
    let req_bad = Request::builder()
        .uri(format!(
            "/v1/analytics/usage-daily?from=2024-01-01&to=2024-01-07&workspace_id={ws_b}"
        ))
        .header("Authorization", format!("Bearer {token_a}"))
        .body(Body::empty())
        .unwrap();
    let resp_bad = app.oneshot(req_bad).await.unwrap();
    assert_eq!(
        resp_bad.status(),
        StatusCode::FORBIDDEN,
        "workspace_id mismatch must return 403"
    );
}

// ── VALIDATION 5-03-02: cost-by-model IDOR guard ─────────────────────────────

#[sqlx::test]
async fn cost_by_model_idor_guard(pool: PgPool) {
    let ws_a = Uuid::new_v4();
    let ws_b = Uuid::new_v4();
    let token_a = make_jwt(ws_a, "admin");

    let (_state, app) = build_app(pool);

    // Matching workspace → 200/404/500
    let req = Request::builder()
        .uri(format!(
            "/v1/analytics/cost-by-model?from=2024-01-01&to=2024-01-07&workspace_id={ws_a}"
        ))
        .header("Authorization", format!("Bearer {token_a}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert!(
        resp.status() == StatusCode::OK
            || resp.status() == StatusCode::NOT_FOUND
            || resp.status() == StatusCode::INTERNAL_SERVER_ERROR,
        "Expected 200/404/500, got {}",
        resp.status()
    );

    // Mismatched workspace → 403
    let req_bad = Request::builder()
        .uri(format!(
            "/v1/analytics/cost-by-model?from=2024-01-01&to=2024-01-07&workspace_id={ws_b}"
        ))
        .header("Authorization", format!("Bearer {token_a}"))
        .body(Body::empty())
        .unwrap();
    let resp_bad = app.oneshot(req_bad).await.unwrap();
    assert_eq!(resp_bad.status(), StatusCode::FORBIDDEN);
}

// ── VALIDATION 5-03-03: policy-violations IDOR guard ─────────────────────────

#[sqlx::test]
async fn policy_violations_idor_guard(pool: PgPool) {
    let ws_a = Uuid::new_v4();
    let ws_b = Uuid::new_v4();
    let token_a = make_jwt(ws_a, "admin");

    let (_state, app) = build_app(pool);

    let req = Request::builder()
        .uri(format!(
            "/v1/analytics/policy-violations?from=2024-01-01&to=2024-01-07&workspace_id={ws_a}"
        ))
        .header("Authorization", format!("Bearer {token_a}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert!(
        resp.status() == StatusCode::OK
            || resp.status() == StatusCode::NOT_FOUND
            || resp.status() == StatusCode::INTERNAL_SERVER_ERROR,
        "Expected 200/404/500, got {}",
        resp.status()
    );

    let req_bad = Request::builder()
        .uri(format!(
            "/v1/analytics/policy-violations?from=2024-01-01&to=2024-01-07&workspace_id={ws_b}"
        ))
        .header("Authorization", format!("Bearer {token_a}"))
        .body(Body::empty())
        .unwrap();
    let resp_bad = app.oneshot(req_bad).await.unwrap();
    assert_eq!(resp_bad.status(), StatusCode::FORBIDDEN);
}

// ── VALIDATION 5-03-04: latency-pctiles IDOR guard ───────────────────────────

#[sqlx::test]
async fn latency_pctiles_idor_guard(pool: PgPool) {
    let ws_a = Uuid::new_v4();
    let ws_b = Uuid::new_v4();
    let token_a = make_jwt(ws_a, "admin");

    let (_state, app) = build_app(pool);

    let req = Request::builder()
        .uri(format!(
            "/v1/analytics/latency-pctiles?from=2024-01-01&to=2024-01-07&workspace_id={ws_a}"
        ))
        .header("Authorization", format!("Bearer {token_a}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert!(
        resp.status() == StatusCode::OK
            || resp.status() == StatusCode::NOT_FOUND
            || resp.status() == StatusCode::INTERNAL_SERVER_ERROR,
        "Expected 200/404/500, got {}",
        resp.status()
    );

    let req_bad = Request::builder()
        .uri(format!(
            "/v1/analytics/latency-pctiles?from=2024-01-01&to=2024-01-07&workspace_id={ws_b}"
        ))
        .header("Authorization", format!("Bearer {token_a}"))
        .body(Body::empty())
        .unwrap();
    let resp_bad = app.oneshot(req_bad).await.unwrap();
    assert_eq!(resp_bad.status(), StatusCode::FORBIDDEN);
}

// ── mart_not_populated: non-200 when db missing ───────────────────────────────

#[sqlx::test]
async fn mart_not_populated_returns_non_200(pool: PgPool) {
    let mut config = test_config();
    // Point at a database name that won't have the mart tables.
    config.clickhouse.database = "nonexistent_db_for_test_404".into();

    let ml_sidecar = Arc::new(MlSidecarClient::new(String::new(), 100));
    let state = AppState::new(pool, config, ml_sidecar);
    let app = build_router(state);

    let ws = Uuid::new_v4();
    let token = make_jwt(ws, "admin");

    let req = Request::builder()
        .uri("/v1/analytics/usage-daily?from=2024-01-01&to=2024-01-07")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    // 404 (ClickHouse reachable, mart absent) or 500 (ClickHouse unreachable).
    // Either way, must NOT be 200.
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "Should not return 200 when mart db doesn't exist"
    );
}

// ── No JWT → 401 ──────────────────────────────────────────────────────────────

#[sqlx::test]
async fn analytics_requires_auth(pool: PgPool) {
    let (_state, app) = build_app(pool);

    let req = Request::builder()
        .uri("/v1/analytics/usage-daily?from=2024-01-01&to=2024-01-07")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ── Invalid date range → 403 ──────────────────────────────────────────────────

#[sqlx::test]
async fn invalid_date_range_returns_forbidden(pool: PgPool) {
    let ws = Uuid::new_v4();
    let token = make_jwt(ws, "admin");
    let (_state, app) = build_app(pool);

    // to < from → 403
    let req = Request::builder()
        .uri("/v1/analytics/usage-daily?from=2024-01-07&to=2024-01-01")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ── Prometheus counters incremented after request ─────────────────────────────

#[sqlx::test]
async fn prometheus_counters_incremented(pool: PgPool) {
    let (state, app) = build_app(pool);

    let ws = Uuid::new_v4();
    let token = make_jwt(ws, "admin");

    // Hit usage-daily — returns 200/404/500; all paths increment counters.
    let req = Request::builder()
        .uri("/v1/analytics/usage-daily?from=2024-01-01&to=2024-01-07")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let _resp = app.oneshot(req).await.unwrap();

    // mart_usage_daily query duration counter must be >= 1.
    let mart_count = state.metrics.mart_query_count("mart_usage_daily");
    assert!(
        mart_count >= 1,
        "mart_usage_daily query count should be >= 1, got {mart_count}"
    );

    // Dashboard request counter (success or error) must be >= 1.
    let success = state.metrics.dashboard_request_count("usage-daily", "success");
    let error = state.metrics.dashboard_request_count("usage-daily", "error");
    assert!(
        success + error >= 1,
        "dashboard_request_duration counter should have at least one entry"
    );

    // Prometheus text output must contain the new metric names.
    let prom = state.metrics.render_prometheus();
    assert!(
        prom.contains("secureprompt_dashboard_mart_query_duration_seconds"),
        "Prometheus output must contain mart query duration metric"
    );
    assert!(
        prom.contains("secureprompt_dashboard_request_duration_seconds"),
        "Prometheus output must contain dashboard request duration metric"
    );
}

// ── CI gate: mart_only_gate ───────────────────────────────────────────────────

#[test]
fn mart_only_gate() {
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root");

    let status = std::process::Command::new("bash")
        .arg("scripts/ci/check-mart-only.sh")
        .current_dir(workspace_root)
        .status()
        .expect("bash must be available");

    assert!(
        status.success(),
        "check-mart-only.sh failed — analytics.rs has a non-mart FROM clause"
    );
}
