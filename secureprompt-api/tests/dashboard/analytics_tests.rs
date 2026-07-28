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
    AppConfig, ClickhouseConfig, DatabaseConfig, JwtConfig, LicenseConfig,
    RedisConfig as AppRedisConfig, ServerConfig, TelemetryConfig,
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

pub fn clickhouse_url() -> String {
    std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://localhost:8123".into())
}

pub fn clickhouse_db() -> String {
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
        chat_debug_mode: false,
        redact_when_no_rules: false,
        sidecar_unavailable_default: "block".to_owned(),
        license: LicenseConfig::default(),
    }
}

pub fn build_app(pool: PgPool) -> (AppState, Router) {
    let config = test_config();
    let ml_sidecar = Arc::new(MlSidecarClient::new(String::new(), 100));
    let state = AppState::new(
        pool,
        config,
        ml_sidecar,
        Arc::new(secureprompt_api::license::LicenseState::unlicensed()),
    );
    let router = build_router(state.clone());
    (state, router)
}

/// Issue a JWT for the given `workspace_id` using the test secret.
pub fn make_jwt(workspace_id: Uuid, role: &str) -> String {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use secureprompt_api::http::middleware::jwt_auth::Claims;
    let claims = Claims {
        sub: Uuid::new_v4(),
        ws: workspace_id,
        role: role.to_owned(),
        jti: Uuid::new_v4().to_string(),
        exp: (chrono::Utc::now() + chrono::Duration::seconds(900)).timestamp(),
        iat: chrono::Utc::now().timestamp(),
        purpose: None,
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

// ── mart_not_populated: returns 200 with empty list when marts are absent ─────
//
// Previously this handler returned 404 when the mart tables didn't exist, which
// surfaced as a broken dashboard on fresh installs (before dbt had ever run).
// We now return `200 []` so the UI renders its natural empty state; operators
// see the underlying condition via the `dashboard_errors_total` metric and a
// `tracing::warn!` from `map_ch_error`.

#[sqlx::test]
async fn mart_not_populated_returns_empty(pool: PgPool) {
    let mut config = test_config();
    // Point at a database name that won't have the mart tables.
    config.clickhouse.database = "nonexistent_db_for_test_empty".into();

    let ml_sidecar = Arc::new(MlSidecarClient::new(String::new(), 100));
    let state = AppState::new(
        pool,
        config,
        ml_sidecar,
        Arc::new(secureprompt_api::license::LicenseState::unlicensed()),
    );
    let app = build_router(state);

    let ws = Uuid::new_v4();
    let token = make_jwt(ws, "admin");

    let req = Request::builder()
        .uri("/v1/analytics/usage-daily?from=2024-01-01&to=2024-01-07")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    // If ClickHouse is reachable the missing-table/db branch maps to 200 []; if
    // ClickHouse is totally unreachable we still tolerate 500. We must NOT
    // return 404 anymore — that was the UX bug we just fixed.
    assert_ne!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "Missing mart should no longer surface as 404 to the dashboard"
    );
    assert!(
        resp.status() == StatusCode::OK
            || resp.status() == StatusCode::INTERNAL_SERVER_ERROR,
        "Expected 200 (mart missing) or 500 (CH unreachable), got {}",
        resp.status()
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

    // KPI-2 monitoring, Task 1 — the three duration metrics are now real
    // bucketed histograms, not summaries: assert the `# TYPE ... histogram`
    // header and a `le="+Inf"` bucket line (with the actual labels this
    // request produced) are present.
    assert!(
        prom.contains("# TYPE secureprompt_dashboard_request_duration_seconds histogram"),
        "secureprompt_dashboard_request_duration_seconds must be exposed as a histogram; got:\n{prom}"
    );
    let request_outcome = if success >= 1 { "success" } else { "error" };
    assert!(
        prom.contains(&format!(
            "secureprompt_dashboard_request_duration_seconds_bucket{{endpoint=\"usage-daily\",outcome=\"{request_outcome}\",le=\"+Inf\"}}"
        )),
        "expected a +Inf bucket line for endpoint=usage-daily,outcome={request_outcome}; got:\n{prom}"
    );

    assert!(
        prom.contains("# TYPE secureprompt_dashboard_mart_query_duration_seconds histogram"),
        "secureprompt_dashboard_mart_query_duration_seconds must be exposed as a histogram; got:\n{prom}"
    );
    assert!(
        prom.contains(
            "secureprompt_dashboard_mart_query_duration_seconds_bucket{mart=\"mart_usage_daily\",le=\"+Inf\"}"
        ),
        "expected a +Inf bucket line for mart=mart_usage_daily; got:\n{prom}"
    );

    // The always-emitted (unlabelled) budget-check histogram must also have
    // converted, even though this test never calls `time_budget_check`.
    assert!(
        prom.contains("# TYPE secureprompt_dashboard_budget_check_duration_seconds histogram"),
        "secureprompt_dashboard_budget_check_duration_seconds must be exposed as a histogram; got:\n{prom}"
    );
    assert!(
        prom.contains("secureprompt_dashboard_budget_check_duration_seconds_bucket{le=\"+Inf\"}"),
        "expected an unlabelled +Inf bucket line for the budget-check histogram; got:\n{prom}"
    );

    // Guard against accidentally dropping a previously-emitted counter family
    // while converting the three histograms above (the `/metrics` scrape also
    // doubles as the k8s health probe — every family must still appear).
    for family in [
        "secureprompt_requests_total",
        "secureprompt_request_failures_total",
        "secureprompt_analytics_dropped_total",
        "secureprompt_analytics_failures_total",
        "secureprompt_clickhouse_insert_failures_total",
        "secureprompt_clickhouse_insert_retries_total",
        "secureprompt_budget_redis_failure_total",
    ] {
        assert!(
            prom.contains(&format!("# TYPE {family} counter")),
            "expected counter family {family} to still be emitted; got:\n{prom}"
        );
    }
}

// ── WS1-2: cost-by-model must be workspace-scoped ────────────────────────────

/// Insert one `request_events` row directly into ClickHouse.
///
/// Deliberately panics rather than skipping when ClickHouse is unreachable.
/// A tenancy test that silently passes because its fixture never landed is
/// the exact failure mode WS1-4 exists to eliminate — see
/// `rls_matrix.rs::is_safe`.
pub async fn seed_request_event(workspace_id: Uuid, model: &str) {
    let sql = format!(
        "INSERT INTO {db}.request_events \
         (request_id, workspace_id, provider, model, final_action, cost_usd, \
          estimated_usage, created_at) \
         VALUES ('{rid}', '{ws}', 'openai', '{model}', 'allow', 1.25, false, now())",
        db = clickhouse_db(),
        rid = Uuid::new_v4(),
        ws = workspace_id,
    );

    let resp = reqwest::Client::new()
        .post(clickhouse_url())
        .body(sql)
        .send()
        .await
        .unwrap_or_else(|e| {
            panic!(
                "ClickHouse unreachable at {} — this test requires a seeded \
                 ClickHouse and must not be skipped: {e}",
                clickhouse_url()
            )
        });

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert!(status.is_success(), "ClickHouse insert failed ({status}): {body}");
}

/// WS1-2 — `GET /v1/analytics/cost-by-model` **without** a `workspace_id`
/// query parameter must still be scoped to the caller's workspace.
///
/// The handler's IDOR guard only fires when `workspace_id` is supplied
/// (`analytics.rs`), and neither the mart query nor its raw fallback carries a
/// workspace filter (`dashboard_reader.rs`). Omitting the parameter therefore
/// bypasses tenancy entirely.
///
/// The canary model name is unique per run, so a match cannot be coincidental:
/// if it appears in workspace A's response, workspace B's data leaked.
#[sqlx::test]
async fn cost_by_model_without_workspace_id_does_not_leak_other_tenants(pool: PgPool) {
    let ws_a = Uuid::new_v4();
    let ws_b = Uuid::new_v4();
    let canary = format!("canary-model-{}", Uuid::new_v4().simple());

    seed_request_event(ws_b, &canary).await;

    let token_a = make_jwt(ws_a, "admin");
    let (_state, app) = build_app(pool);

    let today = chrono::Utc::now().date_naive();
    let from = today - chrono::Duration::days(1);
    let to = today + chrono::Duration::days(1);

    // No `workspace_id` parameter — the path that skips the guard.
    let req = Request::builder()
        .uri(format!(
            "/v1/analytics/cost-by-model?from={from}&to={to}"
        ))
        .header("Authorization", format!("Bearer {token_a}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("read body");
    let body = String::from_utf8_lossy(&bytes).to_string();

    assert_eq!(
        status,
        StatusCode::OK,
        "cost-by-model should succeed for the caller's own workspace; body: {body}"
    );
    assert!(
        !body.contains(&canary),
        "CROSS-TENANT LEAK: workspace A received workspace B's model \
         '{canary}' from cost-by-model. body: {body}"
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
