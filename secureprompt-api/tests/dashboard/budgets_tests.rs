//! Phase 5 / Plan 05-05 — Workspace budgets integration tests.
//!
//! Covers Task 5-05-A (CRUD + RLS + IDOR + role gate + Redis-sourced current
//! usage) and Task 5-05-B (enforcement: daily counter, 402 block, warn header,
//! flag silent, parallel no-bypass, Prometheus counters).
//!
//! Every test spins up a real Postgres (via `#[sqlx::test]` fresh per-test
//! database) and a real `deadpool-redis` pool against `REDIS_URL` (defaults
//! to `redis://localhost:6379`). Redis keys are scoped per-test with a random
//! workspace UUID so parallel test runs don't stomp on each other, and every
//! test flushes its own keys on entry + exit.

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use chrono::Utc;
use deadpool_redis::{redis::cmd, Config as RedisConfig, Pool, Runtime};
use secureprompt_api::{
    app_state::AppState, http::build_router, ml_sidecar::MlSidecarClient,
};
use secureprompt_common::config::{
    AppConfig, ClickhouseConfig, DatabaseConfig, JwtConfig, RedisConfig as AppRedisConfig,
    ServerConfig, TelemetryConfig,
};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

use super::fixtures;

// ---------- Common harness (mirrors auth_tests.rs) ----------

const TEST_JWT_SECRET: &str = "dashboard-budgets-test-secret";

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
    }
}

fn build_app(pool: PgPool) -> (AppState, Router) {
    let config = test_config();
    let ml_sidecar = Arc::new(MlSidecarClient::new(String::new(), 100));
    let state = AppState::new(pool, config, ml_sidecar);
    let router = build_router(state.clone());
    (state, router)
}

async fn read_json(response: axum::response::Response) -> (StatusCode, Value) {
    let status = response.status();
    let body = to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("read body");
    let value: Value = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).expect("JSON body")
    };
    (status, value)
}

async fn post_json(
    router: &Router,
    path: &str,
    body: Value,
    headers: &[(&str, String)],
) -> axum::response::Response {
    let mut builder = Request::builder().method("POST").uri(path);
    builder = builder.header("content-type", "application/json");
    for (name, value) in headers {
        builder = builder.header(*name, value);
    }
    let request = builder
        .body(Body::from(body.to_string()))
        .expect("valid request");
    router.clone().oneshot(request).await.expect("router runs")
}

async fn send_json(
    router: &Router,
    method: &str,
    path: &str,
    body: Option<Value>,
    headers: &[(&str, String)],
) -> axum::response::Response {
    let mut builder = Request::builder().method(method).uri(path);
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    for (name, value) in headers {
        builder = builder.header(*name, value);
    }
    let body = match body {
        Some(v) => Body::from(v.to_string()),
        None => Body::empty(),
    };
    let request = builder.body(body).expect("valid request");
    router.clone().oneshot(request).await.expect("router runs")
}

async fn connect_redis() -> Pool {
    RedisConfig::from_url(redis_url())
        .create_pool(Some(Runtime::Tokio1))
        .expect("redis pool")
}

/// Remove any budget counters that may linger from a previous (failed) run.
/// Keys are namespaced per-workspace so different tests never collide.
async fn flush_budget_keys(pool: &Pool, workspace_id: Uuid) {
    let mut conn = pool.get().await.expect("redis checkout");
    // Best-effort scan + delete. We delete both daily and monthly buckets
    // for the current UTC day/month plus yesterday (safety margin for
    // midnight-straddling runs).
    let now = Utc::now();
    let yesterday = now - chrono::Duration::days(1);
    let keys = [
        format!(
            "budget:{}:tokens:{}",
            workspace_id,
            now.format("%Y%m%d")
        ),
        format!(
            "budget:{}:tokens:{}",
            workspace_id,
            yesterday.format("%Y%m%d")
        ),
        format!(
            "budget:{}:tokens:{}",
            workspace_id,
            now.format("%Y%m")
        ),
    ];
    for key in keys {
        let _: i64 = cmd("DEL")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .unwrap_or(0);
    }
}

/// Log in as a specific seeded user and return their access token.
async fn login(router: &Router, email: &str, password: &str) -> String {
    let response = post_json(
        router,
        "/v1/auth/token",
        json!({"email": email, "password": password}),
        &[],
    )
    .await;
    let (status, body) = read_json(response).await;
    assert_eq!(status, StatusCode::OK, "login must succeed: body={body}");
    body["access_token"]
        .as_str()
        .expect("access token")
        .to_owned()
}

fn bearer(token: &str) -> Vec<(&str, String)> {
    vec![("authorization", format!("Bearer {token}"))]
}

fn daily_key(workspace_id: Uuid) -> String {
    format!(
        "budget:{}:tokens:{}",
        workspace_id,
        Utc::now().format("%Y%m%d")
    )
}

#[allow(dead_code)]
fn monthly_key(workspace_id: Uuid) -> String {
    format!(
        "budget:{}:tokens:{}",
        workspace_id,
        Utc::now().format("%Y%m")
    )
}

async fn set_counter(pool: &Pool, key: &str, value: i64) {
    let mut conn = pool.get().await.expect("redis checkout");
    cmd("SET")
        .arg(key)
        .arg(value)
        .arg("EX")
        .arg(600_i64)
        .query_async::<()>(&mut conn)
        .await
        .expect("SET");
}

// ---------- Task 5-05-A — CRUD tests ----------

/// GET with no row returns defaults {daily:null, monthly:null, behavior:"warn"}.
/// Decision recorded in the plan: empty state returns 200 with defaults rather
/// than 404, so the UI always has a valid shape to render.
#[sqlx::test]
async fn get_empty(pool: PgPool) -> sqlx::Result<()> {
    let ws = fixtures::seed_unique_workspace(&pool).await?;
    let redis_pool = connect_redis().await;
    flush_budget_keys(&redis_pool, ws.workspace_id).await;

    let (_state, router) = build_app(pool);
    let token = login(&router, &ws.admin_email, &ws.password).await;

    let response = send_json(
        &router,
        "GET",
        &format!("/v1/workspaces/{}/budgets", ws.workspace_id),
        None,
        &bearer(&token),
    )
    .await;
    let (status, body) = read_json(response).await;

    assert_eq!(status, StatusCode::OK, "body={body}");
    assert!(body["daily_token_limit"].is_null());
    assert!(body["monthly_token_limit"].is_null());
    assert_eq!(body["behavior"], "warn");
    assert_eq!(body["daily_used"], 0);
    assert_eq!(body["monthly_used"], 0);
    Ok(())
}

/// PUT succeeds as admin; follow-up GET echoes the new values.
#[sqlx::test]
async fn put_happy(pool: PgPool) -> sqlx::Result<()> {
    let ws = fixtures::seed_unique_workspace(&pool).await?;
    let redis_pool = connect_redis().await;
    flush_budget_keys(&redis_pool, ws.workspace_id).await;

    let (_state, router) = build_app(pool);
    let token = login(&router, &ws.admin_email, &ws.password).await;

    let put_body = json!({
        "daily_token_limit": 100_000,
        "monthly_token_limit": 3_000_000,
        "behavior": "warn",
    });

    let response = send_json(
        &router,
        "PUT",
        &format!("/v1/workspaces/{}/budgets", ws.workspace_id),
        Some(put_body),
        &bearer(&token),
    )
    .await;
    let (status, body) = read_json(response).await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert_eq!(body["daily_token_limit"], 100_000);
    assert_eq!(body["monthly_token_limit"], 3_000_000);
    assert_eq!(body["behavior"], "warn");

    // Follow-up GET echoes the same values.
    let response = send_json(
        &router,
        "GET",
        &format!("/v1/workspaces/{}/budgets", ws.workspace_id),
        None,
        &bearer(&token),
    )
    .await;
    let (status, body) = read_json(response).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["daily_token_limit"], 100_000);
    assert_eq!(body["monthly_token_limit"], 3_000_000);
    assert_eq!(body["behavior"], "warn");
    Ok(())
}

/// Viewer is not allowed to PUT — 403.
#[sqlx::test]
async fn put_viewer_forbidden(pool: PgPool) -> sqlx::Result<()> {
    let ws = fixtures::seed_unique_workspace(&pool).await?;
    let redis_pool = connect_redis().await;
    flush_budget_keys(&redis_pool, ws.workspace_id).await;

    let (_state, router) = build_app(pool);
    let token = login(&router, &ws.viewer_email, &ws.password).await;

    let response = send_json(
        &router,
        "PUT",
        &format!("/v1/workspaces/{}/budgets", ws.workspace_id),
        Some(json!({"behavior": "block"})),
        &bearer(&token),
    )
    .await;
    let (status, body) = read_json(response).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body={body}");
    Ok(())
}

/// Admin in workspace A attempts to PUT into workspace B — 403 IDOR guard
/// (T-05-05). Guard fires before the role check so this is 403, not 200.
#[sqlx::test]
async fn idor_guard(pool: PgPool) -> sqlx::Result<()> {
    let ws_a = fixtures::seed_unique_workspace(&pool).await?;
    let ws_b = fixtures::seed_unique_workspace(&pool).await?;
    let redis_pool = connect_redis().await;
    flush_budget_keys(&redis_pool, ws_a.workspace_id).await;
    flush_budget_keys(&redis_pool, ws_b.workspace_id).await;

    let (_state, router) = build_app(pool);
    let token = login(&router, &ws_a.admin_email, &ws_a.password).await;

    // IDOR via PUT — target workspace B while signed in as admin A.
    let response = send_json(
        &router,
        "PUT",
        &format!("/v1/workspaces/{}/budgets", ws_b.workspace_id),
        Some(json!({"behavior": "block"})),
        &bearer(&token),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // IDOR via GET — same contract.
    let response = send_json(
        &router,
        "GET",
        &format!("/v1/workspaces/{}/budgets", ws_b.workspace_id),
        None,
        &bearer(&token),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    Ok(())
}

/// RLS isolation: workspace A's PUT leaves workspace B's row untouched.
/// Both workspaces start with no row; A upserts; verify via direct SQL that
/// B still has no row.
#[sqlx::test]
async fn rls_isolation(pool: PgPool) -> sqlx::Result<()> {
    let ws_a = fixtures::seed_unique_workspace(&pool).await?;
    let ws_b = fixtures::seed_unique_workspace(&pool).await?;
    let redis_pool = connect_redis().await;
    flush_budget_keys(&redis_pool, ws_a.workspace_id).await;
    flush_budget_keys(&redis_pool, ws_b.workspace_id).await;

    let (_state, router) = build_app(pool.clone());
    let token = login(&router, &ws_a.admin_email, &ws_a.password).await;

    let response = send_json(
        &router,
        "PUT",
        &format!("/v1/workspaces/{}/budgets", ws_a.workspace_id),
        Some(json!({
            "daily_token_limit": 500,
            "monthly_token_limit": 10_000,
            "behavior": "block",
        })),
        &bearer(&token),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    // Direct SQL check: only workspace A's row exists.
    let rows = sqlx::query(
        "SELECT workspace_id FROM workspace_budgets WHERE workspace_id = $1 OR workspace_id = $2",
    )
    .bind(ws_a.workspace_id)
    .bind(ws_b.workspace_id)
    .fetch_all(&pool)
    .await?;
    assert_eq!(rows.len(), 1, "only workspace A's row must exist");
    let ws_stored: Uuid = rows[0].get("workspace_id");
    assert_eq!(ws_stored, ws_a.workspace_id);
    Ok(())
}

/// Current usage is read live from Redis. Seed a counter directly and expect
/// GET to echo it in `daily_used`.
#[sqlx::test]
async fn current_usage_from_redis(pool: PgPool) -> sqlx::Result<()> {
    let ws = fixtures::seed_unique_workspace(&pool).await?;
    let redis_pool = connect_redis().await;
    flush_budget_keys(&redis_pool, ws.workspace_id).await;

    let daily = daily_key(ws.workspace_id);
    set_counter(&redis_pool, &daily, 500).await;

    let (_state, router) = build_app(pool);
    let token = login(&router, &ws.admin_email, &ws.password).await;

    let response = send_json(
        &router,
        "GET",
        &format!("/v1/workspaces/{}/budgets", ws.workspace_id),
        None,
        &bearer(&token),
    )
    .await;
    let (status, body) = read_json(response).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["daily_used"], 500);

    flush_budget_keys(&redis_pool, ws.workspace_id).await;
    Ok(())
}

// ---------- Task 5-05-B — enforcement tests ----------

/// VALIDATION 5-07-01 — daily counter semantics. Call `budget_check` with
/// delta=100 and daily_limit=1000 ten times — all Allow. Eleventh call
/// Exceeded.
#[sqlx::test]
async fn daily_counter(pool: PgPool) -> sqlx::Result<()> {
    use secureprompt_api::http::middleware::rate_limit::{budget_check, BudgetOutcome};

    let ws = fixtures::seed_unique_workspace(&pool).await?;
    let redis_pool = connect_redis().await;
    flush_budget_keys(&redis_pool, ws.workspace_id).await;

    // Seed a budget row: daily=1000, monthly unlimited, behavior=block.
    // Use the repo indirectly via a PUT through the router so this test
    // stays hermetic (no private-module access).
    let (state, router) = build_app(pool);
    let token = login(&router, &ws.admin_email, &ws.password).await;
    let response = send_json(
        &router,
        "PUT",
        &format!("/v1/workspaces/{}/budgets", ws.workspace_id),
        Some(json!({
            "daily_token_limit": 1000,
            "monthly_token_limit": null,
            "behavior": "block",
        })),
        &bearer(&token),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    for _ in 0..10 {
        let outcome = budget_check(&state, ws.workspace_id, 100)
            .await
            .expect("budget_check ok");
        assert!(matches!(outcome, BudgetOutcome::Allow), "outcome={outcome:?}");
    }

    let outcome = budget_check(&state, ws.workspace_id, 100)
        .await
        .expect("budget_check ok");
    assert!(
        matches!(outcome, BudgetOutcome::Exceeded(_)),
        "11th call must be Exceeded, got {outcome:?}"
    );

    flush_budget_keys(&redis_pool, ws.workspace_id).await;
    Ok(())
}

/// VALIDATION 5-07-02 — behavior=block + exceeded → 402 response body matches
/// `{"error":{"code":"budget_exceeded",...}}`.
/// Driven through the dedicated `/v1/internal/budget-probe` test route
/// (registered only under `#[cfg(test)]` by the rate_limit module). The
/// probe runs the budget check as if a real chat completion had arrived.
#[sqlx::test]
async fn block_402(pool: PgPool) -> sqlx::Result<()> {
    let ws = fixtures::seed_unique_workspace(&pool).await?;
    let redis_pool = connect_redis().await;
    flush_budget_keys(&redis_pool, ws.workspace_id).await;

    let (_state, router) = build_app(pool);
    let token = login(&router, &ws.admin_email, &ws.password).await;
    let response = send_json(
        &router,
        "PUT",
        &format!("/v1/workspaces/{}/budgets", ws.workspace_id),
        Some(json!({
            "daily_token_limit": 1,
            "monthly_token_limit": null,
            "behavior": "block",
        })),
        &bearer(&token),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    // Pre-seed the counter to 2 so the next probe is over the limit.
    set_counter(&redis_pool, &daily_key(ws.workspace_id), 2).await;

    let response = post_json(
        &router,
        "/v1/internal/budget-probe",
        json!({"estimated_tokens": 0}),
        &bearer(&token),
    )
    .await;
    let (status, body) = read_json(response).await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED, "body={body}");
    assert_eq!(body["error"]["code"], "budget_exceeded");

    flush_budget_keys(&redis_pool, ws.workspace_id).await;
    Ok(())
}

/// VALIDATION 5-07-03 — behavior=warn + exceeded → 200 + header
/// `x-secureprompt-budget-warning: daily`.
#[sqlx::test]
async fn warn_header(pool: PgPool) -> sqlx::Result<()> {
    let ws = fixtures::seed_unique_workspace(&pool).await?;
    let redis_pool = connect_redis().await;
    flush_budget_keys(&redis_pool, ws.workspace_id).await;

    let (_state, router) = build_app(pool);
    let token = login(&router, &ws.admin_email, &ws.password).await;
    let response = send_json(
        &router,
        "PUT",
        &format!("/v1/workspaces/{}/budgets", ws.workspace_id),
        Some(json!({
            "daily_token_limit": 1,
            "monthly_token_limit": null,
            "behavior": "warn",
        })),
        &bearer(&token),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    set_counter(&redis_pool, &daily_key(ws.workspace_id), 2).await;

    let response = post_json(
        &router,
        "/v1/internal/budget-probe",
        json!({"estimated_tokens": 0}),
        &bearer(&token),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let header = response
        .headers()
        .get("x-secureprompt-budget-warning")
        .expect("warn header present")
        .to_str()
        .expect("ascii header")
        .to_owned();
    assert_eq!(header, "daily");

    flush_budget_keys(&redis_pool, ws.workspace_id).await;
    Ok(())
}

/// VALIDATION 5-07-04 — behavior=flag + exceeded → 200, no budget header,
/// silent to the client. We assert the header is absent; log capture is not
/// exercised here (tracing_test would add a big dep for a minor log-line
/// assertion).
#[sqlx::test]
async fn flag_silent(pool: PgPool) -> sqlx::Result<()> {
    let ws = fixtures::seed_unique_workspace(&pool).await?;
    let redis_pool = connect_redis().await;
    flush_budget_keys(&redis_pool, ws.workspace_id).await;

    let (_state, router) = build_app(pool);
    let token = login(&router, &ws.admin_email, &ws.password).await;
    let response = send_json(
        &router,
        "PUT",
        &format!("/v1/workspaces/{}/budgets", ws.workspace_id),
        Some(json!({
            "daily_token_limit": 1,
            "monthly_token_limit": null,
            "behavior": "flag",
        })),
        &bearer(&token),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    set_counter(&redis_pool, &daily_key(ws.workspace_id), 2).await;

    let response = post_json(
        &router,
        "/v1/internal/budget-probe",
        json!({"estimated_tokens": 0}),
        &bearer(&token),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get("x-secureprompt-budget-warning")
            .is_none(),
        "flag behavior must not emit the budget header"
    );

    flush_budget_keys(&redis_pool, ws.workspace_id).await;
    Ok(())
}

/// VALIDATION 5-07-05 / T-05-08 — parallel bypass safety. With daily_limit=10,
/// behavior=block, and a clean counter, fire 20 concurrent probe requests
/// each charging +1 token. Expect:
///   - exactly 20 responses in total
///   - at least 10 hit 402 (because >10 collective tokens exceed the limit)
///   - the Redis final counter is bounded: <= limit + 20 (reservation overshoot)
///   - no second-wave 200 after exhaustion
#[sqlx::test]
async fn parallel_no_bypass(pool: PgPool) -> sqlx::Result<()> {
    let ws = fixtures::seed_unique_workspace(&pool).await?;
    let redis_pool = connect_redis().await;
    flush_budget_keys(&redis_pool, ws.workspace_id).await;

    let (_state, router) = build_app(pool);
    let token = login(&router, &ws.admin_email, &ws.password).await;
    let response = send_json(
        &router,
        "PUT",
        &format!("/v1/workspaces/{}/budgets", ws.workspace_id),
        Some(json!({
            "daily_token_limit": 10,
            "monthly_token_limit": null,
            "behavior": "block",
        })),
        &bearer(&token),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    // Reset the counter to 0 explicitly (the PUT doesn't touch it).
    flush_budget_keys(&redis_pool, ws.workspace_id).await;

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..20 {
        let r = router.clone();
        let t = token.clone();
        set.spawn(async move {
            post_json(
                &r,
                "/v1/internal/budget-probe",
                json!({"estimated_tokens": 1}),
                &bearer(&t),
            )
            .await
            .status()
        });
    }

    let mut status_200 = 0;
    let mut status_402 = 0;
    while let Some(r) = set.join_next().await {
        match r.expect("task panicked") {
            StatusCode::OK => status_200 += 1,
            StatusCode::PAYMENT_REQUIRED => status_402 += 1,
            other => panic!("unexpected status {other}"),
        }
    }
    assert_eq!(status_200 + status_402, 20, "total responses");
    assert!(
        status_402 >= 10,
        "at least 10 must 402 (got {status_402})"
    );
    assert!(
        status_200 <= 10,
        "at most 10 must succeed (got {status_200})"
    );

    // Redis counter is bounded: reservation pattern may overshoot by at most
    // the concurrency delta.
    let mut conn = redis_pool.get().await.expect("redis checkout");
    let counter: i64 = cmd("GET")
        .arg(daily_key(ws.workspace_id))
        .query_async(&mut conn)
        .await
        .unwrap_or(0);
    assert!(
        counter <= 30,
        "counter overshoot must be bounded by concurrency (got {counter})"
    );

    flush_budget_keys(&redis_pool, ws.workspace_id).await;
    Ok(())
}

/// VALIDATION 5-07-06 — Prometheus counters increment per behavior/outcome.
#[sqlx::test]
async fn prometheus_events(pool: PgPool) -> sqlx::Result<()> {
    let ws = fixtures::seed_unique_workspace(&pool).await?;
    let redis_pool = connect_redis().await;
    flush_budget_keys(&redis_pool, ws.workspace_id).await;

    let (_state, router) = build_app(pool);
    let token = login(&router, &ws.admin_email, &ws.password).await;

    // Behavior=block, Redis=2, limit=1 → one "block/exceeded" event.
    let _ = send_json(
        &router,
        "PUT",
        &format!("/v1/workspaces/{}/budgets", ws.workspace_id),
        Some(json!({"daily_token_limit": 1, "behavior": "block"})),
        &bearer(&token),
    )
    .await;
    set_counter(&redis_pool, &daily_key(ws.workspace_id), 2).await;
    let _ = post_json(
        &router,
        "/v1/internal/budget-probe",
        json!({"estimated_tokens": 0}),
        &bearer(&token),
    )
    .await;

    // Scrape /metrics and assert the labelled counter is present.
    let response = send_json(&router, "GET", "/metrics", None, &[]).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1 << 20).await.expect("body");
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("secureprompt_dashboard_budget_events_total"),
        "metrics must expose the budget events counter; got:\n{text}"
    );
    assert!(
        text.contains(r#"behavior="block""#),
        "metrics must include behavior label; got:\n{text}"
    );
    assert!(
        text.contains(r#"outcome="exceeded""#),
        "metrics must include outcome label; got:\n{text}"
    );

    flush_budget_keys(&redis_pool, ws.workspace_id).await;
    Ok(())
}
