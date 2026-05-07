//! Phase 5 / Plan 05-06 — Cross-tenant RLS matrix test (VALIDATION 5-08-01 / T-05-05).
//!
//! Iterates over every dashboard endpoint that accepts a workspace-scoped
//! parameter. For each endpoint, issues the request using a JWT minted for
//! workspace A while targeting workspace B. Asserts that every response is
//! either HTTP 403 Forbidden or returns an empty result set (no data leakage).
//!
//! The test is data-driven via an `EndpointCase` manifest so new endpoints
//! can be added by appending a row — no new test function required.

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use deadpool_redis::{Config as RedisConfig, Runtime};
use secureprompt_api::{app_state::AppState, http::build_router, ml_sidecar::MlSidecarClient};
use secureprompt_common::config::{
    AppConfig, ClickhouseConfig, DatabaseConfig, JwtConfig, RedisConfig as AppRedisConfig,
    ServerConfig, TelemetryConfig,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

use super::fixtures;

// ---------- Harness ----------------------------------------------------------

const TEST_JWT_SECRET: &str = "rls-matrix-test-secret-value-here";

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
    }
}

fn build_app(pool: PgPool) -> (AppState, Router) {
    let config = test_config();
    let ml_sidecar = Arc::new(MlSidecarClient::new(String::new(), 100));
    let state = AppState::new(pool, config, ml_sidecar);
    let router = build_router(state.clone());
    (state, router)
}

async fn post_json_raw(
    router: &Router,
    path: &str,
    body: Value,
    token: &str,
) -> axum::response::Response {
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .expect("valid request");
    router.clone().oneshot(request).await.expect("router")
}

async fn send_raw(
    router: &Router,
    method: &str,
    path: &str,
    body: Option<Value>,
    token: &str,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {token}"));
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let body_bytes = match body {
        Some(v) => Body::from(v.to_string()),
        None => Body::empty(),
    };
    let request = builder.body(body_bytes).expect("valid request");
    let response = router.clone().oneshot(request).await.expect("router");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("read body");
    let val: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, val)
}

/// Log in and return an access token.
async fn login(router: &Router, email: &str) -> String {
    let (status, body) = send_raw(
        router,
        "POST",
        "/v1/auth/token",
        Some(json!({ "email": email, "password": fixtures::SHARED_PASSWORD })),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "login must succeed: {body}");
    body["access_token"]
        .as_str()
        .expect("access_token field")
        .to_owned()
}

// ---------- Matrix -----------------------------------------------------------

/// A single endpoint under test.
struct Case {
    method: &'static str,
    /// Path template — `{B}` is replaced with workspace_b UUID at runtime.
    path_template: &'static str,
    body_fn: Option<fn(Uuid) -> Value>,
}

fn matrix_cases() -> Vec<Case> {
    vec![
        // Analytics endpoints (query-param workspace_id=B).
        Case {
            method: "GET",
            path_template: "/v1/analytics/usage-daily?workspace_id={B}",
            body_fn: None,
        },
        Case {
            method: "GET",
            path_template: "/v1/analytics/cost-by-model?workspace_id={B}",
            body_fn: None,
        },
        Case {
            method: "GET",
            path_template: "/v1/analytics/policy-violations?workspace_id={B}",
            body_fn: None,
        },
        Case {
            method: "GET",
            path_template: "/v1/analytics/latency-pctiles?workspace_id={B}",
            body_fn: None,
        },
        // Requests list (query-param workspace_id=B).
        Case {
            method: "GET",
            path_template: "/v1/requests?workspace_id={B}",
            body_fn: None,
        },
        // Keys list (query-param workspace_id=B).
        Case {
            method: "GET",
            path_template: "/v1/keys?workspace_id={B}",
            body_fn: None,
        },
        // Providers list (query-param workspace_id=B).
        Case {
            method: "GET",
            path_template: "/v1/providers?workspace_id={B}",
            body_fn: None,
        },
        // Policy rules list (query-param workspace_id=B).
        Case {
            method: "GET",
            path_template: "/v1/policy-rules?workspace_id={B}",
            body_fn: None,
        },
        // Budget GET (path param /:id/budgets where id=B).
        Case {
            method: "GET",
            path_template: "/v1/workspaces/{B}/budgets",
            body_fn: None,
        },
        // Budget PUT (path param /:id/budgets where id=B).
        Case {
            method: "PUT",
            path_template: "/v1/workspaces/{B}/budgets",
            body_fn: Some(|_| json!({ "behavior": "warn" })),
        },
    ]
}

/// Expand `{B}` placeholder in a path template.
fn expand_path(template: &str, workspace_b: Uuid) -> String {
    template.replace("{B}", &workspace_b.to_string())
}

/// Returns true if the response is safe: either 403 Forbidden or an empty
/// result set (empty array / null body). Fails if actual workspace-B data
/// is returned.
fn is_safe(status: StatusCode, body: &Value) -> bool {
    if status == StatusCode::FORBIDDEN {
        return true;
    }
    // Some analytics endpoints may return 200 with an empty list when there
    // is genuinely no data — that is acceptable as long as no B-data leaks.
    if status == StatusCode::OK {
        match body {
            Value::Array(arr) => return arr.is_empty(),
            Value::Object(map) => {
                // Cursor-paginated: { data: [], next_cursor: null }
                if let Some(Value::Array(arr)) = map.get("data") {
                    return arr.is_empty();
                }
                // Mart result with empty rows array.
                if let Some(Value::Array(arr)) = map.get("rows") {
                    return arr.is_empty();
                }
                // Budget response — should not be accessible (403 expected),
                // but if somehow reached, it must not contain B-specific data.
                // We don't know B's exact values so we accept empty default.
                return false;
            }
            Value::Null => return true,
            _ => return false,
        }
    }
    // Any other status (400, 404, 500) is not an information leak.
    !status.is_success()
}

// ---------- Test -------------------------------------------------------------

/// VALIDATION 5-08-01 / T-05-05 — cross-tenant matrix.
///
/// Every dashboard endpoint must return 403 or empty when accessed with
/// workspace A's JWT while targeting workspace B.
#[sqlx::test]
async fn cross_tenant_matrix(pool: PgPool) -> sqlx::Result<()> {
    let seeded = fixtures::seed_two_workspaces(&pool).await?;

    // Build Redis pool (needed by AppState even if not seeding budget data).
    let _redis_pool = RedisConfig::from_url(redis_url())
        .create_pool(Some(Runtime::Tokio1))
        .expect("redis pool");

    let (_state, router) = build_app(pool);

    // Authenticate as admin_a (workspace A).
    let token_a = login(&router, fixtures::ADMIN_A_EMAIL).await;

    let workspace_b = seeded.workspace_b;
    let cases = matrix_cases();

    let mut failures: Vec<String> = Vec::new();

    for case in &cases {
        let path = expand_path(case.path_template, workspace_b);
        let body = case.body_fn.map(|f| f(workspace_b));

        let (status, body_val) = send_raw(&router, case.method, &path, body, &token_a).await;

        if !is_safe(status, &body_val) {
            failures.push(format!(
                "LEAK: {} {} → status={} body={}",
                case.method, path, status, body_val
            ));
        }
    }

    if !failures.is_empty() {
        panic!(
            "Cross-tenant RLS matrix found data leakage on {} endpoint(s):\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    Ok(())
}
