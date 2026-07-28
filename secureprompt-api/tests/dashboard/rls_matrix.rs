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
    AppConfig, ClickhouseConfig, DatabaseConfig, JwtConfig, LicenseConfig,
    RedisConfig as AppRedisConfig, ServerConfig, TelemetryConfig,
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
        // Must resolve through the same helpers as `seed_canary`. These were
        // previously hardcoded to `default` while fixtures wrote elsewhere,
        // so the app under test queried an empty database and every case
        // passed vacuously.
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

fn build_app(pool: PgPool) -> (AppState, Router) {
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

fn clickhouse_url() -> String {
    std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://localhost:8123".into())
}

fn clickhouse_db() -> String {
    std::env::var("CLICKHOUSE_DB").unwrap_or_else(|_| "sp_analytics".into())
}

/// Seed one `request_events` row for `workspace_id` carrying a run-unique
/// `canary` model name.
///
/// WS1-4: the matrix previously ran against an unseeded ClickHouse, so every
/// analytics endpoint returned 500 and the old `is_safe` classified 500 as
/// "not a leak". The matrix was therefore green while `cost-by-model` was
/// returning every tenant's data. Isolation can only be *proven* against a
/// datastore that actually holds another tenant's rows, so this panics rather
/// than skipping when ClickHouse is unreachable.
async fn seed_canary(workspace_id: Uuid, canary: &str) {
    let sql = format!(
        "INSERT INTO {db}.request_events \
         (request_id, workspace_id, provider, model, final_action, cost_usd, \
          estimated_usage, created_at) \
         VALUES ('{rid}', '{ws}', 'openai', '{canary}', 'allow', 4.5, false, now())",
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
                "ClickHouse unreachable at {} — the RLS matrix cannot prove \
                 isolation without seeded cross-tenant data and must not be \
                 skipped: {e}",
                clickhouse_url()
            )
        });

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "ClickHouse canary insert failed ({status}): {body}"
    );
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

// ---------- Matrix -----------------------------------------------------------

/// What a given request is allowed to return.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Expect {
    /// Caller explicitly named workspace B. Only 403 or an empty result set
    /// is acceptable — the guard should reject before any query runs.
    ForbiddenOrEmpty,
    /// Caller named no workspace at all, so returning *their own* data is
    /// correct and expected. The only forbidden outcome is B's canary
    /// appearing in the payload.
    ///
    /// WS1-2 lived entirely in this shape: every pre-existing matrix case
    /// supplied `workspace_id={B}` and so only ever exercised the handler
    /// guard, never the query underneath it.
    NoCanary,
}

/// A single endpoint under test.
struct Case {
    method: &'static str,
    /// Path template — `{B}` is replaced with workspace_b UUID at runtime.
    path_template: &'static str,
    body_fn: Option<fn(Uuid) -> Value>,
    expect: Expect,
}

/// A short window spanning "now", so freshly inserted canary rows fall inside
/// it. Must stay under the handler's 366-day cap (`validate_date_range`).
fn date_range() -> String {
    let today = chrono::Utc::now().date_naive();
    format!(
        "from={}&to={}",
        today - chrono::Duration::days(1),
        today + chrono::Duration::days(1)
    )
}

fn matrix_cases() -> Vec<Case> {
    let range = date_range();

    // The four analytics endpoints require `from`/`to`. Without them the
    // request fails validation with 400 *before* reaching the IDOR guard —
    // which is how the original matrix "covered" these endpoints while
    // exercising nothing (the old `is_safe` scored 400 as not-a-leak).
    let mut cases: Vec<Case> = [
        "/v1/analytics/usage-daily",
        "/v1/analytics/cost-by-model",
        "/v1/analytics/policy-violations",
        "/v1/analytics/latency-pctiles",
    ]
    .into_iter()
    .map(|path| Case {
        method: "GET",
        path_template: Box::leak(format!("{path}?{range}&workspace_id={{B}}").into_boxed_str()),
        body_fn: None,
        expect: Expect::ForbiddenOrEmpty,
    })
    .collect();

    cases.extend([
        // ---- Explicit cross-tenant targeting: workspace_id=B --------------
        Case {
            method: "GET",
            path_template: "/v1/requests?workspace_id={B}",
            body_fn: None,
            expect: Expect::ForbiddenOrEmpty,
        },
        Case {
            method: "GET",
            path_template: "/v1/keys?workspace_id={B}",
            body_fn: None,
            expect: Expect::ForbiddenOrEmpty,
        },
        Case {
            method: "GET",
            path_template: "/v1/providers?workspace_id={B}",
            body_fn: None,
            expect: Expect::ForbiddenOrEmpty,
        },
        Case {
            method: "GET",
            path_template: "/v1/policy-rules?workspace_id={B}",
            body_fn: None,
            expect: Expect::ForbiddenOrEmpty,
        },
        Case {
            method: "GET",
            path_template: "/v1/workspaces/{B}/budgets",
            body_fn: None,
            expect: Expect::ForbiddenOrEmpty,
        },
        Case {
            method: "PUT",
            path_template: "/v1/workspaces/{B}/budgets",
            body_fn: Some(|_| json!({ "behavior": "warn" })),
            expect: Expect::ForbiddenOrEmpty,
        },
    ]);

    // ---- Omitted workspace_id: the guard never fires -----------------------
    // These are the cases that catch a query missing its tenancy predicate.
    for path in [
        "/v1/analytics/usage-daily",
        "/v1/analytics/cost-by-model",
        "/v1/analytics/policy-violations",
        "/v1/analytics/latency-pctiles",
    ] {
        cases.push(Case {
            method: "GET",
            path_template: Box::leak(format!("{path}?{range}").into_boxed_str()),
            body_fn: None,
            expect: Expect::NoCanary,
        });
    }
    cases.push(Case {
        method: "GET",
        path_template: "/v1/requests",
        body_fn: None,
        expect: Expect::NoCanary,
    });

    cases
}

/// Expand `{B}` placeholder in a path template.
fn expand_path(template: &str, workspace_b: Uuid) -> String {
    template.replace("{B}", &workspace_b.to_string())
}

/// Outcome of classifying one response.
#[derive(Debug)]
enum Verdict {
    Safe,
    /// Workspace B's data reached workspace A.
    Leak(String),
    /// The harness could not determine whether isolation held — almost always
    /// a missing or unseeded dependency.
    ///
    /// WS1-4: this variant is the entire point of the fix. The previous
    /// `is_safe` ended with `!status.is_success()`, so a 500 from an unseeded
    /// ClickHouse counted as *safe*. The matrix passed for months while
    /// `cost-by-model` returned every tenant's costs. Inconclusive must fail
    /// the run: a test that cannot fail cannot pass either.
    Inconclusive(String),
}

/// Extract the first non-empty array a response body exposes, if any.
fn rows_of(body: &Value) -> Option<&Vec<Value>> {
    match body {
        Value::Array(arr) => Some(arr),
        Value::Object(map) => map
            .get("data")
            .or_else(|| map.get("rows"))
            .or_else(|| map.get("items"))
            .and_then(|v| v.as_array()),
        _ => None,
    }
}

fn classify(status: StatusCode, body: &Value, expect: Expect, canary: &str) -> Verdict {
    // A canary sighting is a leak regardless of status or expectation.
    if body.to_string().contains(canary) {
        return Verdict::Leak(format!("workspace B canary '{canary}' present"));
    }

    match expect {
        Expect::ForbiddenOrEmpty => {
            if status == StatusCode::FORBIDDEN {
                return Verdict::Safe;
            }
            if status.is_success() {
                return match rows_of(body) {
                    Some(rows) if rows.is_empty() => Verdict::Safe,
                    Some(rows) => {
                        Verdict::Leak(format!("{} row(s) returned for workspace B", rows.len()))
                    }
                    None if matches!(body, Value::Null) => Verdict::Safe,
                    None => Verdict::Leak("non-empty object returned for workspace B".into()),
                };
            }
            Verdict::Inconclusive(format!(
                "expected 403 or empty 2xx, got {status} — dependency likely unseeded"
            ))
        }
        Expect::NoCanary => {
            if status.is_success() {
                // Canary already checked above; returning the caller's own
                // data here is correct behaviour.
                return Verdict::Safe;
            }
            Verdict::Inconclusive(format!(
                "expected 2xx so tenancy could be observed, got {status} — \
                 dependency likely unseeded"
            ))
        }
    }
}

// ---------- Test -------------------------------------------------------------

/// VALIDATION 5-08-01 / T-05-05 — cross-tenant matrix.
///
/// Every dashboard endpoint must return 403 or empty when accessed with
/// workspace A's JWT while targeting workspace B.
#[sqlx::test]
async fn cross_tenant_matrix(pool: PgPool) -> sqlx::Result<()> {
    let seeded = fixtures::seed_two_workspaces(&pool).await?;

    // Give workspace B something worth stealing, tagged uniquely per run so a
    // sighting can never be coincidental.
    let canary = format!("rls-canary-{}", Uuid::new_v4().simple());
    seed_canary(seeded.workspace_b, &canary).await;

    // Build Redis pool (needed by AppState even if not seeding budget data).
    let _redis_pool = RedisConfig::from_url(redis_url())
        .create_pool(Some(Runtime::Tokio1))
        .expect("redis pool");

    let (_state, router) = build_app(pool);

    // Authenticate as admin_a (workspace A). Minted directly rather than via
    // POST /v1/auth/token: the 2FA gate now forces Admin/Owner logins into
    // the enrollment branch (202 `enroll_required`) instead of returning an
    // access token, and this test needs an authenticated admin session, not
    // the login flow itself — see `fixtures::mint_jwt` for why this bypass
    // is safe.
    let token_a = fixtures::mint_jwt(TEST_JWT_SECRET, seeded.workspace_a, seeded.admin_a, "admin");

    let workspace_b = seeded.workspace_b;
    let cases = matrix_cases();

    let mut leaks: Vec<String> = Vec::new();
    let mut inconclusive: Vec<String> = Vec::new();

    for case in &cases {
        let path = expand_path(case.path_template, workspace_b);
        let body = case.body_fn.map(|f| f(workspace_b));

        let (status, body_val) = send_raw(&router, case.method, &path, body, &token_a).await;

        match classify(status, &body_val, case.expect, &canary) {
            Verdict::Safe => {}
            Verdict::Leak(why) => leaks.push(format!(
                "LEAK: {} {} [{:?}] → {why} (status={status} body={body_val})",
                case.method, path, case.expect
            )),
            Verdict::Inconclusive(why) => inconclusive.push(format!(
                "INCONCLUSIVE: {} {} [{:?}] → {why} (body={body_val})",
                case.method, path, case.expect
            )),
        }
    }

    assert!(
        leaks.is_empty(),
        "Cross-tenant RLS matrix found data leakage on {} endpoint(s):\n{}",
        leaks.len(),
        leaks.join("\n")
    );

    // WS1-4: an unprovable case is a failed case. Previously these were
    // silently counted as safe, which is how the cost-by-model leak stayed
    // green.
    assert!(
        inconclusive.is_empty(),
        "Cross-tenant RLS matrix could not prove isolation for {} endpoint(s) \
         — seed the dependency or mark the case explicitly:\n{}",
        inconclusive.len(),
        inconclusive.join("\n")
    );

    Ok(())
}
