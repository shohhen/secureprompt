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

/// POST a statement to the test `ClickHouse`, failing loudly with the server's
/// own error text. Same "never skip" stance as `seed_canary`: an unreachable or
/// erroring datastore must fail the run, not silently weaken it.
async fn clickhouse_exec(sql: String, what: &str) -> String {
    let resp = reqwest::Client::new()
        .post(clickhouse_url())
        .body(sql)
        .send()
        .await
        .unwrap_or_else(|e| {
            panic!(
                "ClickHouse unreachable at {} while {what}: {e}",
                clickhouse_url()
            )
        });

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "ClickHouse {what} failed ({status}): {body}"
    );
    body
}

/// `SELECT count()` over one table, used for premise assertions.
async fn clickhouse_count(table: &str, predicate: &str) -> u64 {
    let body = clickhouse_exec(
        format!(
            "SELECT count() FROM {db}.{table} WHERE {predicate}",
            db = clickhouse_db()
        ),
        "counting rows",
    )
    .await;
    body.trim()
        .parse()
        .unwrap_or_else(|e| panic!("count() did not return a number ({body:?}): {e}"))
}

/// Create `mart_cost_by_model` with its production shape.
///
/// Columns and types are transcribed from the two authorities that must agree:
/// `secureprompt-analytics/models/marts/mart_cost_by_model.sql` (grain and
/// column list) and `analytics::dashboard_reader::CostByModelRow` (the Rust
/// types the reader deserializes into — `u64` → `UInt64`, `f64` → `Float64`,
/// `NaiveDate` → `Date`). Engine, `ORDER BY`, and `PARTITION BY` are copied
/// from the dbt model's `config()` block.
async fn create_mart_cost_by_model() {
    clickhouse_exec(
        format!(
            "CREATE TABLE IF NOT EXISTS {db}.mart_cost_by_model \
             (workspace_id UUID, \
              model String, \
              usage_date Date, \
              daily_cost_usd Float64, \
              daily_request_count UInt64, \
              rolling_7d_cost_usd Float64, \
              rolling_30d_cost_usd Float64) \
             ENGINE = MergeTree \
             PARTITION BY toYYYYMM(usage_date) \
             ORDER BY (workspace_id, model, usage_date)",
            db = clickhouse_db()
        ),
        "creating mart_cost_by_model",
    )
    .await;
}

/// Seed one `mart_cost_by_model` row dated today.
///
/// The rolling-window figures are passed in deliberately: the raw fallback
/// cannot compute them and sets both equal to the daily cost, so a caller that
/// seeds `rolling != daily` can tell from the response body alone which code
/// path answered.
async fn seed_mart_row(ws: Uuid, model: &str, daily: f64, rolling_7d: f64, rolling_30d: f64) {
    clickhouse_exec(
        format!(
            "INSERT INTO {db}.mart_cost_by_model \
             (workspace_id, model, usage_date, daily_cost_usd, daily_request_count, \
              rolling_7d_cost_usd, rolling_30d_cost_usd) \
             VALUES ('{ws}', '{model}', today(), {daily}, 3, {rolling_7d}, {rolling_30d})",
            db = clickhouse_db()
        ),
        "seeding mart_cost_by_model",
    )
    .await;
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

/// WS1-2 follow-up — tenancy on the MART ITSELF, not on the raw fallback.
///
/// `cross_tenant_matrix` above can only ever exercise the raw `request_events`
/// fallback: no `mart_cost_by_model` table exists in the test `ClickHouse`, so
/// `query_cost_by_model` always fails into `is_stale_mart_err` and answers from
/// `request_events`. The `WHERE workspace_id = ?` that the WS1-2 fix added to
/// the *mart* query was therefore covered by nothing at all and could have been
/// deleted without reddening a single test.
///
/// This test creates the mart with its production shape, seeds one row for each
/// of two workspaces, and asserts workspace A never sees workspace B's row —
/// while proving the answer actually came from the mart.
///
/// Three separate defences against a vacuous pass, because a tenancy test that
/// "passes" on an error, an empty table, or a silent fallback proves nothing:
///
/// 1. **Premise** — B's mart row is confirmed present by a direct `count()`
///    before the request is issued, so "B is absent from the response" cannot
///    be true merely because B was never seeded.
/// 2. **Positive control** — A's own row, differing from B's only in
///    `workspace_id`, MUST come back. The same assertion set on an empty
///    response would otherwise pass.
/// 3. **Path proof** — the raw fallback aggregates `request_events` (asserted
///    to contain neither canary) and sets `rolling_7d = rolling_30d = daily`.
///    Reading back three DIFFERENT figures is only possible from the mart.
///
/// Falsifier (verified, see the WS1 report): delete `workspace_id = ? AND` from
/// the `mart_cost_by_model` query in `analytics/dashboard_reader.rs` together
/// with its matching `.bind(ws)` — i.e. revert the WS1-2 fix — and this test
/// fails with workspace B's canary model present in workspace A's response.
#[sqlx::test]
async fn mart_cost_by_model_is_workspace_scoped(pool: PgPool) -> sqlx::Result<()> {
    // Fresh UUIDs rather than the fixed `WS_A_UUID`/`WS_B_UUID`: the mart table
    // is created once and shared by every run against this ClickHouse, and
    // seeding rows under the matrix's own workspaces would divert
    // `cross_tenant_matrix`'s cost-by-model case off the fallback it covers.
    let ws_a = fixtures::seed_unique_workspace(&pool).await?;
    let ws_b = fixtures::seed_unique_workspace(&pool).await?;

    create_mart_cost_by_model().await;

    // Run-unique model names, same reasoning as `seed_canary`: a sighting can
    // never be a leftover row from an earlier run.
    let run = Uuid::new_v4().simple().to_string();
    let model_a = format!("mart-own-{run}");
    let model_b = format!("mart-other-{run}");

    // daily / 7d / 30d deliberately all different — see "Path proof" above.
    // Every figure is exactly representable in binary floating point so the
    // JSON round-trip compares exactly.
    seed_mart_row(ws_a.workspace_id, &model_a, 1.25, 77.5, 333.75).await;
    seed_mart_row(ws_b.workspace_id, &model_b, 9.5, 88.25, 444.5).await;

    // ---- Premise assertions, before anything is asserted to be absent ------
    assert_eq!(
        clickhouse_count("mart_cost_by_model", &format!("model = '{model_b}'")).await,
        1,
        "premise failed: workspace B has no mart row, so 'A cannot see B' \
         would pass vacuously"
    );
    assert_eq!(
        clickhouse_count("mart_cost_by_model", &format!("model = '{model_a}'")).await,
        1,
        "premise failed: workspace A has no mart row, so the positive control \
         could not distinguish the mart from the fallback"
    );
    assert_eq!(
        clickhouse_count(
            "request_events",
            &format!("model IN ('{model_a}', '{model_b}')")
        )
        .await,
        0,
        "premise failed: a canary model exists in request_events, so the raw \
         fallback could also have produced it and the path proof is void"
    );

    let token_a = fixtures::mint_jwt(TEST_JWT_SECRET, ws_a.workspace_id, ws_a.admin_id, "admin");
    let (_state, router) = build_app(pool);

    let path = format!("/v1/analytics/cost-by-model?{}", date_range());
    let (status, body) = send_raw(&router, "GET", &path, None, &token_a).await;
    assert_eq!(status, StatusCode::OK, "cost-by-model failed: {body}");

    let rows = body
        .as_array()
        .unwrap_or_else(|| panic!("cost-by-model must return a JSON array, got {body}"));

    // ---- Positive control: the permitted row DOES come back ----------------
    let own = rows
        .iter()
        .find(|row| row["model"] == json!(model_a))
        .unwrap_or_else(|| {
            panic!(
                "positive control failed: workspace A's own mart row \
                 '{model_a}' is missing, so the absence of B's row proves \
                 nothing. Response: {body}"
            )
        });

    // ---- Path proof: this answer came from the mart, not the fallback ------
    assert_eq!(
        own["daily_cost_usd"],
        json!(1.25),
        "unexpected daily cost in {own}"
    );
    assert_eq!(
        own["rolling_7d_cost_usd"],
        json!(77.5),
        "rolling_7d does not match the seeded mart value — the raw fallback \
         answered (it sets rolling_7d = daily), so the mart's own tenancy \
         filter is still untested: {own}"
    );
    assert_eq!(
        own["rolling_30d_cost_usd"],
        json!(333.75),
        "rolling_30d does not match the seeded mart value — see above: {own}"
    );

    // ---- The tenancy assertion --------------------------------------------
    assert!(
        !body.to_string().contains(&model_b),
        "workspace B's mart row '{model_b}' leaked into workspace A's \
         cost-by-model response: {body}"
    );

    Ok(())
}
