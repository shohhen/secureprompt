//! Phase 5 / Plan 05-06 — Cross-tenant **IDOR** matrix (VALIDATION 5-08-01 /
//! T-05-05).
//!
//! Iterates over every dashboard endpoint that accepts a workspace-scoped
//! parameter. For each endpoint, issues the request using a JWT minted for
//! workspace A while targeting workspace B. Asserts that every response is
//! either HTTP 403 Forbidden or returns an empty result set (no data leakage).
//!
//! The test is data-driven via a `Case` manifest so new endpoints can be added
//! by appending a row — no new test function required.
//!
//! # What this file proves, and what it does NOT (MR1 review I5)
//!
//! It proves **application** tenancy: the handler-level IDOR guards, and the
//! `WHERE workspace_id = ?` predicates in the ClickHouse readers underneath
//! them. It does **not** prove Postgres row-level security, and the earlier
//! header — "Cross-tenant RLS matrix test" — claimed otherwise.
//!
//! `#[sqlx::test]` connects as the role `DATABASE_URL` names, which for the
//! compose stack is `POSTGRES_USER` — a superuser, and a superuser bypasses
//! RLS including `FORCE`. Nothing here sets `app.current_workspace_id` on the
//! connection the app reads through, and nothing does `SET LOCAL ROLE`.
//! Deleting the whole `CREATE POLICY workspace_isolation` block from
//! `001_init.sql` reddens no assertion in this file. That premise is not left
//! as prose — `the_matrix_role_bypasses_rls` below asserts it on the wire, so
//! the day it stops being true this note fails instead of quietly rotting.
//!
//! RLS itself is covered, and covered properly, by the suites that build a
//! non-`BYPASSRLS` connection on purpose: `tests/rls_unscoped_read_is_invisible.rs`,
//! `tests/rls_scope_readback.rs`, `tests/rls_repo_scope.rs`,
//! `tests/rls_missing_predicate.rs`, `tests/db_role_split.rs` and the
//! `tests/migration_*_rls.rs` family.
//!
//! The MODULE is named `cross_tenant_idor` (see `dashboard/mod.rs`) so the
//! test IDs cargo prints say what is actually being proved. The FILE keeps its
//! path deliberately: several dated plan and audit documents cite
//! `tests/dashboard/rls_matrix.rs` by name, and a path that no longer resolves
//! is worse for the next auditor than a path whose contents say plainly, in
//! the first screen, what they are.

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
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
                "ClickHouse unreachable at {} — the IDOR matrix cannot prove \
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

/// Seed one `policy_events` row for `workspace_id` carrying `canary` as the
/// rule NAME.
///
/// MR1 review I7: two of the four `NoCanary` cases —
/// `/v1/analytics/policy-violations` and `/v1/analytics/latency-pctiles` —
/// asserted the absence of a canary the endpoint could not have returned.
/// The only canary was a `request_events` row, and `query_policy_violations`
/// reads `mart_policy_violations` and falls back to `policy_events`; neither
/// touches `request_events` and both were empty. `body.contains(canary)` was
/// therefore false unconditionally, and removing `WHERE workspace_id = ?` from
/// `dashboard_reader.rs` left both cases green.
///
/// `rule_name` is the carrier because `PolicyViolationsRow` serialises it, so
/// a row belonging to another tenant is visible in the response body — which
/// is the only thing the matrix's classifier can see.
async fn seed_policy_event(workspace_id: Uuid, canary: &str) {
    clickhouse_exec(
        format!(
            "INSERT INTO {db}.policy_events \
             (request_id, workspace_id, rule_id, rule_name, action, dry_run, created_at) \
             VALUES ('{rid}', '{ws}', '{rule}', '{canary}', 'redact', false, now())",
            db = clickhouse_db(),
            rid = Uuid::new_v4(),
            rule = Uuid::new_v4(),
            ws = workspace_id,
        ),
        "seeding policy_events",
    )
    .await;
}

/// Seed one `latency_samples` row for `workspace_id` carrying `canary` as the
/// MODEL name — the `latency-pctiles` half of I7, same reasoning as
/// `seed_policy_event`. `LatencyPctilesRow` serialises `model`, and
/// `query_latency_pctiles` falls back to `latency_samples`.
async fn seed_latency_sample(workspace_id: Uuid, canary: &str) {
    clickhouse_exec(
        format!(
            "INSERT INTO {db}.latency_samples \
             (request_id, workspace_id, model, latency_ms, created_at) \
             VALUES ('{rid}', '{ws}', '{canary}', 120, now())",
            db = clickhouse_db(),
            rid = Uuid::new_v4(),
            ws = workspace_id,
        ),
        "seeding latency_samples",
    )
    .await;
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
        // `/v1/providers?workspace_id={B}` and `/v1/policy-rules?workspace_id={B}`
        // used to sit here and were REMOVED by MR1 review I6. Neither handler
        // takes a `workspace_id` query parameter — `list_providers` and
        // `list_rules` are `(State, Extension<JwtAuthContext>)` and axum
        // discards the query string — so there was no production line whose
        // deletion could redden them, which directly contradicts
        // `Expect::ForbiddenOrEmpty`'s doc ("the guard should reject before
        // any query runs"). They were fixtures named for a code path that
        // does not exist.
        //
        // The property those endpoints DO have — a supplied `workspace_id`
        // must not change the answer, and must never surface another tenant's
        // rows — is real and was untested. It is now
        // `providers_and_policy_rules_ignore_a_workspace_id_parameter` below,
        // where it can be falsified by a production line.
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
    // All four of them, since MR1 review I7: the canary is now seeded into
    // `policy_events` and `latency_samples` as well as `request_events`, so
    // `policy-violations` and `latency-pctiles` can finally see the row whose
    // absence they assert. Before that, this comment was true only of
    // `usage-daily` and `cost-by-model`.
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
    // WS3-5. Takes no workspace parameter at all — the workspace comes from
    // the JWT — so `NoCanary` is the only shape that applies. What this case
    // actually pins is that the endpoint ANSWERS 2xx for an authenticated
    // admin: a 403 or 500 lands as `Inconclusive`, which fails the run.
    //
    // It cannot pin tenancy: the canary is a model NAME and this endpoint
    // returns counts, so an unfiltered count query would still show no
    // canary. `data_inventory_is_workspace_scoped` below carries that half,
    // exactly as `mart_cost_by_model_is_workspace_scoped` does for the mart.
    cases.push(Case {
        method: "GET",
        path_template: "/v1/data-inventory",
        body_fn: None,
        expect: Expect::NoCanary,
    });
    // WS3-6. Same shape as data-inventory: no workspace parameter at all, so
    // `NoCanary` is the only form that applies and what it pins is that an
    // authenticated admin gets a 2xx (a 403 or 500 lands as `Inconclusive`,
    // which fails the run). It cannot pin tenancy — the canary is a model NAME
    // in `request_events` and this endpoint reads `detection_class_counts`,
    // where the matrix seeds nothing. `leak_report_is_workspace_scoped` below
    // carries that half.
    cases.push(Case {
        method: "GET",
        path_template: Box::leak(format!("/v1/leak-report?{range}").into_boxed_str()),
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

/// The header's scope claim, asserted rather than asserted-in-prose.
///
/// MR1 review I5 found this file named and documented as an *RLS* matrix when
/// every connection it uses bypasses RLS entirely. A comment saying so would
/// be the same species of defect as the one being fixed — a claim about the
/// runtime that nothing checks — so the claim is a test.
///
/// If this ever reddens, `#[sqlx::test]`'s role stopped bypassing RLS, the
/// matrix's verdicts became partly attributable to `workspace_isolation`, and
/// the header above has to be rewritten before the results mean what they say.
/// Redden it deliberately by pointing `DATABASE_URL` at a non-superuser role.
#[sqlx::test]
async fn the_matrix_role_bypasses_rls(pool: PgPool) -> sqlx::Result<()> {
    let (role, is_super, bypasses): (String, bool, bool) = sqlx::query_as(
        "SELECT current_user::text, rolsuper, rolbypassrls \
         FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&pool)
    .await?;

    assert!(
        is_super || bypasses,
        "the matrix now runs as `{role}` (rolsuper={is_super}, \
         rolbypassrls={bypasses}), which does NOT bypass row-level security. \
         Every verdict in this file is now partly attributable to \
         `workspace_isolation` rather than to the handler guards it is written \
         to test — rewrite this file's header before trusting a green run."
    );

    Ok(())
}

/// VALIDATION 5-08-01 / T-05-05 — cross-tenant matrix.
///
/// Every dashboard endpoint must return 403 or empty when accessed with
/// workspace A's JWT while targeting workspace B.
#[sqlx::test]
async fn cross_tenant_matrix(pool: PgPool) -> sqlx::Result<()> {
    let seeded = fixtures::seed_two_workspaces(&pool).await?;

    // Give workspace B something worth stealing, tagged uniquely per run so a
    // sighting can never be coincidental.
    //
    // THREE tables, not one (MR1 review I7). The canary used to be a
    // `request_events` row only, and `policy-violations` / `latency-pctiles`
    // read `policy_events` / `latency_samples` — so their `NoCanary` cases
    // asserted the absence of something the endpoint structurally could not
    // return, and stayed green with `WHERE workspace_id = ?` deleted from
    // `dashboard_reader.rs`.
    let canary = format!("rls-canary-{}", Uuid::new_v4().simple());
    seed_canary(seeded.workspace_b, &canary).await;
    seed_policy_event(seeded.workspace_b, &canary).await;
    seed_latency_sample(seeded.workspace_b, &canary).await;

    // And give workspace A — the CALLER — its own rows in the same three
    // tables (MR1 review I6).
    //
    // Only B was seeded before, so for every endpoint that already scopes by
    // `ctx.workspace_id` the `ForbiddenOrEmpty` verdict was reachable two
    // ways: 403 from the IDOR guard, or `200 []` because the caller's own
    // workspace was empty. Deleting all four guards at
    // `analytics.rs:80-88,…` and the one at `requests.rs:238-244` left the
    // matrix green — measured. With A seeded, guard deletion returns A's own
    // rows for a request that named B, `rows_of` sees a non-empty array, and
    // the verdict is `Leak`.
    //
    // A's marker is deliberately NOT the canary: a canary sighting is a leak
    // by definition in `classify`, and A seeing its own data is correct.
    let own = format!("rls-own-{}", Uuid::new_v4().simple());
    seed_canary(seeded.workspace_a, &own).await;
    seed_policy_event(seeded.workspace_a, &own).await;
    seed_latency_sample(seeded.workspace_a, &own).await;

    // MR1 review M3: a `let _redis_pool = …` stood here under the comment
    // "needed by AppState even if not seeding budget data". It was not.
    // `AppState::new` builds its own pool from `config.redis.url`
    // (`src/app_state.rs:81`), which is what `build_app` below goes through,
    // and nothing in this file ever read the binding. Deleted rather than
    // renamed: a discarded value under a comment asserting a dependency that
    // does not exist is worse than no line at all — the next reader adds one
    // to the next matrix test.
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

/// MR1 review I6(c) — what the two deleted matrix rows should have been.
///
/// The matrix carried `/v1/providers?workspace_id={B}` and
/// `/v1/policy-rules?workspace_id={B}` as `Expect::ForbiddenOrEmpty`, whose
/// doc says "the guard should reject before any query runs". Neither handler
/// has such a guard, or could: `list_providers` (`providers.rs`) and
/// `list_rules` (`policy_rules.rs`) are `(State, Extension<JwtAuthContext>)`,
/// so axum parses no query string and there is nothing to compare. No
/// production line's deletion reddened those rows. They are gone.
///
/// The property these endpoints really have is worth pinning and was not
/// pinned anywhere: the workspace comes from the JWT only, so supplying
/// `workspace_id={B}` must change nothing — the caller still gets their own
/// rows, and never B's. That is the same guarantee the deleted rows were
/// gesturing at, expressed so a production line can falsify it.
///
/// Three defences against a vacuous pass:
///
/// 1. **Premise / positive control** — A's own provider and rule MUST appear.
///    An empty or errored response fails here rather than passing the
///    tenancy assertion by returning nothing.
/// 2. **B is really seeded** — B's rows go in under B's own armed scope, so
///    "B is absent" cannot be true merely because B has nothing.
/// 3. **Both spellings** — with and without the parameter. If a future change
///    starts honouring `workspace_id`, the parameterised call returns B's
///    rows and the tenancy assertion catches it.
///
/// Falsifier (verified): delete `WHERE workspace_id = $1` from
/// `provider_repo::list_providers` or `policy_repo::list_rules` — the two
/// queries whose comments say "this WHERE, not `begin_scoped`, is the real
/// isolation boundary. Do not remove." Both reddened.
#[sqlx::test]
async fn providers_and_policy_rules_ignore_a_workspace_id_parameter(
    pool: PgPool,
) -> sqlx::Result<()> {
    let seeded = fixtures::seed_two_workspaces(&pool).await?;

    let run = Uuid::new_v4().simple().to_string();
    let provider_a = format!("provider-own-{run}");
    let provider_b = format!("provider-other-{run}");
    let rule_a = format!("rule-own-{run}");
    let rule_b = format!("rule-other-{run}");

    // Written from inside each workspace's own armed scope, the way
    // `seed_two_workspaces` writes `api_keys`: one scope names exactly one
    // tenant, so the two tenants cannot share a transaction.
    for (workspace_id, provider, rule) in [
        (seeded.workspace_a, &provider_a, &rule_a),
        (seeded.workspace_b, &provider_b, &rule_b),
    ] {
        let mut tx = fixtures::scoped(&pool, workspace_id).await;
        sqlx::query(
            "INSERT INTO providers (id, workspace_id, name, provider_type)
             VALUES ($1, $2, $3, 'openai')",
        )
        .bind(Uuid::new_v4())
        .bind(workspace_id)
        .bind(provider)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO policy_rules (id, workspace_id, name, action)
             VALUES ($1, $2, $3, 'redact')",
        )
        .bind(Uuid::new_v4())
        .bind(workspace_id)
        .bind(rule)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
    }

    let token_a = fixtures::mint_jwt(TEST_JWT_SECRET, seeded.workspace_a, seeded.admin_a, "admin");
    let (_state, router) = build_app(pool);

    for (endpoint, own, other) in [
        ("/v1/providers", &provider_a, &provider_b),
        ("/v1/policy-rules", &rule_a, &rule_b),
    ] {
        for path in [
            endpoint.to_owned(),
            format!("{endpoint}?workspace_id={}", seeded.workspace_b),
        ] {
            let (status, body) = send_raw(&router, "GET", &path, None, &token_a).await;
            assert_eq!(status, StatusCode::OK, "{path} failed: {body}");

            let rendered = body.to_string();
            assert!(
                rendered.contains(own.as_str()),
                "positive control: workspace A's own row '{own}' is missing \
                 from {path}, so the absence of B's row proves nothing: {body}"
            );
            assert!(
                !rendered.contains(other.as_str()),
                "workspace B's row '{other}' reached workspace A via {path}: {body}"
            );
        }
    }

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

/// WS3-5 — tenancy on `GET /v1/data-inventory`.
///
/// The matrix case above can only prove this endpoint answers 2xx. It returns
/// COUNTS, so the canary-substring check that catches every other leak here is
/// structurally blind to it: an unfiltered `SELECT count()` returns a number
/// containing no canary and the matrix stays green while the endpoint reports
/// the whole cluster's row counts to one tenant. That is the same shape as the
/// `cost-by-model` leak this branch already shipped — a guard that fired only
/// on a supplied parameter over a query that never filtered — so it gets its
/// own test rather than a matrix row.
///
/// Three defences against a vacuous pass:
///
/// 1. **Premise** — both workspaces' row counts are confirmed by direct
///    `count()` queries against ClickHouse before the request, so "A sees 4"
///    cannot be true merely because B was never seeded.
/// 2. **Positive control** — A's own count MUST come back, and it is non-zero
///    and distinct. An empty or errored response fails here rather than
///    passing the tenancy assertion by returning nothing.
/// 3. **Distinguishable totals** — A and B are seeded DIFFERENT, non-zero
///    counts, so `own == 4` and `own == 4 + 9` are different assertions. A
///    count query missing its tenancy predicate reports 13.
///
/// Falsifier (verified, see the WS3-5 report): replace
/// `WHERE workspace_id = toUUID('{ws}')` with `WHERE 1 = 1` in
/// `data_inventory::ch_count` — this test fails with `13 != 4`.
#[sqlx::test]
async fn data_inventory_is_workspace_scoped(pool: PgPool) -> sqlx::Result<()> {
    // Fresh UUIDs: `request_events` is shared across every run against this
    // ClickHouse, and seeding under the matrix's fixed workspaces would change
    // what `cross_tenant_matrix` sees.
    let ws_a = fixtures::seed_unique_workspace(&pool).await?;
    let ws_b = fixtures::seed_unique_workspace(&pool).await?;

    let run = Uuid::new_v4().simple().to_string();
    for _ in 0..4 {
        seed_canary(ws_a.workspace_id, &format!("inv-own-{run}")).await;
    }
    for _ in 0..9 {
        seed_canary(ws_b.workspace_id, &format!("inv-other-{run}")).await;
    }

    // ---- Premise assertions, before anything is asserted to be absent ------
    assert_eq!(
        clickhouse_count(
            "request_events",
            &format!("workspace_id = toUUID('{}')", ws_a.workspace_id)
        )
        .await,
        4,
        "premise failed: workspace A has no request_events rows, so the \
         positive control below could not distinguish a live count from a zero"
    );
    assert_eq!(
        clickhouse_count(
            "request_events",
            &format!("workspace_id = toUUID('{}')", ws_b.workspace_id)
        )
        .await,
        9,
        "premise failed: no OTHER tenant's rows exist, so an unfiltered count \
         would return the same number as a correct one and this test could not \
         tell them apart"
    );

    let token_a = fixtures::mint_jwt(TEST_JWT_SECRET, ws_a.workspace_id, ws_a.admin_id, "admin");
    let (_state, router) = build_app(pool);

    let (status, body) = send_raw(&router, "GET", "/v1/data-inventory", None, &token_a).await;
    assert_eq!(status, StatusCode::OK, "data-inventory failed: {body}");

    let events = body["artifacts"]
        .as_array()
        .unwrap_or_else(|| panic!("`artifacts` must be an array: {body}"))
        .iter()
        .find(|entry| entry["class"] == json!("request_events"))
        .unwrap_or_else(|| panic!("no `request_events` class in the inventory: {body}"));

    // ---- Positive control: the permitted count DOES come back --------------
    assert_eq!(
        events["row_count_status"],
        json!("counted"),
        "the count did not run, so the tenancy assertion below would pass on \
         a null: {events}"
    );

    // ---- The tenancy assertion --------------------------------------------
    assert_eq!(
        events["row_count"],
        json!(4),
        "workspace A must see only its own 4 rows. Seeing 13 means the count \
         query is missing its tenancy predicate and every tenant's row counts \
         are being reported to A: {events}"
    );

    Ok(())
}

/// Seed one `detection_class_counts` row for `workspace_id`.
///
/// Written directly rather than by driving a request through the pipeline:
/// this file's job is the tenancy predicate, and `tests/leak_report.rs`
/// already covers the write path end-to-end.
async fn seed_detection_count(workspace_id: Uuid, model: &str, class: &str, count: u32) {
    clickhouse_exec(
        format!(
            "INSERT INTO {db}.detection_class_counts \
             (request_id, workspace_id, created_at, model, user_id, api_key_name, \
              entity_class, entity_count) \
             VALUES ('{rid}', '{ws}', now(), '{model}', NULL, NULL, '{class}', {count})",
            db = clickhouse_db(),
            rid = Uuid::new_v4(),
            ws = workspace_id,
        ),
        "seeding detection_class_counts",
    )
    .await;
}

/// WS3-6 — `GET /v1/leak-report` takes no workspace parameter, so the matrix
/// above can only prove it answers. This proves it answers with the CALLER'S
/// data and nobody else's.
///
/// The three defences, matching `data_inventory_is_workspace_scoped`:
///
/// 1. **Premise** — both workspaces' rows are confirmed by direct `count()`
///    against ClickHouse first, so "A sees 4" cannot be true merely because B
///    was never seeded.
/// 2. **Positive control** — A's own total MUST come back non-zero, and B's
///    canary model MUST appear in B's OWN report. An empty or errored response
///    fails there rather than passing the tenancy assertion by returning
///    nothing.
/// 3. **Distinguishable totals** — A and B are seeded DIFFERENT, non-zero
///    counts (4 and 9), so `4` and `13` are different assertions. A query
///    missing its tenancy predicate reports 13.
///
/// Falsifier (VERIFIED, and not where it was first assumed): replace
/// `workspace_id = ?` with `workspace_id = workspace_id` in
/// `leak_report::SCOPE`. This test then fails at the POSITIVE CONTROL, not at
/// the tenancy assertion — B's total comes back as every workspace's rows in a
/// shared, never-reset ClickHouse, which is far more than 9. The tenancy
/// assertion is never reached. That is still a correct falsification, and it
/// is written down rather than guessed because the obvious prediction
/// (`13 != 4`) is wrong: it would only hold against a database containing
/// exactly these two tenants.
#[sqlx::test]
async fn leak_report_is_workspace_scoped(pool: PgPool) -> sqlx::Result<()> {
    let ws_a = fixtures::seed_unique_workspace(&pool).await?;
    let ws_b = fixtures::seed_unique_workspace(&pool).await?;

    let run = Uuid::new_v4().simple().to_string();
    let model_a = format!("leak-own-{run}");
    let model_b = format!("leak-other-{run}");
    seed_detection_count(ws_a.workspace_id, &model_a, "PERSON", 4).await;
    seed_detection_count(ws_b.workspace_id, &model_b, "PINFL", 9).await;

    // ---- Premise: both tenants really have rows ---------------------------
    assert_eq!(
        clickhouse_count(
            "detection_class_counts",
            &format!("workspace_id = toUUID('{}')", ws_a.workspace_id)
        )
        .await,
        1,
        "premise failed: workspace A has no counts row, so the positive \
         control below could not distinguish a live query from an empty table"
    );
    assert_eq!(
        clickhouse_count(
            "detection_class_counts",
            &format!("workspace_id = toUUID('{}')", ws_b.workspace_id)
        )
        .await,
        1,
        "premise failed: no OTHER tenant's rows exist, so an unfiltered query \
         would return the same numbers as a correct one"
    );

    let (_state, router) = build_app(pool);
    let path = format!("/v1/leak-report?{}", date_range());

    // ---- Positive control: B's canary is visible in B's OWN report ---------
    let token_b = fixtures::mint_jwt(TEST_JWT_SECRET, ws_b.workspace_id, ws_b.admin_id, "admin");
    let (status_b, body_b) = send_raw(&router, "GET", &path, None, &token_b).await;
    assert_eq!(
        status_b,
        StatusCode::OK,
        "leak-report failed for B: {body_b}"
    );
    assert_eq!(
        body_b["totals"]["entities_detected"],
        json!(9),
        "positive control: B must see its own 9, or the absence of 9 from A's \
         report proves nothing: {body_b}"
    );

    // ---- The tenancy assertion --------------------------------------------
    let token_a = fixtures::mint_jwt(TEST_JWT_SECRET, ws_a.workspace_id, ws_a.admin_id, "admin");
    let (status_a, body_a) = send_raw(&router, "GET", &path, None, &token_a).await;
    assert_eq!(
        status_a,
        StatusCode::OK,
        "leak-report failed for A: {body_a}"
    );
    assert_eq!(
        body_a["totals"]["entities_detected"],
        json!(4),
        "workspace A must see only its own 4 entities. Seeing 13 means the \
         query is missing its tenancy predicate and every tenant's detection \
         counts are being reported to A: {body_a}"
    );
    assert!(
        !body_a.to_string().contains(&model_b),
        "another tenant's destination model reached A's leak report: {body_a}"
    );
    Ok(())
}
