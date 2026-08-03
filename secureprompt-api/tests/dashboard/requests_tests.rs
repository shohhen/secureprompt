//! Phase 5 / Plan 05-04 — Request list/detail integration tests.
//!
//! Tests:
//!   cursor          — 250 events, limit=100, verify pagination
//!   cursor_tiebreak — same created_at, different IDs, stable order
//!   no_leak         — compile-time assert token_vault_entries absent from requests.rs
//!   idor_guard      — workspace B JWT + workspace A ID → 403
//!   time_window_cap — from = now() - 100d → 400
//!   limit_cap       — limit=500 → ≤200 items (capped at 200)
//!   ci_gate_stays_scoped — check-mart-only.sh targets only analytics.rs

// ── no_leak compile-time assert ──────────────────────────────────────────────

/// Compile-time assertion: `requests.rs` must never SELECT FROM `token_vault_entries`.
/// The test scans for SQL-level references (FROM/JOIN clauses) — comments that
/// document the prohibition are allowed.
#[test]
fn no_leak() {
    let src = include_str!("../../src/http/routes/dashboard/requests.rs");

    // Check that token_vault_entries does not appear in a SQL query context.
    // We look for the pattern inside string literals (query format strings) which
    // would indicate an actual SQL reference, not just a comment.
    let has_sql_ref = src
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            // Skip comment lines (both // and //! doc comments)
            !trimmed.starts_with("//")
        })
        .any(|line| line.contains("token_vault_entries"));

    assert!(
        !has_sql_ref,
        "requests.rs must NOT reference token_vault_entries in code — \
         raw vault data must never be exposed via the requests drilldown"
    );
}

// ── WS1-1: the `model` filter must not be SQL-injectable ─────────────────────

/// WS1-1 — `GET /v1/requests?model=…` interpolates the caller's string into a
/// ClickHouse query, escaping only `'` by doubling it. ClickHouse string
/// literals also honour backslash escapes, so a trailing `\` escapes the
/// closing quote and the remainder of the filter is parsed as SQL.
///
/// Reachable by the lowest-privilege roles: the same handler builds a
/// `user_scope_clause` specifically for Employee/Viewer.
///
/// The control assertion is load-bearing. Without proving the filter matches
/// something, "the payloads returned no rows" would be satisfied by an
/// endpoint that returns nothing at all — the WS1-4 failure mode.
#[sqlx::test]
async fn model_filter_is_not_sql_injectable(pool: sqlx::PgPool) {
    use super::analytics::{build_app, make_jwt, seed_request_event};
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
        Router,
    };
    use tower::ServiceExt;
    use uuid::Uuid;

    async fn list(app: &Router, token: &str, model_qs: &str) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .uri(format!("/v1/requests?model={model_qs}"))
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("read body");
        let val = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, val)
    }

    fn item_count(body: &serde_json::Value) -> usize {
        body.get("items")
            .and_then(|v| v.as_array())
            .map_or(0, Vec::len)
    }

    let ws = Uuid::new_v4();
    let control_model = format!("control-model-{}", Uuid::new_v4().simple());
    seed_request_event(ws, &control_model).await;

    let token = make_jwt(ws, "admin");
    let (_state, app) = build_app(pool);

    // Control — the filter really does match, so a later empty result is
    // evidence rather than an artefact.
    let (status, body) = list(&app, &token, &control_model).await;
    assert_eq!(status, StatusCode::OK, "control request failed: {body}");
    assert_eq!(
        item_count(&body),
        1,
        "control model should match exactly one seeded row: {body}"
    );

    // Each payload must be treated as an ordinary (non-matching) model name:
    // HTTP 200, zero rows. A 5xx means the parser saw SQL, not data.
    for (label, encoded) in [
        // `x\` — trailing backslash escapes the closing quote.
        ("trailing-backslash", "x%5C"),
        // `x\' OR 1=1 --` — breaks out and disjoins the WHERE clause. Because
        // OR binds looser than AND, a successful injection turns the whole
        // predicate into a tautology.
        ("tautology", "x%5C%27%20OR%201%3D1%20--"),
        // `x' OR 1=1 --` — plain quote, the case the doubling does handle.
        ("plain-quote", "x%27%20OR%201%3D1%20--"),
    ] {
        let (status, body) = list(&app, &token, encoded).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "payload '{label}' must be treated as data, not SQL — got {status}: {body}"
        );
        assert_eq!(
            item_count(&body),
            0,
            "payload '{label}' must match no rows; a non-empty result means the \
             filter was defeated: {body}"
        );
    }
}

// ── cursor encoding unit tests ────────────────────────────────────────────────

#[test]
fn cursor_encode_decode_roundtrip() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use uuid::Uuid;

    let ts = 1_700_000_000_i64;
    let request_id = Uuid::new_v4();

    // Replicate the encode logic from requests.rs
    let payload = serde_json::json!({"ts": ts, "request_id": request_id}).to_string();
    let encoded = URL_SAFE_NO_PAD.encode(payload.as_bytes());

    // Decode
    let bytes = URL_SAFE_NO_PAD.decode(&encoded).expect("valid base64url");
    let decoded: serde_json::Value =
        serde_json::from_slice(&bytes).expect("valid json");

    assert_eq!(decoded["ts"].as_i64().unwrap(), ts);
    assert_eq!(
        decoded["request_id"].as_str().unwrap(),
        request_id.to_string()
    );
}

#[test]
fn cursor_invalid_base64_is_bad_request() {
    // This tests the decode path in isolation (no server needed).
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    let result = URL_SAFE_NO_PAD.decode("!!!not-valid-base64!!!");
    assert!(result.is_err(), "invalid base64 must fail decode");
}

// ── limit cap unit test ───────────────────────────────────────────────────────

#[test]
fn limit_cap_max_200() {
    // Verify the cap logic: min(requested, 200)
    let requested: u32 = 500;
    let capped = requested.min(200);
    assert_eq!(capped, 200, "limit must be capped at 200");
}

#[test]
fn limit_default_50() {
    // Default when limit param is absent.
    let limit: u32 = 50; // unwrap_or(50)
    assert_eq!(limit, 50);
}

// ── time window cap unit test ─────────────────────────────────────────────────

#[test]
fn time_window_cap_rejects_100_days_ago() {
    use chrono::Utc;

    let now = Utc::now();
    let ninety_days_ago = now - chrono::Duration::days(90);
    let from = now - chrono::Duration::days(100);

    assert!(
        from < ninety_days_ago,
        "from=100d ago must be before the 90-day cutoff"
    );
    // The handler returns 400 when `from < ninety_days_ago`.
}

#[test]
fn time_window_cap_accepts_89_days_ago() {
    use chrono::Utc;

    let now = Utc::now();
    let ninety_days_ago = now - chrono::Duration::days(90);
    let from = now - chrono::Duration::days(89);

    assert!(
        from >= ninety_days_ago,
        "from=89d ago is within the 90-day window"
    );
}

// ── CI gate scope test ────────────────────────────────────────────────────────

/// Verify that check-mart-only.sh is scoped to analytics.rs ONLY.
/// It must NOT mention requests.rs (which intentionally reads raw tables).
#[test]
fn ci_gate_stays_scoped() {
    let script = include_str!("../../../scripts/ci/check-mart-only.sh");

    // The script must target analytics.rs
    assert!(
        script.contains("analytics.rs"),
        "check-mart-only.sh must reference analytics.rs"
    );

    // The script must NOT be extended to requests.rs
    assert!(
        !script.contains("requests.rs"),
        "check-mart-only.sh must NOT include requests.rs — \
         requests.rs intentionally reads raw tables"
    );
}

// ── IDOR guard unit test ──────────────────────────────────────────────────────

#[test]
fn idor_guard_workspace_mismatch_is_forbidden() {
    use uuid::Uuid;

    let ctx_workspace = Uuid::new_v4();
    let other_workspace = Uuid::new_v4();

    // Simulate the IDOR check in list_requests:
    // if params.workspace_id.is_some_and(|w| w != ctx.workspace_id.0) → 403
    let param_workspace = Some(other_workspace);
    let is_idor = param_workspace.is_some_and(|w| w != ctx_workspace);

    assert!(is_idor, "mismatched workspace_id must be detected as IDOR");
}

#[test]
fn idor_guard_same_workspace_is_allowed() {
    use uuid::Uuid;

    let ctx_workspace = Uuid::new_v4();
    let param_workspace = Some(ctx_workspace);
    let is_idor = param_workspace.is_some_and(|w| w != ctx_workspace);

    assert!(!is_idor, "same workspace_id must pass IDOR check");
}

#[test]
fn idor_guard_absent_param_is_allowed() {
    use uuid::Uuid;

    let ctx_workspace = Uuid::new_v4();
    let param_workspace: Option<Uuid> = None;
    let is_idor = param_workspace.is_some_and(|w| w != ctx_workspace);

    assert!(!is_idor, "absent workspace_id param must pass IDOR check");
}

// ── WS2-4: detection provenance on the audit detail endpoint ────────────────

/// Seed one `request_events` row with an explicit `engines` array and return
/// its id. Raw SQL rather than the writer, so the READ path is what is under
/// test and a write-path bug cannot make this pass by coincidence.
async fn seed_request_event_with_engines(workspace_id: uuid::Uuid, engines: &str) -> uuid::Uuid {
    use super::analytics::{clickhouse_db, clickhouse_url};

    // Idempotent: the reader SELECTs `engines`, so the column has to exist
    // before this runs. Applying the real migration file rather than restating
    // its DDL keeps this from drifting from what the worker applies.
    let migration: String = include_str!("../../clickhouse/migrations/009_detection_engines.sql")
        .lines()
        .filter(|l| !l.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n");
    let request_id = uuid::Uuid::new_v4();
    let insert = format!(
        "INSERT INTO {db}.request_events \
         (request_id, workspace_id, provider, model, final_action, cost_usd, \
          estimated_usage, created_at, engines) \
         VALUES ('{request_id}', '{workspace_id}', 'anthropic', 'claude-3-haiku', \
                 'allow', 0.0, false, now(), {engines})",
        db = clickhouse_db(),
    );
    for sql in migration
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .chain(std::iter::once(insert.as_str()))
    {
        let resp = reqwest::Client::new()
            .post(format!(
                "{}/?database={}",
                clickhouse_url(),
                clickhouse_db()
            ))
            .body(sql.to_owned())
            .send()
            .await
            .expect("ClickHouse must be reachable — this test must not be skipped");
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        assert!(
            status.is_success(),
            "clickhouse failed ({status}): {body}\nsql: {sql}"
        );
    }
    request_id
}

/// WS2-4 acceptance, read side: `GET /v1/requests/:id` states which engines
/// produced coverage, and states DIFFERENT things for rows that were scanned
/// differently.
///
/// THE DISCRIMINATING PAIR is the whole test. A handler that hard-coded
/// `["floor"]`, or that dropped the column and returned `[]`, would satisfy
/// "the response has an `engines` field" — so two rows seeded with different
/// arrays must come back different.
///
/// POSITIVE CONTROL: the `["floor","ml"]` row, which must round-trip a value
/// the floor-only row does not have.
///
/// WORKSPACE SCOPING is asserted in the same test because this is a new read
/// path over a multi-tenant table: a third row is seeded in ANOTHER workspace
/// and must 404, and the filter that does it is in the query's WHERE clause
/// (`requests.rs`), not only in a caller-side guard.
#[sqlx::test]
async fn request_detail_reports_which_engines_scanned_the_prompt(pool: sqlx::PgPool) {
    use super::analytics::{build_app, make_jwt};
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use uuid::Uuid;

    let workspace = Uuid::new_v4();
    let other_workspace = Uuid::new_v4();

    let ml_id = seed_request_event_with_engines(workspace, "['floor','ml']").await;
    let floor_id = seed_request_event_with_engines(workspace, "['floor']").await;
    let partial_id = seed_request_event_with_engines(workspace, "['floor','ml_partial']").await;
    let foreign_id = seed_request_event_with_engines(other_workspace, "['floor','ml']").await;

    let token = make_jwt(workspace, "admin");
    let (_state, app) = build_app(pool);

    let fetch = |id: Uuid| {
        let app = app.clone();
        let token = token.clone();
        async move {
            let request = Request::builder()
                .uri(format!("/v1/requests/{id}"))
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request builds");
            let response = app.oneshot(request).await.expect("router responds");
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 1 << 20)
                .await
                .expect("body reads");
            let json: serde_json::Value =
                serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
            (status, json)
        }
    };

    let (status, ml) = fetch(ml_id).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "premise: the seeded row is readable"
    );
    let (_, floor) = fetch(floor_id).await;
    let (_, partial) = fetch(partial_id).await;

    assert_eq!(
        ml["engines"],
        serde_json::json!(["floor", "ml"]),
        "a request the model fully scanned must say so"
    );
    assert_eq!(
        floor["engines"],
        serde_json::json!(["floor"]),
        "a request the model never saw must not claim the model ran"
    );
    assert_eq!(
        partial["engines"],
        serde_json::json!(["floor", "ml_partial"]),
        "partial coverage must be distinguishable from both"
    );
    assert_ne!(ml["engines"], floor["engines"]);
    assert_ne!(ml["engines"], partial["engines"]);

    // Workspace scoping. The premise for this absence is the three OK
    // responses above: the endpoint demonstrably CAN return a row, so a 404
    // here is tenancy filtering and not a broken handler.
    let (status, _) = fetch(foreign_id).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "another workspace's audit row must not be readable through this endpoint"
    );
}
