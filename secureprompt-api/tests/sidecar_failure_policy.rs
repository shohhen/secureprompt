//! WS2-3 — per-workspace `sidecar_unavailable` policy, end to end.
//!
//! `MlSidecarClient::detect_if_available` returns an empty detection set on
//! four paths that have nothing to do with the prompt: unconfigured client,
//! disabled client (bad scheme), OPEN circuit breaker, and every chunk call
//! failing. An empty set is indistinguishable from "there was no PII", so
//! before WS2-3 an ML outage silently degraded the gateway to the
//! deterministic Rust floor and still answered 200.
//!
//! These tests drive the whole HTTP path (auth → pipeline → provider) with a
//! REAL loopback sidecar for the healthy cases, so the failure assertions
//! cannot pass merely because nothing ever talked to a sidecar. The
//! `anthropic` provider type is used throughout because it is still an echo
//! stub in this workspace — the `openai` type is a real HTTP adapter and its
//! tests are part of the known-red baseline.
//!
//! All fixture PII is synthetic.

mod support;

use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use serde_json::json;
use sqlx::PgPool;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;
use uuid::Uuid;

const API_KEY: &str = "sp_ws2_3_sidecar_policy";
const DEGRADED_HEADER: &str = "x-secureprompt-sidecar-degraded";
/// Synthetic name used as the "PII" the mock sidecar reports.
const SYNTHETIC_NAME: &str = "Anvar Karimov";

// ── Mock ML sidecar ───────────────────────────────────────────────────────

/// A loopback HTTP server that speaks just enough of the sidecar protocol for
/// the gateway request path: `/detect/ner`, `/v1/rag-check` and
/// `/detect/injection`. Every request it serves is captured so a test can
/// assert the gateway ACTUALLY reached it — the difference between a positive
/// control and a test that passes because nothing happened.
struct MockSidecar {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
}

impl MockSidecar {
    /// Serve `/detect/ner` with a single PERSON entity spanning `name` inside
    /// whatever text is sent. The span values do not have to be exact for
    /// these tests — what matters is that a live sidecar returns coverage.
    fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local addr");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&requests);

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut buf = [0u8; 16384];
                let n = stream.read(&mut buf).unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).to_string();

                let body: &[u8] = if request.contains("/detect/ner") {
                    br#"{"entities":[{"entity_type":"PERSON","start":0,"end":13,"score":0.97,"text":"Anvar Karimov","compliance_categories":[]}]}"#
                } else if request.contains("/v1/rag-check") {
                    br#"{"matches":[],"is_match":false}"#
                } else if request.contains("/detect/injection") {
                    br#"{"is_injection":false,"score":0.0}"#
                } else {
                    b"{}"
                };

                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(body);
                sink.lock().expect("request sink mutex").push(request);
            }
        });

        Self { addr, requests }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn ner_requests(&self) -> Vec<String> {
        self.requests
            .lock()
            .expect("request sink mutex")
            .iter()
            .filter(|r| r.contains("/detect/ner"))
            .cloned()
            .collect()
    }
}

/// An address nothing is listening on: bind an ephemeral port, record it,
/// then drop the listener. Connections to it are refused immediately, which
/// is the `AllCallsFailed` outage.
fn dead_sidecar_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);
    format!("http://{addr}")
}

// ── Fixtures ──────────────────────────────────────────────────────────────

async fn seed(pool: &PgPool, workspace_id: Uuid) -> sqlx::Result<()> {
    support::seed_workspace(pool, workspace_id, API_KEY).await?;
    support::seed_provider_and_model(
        pool,
        workspace_id,
        Uuid::new_v4(),
        "anthropic-primary",
        // `anthropic` is still an echo stub in this workspace, so a request
        // that gets past the sidecar gate reaches a working provider and
        // returns 200 — which is what makes "503 vs 200" a real signal.
        "anthropic",
        None,
        "claude-3-haiku",
    )
    .await
}

/// Write an explicit `sidecar_unavailable` choice for the workspace. Tests
/// that exercise the DEFAULT deliberately do not call this.
async fn set_policy(pool: &PgPool, workspace_id: Uuid, value: &str) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO workspace_sidecar_policy (workspace_id, sidecar_unavailable, updated_at)
         VALUES ($1, $2, NOW())
         ON CONFLICT (workspace_id) DO UPDATE SET sidecar_unavailable = EXCLUDED.sidecar_unavailable",
    )
    .bind(workspace_id)
    .bind(value)
    .execute(pool)
    .await
    .map(|_| ())
}

fn chat_request(api_key: &str, stream: bool) -> Request<axum::body::Body> {
    let mut request = support::authorized_request(
        Request::builder()
            .method(Method::POST)
            .uri("/v1/chat/completions"),
        api_key,
        json!({
            "model": "claude-3-haiku",
            "stream": stream,
            "messages": [{
                "role": "user",
                "content": format!("Please summarise the file for {SYNTHETIC_NAME}"),
            }],
        }),
    );
    // `chat_completions` extracts `ConnectInfo<SocketAddr>` for the audit
    // row's client IP. `ServiceExt::oneshot` bypasses the connection layer
    // that normally inserts it, so a router driven directly in-process must
    // supply it or every request 500s before it reaches the pipeline. (This
    // is also the root cause of the known-red baseline in `openai_compat.rs`,
    // `provider_fallback.rs`, `streaming_redaction.rs` and
    // `token_usage_fallback.rs` — deliberately not fixed here.)
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 50_000))));
    request
}

// ── POSITIVE CONTROL ──────────────────────────────────────────────────────

/// With a REACHABLE sidecar, the strictest policy (`block`) must let the
/// request through — and the sidecar must actually have been asked about the
/// real prompt.
///
/// Every "sidecar down → 503" assertion below is worthless without this: it
/// proves the 503s come from the sidecar being unavailable and not from the
/// gate rejecting everything, and it proves the harness can reach a sidecar
/// at all.
#[sqlx::test]
async fn healthy_sidecar_under_block_policy_succeeds(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;
    set_policy(&pool, workspace_id, "block").await?;

    let sidecar = MockSidecar::spawn();
    let app = support::router_with(pool.clone(), &sidecar.url(), "default");
    let response = app
        .oneshot(chat_request(API_KEY, false))
        .await
        .expect("router should respond");

    let status = response.status();
    let degraded = response
        .headers()
        .get(DEGRADED_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = support::response_text(response).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a healthy sidecar must not be blocked even under the strictest policy; body={body}"
    );
    assert!(
        degraded.is_none(),
        "a healthy sidecar must not mark the response degraded"
    );

    let ner = sidecar.ner_requests();
    assert!(
        !ner.is_empty(),
        "the gateway must actually have called /detect/ner — otherwise every \
         'sidecar unavailable' assertion in this file proves nothing"
    );
    assert!(
        ner.iter().any(|r| r.contains(SYNTHETIC_NAME)),
        "the sidecar must have been asked about the REAL prompt text, not an \
         empty probe; captured requests:\n{ner:?}"
    );
    Ok(())
}

// ── block: fail closed on every fail-open path ────────────────────────────

/// Fail-open path 1: no `ML_SIDECAR_URL` at all.
#[sqlx::test]
async fn block_policy_rejects_when_sidecar_unconfigured(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;
    set_policy(&pool, workspace_id, "block").await?;

    let app = support::router_with(pool.clone(), "", "default");
    let response = app
        .oneshot(chat_request(API_KEY, false))
        .await
        .expect("router should respond");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    Ok(())
}

/// Fail-open path 2: a URL is configured but the client refused it (invalid
/// scheme, T-03-05b SSRF guard) — the operator believes ML detection is on.
#[sqlx::test]
async fn block_policy_rejects_when_sidecar_disabled_by_bad_scheme(
    pool: PgPool,
) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;
    set_policy(&pool, workspace_id, "block").await?;

    let app = support::router_with(pool.clone(), "ftp://ml.internal:9000", "default");
    let response = app
        .oneshot(chat_request(API_KEY, false))
        .await
        .expect("router should respond");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    Ok(())
}

/// Fail-open path 3/4: the sidecar is configured and enabled but every call
/// fails (connection refused). Same class of silent empty result.
#[sqlx::test]
async fn block_policy_rejects_when_sidecar_unreachable(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;
    set_policy(&pool, workspace_id, "block").await?;

    let app = support::router_with(pool.clone(), &dead_sidecar_url(), "default");
    let response = app
        .oneshot(chat_request(API_KEY, false))
        .await
        .expect("router should respond");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    Ok(())
}

/// Acceptance criterion: a workspace that has NEVER chosen a policy — no row
/// in `workspace_sidecar_policy`, which is the state of every workspace that
/// predates migration 018 — fails closed.
#[sqlx::test]
async fn fresh_workspace_defaults_to_block(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;

    // Guard the premise: the test is only meaningful if no row exists.
    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM workspace_sidecar_policy WHERE workspace_id = $1")
            .bind(workspace_id)
            .fetch_one(&pool)
            .await?;
    assert_eq!(
        rows, 0,
        "test premise: the workspace must have no policy row"
    );

    let app = support::router_with(pool.clone(), &dead_sidecar_url(), "default");
    let response = app
        .oneshot(chat_request(API_KEY, false))
        .await
        .expect("router should respond");

    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "the default for a workspace with no stored choice must be block"
    );
    Ok(())
}

// ── degrade_with_alert: proceed, but loudly ───────────────────────────────

#[sqlx::test]
async fn degrade_policy_proceeds_with_header_when_sidecar_unreachable(
    pool: PgPool,
) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;
    set_policy(&pool, workspace_id, "degrade_with_alert").await?;

    let app = support::router_with(pool.clone(), &dead_sidecar_url(), "default");
    let response = app
        .oneshot(chat_request(API_KEY, false))
        .await
        .expect("router should respond");

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "degrade_with_alert must not fail the request"
    );
    assert_eq!(
        response
            .headers()
            .get(DEGRADED_HEADER)
            .and_then(|v| v.to_str().ok()),
        Some("all_calls_failed"),
        "the response must carry the degradation reason"
    );
    Ok(())
}

#[sqlx::test]
async fn degrade_policy_reports_unconfigured_reason(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;
    set_policy(&pool, workspace_id, "degrade_with_alert").await?;

    let app = support::router_with(pool.clone(), "", "default");
    let response = app
        .oneshot(chat_request(API_KEY, false))
        .await
        .expect("router should respond");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(DEGRADED_HEADER)
            .and_then(|v| v.to_str().ok()),
        Some("unconfigured"),
        "an unconfigured sidecar is a distinct reason from a dead one"
    );
    Ok(())
}

/// The streaming path shares `prepare` with the buffered path, so it must
/// carry the same header. It is a separate response builder (`Sse`), which is
/// exactly the kind of place a header gets dropped.
#[sqlx::test]
async fn degrade_policy_sets_header_on_streaming_path(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;
    set_policy(&pool, workspace_id, "degrade_with_alert").await?;

    let app = support::router_with(pool.clone(), &dead_sidecar_url(), "default");
    let response = app
        .oneshot(chat_request(API_KEY, true))
        .await
        .expect("router should respond");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(DEGRADED_HEADER)
            .and_then(|v| v.to_str().ok()),
        Some("all_calls_failed"),
        "the streaming response must carry the degradation reason too"
    );
    Ok(())
}

/// `block` must fail closed on the streaming path too — an SSE response
/// cannot be un-sent once its status line is committed, so the gate has to
/// fire before the stream is opened.
#[sqlx::test]
async fn block_policy_rejects_streaming_request(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;
    set_policy(&pool, workspace_id, "block").await?;

    let app = support::router_with(pool.clone(), &dead_sidecar_url(), "default");
    let response = app
        .oneshot(chat_request(API_KEY, true))
        .await
        .expect("router should respond");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    Ok(())
}

// ── the alert ─────────────────────────────────────────────────────────────

async fn scrape_metrics(app: axum::Router) -> String {
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/metrics")
                .body(axum::body::Body::empty())
                .expect("metrics request must build"),
        )
        .await
        .expect("router should respond");
    assert_eq!(response.status(), StatusCode::OK);
    support::response_text(response).await
}

/// `degrade_with_alert` must ALERT, not just proceed quietly. The alert this
/// deployment can actually route is the Prometheus counter that
/// `monitoring/prometheus/alerts.yml` fires `MLSidecarCoverageLost` on.
///
/// The positive control is the metric's own absence beforehand: a fresh
/// registry must not already claim a degradation, otherwise "the counter is
/// non-zero" would prove nothing.
#[sqlx::test]
async fn degrade_policy_increments_the_alert_counter(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;
    set_policy(&pool, workspace_id, "degrade_with_alert").await?;

    let app = support::router_with(pool.clone(), &dead_sidecar_url(), "default");

    let before = scrape_metrics(app.clone()).await;
    assert!(
        !before.contains("secureprompt_sidecar_unavailable_total"),
        "positive control: a fresh registry must not already report a \
         degradation; got:\n{before}"
    );

    let response = app
        .clone()
        .oneshot(chat_request(API_KEY, false))
        .await
        .expect("router should respond");
    assert_eq!(response.status(), StatusCode::OK);

    let after = scrape_metrics(app).await;
    assert!(
        after.contains(
            "secureprompt_sidecar_unavailable_total{reason=\"all_calls_failed\",action=\"degrade_with_alert\"}"
        ),
        "the degradation must be exported as an alertable counter; got:\n{after}"
    );
    Ok(())
}

/// `block` alerts too — a fail-closed workspace losing its sidecar is an
/// operator emergency (every request is now 503), not a silent success.
#[sqlx::test]
async fn block_policy_increments_the_alert_counter(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;
    set_policy(&pool, workspace_id, "block").await?;

    let app = support::router_with(pool.clone(), &dead_sidecar_url(), "default");

    let before = scrape_metrics(app.clone()).await;
    assert!(!before.contains("secureprompt_sidecar_unavailable_total"));

    let response = app
        .clone()
        .oneshot(chat_request(API_KEY, false))
        .await
        .expect("router should respond");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    let after = scrape_metrics(app).await;
    assert!(
        after.contains(
            "secureprompt_sidecar_unavailable_total{reason=\"all_calls_failed\",action=\"block\"}"
        ),
        "a blocked request must still alert; got:\n{after}"
    );
    Ok(())
}

// ── the audit row ─────────────────────────────────────────────────────────

/// ClickHouse database the analytics writer targets for the audit-row test.
/// The gateway's own `sp_analytics` schema, so the assertion runs against the
/// real `request_events` table rather than a bespoke fixture.
const CH_DB: &str = "sp_analytics";

async fn ch_query(sql: &str) -> String {
    let url =
        std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://localhost:8123".to_owned());
    let response = reqwest::Client::new()
        .post(format!("{url}/?database={CH_DB}"))
        .body(sql.to_owned())
        .send()
        .await
        .expect("ClickHouse must be reachable — see the task env (CLICKHOUSE_URL)");
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "clickhouse query failed ({status}): {text}\nsql: {sql}"
    );
    text
}

/// Apply ClickHouse migration 006 the same way the worker does at startup.
/// Idempotent (`IF NOT EXISTS`), and deliberately explicit rather than a
/// "skip if the column is missing" guard — a missing column must surface as a
/// real failure, never as a quietly-passing test.
async fn ensure_floor_only_column() {
    ch_query("ALTER TABLE request_events ADD COLUMN IF NOT EXISTS floor_only Bool DEFAULT false")
        .await;
}

/// Poll for the request's audit row — the analytics writer batches on a 1s
/// period, so the row is not visible synchronously.
async fn await_floor_only(request_id_prefix: &str) -> String {
    for _ in 0..40 {
        let out = ch_query(&format!(
            "SELECT floor_only FROM request_events WHERE user_agent = '{request_id_prefix}' \
             ORDER BY created_at DESC LIMIT 1"
        ))
        .await;
        if !out.trim().is_empty() {
            return out.trim().to_owned();
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    panic!("no request_events row appeared for marker {request_id_prefix}");
}

fn tagged_chat_request(marker: &str) -> Request<axum::body::Body> {
    let mut request = chat_request(API_KEY, false);
    // The audit row's `user_agent` is a free-text passthrough — used here
    // purely as a per-test correlation key, since ClickHouse is shared
    // across the whole suite and `request_id` is not visible to the caller
    // before the response is parsed.
    request.headers_mut().insert(
        axum::http::header::USER_AGENT,
        axum::http::HeaderValue::from_str(marker).expect("marker is a valid header value"),
    );
    request
}

/// Acceptance criterion: `degrade_with_alert` marks the audit/analytics row
/// `floor_only = true`.
///
/// The POSITIVE CONTROL is the second half of the same test: an otherwise
/// identical request served by a HEALTHY sidecar must land a row with
/// `floor_only = false`. Without it, "the column reads 1" could just mean the
/// column defaults to 1, or that both requests wrote the same value.
#[sqlx::test]
async fn degraded_request_marks_floor_only_in_the_audit_row(pool: PgPool) -> sqlx::Result<()> {
    ensure_floor_only_column().await;

    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;
    set_policy(&pool, workspace_id, "degrade_with_alert").await?;

    // POSITIVE CONTROL: healthy sidecar → a normally-served row.
    let healthy_marker = format!("ws2-3-healthy-{}", Uuid::new_v4());
    let sidecar = MockSidecar::spawn();
    let healthy_app = support::router_with(pool.clone(), &sidecar.url(), CH_DB);
    let response = healthy_app
        .oneshot(tagged_chat_request(&healthy_marker))
        .await
        .expect("router should respond");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        !sidecar.ner_requests().is_empty(),
        "positive control requires the sidecar to actually have been called"
    );

    // Degraded: sidecar gone.
    let degraded_marker = format!("ws2-3-degraded-{}", Uuid::new_v4());
    let degraded_app = support::router_with(pool.clone(), &dead_sidecar_url(), CH_DB);
    let response = degraded_app
        .oneshot(tagged_chat_request(&degraded_marker))
        .await
        .expect("router should respond");
    assert_eq!(response.status(), StatusCode::OK);

    assert_eq!(
        await_floor_only(&healthy_marker).await,
        "false",
        "a request served with real ML coverage must NOT be marked floor_only"
    );
    assert_eq!(
        await_floor_only(&degraded_marker).await,
        "true",
        "a degraded request must be marked floor_only in the audit row"
    );
    Ok(())
}
