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
        Self::spawn_with(usize::MAX, false)
    }

    /// `max_connections`: stop accepting after this many, so later calls hit
    /// connection-refused — how a sidecar that dies part-way through a
    /// multi-chunk prompt is simulated.
    ///
    /// `fail_injection`: answer `/detect/injection` with a 500 while keeping
    /// `/detect/ner` healthy — the independent-failure case that made the
    /// "same client, same request" exclusion wrong.
    fn spawn_with(max_connections: usize, fail_injection: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local addr");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&requests);

        std::thread::spawn(move || {
            let mut served = 0usize;
            loop {
                if served >= max_connections {
                    // Stop accepting: dropping the listener makes every later
                    // connect fail with connection-refused, which is how a
                    // sidecar dying part-way through a multi-chunk prompt is
                    // simulated.
                    drop(listener);
                    return;
                }
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                served += 1;
                let Some(request) = read_http_request(&mut stream) else {
                    continue;
                };

                if fail_injection && request.contains("/detect/injection") {
                    let body = b"upstream classifier unavailable";
                    let head = format!(
                        "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(head.as_bytes());
                    let _ = stream.write_all(body);
                    sink.lock().expect("request sink mutex").push(request);
                    continue;
                }

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

/// Read one complete HTTP request: headers, then exactly `Content-Length`
/// bytes of body.
///
/// A single fixed-size `read` is not good enough here. A `/detect/ner` chunk
/// can carry ~24 KB of JSON, so a server that replies and closes after
/// reading only the first buffer-full leaves the client still writing — the
/// client then sees a broken pipe and records the call as FAILED. That turned
/// a "one chunk scanned, one refused" scenario into "no chunks scanned",
/// which silently changed what the test was exercising.
fn read_http_request(stream: &mut std::net::TcpStream) -> Option<String> {
    let mut raw: Vec<u8> = Vec::new();
    let mut buf = [0u8; 8192];

    // Headers.
    let header_end = loop {
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        let n = stream.read(&mut buf).ok()?;
        if n == 0 {
            return None;
        }
        raw.extend_from_slice(&buf[..n]);
    };

    let headers = String::from_utf8_lossy(&raw[..header_end]).to_string();
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);

    // Body, in full.
    while raw.len() < header_end + content_length {
        let n = stream.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&buf[..n]);
    }
    Some(String::from_utf8_lossy(&raw).to_string())
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
    // Read the real migration rather than restating its DDL, so this cannot
    // drift from what the worker actually applies at startup.
    const MIGRATION: &str = include_str!("../clickhouse/migrations/006_floor_only.sql");
    let sql: String = MIGRATION
        .lines()
        .filter(|l| !l.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n");
    for statement in sql.split(';') {
        if !statement.trim().is_empty() {
            ch_query(statement.trim()).await;
        }
    }
}

/// Poll for one column of the request's audit row — the analytics writer
/// batches on a 1s period, so the row is not visible synchronously.
async fn await_column(column: &str, marker: &str) -> String {
    for _ in 0..40 {
        let out = ch_query(&format!(
            "SELECT {column} FROM request_events WHERE user_agent = '{marker}' \
             ORDER BY created_at DESC LIMIT 1"
        ))
        .await;
        if !out.trim().is_empty() {
            return out.trim().to_owned();
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    panic!("no request_events row appeared for marker {marker}");
}

async fn await_floor_only(marker: &str) -> String {
    await_column("floor_only", marker).await
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

// ── Fix round 1 ───────────────────────────────────────────────────────────

/// Long prompt: > `DEFAULT_NER_CHUNK_CHARS` (24,000) so the gateway tiles it
/// into more than one `/detect/ner` call. Synthetic filler plus one synthetic
/// name.
fn long_chat_request(marker: Option<&str>) -> Request<axum::body::Body> {
    let filler = "lorem ipsum dolor sit amet ".repeat(1_400); // ~37,800 chars
    let mut request = support::authorized_request(
        Request::builder()
            .method(Method::POST)
            .uri("/v1/chat/completions"),
        API_KEY,
        json!({
            "model": "claude-3-haiku",
            "stream": false,
            "messages": [{
                "role": "user",
                "content": format!("{filler} contract for {SYNTHETIC_NAME}"),
            }],
        }),
    );
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 50_000))));
    if let Some(marker) = marker {
        request.headers_mut().insert(
            axum::http::header::USER_AGENT,
            axum::http::HeaderValue::from_str(marker).expect("valid header"),
        );
    }
    request
}

/// CRITICAL 1 — a prompt long enough to tile into several chunks, with a
/// sidecar that answers the first chunk and then dies. The remaining chunks
/// are never scanned, so a `block` workspace must NOT forward the prompt.
///
/// Before the fix this returned 200 with no header and `floor_only = false`:
/// unscanned text forwarded to the provider under a fail-closed policy.
#[sqlx::test]
async fn block_policy_rejects_partially_scanned_long_prompt(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;
    set_policy(&pool, workspace_id, "block").await?;

    // Serve exactly one connection, then refuse.
    let sidecar = MockSidecar::spawn_with(1, false);
    let app = support::router_with(pool.clone(), &sidecar.url(), "default");
    let response = app
        .clone()
        .oneshot(long_chat_request(None))
        .await
        .expect("router should respond");

    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "a block workspace must not forward chunks the sidecar never scanned"
    );

    // Fix round 2 — 503 alone does NOT discriminate: `block` returns it for
    // Partial AND for AllCallsFailed, so a regression that stopped counting
    // the first chunk as covered would leave this test green while the
    // scenario under test had silently changed (exactly what happened to the
    // degrade twin before its mock was fixed). The metric label is the
    // discriminator. `!ner_requests().is_empty()` is not enough either — it
    // proves the mock RECEIVED a request, not that the client counted it
    // covered.
    let metrics = scrape_metrics(app).await;
    assert!(
        metrics.contains(
            "secureprompt_sidecar_unavailable_total{reason=\"partial_coverage\",action=\"block\"}"
        ),
        "the 503 must be attributed to PARTIAL coverage; got:\n{metrics}"
    );
    assert!(
        !metrics.contains("reason=\"all_calls_failed\""),
        "the first chunk WAS scanned, so this must not be a total outage; got:\n{metrics}"
    );
    Ok(())
}

/// POSITIVE CONTROL for the test above, and the regression guard that matters
/// most: a long prompt whose chunks are ALL scanned must still succeed. If
/// `Partial` were over-applied, every document over 24k chars would 503 on a
/// bank profile — a worse outage than the bug being fixed.
#[sqlx::test]
async fn block_policy_allows_fully_scanned_long_prompt(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;
    set_policy(&pool, workspace_id, "block").await?;

    let sidecar = MockSidecar::spawn();
    let app = support::router_with(pool.clone(), &sidecar.url(), "default");
    let response = app
        .oneshot(long_chat_request(None))
        .await
        .expect("router should respond");

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a multi-chunk prompt that was fully scanned is not degraded"
    );
    assert!(
        response.headers().get(DEGRADED_HEADER).is_none(),
        "full coverage across several chunks must not be reported as degraded"
    );
    assert!(
        sidecar.ner_requests().len() > 1,
        "premise: the prompt must actually have tiled into >1 chunk; got {}",
        sidecar.ner_requests().len()
    );
    Ok(())
}

/// CRITICAL 1, degrade side — partial coverage reports its own distinct
/// reason, so an operator can tell "prompt outran the budget / sidecar died
/// mid-prompt" from "sidecar is gone".
#[sqlx::test]
async fn degrade_policy_reports_partial_coverage_reason(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;
    set_policy(&pool, workspace_id, "degrade_with_alert").await?;

    let sidecar = MockSidecar::spawn_with(1, false);
    let app = support::router_with(pool.clone(), &sidecar.url(), "default");
    let response = app
        .oneshot(long_chat_request(None))
        .await
        .expect("router should respond");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(DEGRADED_HEADER)
            .and_then(|v| v.to_str().ok()),
        Some("partial_coverage"),
        "partial coverage is its own reason, not an outage reason"
    );
    Ok(())
}

/// IMPORTANT — `/detect/injection` fails independently of `/detect/ner`.
/// With NER healthy (coverage Complete) and the injection classifier
/// 500-ing, `block_on_injection_detection` was silently bypassed: the request
/// sailed through with no 503, no header and no alert.
#[sqlx::test]
async fn block_policy_rejects_when_injection_check_fails_alone(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;
    set_policy(&pool, workspace_id, "block").await?;
    sqlx::query(
        "INSERT INTO workspace_secure_mode
            (workspace_id, enabled, level, block_on_injection_detection)
         VALUES ($1, true, 'standard', true)",
    )
    .bind(workspace_id)
    .execute(&pool)
    .await?;

    let sidecar = MockSidecar::spawn_with(usize::MAX, true);
    let app = support::router_with(pool.clone(), &sidecar.url(), "default");
    let response = app
        .oneshot(chat_request(API_KEY, false))
        .await
        .expect("router should respond");

    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "an injection gate the workspace enforces must fail closed when the \
         classifier cannot answer"
    );
    assert!(
        !sidecar.ner_requests().is_empty(),
        "premise: NER must have been healthy, so this 503 is about the \
         injection check alone"
    );
    Ok(())
}

/// POSITIVE CONTROL / scope guard: the SAME broken injection classifier must
/// NOT 503 a workspace that does not enforce an injection gate. Fail-closed
/// has to be proportionate — costing every workspace a 503 for a control they
/// never enabled would be its own outage.
#[sqlx::test]
async fn injection_failure_does_not_block_when_gate_is_off(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;
    set_policy(&pool, workspace_id, "block").await?;
    sqlx::query(
        "INSERT INTO workspace_secure_mode
            (workspace_id, enabled, level, block_on_injection_detection)
         VALUES ($1, true, 'standard', false)",
    )
    .bind(workspace_id)
    .execute(&pool)
    .await?;

    let sidecar = MockSidecar::spawn_with(usize::MAX, true);
    let app = support::router_with(pool.clone(), &sidecar.url(), "default");
    let response = app
        .oneshot(chat_request(API_KEY, false))
        .await
        .expect("router should respond");

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the injection result is never read when the gate is off, so losing \
         it has no security consequence and must not cost a 503"
    );
    Ok(())
}

/// IMPORTANT — a fail-closed rejection must be visible in the audit trail,
/// not just the logs. Its policy-deny twin has always written a row.
#[sqlx::test]
async fn blocked_request_writes_an_audit_row(pool: PgPool) -> sqlx::Result<()> {
    ensure_floor_only_column().await;

    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;
    set_policy(&pool, workspace_id, "block").await?;

    let marker = format!("ws2-3-blocked-{}", Uuid::new_v4());
    let app = support::router_with(pool.clone(), &dead_sidecar_url(), CH_DB);
    let response = app
        .oneshot(tagged_chat_request(&marker))
        .await
        .expect("router should respond");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    let action = await_column("final_action", &marker).await;
    assert_eq!(
        action, "block_sidecar_unavailable",
        "a 503 from the coverage gate must be auditable, and distinguishable \
         from a policy deny"
    );
    assert_eq!(
        await_column("floor_only", &marker).await,
        "false",
        "a blocked request was never answered, so it was not answered on the floor"
    );
    Ok(())
}

/// The four `block_*` reason paths each get their own falsifier: the metric
/// label, which distinguishes `unconfigured` from `disabled` (both of which
/// merely produced a 503 before, so any one of them could have been broken
/// invisibly).
#[sqlx::test]
async fn block_reasons_are_reported_distinctly(pool: PgPool) -> sqlx::Result<()> {
    for (sidecar_url, expected_reason) in
        [("", "unconfigured"), ("ftp://ml.internal:9000", "disabled")]
    {
        let workspace_id = Uuid::new_v4();
        let api_key = format!("{API_KEY}_{expected_reason}");
        support::seed_workspace(&pool, workspace_id, &api_key).await?;
        support::seed_provider_and_model(
            &pool,
            workspace_id,
            Uuid::new_v4(),
            "anthropic-primary",
            "anthropic",
            None,
            "claude-3-haiku",
        )
        .await?;
        set_policy(&pool, workspace_id, "block").await?;

        let app = support::router_with(pool.clone(), sidecar_url, "default");
        let response = app
            .clone()
            .oneshot(chat_request(&api_key, false))
            .await
            .expect("router should respond");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let metrics = scrape_metrics(app).await;
        assert!(
            metrics.contains(&format!(
                "secureprompt_sidecar_unavailable_total{{reason=\"{expected_reason}\",action=\"block\"}}"
            )),
            "expected reason={expected_reason}; got:\n{metrics}"
        );
    }
    Ok(())
}

/// End-to-end coverage for the breaker path, which previously had none: drive
/// enough failed requests to trip it, then assert the reason flips from
/// `all_calls_failed` to `circuit_open`.
#[sqlx::test]
async fn degrade_policy_reports_circuit_open_after_repeated_failures(
    pool: PgPool,
) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;
    set_policy(&pool, workspace_id, "degrade_with_alert").await?;

    let app = support::router_with(pool.clone(), &dead_sidecar_url(), "default");

    let mut reasons = Vec::new();
    for _ in 0..8 {
        let response = app
            .clone()
            .oneshot(chat_request(API_KEY, false))
            .await
            .expect("router should respond");
        assert_eq!(response.status(), StatusCode::OK);
        reasons.push(
            response
                .headers()
                .get(DEGRADED_HEADER)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_owned(),
        );
    }

    assert_eq!(
        reasons.first().map(String::as_str),
        Some("all_calls_failed"),
        "the first failures are transport failures, not an open breaker"
    );
    assert!(
        reasons.iter().any(|r| r == "circuit_open"),
        "sustained failures must eventually report circuit_open; got {reasons:?}"
    );
    Ok(())
}

// ── Operator off-switch: deployment-level default ─────────────────────────

/// `block` is only a safe default if an operator can reach the off-switch.
/// `docker-compose.simple.yml` ships no ML sidecar at all, so without a
/// deployment-level override it would 503 every request out of the box with
/// no recourse except an admin-JWT PUT per workspace.
#[sqlx::test]
async fn deployment_default_applies_when_workspace_has_no_row(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;

    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM workspace_sidecar_policy WHERE workspace_id = $1")
            .bind(workspace_id)
            .fetch_one(&pool)
            .await?;
    assert_eq!(
        rows, 0,
        "test premise: the workspace must have no policy row"
    );

    let app = support::router_with_default(
        pool.clone(),
        &dead_sidecar_url(),
        "default",
        "degrade_with_alert",
    );
    let response = app
        .oneshot(chat_request(API_KEY, false))
        .await
        .expect("router should respond");

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the deployment default must apply to a workspace that never chose"
    );
    assert_eq!(
        response
            .headers()
            .get(DEGRADED_HEADER)
            .and_then(|v| v.to_str().ok()),
        Some("all_calls_failed"),
        "degrading via the deployment default is still a degradation and must \
         be reported exactly like an explicit one"
    );
    Ok(())
}

/// The escape hatch must not become a back door: a workspace that explicitly
/// chose `block` keeps failing closed even on a deployment whose default is
/// `degrade_with_alert`.
#[sqlx::test]
async fn workspace_choice_overrides_a_permissive_deployment_default(
    pool: PgPool,
) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;
    set_policy(&pool, workspace_id, "block").await?;

    let app = support::router_with_default(
        pool.clone(),
        &dead_sidecar_url(),
        "default",
        "degrade_with_alert",
    );
    let response = app
        .oneshot(chat_request(API_KEY, false))
        .await
        .expect("router should respond");

    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "an explicit workspace choice must win over the deployment default"
    );
    Ok(())
}

// ── WS2-4 — the same policy on the NON-provider routes ────────────────────
//
// `POST /v1/secure-mode/tokenize`, the MCP `redact` tool (`POST /v1/redact`)
// and the MCP `policy_check` tool (`POST /v1/policy/check`) all called
// `detect_if_available(..).detections` and threw `.coverage` away, so the
// workspace's `sidecar_unavailable` choice was ignored on three routes.
//
// These routes do not egress to a provider — they hand the CALLER a
// redaction, a detection list, or an allow/deny verdict, which the caller
// then acts on. A floor-only answer served as a normal 200 is therefore a
// laundered artifact: it looks exactly like a fully-scanned one.
//
// The mock sidecar reports `PERSON` at bytes 0..13 of whatever it is sent, so
// every fixture below puts SYNTHETIC_NAME at offset 0. `PERSON` is
// ML-ONLY — no deterministic Rust recognizer emits it — which makes it the
// discriminator between "the sidecar was reached" and "only the floor ran".

use axum::body::Body;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use secureprompt_api::http::middleware::jwt_auth::Claims;

/// `/v1/secure-mode/*` is JWT-gated, not API-key-gated. Signed with the same
/// secret `support::test_config` hands the router.
fn dashboard_jwt(workspace_id: Uuid) -> String {
    let claims = Claims {
        sub: Uuid::new_v4(),
        ws: workspace_id,
        role: "owner".to_owned(),
        jti: Uuid::new_v4().to_string(),
        iat: chrono::Utc::now().timestamp(),
        exp: (chrono::Utc::now() + chrono::Duration::seconds(900)).timestamp(),
        purpose: None,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(support::test_config().jwt.secret.as_bytes()),
    )
    .expect("jwt must encode")
}

/// Text whose ONLY detectable PII is the synthetic name at byte 0 — so the
/// deterministic floor finds nothing and `PERSON` in the answer can only have
/// come from the sidecar.
fn ml_only_text() -> String {
    format!("{SYNTHETIC_NAME} shartnomani imzoladi")
}

fn tokenize_request(jwt: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/v1/secure-mode/tokenize")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {jwt}"))
        .body(Body::from(json!({ "text": ml_only_text() }).to_string()))
        .expect("request must build")
}

fn mcp_request(uri: &'static str, api_key: &str) -> Request<Body> {
    support::authorized_request(
        Request::builder().method(Method::POST).uri(uri),
        api_key,
        json!({ "text": ml_only_text() }),
    )
}

fn degraded_header(response: &axum::response::Response) -> Option<String> {
    response
        .headers()
        .get(DEGRADED_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

async fn vault_row_count(pool: &PgPool, workspace_id: Uuid) -> sqlx::Result<i64> {
    sqlx::query_scalar("SELECT COUNT(*) FROM token_vault_entries WHERE workspace_id = $1")
        .bind(workspace_id)
        .fetch_one(pool)
        .await
}

// ── /v1/secure-mode/tokenize ──────────────────────────────────────────────

/// POSITIVE CONTROL for both tokenize tests below.
///
/// Carries the premise every absence-assertion in this section leans on: with
/// a REACHABLE sidecar the answer contains `PERSON` and a vault row is
/// written. Without this, "no PERSON" and "no vault row" would be consistent
/// with tokenize being broken for every input.
#[sqlx::test]
async fn tokenize_under_block_policy_succeeds_with_healthy_sidecar(
    pool: PgPool,
) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;
    set_policy(&pool, workspace_id, "block").await?;

    let sidecar = MockSidecar::spawn();
    let app = support::router_with(pool.clone(), &sidecar.url(), "default");
    let response = app
        .oneshot(tokenize_request(&dashboard_jwt(workspace_id)))
        .await
        .expect("router should respond");

    let status = response.status();
    let degraded = degraded_header(&response);
    let body = support::response_json(response).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a healthy sidecar must not be blocked even under the strictest policy; body={body}"
    );
    assert!(
        degraded.is_none(),
        "a healthy sidecar must not mark the response degraded; got {degraded:?}"
    );

    let ner = sidecar.ner_requests();
    assert!(
        ner.iter().any(|r| r.contains(SYNTHETIC_NAME)),
        "premise: tokenize must actually have asked the sidecar about the real \
         text; captured:\n{ner:?}"
    );
    assert_eq!(
        body["entity_counts"]["PERSON"].as_u64(),
        Some(1),
        "premise: PERSON is ML-only, so a healthy run must report exactly one; \
         body={body}"
    );
    assert!(
        body["token_vault_id"].as_str().is_some(),
        "premise: a served tokenize writes a vault entry; body={body}"
    );
    assert_eq!(
        vault_row_count(&pool, workspace_id).await?,
        1,
        "premise: a served tokenize persists exactly one vault row"
    );
    Ok(())
}

/// THE DEFECT, tokenize side: a `block` workspace asked to tokenize during a
/// sidecar outage used to get HTTP 200 and a floor-only redaction, with
/// nothing in the response saying so.
#[sqlx::test]
async fn tokenize_under_block_policy_rejects_when_sidecar_unreachable(
    pool: PgPool,
) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;
    set_policy(&pool, workspace_id, "block").await?;

    let app = support::router_with(pool.clone(), &dead_sidecar_url(), "default");
    let response = app
        .clone()
        .oneshot(tokenize_request(&dashboard_jwt(workspace_id)))
        .await
        .expect("router should respond");

    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "a block workspace must not be handed a floor-only tokenization"
    );

    // 503 alone does not discriminate — the JWT layer, the license gate and a
    // Postgres failure can all produce non-200s. The bounded metric label is
    // what attributes this one to the coverage gate, under the SAME action
    // vocabulary the chat path uses.
    let metrics = scrape_metrics(app).await;
    assert!(
        metrics.contains(
            "secureprompt_sidecar_unavailable_total{reason=\"all_calls_failed\",action=\"block\"}"
        ),
        "the 503 must be attributed to lost sidecar coverage; got:\n{metrics}"
    );

    // Premise for this absence is the positive control above: a served
    // tokenize writes exactly one row.
    assert_eq!(
        vault_row_count(&pool, workspace_id).await?,
        0,
        "a blocked tokenize must not persist a half-redacted vault entry"
    );
    Ok(())
}

/// `degrade_with_alert` on tokenize: 200, but the caller can TELL from the
/// header alone — no counting of `entity_counts` required.
#[sqlx::test]
async fn tokenize_under_degrade_policy_reports_the_reason(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;
    set_policy(&pool, workspace_id, "degrade_with_alert").await?;

    let app = support::router_with(pool.clone(), &dead_sidecar_url(), "default");
    let response = app
        .oneshot(tokenize_request(&dashboard_jwt(workspace_id)))
        .await
        .expect("router should respond");

    let status = response.status();
    let degraded = degraded_header(&response);
    let body = support::response_json(response).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "degrade_with_alert must still answer; body={body}"
    );
    assert_eq!(
        degraded.as_deref(),
        Some("all_calls_failed"),
        "the caller must be able to tell from the header alone; body={body}"
    );
    // The reason the header matters, asserted against the positive control's
    // premise (`PERSON` == 1 with a live sidecar).
    assert!(
        body["entity_counts"]["PERSON"].as_u64().is_none(),
        "premise check: this answer really is floor-only — PERSON is ML-only \
         and the sidecar was dead; body={body}"
    );
    Ok(())
}

/// A workspace that never chose fails closed on tokenize too — the default
/// must not be route-dependent.
#[sqlx::test]
async fn tokenize_defaults_to_block_for_a_fresh_workspace(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;

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
        .oneshot(tokenize_request(&dashboard_jwt(workspace_id)))
        .await
        .expect("router should respond");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    Ok(())
}

// ── MCP `redact` — POST /v1/redact ────────────────────────────────────────

/// POSITIVE CONTROL: with the sidecar up, `block` serves the request and the
/// detection list contains the ML-only `PERSON`.
#[sqlx::test]
async fn redact_under_block_policy_succeeds_with_healthy_sidecar(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;
    set_policy(&pool, workspace_id, "block").await?;

    let sidecar = MockSidecar::spawn();
    let app = support::router_with(pool.clone(), &sidecar.url(), "default");
    let response = app
        .oneshot(mcp_request("/v1/redact", API_KEY))
        .await
        .expect("router should respond");

    let status = response.status();
    let degraded = degraded_header(&response);
    let body = support::response_json(response).await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert!(degraded.is_none(), "got {degraded:?}");
    assert!(
        sidecar
            .ner_requests()
            .iter()
            .any(|r| r.contains(SYNTHETIC_NAME)),
        "premise: /v1/redact must actually have called the sidecar"
    );
    assert!(
        body["detections"]
            .as_array()
            .expect("detections array")
            .iter()
            .any(|d| d["class"] == "PERSON"),
        "premise: PERSON is ML-only, so a healthy run must report it; body={body}"
    );
    // NOT `redacted_text`: with no policy rules and `redact_when_no_rules =
    // false` this endpoint returns the policy engine's passthrough content,
    // so the name legitimately survives in the text. `vault_size` is the
    // field that actually moves with ML coverage — 1 here, 0 when the
    // sidecar is gone.
    assert_eq!(
        body["vault_size"].as_u64(),
        Some(1),
        "premise: a healthy run vaults the ML-only PERSON; body={body}"
    );
    Ok(())
}

/// THE DEFECT, MCP `redact` side.
#[sqlx::test]
async fn redact_under_block_policy_rejects_when_sidecar_unreachable(
    pool: PgPool,
) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;
    set_policy(&pool, workspace_id, "block").await?;

    let app = support::router_with(pool.clone(), &dead_sidecar_url(), "default");

    let before = scrape_metrics(app.clone()).await;
    assert!(
        !before.contains("secureprompt_sidecar_unavailable_total"),
        "positive control: a fresh registry must not already report a \
         degradation; got:\n{before}"
    );

    let response = app
        .clone()
        .oneshot(mcp_request("/v1/redact", API_KEY))
        .await
        .expect("router should respond");
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "a block workspace must not be handed a floor-only redaction"
    );

    let after = scrape_metrics(app).await;
    assert!(
        after.contains(
            "secureprompt_sidecar_unavailable_total{reason=\"all_calls_failed\",action=\"block\"}"
        ),
        "the 503 must be attributed to lost sidecar coverage; got:\n{after}"
    );
    Ok(())
}

/// `degrade_with_alert` on `redact`: answered, but flagged.
#[sqlx::test]
async fn redact_under_degrade_policy_reports_the_reason(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;
    set_policy(&pool, workspace_id, "degrade_with_alert").await?;

    let app = support::router_with(pool.clone(), &dead_sidecar_url(), "default");
    let response = app
        .oneshot(mcp_request("/v1/redact", API_KEY))
        .await
        .expect("router should respond");

    let status = response.status();
    let degraded = degraded_header(&response);
    let body = support::response_json(response).await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert_eq!(
        degraded.as_deref(),
        Some("all_calls_failed"),
        "the caller must be able to tell without inspecting the detection \
         list; body={body}"
    );
    assert!(
        !body["detections"]
            .as_array()
            .expect("detections array")
            .iter()
            .any(|d| d["class"] == "PERSON"),
        "premise check: this answer really is floor-only; body={body}"
    );
    Ok(())
}

// ── MCP `policy_check` — POST /v1/policy/check ────────────────────────────

/// POSITIVE CONTROL: `block` + healthy sidecar answers, and the sidecar was
/// really consulted.
#[sqlx::test]
async fn policy_check_under_block_policy_succeeds_with_healthy_sidecar(
    pool: PgPool,
) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;
    set_policy(&pool, workspace_id, "block").await?;

    let sidecar = MockSidecar::spawn();
    let app = support::router_with(pool.clone(), &sidecar.url(), "default");
    let response = app
        .oneshot(mcp_request("/v1/policy/check", API_KEY))
        .await
        .expect("router should respond");

    let status = response.status();
    let degraded = degraded_header(&response);
    let body = support::response_json(response).await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert!(degraded.is_none(), "got {degraded:?}");
    assert!(
        body["allowed"].as_bool().is_some(),
        "premise: a served policy_check returns a verdict; body={body}"
    );
    assert!(
        sidecar
            .ner_requests()
            .iter()
            .any(|r| r.contains(SYNTHETIC_NAME)),
        "premise: /v1/policy/check must actually have called the sidecar"
    );
    Ok(())
}

/// THE DEFECT, MCP `policy_check` side — the worst of the three: the caller
/// receives an `allowed` verdict computed from a detection set the ML layer
/// never contributed to, and acts on it.
#[sqlx::test]
async fn policy_check_under_block_policy_rejects_when_sidecar_unreachable(
    pool: PgPool,
) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;
    set_policy(&pool, workspace_id, "block").await?;

    let app = support::router_with(pool.clone(), &dead_sidecar_url(), "default");
    let response = app
        .clone()
        .oneshot(mcp_request("/v1/policy/check", API_KEY))
        .await
        .expect("router should respond");

    let status = response.status();
    let body = support::response_text(response).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "a block workspace must not be handed a verdict the ML layer never \
         informed; body={body}"
    );
    // Premise for the absence below: a served policy_check returns `allowed`
    // (asserted in the positive control above).
    assert!(
        !body.contains("\"allowed\""),
        "a blocked policy_check must not also ship a verdict; body={body}"
    );

    let metrics = scrape_metrics(app).await;
    assert!(
        metrics.contains(
            "secureprompt_sidecar_unavailable_total{reason=\"all_calls_failed\",action=\"block\"}"
        ),
        "the 503 must be attributed to lost sidecar coverage; got:\n{metrics}"
    );
    Ok(())
}

/// `degrade_with_alert` on `policy_check`: the verdict is served, flagged.
#[sqlx::test]
async fn policy_check_under_degrade_policy_reports_the_reason(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;
    set_policy(&pool, workspace_id, "degrade_with_alert").await?;

    let app = support::router_with(pool.clone(), &dead_sidecar_url(), "default");
    let response = app
        .oneshot(mcp_request("/v1/policy/check", API_KEY))
        .await
        .expect("router should respond");

    let status = response.status();
    let degraded = degraded_header(&response);
    let body = support::response_json(response).await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert!(
        body["allowed"].as_bool().is_some(),
        "premise: the verdict is still served; body={body}"
    );
    assert_eq!(
        degraded.as_deref(),
        Some("all_calls_failed"),
        "a verdict computed without ML coverage must say so; body={body}"
    );
    Ok(())
}

/// Partial coverage is a coverage LOSS on these routes too — a long input
/// whose later chunks were never scanned must not be answered as if it had
/// been. Uses the distinct `partial_coverage` reason so an operator can tell
/// it from a total outage.
#[sqlx::test]
async fn redact_under_degrade_policy_reports_partial_coverage(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;
    set_policy(&pool, workspace_id, "degrade_with_alert").await?;

    // Serve exactly one chunk, then refuse — the rest of the text is never
    // scanned.
    let sidecar = MockSidecar::spawn_with(1, false);
    let filler = "lorem ipsum dolor sit amet ".repeat(1_400); // ~37,800 chars
    let app = support::router_with(pool.clone(), &sidecar.url(), "default");
    let response = app
        .oneshot(support::authorized_request(
            Request::builder().method(Method::POST).uri("/v1/redact"),
            API_KEY,
            json!({ "text": format!("{SYNTHETIC_NAME} {filler}") }),
        ))
        .await
        .expect("router should respond");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        degraded_header(&response).as_deref(),
        Some("partial_coverage"),
        "partial coverage is its own reason, not an outage reason"
    );
    Ok(())
}
