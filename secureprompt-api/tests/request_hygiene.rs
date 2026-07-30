//! WS4-5 — request-path hygiene on the INBOUND side.
//!
//! Three of the four acceptance criteria live here:
//!
//!   * an oversized request body is refused with 413,
//!   * a request id appears in the logs,
//!   * the same request id appears in the audit row,
//!
//! plus the regression guard the fourth criterion needs: a legitimate
//! long-lived SSE stream must still stream once an inbound deadline exists.
//!
//! The OUTBOUND half of the deadline criterion — a hung provider releasing the
//! socket — is `tests/upstream_deadline.rs`, because an inbound `TimeoutLayer`
//! cannot release a socket held by `reqwest`.
//!
//! All fixture PII is synthetic.

mod support;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, Method, Request, StatusCode};
use serde_json::json;
use sqlx::PgPool;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;
use uuid::Uuid;

const API_KEY: &str = "sp_ws4_5_request_hygiene";
const REQUEST_ID_HEADER: &str = "x-request-id";

/// The gateway's own analytics database — the same one
/// `tests/sidecar_failure_policy.rs` asserts against, so "the audit row" here
/// means the real `request_events` table and not a bespoke fixture.
const CH_DB: &str = "sp_analytics";

// ── Fixtures ──────────────────────────────────────────────────────────────

async fn seed(pool: &PgPool, workspace_id: Uuid) -> sqlx::Result<()> {
    support::seed_workspace(pool, workspace_id, API_KEY).await?;
    support::seed_provider_and_model(
        pool,
        workspace_id,
        Uuid::new_v4(),
        "anthropic-primary",
        // `anthropic` is still an echo stub in this workspace, so a request
        // that gets past the gates reaches a working provider and answers 200
        // without any network egress.
        "anthropic",
        None,
        "claude-3-haiku",
    )
    .await
}

/// A chat request tagged with `marker` in the User-Agent.
///
/// `user_agent` is a free-text passthrough that lands in the audit row, so it
/// is the correlation key a test uses to find its own row in a ClickHouse
/// table shared by the whole suite — the same idiom
/// `tests/sidecar_failure_policy.rs` uses.
fn chat_request(marker: &str, stream: bool) -> Request<Body> {
    let mut request = support::authorized_request(
        Request::builder()
            .method(Method::POST)
            .uri("/v1/chat/completions"),
        API_KEY,
        json!({
            "model": "claude-3-haiku",
            "stream": stream,
            "messages": [{ "role": "user", "content": "Summarise the quarterly report." }],
        }),
    );
    request.headers_mut().insert(
        header::USER_AGENT,
        marker.parse().expect("marker is a valid header value"),
    );
    // `chat_completions` extracts `ConnectInfo<SocketAddr>`; `oneshot` bypasses
    // the connection layer that installs it in production, so it is inserted
    // by hand (see the note in tests/sidecar_failure_policy.rs).
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 50_000))));
    request
}

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

/// Poll for one column of this request's audit row. The analytics writer
/// batches on a ~1s period, so the row is not visible synchronously.
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

// ── Criterion: oversized body rejected with 413 ───────────────────────────

/// An oversized body is refused at the router edge — before routing to a
/// handler, before any extractor, and before anything buffers it.
///
/// Driven against `/metrics` ON PURPOSE. That route has no body extractor, so
/// nothing in the stack ever looks at its body: axum's per-extractor
/// `DefaultBodyLimit` (2 MiB, the thing that already returns 413 for
/// `Json`-taking routes) cannot fire here. A 413 on this route therefore says
/// something axum's default does not — the limit is enforced at the edge, for
/// every route, on `Content-Length`, without reading a byte of the body.
///
/// `/metrics` is also on the license gate's `RECOVERY_ALLOWLIST`, which is the
/// second thing this pins: allowlisted-for-licensing does NOT mean
/// allowlisted-for-limits.
#[sqlx::test]
async fn oversized_body_is_rejected_with_413_on_a_route_that_never_reads_it(
    pool: PgPool,
) -> sqlx::Result<()> {
    // POSITIVE CONTROL: same route, same method, a body UNDER the limit still
    // answers 200. Without it, a 413 below could just mean the route broke.
    let small = Request::builder()
        .method(Method::GET)
        .uri("/metrics")
        .header(header::CONTENT_LENGTH, "3")
        .body(Body::from("abc"))
        .expect("request must build");
    let ok = support::router(pool.clone())
        .oneshot(small)
        .await
        .expect("router should respond");
    assert_eq!(
        ok.status(),
        StatusCode::OK,
        "positive control: an under-limit body must still be served"
    );

    // 3 MiB — over the 2 MiB default.
    let huge = vec![b'x'; 3 * 1024 * 1024];
    let oversized = Request::builder()
        .method(Method::GET)
        .uri("/metrics")
        .header(header::CONTENT_LENGTH, huge.len().to_string())
        .body(Body::from(huge))
        .expect("request must build");
    let response = support::router(pool.clone())
        .oneshot(oversized)
        .await
        .expect("router should respond");
    assert_eq!(
        response.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "a 3 MiB body must be refused at the edge even on a route that never \
         reads its body — otherwise the only body limit on this gateway is \
         axum's per-extractor default, which this route does not have"
    );
    Ok(())
}

// ── Criterion: request ids in logs AND in audit rows ──────────────────────

/// The caller's `x-request-id` survives to BOTH ends of the correlation: it
/// comes back on the response, and it is the `request_id` of the audit row the
/// request produced.
///
/// This is the whole forensic point. Before this, `request_id` was minted
/// inside the pipeline and was invisible to the caller, so a client-reported
/// id could not be turned into an audit row.
#[sqlx::test]
async fn caller_request_id_reaches_the_response_header_and_the_audit_row(
    pool: PgPool,
) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;

    let supplied = Uuid::new_v4();
    let marker = format!("ws4-5-supplied-{supplied}");
    let mut request = chat_request(&marker, false);
    request.headers_mut().insert(
        REQUEST_ID_HEADER,
        supplied
            .to_string()
            .parse()
            .expect("a uuid is a valid header value"),
    );

    // `degrade_with_alert` + an unconfigured sidecar keeps the request on the
    // 200 path with no ML dependency, so this test measures id propagation and
    // nothing else.
    let app = support::router_with_default(pool.clone(), "", CH_DB, "degrade_with_alert");
    let response = app.oneshot(request).await.expect("router should respond");

    let status = response.status();
    let echoed = response
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = support::response_text(response).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "request must be served; body={body}"
    );
    assert_eq!(
        echoed.as_deref(),
        Some(supplied.to_string().as_str()),
        "the response must echo the caller's request id"
    );

    let recorded = await_column("request_id", &marker).await;
    assert_eq!(
        recorded,
        supplied.to_string(),
        "the audit row must carry the id the caller supplied — a log line and \
         an audit row that cannot be joined are worth much less to an incident \
         responder than either alone"
    );
    Ok(())
}

/// A caller that supplies no id still gets one, it is unique per request, and
/// it is the id its own audit row carries.
///
/// This is the POSITIVE CONTROL for the test above: it rules out "the header
/// is echoed back from the request" (there is no request header here) and "the
/// id is a constant" (two requests, two different ids, two matching rows).
#[sqlx::test]
async fn a_request_without_an_id_gets_a_unique_one_that_matches_its_own_audit_row(
    pool: PgPool,
) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;

    let mut seen = Vec::new();
    for n in 0..2 {
        let marker = format!("ws4-5-generated-{}-{n}", Uuid::new_v4());
        let app = support::router_with_default(pool.clone(), "", CH_DB, "degrade_with_alert");
        let response = app
            .oneshot(chat_request(&marker, false))
            .await
            .expect("router should respond");
        assert_eq!(response.status(), StatusCode::OK);
        let generated = response
            .headers()
            .get(REQUEST_ID_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .expect("a response must carry a request id even when the caller sent none");
        assert!(
            Uuid::parse_str(&generated).is_ok(),
            "a generated request id must be a uuid, got {generated:?}"
        );
        let recorded = await_column("request_id", &marker).await;
        assert_eq!(
            recorded, generated,
            "the audit row must carry the id the response advertised"
        );
        seen.push(generated);
    }
    assert_ne!(
        seen[0], seen[1],
        "generated request ids must differ per request — an id that is the \
         same for every request correlates nothing"
    );
    Ok(())
}

/// The request id appears in a log line, on the SAME line as the request it
/// belongs to.
///
/// Runs on a current-thread runtime inside `with_default` so every poll of the
/// request future happens on this thread while the capturing subscriber is
/// installed — no global subscriber, no cross-test interference.
///
/// The pool is lazy and never connected: `/metrics` touches no database.
#[test]
fn request_id_appears_in_the_log_line_for_its_own_request() {
    let sink = LogSink::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(sink.clone())
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .finish();

    let supplied = Uuid::new_v4().to_string();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime must build");

    tracing::subscriber::with_default(subscriber, || {
        runtime.block_on(async {
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .connect_lazy("postgres://secureprompt:secureprompt@localhost:5432/secureprompt")
                .expect("lazy pool must build");
            let request = Request::builder()
                .method(Method::GET)
                .uri("/metrics")
                .header(REQUEST_ID_HEADER, &supplied)
                .body(Body::empty())
                .expect("request must build");
            let response = support::router(pool)
                .oneshot(request)
                .await
                .expect("router should respond");
            assert_eq!(response.status(), StatusCode::OK);
        });
    });

    let captured = sink.contents();
    let correlated = captured
        .lines()
        .any(|line| line.contains(&supplied) && line.contains("/metrics"));
    assert!(
        correlated,
        "no captured log line carries both the request id and the path it \
         belongs to; an id that is not on the line is not correlatable.\n\
         captured output was:\n{captured}"
    );
}

// ── Regression guard: streaming must survive the inbound deadline ─────────

/// A legitimate SSE stream still streams.
///
/// An inbound deadline that kills long-lived streams would take out token
/// streaming, which is a product feature. This asserts the whole streaming
/// path — 200, `text/event-stream`, real `data:` frames, terminal `[DONE]` —
/// still works with the hygiene layers installed.
#[sqlx::test]
async fn a_streaming_response_still_streams_with_the_hygiene_layers_installed(
    pool: PgPool,
) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;

    let marker = format!("ws4-5-stream-{}", Uuid::new_v4());
    let app = support::router_with_default(pool.clone(), "", CH_DB, "degrade_with_alert");
    let response = app
        .oneshot(chat_request(&marker, true))
        .await
        .expect("router should respond");

    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .unwrap_or_default();
    let body = support::response_text(response).await;

    assert_eq!(status, StatusCode::OK, "streaming request must be served");
    assert!(
        content_type.starts_with("text/event-stream"),
        "streaming request must answer as SSE, got {content_type:?}"
    );
    assert!(
        body.contains("data:"),
        "the SSE body must carry data frames; body={body}"
    );
    assert!(
        body.contains("[DONE]"),
        "the SSE body must terminate with [DONE]; body={body}"
    );
    Ok(())
}

// ── Log capture ───────────────────────────────────────────────────────────

/// An in-memory `MakeWriter` so a test can read what the subscriber wrote.
#[derive(Clone, Default)]
struct LogSink(Arc<Mutex<Vec<u8>>>);

impl LogSink {
    fn contents(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("log sink is not poisoned")).into_owned()
    }
}

impl std::io::Write for LogSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("log sink is not poisoned")
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogSink {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}
