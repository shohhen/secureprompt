//! WS3-1 / WS3-2 — raw prompt & response capture is opt-in, default OFF, and
//! encrypted at rest with a per-workspace retention when it is on.
//!
//! SecurePrompt's product claim is "your prompts never leave your building".
//! Before this workstream the gateway wrote the RAW user message, the RAW
//! upstream response and the PII-RESTORED response into its own ClickHouse in
//! plaintext, on every request, unconditionally, with no configuration gate
//! anywhere in the repo.
//!
//! Every assertion below reads ClickHouse DIRECTLY over HTTP rather than
//! through the dashboard API, because the question is what is on disk, not
//! what a handler chooses to show.
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

const API_KEY: &str = "sp_ws3_1_raw_capture";
/// Synthetic name — the "PII" the mock sidecar reports and the string every
/// leak assertion hunts for in ClickHouse.
const SYNTHETIC_NAME: &str = "Anvar Karimov";
/// Prose that surrounds the synthetic name in the prompt. It is NOT PII, it
/// survives redaction verbatim into `redacted_prompt`, and it is therefore
/// the positive control for "a substring search against ClickHouse finds
/// plaintext when plaintext is there".
const PROMPT_PROSE: &str = "Please summarise the contract for";

/// The gateway's own analytics database, so these assertions run against the
/// real `request_events` table rather than a bespoke fixture.
const CH_DB: &str = "sp_analytics";

// ── Mock ML sidecar ───────────────────────────────────────────────────────

/// Loopback server speaking just enough of the sidecar protocol for the
/// gateway request path. Captures every request so a test can prove the
/// gateway actually reached it.
struct MockSidecar {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
}

impl MockSidecar {
    fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local addr");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&requests);

        std::thread::spawn(move || loop {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let Some(request) = read_http_request(&mut stream) else {
                continue;
            };
            let body: &[u8] = if request.contains("/detect/ner") {
                br#"{"entities":[{"entity_type":"PERSON","start":38,"end":51,"score":0.97,"text":"Anvar Karimov","compliance_categories":[]}]}"#
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
/// bytes of body. A single fixed-size read truncates large `/detect/ner`
/// bodies and turns "the sidecar answered" into "the call failed".
fn read_http_request(stream: &mut std::net::TcpStream) -> Option<String> {
    let mut raw: Vec<u8> = Vec::new();
    let mut buf = [0u8; 8192];

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

    while raw.len() < header_end + content_length {
        let n = stream.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&buf[..n]);
    }
    Some(String::from_utf8_lossy(&raw).to_string())
}

// ── ClickHouse, read directly ─────────────────────────────────────────────

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
    text.trim().to_owned()
}

/// Poll for one expression evaluated over the request's audit row. The
/// analytics writer batches on a 1s period, so nothing is visible
/// synchronously. Panics rather than skipping when the row never lands — a
/// missing row must be a failure, never a quiet pass.
async fn await_request_events(expr: &str, marker: &str) -> String {
    for _ in 0..40 {
        let out = ch_query(&format!(
            "SELECT {expr} FROM request_events WHERE user_agent = '{marker}' \
             ORDER BY created_at DESC LIMIT 1"
        ))
        .await;
        if !out.is_empty() {
            return out;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    panic!("no request_events row appeared for marker {marker}");
}

// ── Fixtures ──────────────────────────────────────────────────────────────

async fn seed(pool: &PgPool, workspace_id: Uuid) -> sqlx::Result<()> {
    support::seed_workspace(pool, workspace_id, API_KEY).await?;
    support::seed_provider_and_model(
        pool,
        workspace_id,
        Uuid::new_v4(),
        "anthropic-primary",
        // `anthropic` is an echo stub in this workspace, so a request that
        // gets past the gates reaches a working provider and returns 200.
        "anthropic",
        None,
        "claude-3-haiku",
    )
    .await
}

fn chat_request(marker: &str) -> Request<axum::body::Body> {
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
                "content": format!("{PROMPT_PROSE} {SYNTHETIC_NAME}"),
            }],
        }),
    );
    // `chat_completions` extracts `ConnectInfo<SocketAddr>`; `oneshot`
    // bypasses the connection layer that normally inserts it.
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 50_000))));
    // `user_agent` is a free-text passthrough used purely as a per-test
    // correlation key, since ClickHouse is shared across the whole suite.
    request.headers_mut().insert(
        axum::http::header::USER_AGENT,
        axum::http::HeaderValue::from_str(marker).expect("marker is a valid header value"),
    );
    request
}

// ── WS3-1: a fresh install stores ZERO raw content ────────────────────────

/// Acceptance criterion: a workspace that has never opted in stores no raw
/// prompt, no raw upstream response and no PII-restored response.
///
/// PREMISE ASSERTIONS, in order, so an absence can never pass trivially:
///   1. the mock sidecar was actually called with the real prompt — the
///      request went down the full pipeline, not a short-circuit;
///   2. an audit row for this exact request EXISTS in `request_events` —
///      the analytics writer ran and ClickHouse accepted the row;
///   3. that row's `redacted_prompt` contains the prompt prose verbatim —
///      the POSITIVE CONTROL: the same substring-search method, against the
///      same table, DOES find plaintext when plaintext is there. Without it,
///      "no raw content" could just mean the query never matches anything.
///
/// Only then does the absence assertion mean anything.
#[sqlx::test]
async fn fresh_workspace_stores_no_raw_content_in_clickhouse(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;

    // Premise: the workspace has never opted in. Asserted against Postgres so
    // the test cannot be passing because some fixture enabled capture.
    let opted_in: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM workspace_raw_capture WHERE workspace_id = $1 AND enabled",
    )
    .bind(workspace_id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        opted_in, 0,
        "test premise: a fresh workspace must have no capture opt-in"
    );

    let marker = format!("ws3-1-default-{}", Uuid::new_v4());
    let sidecar = MockSidecar::spawn();
    let app = support::router_with(pool.clone(), &sidecar.url(), CH_DB);
    let response = app
        .oneshot(chat_request(&marker))
        .await
        .expect("router should respond");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the request itself must succeed — a 4xx/5xx would make every \
         'nothing was stored' assertion below meaningless"
    );

    // Premise 1: the pipeline really ran.
    let ner = sidecar.ner_requests();
    assert!(
        ner.iter().any(|r| r.contains(SYNTHETIC_NAME)),
        "the gateway must have asked the sidecar about the REAL prompt; \
         captured requests:\n{ner:?}"
    );

    // Premise 2 + POSITIVE CONTROL: the audit row exists AND a plaintext
    // substring search over it succeeds.
    let prose_hits = await_request_events(
        &format!("toUInt8(position(coalesce(redacted_prompt, ''), '{PROMPT_PROSE}') > 0)"),
        &marker,
    )
    .await;
    assert_eq!(
        prose_hits, "1",
        "positive control: `redacted_prompt` must contain the prompt prose \
         verbatim. If this fails, the absence assertions below prove nothing \
         because the search method itself does not work."
    );

    // THE ASSERTION. Every raw-content column must be NULL.
    let nulls = await_request_events(
        "concat(toString(isNull(raw_prompt)), ',', toString(isNull(raw_response)), \
         ',', toString(isNull(restored_response)))",
        &marker,
    )
    .await;
    assert_eq!(
        nulls, "1,1,1",
        "a fresh install must store ZERO raw content in request_events \
         (raw_prompt, raw_response, restored_response), got isNull triple: {nulls}"
    );

    // And the synthetic PII must not be anywhere in the row.
    let leaked = ch_query(&format!(
        "SELECT count() FROM request_events WHERE user_agent = '{marker}' AND (\
            position(coalesce(raw_prompt, ''), '{SYNTHETIC_NAME}') > 0 OR \
            position(coalesce(raw_response, ''), '{SYNTHETIC_NAME}') > 0 OR \
            position(coalesce(restored_response, ''), '{SYNTHETIC_NAME}') > 0)"
    ))
    .await;
    assert_eq!(
        leaked, "0",
        "the synthetic PII leaked into request_events on a workspace that \
         never opted in"
    );

    Ok(())
}
