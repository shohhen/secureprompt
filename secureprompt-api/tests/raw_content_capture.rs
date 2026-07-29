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

/// Apply ClickHouse migration 007 the same way the worker does at startup.
///
/// Idempotent (`IF NOT EXISTS`), and deliberately NOT a "skip if the table is
/// missing" guard: a missing table must surface as a real failure, never as a
/// quietly-passing "no raw content found". The migration text is read from
/// the real file rather than restated, so this cannot drift from what the
/// worker applies.
async fn ensure_capture_table() {
    const MIGRATION: &str =
        include_str!("../clickhouse/migrations/007_request_content_captures.sql");
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
    ensure_capture_table().await;
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

    // ...and nothing went to the opt-in store either. This assertion is not
    // redundant with the two above: since WS3-1 the writer sends NULL for the
    // `request_events` raw columns UNCONDITIONALLY, so deleting the opt-in
    // gate in `analytics::capture::seal` would move the plaintext into
    // `request_content_captures` and leave every request_events assertion
    // above still passing. Without this line the test would keep its name and
    // stop testing the gate.
    assert_eq!(
        capture_rows_for(&marker).await,
        0,
        "a fresh install must write no row at all to request_content_captures"
    );

    Ok(())
}

// ── Fixtures for the opt-in half ──────────────────────────────────────────

/// Opt a workspace in, straight into Postgres. The HTTP route that normally
/// does this (`PUT /v1/secure-mode`, admin-only, audited) is covered by
/// `tests/dashboard/secure_mode_tests.rs`; writing the row directly here
/// keeps these pipeline assertions independent of the settings API.
async fn enable_capture(
    pool: &PgPool,
    workspace_id: Uuid,
    retention_days: i32,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO workspace_raw_capture (workspace_id, enabled, retention_days, updated_at)
         VALUES ($1, true, $2, NOW())
         ON CONFLICT (workspace_id) DO UPDATE SET
            enabled = true, retention_days = EXCLUDED.retention_days",
    )
    .bind(workspace_id)
    .bind(retention_days)
    .execute(pool)
    .await
    .map(|_| ())
}

/// An address nothing is listening on — the `AllCallsFailed` sidecar outage
/// that drives `fail_closed_on_coverage_loss` (capture site 1/7).
fn dead_sidecar_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);
    format!("http://{addr}")
}

fn streaming_chat_request(marker: &str) -> Request<axum::body::Body> {
    let mut request = support::authorized_request(
        Request::builder()
            .method(Method::POST)
            .uri("/v1/chat/completions"),
        API_KEY,
        json!({
            "model": "claude-3-haiku",
            "stream": true,
            "messages": [{
                "role": "user",
                "content": format!("{PROMPT_PROSE} {SYNTHETIC_NAME}"),
            }],
        }),
    );
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 50_000))));
    request.headers_mut().insert(
        axum::http::header::USER_AGENT,
        axum::http::HeaderValue::from_str(marker).expect("marker is a valid header value"),
    );
    request
}

/// Drain an SSE response so the streaming finalizer (capture sites 6/7)
/// actually runs — it is deferred until the upstream stream drains.
async fn drain(response: axum::response::Response) {
    use http_body_util::BodyExt;
    let _ = response.into_body().collect().await;
}

/// Count capture rows for one request. `request_id` is not visible to the
/// caller, so the marker is resolved through `request_events` first — which
/// doubles as the premise that the request produced an audit row at all.
async fn capture_rows_for(marker: &str) -> u32 {
    let request_id = await_request_events("toString(request_id)", marker).await;
    ch_query(&format!(
        "SELECT count() FROM request_content_captures \
         WHERE request_id = toUUID('{request_id}')"
    ))
    .await
    .parse()
    .expect("count() returns a number")
}

/// Poll for the capture row's columns, since the writer batches.
async fn await_capture(expr: &str, marker: &str) -> String {
    let request_id = await_request_events("toString(request_id)", marker).await;
    for _ in 0..40 {
        let out = ch_query(&format!(
            "SELECT {expr} FROM request_content_captures \
             WHERE request_id = toUUID('{request_id}') LIMIT 1"
        ))
        .await;
        if !out.is_empty() {
            return out;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    panic!("no request_content_captures row appeared for marker {marker}");
}

// ── WS3-1: every one of the seven write sites is gated ────────────────────

/// The seven original assignments live on four distinct code paths. This
/// drives ALL FOUR on a workspace that never opted in and asserts none of
/// them produced a capture row.
///
/// PREMISE for every path: an audit row for that request exists in
/// `request_events`. That is what makes "zero capture rows" mean "the gate
/// held" rather than "the request never happened". Each path's expected HTTP
/// status is asserted too, so a path that silently stopped exercising its
/// branch fails instead of passing.
#[sqlx::test]
async fn no_write_site_captures_raw_content_by_default(pool: PgPool) -> sqlx::Result<()> {
    ensure_capture_table().await;
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;
    // A rule that denies on any PERSON detection — drives capture site 2/7.
    support::seed_policy_rule(
        &pool,
        workspace_id,
        "deny person",
        10,
        json!([{ "field": "detection_class", "op": "eq", "value": "PERSON" }]),
        "deny",
        json!({}),
        false,
    )
    .await?;

    // Site 3/7, 4/7, 5/7 — buffered execute. Sidecar healthy, so the deny
    // rule fires: run this workspace's buffered case on the DENY path and
    // cover the success path on a second workspace below.
    let deny_marker = format!("ws3-1-deny-{}", Uuid::new_v4());
    let sidecar = MockSidecar::spawn();
    let response = support::router_with(pool.clone(), &sidecar.url(), CH_DB)
        .oneshot(chat_request(&deny_marker))
        .await
        .expect("router should respond");
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "premise: the policy rule must actually deny, otherwise capture site \
         2/7 is never reached"
    );

    // Site 1/7 — fail-closed on coverage loss. Default sidecar policy is
    // `block`, so a dead sidecar rejects with 503 after writing an audit row.
    let blocked_marker = format!("ws3-1-blocked-{}", Uuid::new_v4());
    let response = support::router_with(pool.clone(), &dead_sidecar_url(), CH_DB)
        .oneshot(chat_request(&blocked_marker))
        .await
        .expect("router should respond");
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "premise: the fail-closed path must actually be taken"
    );

    // A second workspace with no deny rule, for the success paths.
    let clean_ws = Uuid::new_v4();
    support::seed_workspace(&pool, clean_ws, "sp_ws3_1_clean").await?;
    support::seed_provider_and_model(
        &pool,
        clean_ws,
        Uuid::new_v4(),
        "anthropic-primary",
        "anthropic",
        None,
        "claude-3-haiku",
    )
    .await?;

    // Sites 6/7 and 7/7 — the streaming finalizer.
    let stream_marker = format!("ws3-1-stream-{}", Uuid::new_v4());
    let sidecar = MockSidecar::spawn();
    let mut request = streaming_chat_request(&stream_marker);
    request.headers_mut().insert(
        axum::http::header::AUTHORIZATION,
        axum::http::HeaderValue::from_static("Bearer sp_ws3_1_clean"),
    );
    let response = support::router_with(pool.clone(), &sidecar.url(), CH_DB)
        .oneshot(request)
        .await
        .expect("router should respond");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "premise: the streaming path must actually be taken"
    );
    drain(response).await;

    // Accumulate rather than assert-and-abort, so a deletion check sees
    // EVERY site that regressed in one run instead of only the first.
    let mut leaked: Vec<String> = Vec::new();
    for (label, marker) in [
        ("policy deny (site 2/7)", &deny_marker),
        ("fail-closed (site 1/7)", &blocked_marker),
        ("streaming (sites 6/7, 7/7)", &stream_marker),
    ] {
        let rows = capture_rows_for(marker).await;
        if rows != 0 {
            leaked.push(format!("{label}: {rows} capture row(s)"));
        }
    }
    assert!(
        leaked.is_empty(),
        "a workspace that never opted in must produce no capture row on any \
         path; leaked on: {leaked:?}"
    );

    Ok(())
}

/// POSITIVE CONTROL for the whole file, and the WS3-2 acceptance criterion.
///
/// The SAME requests on a workspace that DID opt in must produce capture
/// rows — and what is on disk must be ciphertext. Both halves are read
/// straight out of ClickHouse; nothing here goes through the decrypt path,
/// because a round-trip through our own decrypt would pass just as happily
/// against plaintext.
#[sqlx::test]
async fn opted_in_workspace_stores_ciphertext_only(pool: PgPool) -> sqlx::Result<()> {
    ensure_capture_table().await;
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;
    enable_capture(&pool, workspace_id, 30).await?;

    let marker = format!("ws3-2-buffered-{}", Uuid::new_v4());
    let sidecar = MockSidecar::spawn();
    let response = support::router_with(pool.clone(), &sidecar.url(), CH_DB)
        .oneshot(chat_request(&marker))
        .await
        .expect("router should respond");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        sidecar
            .ner_requests()
            .iter()
            .any(|r| r.contains(SYNTHETIC_NAME)),
        "premise: the pipeline must have run over the real prompt"
    );

    // Premise: a capture row exists, is flagged encrypted, and carries a
    // non-empty payload in all three fields. "No plaintext found" in an empty
    // string is not a result.
    let shape = await_capture(
        "concat(toString(encrypted), ',', toString(length(coalesce(raw_prompt, ''))>0), \
         ',', toString(length(coalesce(raw_response, ''))>0), ',', \
         toString(length(coalesce(restored_response, ''))>0))",
        &marker,
    )
    .await;
    assert_eq!(
        shape, "true,1,1,1",
        "premise: an opted-in request must store a flagged-encrypted row with \
         all three payloads present, got (encrypted,prompt,response,restored)={shape}"
    );

    let request_id = await_request_events("toString(request_id)", &marker).await;

    // POSITIVE CONTROL for the search method itself: the same
    // `position(... , '<needle>') > 0` test, over the SAME request, against a
    // column that is deliberately NOT encrypted, must FIND the needle. If
    // this reads 0 the assertions below prove nothing.
    let control = ch_query(&format!(
        "SELECT count() FROM request_events \
         WHERE request_id = toUUID('{request_id}') \
           AND position(coalesce(redacted_prompt, ''), '{PROMPT_PROSE}') > 0"
    ))
    .await;
    assert_eq!(
        control, "1",
        "positive control: the plaintext prose must be findable in \
         `redacted_prompt`, proving the substring search works"
    );

    // THE ASSERTION. Neither the prose nor the synthetic PII may appear
    // anywhere in the stored capture.
    for needle in [PROMPT_PROSE, SYNTHETIC_NAME] {
        let hits = ch_query(&format!(
            "SELECT count() FROM request_content_captures \
             WHERE request_id = toUUID('{request_id}') AND (\
                position(coalesce(raw_prompt, ''), '{needle}') > 0 OR \
                position(coalesce(raw_response, ''), '{needle}') > 0 OR \
                position(coalesce(restored_response, ''), '{needle}') > 0)"
        ))
        .await;
        assert_eq!(
            hits, "0",
            "'{needle}' is stored in plaintext in request_content_captures"
        );
    }

    // Defence in depth: even with capture ON, nothing raw goes into
    // `request_events`. That table backs the cost and latency dashboards and
    // has a fixed 90-day TTL nobody can shorten per workspace.
    let nulls = await_request_events(
        "concat(toString(isNull(raw_prompt)), ',', toString(isNull(raw_response)), \
         ',', toString(isNull(restored_response)))",
        &marker,
    )
    .await;
    assert_eq!(
        nulls, "1,1,1",
        "capture must never repopulate the request_events columns, got {nulls}"
    );

    Ok(())
}

/// WS3-2 — retention is per workspace, and it is genuinely independent of
/// `request_events`' fixed 90-day row TTL: one workspace gets a window
/// SHORTER than 90 days and another gets one LONGER, and both are honoured.
///
/// Two workspaces with two different values is the positive control: a
/// hard-coded `expires_at` would have to disagree with one of them.
#[sqlx::test]
async fn retention_window_is_per_workspace(pool: PgPool) -> sqlx::Result<()> {
    ensure_capture_table().await;
    let short_ws = Uuid::new_v4();
    seed(&pool, short_ws).await?;
    enable_capture(&pool, short_ws, 7).await?;

    let long_ws = Uuid::new_v4();
    support::seed_workspace(&pool, long_ws, "sp_ws3_2_long").await?;
    support::seed_provider_and_model(
        &pool,
        long_ws,
        Uuid::new_v4(),
        "anthropic-primary",
        "anthropic",
        None,
        "claude-3-haiku",
    )
    .await?;
    enable_capture(&pool, long_ws, 180).await?;

    let short_marker = format!("ws3-2-short-{}", Uuid::new_v4());
    let sidecar = MockSidecar::spawn();
    let response = support::router_with(pool.clone(), &sidecar.url(), CH_DB)
        .oneshot(chat_request(&short_marker))
        .await
        .expect("router should respond");
    assert_eq!(response.status(), StatusCode::OK);

    let long_marker = format!("ws3-2-long-{}", Uuid::new_v4());
    let mut request = chat_request(&long_marker);
    request.headers_mut().insert(
        axum::http::header::AUTHORIZATION,
        axum::http::HeaderValue::from_static("Bearer sp_ws3_2_long"),
    );
    let sidecar = MockSidecar::spawn();
    let response = support::router_with(pool.clone(), &sidecar.url(), CH_DB)
        .oneshot(request)
        .await
        .expect("router should respond");
    assert_eq!(response.status(), StatusCode::OK);

    assert_eq!(
        await_capture("dateDiff('day', created_at, expires_at)", &short_marker).await,
        "7",
        "a 7-day workspace must expire its captured content after 7 days"
    );
    assert_eq!(
        await_capture("dateDiff('day', created_at, expires_at)", &long_marker).await,
        "180",
        "a 180-day workspace must be able to retain LONGER than the 90-day \
         row TTL on request_events — which is only possible because captured \
         content lives in its own table"
    );

    Ok(())
}
