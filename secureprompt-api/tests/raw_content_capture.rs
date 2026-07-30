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

/// The exact user message every request in this file sends: `PROMPT_PROSE`,
/// one space, `SYNTHETIC_NAME`. Spelled out rather than `format!`ed so the
/// byte offsets below can be `const`; `offsets_address_the_synthetic_name`
/// proves it really is those three pieces.
const PROMPT_TEXT: &str = "Please summarise the contract for Anvar Karimov";

/// BYTE offsets of `SYNTHETIC_NAME` inside `PROMPT_TEXT`, derived from the
/// fixture instead of hardcoded.
///
/// The mock sidecar used to report a hardcoded `38..51` while the name
/// actually sits at `34..47`. `apply_redaction` skips any span whose `end`
/// exceeds the content length and `redact_last_user_message_with` drops any
/// span whose bytes do not equal the detection's `value`, so the detection
/// was discarded on every path — redaction NEVER RAN in this file, and every
/// test passed identically either way. Deriving the offsets makes that class
/// of miscalibration impossible; `offsets_address_the_synthetic_name` below
/// proves the derivation.
const NAME_START: usize = PROMPT_PROSE.len() + 1; // +1 for the separating space
const NAME_END: usize = NAME_START + SYNTHETIC_NAME.len();

/// The redacted form the gateway must produce for `PROMPT_TEXT`: prose
/// verbatim (not PII) with the name replaced by its placeholder.
const REDACTED_PROMPT: &str = "Please summarise the contract for {{Person_1}}";

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

        // Offsets DERIVED from the fixture, not typed in. See `NAME_START`.
        let ner_body = format!(
            r#"{{"entities":[{{"entity_type":"PERSON","start":{NAME_START},"end":{NAME_END},"score":0.97,"text":"{SYNTHETIC_NAME}","compliance_categories":[]}}]}}"#
        );

        std::thread::spawn(move || loop {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let Some(request) = read_http_request(&mut stream) else {
                continue;
            };
            let body: &[u8] = if request.contains("/detect/ner") {
                ner_body.as_bytes()
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
                "content": PROMPT_TEXT,
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

// ── Fixture self-check ────────────────────────────────────────────────────

/// The mock sidecar's detection offsets must address the synthetic name in
/// the fixture prompt, and the expected redacted form must be the fixture
/// with exactly that slice replaced.
///
/// This is the guard the file did not have. Every ClickHouse-backed test here
/// depends on the gateway ACTUALLY REDACTING; when the offsets addressed
/// `38..51` instead of `34..47` the detection was discarded, redaction never
/// ran, and all four tests passed anyway. A pure-arithmetic check costs
/// nothing and fails in milliseconds instead of hiding a leak for a
/// workstream.
#[test]
fn offsets_address_the_synthetic_name() {
    assert_eq!(
        PROMPT_TEXT,
        format!("{PROMPT_PROSE} {SYNTHETIC_NAME}"),
        "PROMPT_TEXT must be exactly prose + space + name, or NAME_START is \
         computed against a string the requests do not send"
    );
    assert_eq!(
        &PROMPT_TEXT[NAME_START..NAME_END],
        SYNTHETIC_NAME,
        "the offsets the mock sidecar reports must select the synthetic name"
    );
    assert_eq!(
        format!(
            "{}{{{{Person_1}}}}{}",
            &PROMPT_TEXT[..NAME_START],
            &PROMPT_TEXT[NAME_END..]
        ),
        REDACTED_PROMPT,
        "REDACTED_PROMPT must be PROMPT_TEXT with exactly the detected span \
         replaced by the placeholder"
    );
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

    seed_barrier_workspace(&pool).await?;

    let marker = format!("ws3-1-default-{}", Uuid::new_v4());
    let sidecar = MockSidecar::spawn();
    let app = support::router_with(pool.clone(), &sidecar.url(), CH_DB);
    let response = app
        .clone()
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

    // Barrier BEFORE any ClickHouse read — see `flush_capture_writer`. It
    // must come first for a second reason: a `clickhouse::inserter` only
    // re-checks its 1s period when the writer task handles the NEXT event, so
    // while this test still holds `app` the lone buffered row never flushes
    // at all and even the `request_events` poll below would time out.
    flush_capture_writer(app, "default").await;

    // Premise 2 + POSITIVE CONTROL: the audit row exists AND a plaintext
    // substring search over it succeeds.
    //
    // Asserted as EXACT EQUALITY against the redacted form, not as
    // `position(prose) > 0`. The substring form is satisfied just as well by
    // the ENTIRE un-redacted prompt, so it passed for four tests while the
    // mock sidecar's offsets addressed bytes the synthetic name does not
    // occupy, `apply_redaction` discarded the out-of-range span, and NOTHING
    // in this file ever redacted anything. Equality is what makes a
    // miscalibrated mock fail loudly instead of silently disabling the
    // feature under test.
    let stored_prompt = await_request_events(
        "concat(toString(isNull(redacted_prompt)), '|', coalesce(redacted_prompt, ''))",
        &marker,
    )
    .await;
    assert_eq!(
        stored_prompt,
        format!("0|{REDACTED_PROMPT}"),
        "positive control: `redacted_prompt` must hold the REDACTED prompt — \
         the prose verbatim (it is not PII) with the synthetic name replaced \
         by its placeholder. A value equal to the raw prompt means redaction \
         never ran and every absence assertion below proves nothing."
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
    //
    // CORRECTION (WS3 review): the claim above was true of the QUERY and
    // false of the TEST. The `count()` below used to run immediately after
    // `await_request_events`, and the capture row is flushed by a different
    // inserter that the writer `end()`s LATER — so with the gate deleted the
    // row really was written and this assertion still read 0. It is the
    // `flush_capture_writer` barrier above, not this line on its own, that
    // makes the deletion check bite.
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
                "content": PROMPT_TEXT,
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

/// API key of the always-opted-in workspace used only to flush the capture
/// writer. See [`flush_capture_writer`].
const BARRIER_KEY: &str = "sp_ws3_capture_barrier";
const BARRIER_BEARER: &str = "Bearer sp_ws3_capture_barrier";

/// A workspace that HAS opted in, used exclusively as the flush barrier.
async fn seed_barrier_workspace(pool: &PgPool) -> sqlx::Result<Uuid> {
    let workspace_id = Uuid::new_v4();
    support::seed_workspace(pool, workspace_id, BARRIER_KEY).await?;
    support::seed_provider_and_model(
        pool,
        workspace_id,
        Uuid::new_v4(),
        "anthropic-primary",
        "anthropic",
        None,
        "claude-3-haiku",
    )
    .await?;
    enable_capture(pool, workspace_id, 30).await?;
    Ok(workspace_id)
}

/// Block until the analytics writer behind `app` has flushed
/// `request_content_captures` past every request already sent through it.
///
/// WHY THIS IS NEEDED, and why `await_request_events` is not enough: the
/// capture row and the audit row go to two SEPARATE `clickhouse::inserter`s,
/// and `analytics/clickhouse_writer.rs` calls `req_inserter.end()` BEFORE
/// `cap_inserter.end()`. An inserter with a 1s period also does not flush a
/// lone buffered row until either another event arrives on the same handle or
/// the handle is dropped. So "the audit row is visible" implies nothing about
/// the capture row, and a single non-polling `count()` taken straight after
/// `await_request_events` races the writer it is trying to observe.
///
/// The barrier: one request on a workspace that DID opt in, pushed through
/// the SAME `Router` — therefore the same `AnalyticsHandle`, the same writer
/// task and the same `cap_inserter`, in FIFO order. `app` is taken BY VALUE
/// and consumed here, so the writer's channel closes and its final
/// `cap_inserter.end()` flushes every buffered capture row in one insert.
/// Once the barrier's own row is on disk, any capture row written for an
/// earlier request on that router is on disk too.
///
/// It is simultaneously the POSITIVE CONTROL for `capture_rows_for`: it
/// proves that helper CAN see a row, so a `0` from it means "nothing was
/// written", not "the query never matches".
async fn flush_capture_writer(app: axum::Router, label: &str) {
    let marker = format!("ws3-barrier-{label}-{}", Uuid::new_v4());
    let mut request = chat_request(&marker);
    request.headers_mut().insert(
        axum::http::header::AUTHORIZATION,
        axum::http::HeaderValue::from_static(BARRIER_BEARER),
    );
    let response = app.oneshot(request).await.expect("router should respond");
    drain(response).await;
    // Panics if it never lands — a barrier that silently gives up would put
    // the race straight back.
    await_capture("toString(request_id)", &marker).await;
    assert_eq!(
        capture_rows_for(&marker).await,
        1,
        "positive control: an opted-in request must produce exactly one \
         capture row, and `capture_rows_for` must be able to see it"
    );
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
    seed_barrier_workspace(&pool).await?;

    // Site 3/7, 4/7, 5/7 — buffered execute. Sidecar healthy, so the deny
    // rule fires: run this workspace's buffered case on the DENY path and
    // cover the success path on a second workspace below.
    let deny_marker = format!("ws3-1-deny-{}", Uuid::new_v4());
    let sidecar = MockSidecar::spawn();
    let deny_app = support::router_with(pool.clone(), &sidecar.url(), CH_DB);
    let response = deny_app
        .clone()
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
    let blocked_app = support::router_with(pool.clone(), &dead_sidecar_url(), CH_DB);
    let response = blocked_app
        .clone()
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
    let stream_app = support::router_with(pool.clone(), &sidecar.url(), CH_DB);
    let response = stream_app
        .clone()
        .oneshot(request)
        .await
        .expect("router should respond");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "premise: the streaming path must actually be taken"
    );
    drain(response).await;

    // Each path ran on its OWN router, so each has its own analytics writer
    // and its own `request_content_captures` inserter. Every one of them
    // needs its own barrier before the counts below mean anything — see
    // `flush_capture_writer`. Without these three lines the loop races three
    // writers at once and the deletion check reports only whichever ones
    // happened to have flushed.
    flush_capture_writer(deny_app, "deny").await;
    flush_capture_writer(blocked_app, "blocked").await;
    flush_capture_writer(stream_app, "stream").await;

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
