//! WS4-5, acceptance criterion 4 — the inbound deadline bounds the response
//! HEAD, not the body, so a stream that outlives it is not cut.
//!
//! # What the previous version of this test measured: nothing in this product
//!
//! `the_inbound_deadline_does_not_cut_a_stream_that_outlives_it` used to build
//! its own `Router::new()` and its own `TimeoutLayer`, reference zero product
//! symbols, and assert that tower-http behaves the way tower-http behaves.
//! Grepping its body for `secureprompt_api`, `build_router`,
//! `inbound_deadline` or `DEFAULT_REQUEST_DEADLINE_MS` matched only the
//! function's own name, and deleting the gateway's entire `TimeoutLayer` left
//! it green. It was the sole evidence offered for this criterion.
//!
//! The property it asserted is true — `tower_http::timeout::Timeout` races the
//! sleep against production of the response head and stops caring once the
//! handler has returned — but it was true by DEPENDENCY BEHAVIOUR, unasserted
//! against this product.
//!
//! Both tests here drive the real [`secureprompt_api::http::build_router`], the
//! real `/v1/chat/completions` route and the real deadline layer. MEASURED,
//! each mutation applied to production source and restored:
//!
//!   * DELETE the `TimeoutLayer` from `http/mod.rs` →
//!     `a_request_that_outruns_the_inbound_deadline_is_cut_with_504` FAILS
//!     ("got 401 Unauthorized after 6.68s" — the slow request ran to
//!     completion). The old test stayed green through this exact deletion.
//!   * REMOVE the streaming dispatch, so `stream: true` is answered buffered →
//!     `the_inbound_deadline_does_not_cut_a_stream_that_outlives_it` FAILS
//!     ("premise: the response under test must be a stream, got
//!     application/json").
//!
//! # A limit this file cannot reach, stated rather than implied
//!
//! Adding `tower_http::timeout::ResponseBodyTimeoutLayer` — the swap the
//! review named as the silent break — leaves BOTH tests green, and that was
//! measured too rather than assumed. The reason is in tower-http's
//! `TimeoutBody::poll_frame`: the `Sleep` is created LAZILY on the first poll
//! and reset after every frame, so it bounds the gap the INNER BODY spends
//! pending, not wall-clock since the head. This gateway's stream comes from
//! the in-process echo stub, whose frames are already materialised, so the
//! inner body is never pending and no body timeout can fire against it —
//! holding the body undrained for three deadlines (which this file does) does
//! not start the clock either.
//!
//! Detecting that swap needs a SLOW PRODUCER, i.e. an upstream fixture that
//! trickles SSE frames. That is not reachable today: `OpenAiCompatAdapter`'s
//! `base_url` is a `&'static str` fixed at construction, so no test can point
//! the chat path at a local server. When that becomes configurable, the
//! discriminating test is a fixture emitting frames further apart than the
//! deadline. Until then this file's streaming half pins that the real route
//! streams complete frames under a short deadline — not that a body timeout
//! would be caught.
//!
//! # Why this is its own test binary
//!
//! `build_router` reads the deadline from `SECUREPROMPT_REQUEST_DEADLINE_MS`
//! at CONSTRUCTION time, and an environment variable is process-global.
//! Setting a two-second deadline inside `tests/request_hygiene.rs` would hand
//! it to whichever sibling test happened to construct a router in the same
//! millisecond. Cargo runs each integration test file as its own process, so a
//! file of its own is the isolation — and the two tests in it want the same
//! value, so they cannot fight over it either.
//!
//! All fixture PII is synthetic.

mod support;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use secureprompt_api::http::middleware::request_hygiene::{
    DEADLINE_ENV, DEFAULT_REQUEST_DEADLINE_MS,
};
use serde_json::json;
use sqlx::PgPool;
use std::net::SocketAddr;
use std::time::Duration;
use tower::ServiceExt;
use uuid::Uuid;

const API_KEY: &str = "sp_ws4_5_inbound_deadline_streaming";
const CH_DB: &str = "sp_analytics";

/// The deadline this file installs, in milliseconds.
///
/// Short enough that a test can outlive it without a slow suite; long enough
/// that the gateway's ordinary work on this route — Postgres, the redaction
/// pipeline, the audit write — finishes well inside it, so the 504 in the
/// control below is the deadline firing and not a busy machine.
const DEADLINE_MS: u64 = 2_000;

/// How long a body is held undrained before it is read: three deadlines.
const HOLD: Duration = Duration::from_millis(DEADLINE_MS * 3);

async fn seed(pool: &PgPool, workspace_id: Uuid) -> sqlx::Result<()> {
    support::seed_workspace(pool, workspace_id, API_KEY).await?;
    support::seed_provider_and_model(
        pool,
        workspace_id,
        Uuid::new_v4(),
        "anthropic-primary",
        // `anthropic` is an echo stub in this workspace, so a request that
        // gets past the gates reaches a working provider with no network
        // egress — the stream under test is the GATEWAY's, not a vendor's.
        "anthropic",
        None,
        "claude-3-haiku",
    )
    .await
}

/// The real router, built with a deliberately short inbound deadline.
///
/// The `set_var` must precede `build_router`, which reads the variable once at
/// construction — see the module docs for why that forces this file to be its
/// own binary.
fn router_with_short_deadline(pool: PgPool) -> Router {
    assert!(
        DEADLINE_MS < DEFAULT_REQUEST_DEADLINE_MS,
        "premise: the installed deadline ({DEADLINE_MS} ms) must be shorter \
         than the product default ({DEFAULT_REQUEST_DEADLINE_MS} ms), or these \
         tests are measuring the default and can never outlive it"
    );
    std::env::set_var(DEADLINE_ENV, DEADLINE_MS.to_string());
    support::router_with_default(pool, "", CH_DB, "degrade_with_alert")
}

fn chat_request(stream: bool) -> Request<Body> {
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
        format!("ws4-5-deadline-{}", Uuid::new_v4())
            .parse()
            .expect("marker is a valid header value"),
    );
    // `chat_completions` extracts `ConnectInfo<SocketAddr>`; `oneshot` bypasses
    // the connection layer that installs it in production.
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 50_001))));
    request
}

// ── The control: the deadline is live, short, and it does cut ─────────────

/// POSITIVE CONTROL. A request whose RESPONSE HEAD cannot be produced inside
/// the deadline is cut with 504, through the real router.
///
/// Without this, "the stream survived" below is also what you would see from a
/// router with no deadline layer at all — which is exactly the state the old
/// test could not distinguish.
///
/// The slowness is on the REQUEST BODY, and that is the point rather than a
/// convenience: `TimeoutLayer` bounds the future that produces the response,
/// and the `Json` extractor cannot produce one until the body has arrived. So
/// a trickling request body is a head that is late, driven entirely from the
/// test side with no production change and no hung vendor. `/v1/auth/token`
/// is used because it is unauthenticated — a 504 here cannot be an auth
/// refusal wearing a different number.
#[sqlx::test]
async fn a_request_that_outruns_the_inbound_deadline_is_cut_with_504(pool: PgPool) {
    let app = router_with_short_deadline(pool);

    // A body that arrives long after the deadline. `Content-Length` is absent,
    // so nothing can answer before the stream ends.
    let slow = Body::from_stream(futures_util::stream::once(async move {
        tokio::time::sleep(HOLD).await;
        Ok::<_, std::io::Error>(br#"{"email":"nobody@example.invalid","password":"x"}"#.to_vec())
    }));
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/auth/token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(slow)
        .expect("request must build");

    let started = std::time::Instant::now();
    let response = app.oneshot(request).await.expect("router should respond");
    let elapsed = started.elapsed();

    assert_eq!(
        response.status(),
        StatusCode::GATEWAY_TIMEOUT,
        "the inbound deadline must cut a request whose head cannot be \
         produced in {DEADLINE_MS} ms; got {} after {elapsed:?}",
        response.status()
    );
    assert!(
        elapsed < HOLD,
        "premise: the 504 must arrive BEFORE the slow body would have \
         finished ({HOLD:?}), or the request completed on its own and the \
         status above is not the deadline; elapsed {elapsed:?}"
    );
}

// ── The claim: a stream that outlives the deadline is not cut ─────────────

/// The deadline does not cut a stream that OUTLIVES it.
///
/// `a_streaming_response_still_streams_with_the_hygiene_layers_installed` in
/// `tests/request_hygiene.rs` finishes in milliseconds, so it would pass
/// whether or not the body were bounded; it proves the stream works, not that
/// a long one survives.
///
/// This drives the same real route with a short deadline and then HOLDS the
/// response body undrained for three of them before reading a byte. Under
/// `TimeoutLayer` the timer stopped when the head was produced, so every frame
/// is still there.
///
/// The assertion is on the FRAMES, not on the status: a 200 with an empty or
/// truncated body is precisely what a cut stream looks like to a client, and
/// asserting only the status would miss it. Removing the streaming dispatch
/// from `routes/openai.rs` is the measured kill — see the module docs, which
/// also state the mutation this test does NOT catch and why.
#[sqlx::test]
async fn the_inbound_deadline_does_not_cut_a_stream_that_outlives_it(
    pool: PgPool,
) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;
    let app = router_with_short_deadline(pool.clone());

    let response = app
        .oneshot(chat_request(true))
        .await
        .expect("router should respond");

    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .unwrap_or_default();

    // PREMISE: the head really is an SSE stream. If the gateway answered with
    // a buffered JSON body, holding it would prove nothing about streaming.
    assert_eq!(status, StatusCode::OK, "streaming request must be served");
    assert!(
        content_type.starts_with("text/event-stream"),
        "premise: the response under test must be a stream, got {content_type:?}"
    );

    // Hold the body, undrained, for three deadlines.
    let body = response.into_body();
    tokio::time::sleep(HOLD).await;

    let collected = body.collect().await;
    let bytes = match collected {
        Ok(c) => c.to_bytes(),
        Err(e) => panic!(
            "the response body was cut after the inbound deadline elapsed: \
             {e}. `TimeoutLayer` must bound the response HEAD only; a layer \
             that bounds the BODY kills token streaming, which is a product \
             feature."
        ),
    };
    let text = String::from_utf8(bytes.to_vec()).expect("body must be utf-8");

    assert!(
        text.contains("data:"),
        "no data frames survived a {HOLD:?} hold under a {DEADLINE_MS} ms \
         deadline; body={text}"
    );
    assert!(
        text.contains("[DONE]"),
        "the stream was truncated before its terminal sentinel — a client \
         would see a half-written answer; body={text}"
    );
    Ok(())
}
