//! WS4-5 — the OUTBOUND half of the deadline criterion.
//!
//! "Hung-upstream test releases the connection within the deadline" cannot be
//! satisfied by an inbound `TimeoutLayer`. That layer stops the *caller*
//! waiting; it does not touch the `reqwest` socket the provider adapter is
//! blocked on. A gateway that answers 504 while still holding one pooled
//! connection per hung request exhausts the pool and takes every tenant down —
//! the 504 is the symptom, not the fix.
//!
//! So this file asserts the thing that actually matters: the socket is
//! RELEASED, observed from the server side, within the configured deadline.
//! The hung upstream reports when its accepted socket saw the client let go.

use secureprompt_api::providers::upstream::{build_upstream_client, UpstreamDeadline};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

/// How long the test allows for the client to give up. Comfortably above the
/// 800 ms read deadline configured below and comfortably below anything that
/// could be confused with the 120 s total timeout the gateway ships with.
const BOUND: Duration = Duration::from_secs(3);

/// The upstream client under test — the PRODUCTION constructor, the one
/// `providers/openai_compat.rs::shared_upstream` calls, given a deadline short
/// enough to assert against.
///
/// The RED commit (d66ab6f) ran these same assertions against the client the
/// gateway built at b9c98a7 — `.timeout(120s)` and nothing else — and the call
/// was still in flight after 3 s. Only this function changed; every assertion
/// below is byte-for-byte what failed then.
fn client_under_test() -> reqwest::Client {
    build_upstream_client(&UpstreamDeadline::parse(
        Some("500"),  // connect
        Some("800"),  // read (idle)
        Some("5000"), // total — not applied by the client; see the module docs
    ))
}

/// What the hung upstream saw before its socket went away.
#[derive(Debug)]
struct Release {
    /// Bytes the client actually sent. PREMISE for the whole test: if this is
    /// zero the connection was never really used and "the socket was released"
    /// would be a statement about a connection that never carried a request.
    bytes_read: usize,
    /// Measured from `accept()` to the moment the socket reported EOF or reset.
    after: Duration,
    /// How the socket ended — EOF (the normal, graceful close) or a reset.
    how: String,
}

/// A TCP listener that accepts one connection, reads the request, and then
/// answers NOTHING, forever. A provider that has taken your socket and will
/// not give it back.
fn hung_upstream() -> (String, Receiver<Release>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let accepted = Instant::now();
        let mut bytes_read = 0usize;
        let mut buf = [0u8; 4096];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => {
                    let _ = tx.send(Release {
                        bytes_read,
                        after: accepted.elapsed(),
                        how: "eof".to_owned(),
                    });
                    return;
                }
                Ok(n) => bytes_read += n,
                Err(err) => {
                    let _ = tx.send(Release {
                        bytes_read,
                        after: accepted.elapsed(),
                        how: format!("error: {err}"),
                    });
                    return;
                }
            }
        }
    });

    (format!("http://{addr}/v1/chat/completions"), rx)
}

/// A listener that answers a real HTTP response — the positive control.
fn responsive_upstream() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");

    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut buf = [0u8; 4096];
        // Read just the head; the fixture body is small enough to arrive with
        // it, and the response does not depend on having all of it.
        let _ = stream.read(&mut buf);
        let body = b"{\"ok\":true}";
        let head = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(head.as_bytes());
        let _ = stream.write_all(body);
        let _ = stream.flush();
    });

    format!("http://{addr}/v1/chat/completions")
}

/// Acceptance criterion: a hung upstream releases the connection within the
/// deadline.
///
/// Three separate claims, because "the caller got an error" proves none of the
/// others:
///
///   1. the call fails within the bound (the caller is not pinned),
///   2. the SERVER observes the socket go away within the bound (the socket is
///      not leaked into the pool while the caller walks away),
///   3. the same client still completes a normal call (the deadline is a
///      deadline, not a broken client).
///
/// ## The runtime detail this test cannot do without
///
/// `flavor = "multi_thread"` and the `spawn_blocking` wait below are both
/// load-bearing, and the reason is worth writing down because it produced a
/// convincing false positive on the way here.
///
/// What actually closes the socket is hyper's connection TASK: reqwest's read
/// deadline resolves the caller's future with an error, and hyper then notices
/// its response callback was dropped and closes the connection. That happens on
/// the runtime, not on the caller. Waiting for the release with a BLOCKING
/// `recv_timeout` under the default single-threaded `#[tokio::test]` therefore
/// starves the one thread that could run it, and the socket stays open for as
/// long as you are willing to wait — measured here at over 100 s, which reads
/// exactly like a connection leak and is not one. Production is unaffected:
/// `main.rs` runs on `#[tokio::main]`, which is multi-threaded.
///
/// Measured with the deadline this test configures: caller errors at 803.4 ms,
/// server observes EOF at 803.8 ms. A raw `TcpStream` close is seen by this
/// harness in 12 µs, so the harness is not what is being measured.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hung_upstream_releases_the_connection_within_the_deadline() {
    let client = client_under_test();
    let (url, released) = hung_upstream();

    let started = Instant::now();
    let outcome = tokio::time::timeout(
        BOUND,
        client
            .post(&url)
            .json(&serde_json::json!({ "model": "m", "messages": [] }))
            .send(),
    )
    .await;

    let inner = outcome.unwrap_or_else(|_| {
        panic!(
            "the upstream call was still in flight after {BOUND:?} — the client \
             has no deadline that a hung provider can trip, so one hung request \
             pins one connection until the total timeout expires"
        )
    });
    assert!(
        inner.is_err(),
        "a provider that never answers must surface as an error, got {inner:?}"
    );
    let gave_up_after = started.elapsed();

    // Off the runtime — see the note above. A blocking wait on a runtime
    // thread would prevent the very close it is waiting for.
    let release = tokio::task::spawn_blocking(move || released.recv_timeout(BOUND))
        .await
        .expect("the waiting task must not panic")
        .unwrap_or_else(|err| {
            panic!(
                "the hung upstream never saw its socket released ({err}) — the \
                 caller got an error but the connection is still held, which is \
                 the leak this criterion exists to rule out"
            )
        });

    // PREMISE: the connection carried a real request. Without this, "the
    // socket was released" could be true of a socket that was never used.
    assert!(
        release.bytes_read > 0,
        "the hung upstream received no request bytes at all, so this test says \
         nothing about releasing a connection that was actually in use"
    );
    assert!(
        release.after <= BOUND,
        "socket released only after {:?} (how={}), which is past the {BOUND:?} \
         deadline; caller gave up after {gave_up_after:?}",
        release.after,
        release.how
    );

    // POSITIVE CONTROL: the same client, a responsive upstream, a real answer.
    let ok = client
        .post(responsive_upstream())
        .json(&serde_json::json!({ "model": "m", "messages": [] }))
        .send()
        .await
        .expect("a responsive upstream must still be reachable with this client");
    assert_eq!(
        ok.status(),
        reqwest::StatusCode::OK,
        "the deadline must not break healthy upstream calls"
    );
}
