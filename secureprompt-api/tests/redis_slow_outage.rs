//! MR3 F16 — the Redis outage mode that is not ECONNREFUSED.
//!
//! `tests/auth_redis_outage.rs` induces its outages with `dead_url()`, which
//! binds an ephemeral port and drops the listener. That is a real socket
//! failure rather than a flag a test set, and the suite is right to say so —
//! but every failure it induces is **ECONNREFUSED**, which returns from
//! `pool.get()` immediately. F16's accurate half is that the stated
//! Redis-outage policy was therefore proven only for the fast-failing form.
//!
//! The other form is Redis reachable at the IP level and **not answering** —
//! a partition, a blackholed SYN, a thrashing or swapping server. There is no
//! refusal to observe, so an unbounded connect would sit in the kernel
//! through its SYN-retry budget: ~75 s on macOS, ~130 s on Linux, both far
//! past the 150 s inbound deadline's usefulness and far past any human's
//! patience.
//!
//! # F16's other half is FALSE, and this file is the measurement
//!
//! F16 concluded "the slow form does not degrade — it stalls", and asked for
//! `deadpool` wait/response timeouts. Measured at this tip, in both slow-fail
//! inductions below, the checkout returns an error in **~1.00 s** and the
//! outage policy is reached normally. Setting `deadpool`'s timeouts to 60 s
//! each does not change that number, because they are upper bounds and are
//! not what is binding. See `redis::build_pool`'s doc for the full
//! measurement and the `redis`-crate constants that are.
//!
//! So the production change F16 asked for is not made. What is closed is the
//! coverage gap F16 correctly identified: nothing exercised the slow form.
//!
//! # HOW LOAD-BEARING THIS IS, stated plainly rather than implied
//!
//! No single-line change to THIS repository's source can redden
//! `an_unanswering_redis_fails_the_checkout_instead_of_stalling`. Two
//! candidate mutations were run and neither did: setting `deadpool`'s three
//! timeouts to 60 s (still 1.0018 s), and removing them again. The bound is
//! `redis` 1.2.0's `DEFAULT_CONNECTION_TIMEOUT` / `DEFAULT_RESPONSE_TIMEOUT`,
//! a dependency default this repository does not configure.
//!
//! That is precisely why the test is worth having rather than a reason to
//! drop it: the property the gateway depends on is owned by somebody else's
//! crate, so the change that breaks it is a version bump, and a version bump
//! is exactly the kind of change no reviewer reads for auth-outage behaviour.
//! This test is the thing that would notice. It is honest about being pinned
//! against a dependency rather than against our own code.
//!
//! What WAS proved, so "cannot be reddened from here" is not mistaken for
//! "asserts nothing": a SENSITIVITY run with `TEST_CEILING` lowered to 400 ms
//! — below the ~1.00 s the checkout really takes — turns both inductions RED
//! (1 passed / 2 failed) while the premise test stays green. So the
//! assertions are coupled to the measured latency and not satisfied by their
//! own structure. A checkout that slowed down, or stopped being bounded,
//! moves them.
//!
//! The premise test below IS reddenable by ordinary means, and guards the
//! failure mode that would otherwise make this suite pass for the wrong
//! reason forever.

use std::net::TcpStream;
use std::time::{Duration, Instant};

use secureprompt_api::http::middleware::request_hygiene::DEFAULT_REQUEST_DEADLINE_MS;
use secureprompt_api::redis::{build_pool, session_gates};

/// TEST-NET-1 (RFC 5737). Reserved for documentation, routed nowhere, so a
/// SYN is dropped rather than refused.
const BLACKHOLE_HOST: &str = "192.0.2.1:6379";

/// How long the premise probe waits before calling the address a blackhole.
/// A refusal comes back in microseconds on loopback and in milliseconds
/// across a network, so anything still outstanding at 2 s is not a refusal.
const PREMISE_PROBE: Duration = Duration::from_secs(2);

/// The ceiling this suite holds the production checkout to.
///
/// Chosen for MARGIN in both directions rather than to be tight: 20x above
/// the ~1.00 s the checkout actually takes, so a loaded CI box cannot redden
/// it; and 3-6x below the kernel's SYN-retry budget, so a genuinely unbounded
/// checkout cannot survive it. F13 flagged a test in this tree whose budget
/// and threshold were the same number and which therefore asserted nothing —
/// this is the opposite arrangement, and the gap is the point.
const TEST_CEILING: Duration = Duration::from_secs(20);

/// PREMISE for the blackhole test. If this address ever starts refusing
/// connections instead of dropping them, that test silently stops exercising
/// the slow-fail mode and starts re-testing the fast-fail mode
/// `auth_redis_outage.rs` already covers — passing for the wrong reason,
/// forever. So it is asserted rather than assumed, the same discipline
/// `auth_redis_outage.rs` applies to its own induction.
#[test]
fn the_blackhole_address_hangs_rather_than_refusing() {
    let address = BLACKHOLE_HOST.parse().expect("parse blackhole address");

    let started = Instant::now();
    let outcome = TcpStream::connect_timeout(&address, PREMISE_PROBE);
    let elapsed = started.elapsed();

    match outcome {
        Ok(_) => panic!(
            "PREMISE BROKEN: {BLACKHOLE_HOST} ACCEPTED a connection. Something \
             on this network answers for TEST-NET-1, so this suite is no \
             longer inducing an unanswering Redis and its green is worthless."
        ),
        Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {}
        Err(error) => panic!(
            "PREMISE BROKEN: {BLACKHOLE_HOST} failed in {elapsed:?} with \
             `{error}` (kind {:?}) rather than hanging. A refusal or an \
             unreachable-host error is the FAST-fail mode that \
             `auth_redis_outage.rs` already covers — this suite exists for \
             the slow one, and would now be testing the wrong thing.",
            error.kind()
        ),
    }
}

/// Induction 1 — a blackholed SYN. Nothing answers at any layer.
#[tokio::test]
async fn an_unanswering_redis_fails_the_checkout_instead_of_stalling() {
    let elapsed =
        assert_checkout_is_bounded(&format!("redis://{BLACKHOLE_HOST}"), "blackholed SYN").await;

    assert!(
        elapsed < TEST_CEILING,
        "elapsed {elapsed:?} reached the test ceiling {TEST_CEILING:?}"
    );
}

/// Induction 2 — the mode the blackhole does NOT cover, and the one F16
/// actually named: "Redis reachable at TCP level and hanging".
///
/// This server COMPLETES the TCP handshake and then never sends a byte, so
/// the connect succeeds and the stall, if there were one, would be in the
/// protocol exchange rather than in `connect()`. `deadpool` is not in that
/// path at all — which is the concrete reason F16's suggested fix could not
/// have addressed the case it was asked to address.
#[tokio::test]
async fn a_redis_that_accepts_and_then_goes_silent_also_fails_the_checkout() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let port = listener.local_addr().expect("local addr").port();

    // Accept and HOLD. Dropping the socket would send a FIN and turn this
    // back into a fast failure, which is the mode this test is NOT for.
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            held.push(socket);
        }
    });

    let elapsed =
        assert_checkout_is_bounded(&format!("redis://127.0.0.1:{port}"), "accepts then silent")
            .await;

    assert!(
        elapsed < TEST_CEILING,
        "elapsed {elapsed:?} reached the test ceiling {TEST_CEILING:?}"
    );
}

/// The shared body: the checkout against `url` must come back, and must come
/// back as an ERROR the outage policy can act on.
///
/// Returning `Ok` would mean the fixture is not really unreachable, which
/// would make the timing assertion meaningless — so that is checked too,
/// rather than assuming the induction worked.
async fn assert_checkout_is_bounded(url: &str, induction: &str) -> Duration {
    let pool = build_pool(url).expect("pool construction is lazy and must succeed");

    let user = uuid::Uuid::new_v4();
    let started = Instant::now();
    let outcome = tokio::time::timeout(TEST_CEILING, session_gates(&pool, "some-jti", &user)).await;
    let elapsed = started.elapsed();

    let Ok(result) = outcome else {
        panic!(
            "[{induction}] the Redis checkout did not return within \
             {TEST_CEILING:?}. This is MR3 F16's stall, and it would mean the \
             bound documented on `redis::build_pool` is gone — most likely a \
             `redis` crate bump that changed DEFAULT_CONNECTION_TIMEOUT or \
             DEFAULT_RESPONSE_TIMEOUT to None. `session_gates` never reaches \
             jwt_auth's decision tree, so no reason label is emitted and no \
             counter moves; the request sits until the \
             {DEFAULT_REQUEST_DEADLINE_MS} ms inbound deadline cuts it with a \
             504, which is not the stated outage policy. Fix by setting the \
             timeout explicitly in `build_pool` — and note that `deadpool`'s \
             own Timeouts are measured INERT for this, see that doc."
        );
    };

    assert!(
        result.is_err(),
        "[{induction}] the checkout RESOLVED against a fixture that answers \
         nothing, so it did not really talk to Redis and the timing above \
         measures nothing: {result:?}"
    );

    elapsed
}
