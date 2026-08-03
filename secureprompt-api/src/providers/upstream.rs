//! WS4-5 — the deadline on the OUTBOUND provider call.
//!
//! An inbound `TimeoutLayer` bounds how long a *caller* waits. It does not
//! touch the socket a provider adapter is blocked on: the caller gets its 504,
//! the request future is dropped, and — depending on how the client is built —
//! the connection can stay in flight until some far-away total timeout. On a
//! gateway that multiplexes every tenant through one pooled client, that is
//! the failure that matters: a provider that accepts sockets and answers
//! nothing exhausts the pool and takes the gateway down for everybody.
//!
//! The configuration this module builds is the fix, and it is three separate
//! deadlines because they answer three different questions:
//!
//! * **connect** — the upstream is black-holing TCP. Without an explicit
//!   deadline this is the OS connect timeout, which on Linux is over two
//!   minutes.
//! * **read (idle)** — the upstream connected, took the request, and went
//!   quiet. `reqwest` arms this before the response head arrives and resets it
//!   after every successful read, so it covers both "never answered" and
//!   "stopped answering half way through a stream". This is the one that
//!   releases a hung socket; see `tests/upstream_deadline.rs`, which asserts
//!   the SERVER observes the release rather than asserting the caller saw an
//!   error.
//! * **total** — a wall clock on one whole request/response. Applied
//!   PER-REQUEST on the buffered path only. It is deliberately NOT set on the
//!   client, because a client-level total also caps streaming: token streaming
//!   is a product feature and a long answer is not a fault. A stream is bounded
//!   by the idle deadline instead, which is the honest statement of what has
//!   gone wrong ("no bytes for N seconds") rather than "this answer took too
//!   long".
//!
//! All three are operator-tunable; the defaults preserve the behaviour the
//! gateway shipped with (a 120 s ceiling on a buffered provider call) and add
//! the two deadlines it did not have.

use std::time::Duration;

/// TCP/TLS connect deadline. 10 s is generous for a TLS handshake to a public
/// provider and still an order of magnitude below the OS default.
pub const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 10_000;

/// Idle-read deadline. Must clear the worst legitimate silence, which on the
/// buffered path is a provider that sends no response head until the whole
/// completion is generated — so it is set to the same 120 s the buffered total
/// has always used rather than to a small "surely a healthy stream ticks more
/// often than this" number.
pub const DEFAULT_READ_TIMEOUT_MS: u64 = 120_000;

/// Wall clock for one buffered provider call. Unchanged from the value
/// `shared_http_client` has always used.
pub const DEFAULT_TOTAL_TIMEOUT_MS: u64 = 120_000;

/// Env var names, in one place so the docs and the parser cannot drift.
pub const CONNECT_ENV: &str = "SECUREPROMPT_UPSTREAM_CONNECT_TIMEOUT_MS";
pub const READ_ENV: &str = "SECUREPROMPT_UPSTREAM_READ_TIMEOUT_MS";
pub const TOTAL_ENV: &str = "SECUREPROMPT_UPSTREAM_TOTAL_TIMEOUT_MS";

/// The three deadlines that bound one upstream call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpstreamDeadline {
    pub connect: Duration,
    pub read_idle: Duration,
    pub total: Duration,
}

impl Default for UpstreamDeadline {
    fn default() -> Self {
        Self {
            connect: Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS),
            read_idle: Duration::from_millis(DEFAULT_READ_TIMEOUT_MS),
            total: Duration::from_millis(DEFAULT_TOTAL_TIMEOUT_MS),
        }
    }
}

impl UpstreamDeadline {
    /// The whole decision as a pure function over plain values — the
    /// `license_gate` house pattern — so every parse case is unit-testable
    /// without touching the process environment.
    ///
    /// A value that is absent, unparseable, or **zero** falls back to the
    /// default. Zero is rejected rather than honoured as "no deadline": the
    /// absence of a deadline is precisely the defect this module exists to
    /// remove, and an operator who fat-fingers `0` should not silently
    /// reintroduce it.
    #[must_use]
    pub fn parse(
        connect_ms: Option<&str>,
        read_idle_ms: Option<&str>,
        total_ms: Option<&str>,
    ) -> Self {
        let defaults = Self::default();
        Self {
            connect: positive_millis(connect_ms).unwrap_or(defaults.connect),
            read_idle: positive_millis(read_idle_ms).unwrap_or(defaults.read_idle),
            total: positive_millis(total_ms).unwrap_or(defaults.total),
        }
    }

    /// [`Self::parse`] against the process environment.
    #[must_use]
    pub fn from_env() -> Self {
        let connect = std::env::var(CONNECT_ENV).ok();
        let read_idle = std::env::var(READ_ENV).ok();
        let total = std::env::var(TOTAL_ENV).ok();
        Self::parse(connect.as_deref(), read_idle.as_deref(), total.as_deref())
    }
}

/// `Some(duration)` only for a parseable, strictly positive millisecond count.
fn positive_millis(raw: Option<&str>) -> Option<Duration> {
    let millis: u64 = raw?.trim().parse().ok()?;
    (millis > 0).then(|| Duration::from_millis(millis))
}

/// Build the HTTP client every provider adapter shares.
///
/// `total` is intentionally absent here — see the module docs. The pool
/// settings are unchanged from the client this replaced: HTTP/2 plus a warm
/// idle pool is what keeps time-to-first-token low, and shrinking the pool to
/// "fix" a hung upstream would treat the symptom.
#[must_use]
pub fn build_upstream_client(deadline: &UpstreamDeadline) -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(deadline.connect)
        .read_timeout(deadline.read_idle)
        // Keep idle connections around for ~90s — long enough that typical
        // chat sessions land on a warm pool.
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(32)
        // HTTP/2 is on by default for HTTPS; explicit TCP keep-alive helps the
        // rare HTTP/1.1 fallbacks.
        .tcp_keepalive(Duration::from_secs(30))
        .build()
        .expect("reqwest::Client build with default-only options cannot fail")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_configuration_yields_the_documented_defaults() {
        let parsed = UpstreamDeadline::parse(None, None, None);
        assert_eq!(parsed, UpstreamDeadline::default());
        assert_eq!(
            parsed.connect,
            Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS)
        );
        assert_eq!(
            parsed.read_idle,
            Duration::from_millis(DEFAULT_READ_TIMEOUT_MS)
        );
        assert_eq!(
            parsed.total,
            Duration::from_millis(DEFAULT_TOTAL_TIMEOUT_MS)
        );
    }

    #[test]
    fn each_deadline_is_tuned_independently() {
        let parsed = UpstreamDeadline::parse(Some("250"), Some("500"), Some("750"));
        assert_eq!(parsed.connect, Duration::from_millis(250));
        assert_eq!(parsed.read_idle, Duration::from_millis(500));
        assert_eq!(parsed.total, Duration::from_millis(750));
    }

    /// Zero is the "no deadline at all" configuration this module exists to
    /// remove, so it is not honoured.
    #[test]
    fn zero_and_garbage_fall_back_to_the_default_rather_than_disabling_the_deadline() {
        for bad in ["0", "", "  ", "-1", "abc", "10s", "1.5"] {
            let parsed = UpstreamDeadline::parse(Some(bad), Some(bad), Some(bad));
            assert_eq!(
                parsed,
                UpstreamDeadline::default(),
                "{bad:?} must fall back to the default deadline, not disable it"
            );
        }
    }

    #[test]
    fn whitespace_around_a_good_value_is_tolerated() {
        assert_eq!(
            UpstreamDeadline::parse(Some(" 300 "), None, None).connect,
            Duration::from_millis(300)
        );
    }
}
