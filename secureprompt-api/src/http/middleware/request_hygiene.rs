//! WS4-5 — request-path hygiene: request-id propagation, and the two limits
//! (body size, inbound deadline) whose values the router needs.
//!
//! ## Why the request id is a `Uuid` and not the caller's string
//!
//! The point of propagating an id is that an incident responder can take one
//! value — from a client bug report, a log line, or a support ticket — and land
//! on the audit row. That row's `request_id` column is a ClickHouse `UUID`, so
//! a caller's `x-request-id: req_abc123` has nowhere to go: storing it would
//! mean adding a second, parallel identifier and hoping the two never disagree.
//!
//! So the rule is narrow and total: **a caller's id is adopted if and only if
//! it is a UUID; otherwise the gateway mints one.** Either way the resolved id
//! goes back on the response, so a caller that sent something unusable is still
//! TOLD the id its request was recorded under. Nothing is rejected — a bad
//! `x-request-id` is not an error, it is just not adopted.
//!
//! This also happens to be the whole of the input-validation story. The value
//! reaches `tracing` output; an attacker-supplied string could otherwise carry
//! newlines and forge log lines, or be megabytes long. A parsed `Uuid` is
//! 36 characters of hex and dashes by construction, so there is no sanitiser to
//! get wrong.
//!
//! ## Where these layers sit
//!
//! See `http::build_router`. Summary: CORS stays outermost (an error response a
//! browser cannot read is not an error response), then request-id, then
//! `TraceLayer`, then the body limit, then the inbound deadline, then the
//! license gate and the routes. Auth and rate-limiting run inside the handlers,
//! so all of this is above them — which is the point of a body limit.

use axum::{
    extract::Request,
    http::{HeaderMap, HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
};
use secureprompt_common::types::RequestId;
use std::time::Duration;
use uuid::Uuid;

/// The de-facto standard correlation header. Read on the way in, always set on
/// the way out.
pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

/// Default maximum request body, in bytes.
///
/// 2 MiB — deliberately the same number as axum's per-extractor
/// `DefaultBodyLimit`, so introducing an edge limit does not narrow any route
/// that works today. What changes is not the size but the coverage: the edge
/// limit applies to every route, including the ones with no body extractor, and
/// it is enforced on `Content-Length` before a byte is read.
pub const DEFAULT_MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

/// Default inbound deadline, in milliseconds.
///
/// 150 s, chosen to sit ABOVE the 120 s upstream total
/// ([`crate::providers::upstream::DEFAULT_TOTAL_TIMEOUT_MS`]) plus the
/// input-side work (`detect` + policy) that runs before it. That ordering is
/// deliberate: the deadline that should normally fire is the upstream one,
/// because it is the one that also releases the provider socket. This layer is
/// the backstop for the cases that deadline cannot see — a wedged handler, a
/// Postgres lock, a task that never wakes — not the primary control.
pub const DEFAULT_REQUEST_DEADLINE_MS: u64 = 150_000;

pub const MAX_BODY_ENV: &str = "SECUREPROMPT_MAX_BODY_BYTES";
pub const DEADLINE_ENV: &str = "SECUREPROMPT_REQUEST_DEADLINE_MS";

/// What the gate decided about one request's id, as plain values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedRequestId {
    pub id: Uuid,
    /// `true` when the caller's `x-request-id` was adopted verbatim.
    pub from_caller: bool,
}

/// The whole decision as a pure function — the `license_gate` house pattern.
/// `generated` is passed in rather than minted here so the function is
/// deterministic and every branch is unit-testable without HTTP.
#[must_use]
pub fn resolve_request_id(inbound: Option<&str>, generated: Uuid) -> ResolvedRequestId {
    match inbound.map(str::trim).map(Uuid::parse_str) {
        Some(Ok(id)) => ResolvedRequestId {
            id,
            from_caller: true,
        },
        _ => ResolvedRequestId {
            id: generated,
            from_caller: false,
        },
    }
}

/// Maximum request body from operator configuration.
///
/// Absent, unparseable or zero falls back to the default: zero would mean "no
/// body at all", which no caller wants and which an operator is far more likely
/// to have typed by accident than on purpose.
#[must_use]
pub fn parse_max_body_bytes(raw: Option<&str>) -> usize {
    raw.and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|bytes| *bytes > 0)
        .unwrap_or(DEFAULT_MAX_BODY_BYTES)
}

/// Inbound deadline from operator configuration. Same fallback rule, same
/// reason: a zero deadline would time out every request instantly.
#[must_use]
pub fn parse_request_deadline(raw: Option<&str>) -> Duration {
    raw.and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|ms| *ms > 0)
        .map_or(
            Duration::from_millis(DEFAULT_REQUEST_DEADLINE_MS),
            Duration::from_millis,
        )
}

/// The resolved id for the request currently being served.
///
/// Reads the header [`propagate`] normalized on the way in, which is why this
/// is total in production: every route is behind that middleware. It is
/// `Option` anyway because a handler invoked directly in a unit test has no
/// middleware above it, and a missing id must degrade to "mint one in the
/// pipeline", never to a panic.
#[must_use]
pub fn request_id_from_headers(headers: &HeaderMap) -> Option<RequestId> {
    let raw = headers.get(&REQUEST_ID_HEADER)?.to_str().ok()?;
    Uuid::parse_str(raw).ok().map(RequestId)
}

/// The `tracing` span every request is served inside.
///
/// This is what puts the id ON the log line rather than merely in a field
/// somewhere: `tower_http`'s `TraceLayer` emits its request/response events
/// inside this span, and the `fmt` subscriber renders the span's fields as the
/// prefix of every one of them.
#[must_use]
pub fn make_span(request: &Request) -> tracing::Span {
    let request_id = request
        .headers()
        .get(&REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unknown");
    tracing::info_span!(
        "http_request",
        method = %request.method(),
        uri = %request.uri(),
        request_id,
    )
}

/// Resolve the request id, make it visible to the handler, and echo it back.
///
/// The inbound header is REWRITTEN to the resolved value rather than merely
/// read. That is what makes one identifier out of three places that would
/// otherwise be free to disagree: what the handler records in the audit row,
/// what the span puts on the log line, and what the caller is told. A caller
/// that sent `x-request-id: nonsense` sees the minted uuid in the response and
/// the same uuid in its audit row.
pub async fn propagate(mut request: Request, next: Next) -> Response {
    let inbound = request
        .headers()
        .get(&REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let resolved = resolve_request_id(inbound.as_deref(), Uuid::new_v4());

    let header_value = HeaderValue::from_str(&resolved.id.to_string())
        .expect("a uuid's hyphenated form is always a valid header value");
    request
        .headers_mut()
        .insert(REQUEST_ID_HEADER, header_value.clone());

    let mut response = next.run(request).await;
    // Set unconditionally: this middleware is above the body limit and the
    // inbound deadline, so a 413 or a 504 carries the id too — those are
    // exactly the responses an operator has to correlate after the fact.
    response
        .headers_mut()
        .insert(REQUEST_ID_HEADER, header_value);
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed() -> Uuid {
        Uuid::parse_str("11111111-2222-3333-4444-555555555555").expect("fixture uuid parses")
    }

    #[test]
    fn a_caller_supplied_uuid_is_adopted_verbatim() {
        let caller = Uuid::parse_str("0189d3f2-1c4b-7c3a-9f2e-0a1b2c3d4e5f").expect("parses");
        let resolved = resolve_request_id(Some(&caller.to_string()), fixed());
        assert_eq!(resolved.id, caller);
        assert!(resolved.from_caller);
    }

    #[test]
    fn a_missing_id_is_minted() {
        let resolved = resolve_request_id(None, fixed());
        assert_eq!(resolved.id, fixed());
        assert!(!resolved.from_caller);
    }

    /// The security half. Every one of these reaches `tracing` output and a
    /// `UUID` column if adopted, so none of them is.
    #[test]
    fn an_unusable_id_is_replaced_rather_than_carried_into_the_logs() {
        let overlong = "x".repeat(100_000);
        let hostile = [
            "",
            "   ",
            "req_abc123",
            // log-forging: a newline would start a fresh line in the output
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\nfake log line",
            // unbounded length
            overlong.as_str(),
            // uuid-ish but not a uuid
            "11111111-2222-3333-4444-55555555555",
            "not-a-uuid-at-all",
        ];
        for value in hostile {
            let resolved = resolve_request_id(Some(value), fixed());
            assert_eq!(
                resolved.id,
                fixed(),
                "{value:?} must not be adopted as a request id"
            );
            assert!(!resolved.from_caller);
        }
    }

    /// A trimmed uuid is still a uuid — clients that pad the header value are
    /// common enough that dropping their correlation would be a silent loss.
    #[test]
    fn surrounding_whitespace_does_not_lose_the_callers_id() {
        let caller = fixed();
        let padded = format!("  {caller}  ");
        let resolved = resolve_request_id(Some(&padded), Uuid::new_v4());
        assert_eq!(resolved.id, caller);
        assert!(resolved.from_caller);
    }

    #[test]
    fn limits_fall_back_to_the_documented_defaults() {
        for bad in [
            None,
            Some(""),
            Some("0"),
            Some("-5"),
            Some("2mb"),
            Some("1.5"),
        ] {
            assert_eq!(
                parse_max_body_bytes(bad),
                DEFAULT_MAX_BODY_BYTES,
                "{bad:?} must fall back to the default body limit"
            );
            assert_eq!(
                parse_request_deadline(bad),
                Duration::from_millis(DEFAULT_REQUEST_DEADLINE_MS),
                "{bad:?} must fall back to the default deadline"
            );
        }
        assert_eq!(parse_max_body_bytes(Some(" 4096 ")), 4096);
        assert_eq!(
            parse_request_deadline(Some("2500")),
            Duration::from_millis(2500)
        );
    }

    /// The inbound backstop must not fire before the upstream deadline that
    /// actually releases the provider socket, or every slow-but-healthy call
    /// would 504 while the socket stayed held. Asserted rather than asserted
    /// in prose, so a future edit to either constant surfaces here.
    #[test]
    fn the_inbound_deadline_sits_above_the_upstream_total() {
        assert!(
            DEFAULT_REQUEST_DEADLINE_MS > crate::providers::upstream::DEFAULT_TOTAL_TIMEOUT_MS,
            "the inbound backstop must outlast the upstream call it wraps"
        );
    }

    #[test]
    fn headers_yield_the_normalized_id_and_nothing_else() {
        let mut headers = HeaderMap::new();
        assert!(request_id_from_headers(&headers).is_none());

        headers.insert(REQUEST_ID_HEADER, HeaderValue::from_static("req_abc123"));
        assert!(
            request_id_from_headers(&headers).is_none(),
            "a non-uuid header must not become a RequestId"
        );

        let id = fixed();
        headers.insert(
            REQUEST_ID_HEADER,
            HeaderValue::from_str(&id.to_string()).expect("valid"),
        );
        assert_eq!(request_id_from_headers(&headers), Some(RequestId(id)));
    }
}
