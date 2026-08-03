//! FU4 — what a session listing is allowed to say about the device that opened
//! it.
//!
//! # Why this module exists rather than two columns copied from headers
//!
//! A session listing is only useful if an administrator can tell one entry from
//! another: "you have three sessions" does not answer "which of these is the
//! laptop I lost". The two headers that answer it, `User-Agent` and
//! `X-Forwarded-For`, are also personal data and are also attacker-controlled
//! on `POST /v1/auth/token`, which is unauthenticated. Copying them verbatim
//! would take on three costs at once — a browser fingerprint, an unbounded
//! write primitive, and a column whose contents nobody can predict.
//!
//! So neither header is stored as sent:
//!
//!   * [`client_descriptor`] reduces the User-Agent to `{browser} on {os}` from
//!     a CLOSED vocabulary. "Chrome on macOS" distinguishes your laptop from
//!     your phone, which is the whole requirement; it does not carry the
//!     version numbers, build ids and extension hints that make a User-Agent
//!     string identifying. Anything unrecognised on both axes yields `None` —
//!     storing "Unknown on Unknown" would be a row of noise, not a fact.
//!   * [`client_ip`] returns the address only when it PARSES as one, and
//!     re-serialises it from the parsed value rather than echoing the input. A
//!     header that is not an address is dropped.
//!
//! Both are recorded once, at sign-in, and never on rotation — see migration
//! 027's header for why a per-rotation copy would be a movement log.

use std::net::IpAddr;

use axum::http::HeaderMap;

/// The device that opened a session, as much of it as is stored.
///
/// Both fields are `None` for a client that sent neither header, or sent values
/// nothing could be made of. That is a legitimate answer and the listing
/// reports it as "unknown" rather than inventing one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceContext {
    pub client_ip: Option<String>,
    pub client_descriptor: Option<String>,
}

impl DeviceContext {
    /// Derive the storable device context from a request's headers.
    #[must_use]
    pub fn from_headers(headers: &HeaderMap) -> Self {
        Self {
            client_ip: client_ip(headers),
            client_descriptor: header_str(headers, "user-agent").and_then(client_descriptor),
        }
    }
}

/// The client address, but only if it is one.
///
/// `X-Forwarded-For` is a comma-separated list appended to by each proxy; the
/// FIRST entry is the original client, which is the same entry
/// `auth::client_ip_key` rate-limits on. It is also the entry the client
/// controls, so the value is parsed as an [`IpAddr`] and re-rendered from the
/// parse rather than echoed: whatever lands in the column is an address of at
/// most 45 characters, which is what migration 027's CHECK constraint enforces
/// independently.
///
/// Returns `None` when the header is absent, unparseable, or a hostname. The
/// deployment terminates TLS at nginx and the router does not attach
/// `ConnectInfo`, so there is no socket address to fall back to — see
/// `auth::client_ip_key`, which has the same limitation for the same reason.
#[must_use]
pub fn client_ip(headers: &HeaderMap) -> Option<String> {
    let first = header_str(headers, "x-forwarded-for")?
        .split(',')
        .next()?
        .trim()
        .to_owned();
    first.parse::<IpAddr>().ok().map(|addr| addr.to_string())
}

/// One browser family the descriptor can name, and the token that identifies
/// it. ORDER IS LOAD-BEARING and is the reason this is a table rather than a
/// chain of `if`s: Edge announces itself as `Edg/… Chrome/… Safari/…`, Opera as
/// `OPR/… Chrome/…`, and Chrome as `Chrome/… Safari/…`. Matching Chrome or
/// Safari first would report every Edge user as Chrome and every Chrome user as
/// Safari, so the most specific token is tried first and `descriptor_order_is_
/// most_specific_first` asserts exactly that on real strings.
const BROWSERS: &[(&str, &str)] = &[
    ("Edg/", "Edge"),
    ("OPR/", "Opera"),
    ("Chrome/", "Chrome"),
    ("Firefox/", "Firefox"),
    ("Safari/", "Safari"),
    ("curl/", "curl"),
];

/// Operating-system families. Order matters here too: an iPhone's User-Agent
/// contains `like Mac OS X`, and Android's contains `Linux`.
const PLATFORMS: &[(&str, &str)] = &[
    ("iPhone", "iOS"),
    ("iPad", "iOS"),
    ("Android", "Android"),
    ("CrOS", "ChromeOS"),
    ("Windows", "Windows"),
    ("Mac OS X", "macOS"),
    ("Macintosh", "macOS"),
    ("Linux", "Linux"),
];

/// Reduce a User-Agent to `{browser} on {os}`, or to whichever half is known.
///
/// Returns `None` when neither axis matches, so an unrecognised client stores
/// nothing rather than a row of `Unknown`.
///
/// The output is drawn entirely from [`BROWSERS`] and [`PLATFORMS`], so no byte
/// of the input reaches the database. That is what
/// `no_part_of_the_input_reaches_the_output` pins.
#[must_use]
pub fn client_descriptor(user_agent: &str) -> Option<String> {
    let browser = BROWSERS
        .iter()
        .find(|(token, _)| user_agent.contains(token))
        .map(|(_, name)| *name);
    let platform = PLATFORMS
        .iter()
        .find(|(token, _)| user_agent.contains(token))
        .map(|(_, name)| *name);

    match (browser, platform) {
        (Some(browser), Some(platform)) => Some(format!("{browser} on {platform}")),
        (Some(browser), None) => Some(browser.to_owned()),
        (None, Some(platform)) => Some(platform.to_owned()),
        (None, None) => None,
    }
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHROME_MAC: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
                              AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 \
                              Safari/537.36";
    const EDGE_WINDOWS: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                                (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 \
                                Edg/141.0.0.0";
    const SAFARI_IPHONE: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) \
                                 AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 \
                                 Mobile/15E148 Safari/604.1";
    const FIREFOX_LINUX: &str =
        "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0";
    const CHROME_ANDROID: &str = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 \
                                  (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36";

    /// The whole table, spelled out rather than derived, so a reordering shows
    /// up here as a diff and not as a still-green tautology.
    ///
    /// Every case is a real User-Agent shape, and each one is a trap: Edge,
    /// Opera and Android Chrome all contain `Chrome/`; Chrome and Safari both
    /// contain `Safari/`; iPhone contains `Mac OS X`; Android contains `Linux`.
    #[test]
    fn descriptor_order_is_most_specific_first() {
        let cases = [
            (CHROME_MAC, Some("Chrome on macOS")),
            (EDGE_WINDOWS, Some("Edge on Windows")),
            (SAFARI_IPHONE, Some("Safari on iOS")),
            (FIREFOX_LINUX, Some("Firefox on Linux")),
            (CHROME_ANDROID, Some("Chrome on Android")),
            (
                "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/141.0.0.0 \
                 Safari/537.36 OPR/117.0.0.0",
                Some("Opera on Windows"),
            ),
            (
                "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 \
                 Chrome/141.0.0.0 Safari/537.36",
                Some("Chrome on ChromeOS"),
            ),
            // One axis only — still worth storing.
            ("curl/8.7.1", Some("curl")),
            (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                Some("macOS"),
            ),
            // Neither axis. `None`, not "Unknown on Unknown".
            ("", None),
            ("SecurePromptAgent/1.0", None),
        ];
        for (input, expected) in cases {
            assert_eq!(
                client_descriptor(input).as_deref(),
                expected,
                "client_descriptor({input:?})"
            );
        }
    }

    /// The output vocabulary is closed. Nothing a caller sends can reach the
    /// database through this function, which is what makes the column bounded
    /// in a way a length check alone would not.
    #[test]
    fn no_part_of_the_input_reaches_the_output() {
        let hostile = format!(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/{} Safari/537.36",
            "9".repeat(8000)
        );
        let descriptor = client_descriptor(&hostile).expect("a recognised browser and platform");
        assert_eq!(descriptor, "Chrome on macOS");
        assert!(
            !descriptor.contains('9'),
            "no byte of the input may survive into the stored value: {descriptor}"
        );

        // Every reachable output is one of these, so migration 027's 64-char
        // CHECK cannot be violated by any input at all.
        let longest = BROWSERS
            .iter()
            .flat_map(|(_, browser)| {
                PLATFORMS
                    .iter()
                    .map(move |(_, platform)| format!("{browser} on {platform}"))
            })
            .map(|s| s.len())
            .max()
            .expect("the tables are not empty");
        assert!(
            longest <= 64,
            "the longest possible descriptor is {longest} chars, which the \
             column CHECK would reject"
        );
    }

    /// A value that is not an address is dropped rather than stored, and the
    /// stored form comes from the PARSE rather than from the header.
    #[test]
    fn only_a_real_address_is_kept_and_it_is_re_rendered() {
        let cases = [
            ("203.0.113.7", Some("203.0.113.7")),
            // Proxy chain — the first entry is the original client.
            ("203.0.113.7, 198.51.100.1, 10.0.0.1", Some("203.0.113.7")),
            ("  203.0.113.7  ", Some("203.0.113.7")),
            // IPv6, re-rendered in its canonical compressed form. The stored
            // value therefore differs from the header the client sent, which is
            // the point: it is the parse, not the input.
            (
                "2001:0db8:0000:0000:0000:0000:0000:0001",
                Some("2001:db8::1"),
            ),
            // Not addresses.
            ("not-an-ip-address", None),
            ("evil.example.com", None),
            ("", None),
            ("'; DROP TABLE refresh_tokens; --", None),
        ];
        for (header, expected) in cases {
            let mut headers = HeaderMap::new();
            headers.insert("x-forwarded-for", header.parse().expect("header value"));
            assert_eq!(
                client_ip(&headers).as_deref(),
                expected,
                "client_ip({header:?})"
            );
        }

        // Absent header — no address, and no panic.
        assert_eq!(client_ip(&HeaderMap::new()), None);
    }

    /// Whatever `client_ip` returns fits migration 027's 45-character CHECK.
    /// The bound is the longest IPv6 text form; assert it against one rather
    /// than trusting the arithmetic.
    #[test]
    fn every_stored_address_fits_the_column_check() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "0000:0000:0000:0000:0000:ffff:255.255.255.255"
                .parse()
                .expect("header value"),
        );
        let stored = client_ip(&headers).expect("a valid IPv4-mapped IPv6 address");
        assert!(
            stored.len() <= 45,
            "stored address {stored:?} is {} chars, past the column CHECK",
            stored.len()
        );
    }

    #[test]
    fn from_headers_reads_both_axes_and_an_empty_request_records_nothing() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.7".parse().expect("value"));
        headers.insert("user-agent", CHROME_MAC.parse().expect("value"));
        assert_eq!(
            DeviceContext::from_headers(&headers),
            DeviceContext {
                client_ip: Some("203.0.113.7".to_owned()),
                client_descriptor: Some("Chrome on macOS".to_owned()),
            }
        );
        assert_eq!(
            DeviceContext::from_headers(&HeaderMap::new()),
            DeviceContext::default(),
            "a request carrying neither header records nothing, rather than \
             recording a placeholder"
        );
    }
}
