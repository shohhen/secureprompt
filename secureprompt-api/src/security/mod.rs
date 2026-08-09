//! Outbound-egress security controls.
//!
//! Every caller-influenced URL that becomes an outbound HTTP request must
//! pass through `url_guard`. See
//! `docs/superpowers/specs/2026-07-20-phase1-security-hardening-design.md` §3.

pub mod url_guard;

pub use url_guard::{build_pinned_client, parse_and_check_url, validate_outbound_url, EgressPolicy, SsrfError, ValidatedUrl};
