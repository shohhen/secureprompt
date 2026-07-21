//! Outbound-egress security controls.
//!
//! Every caller-influenced URL that becomes an outbound HTTP request must
//! pass through `url_guard`. See
//! `docs/superpowers/specs/2026-07-20-phase1-security-hardening-design.md` §3.

pub mod url_guard;

// NOTE: `build_pinned_client` is added to this re-export list by Task 5
// (pinned HTTP client builder) once `url_guard` defines it.
pub use url_guard::{validate_outbound_url, EgressPolicy, SsrfError, ValidatedUrl};
