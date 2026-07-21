//! Outbound-egress security controls.
//!
//! Every caller-influenced URL that becomes an outbound HTTP request must
//! pass through `url_guard`. See
//! `docs/superpowers/specs/2026-07-20-phase1-security-hardening-design.md` §3.

pub mod url_guard;

// NOTE: `build_pinned_client`, `validate_outbound_url`, and `ValidatedUrl` are
// added to this re-export list by Task 4 (DNS resolution / async validation)
// and Task 5 (pinned HTTP client builder) once `url_guard` defines them. The
// plan's mod.rs listing shows the final state; re-exporting them here before
// they exist does not compile, so Task 1 exports only what it produces.
pub use url_guard::{EgressPolicy, SsrfError};
