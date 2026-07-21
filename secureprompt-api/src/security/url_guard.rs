//! SSRF egress guard.
//!
//! Validates a caller-supplied URL, resolves it, screens every resolved
//! address against blocked ranges, and pins the validated address at
//! connect time so the connection cannot be re-resolved afterwards
//! (TOCTOU / DNS-rebinding defence).

use std::net::IpAddr;

/// Deployment-scoped egress policy.
///
/// `allow_private_ranges` exists because on-prem and air-gapped installs
/// legitimately point providers at internal vLLM/Ollama endpoints on
/// RFC1918 addresses. Cloud metadata is denied regardless — see
/// `classify_ip`.
#[derive(Debug, Clone)]
pub struct EgressPolicy {
    pub allow_private_ranges: bool,
    pub extra_denied_hosts: Vec<String>,
}

impl EgressPolicy {
    /// Deny private ranges. The safe default for cloud/GKE deployments.
    #[must_use]
    pub fn deny_private() -> Self {
        Self { allow_private_ranges: false, extra_denied_hosts: Vec::new() }
    }

    /// Read `SECUREPROMPT_ALLOW_PRIVATE_PROVIDER_URLS`. Absent or
    /// unparseable means deny.
    #[must_use]
    pub fn from_env() -> Self {
        let raw = std::env::var("SECUREPROMPT_ALLOW_PRIVATE_PROVIDER_URLS").ok();
        Self {
            allow_private_ranges: Self::parse_flag(raw.as_deref()),
            extra_denied_hosts: Vec::new(),
        }
    }

    /// Truthy-flag parsing, factored out so it is testable without
    /// mutating process env (which races across parallel tests).
    #[must_use]
    pub fn parse_flag(raw: Option<&str>) -> bool {
        matches!(
            raw.map(|v| v.trim().to_ascii_lowercase()).as_deref(),
            Some("1" | "true" | "yes" | "on")
        )
    }
}

/// Why an outbound request was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsrfError {
    InvalidUrl(String),
    ForbiddenScheme(String),
    CredentialsInUrl,
    MissingHost,
    DeniedHost(String),
    DnsFailure(String),
    BlockedAddress { host: String, addr: IpAddr, reason: &'static str },
}

impl std::fmt::Display for SsrfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUrl(e) => write!(f, "invalid URL: {e}"),
            Self::ForbiddenScheme(s) => write!(f, "forbidden URL scheme: {s}"),
            Self::CredentialsInUrl => write!(f, "URL must not embed credentials"),
            Self::MissingHost => write!(f, "URL has no host"),
            Self::DeniedHost(h) => write!(f, "host is denied by policy: {h}"),
            Self::DnsFailure(e) => write!(f, "DNS resolution failed: {e}"),
            Self::BlockedAddress { host, addr, reason } => {
                write!(f, "host {host} resolves to blocked address {addr} ({reason})")
            }
        }
    }
}

impl std::error::Error for SsrfError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_denies_private_by_default() {
        let p = EgressPolicy::deny_private();
        assert!(!p.allow_private_ranges);
        assert!(p.extra_denied_hosts.is_empty());
    }

    #[test]
    fn policy_from_env_parses_truthy_values() {
        for v in ["1", "true", "TRUE", "yes", "on"] {
            assert!(EgressPolicy::parse_flag(Some(v)), "{v} must enable private ranges");
        }
        for v in ["0", "false", "no", "off", "", "garbage"] {
            assert!(!EgressPolicy::parse_flag(Some(v)), "{v} must NOT enable private ranges");
        }
        assert!(!EgressPolicy::parse_flag(None), "unset must default to deny");
    }

    #[test]
    fn ssrf_error_displays_reason() {
        let e = SsrfError::ForbiddenScheme("file".into());
        assert!(e.to_string().contains("file"));
    }
}
