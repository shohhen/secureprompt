//! SSRF egress guard.
//!
//! Validates a caller-supplied URL, resolves it, screens every resolved
//! address against blocked ranges, and pins the validated address at
//! connect time so the connection cannot be re-resolved afterwards
//! (TOCTOU / DNS-rebinding defence).

use std::net::IpAddr;
use std::net::{Ipv4Addr, Ipv6Addr};

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

/// The IMDS address used by AWS, GCP, Azure, OpenStack and DigitalOcean.
const CLOUD_METADATA_V4: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);

/// Hostnames that must never be reachable, regardless of policy.
pub(crate) const ALWAYS_DENIED_HOSTS: &[&str] =
    &["metadata.google.internal", "metadata.goog", "instance-data"];

/// Classify an address. `Some(reason)` means BLOCKED.
///
/// `allow_private` relaxes ONLY the RFC1918 / unique-local arms. Loopback,
/// link-local, CGNAT, multicast, broadcast, unspecified and the cloud
/// metadata address stay blocked unconditionally: none of them is ever a
/// legitimate remote provider endpoint, and metadata in particular is the
/// exact target this guard exists to protect.
pub(crate) fn classify_ip(addr: IpAddr, allow_private: bool) -> Option<&'static str> {
    match addr {
        IpAddr::V4(v4) => classify_v4(v4, allow_private),
        IpAddr::V6(v6) => {
            // Unwrap IPv4-mapped form first, or ::ffff:169.254.169.254
            // would slip past every v4 check below.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return classify_v4(v4, allow_private);
            }
            if v6.is_loopback() {
                return Some("loopback");
            }
            if v6.is_unspecified() {
                return Some("unspecified");
            }
            if v6.is_multicast() {
                return Some("multicast");
            }
            if is_v6_link_local(v6) {
                return Some("link-local");
            }
            if is_v6_unique_local(v6) && !allow_private {
                return Some("unique-local");
            }
            None
        }
    }
}

fn classify_v4(v4: Ipv4Addr, allow_private: bool) -> Option<&'static str> {
    if v4 == CLOUD_METADATA_V4 {
        return Some("cloud metadata endpoint");
    }
    if v4.is_loopback() {
        return Some("loopback");
    }
    if v4.is_link_local() {
        return Some("link-local");
    }
    if v4.is_broadcast() {
        return Some("broadcast");
    }
    if v4.is_multicast() {
        return Some("multicast");
    }
    if v4.is_unspecified() {
        return Some("unspecified");
    }
    if is_cgnat_v4(v4) {
        return Some("CGNAT");
    }
    if v4.is_private() && !allow_private {
        return Some("private range");
    }
    None
}

/// 100.64.0.0/10 (RFC 6598).
fn is_cgnat_v4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 100 && (64..=127).contains(&o[1])
}

/// fe80::/10. `Ipv6Addr::is_unicast_link_local` is unstable, so match manually.
fn is_v6_link_local(v6: Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xffc0) == 0xfe80
}

/// fc00::/7. `Ipv6Addr::is_unique_local` is unstable, so match manually.
fn is_v6_unique_local(v6: Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xfe00) == 0xfc00
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn blocks_cloud_metadata_even_when_private_allowed() {
        // The single most important assertion in this module.
        assert_eq!(classify_ip(v4(169, 254, 169, 254), true), Some("cloud metadata endpoint"));
        assert_eq!(classify_ip(v4(169, 254, 169, 254), false), Some("cloud metadata endpoint"));
    }

    #[test]
    fn blocks_internal_ranges_when_private_denied() {
        assert_eq!(classify_ip(v4(127, 0, 0, 1), false), Some("loopback"));
        assert_eq!(classify_ip(v4(10, 0, 0, 5), false), Some("private range"));
        assert_eq!(classify_ip(v4(172, 16, 3, 9), false), Some("private range"));
        assert_eq!(classify_ip(v4(192, 168, 1, 14), false), Some("private range"));
        assert_eq!(classify_ip(v4(169, 254, 1, 1), false), Some("link-local"));
        assert_eq!(classify_ip(v4(100, 64, 0, 1), false), Some("CGNAT"));
        assert_eq!(classify_ip(v4(0, 0, 0, 0), false), Some("unspecified"));
        assert_eq!(classify_ip(v4(224, 0, 0, 1), false), Some("multicast"));
        assert_eq!(classify_ip(v4(255, 255, 255, 255), false), Some("broadcast"));
    }

    #[test]
    fn allows_private_when_policy_permits_but_never_loopback_or_linklocal() {
        // On-prem: internal vLLM/Ollama must work.
        assert_eq!(classify_ip(v4(192, 168, 1, 14), true), None);
        assert_eq!(classify_ip(v4(10, 0, 0, 5), true), None);
        // Loopback and link-local stay blocked — they are never a
        // legitimate *remote* provider endpoint.
        assert_eq!(classify_ip(v4(127, 0, 0, 1), true), Some("loopback"));
        assert_eq!(classify_ip(v4(169, 254, 1, 1), true), Some("link-local"));
    }

    #[test]
    fn allows_ordinary_public_addresses() {
        assert_eq!(classify_ip(v4(140, 82, 121, 4), false), None);
        assert_eq!(classify_ip(v4(8, 8, 8, 8), false), None);
    }

    #[test]
    fn blocks_ipv6_internal_ranges() {
        assert_eq!(classify_ip(IpAddr::V6(Ipv6Addr::LOCALHOST), false), Some("loopback"));
        assert_eq!(classify_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED), false), Some("unspecified"));
        // fe80::1 link-local
        assert_eq!(
            classify_ip(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)), false),
            Some("link-local")
        );
        // fd00::1 unique-local
        assert_eq!(
            classify_ip(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)), false),
            Some("unique-local")
        );
        // 2606:4700::1111 public
        assert_eq!(
            classify_ip(IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111)), false),
            None
        );
    }

    #[test]
    fn unwraps_ipv4_mapped_ipv6_before_classifying() {
        // ::ffff:169.254.169.254 must not smuggle metadata past the v6 arm.
        let mapped = IpAddr::V6(Ipv4Addr::new(169, 254, 169, 254).to_ipv6_mapped());
        assert_eq!(classify_ip(mapped, true), Some("cloud metadata endpoint"));
        let mapped_priv = IpAddr::V6(Ipv4Addr::new(10, 0, 0, 5).to_ipv6_mapped());
        assert_eq!(classify_ip(mapped_priv, false), Some("private range"));
    }

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
