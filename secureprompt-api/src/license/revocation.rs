//! Online revocation check (OCSP-style). The gateway polls sp-admin's public
//! `GET /v1/licenses/{id}/status` endpoint and fail-CLOSES only on a definitive
//! `revoked` verdict. Any uncertainty — sp-admin unreachable, timeout, non-200,
//! unparseable body — yields `Unknown`, and the caller keeps the last-known
//! state (soft-fail). This is the standard OCSP soft-fail posture: a vendor
//! outage must never take down the customer's traffic, but a real revocation
//! propagates within one poll interval once sp-admin is reachable again.

use std::time::Duration;

/// Outcome of one revocation poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationVerdict {
    /// sp-admin confirmed the license is active (or superseded) — not revoked.
    Active,
    /// sp-admin confirmed the license is revoked — fail-closed.
    Revoked,
    /// Could not get a definitive answer (unreachable/timeout/non-200/bad body).
    /// Caller keeps the last-known state.
    Unknown,
}

/// Poll `{server_url}/v1/licenses/{lic_id}/status` once. Never panics; maps every
/// error path to `Unknown`. `server_url` is the sp-admin base (no trailing slash
/// required); `lic_id` is the license UUID from the local license file.
pub async fn check(client: &reqwest::Client, server_url: &str, lic_id: &str) -> RevocationVerdict {
    let url = format!(
        "{}/v1/licenses/{}/status",
        server_url.trim_end_matches('/'),
        lic_id
    );
    let resp = match client.get(&url).timeout(Duration::from_secs(5)).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "revocation check: sp-admin unreachable — keeping last-known state");
            return RevocationVerdict::Unknown;
        }
    };
    if !resp.status().is_success() {
        tracing::warn!(status = %resp.status(), "revocation check: non-200 from sp-admin — keeping last-known state");
        return RevocationVerdict::Unknown;
    }
    let body: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "revocation check: unparseable body — keeping last-known state");
            return RevocationVerdict::Unknown;
        }
    };
    match body.get("status").and_then(|s| s.as_str()) {
        Some("revoked") => RevocationVerdict::Revoked,
        Some(_) => RevocationVerdict::Active,
        None => {
            tracing::warn!("revocation check: response missing `status` field — keeping last-known state");
            RevocationVerdict::Unknown
        }
    }
}

/// Classify a status string + reachability into a verdict. Pure helper, unit-tested.
/// `None` body means "no definitive response".
pub fn verdict_from_status(status: Option<&str>) -> RevocationVerdict {
    match status {
        Some("revoked") => RevocationVerdict::Revoked,
        Some(_) => RevocationVerdict::Active,
        None => RevocationVerdict::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_mapping() {
        assert_eq!(verdict_from_status(Some("revoked")), RevocationVerdict::Revoked);
        assert_eq!(verdict_from_status(Some("active")), RevocationVerdict::Active);
        assert_eq!(verdict_from_status(Some("superseded")), RevocationVerdict::Active);
        assert_eq!(verdict_from_status(None), RevocationVerdict::Unknown);
    }
}
