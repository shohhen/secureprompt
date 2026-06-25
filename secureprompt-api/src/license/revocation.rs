//! Online revocation check (OCSP-style). The gateway polls sp-admin's public
//! `GET /v1/licenses/{id}/status` endpoint and fail-CLOSES only on a definitive
//! `revoked` verdict. Any uncertainty — sp-admin unreachable, timeout, non-200,
//! unparseable body — yields `Unknown`, and the caller keeps the last-known
//! state (soft-fail). This is the standard OCSP soft-fail posture: a vendor
//! outage must never take down the customer's traffic, but a real revocation
//! propagates within one poll interval once sp-admin is reachable again.
//!
//! The endpoint now returns a superset response including a signed
//! `FreshnessAssertion`. A valid signature yields the assertion's `issued_at`
//! as epoch seconds so the poller can advance the freshness high-water mark.
//! An unsigned/stub response that omits the assertion falls back to the
//! top-level `status` field for the verdict but returns `None` for the
//! timestamp — no freshness credit is issued for unsigned responses.

use std::time::Duration;
use ed25519_dalek::VerifyingKey;
use sp_license::{FreshnessAssertion, verify_assertion};
use sp_license::sign::parse_rfc3339;

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

/// Poll `{server_url}/v1/licenses/{lic_id}/status` once.
///
/// Returns `(verdict, issued_at_epoch)` where the second element is:
/// - `Some(epoch_secs)` only when the response contained a signed
///   `FreshnessAssertion` whose signature verified against `vk` and whose
///   status is not `"revoked"`. The caller may use this to advance the
///   freshness high-water mark.
/// - `None` for every other case — including unsigned/legacy responses
///   (which must never yield freshness credit), bad signatures, or revoked
///   assertions.
///
/// Never panics; maps every error path to `(Unknown, None)`.
/// `server_url` is the sp-admin base (no trailing slash required).
pub async fn check(
    client: &reqwest::Client,
    server_url: &str,
    lic_id: &str,
    vk: &VerifyingKey,
) -> (RevocationVerdict, Option<i64>) {
    let url = format!(
        "{}/v1/licenses/{}/status",
        server_url.trim_end_matches('/'),
        lic_id
    );
    let resp = match client.get(&url).timeout(Duration::from_secs(5)).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "revocation check: sp-admin unreachable — keeping last-known state");
            return (RevocationVerdict::Unknown, None);
        }
    };
    if !resp.status().is_success() {
        tracing::warn!(status = %resp.status(), "revocation check: non-200 from sp-admin — keeping last-known state");
        return (RevocationVerdict::Unknown, None);
    }
    let body: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "revocation check: unparseable body — keeping last-known state");
            return (RevocationVerdict::Unknown, None);
        }
    };

    // --- Signed path: try to parse assertion + sig ----------------------------
    let assertion_val = body.get("assertion");
    let sig_val = body.get("sig").and_then(|s| s.as_str());

    // Rollout/observability: an assertion present without a usable signature is a
    // misconfigured signer. We treat it as unsigned (no freshness credit) below, but
    // surface it so the §4.5 signed-assertion rollout gap is visible.
    if assertion_val.is_some() && sig_val.is_none() {
        tracing::warn!("revocation check: response has 'assertion' but no 'sig' — treating as unsigned (no freshness credit); verify admin signing config");
    }

    if let (Some(av), Some(sig_str)) = (assertion_val, sig_val) {
        // Attempt to deserialise the assertion.
        let assertion: FreshnessAssertion = match serde_json::from_value(av.clone()) {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(error = %e, "revocation check: unparseable assertion — keeping last-known state");
                return (RevocationVerdict::Unknown, None);
            }
        };
        // Verify the vendor signature.
        if !verify_assertion(vk, &assertion, sig_str) {
            tracing::warn!("revocation check: assertion signature invalid — keeping last-known state");
            return (RevocationVerdict::Unknown, None);
        }
        // Signature is valid — map by status.
        if assertion.status == "revoked" {
            return (RevocationVerdict::Revoked, None);
        }
        // Non-revoked signed assertion: parse issued_at for freshness credit.
        // Accept full RFC3339 (sub-second precision + numeric offset, e.g. the
        // admin's chrono `to_rfc3339()` output like `...311864977+00:00`) via
        // chrono, falling back to the crate's strict `YYYY-MM-DDTHH:MM:SSZ` parser.
        let issued_epoch = chrono::DateTime::parse_from_rfc3339(&assertion.issued_at)
            .ok()
            .map(|dt| dt.timestamp())
            .or_else(|| parse_rfc3339(&assertion.issued_at).ok());
        match issued_epoch {
            Some(epoch) => return (RevocationVerdict::Active, Some(epoch)),
            None => {
                tracing::warn!(issued_at = %assertion.issued_at, "revocation check: assertion issued_at unparseable — no freshness credit");
                return (RevocationVerdict::Unknown, None);
            }
        }
    }

    // --- Legacy unsigned path: fall back to top-level `status` ---------------
    // No freshness credit is issued (timestamp = None) — an unsigned/stub
    // response must never advance the freshness high-water mark.
    match body.get("status").and_then(|s| s.as_str()) {
        Some("revoked") => (RevocationVerdict::Revoked, None),
        Some(_) => (RevocationVerdict::Active, None),
        None => {
            tracing::warn!("revocation check: response missing `status` field — keeping last-known state");
            (RevocationVerdict::Unknown, None)
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
    use axum::{routing::get, Router};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use serde_json::json;
    use std::sync::Arc;
    use tokio::net::TcpListener;

    /// Spin up a minimal Axum server on a random port, serve `body` as JSON
    /// for all GET requests, and return the base URL string. The server task
    /// is detached — it exits when the test process ends.
    async fn start_mock(body: serde_json::Value) -> String {
        let body = Arc::new(body);
        let router = Router::new().route(
            "/{*path}",
            get(move || {
                let b = Arc::clone(&body);
                async move { axum::Json((*b).clone()) }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        format!("http://127.0.0.1:{}", addr.port())
    }

    /// Build a signed FreshnessAssertion and return (body_json, signing_key).
    fn signed_body(sk: &SigningKey, status: &str) -> serde_json::Value {
        let assertion = FreshnessAssertion {
            lic_id: "test-lic".into(),
            status: status.into(),
            issued_at: "2026-06-24T10:00:00Z".into(),
            expires_at: "2026-06-24T11:00:00Z".into(),
            nonce: "abc123".into(),
        };
        let sig = sp_license::sign_assertion(&assertion, sk).unwrap();
        json!({
            "lic_id": "test-lic",
            "status": status,
            "revoked_at": null,
            "assertion": assertion,
            "sig": sig
        })
    }

    // -- Pure unit tests (no I/O) -------------------------------------------

    #[test]
    fn verdict_mapping() {
        assert_eq!(verdict_from_status(Some("revoked")), RevocationVerdict::Revoked);
        assert_eq!(verdict_from_status(Some("active")), RevocationVerdict::Active);
        assert_eq!(verdict_from_status(Some("superseded")), RevocationVerdict::Active);
        assert_eq!(verdict_from_status(None), RevocationVerdict::Unknown);
    }

    // -- Signed-path tests (require a mock HTTP server) ----------------------

    #[tokio::test]
    async fn signed_active_body_yields_active_with_issued_at() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let base_url = start_mock(signed_body(&sk, "active")).await;
        let client = reqwest::Client::new();

        let (verdict, issued_at) = check(&client, &base_url, "test-lic", &vk).await;

        assert_eq!(verdict, RevocationVerdict::Active);
        // issued_at = parse_rfc3339("2026-06-24T10:00:00Z") — must be Some
        assert!(issued_at.is_some(), "signed active must yield Some(issued_at)");
        let epoch = issued_at.unwrap();
        // 2026-06-24T10:00:00Z should be > 0 and a reasonable epoch
        assert!(epoch > 0, "epoch must be positive");
    }

    #[tokio::test]
    async fn signed_active_with_chrono_rfc3339_timestamp_parses() {
        // Regression: the live admin emits issued_at via chrono `to_rfc3339()`
        // (sub-second precision + numeric offset, e.g. ...311864977+00:00). The
        // gateway must parse it and grant freshness credit, not reject it — else a
        // budgeted license would falsely hard-stale against a healthy admin.
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let assertion = FreshnessAssertion {
            lic_id: "test-lic".into(),
            status: "active".into(),
            issued_at: "2026-06-25T09:12:35.311864977+00:00".into(),
            expires_at: "2026-06-25T09:22:35.311864977+00:00".into(),
            nonce: "n".into(),
        };
        let sig = sp_license::sign_assertion(&assertion, &sk).unwrap();
        let body = json!({ "lic_id":"test-lic","status":"active","revoked_at":null,"assertion":assertion,"sig":sig });
        let base_url = start_mock(body).await;
        let client = reqwest::Client::new();

        let (verdict, issued_at) = check(&client, &base_url, "test-lic", &vk).await;

        assert_eq!(verdict, RevocationVerdict::Active);
        assert!(issued_at.is_some(), "chrono-format issued_at must parse and yield freshness credit");
    }

    #[tokio::test]
    async fn signed_revoked_body_yields_revoked_no_timestamp() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let base_url = start_mock(signed_body(&sk, "revoked")).await;
        let client = reqwest::Client::new();

        let (verdict, issued_at) = check(&client, &base_url, "test-lic", &vk).await;

        assert_eq!(verdict, RevocationVerdict::Revoked);
        assert_eq!(issued_at, None, "revoked must not yield a freshness timestamp");
    }

    #[tokio::test]
    async fn legacy_unsigned_active_yields_active_no_timestamp() {
        // Legacy response: top-level status only, no assertion/sig fields.
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let legacy_body = json!({ "status": "active" });
        let base_url = start_mock(legacy_body).await;
        let client = reqwest::Client::new();

        let (verdict, issued_at) = check(&client, &base_url, "test-lic", &vk).await;

        assert_eq!(verdict, RevocationVerdict::Active);
        assert_eq!(issued_at, None, "unsigned legacy response must never yield freshness credit");
    }

    #[tokio::test]
    async fn bad_signature_yields_unknown_no_timestamp() {
        let sk = SigningKey::generate(&mut OsRng);
        let wrong_sk = SigningKey::generate(&mut OsRng);
        // Body signed with `sk` but we verify with `wrong_sk`'s verifying key.
        let vk = wrong_sk.verifying_key();
        let base_url = start_mock(signed_body(&sk, "active")).await;
        let client = reqwest::Client::new();

        let (verdict, issued_at) = check(&client, &base_url, "test-lic", &vk).await;

        assert_eq!(verdict, RevocationVerdict::Unknown);
        assert_eq!(issued_at, None, "bad signature must not yield freshness credit");
    }

    #[tokio::test]
    async fn legacy_unsigned_revoked_yields_revoked_no_timestamp() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let legacy_body = json!({ "status": "revoked" });
        let base_url = start_mock(legacy_body).await;
        let client = reqwest::Client::new();

        let (verdict, issued_at) = check(&client, &base_url, "test-lic", &vk).await;

        assert_eq!(verdict, RevocationVerdict::Revoked);
        assert_eq!(issued_at, None);
    }

    #[tokio::test]
    async fn non_200_response_yields_unknown() {
        // Serve a 404 — reqwest will not return an Err here, but status.is_success() → false.
        let router = Router::new().route(
            "/{*path}",
            get(|| async { (axum::http::StatusCode::NOT_FOUND, "not found") }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let base_url = format!("http://127.0.0.1:{}", addr.port());

        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let client = reqwest::Client::new();

        let (verdict, issued_at) = check(&client, &base_url, "test-lic", &vk).await;

        assert_eq!(verdict, RevocationVerdict::Unknown);
        assert_eq!(issued_at, None);
    }
}
