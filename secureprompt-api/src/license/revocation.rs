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

use std::sync::Arc;
use std::time::Duration;
use ed25519_dalek::VerifyingKey;
use sp_license::{FreshnessAssertion, verify_assertion};
use sp_license::sign::parse_rfc3339;

use super::LicenseState;

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

// ── The poll loop ────────────────────────────────────────────────────────────
//
// WS4-4 made a revocation non-terminal: an administrator can install a
// DIFFERENT vendor-signed license through `PUT /v1/license` and the gateway
// recovers live, without a restart. That turned this loop's control flow into a
// security property. The loop used to `return` the moment it saw the sticky
// revoked flag, because a revocation was terminal for the process. If it still
// did, superseding a revocation would leave the replacement license unpolled
// until the next restart: a running gateway that never checks revocation again,
// silently, for a customer who now looks perfectly healthy. So the loop has NO
// terminal path — every condition one tick can observe is an idle-and-re-arm.
//
// It lives here rather than inline in `main.rs` so that control flow is
// reachable from a test at all. That is the same move
// `http::middleware::license_gate` makes for the gate decision: the choice is a
// pure function over plain values ([`poll_tick`], [`verdict_action`]), and the
// two things a tick touches outside the process — sp-admin over HTTP and
// Postgres — sit behind [`PollerDeps`] so a test can drive every branch with no
// socket and no database.

/// Why a tick did not contact the vendor. Both reasons are transient states of
/// this gateway, never reasons to stop polling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleReason {
    /// A revocation is already recorded. Nothing to ask about until an admin
    /// supersedes it — but the poller must stay armed for exactly that.
    AlreadyRevoked,
    /// The locally-held token does not currently verify, so there is no
    /// `lic_id` to ask sp-admin about (Grace/Unlicensed/hard-stale-then-swapped).
    NoLicenseId,
}

/// What one tick of the poller does.
///
/// There is deliberately no terminal variant. Adding one would be the shape of
/// the WS4-4 defect: a single observation quietly disabling revocation checking
/// for the rest of the process's life.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollTick {
    /// Stay armed; ask again on the next tick without contacting the vendor.
    Idle(IdleReason),
    /// Ask sp-admin about this `lic_id`.
    Check(String),
}

/// The whole per-tick decision, as a pure function over plain values.
#[must_use]
pub fn poll_tick(revoked: bool, lic_id: Option<&str>) -> PollTick {
    if revoked {
        return PollTick::Idle(IdleReason::AlreadyRevoked);
    }
    match lic_id {
        Some(id) => PollTick::Check(id.to_owned()),
        None => PollTick::Idle(IdleReason::NoLicenseId),
    }
}

/// What the poller does with one verdict. No terminal variant here either: a
/// `Revoked` verdict records the revocation and the poller keeps running, so a
/// superseding license is polled without a restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictAction {
    /// Record the revocation against this tick's `lic_id`.
    MarkRevoked,
    /// Fold a freshness observation in. `Some(t)` only ever comes from a
    /// signature-verified assertion; `Unknown` is mapped to `None` here so an
    /// unreachable or unparseable vendor can never buy freshness credit.
    RecordFreshness(Option<i64>),
}

/// Pure verdict → action mapping.
#[must_use]
pub const fn verdict_action(verdict: RevocationVerdict, issued_at: Option<i64>) -> VerdictAction {
    match verdict {
        RevocationVerdict::Revoked => VerdictAction::MarkRevoked,
        RevocationVerdict::Active => VerdictAction::RecordFreshness(issued_at),
        RevocationVerdict::Unknown => VerdictAction::RecordFreshness(None),
    }
}

/// The poller's two outside dependencies, behind one seam.
///
/// Neither method returns an error: every failure mode is already folded into
/// the return type (`RevocationVerdict::Unknown`, `None`) because a failure to
/// reach the vendor or the database is a soft-fail, not a reason to unwind.
#[async_trait::async_trait]
pub trait PollerDeps: Send + Sync + 'static {
    /// Ask the vendor about `lic_id`. Must never panic; see [`check`].
    async fn check_status(&self, lic_id: &str) -> (RevocationVerdict, Option<i64>);
    /// Persist the observation and read back the merged freshness row as
    /// `(last_assertion_at, highwater_at)`. `None` when the write or the
    /// read-back failed — the poller carries on regardless.
    async fn record_freshness(
        &self,
        lic_id: &str,
        assertion_at: Option<i64>,
        now: i64,
    ) -> Option<(i64, i64)>;
}

/// Production wiring: sp-admin over HTTP, freshness in Postgres.
pub struct LiveDeps {
    pub client: reqwest::Client,
    pub server_url: String,
    pub vk: VerifyingKey,
    pub db: sqlx::PgPool,
}

#[async_trait::async_trait]
impl PollerDeps for LiveDeps {
    async fn check_status(&self, lic_id: &str) -> (RevocationVerdict, Option<i64>) {
        check(&self.client, &self.server_url, lic_id, &self.vk).await
    }

    async fn record_freshness(
        &self,
        lic_id: &str,
        assertion_at: Option<i64>,
        now: i64,
    ) -> Option<(i64, i64)> {
        use crate::license::freshness_store;
        let _ = freshness_store::record(&self.db, lic_id, assertion_at, now).await;
        match freshness_store::load(&self.db, lic_id).await {
            Ok(Some(row)) => Some((row.last_assertion_at, row.highwater_at)),
            _ => None,
        }
    }
}

/// Run the revocation poller until the process ends. Never returns on its own.
///
/// `interval` is a parameter rather than a constant so the loop is testable at
/// millisecond granularity instead of the production hour.
pub async fn run_poller(state: Arc<LicenseState>, deps: Arc<dyn PollerDeps>, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await; // the first tick is immediate — check promptly at startup
        let snapshot = state.snapshot();
        let lic_id = match poll_tick(state.is_revoked(), snapshot.lic_id.as_deref()) {
            // WS4-4: idle, do NOT return. The tick is at the top of the loop,
            // so `continue` re-arms rather than spins.
            PollTick::Idle(_) => continue,
            PollTick::Check(id) => id,
        };
        let (verdict, issued_at) = deps.check_status(&lic_id).await;
        let now = chrono::Utc::now().timestamp();
        match verdict_action(verdict, issued_at) {
            VerdictAction::MarkRevoked => {
                // Record WHICH license was revoked, so a different one can
                // supersede it without a restart.
                state.mark_revoked(&lic_id);
                tracing::error!(
                    lic_id,
                    "license REVOKED by vendor — gateway is now fail-closed (403); install a replacement via PUT /v1/license"
                );
            }
            VerdictAction::RecordFreshness(assertion_at) => {
                if let Some((last, highwater)) =
                    deps.record_freshness(&lic_id, assertion_at, now).await
                {
                    state.observe_freshness(last, highwater);
                }
            }
        }
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

    /// The `Err` arm of `send()` — sp-admin simply is not there. Bind a port to
    /// learn a free one, then drop the listener so the connect is refused
    /// immediately rather than hanging on the 5 s timeout.
    ///
    /// This is the bridge the poller tests below stand on: "a network failure"
    /// has to become a `RevocationVerdict::Unknown` value, not an `Err` and not
    /// a panic, before "the poller survives a network failure" means anything.
    #[tokio::test]
    async fn unreachable_admin_yields_unknown() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let sk = SigningKey::generate(&mut OsRng);
        let (verdict, issued_at) = check(
            &reqwest::Client::new(),
            &format!("http://127.0.0.1:{port}"),
            "test-lic",
            &sk.verifying_key(),
        )
        .await;

        assert_eq!(verdict, RevocationVerdict::Unknown);
        assert_eq!(issued_at, None, "an unreachable vendor must not buy freshness credit");
    }

    /// A 200 whose body is not JSON at all — the `resp.json()` error arm.
    #[tokio::test]
    async fn unparseable_body_yields_unknown() {
        let router = Router::new().route("/{*path}", get(|| async { "definitely not json" }));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

        let sk = SigningKey::generate(&mut OsRng);
        let (verdict, issued_at) = check(
            &reqwest::Client::new(),
            &format!("http://127.0.0.1:{}", addr.port()),
            "test-lic",
            &sk.verifying_key(),
        )
        .await;

        assert_eq!(verdict, RevocationVerdict::Unknown);
        assert_eq!(issued_at, None);
    }

    // ── The poll loop's control flow ────────────────────────────────────────
    //
    // WS4-4 made a revocation non-terminal and, in the same edit, changed the
    // poller from `return` to `continue` when it sees the revoked flag. Without
    // that second half, superseding a revocation would have left a running
    // gateway that never checks revocation again — silently, permanently, for a
    // customer who now looks healthy. These tests pin that, plus every other
    // condition one tick can observe.
    //
    // Everything below runs against a fake: no socket, no database, no
    // `sp-license` server. The interval is 1 ms, so a "poll cycle" is
    // microseconds and nothing sleeps for a production interval.

    use crate::license::{LicenseSnapshot, LicenseStatus};
    use std::collections::VecDeque;
    use std::sync::Mutex;

    struct Script {
        /// Answers consumed in order. Once empty, `sticky` answers forever.
        queue: VecDeque<(RevocationVerdict, Option<i64>)>,
        sticky: (RevocationVerdict, Option<i64>),
        /// Every `lic_id` the poller has asked about, in order.
        asked: Vec<String>,
        /// While true every freshness write fails (Postgres unreachable).
        freshness_down: bool,
        /// Freshness writes attempted, successful or not.
        record_attempts: usize,
        /// Freshness writes that succeeded.
        recorded: Vec<(String, Option<i64>)>,
    }

    /// A scripted stand-in for sp-admin AND Postgres at once — the poller's
    /// only two outside dependencies, so faking both here removes all I/O.
    struct FakeVendor(Mutex<Script>);

    impl FakeVendor {
        fn new(sticky: RevocationVerdict) -> Arc<Self> {
            Arc::new(Self(Mutex::new(Script {
                queue: VecDeque::new(),
                sticky: (sticky, None),
                asked: Vec::new(),
                freshness_down: false,
                record_attempts: 0,
                recorded: Vec::new(),
            })))
        }
        /// Change the standing answer, effective from the next tick.
        fn say(&self, verdict: RevocationVerdict) {
            self.0.lock().unwrap().sticky = (verdict, None);
        }
        fn enqueue(&self, answers: impl IntoIterator<Item = (RevocationVerdict, Option<i64>)>) {
            self.0.lock().unwrap().queue.extend(answers);
        }
        fn fail_freshness(&self) {
            self.0.lock().unwrap().freshness_down = true;
        }
        fn asked(&self) -> Vec<String> {
            self.0.lock().unwrap().asked.clone()
        }
        fn queue_len(&self) -> usize {
            self.0.lock().unwrap().queue.len()
        }
        fn record_attempts(&self) -> usize {
            self.0.lock().unwrap().record_attempts
        }
        fn recorded(&self) -> Vec<(String, Option<i64>)> {
            self.0.lock().unwrap().recorded.clone()
        }
    }

    #[async_trait::async_trait]
    impl PollerDeps for FakeVendor {
        async fn check_status(&self, lic_id: &str) -> (RevocationVerdict, Option<i64>) {
            let mut s = self.0.lock().unwrap();
            s.asked.push(lic_id.to_owned());
            match s.queue.pop_front() {
                Some(answer) => answer,
                None => s.sticky,
            }
        }
        async fn record_freshness(
            &self,
            lic_id: &str,
            assertion_at: Option<i64>,
            _now: i64,
        ) -> Option<(i64, i64)> {
            let mut s = self.0.lock().unwrap();
            s.record_attempts += 1;
            if s.freshness_down {
                return None;
            }
            s.recorded.push((lic_id.to_owned(), assertion_at));
            Some((assertion_at.unwrap_or(0), 0))
        }
    }

    /// The snapshot shape the poller sees while a license is installed and its
    /// local signature verifies: `Valid`, carrying a `lic_id`.
    fn snapshot_for(lic_id: &str) -> LicenseSnapshot {
        let mut s = LicenseSnapshot::unlicensed();
        s.status = LicenseStatus::Valid;
        s.lic_id = Some(lic_id.to_owned());
        s
    }

    fn state_for(lic_id: &str) -> Arc<LicenseState> {
        Arc::new(LicenseState::new(snapshot_for(lic_id)))
    }

    fn spawn_poller(state: &Arc<LicenseState>, vendor: &Arc<FakeVendor>) {
        tokio::spawn(run_poller(
            Arc::clone(state),
            Arc::clone(vendor) as Arc<dyn PollerDeps>,
            Duration::from_millis(1),
        ));
    }

    /// Wait for `cond` or fail the test. Bounded, so a poller that has died
    /// fails loudly with a named condition instead of hanging the suite.
    async fn until(what: &str, mut cond: impl FnMut() -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if cond() {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out after 5s waiting for: {what}"
            );
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    /// The exhaustive per-tick decision table. The point is the *absence* of a
    /// terminal outcome: no combination of (revoked, lic_id) stops the poller.
    #[test]
    fn no_tick_outcome_stops_the_poller() {
        assert_eq!(
            poll_tick(true, Some("lic-a")),
            PollTick::Idle(IdleReason::AlreadyRevoked)
        );
        assert_eq!(
            poll_tick(true, None),
            PollTick::Idle(IdleReason::AlreadyRevoked)
        );
        assert_eq!(
            poll_tick(false, None),
            PollTick::Idle(IdleReason::NoLicenseId)
        );
        assert_eq!(
            poll_tick(false, Some("lic-a")),
            PollTick::Check("lic-a".to_owned())
        );
    }

    /// Every verdict maps to an action, and `Unknown` never buys freshness
    /// credit even when the response carried a timestamp.
    #[test]
    fn every_verdict_maps_to_a_non_terminal_action() {
        assert_eq!(
            verdict_action(RevocationVerdict::Revoked, None),
            VerdictAction::MarkRevoked
        );
        assert_eq!(
            verdict_action(RevocationVerdict::Revoked, Some(42)),
            VerdictAction::MarkRevoked
        );
        assert_eq!(
            verdict_action(RevocationVerdict::Active, Some(42)),
            VerdictAction::RecordFreshness(Some(42))
        );
        assert_eq!(
            verdict_action(RevocationVerdict::Active, None),
            VerdictAction::RecordFreshness(None)
        );
        assert_eq!(
            verdict_action(RevocationVerdict::Unknown, Some(42)),
            VerdictAction::RecordFreshness(None),
            "an unreachable or unparseable vendor must never advance the freshness mark"
        );
    }

    /// THE regression WS4-4 avoided by one edit.
    ///
    /// A revoked license is superseded live by a different one. The poller must
    /// still be checking afterwards, and a revocation of the REPLACEMENT must
    /// still take effect. The assertion is an observable effect and not a
    /// liveness flag on purpose: "the task handle is not finished" would also be
    /// true of a task parked forever, and what the product needs is that the
    /// kill-switch still fires.
    #[tokio::test]
    async fn poller_survives_a_supersede_and_still_revokes_the_replacement() {
        let state = state_for("lic-a");
        let vendor = FakeVendor::new(RevocationVerdict::Revoked);
        spawn_poller(&state, &vendor);

        until("lic-a is revoked", || state.is_revoked()).await;
        assert_eq!(state.revoked_lic_id().as_deref(), Some("lic-a"));

        // Control that must differ, half one: while revoked the poller IDLES —
        // it stops asking about a license it already knows is dead.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let asked_while_revoked = vendor.asked().len();
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(
            vendor.asked().len(),
            asked_while_revoked,
            "a revoked poller must idle, not keep re-asking about the revoked license"
        );

        // The supersede, exactly as `PUT /v1/license` performs it: swap the
        // snapshot, then lift the revocation because the `lic_id` differs.
        vendor.say(RevocationVerdict::Active);
        state.set(snapshot_for("lic-b"));
        assert!(
            state.clear_revocation_if_superseded("lic-b"),
            "premise: a different vendor-signed license supersedes the revocation"
        );
        assert!(!state.is_revoked(), "premise: back in good standing");

        // Control that must differ, half two: the poller resumes, and asks
        // about the NEW license. A poller that had returned on the revocation
        // never reaches this — the replacement goes unpolled until a restart.
        until("the poller polls the replacement license", || {
            vendor.asked().iter().any(|id| id == "lic-b")
        })
        .await;

        // The property that matters: superseding did not leave the gateway
        // permanently un-revocable.
        vendor.say(RevocationVerdict::Revoked);
        until("lic-b is revoked", || state.is_revoked()).await;
        assert_eq!(
            state.revoked_lic_id().as_deref(),
            Some("lic-b"),
            "the revocation must name the replacement, not the license it superseded"
        );
        assert_eq!(
            state.status(),
            LicenseStatus::Revoked,
            "and the gateway must be fail-closed again"
        );
    }

    /// Everything `check()` folds into `Unknown` — an unreachable vendor, a
    /// non-200, an unparseable body, an assertion whose signature does not
    /// verify — plus a Postgres that refuses every freshness write. None of it
    /// may stop the poller. The proof is that a revocation arriving afterwards
    /// still lands.
    #[tokio::test]
    async fn poller_survives_a_hostile_vendor_and_a_dead_database() {
        let state = state_for("lic-a");
        let vendor = FakeVendor::new(RevocationVerdict::Unknown);
        vendor.enqueue([
            (RevocationVerdict::Unknown, None), // vendor unreachable
            (RevocationVerdict::Unknown, None), // non-200 from the vendor
            (RevocationVerdict::Unknown, None), // 200 with an unparseable body
            (RevocationVerdict::Unknown, None), // assertion signature invalid
            (RevocationVerdict::Active, Some(1_700_000_000)), // recovered
            (RevocationVerdict::Unknown, None), // and lost again
        ]);
        vendor.fail_freshness();
        spawn_poller(&state, &vendor);

        until("the hostile script is fully consumed", || {
            vendor.queue_len() == 0
        })
        .await;

        // Premise assertions: without these, "it survived" could quietly mean
        // "it never actually saw any of that".
        assert!(
            vendor.asked().len() >= 6,
            "premise: every scripted answer must have reached the poller, saw {}",
            vendor.asked().len()
        );
        assert!(
            vendor.record_attempts() >= 6,
            "premise: each non-revoked tick must have attempted a freshness write, saw {}",
            vendor.record_attempts()
        );
        assert!(
            vendor.recorded().is_empty(),
            "premise: with the database down not one freshness write may have succeeded"
        );
        assert!(
            !state.is_revoked(),
            "premise: nothing in the script was a revocation verdict"
        );

        // The effect: the kill-switch still works after all of that.
        vendor.say(RevocationVerdict::Revoked);
        until("a revocation still lands after the hostile run", || {
            state.is_revoked()
        })
        .await;
        assert_eq!(state.revoked_lic_id().as_deref(), Some("lic-a"));
    }

    /// The third condition a tick can observe: no `lic_id`, because the locally
    /// held token does not currently verify. There is nothing to ask sp-admin
    /// about, but that is a reason to idle, not to exit — the token can start
    /// verifying at any moment (the boot race, or an operator activating one).
    #[tokio::test]
    async fn poller_idles_without_a_lic_id_and_picks_one_up_later() {
        let state = Arc::new(LicenseState::unlicensed()); // snapshot carries no lic_id
        let vendor = FakeVendor::new(RevocationVerdict::Revoked);
        spawn_poller(&state, &vendor);

        // Premise and control that must differ: with no `lic_id` the vendor is
        // never contacted, so the Revoked answer already loaded into the fake
        // cannot be what causes anything below.
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            vendor.asked().is_empty(),
            "premise: with no lic_id there is nothing to ask the vendor about"
        );
        assert!(!state.is_revoked(), "premise: not revoked yet");

        state.set(snapshot_for("lic-late"));
        until("the poller picks up the newly-verifying license", || {
            state.is_revoked()
        })
        .await;
        assert_eq!(
            state.revoked_lic_id().as_deref(),
            Some("lic-late"),
            "a poller that had exited on the empty ticks would never see this license"
        );
    }
}
