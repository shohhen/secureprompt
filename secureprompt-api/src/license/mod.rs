//! Gateway-side license verification (Plan 3). Fail-open: a bad/missing/expired
//! license degrades to Unlicensed/Grace and is logged — it never blocks the
//! request pipeline (mirrors the ml_sidecar circuit-breaker contract). The
//! license token is supplied as a single-line env var (no on-disk fallback).

pub mod attestation;
pub mod revocation;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::RwLock;
use ed25519_dalek::VerifyingKey;
use sp_license::sign::{decode_verified_token, parse_rfc3339};
use sp_license::token::License;

/// `Revoked` is set out-of-band by the online revocation poller (see `revocation`)
/// and is **fail-closed**: it overrides whatever the locally-signed file says, so a
/// revoked license blocks traffic even though its on-disk token is still valid and
/// in-window. The other three states come from local signature/window checks and
/// remain fail-open. Revocation is terminal — once observed it sticks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseStatus { Valid, Grace, Unlicensed, Revoked }

#[derive(Debug, Clone)]
pub struct LicenseSnapshot {
    pub status: LicenseStatus,
    pub max_seats: Option<u32>,
    pub features: Vec<String>,
    pub customer_name: Option<String>,
    pub expires_at: Option<String>,
    pub wrapped_model_key: Option<String>,
    pub lic_id: Option<String>,
    /// The per-deployment attestation signing key wrapped under the KEK — Valid license only.
    pub wrapped_attestation_key: Option<String>,
    /// Image digests from the license's integrity section — Valid license only; empty otherwise.
    pub image_digests: std::collections::BTreeMap<String, String>,
}

impl LicenseSnapshot {
    fn unlicensed() -> Self {
        Self {
            status: LicenseStatus::Unlicensed,
            max_seats: None,
            features: vec![],
            customer_name: None,
            expires_at: None,
            wrapped_model_key: None,
            lic_id: None,
            wrapped_attestation_key: None,
            image_digests: std::collections::BTreeMap::new(),
        }
    }
}

fn snapshot_from(lic: &License, status: LicenseStatus) -> LicenseSnapshot {
    let valid = status == LicenseStatus::Valid;
    LicenseSnapshot {
        status,
        max_seats: Some(lic.entitlements.seats),
        features: lic.entitlements.features.clone(),
        customer_name: Some(lic.customer.name.clone()),
        expires_at: Some(lic.entitlements.expires_at.clone()),
        wrapped_model_key: if valid { Some(lic.model.wrapped_key.clone()) } else { None },
        lic_id: if valid { Some(lic.lic_id.clone()) } else { None },
        wrapped_attestation_key: if valid { Some(lic.deployment.wrapped_attestation_key.clone()) } else { None },
        image_digests: if valid { lic.integrity.image_digests.clone() } else { std::collections::BTreeMap::new() },
    }
}

/// Lives in AppState as `Arc<LicenseState>`. Interior RwLock lets the periodic
/// re-verify task atomically swap the snapshot. `revoked` is a separate sticky
/// flag set by the online revocation poller — kept out of the snapshot so the
/// hourly local re-verify (which replaces the snapshot) can't clear it.
pub struct LicenseState { inner: RwLock<LicenseSnapshot>, revoked: AtomicBool }

impl LicenseState {
    pub fn new(s: LicenseSnapshot) -> Self { Self { inner: RwLock::new(s), revoked: AtomicBool::new(false) } }
    pub fn unlicensed() -> Self { Self::new(LicenseSnapshot::unlicensed()) }
    pub fn snapshot(&self) -> LicenseSnapshot { self.inner.read().expect("license lock poisoned").clone() }
    pub fn set(&self, s: LicenseSnapshot) { *self.inner.write().expect("license lock poisoned") = s; }
    /// Mark the license revoked (fail-closed). Sticky: the vendor never un-revokes,
    /// so once observed it stays set for the life of the process.
    pub fn mark_revoked(&self) { self.revoked.store(true, Ordering::SeqCst); }
    /// True once the online poller has confirmed a `revoked` verdict from sp-admin.
    pub fn is_revoked(&self) -> bool { self.revoked.load(Ordering::SeqCst) }
    /// Effective status — `Revoked` overrides the locally-derived snapshot status.
    pub fn status(&self) -> LicenseStatus {
        if self.is_revoked() { return LicenseStatus::Revoked; }
        self.snapshot().status
    }
    /// Seat ceiling to enforce. `None` under Unlicensed/Grace (fail-open: no enforcement on a license hiccup).
    pub fn max_seats(&self) -> Option<u32> {
        if self.is_revoked() { return None; }
        let s = self.snapshot();
        match s.status { LicenseStatus::Valid => s.max_seats, _ => None }
    }
    /// Feature gate. Fail-open: Unlicensed/Grace permits everything (don't hard-block on a hiccup).
    /// Revoked is fail-CLOSED (no features) — though the request-pipeline gate blocks first.
    pub fn is_feature_enabled(&self, f: &str) -> bool {
        if self.is_revoked() { return false; }
        let s = self.snapshot();
        match s.status {
            LicenseStatus::Valid => s.features.iter().any(|x| x == f),
            LicenseStatus::Grace | LicenseStatus::Unlicensed => true,
            LicenseStatus::Revoked => false,
        }
    }

    /// The 32-byte model decryption key — ONLY when the license is Valid and not revoked.
    pub fn unwrap_model_key(&self, kek: &[u8; 32]) -> Option<[u8; 32]> {
        if self.is_revoked() { return None; }
        let s = self.snapshot();
        if s.status != LicenseStatus::Valid { return None; }
        let wrapped = s.wrapped_model_key.as_ref()?;
        let lic_id = s.lic_id.as_ref()?;
        let aad = format!("{lic_id}:model");
        let bytes = sp_license::unwrap_key_with_aad(kek, wrapped, aad.as_bytes()).ok()?;
        bytes.try_into().ok()
    }

    /// Returns tamper flags if the running image digest mismatches the license's pinned digest.
    /// Fail-open: returns empty vec when no pin or no actual digest.
    pub fn tamper_flags(&self, component: &str, actual: &str) -> Vec<String> {
        tamper_check(&self.snapshot().image_digests, component, actual)
            .into_iter()
            .collect()
    }

    /// The per-deployment attestation signing key — Valid license only, never when revoked.
    pub fn unwrap_attestation_key(&self, kek: &[u8; 32]) -> Option<ed25519_dalek::SigningKey> {
        if self.is_revoked() { return None; }
        let s = self.snapshot();
        if s.status != LicenseStatus::Valid { return None; }
        let wrapped = s.wrapped_attestation_key.as_ref()?;
        let lic_id = s.lic_id.as_ref()?;
        let bytes = sp_license::unwrap_key_with_aad(kek, wrapped, format!("{lic_id}:attest").as_bytes()).ok()?;
        let arr: [u8; 32] = bytes.try_into().ok()?;
        Some(ed25519_dalek::SigningKey::from_bytes(&arr))
    }
}

/// Parse a base64 Ed25519 vendor public key. None on bad input.
pub fn parse_vendor_key(b64: &str) -> Option<VerifyingKey> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let bytes: [u8; 32] = B64.decode(b64.trim()).ok()?.try_into().ok()?;
    VerifyingKey::from_bytes(&bytes).ok()
}

/// Parse a base64-encoded 32-byte key-encryption key. Returns `None` on bad input or wrong length.
pub fn parse_kek(b64: &str) -> Option<[u8; 32]> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    B64.decode(b64.trim()).ok()?.try_into().ok()
}

/// Prefer a compile-time-pinned vendor public key (base64) baked in via the
/// SECUREPROMPT_PINNED_VENDOR_PUBKEY build-time env; fall back to the runtime value.
pub fn effective_vendor_pubkey(runtime_b64: &str) -> String {
    option_env!("SECUREPROMPT_PINNED_VENDOR_PUBKEY")
        .map(str::to_string)
        .unwrap_or_else(|| runtime_b64.to_string())
}

/// Same for the symmetric KEK.
pub fn effective_kek(runtime_b64: &str) -> String {
    option_env!("SECUREPROMPT_PINNED_MODEL_KEK")
        .map(str::to_string)
        .unwrap_or_else(|| runtime_b64.to_string())
}

/// Tamper flag if the running image digest mismatches the license's pinned digest for `component`.
/// Empty actual or empty/absent pin → None (fail-open).
pub fn tamper_check(
    pins: &std::collections::BTreeMap<String, String>,
    component: &str,
    actual_digest: &str,
) -> Option<String> {
    if actual_digest.is_empty() { return None; }
    match pins.get(component) {
        Some(expected) if !expected.is_empty() && expected != actual_digest =>
            Some(format!("image digest mismatch for {component}: licensed {expected}, running {actual_digest}")),
        _ => None,
    }
}

/// Verify a license **token** against the vendor key. NEVER returns Err — failures
/// map to a snapshot (fail-open). `now_epoch` injected for testing/clock control.
///
/// The token is the single-line compact form `base64url(payload).base64url(sig)`.
/// We verify the signature over the transmitted payload bytes (no
/// re-serialization), then classify by the validity window: in-window → Valid;
/// signed but outside the window → Grace; anything else (empty, bad signature,
/// malformed, wrong key) → Unlicensed.
pub fn load_and_verify_token(token: &str, vk: &VerifyingKey, now_epoch: i64) -> LicenseSnapshot {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        tracing::warn!("SECUREPROMPT_LICENSE_TOKEN unset/empty — unlicensed");
        return LicenseSnapshot::unlicensed();
    }
    // Signature check first → Unlicensed on bad sig / malformed / wrong key.
    let lic = match decode_verified_token(trimmed, vk) {
        Ok(l) => l,
        Err(e) => { tracing::warn!(error = %e, "license token invalid — unlicensed"); return LicenseSnapshot::unlicensed(); }
    };
    // Signature is valid → classify by the validity window.
    match (parse_rfc3339(&lic.entitlements.not_before), parse_rfc3339(&lic.entitlements.expires_at)) {
        (Ok(nb), Ok(exp)) if now_epoch >= nb && now_epoch <= exp => snapshot_from(&lic, LicenseStatus::Valid),
        (Ok(_), Ok(_)) => {
            tracing::warn!(customer = ?lic.customer.name, "license outside validity window — GRACE");
            snapshot_from(&lic, LicenseStatus::Grace)
        }
        _ => { tracing::warn!("license has unparseable validity timestamps — unlicensed"); LicenseSnapshot::unlicensed() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use sp_license::sign::{sign_license, LicenseEnvelope};
    use sp_license::envelope_to_token;
    use sp_license::token::*;
    use std::collections::BTreeMap;

    fn mint(sk: &SigningKey, not_before: &str, expires: &str, seats: u32, features: &[&str]) -> LicenseEnvelope {
        let lic = License {
            v: 1, lic_id: "test-lic".into(),
            customer: Customer { id: "c".into(), name: "Acme".into() },
            deployment: Deployment { scope: "single-node".into(), max_nodes: 1, sign_pubkey: "p".into(), wrapped_attestation_key: String::new() },
            entitlements: Entitlements {
                not_before: not_before.into(), expires_at: expires.into(),
                seats, features: features.iter().map(|s| s.to_string()).collect(), components: vec![],
            },
            model: ModelGrant { wrapped_key: "w".into(), models: vec![] },
            integrity: Integrity { image_digests: BTreeMap::new() },
            iss: "sp-admin".into(), iat: not_before.into(),
        };
        sign_license(&lic, sk).unwrap()
    }
    // Encode an envelope as the single-line compact token the gateway now consumes.
    // Re-encoding reuses the signature, so a tampered envelope (signature stale
    // vs payload) still fails verification.
    fn tok(env: &LicenseEnvelope) -> String {
        envelope_to_token(env).unwrap()
    }
    fn now() -> i64 { parse_rfc3339("2026-06-01T00:00:00Z").unwrap() }

    #[test]
    fn valid_license_is_valid_with_entitlements() {
        let sk = SigningKey::generate(&mut OsRng);
        let token = tok(&mint(&sk, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z", 50, &["pii.uz"]));
        let s = load_and_verify_token(&token, &sk.verifying_key(), now());
        assert_eq!(s.status, LicenseStatus::Valid);
        assert_eq!(s.max_seats, Some(50));
        assert_eq!(s.customer_name.as_deref(), Some("Acme"));
        assert!(s.features.iter().any(|f| f == "pii.uz"));
    }

    #[test]
    fn expired_license_is_grace() {
        let sk = SigningKey::generate(&mut OsRng);
        let token = tok(&mint(&sk, "2025-01-01T00:00:00Z", "2025-02-01T00:00:00Z", 10, &[]));
        let s = load_and_verify_token(&token, &sk.verifying_key(), now());
        assert_eq!(s.status, LicenseStatus::Grace);
        assert_eq!(s.max_seats, Some(10));
        let st = LicenseState::new(s);
        assert_eq!(st.max_seats(), None);
        assert!(st.is_feature_enabled("any-feature"));
    }

    #[test]
    fn wrong_key_is_unlicensed() {
        let sk = SigningKey::generate(&mut OsRng);
        let other = SigningKey::generate(&mut OsRng);
        let token = tok(&mint(&sk, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z", 10, &[]));
        let s = load_and_verify_token(&token, &other.verifying_key(), now());
        assert_eq!(s.status, LicenseStatus::Unlicensed);
    }

    #[test]
    fn tampered_license_is_unlicensed() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut env = mint(&sk, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z", 10, &[]);
        env.license.entitlements.seats = 9999; // tamper after signing
        let token = tok(&env);
        let s = load_and_verify_token(&token, &sk.verifying_key(), now());
        assert_eq!(s.status, LicenseStatus::Unlicensed);
    }

    #[test]
    fn empty_token_is_unlicensed_no_panic() {
        let sk = SigningKey::generate(&mut OsRng);
        let s = load_and_verify_token("", &sk.verifying_key(), now());
        assert_eq!(s.status, LicenseStatus::Unlicensed);
        // Whitespace-only is also treated as empty.
        let s = load_and_verify_token("   \n", &sk.verifying_key(), now());
        assert_eq!(s.status, LicenseStatus::Unlicensed);
    }

    #[test]
    fn feature_and_seat_gates_fail_open() {
        // Valid: enforces
        let valid = LicenseState::new(LicenseSnapshot { status: LicenseStatus::Valid, max_seats: Some(5), features: vec!["a".into()], customer_name: None, expires_at: None, wrapped_model_key: None, lic_id: None, wrapped_attestation_key: None, image_digests: Default::default() });
        assert_eq!(valid.max_seats(), Some(5));
        assert!(valid.is_feature_enabled("a"));
        assert!(!valid.is_feature_enabled("b"));
        // Unlicensed: fail-open (no seat ceiling, all features permitted)
        let un = LicenseState::unlicensed();
        assert_eq!(un.max_seats(), None);
        assert!(un.is_feature_enabled("anything"));
    }

    #[test]
    fn revoked_is_sticky_and_fail_closed() {
        // Start from a fully Valid snapshot with seats + a feature.
        let st = LicenseState::new(LicenseSnapshot {
            status: LicenseStatus::Valid,
            max_seats: Some(5),
            features: vec!["pii.uz".into()],
            customer_name: None,
            expires_at: None,
            wrapped_model_key: None,
            lic_id: Some("lic-1".into()),
            wrapped_attestation_key: None,
            image_digests: Default::default(),
        });
        assert!(!st.is_revoked());
        assert_eq!(st.status(), LicenseStatus::Valid);
        assert!(st.is_feature_enabled("pii.uz"));

        // Revoke out-of-band (as the poller would).
        st.mark_revoked();
        assert!(st.is_revoked());
        assert_eq!(st.status(), LicenseStatus::Revoked); // overrides snapshot
        assert!(!st.is_feature_enabled("pii.uz")); // fail-closed
        assert_eq!(st.max_seats(), None);
        assert_eq!(st.unwrap_model_key(&[0u8; 32]), None);
        assert!(st.unwrap_attestation_key(&[0u8; 32]).is_none());

        // Sticky: a fresh local re-verify (snapshot swap to Valid) must NOT clear it.
        st.set(LicenseSnapshot {
            status: LicenseStatus::Valid,
            max_seats: Some(5),
            features: vec!["pii.uz".into()],
            customer_name: None,
            expires_at: None,
            wrapped_model_key: None,
            lic_id: Some("lic-1".into()),
            wrapped_attestation_key: None,
            image_digests: Default::default(),
        });
        assert!(st.is_revoked());
        assert_eq!(st.status(), LicenseStatus::Revoked);
    }

    #[test]
    fn parse_vendor_key_roundtrip() {
        let sk = SigningKey::generate(&mut OsRng);
        use base64::{engine::general_purpose::STANDARD as B64, Engine};
        let b64 = B64.encode(sk.verifying_key().to_bytes());
        assert!(parse_vendor_key(&b64).is_some());
        assert!(parse_vendor_key("not-base64!!").is_none());
    }

    #[test]
    fn unwrap_model_key_only_when_valid() {
        use sp_license::seal_key_with_aad;
        let sk = SigningKey::generate(&mut OsRng);
        let kek = [3u8; 32];
        let model_key = [7u8; 32];
        let lic_id = "mk-test";
        let wrapped = seal_key_with_aad(&kek, &model_key, format!("{lic_id}:model").as_bytes()).unwrap();
        let base = License {
            v: 1, lic_id: lic_id.into(),
            customer: Customer { id: "c".into(), name: "Acme".into() },
            deployment: Deployment { scope: "single-node".into(), max_nodes: 1, sign_pubkey: "p".into(), wrapped_attestation_key: String::new() },
            entitlements: Entitlements { not_before: "2026-01-01T00:00:00Z".into(), expires_at: "2027-01-01T00:00:00Z".into(), seats: 5, features: vec![], components: vec![] },
            model: ModelGrant { wrapped_key: wrapped, models: vec![] },
            integrity: Integrity { image_digests: BTreeMap::new() },
            iss: "sp-admin".into(), iat: "2026-01-01T00:00:00Z".into(),
        };
        // Valid → unwraps to the original key
        let env = sign_license(&base, &sk).unwrap();
        let token = tok(&env);
        let st = LicenseState::new(load_and_verify_token(&token, &sk.verifying_key(), now()));
        assert_eq!(st.status(), LicenseStatus::Valid);
        assert_eq!(st.unwrap_model_key(&kek), Some(model_key));
        assert_eq!(st.unwrap_model_key(&[9u8; 32]), None);

        // Expired (Grace) → None even with the right KEK
        let mut exp_lic = base.clone();
        exp_lic.entitlements.not_before = "2025-01-01T00:00:00Z".into();
        exp_lic.entitlements.expires_at = "2025-02-01T00:00:00Z".into();
        let env2 = sign_license(&exp_lic, &sk).unwrap();
        let token2 = tok(&env2);
        let st2 = LicenseState::new(load_and_verify_token(&token2, &sk.verifying_key(), now()));
        assert_eq!(st2.status(), LicenseStatus::Grace);
        assert_eq!(st2.unwrap_model_key(&kek), None);
    }

    #[test]
    fn unwrap_attestation_key_only_when_valid() {
        use sp_license::seal_key_with_aad;
        let vendor_sk = SigningKey::generate(&mut OsRng);
        let kek = [5u8; 32];
        // Generate a known attestation keypair
        let att_sk = SigningKey::generate(&mut OsRng);
        let att_vk = att_sk.verifying_key();
        let lic_id = "attest-test-lic";
        let wrapped = seal_key_with_aad(&kek, att_sk.as_bytes(), format!("{lic_id}:attest").as_bytes()).unwrap();
        let base = License {
            v: 1, lic_id: lic_id.into(),
            customer: Customer { id: "c".into(), name: "Acme".into() },
            deployment: Deployment {
                scope: "single-node".into(), max_nodes: 1, sign_pubkey: "p".into(),
                wrapped_attestation_key: wrapped,
            },
            entitlements: Entitlements {
                not_before: "2026-01-01T00:00:00Z".into(), expires_at: "2027-01-01T00:00:00Z".into(),
                seats: 5, features: vec![], components: vec![],
            },
            model: ModelGrant { wrapped_key: "w".into(), models: vec![] },
            integrity: Integrity { image_digests: BTreeMap::new() },
            iss: "sp-admin".into(), iat: "2026-01-01T00:00:00Z".into(),
        };
        // Valid → unwraps to the original attestation key
        let env = sign_license(&base, &vendor_sk).unwrap();
        let token = tok(&env);
        let st = LicenseState::new(load_and_verify_token(&token, &vendor_sk.verifying_key(), now()));
        assert_eq!(st.status(), LicenseStatus::Valid);
        let recovered = st.unwrap_attestation_key(&kek).expect("should unwrap");
        assert_eq!(recovered.verifying_key(), att_vk);
        // Wrong KEK → None
        assert!(st.unwrap_attestation_key(&[9u8; 32]).is_none());

        // Expired (Grace) → None even with correct KEK
        let mut exp_lic = base.clone();
        exp_lic.entitlements.not_before = "2025-01-01T00:00:00Z".into();
        exp_lic.entitlements.expires_at = "2025-02-01T00:00:00Z".into();
        let env2 = sign_license(&exp_lic, &vendor_sk).unwrap();
        let token2 = tok(&env2);
        let st2 = LicenseState::new(load_and_verify_token(&token2, &vendor_sk.verifying_key(), now()));
        assert_eq!(st2.status(), LicenseStatus::Grace);
        assert!(st2.unwrap_attestation_key(&kek).is_none());
    }

    #[test]
    fn parse_kek_roundtrip() {
        use base64::{engine::general_purpose::STANDARD as B64, Engine};
        assert_eq!(parse_kek(&B64.encode([4u8; 32])), Some([4u8; 32]));
        assert_eq!(parse_kek("nope!!"), None);
        assert_eq!(parse_kek(&B64.encode([4u8; 16])), None); // wrong length
    }

    #[test]
    fn effective_vendor_pubkey_falls_back_to_runtime() {
        // Build env is unset in tests → must return the runtime value.
        assert_eq!(effective_vendor_pubkey("RT"), "RT");
    }

    #[test]
    fn effective_kek_falls_back_to_runtime() {
        // Build env is unset in tests → must return the runtime value.
        assert_eq!(effective_kek("RT"), "RT");
    }

    #[test]
    fn tamper_check_cases() {
        let mut pins = BTreeMap::new();
        pins.insert("api".to_string(), "sha256:expected".to_string());

        // Matching digest → None (no flag).
        assert_eq!(tamper_check(&pins, "api", "sha256:expected"), None);

        // Mismatch → Some with a descriptive message.
        let flag = tamper_check(&pins, "api", "sha256:different");
        assert!(flag.is_some());
        let msg = flag.unwrap();
        assert!(msg.contains("api"));
        assert!(msg.contains("sha256:expected"));
        assert!(msg.contains("sha256:different"));

        // Empty actual → None (fail-open).
        assert_eq!(tamper_check(&pins, "api", ""), None);

        // Absent pin → None (fail-open).
        assert_eq!(tamper_check(&pins, "ml", "sha256:something"), None);

        // Empty pin value → None (fail-open).
        let mut empty_pin = BTreeMap::new();
        empty_pin.insert("api".to_string(), String::new());
        assert_eq!(tamper_check(&empty_pin, "api", "sha256:something"), None);
    }

    #[test]
    fn tamper_flags_on_license_state() {
        let mut digests = BTreeMap::new();
        digests.insert("api".to_string(), "sha256:pinned".to_string());
        let snap = LicenseSnapshot {
            status: LicenseStatus::Valid,
            max_seats: None,
            features: vec![],
            customer_name: None,
            expires_at: None,
            wrapped_model_key: None,
            lic_id: None,
            wrapped_attestation_key: None,
            image_digests: digests,
        };
        let state = LicenseState::new(snap);

        // Matching → empty vec.
        assert!(state.tamper_flags("api", "sha256:pinned").is_empty());

        // Mismatch → one flag.
        let flags = state.tamper_flags("api", "sha256:other");
        assert_eq!(flags.len(), 1);

        // No actual digest → empty (fail-open).
        assert!(state.tamper_flags("api", "").is_empty());
    }

    #[test]
    fn image_digests_only_in_valid_snapshot() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut env = mint(&sk, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z", 10, &[]);
        // Inject a digest into the license before signing.
        env.license.integrity.image_digests.insert("api".into(), "sha256:abc".into());
        // Re-sign with the digest.
        let env = sp_license::sign::sign_license(&env.license, &sk).unwrap();
        let token = tok(&env);
        let s = load_and_verify_token(&token, &sk.verifying_key(), now());
        assert_eq!(s.status, LicenseStatus::Valid);
        assert_eq!(s.image_digests.get("api").map(String::as_str), Some("sha256:abc"));

        // Grace → image_digests must be empty.
        let mut exp_lic = env.license.clone();
        exp_lic.entitlements.not_before = "2025-01-01T00:00:00Z".into();
        exp_lic.entitlements.expires_at = "2025-02-01T00:00:00Z".into();
        let env2 = sp_license::sign::sign_license(&exp_lic, &sk).unwrap();
        let token2 = tok(&env2);
        let s2 = load_and_verify_token(&token2, &sk.verifying_key(), now());
        assert_eq!(s2.status, LicenseStatus::Grace);
        assert!(s2.image_digests.is_empty());
    }
}
