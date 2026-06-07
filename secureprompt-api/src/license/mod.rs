//! Gateway-side license verification (Plan 3). Fail-open: a bad/missing/expired
//! license degrades to Unlicensed/Grace and is logged — it never blocks the
//! request pipeline (mirrors the ml_sidecar circuit-breaker contract).
use std::sync::RwLock;
use ed25519_dalek::VerifyingKey;
use sp_license::sign::{verify_license, LicenseEnvelope};
use sp_license::token::License;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseStatus { Valid, Grace, Unlicensed }

#[derive(Debug, Clone)]
pub struct LicenseSnapshot {
    pub status: LicenseStatus,
    pub max_seats: Option<u32>,
    pub features: Vec<String>,
    pub customer_name: Option<String>,
    pub expires_at: Option<String>,
    pub wrapped_model_key: Option<String>,
    pub lic_id: Option<String>,
}

impl LicenseSnapshot {
    fn unlicensed() -> Self {
        Self { status: LicenseStatus::Unlicensed, max_seats: None, features: vec![], customer_name: None, expires_at: None, wrapped_model_key: None, lic_id: None }
    }
}

fn snapshot_from(lic: &License, status: LicenseStatus) -> LicenseSnapshot {
    LicenseSnapshot {
        status,
        max_seats: Some(lic.entitlements.seats),
        features: lic.entitlements.features.clone(),
        customer_name: Some(lic.customer.name.clone()),
        expires_at: Some(lic.entitlements.expires_at.clone()),
        wrapped_model_key: Some(lic.model.wrapped_key.clone()),
        lic_id: Some(lic.lic_id.clone()),
    }
}

/// Lives in AppState as `Arc<LicenseState>`. Interior RwLock lets the periodic
/// re-verify task atomically swap the snapshot.
pub struct LicenseState { inner: RwLock<LicenseSnapshot> }

impl LicenseState {
    pub fn new(s: LicenseSnapshot) -> Self { Self { inner: RwLock::new(s) } }
    pub fn unlicensed() -> Self { Self::new(LicenseSnapshot::unlicensed()) }
    pub fn snapshot(&self) -> LicenseSnapshot { self.inner.read().expect("license lock poisoned").clone() }
    pub fn set(&self, s: LicenseSnapshot) { *self.inner.write().expect("license lock poisoned") = s; }
    pub fn status(&self) -> LicenseStatus { self.snapshot().status }
    /// Seat ceiling to enforce. `None` under Unlicensed/Grace (fail-open: no enforcement on a license hiccup).
    pub fn max_seats(&self) -> Option<u32> {
        let s = self.snapshot();
        match s.status { LicenseStatus::Valid => s.max_seats, _ => None }
    }
    /// Feature gate. Fail-open: Unlicensed/Grace permits everything (don't hard-block on a hiccup).
    pub fn is_feature_enabled(&self, f: &str) -> bool {
        let s = self.snapshot();
        match s.status {
            LicenseStatus::Valid => s.features.iter().any(|x| x == f),
            LicenseStatus::Grace | LicenseStatus::Unlicensed => true,
        }
    }

    /// The 32-byte model decryption key — ONLY when the license is Valid.
    pub fn unwrap_model_key(&self, kek: &[u8; 32]) -> Option<[u8; 32]> {
        let s = self.snapshot();
        if s.status != LicenseStatus::Valid { return None; }
        let wrapped = s.wrapped_model_key.as_ref()?;
        let lic_id = s.lic_id.as_ref()?;
        let aad = format!("{lic_id}:model");
        let bytes = sp_license::unwrap_key_with_aad(kek, wrapped, aad.as_bytes()).ok()?;
        bytes.try_into().ok()
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

/// Load + verify a license file. NEVER returns Err — failures map to a snapshot
/// (fail-open). `now_epoch` injected for testing/clock control.
pub fn load_and_verify(path: &str, vk: &VerifyingKey, now_epoch: i64) -> LicenseSnapshot {
    let raw = match std::fs::read_to_string(path) {
        Ok(r) => r,
        Err(e) => { tracing::warn!(error = %e, path, "license file unreadable — unlicensed (grace)"); return LicenseSnapshot::unlicensed(); }
    };
    let env: LicenseEnvelope = match serde_json::from_str(&raw) {
        Ok(e) => e,
        Err(e) => { tracing::warn!(error = %e, "license not valid JSON — unlicensed"); return LicenseSnapshot::unlicensed(); }
    };
    match verify_license(&env, vk, now_epoch) {
        Ok(lic) => snapshot_from(&lic, LicenseStatus::Valid),
        // sp-license verifies signature BEFORE the window, so Expired/NotYetValid
        // means the signature was valid → safe to read entitlements in Grace.
        Err(sp_license::LicenseError::Expired) | Err(sp_license::LicenseError::NotYetValid) => {
            tracing::warn!(customer = ?env.license.customer.name, "license outside validity window — GRACE");
            snapshot_from(&env.license, LicenseStatus::Grace)
        }
        Err(e) => { tracing::warn!(error = %e, "license verification failed — unlicensed"); LicenseSnapshot::unlicensed() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use sp_license::sign::{sign_license, parse_rfc3339};
    use sp_license::token::*;
    use std::collections::BTreeMap;

    fn mint(sk: &SigningKey, not_before: &str, expires: &str, seats: u32, features: &[&str]) -> LicenseEnvelope {
        let lic = License {
            v: 1, lic_id: "test-lic".into(),
            customer: Customer { id: "c".into(), name: "Acme".into() },
            deployment: Deployment { scope: "single-node".into(), max_nodes: 1, sign_pubkey: "p".into() },
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
    fn write(name: &str, env: &LicenseEnvelope) -> String {
        let p = std::env::temp_dir().join(name);
        std::fs::write(&p, serde_json::to_string(env).unwrap()).unwrap();
        p.to_string_lossy().into_owned()
    }
    fn now() -> i64 { parse_rfc3339("2026-06-01T00:00:00Z").unwrap() }

    #[test]
    fn valid_license_is_valid_with_entitlements() {
        let sk = SigningKey::generate(&mut OsRng);
        let path = write("sp_lic_valid.json", &mint(&sk, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z", 50, &["pii.uz"]));
        let s = load_and_verify(&path, &sk.verifying_key(), now());
        assert_eq!(s.status, LicenseStatus::Valid);
        assert_eq!(s.max_seats, Some(50));
        assert_eq!(s.customer_name.as_deref(), Some("Acme"));
        assert!(s.features.iter().any(|f| f == "pii.uz"));
    }

    #[test]
    fn expired_license_is_grace() {
        let sk = SigningKey::generate(&mut OsRng);
        let path = write("sp_lic_expired.json", &mint(&sk, "2025-01-01T00:00:00Z", "2025-02-01T00:00:00Z", 10, &[]));
        let s = load_and_verify(&path, &sk.verifying_key(), now()); // now (2026) is after expiry
        assert_eq!(s.status, LicenseStatus::Grace);
        assert_eq!(s.max_seats, Some(10)); // entitlements still readable in grace
        // Grace fail-opens: no seat ceiling, all features permitted
        let st = LicenseState::new(s);
        assert_eq!(st.max_seats(), None);
        assert!(st.is_feature_enabled("any-feature"));
    }

    #[test]
    fn wrong_key_is_unlicensed() {
        let sk = SigningKey::generate(&mut OsRng);
        let other = SigningKey::generate(&mut OsRng);
        let path = write("sp_lic_wrongkey.json", &mint(&sk, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z", 10, &[]));
        let s = load_and_verify(&path, &other.verifying_key(), now());
        assert_eq!(s.status, LicenseStatus::Unlicensed);
    }

    #[test]
    fn tampered_license_is_unlicensed() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut env = mint(&sk, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z", 10, &[]);
        env.license.entitlements.seats = 9999; // tamper after signing
        let path = write("sp_lic_tampered.json", &env);
        let s = load_and_verify(&path, &sk.verifying_key(), now());
        assert_eq!(s.status, LicenseStatus::Unlicensed);
    }

    #[test]
    fn missing_file_is_unlicensed_no_panic() {
        let sk = SigningKey::generate(&mut OsRng);
        let s = load_and_verify("/nonexistent/sp_lic_nope.json", &sk.verifying_key(), now());
        assert_eq!(s.status, LicenseStatus::Unlicensed);
    }

    #[test]
    fn feature_and_seat_gates_fail_open() {
        // Valid: enforces
        let valid = LicenseState::new(LicenseSnapshot { status: LicenseStatus::Valid, max_seats: Some(5), features: vec!["a".into()], customer_name: None, expires_at: None, wrapped_model_key: None, lic_id: None });
        assert_eq!(valid.max_seats(), Some(5));
        assert!(valid.is_feature_enabled("a"));
        assert!(!valid.is_feature_enabled("b"));
        // Unlicensed: fail-open (no seat ceiling, all features permitted)
        let un = LicenseState::unlicensed();
        assert_eq!(un.max_seats(), None);
        assert!(un.is_feature_enabled("anything"));
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
            deployment: Deployment { scope: "single-node".into(), max_nodes: 1, sign_pubkey: "p".into() },
            entitlements: Entitlements { not_before: "2026-01-01T00:00:00Z".into(), expires_at: "2027-01-01T00:00:00Z".into(), seats: 5, features: vec![], components: vec![] },
            model: ModelGrant { wrapped_key: wrapped, models: vec![] },
            integrity: Integrity { image_digests: BTreeMap::new() },
            iss: "sp-admin".into(), iat: "2026-01-01T00:00:00Z".into(),
        };
        // Valid → unwraps to the original key
        let env = sign_license(&base, &sk).unwrap();
        let path = write("sp_lic_mk.json", &env);
        let st = LicenseState::new(load_and_verify(&path, &sk.verifying_key(), now()));
        assert_eq!(st.status(), LicenseStatus::Valid);
        assert_eq!(st.unwrap_model_key(&kek), Some(model_key));
        assert_eq!(st.unwrap_model_key(&[9u8; 32]), None); // wrong KEK

        // Expired (Grace) → None even with the right KEK (only Valid yields the key)
        let mut exp_lic = base.clone();
        exp_lic.entitlements.not_before = "2025-01-01T00:00:00Z".into();
        exp_lic.entitlements.expires_at = "2025-02-01T00:00:00Z".into();
        let env2 = sign_license(&exp_lic, &sk).unwrap();
        let p2 = write("sp_lic_mk_exp.json", &env2);
        let st2 = LicenseState::new(load_and_verify(&p2, &sk.verifying_key(), now()));
        assert_eq!(st2.status(), LicenseStatus::Grace);
        assert_eq!(st2.unwrap_model_key(&kek), None);
    }

    #[test]
    fn parse_kek_roundtrip() {
        use base64::{engine::general_purpose::STANDARD as B64, Engine};
        assert_eq!(parse_kek(&B64.encode([4u8; 32])), Some([4u8; 32]));
        assert_eq!(parse_kek("nope!!"), None);
        assert_eq!(parse_kek(&B64.encode([4u8; 16])), None); // wrong length
    }
}
