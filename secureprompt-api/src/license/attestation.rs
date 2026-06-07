//! Build and sign per-deployment usage bundles (Plan 5).
//! The gateway calls `build_bundle` + `sign_bundle` from the `/internal/attestation`
//! handler; sp-admin reconciles the `SignedAttestation` payload.
use ed25519_dalek::SigningKey;
use sp_license::{AttestationBundle, SignedAttestation, sign_bytes};

/// Construct an `AttestationBundle` from the supplied metrics snapshot.
/// All string arguments are already formatted (RFC 3339 for datetimes).
pub fn build_bundle(
    lic_id: &str,
    deployment_fp: &str,
    active_seats: u32,
    requests: u64,
    period_from: &str,
    period_to: &str,
    now_rfc3339: &str,
) -> AttestationBundle {
    AttestationBundle {
        lic_id: lic_id.into(),
        deployment_fp: deployment_fp.into(),
        period_from: period_from.into(),
        period_to: period_to.into(),
        active_seats,
        requests,
        version: env!("CARGO_PKG_VERSION").into(),
        tamper_flags: vec![],
        generated_at: now_rfc3339.into(),
    }
}

/// Serialize `bundle` to canonical bytes and sign with `sk`.
/// Returns `Err(String)` only if JSON serialisation fails (should never happen
/// for a well-formed bundle).
pub fn sign_bundle(
    bundle: &AttestationBundle,
    sk: &SigningKey,
) -> Result<SignedAttestation, String> {
    let msg = bundle.canonical_bytes().map_err(|e| e.to_string())?;
    Ok(SignedAttestation {
        bundle: bundle.clone(),
        signature: sign_bytes(&msg, sk),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use sp_license::verify_bytes;

    #[test]
    fn build_sign_and_verify_bundle() {
        let sk = SigningKey::generate(&mut OsRng);
        let bundle = build_bundle(
            "lic-abc-123",
            "fp-xyz",
            42,
            1000,
            "2026-01-01T00:00:00Z",
            "2026-02-01T00:00:00Z",
            "2026-01-15T12:00:00Z",
        );
        let signed = sign_bundle(&bundle, &sk).expect("sign_bundle must succeed");
        assert_eq!(signed.bundle, bundle);
        let msg = bundle.canonical_bytes().unwrap();
        assert!(
            verify_bytes(&msg, &signed.signature, &sk.verifying_key()).is_ok(),
            "signature must verify with the signing key's verifying key"
        );
    }

    #[test]
    fn version_field_is_set() {
        let bundle = build_bundle("l", "d", 0, 0, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z");
        assert!(!bundle.version.is_empty());
    }
}
