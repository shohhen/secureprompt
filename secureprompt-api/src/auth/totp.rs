//! TOTP (RFC 6238) primitives for two-factor authentication.
//!
//! RFC 6238 defaults: SHA1, 6 digits, 30-second step — this is what
//! authenticator apps (Google Authenticator, Authy, 1Password, etc.) expect.

use totp_rs::{Algorithm, Secret, TOTP};

/// TOTP step size in seconds (RFC 6238 default).
const STEP_SECONDS: u64 = 30;
/// TOTP code length in digits (RFC 6238 default; authenticator apps expect 6).
const DIGITS: usize = 6;

/// Errors returned by [`verify_code`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpError {
    /// No timestep in `[now-1, now, now+1]` produced a matching code.
    Invalid,
    /// The matched timestep was already consumed (`<= last_timestep`); the
    /// code is being replayed.
    Replayed,
}

/// Build a `TOTP` (SHA1 / 6 digits / 30s step) for verification purposes from
/// a base32 secret.
///
/// `skew` is always 0 here: `verify_code` walks the ±1 timestep window
/// itself so it can tell *which* step matched (needed for replay
/// prevention) rather than delegating to the crate's built-in skew check.
/// Returns `None` if `secret_b32` is not valid base32 or decodes to fewer
/// than 128 bits (RFC 6238 minimum) — both indicate a corrupt/foreign
/// secret, which can never produce a valid code.
fn build_totp(secret_b32: &str) -> Option<TOTP> {
    let secret_bytes = Secret::Encoded(secret_b32.to_string()).to_bytes().ok()?;
    TOTP::new(
        Algorithm::SHA1,
        DIGITS,
        0,
        STEP_SECONDS,
        secret_bytes,
        None,
        String::new(),
    )
    .ok()
}

/// Generate a new random base32-encoded TOTP secret (160-bit, RFC 4226 §4
/// recommended length).
#[must_use]
pub fn generate_secret() -> String {
    Secret::generate_secret().to_encoded().to_string()
}

/// Build an `otpauth://totp/...` provisioning URI (for QR-code enrollment)
/// from an existing base32 secret, account identifier, and issuer name.
///
/// Uses `TOTP::new_unchecked` rather than the length-validating constructor:
/// this only formats a URL (no cryptographic verification happens here), and
/// some legacy/imported secrets (e.g. the classic demo secret
/// `JBSWY3DPEHPK3PXP`) are shorter than the 128-bit RFC minimum but are
/// still valid for generating a scannable URI.
///
/// # Panics
///
/// Panics if `secret_b32` is not valid base32. Callers should only ever pass
/// a secret previously produced by [`generate_secret`] (or another
/// already-validated base32 string), so this indicates a caller bug rather
/// than untrusted input.
#[must_use]
pub fn provisioning_uri(secret_b32: &str, account: &str, issuer: &str) -> String {
    let secret_bytes = Secret::Encoded(secret_b32.to_string())
        .to_bytes()
        .expect("secret_b32 must be valid base32");
    // Colons are the otpauth label delimiter; strip them defensively so a
    // caller-supplied account (e.g. an email) can never corrupt the URI.
    let account = account.replace(':', "_");
    let issuer_sanitized = issuer.replace(':', "_");
    let totp = TOTP::new_unchecked(
        Algorithm::SHA1,
        DIGITS,
        0,
        STEP_SECONDS,
        secret_bytes,
        Some(issuer_sanitized),
        account,
    );
    totp.get_url()
}

/// Verify a submitted TOTP `code` against `secret_b32`, allowing ±1 timestep
/// (30s) clock skew.
///
/// Checks candidate steps `[now/30 - 1, now/30, now/30 + 1]` in
/// chronological order. On a match:
/// - if the matched step is `<= last_timestep`, the code has already been
///   consumed and `TotpError::Replayed` is returned (replay prevention);
/// - otherwise the matched step is returned so the caller can persist it as
///   the new `last_timestep`.
///
/// Returns `TotpError::Invalid` if no candidate step matches.
///
/// # Errors
///
/// Returns `Err(TotpError::Invalid)` if `secret_b32` is malformed or no
/// candidate timestep produces a matching code, and
/// `Err(TotpError::Replayed)` if the matched timestep is `<= last_timestep`.
pub fn verify_code(
    secret_b32: &str,
    code: &str,
    last_timestep: Option<u64>,
    now_unix: u64,
) -> Result<u64, TotpError> {
    let totp = build_totp(secret_b32).ok_or(TotpError::Invalid)?;
    let now_step = now_unix / STEP_SECONDS;
    let candidates = [now_step.saturating_sub(1), now_step, now_step + 1];

    for &step in &candidates {
        let step_time = step * STEP_SECONDS;
        if totp.check(code, step_time) {
            if let Some(last) = last_timestep {
                if step <= last {
                    return Err(TotpError::Replayed);
                }
            }
            return Ok(step);
        }
    }
    Err(TotpError::Invalid)
}

/// Test-only helper: generate the code for `secret_b32` at a given unix
/// timestamp, using the exact same `TOTP::generate` call `verify_code` uses
/// internally (via `check`, which calls `generate` under the hood).
#[cfg(test)]
fn code_at(secret_b32: &str, time: u64) -> String {
    build_totp(secret_b32)
        .expect("valid secret")
        .generate(time)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_verify_roundtrip() {
        let secret = generate_secret();
        // A TOTP for `now` must verify at `now`.
        let now = 1_700_000_000u64;
        let code = code_at(&secret, now); // test helper defined in impl
        let step = verify_code(&secret, &code, None, now).expect("valid code");
        assert_eq!(step, now / 30);
    }

    #[test]
    fn rejects_replayed_timestep() {
        let secret = generate_secret();
        let now = 1_700_000_000u64;
        let code = code_at(&secret, now);
        let step = verify_code(&secret, &code, None, now).unwrap();
        // Same code again with last_timestep = step must be rejected.
        assert!(matches!(
            verify_code(&secret, &code, Some(step), now),
            Err(TotpError::Replayed)
        ));
    }

    #[test]
    fn accepts_one_step_skew_but_not_two() {
        let secret = generate_secret();
        let now = 1_700_000_000u64;
        let prev = code_at(&secret, now - 30);
        assert!(verify_code(&secret, &prev, None, now).is_ok(), "±1 step ok");
        let two_ago = code_at(&secret, now - 90);
        assert!(matches!(verify_code(&secret, &two_ago, None, now), Err(TotpError::Invalid)));
    }

    #[test]
    fn rejects_garbage_code() {
        let secret = generate_secret();
        assert!(matches!(verify_code(&secret, "000000", Some(0), 1_700_000_000), Err(TotpError::Invalid) | Err(TotpError::Replayed)));
    }

    #[test]
    fn provisioning_uri_shape() {
        let uri = provisioning_uri("JBSWY3DPEHPK3PXP", "alice@example.com", "SecurePrompt");
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("issuer=SecurePrompt"));
    }
}
