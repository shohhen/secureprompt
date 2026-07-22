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

/// Build a `TOTP` (SHA1 / 6 digits / 30s step) from a base32 secret, using
/// the checked `TOTP::new` (RFC 6238 minimum 128-bit secret enforced).
///
/// `skew` is always 0 here: `verify_code` walks the ±1 timestep window
/// itself so it can tell *which* step matched (needed for replay
/// prevention) rather than delegating to the crate's built-in skew check.
/// Returns `None` if `secret_b32` is not valid base32, decodes to fewer
/// than 128 bits (RFC 6238 minimum), or `issuer`/`account_name` contain a
/// `:` — all indicate malformed input, which can never produce a valid
/// code or a well-formed provisioning URI.
///
/// Used by both `verify_code` (via `build_totp`) and `provisioning_uri`, so
/// the two entry points agree on what counts as a valid secret.
fn build_totp_checked(
    secret_b32: &str,
    issuer: Option<String>,
    account_name: String,
) -> Option<TOTP> {
    let secret_bytes = Secret::Encoded(secret_b32.to_string()).to_bytes().ok()?;
    TOTP::new(
        Algorithm::SHA1,
        DIGITS,
        0,
        STEP_SECONDS,
        secret_bytes,
        issuer,
        account_name,
    )
    .ok()
}

/// [`build_totp_checked`] with no issuer/account — the shape `verify_code`
/// and the test-only `code_at` need (they only generate/check codes, never
/// format a URL).
fn build_totp(secret_b32: &str) -> Option<TOTP> {
    build_totp_checked(secret_b32, None, String::new())
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
/// Uses the same checked `TOTP::new` as `verify_code`/`build_totp` (via
/// `build_totp_checked`), so both entry points agree on what counts as a
/// valid secret — in particular this now also enforces the 128-bit RFC 6238
/// minimum, matching `verify_code`. `generate_secret()` always emits a
/// 160-bit secret, so real enrollment call sites are unaffected.
///
/// # Errors
///
/// Returns `Err(TotpError::Invalid)` if `secret_b32` is not valid base32 or
/// decodes to fewer than 128 bits. Never panics.
pub fn provisioning_uri(
    secret_b32: &str,
    account: &str,
    issuer: &str,
) -> Result<String, TotpError> {
    // Colons are the otpauth label delimiter; strip them defensively so a
    // caller-supplied account (e.g. an email) can never corrupt the URI.
    let account = account.replace(':', "_");
    let issuer_sanitized = issuer.replace(':', "_");
    let totp = build_totp_checked(secret_b32, Some(issuer_sanitized), account)
        .ok_or(TotpError::Invalid)?;
    Ok(totp.get_url())
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
    fn accepts_one_step_skew_past_and_future() {
        let secret = generate_secret();
        let now = 1_700_000_000u64;
        // n-1: previous step must verify.
        let prev = code_at(&secret, now - 30);
        assert!(verify_code(&secret, &prev, None, now).is_ok(), "±1 step (past) ok");
        // n+1: next step must also verify — a regression that only checked
        // the past direction would pass unnoticed without this.
        let next = code_at(&secret, now + 30);
        assert!(verify_code(&secret, &next, None, now).is_ok(), "±1 step (future) ok");
    }

    #[test]
    fn rejects_two_steps_away_both_directions() {
        let secret = generate_secret();
        let now = 1_700_000_000u64;
        // n-2 and n+2 are both one step outside the accepted [-1, +1]
        // window and must be rejected on both sides.
        let two_back = code_at(&secret, now - 60);
        assert!(matches!(verify_code(&secret, &two_back, None, now), Err(TotpError::Invalid)));
        let two_forward = code_at(&secret, now + 60);
        assert!(matches!(verify_code(&secret, &two_forward, None, now), Err(TotpError::Invalid)));
    }

    #[test]
    fn rejects_garbage_code() {
        let secret = generate_secret();
        assert!(matches!(verify_code(&secret, "000000", Some(0), 1_700_000_000), Err(TotpError::Invalid) | Err(TotpError::Replayed)));
    }

    #[test]
    fn rejects_malformed_input_without_panic() {
        let secret = generate_secret();
        let now = 1_700_000_000u64;
        // Non-numeric code: must be rejected, not panic.
        assert!(matches!(verify_code(&secret, "abcdef", None, now), Err(TotpError::Invalid)));
        // Malformed (non-base32) secret: must be rejected, not panic.
        assert!(matches!(verify_code("not!base32", "123456", None, now), Err(TotpError::Invalid)));
    }

    #[test]
    fn provisioning_uri_shape() {
        // Realistic (160-bit, generate_secret()-produced) secret — not the
        // 80-bit classic demo secret, which is below the RFC 6238 minimum
        // that provisioning_uri now enforces via the checked constructor.
        let secret = generate_secret();
        let uri = provisioning_uri(&secret, "alice@example.com", "SecurePrompt")
            .expect("valid secret");
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("issuer=SecurePrompt"));
    }

    #[test]
    fn provisioning_uri_rejects_malformed_secret_without_panic() {
        assert!(matches!(
            provisioning_uri("not!base32", "alice@example.com", "SecurePrompt"),
            Err(TotpError::Invalid)
        ));
    }
}
