//! AES-256-GCM envelope encryption helpers.
//!
//! Used by `secureprompt-api` Plan 05-04 to encrypt provider credentials
//! before storing them in the `providers.encrypted_credential` column.
//!
//! Key material is loaded from `SECUREPROMPT_PROVIDER_KEY` (32-byte hex string,
//! distinct from `SECUREPROMPT_JWT_SECRET` — enforced by `JwtConfig::from_env`).
//!
//! Storage format: `base64url_no_pad(nonce || ciphertext)` stored as a single
//! TEXT column value. The 12-byte nonce is prepended so each encrypted value
//! is self-contained and can be rotated independently.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use thiserror::Error;

/// Errors returned by the crypto helpers.
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("AES-GCM encryption failed")]
    EncryptFailed,
    #[error("AES-GCM decryption failed (wrong key or corrupt ciphertext)")]
    DecryptFailed,
    #[error("invalid key: {0}")]
    InvalidKey(String),
}

/// Encrypt `plaintext` with AES-256-GCM using the provided 32-byte key.
///
/// Returns `(nonce, ciphertext)`. The caller is responsible for persisting
/// both (typically by concatenating `nonce || ciphertext` and base64-encoding).
///
/// # Errors
/// Returns `CryptoError::EncryptFailed` if the AES-GCM AEAD operation fails
/// (should never happen with a valid 32-byte key and fresh 12-byte nonce).
pub fn encrypt_aes_gcm(
    plaintext: &[u8],
    key: &[u8; 32],
) -> Result<([u8; 12], Vec<u8>), CryptoError> {
    use aes_gcm::aead::OsRng;
    use aes_gcm::aead::rand_core::RngCore;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::EncryptFailed)?;

    Ok((nonce_bytes, ciphertext))
}

/// Decrypt `ciphertext` with AES-256-GCM using the provided 32-byte key and
/// 12-byte nonce.
///
/// # Errors
/// Returns `CryptoError::DecryptFailed` when the authentication tag does not
/// match (wrong key, corrupt ciphertext, or tampered data).
pub fn decrypt_aes_gcm(
    nonce: &[u8; 12],
    ciphertext: &[u8],
    key: &[u8; 32],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptFailed)
}

/// Encode `nonce || ciphertext` as a base64url-no-padding string for storage
/// in a TEXT column.
#[must_use]
pub fn encode_encrypted(nonce: &[u8; 12], ciphertext: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let mut combined = Vec::with_capacity(12 + ciphertext.len());
    combined.extend_from_slice(nonce);
    combined.extend_from_slice(ciphertext);
    URL_SAFE_NO_PAD.encode(&combined)
}

/// Decode a storage string produced by `encode_encrypted` back into
/// `(nonce, ciphertext)`.
///
/// # Errors
/// Returns an error string if the value is not valid base64url or is too short
/// to contain a 12-byte nonce.
pub fn decode_encrypted(stored: &str) -> Result<([u8; 12], Vec<u8>), CryptoError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let bytes = URL_SAFE_NO_PAD
        .decode(stored)
        .map_err(|e| CryptoError::InvalidKey(format!("base64 decode failed: {e}")))?;
    if bytes.len() < 12 {
        return Err(CryptoError::InvalidKey(
            "encrypted value too short (< 12 bytes)".into(),
        ));
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&bytes[..12]);
    let ciphertext = bytes[12..].to_vec();
    Ok((nonce, ciphertext))
}

/// Parse a 32-byte hex string into a key array.
///
/// # Errors
/// Returns `CryptoError::InvalidKey` if the string is not exactly 64 hex
/// characters or contains non-hex digits.
pub fn parse_provider_key(hex_key: &str) -> Result<[u8; 32], CryptoError> {
    let bytes = hex::decode(hex_key.trim())
        .map_err(|e| CryptoError::InvalidKey(format!("hex decode failed: {e}")))?;
    if bytes.len() != 32 {
        return Err(CryptoError::InvalidKey(format!(
            "expected 32 bytes (64 hex chars), got {} bytes",
            bytes.len()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        let hex = "0000000000000000000000000000000000000000000000000000000000000001";
        parse_provider_key(hex).expect("valid test key")
    }

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let key = test_key();
        let plaintext = b"sk-test-secret-value";
        let (nonce, ciphertext) = encrypt_aes_gcm(plaintext, &key).expect("encrypt");
        // Ciphertext must not equal plaintext
        assert_ne!(ciphertext, plaintext);
        let recovered = decrypt_aes_gcm(&nonce, &ciphertext, &key).expect("decrypt");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn wrong_key_fails_decrypt() {
        let key = test_key();
        let wrong_key = [0xffu8; 32];
        let (nonce, ciphertext) = encrypt_aes_gcm(b"secret", &key).expect("encrypt");
        let result = decrypt_aes_gcm(&nonce, &ciphertext, &wrong_key);
        assert!(matches!(result, Err(CryptoError::DecryptFailed)));
    }

    #[test]
    fn encode_decode_storage_roundtrip() {
        let key = test_key();
        let (nonce, ct) = encrypt_aes_gcm(b"hello", &key).expect("encrypt");
        let stored = encode_encrypted(&nonce, &ct);
        let (decoded_nonce, decoded_ct) = decode_encrypted(&stored).expect("decode");
        assert_eq!(decoded_nonce, nonce);
        assert_eq!(decoded_ct, ct);
    }

    #[test]
    fn parse_provider_key_rejects_short() {
        let result = parse_provider_key("deadbeef");
        assert!(matches!(result, Err(CryptoError::InvalidKey(_))));
    }

    #[test]
    fn parse_provider_key_rejects_non_hex() {
        let result = parse_provider_key(&"z".repeat(64));
        assert!(matches!(result, Err(CryptoError::InvalidKey(_))));
    }
}
