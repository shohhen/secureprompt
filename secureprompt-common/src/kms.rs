//! KMS abstraction layer.
//!
//! Provides a `KmsBackend` async trait with two implementations:
//!
//! * `FileKms` — AES-256-GCM envelope encryption via [`crate::crypto`].
//!   Key material is a base64-encoded 32-byte value from `KMS_FILE_KEY`.
//!   Suitable for single-node and air-gapped deployments.
//!
//! * `VaultKms` — HashiCorp Vault Transit secrets engine.
//!   Configured via `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_TRANSIT_MOUNT`,
//!   and `VAULT_TRANSIT_KEY`. For distributed or regulated environments.
//!
//! Select the backend at startup via `KMS_BACKEND=file` (default) or
//! `KMS_BACKEND=vault`, then call `kms_backend_from_env()`.

use anyhow::{Context, Result};
use async_trait::async_trait;
use std::sync::Arc;

/// Unified KMS interface — all backends implement this trait.
///
/// Both methods accept and return raw byte slices so the caller is
/// decoupled from any particular encoding or key-management scheme.
#[async_trait]
pub trait KmsBackend: Send + Sync {
    async fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;
    async fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

// ---------------------------------------------------------------------------
// FileKms
// ---------------------------------------------------------------------------

/// AES-256-GCM backend.  Key material is read once at construction time
/// from the `KMS_FILE_KEY` environment variable (base64-encoded 32 bytes).
pub struct FileKms {
    key: [u8; 32],
}

impl FileKms {
    /// Construct from `KMS_FILE_KEY` (base64-standard, exactly 32 decoded bytes).
    ///
    /// # Errors
    /// Returns an error if the variable is unset, not valid base64, or does
    /// not decode to exactly 32 bytes.
    pub fn from_env() -> Result<Self> {
        let raw = std::env::var("KMS_FILE_KEY")
            .context("KMS_FILE_KEY not set — generate with: openssl rand 32 | base64")?;
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let bytes = STANDARD
            .decode(raw.trim())
            .context("KMS_FILE_KEY: invalid base64")?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("KMS_FILE_KEY must be exactly 32 bytes after base64 decode"))?;
        Ok(Self { key })
    }
}

#[async_trait]
impl KmsBackend for FileKms {
    async fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let (nonce, ct) = crate::crypto::encrypt_aes_gcm(plaintext, &self.key)
            .map_err(|e| anyhow::anyhow!("FileKms encrypt failed: {e}"))?;
        let stored = crate::crypto::encode_encrypted(&nonce, &ct);
        Ok(stored.into_bytes())
    }

    async fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let stored = std::str::from_utf8(ciphertext)
            .context("FileKms: ciphertext not valid UTF-8")?;
        let (nonce, ct) = crate::crypto::decode_encrypted(stored)
            .map_err(|e| anyhow::anyhow!("FileKms decode failed: {e}"))?;
        crate::crypto::decrypt_aes_gcm(&nonce, &ct, &self.key)
            .map_err(|e| anyhow::anyhow!("FileKms decrypt failed: {e}"))
    }
}

// ---------------------------------------------------------------------------
// VaultKms
// ---------------------------------------------------------------------------

/// HashiCorp Vault Transit backend.
///
/// Requires a running Vault server with the Transit secrets engine enabled
/// and an encryption key provisioned under `VAULT_TRANSIT_KEY`.
///
/// All integration tests are `#[ignore]`d — no live Vault is required in CI.
pub struct VaultKms {
    client: vaultrs::client::VaultClient,
    mount: String,
    key_name: String,
}

impl VaultKms {
    /// Construct from environment variables:
    ///
    /// | Variable              | Default                          |
    /// |-----------------------|----------------------------------|
    /// | `VAULT_ADDR`          | `http://vault:8200`              |
    /// | `VAULT_TOKEN`         | *required*                       |
    /// | `VAULT_TRANSIT_MOUNT` | `transit`                        |
    /// | `VAULT_TRANSIT_KEY`   | `secureprompt-kms`               |
    ///
    /// # Errors
    /// Returns an error if `VAULT_TOKEN` is unset or if the client cannot be
    /// constructed from the provided settings.
    pub fn from_env() -> Result<Self> {
        use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
        let addr = std::env::var("VAULT_ADDR")
            .unwrap_or_else(|_| "http://vault:8200".into());
        let token = std::env::var("VAULT_TOKEN")
            .context("VAULT_TOKEN required for VaultKms backend")?;
        let settings = VaultClientSettingsBuilder::default()
            .address(addr)
            .token(token)
            .build()
            .context("VaultKms: failed to build VaultClientSettings")?;
        Ok(Self {
            client: VaultClient::new(settings)
                .context("VaultKms: failed to create VaultClient")?,
            mount: std::env::var("VAULT_TRANSIT_MOUNT")
                .unwrap_or_else(|_| "transit".into()),
            key_name: std::env::var("VAULT_TRANSIT_KEY")
                .unwrap_or_else(|_| "secureprompt-kms".into()),
        })
    }
}

#[async_trait]
impl KmsBackend for VaultKms {
    async fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        // Vault Transit encrypt expects base64-encoded plaintext.
        let b64 = STANDARD.encode(plaintext);
        let resp = vaultrs::transit::data::encrypt(
            &self.client,
            &self.mount,
            &self.key_name,
            &b64,
            None,
        )
        .await
        .context("VaultKms: encrypt request failed")?;
        Ok(resp.ciphertext.into_bytes())
    }

    async fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let ct_str = std::str::from_utf8(ciphertext)
            .context("VaultKms: ciphertext not valid UTF-8")?;
        let resp = vaultrs::transit::data::decrypt(
            &self.client,
            &self.mount,
            &self.key_name,
            ct_str,
            None,
        )
        .await
        .context("VaultKms: decrypt request failed")?;
        // Vault Transit decrypt returns base64-encoded plaintext.
        STANDARD
            .decode(&resp.plaintext)
            .context("VaultKms: failed to base64-decode decrypted plaintext")
    }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/// Create a `KmsBackend` from the `KMS_BACKEND` environment variable.
///
/// | Value   | Backend   |
/// |---------|-----------|
/// | `file`  | `FileKms` |
/// | `vault` | `VaultKms`|
///
/// Defaults to `file` if the variable is not set.
///
/// # Errors
/// Returns an error if the selected backend cannot be initialised (e.g.,
/// missing environment variables) or if an unknown value is supplied.
pub fn kms_backend_from_env() -> Result<Arc<dyn KmsBackend>> {
    let backend = std::env::var("KMS_BACKEND").unwrap_or_else(|_| "file".into());
    match backend.as_str() {
        "file" => Ok(Arc::new(FileKms::from_env()?)),
        "vault" => Ok(Arc::new(VaultKms::from_env()?)),
        other => anyhow::bail!("unknown KMS_BACKEND: {other} (expected: file | vault)"),
    }
}
