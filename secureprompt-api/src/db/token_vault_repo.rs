//! Persistence for the tokenize/detokenize endpoints.
//!
//! A vault entry holds the mapping produced by `vault::apply_redaction`
//! (placeholder → original) for a single tokenize call. Entries are scoped
//! to the workspace and auto-expire after 24 h.
//!
//! # WS3-3 — the mapping is ciphertext on disk
//!
//! The originals in that mapping are the un-redacted PII the caller asked
//! SecurePrompt to protect, so they are encrypted through
//! [`secureprompt_common::kms::KmsBackend`] — the same `AppState.kms` that
//! [`crate::analytics::capture::seal`] uses for captured request content —
//! before they ever reach Postgres. Migration 022 replaced the plaintext
//! `mapping JSONB` column with `mapping_ciphertext TEXT` to make that the
//! only shape the table can hold.
//!
//! Two rules, both mirroring `capture::seal`:
//!
//! 1. **Encrypt-or-fail.** A KMS outage makes [`TokenVaultRepository::insert`]
//!    return an error, which fails the tokenize request. It never degrades to
//!    writing the original in the clear. Losing a tokenize call is
//!    recoverable — the caller retries; silently storing the customer's PII
//!    unencrypted because Vault was unreachable is the defect this module was
//!    changed to remove.
//! 2. **No plaintext read path.** There is no "if it looks like JSON, parse
//!    it directly" fallback for pre-022 rows, because 022 deleted them. A row
//!    that will not decrypt is an error, not an invitation to guess.

use chrono::{DateTime, Utc};
use secureprompt_common::{errors::ApiError, kms::KmsBackend};
use sqlx::{PgPool, Row as _};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

pub struct TokenVaultRepository {
    pool: PgPool,
    kms: Arc<dyn KmsBackend>,
}

pub struct TokenVaultEntry {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub mapping: HashMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl TokenVaultRepository {
    pub const fn new(pool: PgPool, kms: Arc<dyn KmsBackend>) -> Self {
        Self { pool, kms }
    }

    /// Serialise the mapping and encrypt it. `Err` when either step fails —
    /// there is deliberately no plaintext fallback.
    async fn seal(&self, mapping: &HashMap<String, String>) -> Result<String, ApiError> {
        let plaintext = serde_json::to_vec(mapping)
            .map_err(|e| ApiError::Internal(format!("vault serialize: {e}")))?;

        let ciphertext = self.kms.encrypt(&plaintext).await.map_err(|e| {
            tracing::error!(
                alert = "token_vault_encrypt_failed",
                error = %e,
                "KMS encrypt failed; refusing the tokenize rather than storing \
                 the originals in the clear"
            );
            ApiError::Internal(format!("vault encrypt: {e}"))
        })?;

        String::from_utf8(ciphertext).map_err(|e| {
            tracing::error!(
                alert = "token_vault_encrypt_failed",
                error = %e,
                "KMS returned non-UTF-8 ciphertext; refusing the tokenize"
            );
            ApiError::Internal("vault encrypt: ciphertext not UTF-8".to_owned())
        })
    }

    /// Decrypt a stored payload back into the placeholder → original map.
    async fn unseal(&self, ciphertext: &str) -> Result<HashMap<String, String>, ApiError> {
        let plaintext = self
            .kms
            .decrypt(ciphertext.as_bytes())
            .await
            .map_err(|e| ApiError::Internal(format!("vault decrypt: {e}")))?;

        serde_json::from_slice(&plaintext)
            .map_err(|e| ApiError::Internal(format!("vault deserialize: {e}")))
    }

    /// # Errors
    /// Returns `ApiError::Internal` if the mapping cannot be serialised or
    /// encrypted, and `ApiError::Database` if the insert fails.
    pub async fn insert(
        &self,
        id: Uuid,
        workspace_id: Uuid,
        mapping: &HashMap<String, String>,
    ) -> Result<TokenVaultEntry, ApiError> {
        // Encrypt BEFORE touching Postgres. A failure here must leave no row
        // at all, not a row awaiting a repair that never comes.
        let ciphertext = self.seal(mapping).await?;

        let row = sqlx::query(
            "INSERT INTO token_vault_entries (id, workspace_id, mapping_ciphertext)
             VALUES ($1, $2, $3)
             RETURNING id, workspace_id, created_at, expires_at",
        )
        .bind(id)
        .bind(workspace_id)
        .bind(&ciphertext)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        // Echo the caller's own mapping rather than decrypting what was just
        // written: the round-trip is proven by the tests, and re-reading here
        // would double the KMS calls on the hot tokenize path.
        Ok(TokenVaultEntry {
            id: row.get("id"),
            workspace_id: row.get("workspace_id"),
            mapping: mapping.clone(),
            created_at: row.get("created_at"),
            expires_at: row.get("expires_at"),
        })
    }

    /// Fetch an un-expired entry scoped to the caller's workspace.
    /// Returns `NotFound` when the row is missing, belongs to another
    /// workspace, or has expired.
    ///
    /// # Errors
    /// Returns `ApiError::Database` on query failure, `ApiError::NotFound`
    /// when no live row matches, and `ApiError::Internal` if the stored
    /// payload cannot be decrypted.
    pub async fn get(&self, id: Uuid, workspace_id: Uuid) -> Result<TokenVaultEntry, ApiError> {
        let row = sqlx::query(
            "SELECT id, workspace_id, mapping_ciphertext, created_at, expires_at
             FROM token_vault_entries
             WHERE id = $1 AND workspace_id = $2 AND expires_at > NOW()",
        )
        .bind(id)
        .bind(workspace_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        let row = row.ok_or_else(|| {
            ApiError::NotFound(format!("token vault entry {id} not found or expired"))
        })?;

        let ciphertext: String = row.get("mapping_ciphertext");
        Ok(TokenVaultEntry {
            id: row.get("id"),
            workspace_id: row.get("workspace_id"),
            mapping: self.unseal(&ciphertext).await?,
            created_at: row.get("created_at"),
            expires_at: row.get("expires_at"),
        })
    }
}
