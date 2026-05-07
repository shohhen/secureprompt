//! Persistence for the tokenize/detokenize endpoints.
//!
//! A vault entry holds the mapping produced by `vault::apply_redaction`
//! (placeholder → original) for a single tokenize call. Entries are scoped
//! to the workspace and auto-expire after 24 h.

use chrono::{DateTime, Utc};
use secureprompt_common::errors::ApiError;
use serde_json::Value;
use sqlx::{PgPool, Row as _};
use std::collections::HashMap;
use uuid::Uuid;

pub struct TokenVaultRepository {
    pool: PgPool,
}

pub struct TokenVaultEntry {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub mapping: HashMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl TokenVaultRepository {
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn insert(
        &self,
        id: Uuid,
        workspace_id: Uuid,
        mapping: &HashMap<String, String>,
    ) -> Result<TokenVaultEntry, ApiError> {
        let mapping_json = serde_json::to_value(mapping)
            .map_err(|e| ApiError::Internal(format!("vault serialize: {e}")))?;

        let row = sqlx::query(
            "INSERT INTO token_vault_entries (id, workspace_id, mapping)
             VALUES ($1, $2, $3)
             RETURNING id, workspace_id, mapping, created_at, expires_at",
        )
        .bind(id)
        .bind(workspace_id)
        .bind(&mapping_json)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        let mapping_row: Value = row.get("mapping");
        Ok(TokenVaultEntry {
            id: row.get("id"),
            workspace_id: row.get("workspace_id"),
            mapping: decode_mapping(mapping_row)?,
            created_at: row.get("created_at"),
            expires_at: row.get("expires_at"),
        })
    }

    /// Fetch an un-expired entry scoped to the caller's workspace.
    /// Returns `NotFound` when the row is missing, belongs to another
    /// workspace, or has expired.
    pub async fn get(
        &self,
        id: Uuid,
        workspace_id: Uuid,
    ) -> Result<TokenVaultEntry, ApiError> {
        let row = sqlx::query(
            "SELECT id, workspace_id, mapping, created_at, expires_at
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

        let mapping_row: Value = row.get("mapping");
        Ok(TokenVaultEntry {
            id: row.get("id"),
            workspace_id: row.get("workspace_id"),
            mapping: decode_mapping(mapping_row)?,
            created_at: row.get("created_at"),
            expires_at: row.get("expires_at"),
        })
    }
}

fn decode_mapping(raw: Value) -> Result<HashMap<String, String>, ApiError> {
    serde_json::from_value::<HashMap<String, String>>(raw)
        .map_err(|e| ApiError::Internal(format!("vault deserialize: {e}")))
}
