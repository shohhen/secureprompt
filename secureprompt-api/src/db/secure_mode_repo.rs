//! Per-workspace secure mode (migration 007) — the redaction control itself.
//!
//! `enabled`, `level` and the three block/redact toggles are read on the
//! request path by [`crate::pipeline::service`] to decide whether PII is
//! redacted and whether a detection blocks the call.
//!
//! ## Row-level security
//!
//! Migration 007 created this table with no row-level security and no stated
//! reason. The reason a reader found instead was circular: 018 declared "NO
//! ROW-LEVEL SECURITY, matching `workspace_secure_mode` (007)", 021 cited 007
//! and 018, and 007 itself said nothing — three tables sharing one argument
//! whose root was an empty cell. Migration 030 armed 018's and 021's tables
//! after measuring that both were readable and writable across tenants, which
//! left this one as the last table in the schema justified only by citations
//! from tables that no longer lack a policy.
//!
//! Measured before migration 031, from a NOSUPERUSER/NOBYPASSRLS role armed to
//! workspace A with `policy_rules` isolated on the same connection as a
//! positive control: workspace A's scope read workspace B's row and got back
//! `level = 'strict'`. Binding `workspace_id` in these three queries protected
//! these three queries and nothing else.
//!
//! Migration 031 arms the table with the standard `workspace_isolation`
//! policy, so BOTH methods below go through [`crate::db::scope::begin_scoped`],
//! which sets `app.current_workspace_id` transaction-locally and READS IT
//! BACK. The read-back is the point, because the two halves of an unarmed
//! scope fail differently: an INSERT is rejected (loud) while a SELECT returns
//! the EMPTY SET and reports no error. Silent is the dangerous half here —
//! [`SecureModeRepository::get`] resolves "no row" to
//! [`SecureModeRow::default`], and that default is `enabled: false`. An
//! unarmed read would not merely hide this table; it would switch redaction
//! OFF for a workspace that switched it on.
//!
//! CORRECTION (MR5 C1 / MR6 F3). This header used to end "…and the request
//! path would carry on with policy-only behaviour having logged nothing",
//! which implied the read-back was the whole fix. It was not: the read-back
//! only turns a silent zero into an `Err`, and the sole caller
//! ([`crate::pipeline::service`]) resolved every `Err` back to
//! [`SecureModeRow::default`] — the same `enabled: false`, at HTTP 200, with
//! a `warn!` line as the only difference. The compensating control was inert
//! on the one path that matters. The caller now REFUSES the request (503) on
//! any error from [`SecureModeRepository::get`]; the read-back is what gives
//! it something to refuse on, rather than the fix by itself.

use chrono::{DateTime, Utc};
use secureprompt_common::{errors::ApiError, types::WorkspaceId};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::db::admin_audit_repo::{
    self, changed_field, AdminActor, AdminAuditAction, AdminAuditEntry,
};
use crate::db::scope::begin_scoped;

#[derive(Debug, Clone)]
pub struct SecureModeRow {
    pub workspace_id: Uuid,
    pub enabled: bool,
    pub level: String,
    pub block_on_pii_detection: bool,
    pub block_on_injection_detection: bool,
    pub redact_pii_in_responses: bool,
    pub updated_at: DateTime<Utc>,
}

impl Default for SecureModeRow {
    fn default() -> Self {
        Self {
            workspace_id: Uuid::nil(),
            enabled: false,
            level: "standard".to_owned(),
            block_on_pii_detection: false,
            block_on_injection_detection: false,
            redact_pii_in_responses: false,
            updated_at: Utc::now(),
        }
    }
}

pub struct SecureModeRepository {
    pool: PgPool,
}

impl SecureModeRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Returns the current config, or defaults when no row exists yet.
    ///
    /// Runs inside [`begin_scoped`] because migration 031 arms this table:
    /// with `app.current_workspace_id` unset the policy predicate is NULL for
    /// every row and this SELECT returns nothing, which `map_or_else` below
    /// resolves to `enabled: false` — redaction off, silently, for a workspace
    /// that turned it on. The read-back inside `begin_scoped` converts that
    /// silence into an error.
    ///
    /// That error is LOAD-BEARING and must not be swallowed. The doc here used
    /// to say the read-back produced "an error the caller can log", and the
    /// caller duly logged it and carried on with `enabled: false` — i.e. with
    /// the outcome the read-back was added to prevent. `pipeline::service`
    /// now refuses the request (503) on any `Err` from this method; see the
    /// comment at its call site for why that costs no availability the
    /// request path had.
    ///
    /// # Errors
    /// `ApiError::Database` on SQL failure, `ApiError::Internal` when the
    /// tenancy scope does not arm.
    pub async fn get(&self, workspace_id: WorkspaceId) -> Result<SecureModeRow, ApiError> {
        let mut tx = begin_scoped(&self.pool, workspace_id.0).await?;

        let row = sqlx::query(
            "SELECT workspace_id, enabled, level,
                    block_on_pii_detection, block_on_injection_detection,
                    redact_pii_in_responses, updated_at
             FROM workspace_secure_mode
             WHERE workspace_id = $1",
        )
        .bind(workspace_id.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?;

        Ok(row.map_or_else(
            || SecureModeRow {
                workspace_id: workspace_id.0,
                ..SecureModeRow::default()
            },
            |r| SecureModeRow {
                workspace_id: r.get("workspace_id"),
                enabled: r.get("enabled"),
                level: r.get("level"),
                block_on_pii_detection: r.get("block_on_pii_detection"),
                block_on_injection_detection: r.get("block_on_injection_detection"),
                redact_pii_in_responses: r.get("redact_pii_in_responses"),
                updated_at: r.get("updated_at"),
            },
        ))
    }

    /// Upsert the config for the workspace, and audit what moved (P1A).
    ///
    /// Secure mode IS the redaction control. "Redaction was switched off for
    /// an afternoon" had no trace at all, which is the same gap FU5 closed for
    /// policy rules, on the setting that governs whether the rules run.
    ///
    /// The pre-existing values are read INSIDE the transaction that replaces
    /// them, so the diff describes what this write actually changed rather than
    /// what a read a moment earlier happened to see. That also fixes a latent
    /// unrelated race: the previous `self.get()` ran on a separate connection,
    /// so a concurrent PUT between it and the INSERT could have its fields
    /// silently reverted by the `unwrap_or(current.…)` defaults below.
    ///
    /// A PUT that moves no field writes no audit row — see
    /// `budget_repo::upsert` for why, and `CONTROL_COVERAGE` for the statement
    /// of it an auditor reads.
    ///
    /// # Errors
    /// `ApiError::Database` on SQL failure, `ApiError::Internal` when the
    /// tenancy scope does not arm.
    pub async fn upsert(
        &self,
        workspace_id: WorkspaceId,
        enabled: Option<bool>,
        level: Option<&str>,
        block_on_pii_detection: Option<bool>,
        block_on_injection_detection: Option<bool>,
        redact_pii_in_responses: Option<bool>,
        actor: &AdminActor,
    ) -> Result<SecureModeRow, ApiError> {
        let mut tx = begin_scoped(&self.pool, workspace_id.0).await?;

        // Read current values so unset fields keep their existing values, and
        // so the audit row can say what moved.
        let existing = sqlx::query(
            "SELECT enabled, level, block_on_pii_detection, block_on_injection_detection,
                    redact_pii_in_responses
             FROM workspace_secure_mode
             WHERE workspace_id = $1",
        )
        .bind(workspace_id.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        let current = existing.map_or_else(
            || SecureModeRow {
                workspace_id: workspace_id.0,
                ..SecureModeRow::default()
            },
            |r| SecureModeRow {
                workspace_id: workspace_id.0,
                enabled: r.get("enabled"),
                level: r.get("level"),
                block_on_pii_detection: r.get("block_on_pii_detection"),
                block_on_injection_detection: r.get("block_on_injection_detection"),
                redact_pii_in_responses: r.get("redact_pii_in_responses"),
                updated_at: Utc::now(),
            },
        );

        let new_enabled = enabled.unwrap_or(current.enabled);
        let new_level = level.unwrap_or(&current.level).to_owned();
        let new_block_pii = block_on_pii_detection.unwrap_or(current.block_on_pii_detection);
        let new_block_inj = block_on_injection_detection.unwrap_or(current.block_on_injection_detection);
        let new_redact = redact_pii_in_responses.unwrap_or(current.redact_pii_in_responses);

        let row = sqlx::query(
            "INSERT INTO workspace_secure_mode
                (workspace_id, enabled, level,
                 block_on_pii_detection, block_on_injection_detection,
                 redact_pii_in_responses, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, NOW())
             ON CONFLICT (workspace_id) DO UPDATE SET
                enabled                     = EXCLUDED.enabled,
                level                       = EXCLUDED.level,
                block_on_pii_detection      = EXCLUDED.block_on_pii_detection,
                block_on_injection_detection = EXCLUDED.block_on_injection_detection,
                redact_pii_in_responses     = EXCLUDED.redact_pii_in_responses,
                updated_at                  = NOW()
             RETURNING workspace_id, enabled, level,
                       block_on_pii_detection, block_on_injection_detection,
                       redact_pii_in_responses, updated_at",
        )
        .bind(workspace_id.0)
        .bind(new_enabled)
        .bind(&new_level)
        .bind(new_block_pii)
        .bind(new_block_inj)
        .bind(new_redact)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        let mut changed = serde_json::Map::new();
        changed_field(&mut changed, "enabled", &json!(current.enabled), &json!(new_enabled));
        changed_field(&mut changed, "level", &json!(current.level), &json!(new_level));
        changed_field(
            &mut changed,
            "block_on_pii_detection",
            &json!(current.block_on_pii_detection),
            &json!(new_block_pii),
        );
        changed_field(
            &mut changed,
            "block_on_injection_detection",
            &json!(current.block_on_injection_detection),
            &json!(new_block_inj),
        );
        changed_field(
            &mut changed,
            "redact_pii_in_responses",
            &json!(current.redact_pii_in_responses),
            &json!(new_redact),
        );
        if !changed.is_empty() {
            admin_audit_repo::write(
                &mut tx,
                actor,
                &AdminAuditEntry::on_object(
                    AdminAuditAction::SecureModeUpdated,
                    workspace_id.0,
                    None,
                )
                .with_detail(json!({ "changed": Value::Object(changed) })),
            )
            .await?;
        }

        tx.commit()
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?;

        Ok(SecureModeRow {
            workspace_id: row.get("workspace_id"),
            enabled: row.get("enabled"),
            level: row.get("level"),
            block_on_pii_detection: row.get("block_on_pii_detection"),
            block_on_injection_detection: row.get("block_on_injection_detection"),
            redact_pii_in_responses: row.get("redact_pii_in_responses"),
            updated_at: row.get("updated_at"),
        })
    }
}
