//! Tenancy scoping for RLS-protected tables, with the read-back FU1 added.
//!
//! # The trap this closes
//!
//! Every `workspace_isolation` policy in this schema is
//! `workspace_id = current_setting('app.current_workspace_id', true)::uuid`.
//! With the GUC unset, `current_setting(..., true)` yields NULL, the predicate
//! is NULL for every row, and the two halves fail DIFFERENTLY:
//!
//!   * A WRITE is loud. The INSERT is rejected and the caller sees an error.
//!   * A READ is SILENT. The SELECT succeeds and returns the EMPTY SET.
//!
//! The silent half is the dangerous one, because zero rows is a plausible
//! answer to almost every question this product asks. On an audit export it
//! reads as "this workspace's administrators did nothing" (FU1's finding); on
//! the FU4 session listing it reads as "this account has no active sessions",
//! which an administrator investigating a suspected compromise would believe.
//!
//! [`begin_scoped`] therefore sets the GUC and then READS IT BACK inside the
//! same transaction, so a transaction that is not armed fails loudly instead of
//! answering nothing. [`scope_is_armed`] is split out so it is directly
//! testable: a guard whose deletion changes no test result is a guard that
//! defends nothing.
//!
//! Same shape and the same reason as
//! `secureprompt-worker/src/tasks/audit_export.rs::begin_scoped`. That copy is
//! in another crate and cannot be shared without giving the worker a dependency
//! on the API crate; this one is the API-side original, and
//! `dashboard::audit_export::begin_scoped` — which predates FU1 and has no
//! read-back — is a candidate to adopt it, deliberately left alone by FU4 so
//! that a signed-export path is not modified by a session-listing change.

use secureprompt_common::errors::ApiError;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

/// Message carried by the error a transaction fails with when the GUC did not
/// take. A constant so a test can match on it without restating the prose.
pub const SCOPE_NOT_ARMED: &str =
    "app.current_workspace_id was not armed for this transaction; refusing to \
     run a row-level-security-protected query that would silently return no rows";

/// The setting migration 032's `refresh_token_possession` policy reads.
///
/// Spelled once, in Rust, and interpolated into the two statements below, so
/// the policy and this module cannot drift apart through a typo that would
/// present as "the lookup finds nothing" rather than as an error.
pub const REFRESH_TOKEN_PROBE_GUC: &str = "app.refresh_token_probe";

/// Message carried by the error [`begin_refresh_token_probe`] fails with when
/// its setting did not take.
pub const PROBE_NOT_ARMED: &str =
    "app.refresh_token_probe was not armed for this transaction; refusing to \
     run a refresh-token lookup that would silently return no rows";

/// Open a transaction with `app.current_workspace_id` set AND verified.
///
/// `true` on `set_config` makes the setting local to this transaction, so it
/// cannot leak onto the next checkout of a pooled connection.
///
/// # Errors
/// Returns `ApiError::Database` when the transaction cannot be opened or the
/// GUC cannot be set, and `ApiError::Internal` carrying [`SCOPE_NOT_ARMED`]
/// when the value does not read back.
pub async fn begin_scoped(
    pool: &PgPool,
    workspace_id: Uuid,
) -> Result<Transaction<'static, Postgres>, ApiError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;
    arm_scope(&mut tx, workspace_id).await?;
    Ok(tx)
}

/// Arm `app.current_workspace_id` on a transaction that is ALREADY OPEN, and
/// verify it took.
///
/// [`begin_scoped`] is the shape almost every caller wants and delegates here.
/// This entry point exists for the one case `begin_scoped` cannot serve: a
/// transaction whose scope is not knowable at `BEGIN`, because the workspace it
/// names is CREATED inside that same transaction.
///
/// `WorkspaceRepository::create_with_owner` is that case. It inserts
/// `workspaces`, then `users`, then the seeded `policy_rules` row — and
/// `policy_rules` is armed while `workspaces` is not, so the scope can only be
/// set once `gen_random_uuid()` has handed back the new workspace's id. The
/// three inserts must stay in ONE transaction (a duplicate email has to roll
/// the workspace back), so re-opening a scoped transaction is not available.
///
/// `true` on `set_config` — transaction-local, never session-local. A
/// session-local `false` would leave the newly created workspace's scope on the
/// pooled connection for whatever statement is handed it next, converting a
/// write rejection into a cross-tenant read.
/// `the_creating_scope_does_not_outlive_the_transaction` in
/// `tests/rls_workspace_creation.rs` is the test that fails if this changes.
///
/// # Errors
/// Returns `ApiError::Database` when the GUC cannot be set, and
/// `ApiError::Internal` carrying [`SCOPE_NOT_ARMED`] when it does not read
/// back.
pub async fn arm_scope(
    tx: &mut Transaction<'static, Postgres>,
    workspace_id: Uuid,
) -> Result<(), ApiError> {
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
        .bind(workspace_id.to_string())
        .execute(&mut **tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;
    scope_is_armed(tx, workspace_id).await
}

/// Open a transaction that may read ONE `refresh_tokens` row: the one whose
/// `token_hash` is `token_hash`.
///
/// # Why this exists at all
///
/// Every other access path in this crate knows its workspace before it opens a
/// transaction. The two by-hash refresh-token lookups cannot: a refresh token
/// is thirty-two bytes of entropy and does not name its workspace, so the
/// lookup is what DISCOVERS the scope. `rotate` then arms [`begin_scoped`] for
/// the write with the workspace this probe handed it.
///
/// # What the transaction can and cannot do
///
/// Migration 032's `refresh_token_possession` policy is `FOR SELECT` and keyed
/// on equality with this setting, so the transaction returned here may READ the
/// named row and nothing else. Measured on PostgreSQL 16 under a
/// NOSUPERUSER/NOBYPASSRLS role, with the probe armed to a FOREIGN workspace's
/// token hash and no workspace scope: `SELECT` saw 1 row, while `UPDATE`,
/// `DELETE` and a blind table-wide `UPDATE` each affected 0 rows and the rows
/// were unchanged on disk after COMMIT. Do not add a write to this
/// transaction — it will not raise, it will silently affect nothing.
/// `the_probe_grants_a_read_and_nothing_else` in
/// `tests/rls_refresh_token_scope.rs` is the test that fails if 032's `FOR
/// SELECT` is ever widened.
///
/// `true` on `set_config` — TRANSACTION-LOCAL. A session-local `false` would
/// leave one caller's token hash armed on a pooled connection for whatever
/// statement is handed it next. The value is read back for the same reason
/// [`arm_scope`] reads its own back: a setting that did not take produces no
/// rows, and no rows is a plausible answer here.
///
/// # Errors
/// Returns `ApiError::Database` when the transaction cannot be opened or the
/// setting cannot be applied, and `ApiError::Internal` carrying
/// [`PROBE_NOT_ARMED`] when it does not read back.
pub async fn begin_refresh_token_probe(
    pool: &PgPool,
    token_hash: &str,
) -> Result<Transaction<'static, Postgres>, ApiError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;
    sqlx::query(&format!(
        "SELECT set_config('{REFRESH_TOKEN_PROBE_GUC}', $1, true)"
    ))
    .bind(token_hash)
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::Database(e.to_string()))?;

    let armed: Option<String> = sqlx::query_scalar(&format!(
        "SELECT current_setting('{REFRESH_TOKEN_PROBE_GUC}', true)"
    ))
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| ApiError::Database(e.to_string()))?;
    if armed.as_deref() == Some(token_hash) {
        Ok(tx)
    } else {
        Err(ApiError::Internal(PROBE_NOT_ARMED.to_owned()))
    }
}

/// Read `app.current_workspace_id` back and require it to be `workspace_id`.
///
/// # Errors
/// Returns `ApiError::Database` if the read itself fails, and
/// `ApiError::Internal` carrying [`SCOPE_NOT_ARMED`] if the value is absent,
/// empty or different.
pub async fn scope_is_armed(
    tx: &mut Transaction<'static, Postgres>,
    workspace_id: Uuid,
) -> Result<(), ApiError> {
    let armed: Option<String> =
        sqlx::query_scalar("SELECT current_setting('app.current_workspace_id', true)")
            .fetch_one(&mut **tx)
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?;
    if armed.as_deref() == Some(workspace_id.to_string().as_str()) {
        Ok(())
    } else {
        Err(ApiError::Internal(SCOPE_NOT_ARMED.to_owned()))
    }
}
