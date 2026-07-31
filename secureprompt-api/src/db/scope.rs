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
