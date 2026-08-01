//! The one cross-tenant read the nightly sweeps are allowed, and the
//! precondition that keeps it honest.
//!
//! # Why this module exists rather than a second copy
//!
//! Both nightly sweeps — `tasks::retention_purge` and
//! `tasks::api_key_rotation` — are cross-tenant by design and solve that the
//! same way: enumerate `workspaces` on a bare pool, then do the work once per
//! workspace inside a transaction armed to that workspace and read back. The
//! alternatives were rejected in both places for the same reasons (a policy
//! hanging off a GUC any holder of the connection can set widens the table for
//! every statement in the process; a `BYPASSRLS` worker role removes the
//! boundary from every query the worker makes, including ones written later by
//! someone who does not know the role is privileged).
//!
//! The enumeration was written twice. MR6 then hardened ONE copy — adding the
//! `row_security_active` precondition below — and left the other with a bare
//! `SELECT`, plus a comment asserting a test-level backstop that did not
//! exist. That is MR6 F2, and a second copy is how it happened, so there is
//! now one.
//!
//! # What the precondition is for
//!
//! `workspaces` carries no `workspace_id` and no policy, which is the whole
//! reason this read may stay on a bare pool. If a migration ever arms it, the
//! enumeration stops being a list of every tenant and becomes a SILENT EMPTY
//! SET — no error, no row, and every sweep built on it then runs zero
//! iterations and reports whatever "no failures" means to it. Checking the
//! premise is what turns that into a recorded refusal.
//!
//! MEASURED both ways: `SELECT row_security_active('public.workspaces')`
//! answers `false` for the runner role on the current schema, and `true` in
//! `retention_purge`'s
//! `a_capture_sweep_that_cannot_enumerate_workspaces_fails_loudly` and
//! `api_key_rotation`'s `a_sweep_that_cannot_enumerate_workspaces_fails_loudly`,
//! both of which arm the table and require the run to fail.

use sqlx::PgPool;
use uuid::Uuid;

/// The refusal recorded when a sweep's ONE bare-pool read is itself policed.
///
/// The wording is load-bearing in `retention_purge`'s census assertions, which
/// require the recorded error to NAME what could not be read.
pub const WORKSPACES_ARE_POLICED: &str =
    "row security is active on `workspaces` for this connection, so enumerating \
     it would return a filtered list and any sweep built on it would silently \
     skip every workspace it cannot see";

/// Enumerate every tenant, refusing to do so blind.
///
/// # Errors
/// `sqlx::Error::Protocol(WORKSPACES_ARE_POLICED)` when row security is active
/// on `workspaces` for this connection — i.e. when the answer would be a
/// filtered list indistinguishable from a complete one. Ordinary `sqlx` errors
/// otherwise.
pub async fn enumerate_workspaces(pg: &PgPool) -> Result<Vec<Uuid>, sqlx::Error> {
    let policed: bool = sqlx::query_scalar("SELECT row_security_active('public.workspaces')")
        .fetch_one(pg)
        .await?;
    if policed {
        return Err(sqlx::Error::Protocol(WORKSPACES_ARE_POLICED.to_owned()));
    }
    sqlx::query_scalar::<_, Uuid>("SELECT id FROM workspaces")
        .fetch_all(pg)
        .await
}
