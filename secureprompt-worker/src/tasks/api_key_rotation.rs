//! Phase 6 / Plan 06-01 — the API-key rotation-cleanup sweep (D-17, AUTH-08).
//!
//! Extracted VERBATIM out of the `0 0 3 * * *` cron closure in
//! `secureprompt-worker/src/main.rs` so it can be driven by a test. The
//! statement, its predicate and its bare-pool executor are unchanged by the
//! extraction; the next commit changes the executor.
//!
//! # What the sweep is for, and what it is NOT for
//!
//! `ApiKeyRepository::rotate` moves the OLD key to `status = 'rotating'` and
//! stamps `rotated_at`. The key stays usable for `rotation_grace_secs` so a
//! deployment mid-roll does not break. This sweep is what finally moves the
//! grace-expired row to `status = 'revoked'` and stamps `revoked_at`.
//!
//! It is NOT the thing that stops the old key working. MEASURED, not assumed:
//! `ApiKeyRepository::authenticate_api_key` re-derives the same boundary in its
//! own WHERE —
//!
//! ```sql
//! status = 'rotating'
//!   AND rotated_at + (rotation_grace_secs || ' seconds')::INTERVAL > NOW()
//! ```
//!
//! — which is the exact complement of this sweep's predicate. A grace-expired
//! key stops authenticating at the boundary whether or not this job ever ran.
//! `secureprompt-api/tests/rls_api_key_grace_window.rs` pins that.
//!
//! What breaks when the sweep does not run is the RECORD, not the gate: the row
//! keeps `status = 'rotating'` and `revoked_at IS NULL` forever, so
//! `GET /v1/keys` shows a dead credential as never-revoked, and a second
//! `POST /v1/keys/{id}/rotate` on it takes `rotate`'s idempotent `'rotating'`
//! branch — returning `200 OK` with a `grace_expires_at` already in the past,
//! issuing no new key and writing NO admin-audit row.

use sqlx::PgPool;
use uuid::Uuid;

use crate::tasks::workspace_enumeration::enumerate_workspaces;

/// The sweep itself, run once per workspace with that workspace's scope armed.
///
/// The `workspace_id = $1` is NOT redundant with the policy and is not there
/// to be the isolation boundary either — it is there so the statement means the
/// same thing under both roles. Under a SUPERUSER the policy is bypassed and
/// the predicate is the only thing keeping one iteration from sweeping every
/// tenant's keys, which would make [`Outcome::keys_revoked`] count each row
/// once per workspace and turn the loop into an accidental O(n²) full-table
/// scan. Under the runner role the policy filters as well and the two agree.
///
/// `<= NOW()` is the exact complement of `authenticate_api_key`'s `> NOW()`.
/// Changing either without the other opens or closes the grace window by one
/// instant on one path only.
const SWEEP_SQL: &str = "UPDATE api_keys
     SET status = 'revoked', revoked_at = NOW()
     WHERE workspace_id = $1
       AND status = 'rotating'
       AND rotated_at + (rotation_grace_secs || ' seconds')::INTERVAL <= NOW()";

/// Message the per-workspace transaction fails with when the GUC did not take.
/// Same shape and the same reason as
/// `retention_purge::write_audit`'s constant and the API side's
/// `db::scope::SCOPE_NOT_ARMED`: an unarmed transaction must fail LOUDLY
/// rather than sweep nothing and report success.
const SCOPE_NOT_ARMED: &str =
    "the rotation-cleanup transaction could not be scoped to this workspace, so no key \
     was revoked in it";

/// What one sweep did, in enough detail that "nothing happened" and "nothing
/// needed to happen" are distinguishable by the caller.
#[derive(Debug, Default, Clone, Copy)]
pub struct Outcome {
    /// Rows moved to `status = 'revoked'`.
    pub keys_revoked: u64,
    /// Workspaces the enumeration returned — the CENSUS, and the denominator
    /// [`Outcome::all_ok`] measures `workspaces_swept` against.
    ///
    /// MR6 F2: without it, `all_ok()` was `failures == 0` and therefore
    /// VACUOUSLY TRUE over an empty enumeration. A policed `workspaces` makes
    /// the bare-pool `SELECT` answer `Ok(vec![])`, the loop runs zero times,
    /// nothing fails because nothing ran, and the cron records success on a
    /// night when every grace-expired key stayed live.
    pub enumerated: usize,
    /// Workspaces the sweep actually visited.
    pub workspaces_swept: usize,
    /// Per-workspace sweeps that returned an error. Non-zero makes
    /// [`Outcome::all_ok`] false, so the job records itself as FAILED rather
    /// than reporting success for a partial pass.
    pub failures: usize,
}

impl Outcome {
    /// Whether the job should record itself as successful.
    ///
    /// Both terms are load-bearing and neither subsumes the other.
    /// `failures == 0` catches a workspace that errored; `swept ==
    /// enumerated` catches a workspace that was skipped without erroring —
    /// which is the only shape an RLS failure takes, since a filtered read
    /// returns rows rather than an error.
    ///
    /// `enumerated == 0` is deliberately NOT a failure on its own: a genuinely
    /// empty deployment must not page anyone nightly. The blind case is caught
    /// upstream instead, by
    /// [`crate::tasks::workspace_enumeration::enumerate_workspaces`]'s
    /// `row_security_active` precondition, which turns "I could not see" into
    /// an error and so into `failures = 1` — a positive statement rather than
    /// an inference from a zero.
    #[must_use]
    pub fn all_ok(&self) -> bool {
        self.failures == 0 && self.workspaces_swept == self.enumerated
    }
}

/// Revoke every rotating API key whose grace window has closed, in every
/// workspace.
///
/// # Why a loop and not one statement, and why not a wider policy
///
/// The sweep is cross-tenant by design — it is one nightly job for the whole
/// deployment — but "cross-tenant" is not a reason to give the job a
/// cross-tenant VIEW of `api_keys`. Three options were on the table:
///
///   * A policy admitting the unarmed sweep (e.g. `USING (... OR
///     current_setting('app.rotation_sweep', true) = 'on')`). Rejected: that
///     GUC is settable by any holder of the same connection, so it turns one
///     forgotten `set_config` in unrelated code into a full cross-tenant read
///     of every workspace's key metadata. It widens the table's policy for
///     every statement in the process, not just this one.
///   * An elevated role for the worker (`BYPASSRLS`, or `SECURITY DEFINER`).
///     Rejected for the same reason at larger scale: it removes the boundary
///     from every query the worker makes, including ones written later by
///     someone who does not know the role is privileged.
///   * This: enumerate `workspaces` — which is NOT armed, so the enumeration
///     needs no privilege — and run the existing statement once per workspace
///     inside a scoped, read-back transaction. `retention_purge::write_audit`
///     adopted exactly this shape for exactly this reason.
///
/// WHAT AN ATTACKER GAINS: nothing that was not already reachable. No policy
/// is widened, no role is elevated, no new GUC is trusted, and the widest read
/// added is `SELECT id FROM workspaces` — a list of tenant UUIDs the worker
/// already obtains, and which `ApiKeyRepository::authenticate_api_key` already
/// reads on a bare pool for the same reason. Anyone who can run this code
/// already holds the worker's database credentials, which is strictly more
/// than the loop grants.
///
/// # Failure is per workspace and it is LOUD
///
/// One workspace erroring does not abort the others — a single bad tenant must
/// not leave every other tenant's keys unrevoked — but it does increment
/// `failures`, which makes `all_ok()` false and the cron record the job as
/// FAILED. The silent-success path this replaces is the whole defect.
pub async fn run(pg: &PgPool) -> Outcome {
    // `workspaces` is not under FORCE ROW LEVEL SECURITY (asserted as a
    // premise in this module's tests), so this enumeration needs no scope.
    //
    // MR6 F2 — that premise is now CHECKED rather than commented. This read
    // used to be a bare `SELECT id FROM workspaces`, under a comment claiming
    // that if a future migration armed the table "the tests here fail on
    // `workspaces_swept`". They did not: there was no such test, and
    // `workspaces_swept` was read by no production code — not by `all_ok()`,
    // not by `main.rs`, only by a `tracing::info!`. An armed `workspaces`
    // makes this answer `Ok(vec![])` with no error at all, so the check has to
    // be a positive one. `enumerate_workspaces` is shared with
    // `tasks::retention_purge`, which got this precondition in the MR that
    // left this function without it.
    let workspaces = match enumerate_workspaces(pg).await {
        Ok(ids) => ids,
        Err(e) => {
            tracing::error!(error = %e, "rotation cleanup could not enumerate workspaces");
            return Outcome {
                failures: 1,
                ..Outcome::default()
            };
        }
    };

    let mut outcome = Outcome {
        enumerated: workspaces.len(),
        ..Outcome::default()
    };
    for workspace_id in workspaces {
        match sweep_one(pg, workspace_id).await {
            Ok(revoked) => {
                outcome.keys_revoked += revoked;
                outcome.workspaces_swept += 1;
            }
            Err(e) => {
                outcome.failures += 1;
                tracing::error!(
                    error = %e,
                    workspace_id = %workspace_id,
                    "rotation cleanup failed for one workspace"
                );
            }
        }
    }
    outcome
}

/// One workspace's sweep, in a transaction armed to that workspace and READ
/// BACK before the UPDATE runs.
///
/// The read-back is the difference between this and the statement it replaces.
/// `set_config` succeeding does not prove the GUC holds the value the UPDATE
/// will be filtered by — and if it does not, the UPDATE matches zero rows and
/// returns `Ok(0)`, which is exactly the silent success this function exists
/// to make impossible.
async fn sweep_one(pg: &PgPool, workspace_id: Uuid) -> Result<u64, sqlx::Error> {
    let mut tx = pg.begin().await?;
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
        .bind(workspace_id.to_string())
        .execute(&mut *tx)
        .await?;
    let armed: Option<String> =
        sqlx::query_scalar("SELECT current_setting('app.current_workspace_id', true)")
            .fetch_one(&mut *tx)
            .await?;
    if armed.as_deref() != Some(workspace_id.to_string().as_str()) {
        return Err(sqlx::Error::Protocol(SCOPE_NOT_ARMED.to_owned()));
    }

    let done = sqlx::query(SWEEP_SQL)
        .bind(workspace_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(done.rows_affected())
}

#[cfg(test)]
mod tests;
