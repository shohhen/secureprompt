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

/// The sweep itself. One copy, so the test and the cron cannot drift.
///
/// `<= NOW()` is the exact complement of `authenticate_api_key`'s `> NOW()`.
/// Changing either without the other opens or closes the grace window by one
/// instant on one path only.
const SWEEP_SQL: &str = "UPDATE api_keys
     SET status = 'revoked', revoked_at = NOW()
     WHERE status = 'rotating'
       AND rotated_at + (rotation_grace_secs || ' seconds')::INTERVAL <= NOW()";

/// What one sweep did, in enough detail that "nothing happened" and "nothing
/// needed to happen" are distinguishable by the caller.
#[derive(Debug, Default, Clone, Copy)]
pub struct Outcome {
    /// Rows moved to `status = 'revoked'`.
    pub keys_revoked: u64,
    /// Sweeps that returned an error.
    pub failures: usize,
}

impl Outcome {
    /// Whether the job should record itself as successful.
    #[must_use]
    pub fn all_ok(&self) -> bool {
        self.failures == 0
    }
}

/// Revoke every rotating API key whose grace window has closed.
pub async fn run(pg: &PgPool) -> Outcome {
    match sqlx::query(SWEEP_SQL).execute(pg).await {
        Ok(done) => Outcome {
            keys_revoked: done.rows_affected(),
            failures: 0,
        },
        Err(e) => {
            tracing::error!(error = %e, "rotation cleanup failed");
            Outcome {
                keys_revoked: 0,
                failures: 1,
            }
        }
    }
}

#[cfg(test)]
mod tests;
