//! The rotation-cleanup sweep, driven through a NON-SUPERUSER, NOBYPASSRLS
//! pool — the role the deployment gets the day the role-split lands.
//!
//! # The failure being measured
//!
//! `api_keys` has been under FORCE ROW LEVEL SECURITY since `001_init.sql:78`
//! with `workspace_isolation ... USING (workspace_id = current_setting(
//! 'app.current_workspace_id', true)::uuid)`. With the GUC unset that predicate
//! is NULL for every row, and a `USING` clause filters UPDATE the same way it
//! filters SELECT.
//!
//! MEASURED on this branch, `SET ROLE secureprompt_runner`, migration-031
//! schema, one grace-expired `'rotating'` row present:
//!
//! ```text
//! unarmed  UPDATE api_keys SET status='revoked' ... -> UPDATE 0   (no error)
//! armed    UPDATE api_keys SET status='revoked' ... -> UPDATE 1
//! ```
//!
//! `UPDATE 0` with no error is the whole problem. Unlike an INSERT — which is
//! refused with `42501` and gets fixed within the hour — an UPDATE that matches
//! nothing is indistinguishable from an UPDATE that had nothing to do, so the
//! cron logs `rows_affected=0`, records `record_job(..., ok = true)`, and the
//! sweep is a permanent no-op that reports success.
//!
//! # What this suite does NOT claim
//!
//! It does not claim the stale key still authenticates. It does not:
//! `authenticate_api_key` re-derives the grace boundary itself, and
//! `secureprompt-api/tests/rls_api_key_grace_window.rs` measures that
//! separately. What rots here is the RECORD — `status` and `revoked_at` — and
//! everything downstream that reads them.
//!
//! # The absence-assertion rule this suite obeys
//!
//! Every read-back ARMS the scope to the row's own workspace before looking.
//! A bare read would return "no row" under the runner role whether the sweep
//! ran or not, which is exactly the ambiguity this file exists to avoid — and
//! it would make the suite behave differently under the two roles the
//! `test:rls-nonsuperuser` job requires it to pass under. `key_state` returns
//! an `Option` and every caller unwraps it with a message, so "the row is
//! invisible" can never be read as "the row is unrevoked".
//!
//! All fixture key material is synthetic and never hashes to a real key.

use super::*;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Same role, password and creation attributes as
/// `scripts/ci/create-nonsuperuser-role.sh` and the API crate's RLS suites.
const RLS_ROLE: &str = "secureprompt_runner";
const RLS_PASSWORD: &str = "secureprompt";

/// One workspace with one API key in it.
struct Seeded {
    workspace_id: Uuid,
    key_id: Uuid,
}

/// Insert a workspace and one `'rotating'` key whose grace window closed
/// `rotated_days_ago - grace` ago (negative = still inside the window).
///
/// `workspaces` is NOT under FORCE ROW LEVEL SECURITY (checked against
/// `pg_class.relforcerowsecurity` in the premise below), so its INSERT needs no
/// scope. `api_keys` IS, so its INSERT is armed — otherwise this fixture would
/// fail with `42501` under the runner role and the suite could not run at all.
async fn seed(pool: &PgPool, label: &str, rotated_ago: &str, grace_secs: i32) -> Seeded {
    let workspace_id = Uuid::new_v4();
    sqlx::query("INSERT INTO workspaces (id, name) VALUES ($1, $2)")
        .bind(workspace_id)
        .bind(format!("Rotation Sweep {label}"))
        .execute(pool)
        .await
        .expect("workspace insert");

    let key_id = Uuid::new_v4();
    let mut tx = pool.begin().await.expect("fixture transaction");
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
        .bind(workspace_id.to_string())
        .execute(&mut *tx)
        .await
        .expect("arm the fixture scope");
    sqlx::query(
        "INSERT INTO api_keys
             (id, workspace_id, name, key_hash, created_at,
              status, rotated_at, rotation_grace_secs)
         VALUES ($1, $2, $3, $4, NOW(),
                 'rotating', NOW() - $5::INTERVAL, $6)",
    )
    .bind(key_id)
    .bind(workspace_id)
    .bind(format!("key-{label}"))
    .bind(format!("synthetic-hash-{}", Uuid::new_v4().simple()))
    .bind(rotated_ago)
    .bind(grace_secs)
    .execute(&mut *tx)
    .await
    .expect("api_keys insert must be armed, or the fixture itself is the bug");
    tx.commit().await.expect("fixture commit");

    Seeded {
        workspace_id,
        key_id,
    }
}

/// `(status, revoked_at IS NULL)` for one key, read from a scope that WOULD
/// see it.
///
/// `None` means the row was genuinely not visible even with the scope armed —
/// which is a broken premise, never an answer about revocation. Callers must
/// treat it as a failure.
async fn key_state(pool: &PgPool, seeded: &Seeded) -> Option<(String, bool)> {
    let mut tx = pool.begin().await.expect("read-back transaction");
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
        .bind(seeded.workspace_id.to_string())
        .execute(&mut *tx)
        .await
        .expect("arm the read-back scope");
    let row = sqlx::query("SELECT status, revoked_at IS NULL AS never FROM api_keys WHERE id = $1")
        .bind(seeded.key_id)
        .fetch_optional(&mut *tx)
        .await
        .expect("read-back query");
    tx.commit().await.expect("read-back commit");
    row.map(|r| (r.get("status"), r.get("never")))
}

/// `(relrowsecurity, relforcerowsecurity)` straight out of the catalog.
async fn rls_flags(pool: &PgPool, table: &str) -> (bool, bool) {
    let row = sqlx::query(
        "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = to_regclass($1)",
    )
    .bind(format!("public.{table}"))
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("{table} must exist to be probed: {e}"));
    (row.get("relrowsecurity"), row.get("relforcerowsecurity"))
}

/// Create `secureprompt_runner` if absent and grant it this test database.
/// Idempotent and concurrency-safe: roles are cluster-global while
/// `#[sqlx::test]` databases are per-test, so several tests race here.
async fn ensure_low_privilege_role(pool: &PgPool) {
    sqlx::raw_sql(&format!(
        "DO $$
         BEGIN
             CREATE ROLE {RLS_ROLE}
                 LOGIN PASSWORD '{RLS_PASSWORD}'
                 NOSUPERUSER CREATEDB CREATEROLE NOBYPASSRLS;
         EXCEPTION
             WHEN duplicate_object THEN NULL;
             WHEN unique_violation THEN NULL;
         END $$;"
    ))
    .execute(pool)
    .await
    .unwrap_or_else(|e| {
        panic!(
            "could not create the {RLS_ROLE} role ({e}). In CI this role is \
             created by scripts/ci/create-nonsuperuser-role.sh; locally the \
             connecting role needs CREATEROLE. This suite refuses to fall back \
             to the superuser pool, because a superuser bypasses RLS and would \
             make every assertion below vacuous."
        )
    });

    sqlx::raw_sql(&format!(
        "GRANT USAGE ON SCHEMA public TO {RLS_ROLE};
         GRANT ALL ON ALL TABLES IN SCHEMA public TO {RLS_ROLE};
         GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO {RLS_ROLE};"
    ))
    .execute(pool)
    .await
    .expect("grants on the test database");
}

/// A POOL onto the same `#[sqlx::test]` database as `RLS_ROLE`, with the
/// role's powerlessness asserted ON THE WIRE.
///
/// A POOL rather than a connection, deliberately: `set_config(..., true)` is
/// transaction-local and a pool hands successive statements to different
/// connections, so a sweep that armed the scope on one checkout and updated on
/// another fails here and would pass a single-connection test.
async fn low_privilege_pool(pool: &PgPool) -> PgPool {
    ensure_low_privilege_role(pool).await;

    let options: PgConnectOptions = (*pool.connect_options())
        .clone()
        .username(RLS_ROLE)
        .password(RLS_PASSWORD);

    let low = PgPoolOptions::new()
        .max_connections(4)
        .min_connections(2)
        .connect_with(options)
        .await
        .expect("low-privilege pool onto the test database");

    let row = sqlx::query(
        "SELECT current_user::text AS who, rolsuper, rolbypassrls, \
         row_security_active('api_keys') AS enforced \
         FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&low)
    .await
    .expect("identity probe");

    let who: String = row.get("who");
    assert_eq!(who, RLS_ROLE, "premise: connected as the wrong role");
    assert!(
        !row.get::<bool, _>("rolsuper"),
        "premise: {who} is a SUPERUSER, so it bypasses RLS and this suite proves nothing"
    );
    assert!(
        !row.get::<bool, _>("rolbypassrls"),
        "premise: {who} has BYPASSRLS, so it bypasses RLS and this suite proves nothing"
    );
    // The two flags above are role ATTRIBUTES; this is Postgres answering
    // whether the policy will actually bind THIS connection on THIS table.
    assert!(
        row.get::<bool, _>("enforced"),
        "premise: row security is not active on api_keys for {who}, so the \
         sweep below runs unfiltered and measures nothing"
    );

    low
}

/// Premises shared by every test here, asserted once per test rather than in a
/// helper that a future edit could stop calling.
async fn assert_table_is_armed(pool: &PgPool) {
    assert_eq!(
        rls_flags(pool, "api_keys").await,
        (true, true),
        "premise: 001_init.sql arms api_keys with ENABLE + FORCE ROW LEVEL \
         SECURITY. Unarmed, the low-privilege pool writes everything and this \
         suite measures nothing."
    );
    assert_eq!(
        rls_flags(pool, "workspaces").await,
        (false, false),
        "premise: workspaces is NOT armed, which is why the sweep may \
         enumerate it on a bare pool and why the fixture's workspace INSERT \
         needs no scope. If a migration arms it, both need revisiting."
    );
}

// ===========================================================================
// The sweep
// ===========================================================================

/// THE DEFECT. A key whose grace window closed must end the sweep as
/// `'revoked'` with `revoked_at` stamped.
///
/// The in-grace key in the same workspace is the POSITIVE CONTROL that must
/// DIFFER: without it, a sweep that revoked every key in the table — or a
/// fixture that seeded them revoked — would pass this test.
#[sqlx::test(migrations = "../secureprompt-api/migrations")]
async fn grace_expired_keys_are_revoked_under_a_non_bypassing_role(pool: PgPool) {
    assert_table_is_armed(&pool).await;

    // 86_400s grace, rotated 10 days ago -> 9 days past the boundary.
    let stale = seed(&pool, "Stale", "10 days", 86_400).await;
    // Same grace, rotated a minute ago -> firmly inside the window.
    let fresh = seed(&pool, "Fresh", "1 minute", 86_400).await;

    // PREMISE: both rows exist and are UNREVOKED before the sweep. Without
    // this, a `'revoked'` afterwards could be the fixture's doing, and a
    // missing row could be read as a passing absence.
    assert_eq!(
        key_state(&pool, &stale).await,
        Some(("rotating".to_owned(), true)),
        "premise: the grace-expired fixture must start rotating and unrevoked"
    );
    assert_eq!(
        key_state(&pool, &fresh).await,
        Some(("rotating".to_owned(), true)),
        "premise: the in-grace fixture must start rotating and unrevoked"
    );

    let low = low_privilege_pool(&pool).await;
    let outcome = run(&low).await;

    assert!(
        outcome.all_ok(),
        "the sweep reported a failure: {outcome:?}. Under RLS this job's \
         failure mode is silence, not an error, so an error here is a \
         different bug."
    );
    assert_eq!(
        outcome.keys_revoked, 1,
        "the sweep reported {} keys revoked. Zero is the RLS failure this \
         suite exists to catch: the UPDATE matched nothing, did not error, and \
         the job recorded itself as successful.",
        outcome.keys_revoked
    );

    assert_eq!(
        key_state(&pool, &stale).await,
        Some(("revoked".to_owned(), false)),
        "the grace-expired key is still `rotating` with revoked_at NULL. \
         GET /v1/keys will show a dead credential as never-revoked, and a \
         re-rotation of it takes ApiKeyRepository::rotate's idempotent branch \
         forever: 200 OK, grace_expires_at in the past, no new key, no audit \
         row."
    );

    // POSITIVE CONTROL. Must DIFFER from the row above.
    assert_eq!(
        key_state(&pool, &fresh).await,
        Some(("rotating".to_owned(), true)),
        "the sweep revoked a key that is still inside its grace window. That \
         is the other direction of the same bug — a rotation that breaks the \
         caller it was supposed to protect."
    );
}

/// THE SWEEP IS CROSS-TENANT BY DESIGN. It is one nightly job for the whole
/// deployment, so a fix that arms a single workspace and stops — the obvious
/// wrong shape — must fail here.
///
/// Two workspaces, one grace-expired key in each, and BOTH must be revoked by
/// ONE call.
#[sqlx::test(migrations = "../secureprompt-api/migrations")]
async fn the_sweep_reaches_every_workspace(pool: PgPool) {
    assert_table_is_armed(&pool).await;

    let first = seed(&pool, "Tenant A", "3 days", 86_400).await;
    let second = seed(&pool, "Tenant B", "3 days", 86_400).await;
    assert_ne!(
        first.workspace_id, second.workspace_id,
        "premise: the two fixtures must be in DIFFERENT workspaces, or this \
         test cannot tell a one-workspace sweep from a complete one"
    );

    for (label, seeded) in [("A", &first), ("B", &second)] {
        assert_eq!(
            key_state(&pool, seeded).await,
            Some(("rotating".to_owned(), true)),
            "premise: tenant {label}'s key must start rotating and unrevoked"
        );
    }

    let low = low_privilege_pool(&pool).await;
    let outcome = run(&low).await;

    assert!(
        outcome.all_ok(),
        "the sweep reported a failure: {outcome:?}"
    );
    assert_eq!(
        outcome.keys_revoked, 2,
        "the sweep revoked {} of 2 grace-expired keys across 2 workspaces. \
         One means it armed a single scope and stopped; zero means it armed \
         none.",
        outcome.keys_revoked
    );

    for (label, seeded) in [("A", &first), ("B", &second)] {
        assert_eq!(
            key_state(&pool, seeded).await,
            Some(("revoked".to_owned(), false)),
            "tenant {label}'s grace-expired key survived the sweep"
        );
    }
}

/// NEGATIVE CONTROL for the sweep's predicate, and for `keys_revoked` as a
/// number rather than a boolean: a deployment with nothing to do must report
/// ZERO revoked and still succeed. Without this, `keys_revoked` could be a
/// count of rows LOOKED at and the two tests above would not notice.
#[sqlx::test(migrations = "../secureprompt-api/migrations")]
async fn a_sweep_with_nothing_to_do_revokes_nothing(pool: PgPool) {
    assert_table_is_armed(&pool).await;

    let fresh = seed(&pool, "Only Fresh", "1 minute", 86_400).await;
    assert_eq!(
        key_state(&pool, &fresh).await,
        Some(("rotating".to_owned(), true)),
        "premise: the only key present must be rotating and inside its window"
    );

    let low = low_privilege_pool(&pool).await;
    let outcome = run(&low).await;

    assert!(
        outcome.all_ok(),
        "the sweep reported a failure: {outcome:?}"
    );
    assert_eq!(
        outcome.keys_revoked, 0,
        "the sweep claims to have revoked {} keys when none were eligible",
        outcome.keys_revoked
    );
    assert_eq!(
        key_state(&pool, &fresh).await,
        Some(("rotating".to_owned(), true)),
        "the in-grace key was revoked by a sweep that had nothing to do"
    );
}
