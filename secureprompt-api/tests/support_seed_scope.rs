//! MR1 review M4 — the shared test seeds must arm tenancy for real, not
//! decoratively.
//!
//! # What M4 found
//!
//! `tests/support/mod.rs` opened `seed_provider_and_model` and
//! `seed_policy_rule` with
//!
//! ```text
//! sqlx::query("SELECT set_config('app.current_workspace_id', $1, false)")
//!     .execute(pool)
//! ```
//!
//! which is wrong twice over. `.execute(pool)` takes its own checkout, so the
//! setting was never in scope for the INSERTs that followed; and `false` is
//! `is_local = false`, so had it landed on the right connection it would have
//! outlived the statement and leaked the workspace id onto the next checkout.
//! `seed_workspace` had no scoping at all, despite `api_keys` being ENABLE +
//! FORCE row-level-security since `001_init.sql`.
//!
//! None of that changed a single test result, because `#[sqlx::test]` connects
//! as the role `DATABASE_URL` names and for the compose stack that role is a
//! SUPERUSER, which bypasses RLS including FORCE. That is precisely why it
//! survived review: it was a comment-shaped claim ("this seed is RLS-aware")
//! with nothing behind it, in a file every dashboard suite depends on.
//!
//! # Why this file exists rather than an assertion in an existing suite
//!
//! The defect is INVISIBLE from a superuser connection. Any test that runs on
//! `#[sqlx::test]`'s own pool passes identically before and after the fix, so
//! it can pin nothing. The only way to make the seeds' scoping observable is
//! to run them as a role that RLS actually applies to — which is also the
//! configuration the DB role split (migration 034, `--migrate-only`) makes
//! supported, and therefore the configuration in which the old seeds would
//! have started failing.
//!
//! # Falsifier
//!
//! Revert any of the three helpers in `tests/support/mod.rs` to the pooled,
//! session-scoped shape above — or simply drop its `begin_scoped` and use
//! `.execute(pool)` — and the corresponding assertion below fails with
//! `new row violates row-level security policy`. Measured; see the commit
//! message.

mod support;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Same role and password `tests/rls_repo_scope.rs` uses, and the same one
/// `scripts/ci/create-nonsuperuser-role.sh` creates in CI. Deliberately shared:
/// a second bespoke role would be a second thing to keep granted.
const RLS_ROLE: &str = "secureprompt_runner";
const RLS_PASSWORD: &str = "secureprompt";

/// Create `secureprompt_runner` if absent and grant it this test database.
/// Idempotent and concurrency-safe: roles are cluster-global while
/// `#[sqlx::test]` databases are per-test, so several tests race here.
async fn ensure_low_privilege_role(pool: &PgPool) {
    sqlx::raw_sql(&format!(
        "DO $$
         BEGIN
             CREATE ROLE {RLS_ROLE}
                 LOGIN PASSWORD '{RLS_PASSWORD}'
                 NOSUPERUSER NOBYPASSRLS;
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

/// A pool onto the same `#[sqlx::test]` database as `RLS_ROLE`, with the
/// role's powerlessness asserted ON THE WIRE.
///
/// `min_connections(2)` is load-bearing: with more than one connection open, a
/// seed that armed the scope OUTSIDE its transaction has a real chance of
/// running its INSERT on a different checkout — which is the exact defect M4
/// reported, and it must be able to surface here.
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
        "SELECT current_user::text AS who, rolsuper, rolbypassrls
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

    low
}

/// PREMISE. If these three tables are not armed, every assertion below is
/// satisfied by nothing happening. Asserted rather than assumed because the
/// arming lives in migrations that a later migration could change.
#[sqlx::test]
async fn the_seeded_tables_are_actually_rls_armed(pool: PgPool) {
    for table in ["api_keys", "providers", "models", "policy_rules"] {
        let row = sqlx::query(
            "SELECT c.relrowsecurity, c.relforcerowsecurity
               FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname = 'public' AND c.relname = $1",
        )
        .bind(table)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("{table} must exist to be probed: {e}"));

        assert!(
            row.get::<bool, _>("relrowsecurity"),
            "{table} has RLS disabled — the seed-scope suite would prove nothing"
        );
        assert!(
            row.get::<bool, _>("relforcerowsecurity"),
            "{table} is not FORCEd — the table owner would still bypass the policy"
        );
    }
}

/// THE PIN.
///
/// Runs the three shared seed helpers through a NOSUPERUSER/NOBYPASSRLS pool.
/// Each INSERT they issue targets a FORCE-RLS table whose
/// `workspace_isolation` policy is
/// `workspace_id = current_setting('app.current_workspace_id', true)::uuid`,
/// so with the GUC unset — which is what `.execute(pool)` on a separate
/// checkout leaves behind — Postgres rejects the write outright:
/// `new row violates row-level security policy for table "..."`.
///
/// Reads back afterwards, because a write that lands is only half the claim:
/// under the correct scope the rows must also be visible to a scoped read, and
/// under no scope they must not.
#[sqlx::test]
async fn the_shared_seeds_write_through_row_level_security(pool: PgPool) {
    let low = low_privilege_pool(&pool).await;

    let workspace_id = Uuid::new_v4();
    let provider_id = Uuid::new_v4();

    support::seed_workspace(&low, workspace_id, "sk-seed-scope-probe")
        .await
        .expect(
            "seed_workspace must write api_keys under RLS — it inserts into a FORCE-RLS \
             table and had no scoping at all before MR1 review M4",
        );

    support::seed_provider_and_model(
        &low,
        workspace_id,
        provider_id,
        "seed-scope-provider",
        "openai",
        Some("enc:seed-scope"),
        "gpt-4o-mini",
    )
    .await
    .expect(
        "seed_provider_and_model must write providers + models under RLS — its \
         `set_config(..., false)` ran on a DIFFERENT pool checkout from the INSERTs",
    );

    support::seed_policy_rule(
        &low,
        workspace_id,
        "seed-scope-rule",
        10,
        serde_json::json!([]),
        "redact",
        serde_json::json!({}),
        false,
    )
    .await
    .expect("seed_policy_rule must write policy_rules under RLS — same defect as above");

    // The rows must be READABLE under the matching scope...
    let mut tx = low.begin().await.expect("scoped read tx");
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
        .bind(workspace_id.to_string())
        .execute(&mut *tx)
        .await
        .expect("arm scope for read-back");

    for (table, expected) in [
        ("api_keys", 1i64),
        ("providers", 1),
        ("models", 1),
        ("policy_rules", 1),
    ] {
        let n: i64 = sqlx::query_scalar(&format!(
            "SELECT count(*) FROM {table} WHERE workspace_id = $1"
        ))
        .bind(workspace_id)
        .fetch_one(&mut *tx)
        .await
        .unwrap_or_else(|e| panic!("scoped count on {table}: {e}"));
        assert_eq!(
            n, expected,
            "{table} should hold {expected} seeded row(s) for this workspace"
        );
    }
    tx.rollback().await.expect("rollback read tx");

    // ...and INVISIBLE with no scope armed. This is the negative control: it
    // rules out "RLS is off and the counts above were free".
    let unscoped: i64 =
        sqlx::query_scalar("SELECT count(*) FROM providers WHERE workspace_id = $1")
            .bind(workspace_id)
            .fetch_one(&low)
            .await
            .expect("unscoped count");
    assert_eq!(
        unscoped, 0,
        "an unarmed connection saw the seeded provider — RLS is not applying to \
         {RLS_ROLE} and every assertion above was vacuous"
    );
}
