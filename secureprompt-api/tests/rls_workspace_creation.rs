//! Workspace creation driven through a NON-SUPERUSER, NOBYPASSRLS pool.
//!
//! # The keystone
//!
//! Every armed `workspace_isolation` policy in this schema is
//! `USING (workspace_id = current_setting('app.current_workspace_id', true)::uuid)`
//! with no separate `WITH CHECK`, so Postgres reuses the `USING` expression as
//! the write check. `WorkspaceRepository::create_with_owner` opens a plain
//! `pool.begin()` and inserts the seeded "Redact common PII" rule into
//! `policy_rules` — a table under FORCE ROW LEVEL SECURITY since
//! `001_init.sql:78-95` — with the GUC never set. The predicate is NULL, the
//! write check fails, and registration dies with
//!
//!     ERROR 42501: new row violates row-level security policy for table
//!                  "policy_rules"
//!
//! MEASURED, on this branch at `a193814`, by pointing `DATABASE_URL` at
//! `secureprompt_runner` and running `cargo test -p secureprompt-api --lib`:
//! 40 failures, every one of them that error. Three are
//! `db::workspace_repo::tests::*`; the rest are suites whose fixtures seed a
//! policy rule. It is invisible on an ordinary developer machine only because
//! the compose `secureprompt` role is a SUPERUSER (`rolsuper = t`,
//! `rolbypassrls = t`) and superusers bypass RLS unconditionally.
//!
//! This is the precondition for every other RLS control on this branch: until
//! the application can run as a role that does NOT bypass RLS, all sixteen
//! armed policies are decoration.
//!
//! # Why this suite builds its own pool instead of taking `DATABASE_URL`'s
//!
//! `#[sqlx::test]` connects as the role in `DATABASE_URL`. On a developer
//! machine and in the ordinary `test` CI job that role is a superuser, and a
//! superuser CANNOT observe this defect at all. A suite that only fails when
//! someone remembers to re-point `DATABASE_URL` is a suite that will go quiet.
//! So the tests below open a SECOND pool onto the same `#[sqlx::test]`
//! database as `secureprompt_runner` and assert that role's powerlessness on
//! the wire before making any claim — the same pattern, role and password as
//! `tests/rls_repo_scope.rs`, `tests/migration_020_rls.rs` and
//! `tests/migration_017_023_rls.rs`, and as
//! `scripts/ci/create-nonsuperuser-role.sh`. That makes these tests fail under
//! BOTH roles, which is the only version of this gate that stays honest.

use secureprompt_api::db::scope::begin_scoped;
use secureprompt_api::db::user_repo::hash_password;
use secureprompt_api::db::workspace_repo::WorkspaceRepository;
use secureprompt_common::errors::ApiError;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgPool, Row};
use uuid::Uuid;

const RLS_ROLE: &str = "secureprompt_runner";
const RLS_PASSWORD: &str = "secureprompt";

/// `(rowsecurity, forcerowsecurity)` straight out of the catalog.
///
/// PREMISE for every test here: if `policy_rules` were not armed, the
/// low-privilege pool would write and read it freely and each assertion below
/// would pass while measuring nothing.
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

/// The low-privilege pool's ceiling, named because
/// `the_creating_scope_does_not_outlive_the_transaction` acquires exactly this
/// many connections at once to make its probe exhaustive rather than lucky.
const LOW_POOL_MAX_CONNECTIONS: u32 = 4;

/// A POOL onto the same `#[sqlx::test]` database as `RLS_ROLE`, with the
/// role's powerlessness asserted ON THE WIRE.
///
/// A POOL rather than one connection, deliberately: `set_config(..., true)` is
/// transaction-local and a pool hands successive statements to different
/// connections, so a fix that armed the scope outside the inserting
/// transaction would pass a single-connection test and fail here.
async fn low_privilege_pool(pool: &PgPool) -> PgPool {
    ensure_low_privilege_role(pool).await;

    let options: PgConnectOptions = (*pool.connect_options())
        .clone()
        .username(RLS_ROLE)
        .password(RLS_PASSWORD);

    let low = PgPoolOptions::new()
        .max_connections(LOW_POOL_MAX_CONNECTIONS)
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

/// Read the seeded rule names for a workspace THROUGH AN ARMED SCOPE.
///
/// Deliberately not a bare `SELECT ... WHERE workspace_id = $1` on the pool:
/// that reads correctly as superuser and returns the empty set as
/// `secureprompt_runner`, so it would report "no rule was seeded" for both the
/// broken and the fixed code under one role and neither under the other.
async fn rule_names_in_scope(pool: &PgPool, workspace_id: Uuid) -> Vec<String> {
    let mut tx = begin_scoped(pool, workspace_id)
        .await
        .expect("an armed scope on the workspace under test");
    let names: Vec<String> = sqlx::query_scalar("SELECT name FROM policy_rules ORDER BY name ASC")
        .fetch_all(&mut *tx)
        .await
        .expect("scoped read of policy_rules");
    names
}

// ===========================================================================
// The keystone
// ===========================================================================

/// THE HEADLINE. Registering a workspace must succeed when the connecting role
/// cannot bypass row-level security, and the seeded default redaction rule
/// must actually land.
///
/// DELETION CHECK: remove the `arm_scope` call from
/// `WorkspaceRepository::create_with_owner` and this test fails with
/// `new row violates row-level security policy for table "policy_rules"`.
#[sqlx::test]
async fn create_with_owner_seeds_the_default_rule_under_a_non_bypassing_role(pool: PgPool) {
    assert_eq!(
        rls_flags(&pool, "policy_rules").await,
        (true, true),
        "premise: 001_init.sql must have armed policy_rules with ENABLE + \
         FORCE, or the low-privilege pool writes it freely and this test \
         measures nothing"
    );

    let low = low_privilege_pool(&pool).await;
    let repo = WorkspaceRepository::new(low.clone());
    let hash = hash_password("pw-for-test-only").expect("argon2 hash");

    let (ws, user) = repo
        .create_with_owner("Runner Role Co", "owner@runner.example", &hash)
        .await
        .expect(
            "registration must survive a role that does not bypass RLS. The \
             failure here is `new row violates row-level security policy for \
             table \"policy_rules\"`: the seeded rule is inserted before any \
             tenancy scope exists for the workspace being created.",
        );

    assert_eq!(user.workspace_id, ws.id);

    // The rule is on disk and belongs to the new workspace. Read through an
    // armed scope on the LOW pool, so the assertion is about the row and about
    // RLS admitting it, not about a superuser reading past the policy.
    assert_eq!(
        rule_names_in_scope(&low, ws.id).await,
        vec!["Redact common PII".to_owned()],
        "the seeded rule is what stops a brand-new workspace forwarding raw \
         PII upstream. An empty vec here means registration reported success \
         and left the workspace with zero rules."
    );
}

/// NEGATIVE CONTROL, and the reason the fix must be transaction-local.
///
/// Arming the creating transaction must not leave `app.current_workspace_id`
/// set on the pooled connection it borrowed. If it did, the NEXT unrelated
/// statement to be handed that connection would silently inherit a foreign
/// tenant's scope — turning a fix for a write rejection into a cross-tenant
/// read.
#[sqlx::test]
async fn the_creating_scope_does_not_outlive_the_transaction(pool: PgPool) {
    let low = low_privilege_pool(&pool).await;
    let repo = WorkspaceRepository::new(low.clone());
    let hash = hash_password("pw-for-test-only").expect("argon2 hash");

    let (ws, _) = repo
        .create_with_owner("Leak Check Co", "owner@leak.example", &hash)
        .await
        .expect("registration must succeed");

    // PREMISE: the row really is there when the scope IS armed, so the empty
    // read below is about the scope and not about an absent row.
    assert_eq!(
        rule_names_in_scope(&low, ws.id).await,
        vec!["Redact common PII".to_owned()],
        "premise: the seeded rule must exist"
    );

    // MR5 M-3: this used to be eight `fetch_one(&low)` probes and a comment
    // saying `min_connections(2)` "makes it very unlikely we only ever probe a
    // connection the creating transaction never touched". Unlikely is not a
    // control. A regression to a session-level `set_config(..., false)` had a
    // real chance of passing, and a test that can pass by luck against the
    // defect it names is the shape this suite exists to refuse.
    //
    // Deterministic instead: hold EVERY connection the pool can hand out, at
    // the same time, and probe each one. The connection the creating
    // transaction borrowed was returned to this pool and cannot have escaped
    // it, so it is necessarily among them.
    let mut held = Vec::new();
    for slot in 0..LOW_POOL_MAX_CONNECTIONS {
        held.push(
            low.acquire()
                .await
                .unwrap_or_else(|e| panic!("holding pool connection {slot}: {e}")),
        );
    }

    // PREMISE, and the one the old loop could not make: at least one held
    // connection must show that it SERVED the creating transaction. Postgres
    // resets a committed `SET LOCAL` custom GUC to the EMPTY STRING rather than
    // unsetting it, so `Some("")` is the fingerprint of a connection that has
    // run a scoped transaction. Without this, every probe below could be
    // reading connections the transaction never touched and the whole test
    // would be about nothing.
    let mut states: Vec<Option<String>> = Vec::new();
    for conn in &mut held {
        states.push(
            sqlx::query_scalar("SELECT current_setting('app.current_workspace_id', true)")
                .fetch_one(&mut **conn)
                .await
                .expect("GUC fingerprint probe"),
        );
    }
    assert!(
        states.iter().any(|s| s.as_deref() == Some("")),
        "premise: none of the {} held connections had ever served a scoped \
         transaction (states {states:?}), so the leak probes below would be \
         reading connections `create_with_owner` never borrowed",
        held.len()
    );

    for (probe, conn) in held.iter_mut().enumerate() {
        let leaked: Option<String> =
            sqlx::query_scalar("SELECT current_setting('app.current_workspace_id', true)")
                .fetch_one(&mut **conn)
                .await
                .expect("GUC probe");
        assert_ne!(
            leaked.as_deref(),
            Some(ws.id.to_string().as_str()),
            "probe {probe}: app.current_workspace_id still names the workspace \
             the creating transaction made. `set_config(..., true)` is \
             required — a session-level `false` leaves that scope on the \
             pooled connection for whatever statement is handed it next, which \
             would turn this fix into a cross-tenant read."
        );

        // MEASURED, and worth stating because it is not what one expects:
        // Postgres does not UNSET a `SET LOCAL` custom GUC at COMMIT, it resets
        // it to the EMPTY STRING. (`psql`: `[<NULL>]` before, `[]` after both
        // COMMIT and ROLLBACK.) So on a connection that has served at least one
        // scoped transaction, `current_setting('app.current_workspace_id',
        // true)::uuid` is `''::uuid` and an unscoped query on an armed table
        // raises `22P02 invalid input syntax for type uuid: ""` instead of
        // silently returning the empty set.
        //
        // That is the LOUD half of the failure mode `db::scope`'s header
        // describes, and it is why both branches are accepted here — what must
        // never happen is the third possibility, the row coming back.
        // On the SAME held connection — going back to `&low` here would
        // deadlock, since this loop owns every connection the pool has.
        let unscoped: Result<Vec<String>, sqlx::Error> =
            sqlx::query_scalar("SELECT name FROM policy_rules WHERE workspace_id = $1")
                .bind(ws.id)
                .fetch_all(&mut **conn)
                .await;

        match unscoped {
            Ok(names) => assert!(
                names.is_empty(),
                "probe {probe}: an UNSCOPED read on a non-bypassing role \
                 returned {names:?}. RLS is not filtering this pool and every \
                 other assertion in this file is vacuous."
            ),
            Err(e) => {
                let text = e.to_string();
                assert!(
                    text.contains("invalid input syntax for type uuid"),
                    "probe {probe}: the unscoped read failed for a reason other \
                     than the reset-to-empty-string GUC: {text}"
                );
            }
        }
    }
}

/// The rollback guarantee `create_with_owner` exists for, re-proved under the
/// role that will actually run it. Arming the scope adds a statement to the
/// transaction; a fix that armed it in a SEPARATE transaction would leave the
/// workspace row committed when the users insert conflicts.
#[sqlx::test]
async fn a_conflicting_registration_leaves_no_workspace_behind(pool: PgPool) {
    let low = low_privilege_pool(&pool).await;
    let repo = WorkspaceRepository::new(low.clone());
    let hash = hash_password("pw-for-test-only").expect("argon2 hash");

    repo.create_with_owner("First Co", "dup@runner.example", &hash)
        .await
        .expect("first registration must succeed");

    let before = repo
        .list_workspace_ids()
        .await
        .expect("workspaces is not RLS-armed, so this read is scope-free")
        .len();
    assert_eq!(before, 1, "premise: exactly one workspace so far");

    let err = repo
        .create_with_owner("Second Co", "dup@runner.example", &hash)
        .await
        .expect_err("a duplicate email must be refused");
    assert!(
        matches!(err, ApiError::Conflict(_)),
        "expected Conflict, got {err:?}"
    );

    assert_eq!(
        repo.list_workspace_ids()
            .await
            .expect("workspace listing")
            .len(),
        before,
        "the failed registration orphaned a workspace row — the whole reason \
         create_with_owner is one transaction"
    );
}
