//! WS1-P0 — the Postgres role split: a migration/owner role that holds DDL and
//! table ownership, and a runtime role that holds neither.
//!
//! # Why the split exists
//!
//! `postgres:16` creates `POSTGRES_USER` as a SUPERUSER, and superusers bypass
//! row-level security unconditionally. The compose stack used that one role for
//! migrations AND for serving, so the sixteen armed RLS policies on this schema
//! were inert at runtime. The runtime role is `secureprompt_app` — declared in
//! `001_init.sql` since the beginning, never actually connected with.
//!
//! # What these tests pin, and why each one is not vacuous
//!
//! Two of the assertions here are about PRIVILEGE, not about rows, so unlike the
//! `rls_*` suites they do not need a non-superuser connection to be meaningful:
//! `has_table_privilege('secureprompt_app', ...)` asks the catalog about a role
//! the test is not connected as. The one test that does need a real connection
//! — `the_runtime_role_cannot_create_objects_in_the_public_schema` — opens one
//! and asserts its powerlessness on the wire first, because a test that
//! accidentally ran as the superuser would report the opposite of the truth.
//!
//! The load-bearing test is
//! `a_table_created_after_the_grants_is_still_reachable_by_the_runtime_role`.
//! Every migration that creates a table re-issues
//! `GRANT ... ON ALL TABLES IN SCHEMA public TO secureprompt_app`, which covers
//! the past but not the future: the day someone adds a migration without that
//! trailing GRANT, the application silently loses access to the new table.
//! `ALTER DEFAULT PRIVILEGES` is what closes that, and it is what this test
//! measures.

use secureprompt_api::db::migrations::{ensure_pg_migrations, MIGRATOR};
use sqlx::postgres::{PgConnectOptions, PgConnection, PgPoolOptions};
use sqlx::{Connection, PgPool, Row};

/// The runtime role. Created by `001_init.sql`; granted, constrained and
/// asserted-powerless by `034_app_role_runtime_grants.sql`.
const APP_ROLE: &str = "secureprompt_app";

/// Password used only to open a probe connection from this suite. Migration 001
/// creates the role with a placeholder password; deployments set a real one out
/// of band (`scripts/db/setup-app-role.sh`, or `secureprompt-api --migrate-only`
/// with `SECUREPROMPT_APP_DB_PASSWORD`). Setting it here is idempotent and
/// concurrency-safe — roles are cluster-global while `#[sqlx::test]` databases
/// are per-test, so several tests race to write the same value.
const APP_PROBE_PASSWORD: &str = "app_probe_password";

/// Open a connection to the SAME `#[sqlx::test]` database as the runtime role,
/// and assert ON THE WIRE that it really is powerless.
///
/// Without the premise assertions this suite would be worthless in exactly the
/// way the role split exists to prevent: if a stray `ALTER ROLE` handed
/// `secureprompt_app` SUPERUSER, the DDL-denial test below would fail loudly
/// rather than pass for the wrong reason — but only because these three lines
/// are here to notice.
async fn app_role_connection(pool: &PgPool) -> PgConnection {
    sqlx::raw_sql(&format!(
        "ALTER ROLE {APP_ROLE} WITH LOGIN PASSWORD '{APP_PROBE_PASSWORD}';"
    ))
    .execute(pool)
    .await
    .expect("set a known password on the runtime role for this probe");

    let options: PgConnectOptions = (*pool.connect_options())
        .clone()
        .username(APP_ROLE)
        .password(APP_PROBE_PASSWORD);

    let mut conn = PgConnection::connect_with(&options)
        .await
        .expect("runtime-role connection to the test database");

    let row = sqlx::query(
        "SELECT current_user::text AS who, rolsuper, rolbypassrls
         FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&mut conn)
    .await
    .expect("identity probe");

    let who: String = row.get("who");
    let superuser: bool = row.get("rolsuper");
    let bypassrls: bool = row.get("rolbypassrls");

    assert_eq!(who, APP_ROLE, "premise: connected as the wrong role");
    assert!(
        !superuser,
        "premise: {who} is a SUPERUSER. It would bypass RLS at runtime and \
         every DDL denial below would be false."
    );
    assert!(
        !bypassrls,
        "premise: {who} has BYPASSRLS. The whole point of the split is that \
         the serving role does not."
    );

    conn
}

// ===========================================================================
// The load-bearing test: future tables.
// ===========================================================================

/// THE SILENT-LOSS SHAPE THE SPLIT INTRODUCES.
///
/// Under one role this could not happen: the connecting role owned every table
/// and needed no grant. Split apart, the runtime role reaches a table only if
/// something granted it — and the repeated
/// `GRANT ... ON ALL TABLES IN SCHEMA public` lines in the migrations grant only
/// what exists at the moment they run.
///
/// So this test does what a future migration does: it creates a table AFTER the
/// whole migration set has been applied, and requires the runtime role to be
/// able to use it. Measured at the parent commit, before
/// `034_app_role_runtime_grants.sql` existed: `pg_default_acl` was empty and
/// this returned `false` for all four privileges.
#[sqlx::test]
async fn a_table_created_after_the_grants_is_still_reachable_by_the_runtime_role(pool: PgPool) {
    sqlx::raw_sql("CREATE TABLE future_migration_table (id UUID PRIMARY KEY)")
        .execute(&pool)
        .await
        .expect("a later migration creates a table, as the owner role does");

    for privilege in ["SELECT", "INSERT", "UPDATE", "DELETE"] {
        let granted: bool =
            sqlx::query_scalar("SELECT has_table_privilege($1, 'future_migration_table', $2)")
                .bind(APP_ROLE)
                .bind(privilege)
                .fetch_one(&pool)
                .await
                .expect("privilege probe");

        assert!(
            granted,
            "{APP_ROLE} has no {privilege} on a table created after the \
             migrations ran. ALTER DEFAULT PRIVILEGES is missing or was \
             issued by a role other than the one running migrations, so the \
             next migration that adds a table without a trailing GRANT will \
             take the feature offline at runtime while every test still passes."
        );
    }
}

/// The same guarantee for sequences. `001_init.sql` grants
/// `USAGE, SELECT ON ALL SEQUENCES` for the same reason it grants on tables,
/// and it has the same blind spot for anything created later.
#[sqlx::test]
async fn a_sequence_created_after_the_grants_is_still_usable_by_the_runtime_role(pool: PgPool) {
    sqlx::raw_sql("CREATE SEQUENCE future_migration_sequence")
        .execute(&pool)
        .await
        .expect("a later migration creates a sequence");

    for privilege in ["USAGE", "SELECT"] {
        let granted: bool = sqlx::query_scalar(
            "SELECT has_sequence_privilege($1, 'future_migration_sequence', $2)",
        )
        .bind(APP_ROLE)
        .bind(privilege)
        .fetch_one(&pool)
        .await
        .expect("privilege probe");

        assert!(
            granted,
            "{APP_ROLE} has no {privilege} on a sequence created after the \
             migrations ran."
        );
    }
}

// ===========================================================================
// The boundary in the other direction: what the runtime role must NOT have.
// ===========================================================================

/// `FORCE ROW LEVEL SECURITY` applies to the table owner too, so ownership is
/// not a way to give the runtime role reach — it is a way to give it a
/// DIFFERENT, unintended filter. The runtime role must own nothing and create
/// nothing; migrations are the only thing that changes the schema.
///
/// This is asserted through a real connection rather than through
/// `has_schema_privilege` alone, because the failure that matters is a
/// statement succeeding, not a catalog bit.
#[sqlx::test]
async fn the_runtime_role_cannot_create_objects_in_the_public_schema(pool: PgPool) {
    let mut conn = app_role_connection(&pool).await;

    let err = sqlx::raw_sql("CREATE TABLE runtime_role_ddl_probe (id INT)")
        .execute(&mut conn)
        .await
        .expect_err(
            "the runtime role created a table. It has CREATE on schema public, \
             which means it can also own tables — and an owner under FORCE ROW \
             LEVEL SECURITY is filtered by policies written for tenants, not \
             for it.",
        );

    let message = err.to_string();
    assert!(
        message.contains("permission denied"),
        "expected a privilege refusal, got: {message}"
    );

    let owns: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_class
          WHERE relnamespace = 'public'::regnamespace
            AND relowner = (SELECT oid FROM pg_roles WHERE rolname = $1)",
    )
    .bind(APP_ROLE)
    .fetch_one(&pool)
    .await
    .expect("ownership probe");

    assert_eq!(
        owns, 0,
        "{APP_ROLE} owns {owns} object(s) in schema public. Under FORCE ROW \
         LEVEL SECURITY an owning role is still filtered, so this is not a \
         harmless extra privilege — it is a second, undesigned access path."
    );
}

/// The mandated powerless-assertion, in the same shape as
/// `scripts/ci/create-nonsuperuser-role.sh`: without it a future base image or
/// a stray GRANT could hand the runtime role superuser and the entire suite
/// would keep passing while enforcing nothing.
#[sqlx::test]
async fn the_runtime_role_is_genuinely_powerless(pool: PgPool) {
    let row = sqlx::query(
        "SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole, rolcanlogin
           FROM pg_roles WHERE rolname = $1",
    )
    .bind(APP_ROLE)
    .fetch_one(&pool)
    .await
    .expect("the runtime role must exist after the migrations run");

    let superuser: bool = row.get("rolsuper");
    let bypassrls: bool = row.get("rolbypassrls");
    let createdb: bool = row.get("rolcreatedb");
    let createrole: bool = row.get("rolcreaterole");
    let canlogin: bool = row.get("rolcanlogin");

    assert!(!superuser, "{APP_ROLE} is a SUPERUSER — it bypasses RLS");
    assert!(!bypassrls, "{APP_ROLE} has BYPASSRLS — it bypasses RLS");
    assert!(
        !createdb,
        "{APP_ROLE} has CREATEDB — the serving process needs no databases"
    );
    assert!(
        !createrole,
        "{APP_ROLE} has CREATEROLE — with it the role can grant itself \
         membership of a privileged role and escape the split entirely"
    );
    assert!(
        canlogin,
        "{APP_ROLE} cannot LOG IN — nothing could serve with it"
    );
}

/// Every table the schema has must be reachable by the runtime role. This is
/// the "does the application still work" half of the split, expressed as a
/// catalog assertion so it fails at the migration that broke it rather than in
/// whichever handler happens to touch that table first.
#[sqlx::test]
async fn every_table_in_the_schema_is_reachable_by_the_runtime_role(pool: PgPool) {
    let unreachable: Vec<String> = sqlx::query_scalar(
        "SELECT relname::text FROM pg_class
          WHERE relkind = 'r'
            AND relnamespace = 'public'::regnamespace
            AND NOT has_table_privilege($1, oid, 'SELECT')
          ORDER BY relname",
    )
    .bind(APP_ROLE)
    .fetch_all(&pool)
    .await
    .expect("privilege sweep");

    assert!(
        unreachable.is_empty(),
        "{APP_ROLE} cannot SELECT from: {unreachable:?}. Each of these is a \
         runtime 42501 waiting for the first request that touches it."
    );
}

// ===========================================================================
// Boot. The knot the split had to untie.
// ===========================================================================

/// A pool connected to the SAME `#[sqlx::test]` database as the runtime role.
/// `ensure_pg_migrations` takes a `&PgPool`, so the probe has to be one.
async fn app_role_pool(pool: &PgPool) -> PgPool {
    sqlx::raw_sql(&format!(
        "ALTER ROLE {APP_ROLE} WITH LOGIN PASSWORD '{APP_PROBE_PASSWORD}';"
    ))
    .execute(pool)
    .await
    .expect("set a known password on the runtime role for this probe");

    let options: PgConnectOptions = (*pool.connect_options())
        .clone()
        .username(APP_ROLE)
        .password(APP_PROBE_PASSWORD);

    let probe = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("runtime-role pool on the test database");

    let can_create: bool =
        sqlx::query_scalar("SELECT has_schema_privilege(current_user, 'public', 'CREATE')")
            .fetch_one(&probe)
            .await
            .expect("schema privilege probe");
    assert!(
        !can_create,
        "premise: the runtime role has CREATE on schema public, so it would \
         take the OWNER branch and this test would measure nothing"
    );

    probe
}

/// THE KNOT.
///
/// `main.rs` ran `sqlx::migrate!` on every boot, on the same pool it then
/// served with — one connection doing both DDL and DML. A migration role needs
/// `CREATE ON SCHEMA public` and table ownership (measured: 018/021/023 fail
/// without CREATE, 022 fails with `must be owner of table
/// token_vault_entries`). The runtime role must have neither.
///
/// It is not enough for the runtime role to have "nothing to do": measured on
/// `postgres:16`, `CREATE TABLE IF NOT EXISTS _sqlx_migrations` on an
/// ALREADY-EXISTING table is still refused with `permission denied for schema
/// public` — Postgres checks the schema privilege before the existence check.
/// So `MIGRATOR.run` cannot even no-op under the runtime role, and the API
/// cannot simply be pointed at the app URL and left otherwise unchanged.
///
/// Boot must therefore notice which role it holds. This test is that
/// behaviour: a fully-migrated schema, a runtime connection, and a boot that
/// succeeds without attempting any DDL.
#[sqlx::test]
async fn boot_as_the_runtime_role_succeeds_without_attempting_ddl(pool: PgPool) {
    let probe = app_role_pool(&pool).await;

    ensure_pg_migrations(&probe)
        .await
        .expect("boot as the runtime role must succeed against a migrated schema");

    probe.close().await;
}

/// The other half: skipping migrations must never mean "not noticing they were
/// skipped". If the migration step did not run — the operator forgot the
/// one-shot, or it failed and was not looked at — the serving process must
/// refuse to start rather than serve requests against a schema it was not
/// compiled for.
///
/// The assertion is on the CONTENT of the error, not merely that there is one.
/// Before this behaviour existed the call also returned `Err`, but with
/// `permission denied for schema public` — an error that tells an operator
/// nothing about what is actually wrong. A bare `expect_err` here would have
/// been a vacuous pass.
#[sqlx::test]
async fn boot_as_the_runtime_role_refuses_a_schema_that_is_behind(pool: PgPool) {
    let head = MIGRATOR
        .iter()
        .map(|m| m.version)
        .max()
        .expect("the embedded migration set is not empty");

    sqlx::query("DELETE FROM _sqlx_migrations WHERE version = $1")
        .bind(head)
        .execute(&pool)
        .await
        .expect("simulate a migration step that never ran to completion");

    let probe = app_role_pool(&pool).await;

    let err = ensure_pg_migrations(&probe)
        .await
        .expect_err("a runtime role must not serve a schema that is behind")
        .to_string();

    assert!(
        err.contains(&head.to_string()),
        "the refusal must name the missing migration so an operator can act \
         on it. Got: {err}"
    );

    probe.close().await;
}

/// POSITIVE CONTROL, over the awkward path `ensure_pg_migrations` was written
/// for: a database whose tables exist but whose `_sqlx_migrations` does not,
/// because someone applied the schema by hand with `psql` and then redeployed.
///
/// This is also the path an EXISTING deployment can land on while adopting the
/// role split, so it is worth pinning as behaviour rather than as prose. The
/// owner branch must still perform DDL here — `CREATE TABLE _sqlx_migrations`
/// plus a row per embedded migration. Without this control,
/// `boot_as_the_runtime_role_succeeds_without_attempting_ddl` could be
/// satisfied by an `ensure_pg_migrations` that had quietly become a no-op for
/// everyone.
#[sqlx::test]
async fn boot_as_the_owner_bootstraps_tracking_when_the_schema_predates_sqlx(pool: PgPool) {
    sqlx::raw_sql("DROP TABLE _sqlx_migrations")
        .execute(&pool)
        .await
        .expect("simulate a schema applied by hand, with no sqlx tracking");

    let tracked_before: bool =
        sqlx::query_scalar("SELECT to_regclass('public._sqlx_migrations') IS NOT NULL")
            .fetch_one(&pool)
            .await
            .expect("existence probe");
    assert!(
        !tracked_before,
        "premise: the tracking table must start absent"
    );

    ensure_pg_migrations(&pool)
        .await
        .expect("boot as the owner must bootstrap the tracking table");

    let tracked: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations WHERE success")
        .fetch_one(&pool)
        .await
        .expect("tracking probe");

    assert_eq!(
        tracked,
        MIGRATOR.iter().count() as i64,
        "the owner branch did not bootstrap every embedded migration. \
         Migrations are no longer being applied on boot for ANYONE, which the \
         runtime-role test above cannot distinguish from working correctly."
    );
}

/// The same database, the other role. An existing deployment that has just
/// been pointed at the runtime URL, before its migration step has ever run,
/// must be told so — not handed `permission denied for schema public`, and
/// certainly not allowed to serve.
#[sqlx::test]
async fn boot_as_the_runtime_role_refuses_a_schema_with_no_tracking_table(pool: PgPool) {
    sqlx::raw_sql("DROP TABLE _sqlx_migrations")
        .execute(&pool)
        .await
        .expect("simulate a schema applied by hand, with no sqlx tracking");

    let probe = app_role_pool(&pool).await;

    let err = ensure_pg_migrations(&probe)
        .await
        .expect_err("a runtime role cannot bootstrap tracking — it has no DDL")
        .to_string();

    assert!(
        err.contains("_sqlx_migrations"),
        "the refusal must name what is missing so an operator knows to run the \
         migration step as the owner role. Got: {err}"
    );

    probe.close().await;
}

// ===========================================================================
// The migration step itself.
// ===========================================================================

/// A role used only to exercise password setting. NOT `secureprompt_app`:
/// roles are cluster-global while `#[sqlx::test]` databases are per-test, so a
/// test that set a DIFFERENT password on the shared runtime role would race
/// every other test in this file that connects as it.
const PASSWORD_PROBE_ROLE: &str = "sp_password_probe";

/// Deliberately awkward. `ALTER ROLE ... PASSWORD` cannot take a bind
/// parameter, so the statement has to be built as text — and the only safe way
/// to build it is to let the server quote it (`format('%L', $1)`). A password
/// containing a single quote, a double quote and a backslash is what tells the
/// difference between that and string concatenation.
const PROBE_PASSWORD: &str = "a'b\"c\\d e";

/// The migration step must set the runtime role's password, because there is
/// nowhere else it can come from: `001_init.sql` creates `secureprompt_app`
/// with a fixed placeholder, and a migration cannot read a deployment's
/// environment.
///
/// The assertion is a successful CONNECTION with the new password, not a
/// catalog read. `pg_authid.rolpassword` is a SCRAM verifier — comparing it
/// would prove only that some bytes changed.
#[sqlx::test]
async fn setting_the_runtime_role_password_lets_it_connect(pool: PgPool) {
    sqlx::raw_sql(&format!(
        "DO $$
         BEGIN
             CREATE ROLE {PASSWORD_PROBE_ROLE} LOGIN NOSUPERUSER NOCREATEDB
                 NOCREATEROLE NOBYPASSRLS;
         EXCEPTION
             WHEN duplicate_object THEN NULL;
             WHEN unique_violation THEN NULL;
         END $$;"
    ))
    .execute(&pool)
    .await
    .expect("probe role");

    secureprompt_api::db::migrations::set_role_password(&pool, PASSWORD_PROBE_ROLE, PROBE_PASSWORD)
        .await
        .expect("the migration step must be able to set the runtime password");

    let options: PgConnectOptions = (*pool.connect_options())
        .clone()
        .username(PASSWORD_PROBE_ROLE)
        .password(PROBE_PASSWORD);

    let mut conn = PgConnection::connect_with(&options).await.expect(
        "the password the migration step set must be the password the runtime \
         role can connect with — otherwise the app URL and the role disagree \
         and the deployment cannot start",
    );

    let who: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&mut conn)
        .await
        .expect("identity probe");
    assert_eq!(who, PASSWORD_PROBE_ROLE);

    conn.close().await.ok();
}

/// `--migrate-only` pointed at the runtime role would apply nothing and report
/// success — the operator would then start the API against a schema that was
/// never migrated, and only find out from the API's own refusal. Catch it in
/// the step that was supposed to do the work.
#[sqlx::test]
async fn the_migration_step_refuses_a_role_that_cannot_migrate(pool: PgPool) {
    let probe = app_role_pool(&pool).await;

    let err = secureprompt_api::db::migrations::run_migration_step(&probe, None)
        .await
        .expect_err("--migrate-only as a non-owner role must not report success")
        .to_string();

    assert!(
        err.contains("CREATE"),
        "the refusal must say what the role is missing. Got: {err}"
    );

    probe.close().await;
}

/// The ordinary path: as the owner, the step migrates and reports success.
/// Positive control for the refusal above.
#[sqlx::test]
async fn the_migration_step_succeeds_as_the_owner(pool: PgPool) {
    secureprompt_api::db::migrations::run_migration_step(&pool, None)
        .await
        .expect("the migration step must succeed as the owner role");
}
