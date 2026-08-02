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
//!
//! # Why this suite is NOT in `test:rls-nonsuperuser`
//!
//! Seven of these tests need to `ALTER ROLE secureprompt_app` — to give it a
//! known password so they can connect as it. MEASURED on postgres:16: a
//! CREATEROLE role may alter only roles it CREATED (it gets ADMIN OPTION on
//! those implicitly, and on nothing else):
//!
//! ```text
//! sp_admopt_creator creates a role, then alters it  -> ALTER ROLE
//! sp_admopt_creator alters a role it did not create -> 42501 permission denied
//! ```
//!
//! So under `DATABASE_URL=…secureprompt_runner…` the result depends on CLUSTER
//! HISTORY rather than on anything this suite is about. MEASURED on a cluster
//! where a superuser had created `secureprompt_app` first: **6 passed, 7
//! failed**, every failure `permission denied to alter role`. On a cluster
//! where the runner creates the role itself by running `001_init.sql` it would
//! hold ADMIN OPTION and could — but that is a prediction from the rule above,
//! not something measured here, and a job whose result turns on which role
//! happened to create a cluster-global role is a flaky job either way.
//!
//! So this suite stays in the ordinary `test:` job, where the connection can
//! administer the role, and `test:rls-nonsuperuser` keeps the suites whose
//! subject is row visibility. The six that DO pass under the runner role are
//! the six that only read the catalogue.
//!
//! This is not only a test concern: the same rule is why
//! `secureprompt-api --migrate-only` cannot set the runtime password on a
//! managed Postgres whose role an administrator created separately. That path
//! is `scripts/db/setup-app-role.sh`, and the error message says so.

use secureprompt_api::db::migrations::{ensure_pg_migrations, versions_ahead_of_binary, MIGRATOR};
use sqlx::postgres::{PgConnectOptions, PgConnection, PgPoolOptions};
use sqlx::{Connection, PgPool, Row};

/// The runtime role. Created by `001_init.sql`; granted, constrained and
/// asserted-powerless by `034_app_role_runtime_grants.sql`.
const APP_ROLE: &str = "secureprompt_app";

/// Fallback password for the probe connection, used when the environment does
/// not say what the runtime role's password should be. Migration 001 creates
/// the role with a placeholder; deployments set a real one out of band
/// (`scripts/db/setup-app-role.sh`, or `secureprompt-api --migrate-only` with
/// `SECUREPROMPT_APP_DB_PASSWORD`).
const APP_PROBE_PASSWORD_FALLBACK: &str = "app_probe_password";

/// The password this suite puts on the runtime role.
///
/// `secureprompt_app` is CLUSTER-GLOBAL while `#[sqlx::test]` databases are
/// per-test, so `ALTER ROLE secureprompt_app WITH PASSWORD` reaches everything
/// else on the same Postgres — including the compose `api` and `worker`, which
/// under the role split now connect as exactly this role. Before the split
/// nothing connected as it and the write was harmless; now `cargo test` would
/// lock a running stack out of its own database until `db-migrate` re-ran.
///
/// So when the environment says what the password is, use THAT: the write
/// becomes a no-op rewrite of the same value instead of a rotation. The
/// fallback only applies where nothing else is using the role.
fn app_probe_password() -> String {
    std::env::var("SECUREPROMPT_APP_DB_PASSWORD")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| APP_PROBE_PASSWORD_FALLBACK.to_string())
}

/// `ALTER ROLE` rewrites one row of the cluster-global `pg_authid`. Several
/// tests in this file need the runtime role to have a known password, they run
/// concurrently, and they were each issuing that write — which fails
/// intermittently with `XX000 tuple concurrently updated`. MEASURED: one
/// failure in two consecutive full-suite runs.
///
/// `#[sqlx::test]` gives every test its own DATABASE but the same PROCESS, and
/// advisory locks are scoped to a database, so they cannot serialise this.
/// A process-wide `OnceCell` can: the password is a constant, so writing it
/// once per test binary is exactly equivalent to writing it before each test,
/// minus the race.
static APP_PASSWORD_SET: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

async fn ensure_app_role_password(pool: &PgPool) {
    APP_PASSWORD_SET
        .get_or_init(|| async {
            secureprompt_api::db::migrations::set_role_password(
                pool,
                APP_ROLE,
                &app_probe_password(),
            )
            .await
            .expect("set a known password on the runtime role for this probe");
        })
        .await;
}

/// Open a connection to the SAME `#[sqlx::test]` database as the runtime role,
/// and assert ON THE WIRE that it really is powerless.
///
/// Without the premise assertions this suite would be worthless in exactly the
/// way the role split exists to prevent: if a stray `ALTER ROLE` handed
/// `secureprompt_app` SUPERUSER, the DDL-denial test below would fail loudly
/// rather than pass for the wrong reason — but only because these three lines
/// are here to notice.
async fn app_role_connection(pool: &PgPool) -> PgConnection {
    ensure_app_role_password(pool).await;

    let options: PgConnectOptions = (*pool.connect_options())
        .clone()
        .username(APP_ROLE)
        .password(&app_probe_password());

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

/// The mandated powerless-assertion.
///
/// PROVED IN REVIEW: this test used to read five `pg_roles` attribute columns
/// and nothing else, so it PASSED with the live `secureprompt_app` granted
/// membership of a BYPASSRLS role — the exact state its own doc-comment
/// promised it would catch ("a stray GRANT could hand the runtime role
/// superuser and the entire suite would keep passing while enforcing
/// nothing"). The membership check had been added to the production assertion
/// and never to the test named for the guarantee.
///
/// So it now calls the PRODUCTION assertion rather than re-implementing a
/// weaker subset of it: whatever a deployment refuses to start on, this
/// refuses to pass on. The attribute checks below are kept because they are
/// STRICTER than production's — CREATEDB, CREATEROLE and LOGIN are not things
/// the migration step refuses on, but a runtime role with CREATEROLE can grant
/// itself membership of a privileged role and escape the split entirely.
#[sqlx::test]
async fn the_runtime_role_is_genuinely_powerless(pool: PgPool) {
    secureprompt_api::db::migrations::assert_runtime_role_is_powerless(&pool)
        .await
        .expect(
            "the runtime role is not powerless by the same standard the \
             migration step applies. A deployment would refuse to start; this \
             suite must not pass.",
        );

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
        "{APP_ROLE} has CREATEROLE — the serving process creates no roles, and \
         a role attribute nothing needs is a role attribute that only widens \
         the blast radius of a compromise"
    );
    // MR7 review M5 — the reason above used to read "with it the role can grant
    // itself membership of a privileged role and escape the split entirely".
    // That was true of PostgreSQL 15 and earlier and is FALSE of PostgreSQL 16,
    // which the chart and every compose file pin. MEASURED on postgres:16.14, as
    // a NOSUPERUSER / CREATEDB / CREATEROLE / NOBYPASSRLS role: GRANT of an
    // existing BYPASSRLS role is denied for want of ADMIN OPTION;
    // `CREATE ROLE x BYPASSRLS`, `ALTER ROLE x BYPASSRLS`,
    // `CREATE ROLE x SUPERUSER` and `ALTER ROLE self BYPASSRLS` are all denied
    // because an attribute can only be conferred by a role that already holds
    // it. PG16 narrowed CREATEROLE to "may administer the roles it created", so
    // it confers the power to make POWERLESS roles and nothing more.
    //
    // The assertion stays -- least privilege does not need a live exploit to
    // justify it, and this is a supported-downgrade hazard: the same schema on
    // a PG15 server would make the old sentence true again. What changed is
    // that the message no longer states something an operator can disprove in
    // one psql session.
    //
    // `scripts/ci/create-nonsuperuser-role.sh` -- which DOES keep CREATEROLE,
    // because five test files create probe roles as the connected role -- now
    // asserts that premise on the live server: a PG16 floor plus a real
    // `SET ROLE` + `CREATE ROLE ... BYPASSRLS` attempt that must be refused.
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
    ensure_app_role_password(pool).await;

    let options: PgConnectOptions = (*pool.connect_options())
        .clone()
        .username(APP_ROLE)
        .password(&app_probe_password());

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

/// MR7 review M1 — the symmetric case: a schema AHEAD of the binary.
///
/// `verify_schema_at_head` checked one direction only (every embedded version
/// must be applied), so a rolled-back deployment running an OLDER image against
/// a NEWER schema passed silently and served. Given this file's premise — that
/// "we skipped migrations" and "migrations never ran" must not look alike —
/// "we rolled back onto a newer schema" must not look like a normal boot.
///
/// BOTH HALVES ARE ASSERTED, and they pull in opposite directions:
///
///   * it must still BOOT. Refusing would make rollback impossible, which is
///     the one lever an operator has during an incident. A test that only
///     checked for the warning would be satisfied by a build that warned and
///     then bailed.
///   * it must SAY SO. The warning is captured off a real `tracing`
///     subscriber driving the real `ensure_pg_migrations`, not re-derived from
///     `versions_ahead_of_binary` in the test.
///
/// FALSIFIERS: delete the `if !ahead.is_empty()` block -> the capture assertion
/// fails; turn the `warn!` into a `bail!` -> the boot assertion fails.
#[sqlx::test]
async fn boot_as_the_runtime_role_warns_when_the_schema_is_ahead(pool: PgPool) {
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;

    /// A `MakeWriter` that appends everything to a shared buffer.
    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("capture buffer")
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> MakeWriter<'a> for Capture {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    // A version this binary can never embed: migration filenames are
    // timestamps/ordinals well below this.
    const FUTURE_VERSION: i64 = 999_999_999;

    sqlx::query(
        "INSERT INTO _sqlx_migrations
             (version, description, installed_on, success, checksum, execution_time)
         VALUES ($1, 'a migration from a newer release', NOW(), TRUE, '\\x00', 0)",
    )
    .bind(FUTURE_VERSION)
    .execute(&pool)
    .await
    .expect("simulate a rollback: the database carries a newer release's migration");

    // PREMISE: the pure comparison must see it. If this is empty the capture
    // assertion below could pass for the wrong reason (some unrelated warn).
    let applied: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM _sqlx_migrations WHERE success")
            .fetch_all(&pool)
            .await
            .expect("read applied versions");
    assert_eq!(
        versions_ahead_of_binary(&applied),
        vec![FUTURE_VERSION],
        "premise: the seeded version must be the only one this binary lacks"
    );

    let probe = app_role_pool(&pool).await;

    let buf = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(Capture(Arc::clone(&buf)))
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .finish();

    // `set_default` rather than `with_default`: the call under test is async,
    // and the guard keeps this thread's subscriber installed across the await
    // without needing a block-on shim.
    let guard = tracing::subscriber::set_default(subscriber);
    let booted = ensure_pg_migrations(&probe).await;
    drop(guard);

    booted.expect(
        "a schema AHEAD of the binary must still boot — refusing would make \
         rollback impossible",
    );

    let logged = String::from_utf8(buf.lock().expect("capture buffer").clone())
        .expect("captured log is utf-8");
    assert!(
        logged.contains("schema_ahead_of_binary"),
        "booting against a newer schema must warn; nothing was logged at WARN. \
         Captured: {logged:?}"
    );
    assert!(
        logged.contains(&FUTURE_VERSION.to_string()),
        "the warning must NAME the versions this binary does not embed, or an \
         operator cannot tell a deliberate rollback from a mis-deployed image. \
         Captured: {logged:?}"
    );

    probe.close().await;
}

/// PROVED IN REVIEW (I3): the boot branch is chosen by
/// `has_schema_privilege(current_user,'public','CREATE')`, so a runtime role
/// that LATER acquires CREATE silently flips to the OWNER branch. On a database
/// already at head `MIGRATOR.run` has nothing to do, so it succeeds — and the
/// API serves as a role that can now create and own tables, with nothing
/// reporting it. `FORCE ROW LEVEL SECURITY` filters an owner rather than
/// exempting it, so that is a second, undesigned access path.
///
/// A `PUBLIC` grant is the reachable way in, and not an exotic one: it is the
/// default on any database created before PostgreSQL 15 (see
/// `migration_034_repairs_a_public_create_grant_instead_of_failing`).
#[sqlx::test]
async fn boot_as_the_runtime_role_refuses_when_a_public_grant_hands_it_create(pool: PgPool) {
    // Built BEFORE the grant: `app_role_pool` asserts the role has no CREATE,
    // which is the premise this test then breaks on purpose.
    let probe = app_role_pool(&pool).await;

    sqlx::raw_sql("GRANT CREATE ON SCHEMA public TO PUBLIC")
        .execute(&pool)
        .await
        .expect("the pre-PG15 default, granted here after boot detection was set up");

    let err = ensure_pg_migrations(&probe)
        .await
        .expect_err(
            "the runtime role acquired CREATE and boot took the OWNER branch \
             without a word. The process would serve as a role that can create \
             and own tables.",
        )
        .to_string();

    assert!(
        err.contains("REVOKE CREATE ON SCHEMA public FROM PUBLIC"),
        "the refusal must give the operator the statement that repairs it. \
         Got: {err}"
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

/// Number of `pg_default_acl` rows in schema `public` naming the runtime role.
/// This is 034's fingerprint: nothing else in the migration set issues
/// `ALTER DEFAULT PRIVILEGES`, and `pg_default_acl` was MEASURED empty at the
/// parent commit. Two rows (tables, sequences) means 034 executed; zero means
/// it did not, whatever `_sqlx_migrations` claims.
async fn runtime_role_default_acls(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM pg_default_acl d
           JOIN pg_namespace n ON n.oid = d.defaclnamespace
          WHERE n.nspname = 'public'
            AND array_to_string(d.defaclacl, ',') LIKE '%' || $1 || '=%'",
    )
    .bind(APP_ROLE)
    .fetch_one(pool)
    .await
    .expect("default-privilege probe")
}

/// THE UPGRADE PATH FOR EVERY EXISTING DEPLOYMENT.
///
/// The bootstrap branch of `apply_as_owner` exists for a database whose schema
/// was applied by hand with `psql` and which therefore has no
/// `_sqlx_migrations`. It marked EVERY embedded migration applied and then ran
/// `MIGRATOR.run`, which consequently found nothing pending — so on a database
/// whose hand-applied schema predates 034, the one migration that grants the
/// runtime role anything was recorded as applied WITHOUT EVER RUNNING.
///
/// MEASURED on `postgres:16` against a database at 001–033 (scratch DB
/// `mr7_pre034`): `pg_default_acl = 0`,
/// `has_table_privilege(secureprompt_app,'_sqlx_migrations','SELECT') = f`,
/// and `--migrate-only` **exits 0**. The API then dies on the bare `42501`
/// this whole change exists to replace — and the obvious operator reaction,
/// pointing DATABASE_URL back at the owner, lands the deployment in exactly
/// the superuser-serving state the split exists to leave.
///
/// So the assertion is not "the tracking table has 34 rows" (that is what the
/// defect produced); it is that the migration's EFFECTS are present, and that
/// the runtime role can then actually boot.
#[sqlx::test]
async fn the_tracking_bootstrap_does_not_claim_a_migration_it_never_ran(pool: PgPool) {
    // Rewind this database to the state a pre-034 hand-applied schema is in:
    // tables present, 034's grants and default privileges absent, no sqlx
    // tracking table.
    sqlx::raw_sql(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public
             REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM secureprompt_app;
         ALTER DEFAULT PRIVILEGES IN SCHEMA public
             REVOKE USAGE, SELECT ON SEQUENCES FROM secureprompt_app;
         REVOKE ALL ON ALL TABLES IN SCHEMA public FROM secureprompt_app;
         DROP TABLE _sqlx_migrations;",
    )
    .execute(&pool)
    .await
    .expect("simulate a schema hand-applied before 034 existed");

    assert_eq!(
        runtime_role_default_acls(&pool).await,
        0,
        "premise: 034's effects must start absent, or this test measures nothing"
    );

    ensure_pg_migrations(&pool)
        .await
        .expect("boot as the owner must bring a pre-034 database up to head");

    assert!(
        runtime_role_default_acls(&pool).await > 0,
        "the bootstrap recorded 034 as applied without running it: \
         pg_default_acl is still empty. Every table a later migration creates \
         will be unreachable by {APP_ROLE}, and the migration step reports \
         success while having prepared nothing."
    );

    let tracking_readable: bool =
        sqlx::query_scalar("SELECT has_table_privilege($1, '_sqlx_migrations', 'SELECT')")
            .bind(APP_ROLE)
            .fetch_one(&pool)
            .await
            .expect("tracking-table privilege probe");
    assert!(
        tracking_readable,
        "{APP_ROLE} cannot SELECT from _sqlx_migrations, which is the FIRST \
         thing the runtime branch of boot reads. The migration step exited 0 \
         and the API cannot start."
    );

    // The end of the story, not a proxy for it: the serving role boots.
    let probe = app_role_pool(&pool).await;
    ensure_pg_migrations(&probe)
        .await
        .expect("the runtime role must be able to boot after the migration step reported success");
    probe.close().await;
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
// Migration 034 itself, re-run against databases it was not written on.
// ===========================================================================

/// The SQL text of one embedded migration.
///
/// Running the migration's own bytes is the only way to test it: by the time
/// `#[sqlx::test]` hands over a pool, 034 is already applied and will never be
/// pending again. 034's header commits to being idempotent — "safe on a fresh
/// database and on one that has been running since 001" — so re-running it is
/// also exactly what the runbook tells an operator to do when grants drift.
fn migration_sql(version: i64) -> String {
    MIGRATOR
        .iter()
        .find(|m| m.version == version)
        .unwrap_or_else(|| panic!("migration {version} is not in the embedded set"))
        .sql
        .to_string()
}

/// PROVED IN REVIEW: 034 took the whole deployment down on any database where
/// `CREATE ON SCHEMA public` is granted to `PUBLIC`.
///
/// `REVOKE CREATE ON SCHEMA public FROM secureprompt_app` does **nothing**
/// against a grant held by `PUBLIC`. Section 5 then sees
/// `has_schema_privilege = true` and raises, so `--migrate-only` exits
/// non-zero, the compose `db-migrate` service never reaches
/// `service_completed_successfully`, and neither `api` nor `worker` starts.
///
/// `PUBLIC` holding `CREATE` on `public` is the default for every database
/// created before PostgreSQL 15, survives `pg_upgrade` (which preserves schema
/// ACLs — only a NEWLY initdb'd PG15+ cluster drops it), and is what an
/// operator gets from the very common `GRANT ALL ON SCHEMA public TO PUBLIC`.
/// A full outage on upgrade, on a database that was working a minute earlier.
#[sqlx::test]
async fn migration_034_repairs_a_public_create_grant_instead_of_failing(pool: PgPool) {
    sqlx::raw_sql("GRANT CREATE ON SCHEMA public TO PUBLIC")
        .execute(&pool)
        .await
        .expect("the pre-PG15 default, and a common operator incantation");

    let can_create_before: bool =
        sqlx::query_scalar("SELECT has_schema_privilege($1, 'public', 'CREATE')")
            .bind(APP_ROLE)
            .fetch_one(&pool)
            .await
            .expect("schema privilege probe");
    assert!(
        can_create_before,
        "premise: the PUBLIC grant must reach {APP_ROLE}, or this test measures \
         nothing"
    );

    sqlx::raw_sql(&migration_sql(34))
        .execute(&pool)
        .await
        .expect(
            "034 must survive a PUBLIC grant. Failing here is a total outage: \
             --migrate-only exits non-zero, db-migrate never completes, and \
             nothing starts.",
        );

    let can_create_after: bool =
        sqlx::query_scalar("SELECT has_schema_privilege($1, 'public', 'CREATE')")
            .bind(APP_ROLE)
            .fetch_one(&pool)
            .await
            .expect("schema privilege probe");
    assert!(
        !can_create_after,
        "034 reported success while {APP_ROLE} can still create — and therefore \
         own — tables in schema public. An owner is filtered by FORCE ROW LEVEL \
         SECURITY rather than exempt from it, so this is a second, undesigned \
         access path that the migration claims to have closed."
    );
}

/// PROVED IN REVIEW: 034's own closing assertion — the ONLY one that runs on
/// the two supported paths where `--migrate-only` is not what applied the
/// schema (`sqlx migrate run`, and any database already at head where 034 is
/// no longer pending) — passed while `secureprompt_app` was a member of a
/// BYPASSRLS role. `migrations.rs` claimed the Rust assertion was "in the same
/// shape as ... the closing block of 034"; only the Rust one asked
/// `pg_auth_members`.
///
/// NOINHERIT is what makes this invisible to the attribute checks: it means
/// the privileges are not AUTOMATIC, not that they are unreachable. `SET ROLE`
/// reaches them over an ordinary connection with no password, so a BYPASSRLS
/// role the runtime role is a member of is BYPASSRLS, one statement away.
///
/// The whole probe runs inside a transaction that is ROLLED BACK: `pg_authid`
/// and `pg_auth_members` are cluster-global, and every other test in this file
/// depends on `secureprompt_app`'s real state. Uncommitted catalog rows are
/// invisible to them.
#[sqlx::test]
async fn migration_034_refuses_a_runtime_role_that_can_reach_bypassrls(pool: PgPool) {
    let mut tx = pool.begin().await.expect("probe transaction");

    sqlx::raw_sql(
        "CREATE ROLE sp_034_bypass_probe NOLOGIN BYPASSRLS;
         GRANT sp_034_bypass_probe TO secureprompt_app;",
    )
    .execute(&mut *tx)
    .await
    .expect("grant the runtime role membership of a BYPASSRLS role");

    // PREMISE: every attribute-based check still calls the role harmless, so
    // only a membership check can catch this.
    let looks_harmless: bool = sqlx::query_scalar(
        "SELECT NOT (rolsuper OR rolbypassrls)
            AND NOT has_schema_privilege($1, 'public', 'CREATE')
           FROM pg_roles WHERE rolname = $1",
    )
    .bind(APP_ROLE)
    .fetch_one(&mut *tx)
    .await
    .expect("attribute probe");
    assert!(
        looks_harmless,
        "premise: the attribute checks must NOT already flag {APP_ROLE}, or \
         this test is not measuring the membership hole"
    );

    let outcome = sqlx::raw_sql(&migration_sql(34)).execute(&mut *tx).await;

    tx.rollback().await.expect("undo the cluster-global grant");

    let err = outcome
        .expect_err(
            "034 reported success while secureprompt_app was one SET ROLE from \
             BYPASSRLS. This is the only powerless-assertion that runs on a \
             `sqlx migrate run` deployment or on a database already at head.",
        )
        .to_string();

    assert!(
        err.contains("sp_034_bypass_probe"),
        "the refusal must name the role that is reachable, or an operator \
         cannot find it. Got: {err}"
    );
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

/// PROVED IN REVIEW, AND RENDERED: the Helm chart puts the `--migrate-only`
/// initContainer on the api Deployment **and** the worker Deployment, so every
/// `helm install`/`helm upgrade` starts at least two of these concurrently
/// (five at `api.replicaCount=3` / `worker.replicaCount=2` — measured by
/// `helm template`). Compose has the same shape whenever anything restarts the
/// one-shot while another is mid-flight.
///
/// `MIGRATOR.run` takes a Postgres advisory lock (sqlx 0.8.6 sets
/// `locking: true` by default), but it RELEASES it before returning — and
/// `set_role_password` runs after that. `ALTER ROLE ... PASSWORD` rewrites one
/// row of the cluster-global `pg_authid`, and concurrent writers get
/// `XX000 tuple concurrently updated`. MEASURED in review: 6 of 8 concurrent
/// `ALTER ROLE` statements failed.
///
/// The consequence is not cosmetic. An initContainer exiting non-zero is
/// `Init:Error`/`CrashLoopBackOff`, and `helm upgrade --wait`/`--atomic` (or
/// any Argo/Flux health gate) sees a failed rollout and can roll the release
/// back — on the security-critical path.
///
/// The password used is the one this suite already puts on the role, so this
/// test writes the same value every other test here relies on.
#[sqlx::test]
async fn concurrent_migration_steps_all_succeed(pool: PgPool) {
    const CONCURRENCY: usize = 8;

    // `#[sqlx::test]`'s own pool is too small to hold this many in flight.
    let options: PgConnectOptions = (*pool.connect_options()).clone();
    let racing = PgPoolOptions::new()
        .max_connections(CONCURRENCY as u32)
        .connect_with(options)
        .await
        .expect("pool wide enough to run the migration step concurrently");

    // `join_all` rather than `tokio::spawn`: sqlx's `Acquire`/`Executor` impls
    // for `&mut PgConnection` are not higher-ranked, so the migration step's
    // future cannot be proved `Send` and will not spawn (sqlx#2941). Joining
    // them on one task is concurrency enough — every one of these blocks on
    // network I/O, so the ALTER ROLEs still overlap at the server, which is
    // where the race is. MEASURED before the fix: 4 of 8 failed.
    let password = app_probe_password();
    let steps = (0..CONCURRENCY).map(|_| {
        let step_pool = racing.clone();
        let password = password.clone();
        async move {
            secureprompt_api::db::migrations::run_migration_step(&step_pool, Some(&password)).await
        }
    });

    let failures: Vec<String> = futures_util::future::join_all(steps)
        .await
        .into_iter()
        .filter_map(|outcome| outcome.err().map(|e| e.to_string()))
        .collect();

    racing.close().await;

    assert!(
        failures.is_empty(),
        "{} of {CONCURRENCY} concurrent migration steps failed. Every one of \
         them is an initContainer exiting non-zero on a rollout that was \
         supposed to be idempotent. Failures: {failures:#?}",
        failures.len()
    );
}

/// PROVED IN REVIEW: nothing reached the powerless assertion THROUGH
/// `run_migration_step`. A full reference sweep found three call sites — one
/// that fails earlier on the CREATE check, one that passes with or without the
/// assertion, and one calling `assert_role_is_powerless` directly — so the line
/// could be deleted from the migration step with all thirteen tests green. The
/// deployment gate was pinned by nothing.
///
/// It could not be tested through `run_migration_step` because that function
/// hard-coded `RUNTIME_ROLE`, which is cluster-global: a test that made
/// `secureprompt_app` a member of a BYPASSRLS role would break every other test
/// in this file. `run_migration_step_for_role` takes the role as a parameter,
/// so the assertion is reachable against a throwaway.
///
/// MUTATION-PROVED: deleting `assert_role_is_powerless_on` from
/// `locked_migration_step` turns THIS test red and leaves the other seventeen
/// green — which is exactly the review's finding, now the other way round.
#[sqlx::test]
async fn the_migration_step_refuses_a_runtime_role_that_can_reach_bypassrls(pool: PgPool) {
    sqlx::raw_sql(
        "DO $$
         BEGIN
             CREATE ROLE sp_step_probe LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
                 NOINHERIT NOBYPASSRLS;
         EXCEPTION WHEN duplicate_object THEN NULL; WHEN unique_violation THEN NULL;
         END $$;
         DO $$
         BEGIN
             CREATE ROLE sp_step_grantor NOLOGIN BYPASSRLS;
         EXCEPTION WHEN duplicate_object THEN NULL; WHEN unique_violation THEN NULL;
         END $$;
         GRANT sp_step_grantor TO sp_step_probe;",
    )
    .execute(&pool)
    .await
    .expect("probe roles");

    // PREMISE: the step is connected as the OWNER, so it gets past the
    // authority check and actually runs. Otherwise it would refuse for an
    // unrelated reason and prove nothing.
    let outcome =
        secureprompt_api::db::migrations::run_migration_step_for_role(&pool, "sp_step_probe", None)
            .await;

    sqlx::raw_sql(
        "REVOKE sp_step_grantor FROM sp_step_probe;
         DROP ROLE IF EXISTS sp_step_grantor;
         DROP ROLE IF EXISTS sp_step_probe;",
    )
    .execute(&pool)
    .await
    .ok();

    let err = outcome
        .expect_err(
            "the migration step completed while its runtime role was one SET \
             ROLE from BYPASSRLS. --migrate-only would exit 0 and the \
             deployment would serve with every RLS policy inert.",
        )
        .to_string();

    assert!(
        err.contains("sp_step_grantor"),
        "the refusal must name the reachable role. Got: {err}"
    );
}

/// A role can be powerless on paper and not in practice.
///
/// MEASURED while exercising `scripts/db/setup-app-role.sh`: granting
/// `secureprompt_app` membership of a role that holds `CREATE ON SCHEMA
/// public` leaves `has_schema_privilege('secureprompt_app','public','CREATE')`
/// answering **false**, because the runtime role is NOINHERIT and so does not
/// pick the privilege up automatically. The catalog says powerless.
///
/// But NOINHERIT only means the privileges are not AUTOMATIC. `SET ROLE` still
/// reaches them, from an ordinary connection, with no password. So membership
/// is an escape hatch out of the split that neither `rolsuper`, `rolbypassrls`
/// nor `has_schema_privilege` reports — and BYPASSRLS held by a role the
/// runtime role can `SET ROLE` to is BYPASSRLS.
///
/// The assertion has to look at membership itself.
#[sqlx::test]
async fn a_role_that_can_reach_privileges_through_membership_is_not_powerless(pool: PgPool) {
    sqlx::raw_sql(
        "DO $$
         BEGIN
             CREATE ROLE sp_member_probe LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
                 NOINHERIT NOBYPASSRLS;
         EXCEPTION WHEN duplicate_object THEN NULL; WHEN unique_violation THEN NULL;
         END $$;
         DO $$
         BEGIN
             CREATE ROLE sp_grantor_probe NOLOGIN BYPASSRLS;
         EXCEPTION WHEN duplicate_object THEN NULL; WHEN unique_violation THEN NULL;
         END $$;
         GRANT sp_grantor_probe TO sp_member_probe;",
    )
    .execute(&pool)
    .await
    .expect("probe roles");

    // PREMISE: every attribute-based check says this role is harmless.
    let looks_harmless: bool = sqlx::query_scalar(
        "SELECT NOT (rolsuper OR rolbypassrls)
            AND NOT has_schema_privilege('sp_member_probe', 'public', 'CREATE')
           FROM pg_roles WHERE rolname = 'sp_member_probe'",
    )
    .fetch_one(&pool)
    .await
    .expect("attribute probe");
    assert!(
        looks_harmless,
        "premise: the attribute checks must NOT already flag this role, or the \
         test is not measuring the membership hole"
    );

    let result =
        secureprompt_api::db::migrations::assert_role_is_powerless(&pool, "sp_member_probe").await;

    sqlx::raw_sql(
        "REVOKE sp_grantor_probe FROM sp_member_probe;
         DROP ROLE IF EXISTS sp_grantor_probe;
         DROP ROLE IF EXISTS sp_member_probe;",
    )
    .execute(&pool)
    .await
    .ok();

    let err = result
        .expect_err(
            "a role that can SET ROLE to a BYPASSRLS role is not powerless, \
             however its own attributes read",
        )
        .to_string();

    assert!(
        err.contains("sp_grantor_probe"),
        "the refusal must name the role that is reachable, or an operator \
         cannot find it. Got: {err}"
    );
}
