//! Applying the Postgres schema, and deciding whether this process may.
//!
//! Moved out of `main.rs` so it can be tested against a real non-owner
//! connection. `main.rs` is a binary crate: nothing there is reachable from
//! `tests/`, and the branch that matters here — what happens when the
//! connected role is NOT allowed to change the schema — cannot be exercised
//! any other way.

use sqlx::{PgConnection, PgPool};

/// Embedded sqlx migrations (all .sql files in `secureprompt-api/migrations/`).
/// Sorted by the leading numeric prefix in each filename. The path is relative
/// to CARGO_MANIFEST_DIR, not to this source file.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// What the connected role is allowed to do to the schema.
///
/// Decided by asking Postgres, not by reading configuration: an env var can be
/// set wrongly and nothing checks it, whereas `has_schema_privilege` is the
/// same question the server itself will answer when the first `CREATE` is
/// attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaAuthority {
    /// Holds `CREATE ON SCHEMA public`. Applies migrations.
    Owner,
    /// Does not. Serves requests, and verifies that someone else applied them.
    Runtime,
}

/// Ask the server which of the two roles this connection is holding.
pub async fn schema_authority(pool: &PgPool) -> anyhow::Result<SchemaAuthority> {
    let mut conn = pool.acquire().await?;
    schema_authority_on(&mut conn).await
}

async fn schema_authority_on(conn: &mut PgConnection) -> anyhow::Result<SchemaAuthority> {
    let can_create: bool =
        sqlx::query_scalar("SELECT has_schema_privilege(current_user, 'public', 'CREATE')")
            .fetch_one(&mut *conn)
            .await?;

    Ok(if can_create {
        SchemaAuthority::Owner
    } else {
        SchemaAuthority::Runtime
    })
}

/// Bring the process and the schema into agreement at boot.
///
/// # Why this branches
///
/// Under the DB role split the API serves as `secureprompt_app`, which has no
/// `CREATE ON SCHEMA public` and owns no tables — that is the entire point,
/// because a role that owns tables is filtered by `FORCE ROW LEVEL SECURITY`
/// rather than exempt from it, and a role that is a SUPERUSER is exempt from
/// RLS altogether. Migrations are applied separately, by the owner role
/// (`secureprompt-api --migrate-only`, or `sqlx migrate run`).
///
/// It is not enough to let the runtime role fall through `MIGRATOR.run` and
/// find nothing to do. MEASURED on postgres:16: `CREATE TABLE IF NOT EXISTS
/// _sqlx_migrations` against an ALREADY-EXISTING table is still refused with
/// `permission denied for schema public`, because the schema privilege is
/// checked before the existence check. `MIGRATOR.run` calls exactly that as its
/// first act, so it cannot even no-op under the runtime role.
///
/// # Why detection rather than a flag
///
/// A single-role deployment that has not adopted the split still connects with
/// CREATE, still takes the `Owner` branch, and behaves exactly as before —
/// there is nothing to set and nothing to get wrong. A deployment that HAS
/// adopted it cannot forget to set the flag, because there is no flag.
///
/// # Why skipping is not silent
///
/// The `Runtime` branch verifies that every embedded migration is recorded as
/// applied, and refuses to boot otherwise. Otherwise "we skipped migrations"
/// and "migrations never ran" would look identical from here, and the process
/// would serve requests against a schema it was not compiled for.
///
/// # Owner branch: two cases, unchanged
///
/// 1. **Fresh DB** (no `workspaces` table): `MIGRATOR.run` creates everything
///    from scratch, including the `_sqlx_migrations` tracking table.
/// 2. **Existing DB without sqlx tracking** (someone applied migrations
///    manually via `psql`, then redeployed): the tables are already there, but
///    `_sqlx_migrations` is missing, so a naive `MIGRATOR.run` would try to
///    recreate `workspaces` and fail. We detect this and bootstrap the tracking
///    table — but only for migrations whose effects we do not have a cheaper
///    way of checking. See `BOOTSTRAP_WITNESSES`.
pub async fn ensure_pg_migrations(pool: &PgPool) -> anyhow::Result<()> {
    let mut conn = pool.acquire().await?;
    match schema_authority_on(&mut conn).await? {
        SchemaAuthority::Owner => {
            // MISDETECTION, not a fallthrough. The branch is chosen by CREATE
            // on schema public, and a PUBLIC grant hands that to every role
            // (proved reachable: it is the default on any database created
            // before PostgreSQL 15). Without this, the serving role would take
            // the owner branch, find nothing pending, and serve as a role that
            // can create and own tables — with nothing reporting it.
            let who: String = sqlx::query_scalar("SELECT current_user::text")
                .fetch_one(&mut *conn)
                .await?;
            if who == RUNTIME_ROLE {
                anyhow::bail!(
                    "connected as the runtime role `{who}`, but it has CREATE on \
                     schema public — so it can create, and therefore own, tables, \
                     and an owner is filtered by FORCE ROW LEVEL SECURITY rather \
                     than exempt from it. The usual cause is `CREATE ON SCHEMA \
                     public` granted to PUBLIC. Fix it with `REVOKE CREATE ON \
                     SCHEMA public FROM PUBLIC;` and re-run the migration step."
                );
            }
            apply_as_owner(&mut conn).await
        }
        SchemaAuthority::Runtime => {
            tracing::info!(
                "connected role has no CREATE on schema public — not applying \
                 migrations. This is the expected shape under the DB role \
                 split; the owner role applies them in a separate step."
            );
            verify_schema_at_head(&mut conn).await?;
            // The powerless assertion runs HERE too, not only in the migration
            // step. Its own doc-comment justified itself as "the last thing that
            // runs before a deployment starts serving" and as catching "a role
            // that acquired SUPERUSER or BYPASSRLS after 034 was applied" — both
            // claims are about boot, and it had no boot call site. A GRANT
            // applied between the migration step and a later pod restart was
            // never re-checked. Three catalog reads.
            assert_role_is_powerless_on(&mut conn, RUNTIME_ROLE).await
        }
    }
}

/// The `Runtime` branch: confirm somebody else did the work.
///
/// Deliberately checks VERSIONS and not checksums. A checksum divergence means
/// a historical migration file was edited after being applied, which
/// `MIGRATOR.run` already refuses in the owner branch — that is the migration
/// step's error to report, and duplicating it here would be a second place to
/// keep true for no extra protection.
async fn verify_schema_at_head(conn: &mut PgConnection) -> anyhow::Result<()> {
    let tracking_exists: bool =
        sqlx::query_scalar("SELECT to_regclass('public._sqlx_migrations') IS NOT NULL")
            .fetch_one(&mut *conn)
            .await?;

    if !tracking_exists {
        anyhow::bail!(
            "this database has no _sqlx_migrations table and the connected role \
             cannot create one. Run the migration step as the owner role first: \
             `secureprompt-api --migrate-only` with DATABASE_URL pointed at the \
             owner/migrator role."
        );
    }

    let applied: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM _sqlx_migrations WHERE success")
            .fetch_all(&mut *conn)
            .await?;

    let missing: Vec<String> = MIGRATOR
        .iter()
        .filter(|m| !applied.contains(&m.version))
        .map(|m| format!("{} ({})", m.version, m.description))
        .collect();

    if !missing.is_empty() {
        anyhow::bail!(
            "this database is behind the embedded migration set and the \
             connected role cannot apply migrations. Not applied: {}. Run the \
             migration step as the owner role first: `secureprompt-api \
             --migrate-only` with DATABASE_URL pointed at the owner/migrator \
             role.",
            missing.join(", ")
        );
    }

    // MR7 review M1 — the check above is one-directional: every EMBEDDED
    // version must be applied. The symmetric case, a database whose schema is
    // AHEAD of this binary, passed silently and served.
    //
    // That is a rollback: a bad release is reverted, the pods come back on the
    // previous image, and the database still carries the newer release's
    // migrations. This MUST NOT refuse to boot — refusing would make rollback,
    // the one lever an operator has during an incident, impossible. But given
    // this file's whole premise, that "we skipped migrations" and "migrations
    // never ran" must not look alike, "we rolled back onto a newer schema"
    // must not look like a normal boot either. It is the state in which a
    // dropped column, a tightened CHECK or a new NOT NULL shows up as a
    // runtime error in one handler rather than as a startup failure.
    let ahead = versions_ahead_of_binary(&applied);
    if !ahead.is_empty() {
        tracing::warn!(
            ahead = ?ahead,
            ahead_count = ahead.len(),
            embedded_head = MIGRATOR.iter().map(|m| m.version).max(),
            "schema_ahead_of_binary: this database has migrations this binary \
             does not embed. Serving anyway — this is the expected shape during \
             a rollback and refusing would make rollback impossible — but any \
             column or constraint those migrations changed is unknown to this \
             build. If this is NOT a deliberate rollback, the deployment is \
             running an image older than its database."
        );
    }

    tracing::info!(
        applied = applied.len(),
        "Postgres schema is at the embedded migration head"
    );
    Ok(())
}

/// Versions `_sqlx_migrations` records that this binary does not embed.
///
/// Split out from [`verify_schema_at_head`] so the comparison is directly
/// testable, and `pub` so `tests/db_role_split.rs` can assert the warning
/// above fires on the state it names rather than on a re-implementation of it.
///
/// Sorted, so the log line and any assertion on it are deterministic.
#[must_use]
pub fn versions_ahead_of_binary(applied: &[i64]) -> Vec<i64> {
    let embedded: std::collections::HashSet<i64> = MIGRATOR.iter().map(|m| m.version).collect();
    let mut ahead: Vec<i64> = applied
        .iter()
        .copied()
        .filter(|v| !embedded.contains(v))
        .collect();
    ahead.sort_unstable();
    ahead
}

/// Migrations the tracking-table bootstrap is NOT allowed to take on faith,
/// paired with a query that answers "did this migration's effect actually
/// land?".
///
/// # Why this list exists
///
/// The bootstrap runs on a database whose `_sqlx_migrations` is missing because
/// the schema was applied by hand with `psql`. It cannot know WHICH migrations
/// that hand-application covered; the presence of `workspaces` only proves 001.
/// Marking the whole set applied is therefore a guess, and MEASURED on
/// `postgres:16` it is a guess that breaks the deployment: on a database
/// hand-applied at 001–033, marking 034 applied means the one migration that
/// grants the runtime role anything never runs. `pg_default_acl` stays empty,
/// `secureprompt_app` cannot even `SELECT` from `_sqlx_migrations`, and
/// `--migrate-only` exits **0** on a database it did not prepare. The API then
/// dies at boot on the bare `permission denied` this module exists to replace.
///
/// A migration listed here is left OUT of the blanket insert when its witness
/// answers false, so `MIGRATOR.run` applies it immediately afterwards. That is
/// only safe for a migration that is idempotent by construction — which is why
/// this is an explicit, reviewed list and not a heuristic over the whole set.
///
/// 034 qualifies: it issues `GRANT`, `ALTER DEFAULT PRIVILEGES` and `REVOKE`,
/// creates no object, moves no data, and its header commits to being re-runnable
/// as the documented repair for drifted grants. Its witness is `pg_default_acl`,
/// which is 034's fingerprint — nothing else in the set issues
/// `ALTER DEFAULT PRIVILEGES`, and the catalog was MEASURED empty at the commit
/// before it.
///
/// The residual gap is deliberate and named: a database hand-applied at, say,
/// 020 still has 021–033 marked applied without running. Those migrations
/// create tables, so re-running them is not safe, and no witness can make it
/// so — the bootstrap warns instead.
const BOOTSTRAP_WITNESSES: &[(i64, &str)] = &[(
    34,
    "SELECT EXISTS (
         SELECT 1
           FROM pg_default_acl d
           JOIN pg_namespace n ON n.oid = d.defaclnamespace
          WHERE n.nspname = 'public'
            AND array_to_string(d.defaclacl, ',') LIKE '%secureprompt_app=%')",
)];

/// The `Owner` branch.
///
/// Takes a single connection rather than the pool because `run_migration_step`
/// holds a session-level advisory lock on it for the whole step — see
/// `MIGRATION_STEP_LOCK_KEY`.
async fn apply_as_owner(conn: &mut PgConnection) -> anyhow::Result<()> {
    let workspaces_exists: bool =
        sqlx::query_scalar("SELECT to_regclass('public.workspaces') IS NOT NULL")
            .fetch_one(&mut *conn)
            .await?;
    let tracking_exists: bool =
        sqlx::query_scalar("SELECT to_regclass('public._sqlx_migrations') IS NOT NULL")
            .fetch_one(&mut *conn)
            .await?;

    if workspaces_exists && !tracking_exists {
        tracing::warn!(
            "Postgres has existing schema but no sqlx tracking table — bootstrapping _sqlx_migrations from embedded migration set"
        );
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS _sqlx_migrations (
                version         BIGINT PRIMARY KEY,
                description     TEXT NOT NULL,
                installed_on    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                success         BOOLEAN NOT NULL,
                checksum        BYTEA NOT NULL,
                execution_time  BIGINT NOT NULL
            )",
        )
        .execute(&mut *conn)
        .await?;

        // Ask, for every migration we have a witness for, whether it really ran.
        // Anything that answers "no" is left out of the insert below so that
        // `MIGRATOR.run` applies it for real.
        let mut unwitnessed: Vec<i64> = Vec::new();
        for (version, witness) in BOOTSTRAP_WITNESSES {
            let effect_present: bool = sqlx::query_scalar(witness).fetch_one(&mut *conn).await?;
            if !effect_present {
                unwitnessed.push(*version);
            }
        }
        if !unwitnessed.is_empty() {
            tracing::warn!(
                versions = ?unwitnessed,
                "these migrations have left no trace in this database, so the \
                 bootstrap will NOT record them as applied — they are about to \
                 be run for real"
            );
        }

        for m in MIGRATOR.iter() {
            if unwitnessed.contains(&m.version) {
                continue;
            }
            sqlx::query(
                "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) \
                 VALUES ($1, $2, TRUE, $3, 0) ON CONFLICT (version) DO NOTHING",
            )
            .bind(m.version)
            .bind(m.description.as_ref())
            .bind(&m.checksum[..])
            .execute(&mut *conn)
            .await?;
        }

        tracing::warn!(
            "the schema this database already carried is being taken on trust \
             for every migration not listed above. If it was hand-applied part \
             way through the set, the migrations after that point are now \
             recorded as applied without having run — verify against \
             secureprompt-api/migrations/ before serving."
        );
    }

    MIGRATOR.run(&mut *conn).await?;
    tracing::info!(
        applied = MIGRATOR.iter().count(),
        "Postgres migrations up to date"
    );
    Ok(())
}

/// The runtime role the deployment serves as. Named in `001_init.sql`,
/// constrained by `034_app_role_runtime_grants.sql`, and connected with by the
/// `DATABASE_URL` that `docker-compose.yml` and the Helm chart hand the API and
/// the worker.
pub const RUNTIME_ROLE: &str = "secureprompt_app";

/// The advisory-lock key `run_migration_step` serialises on.
///
/// # Why the step needs its own lock
///
/// `MIGRATOR.run` takes an advisory lock of its own (sqlx 0.8.6 sets
/// `locking: true` by default) — and RELEASES it before returning. Everything
/// the migration step does afterwards, `ALTER ROLE ... PASSWORD` above all,
/// therefore ran unserialised.
///
/// That is not theoretical. `helm template` at chart defaults renders a
/// `--migrate-only` initContainer on BOTH the api and the worker Deployment —
/// two concurrent migration steps on every `helm install`/`helm upgrade`, five
/// at `api.replicaCount=3` / `worker.replicaCount=2`. `ALTER ROLE` rewrites one
/// row of the cluster-global `pg_authid`, and concurrent writers get
/// `XX000 tuple concurrently updated`. MEASURED on postgres:16: **4 of 8**
/// concurrent migration steps failed that way. Each failure is an initContainer
/// exiting non-zero, which `helm upgrade --wait`/`--atomic` and any Argo/Flux
/// health gate read as a failed rollout — on the security-critical path.
///
/// # Scope, stated honestly
///
/// Postgres advisory locks are scoped to a DATABASE, while `pg_authid` is
/// cluster-global. Two SecurePrompt deployments in two databases of one cluster
/// could therefore still collide on the same role — but they would also be
/// fighting over one role's password, which is a misconfiguration this lock is
/// not the right place to paper over. Within one database, which is every
/// supported topology, this serialises the step completely.
///
/// The value is arbitrary but must never collide with sqlx's own key, which is
/// derived from the database name via `crc32`, so it is always positive and
/// below 2^32. This one is far above that.
pub const MIGRATION_STEP_LOCK_KEY: i64 = 0x5350_4442_5F53_5445;

/// Set a role's login password.
///
/// # Why the statement is built server-side
///
/// `ALTER ROLE ... PASSWORD` accepts no bind parameter, so the statement has to
/// be built as text. Both the identifier and the literal are quoted BY THE
/// SERVER (`format('%I', ...)` / `format('%L', ...)`) rather than concatenated
/// here, so a password containing a quote is quoted correctly instead of ending
/// the literal.
///
/// # Why the password is passed through `set_config` and not interpolated
///
/// The earlier version built the whole `ALTER ROLE ... PASSWORD 'literal'` text
/// server-side and then executed THAT text, and the comment claimed it was
/// "never logged: it contains the credential". That was true only of this
/// process's own `tracing` output. MEASURED on postgres:16 with the routine
/// audit setting `log_statement = 'ddl'`:
///
/// ```text
/// LOG:  statement: ALTER ROLE mr7_race_probe WITH LOGIN PASSWORD 'super_secret_value_12345';
/// ```
///
/// The password is now handed over as a bind parameter to `set_config(...,
/// true)` inside a transaction and read back with `current_setting`, which is
/// the technique `scripts/db/setup-app-role.sh` already used. The DDL text
/// Postgres logs contains `current_setting('sp.pw')`, not the credential;
/// `local = true` drops the setting at commit so it does not linger on a
/// pooled connection.
pub async fn set_role_password(pool: &PgPool, role: &str, password: &str) -> anyhow::Result<()> {
    let mut conn = pool.acquire().await?;
    set_role_password_on(&mut conn, role, password).await
}

async fn set_role_password_on(
    conn: &mut PgConnection,
    role: &str,
    password: &str,
) -> anyhow::Result<()> {
    use sqlx::Connection as _;

    let mut tx = conn.begin().await?;

    sqlx::query("SELECT set_config('sp.role', $1, true), set_config('sp.pw', $2, true)")
        .bind(role)
        .bind(password)
        .execute(&mut *tx)
        .await?;

    // MEASURED on postgres:16 — the two failures worth naming.
    //
    // 42501: a CREATEROLE role may alter only roles it CREATED (it gets ADMIN
    //   OPTION on those implicitly). So this succeeds when the migration role is
    //   a superuser, or when it is the role that ran 001_init.sql on a fresh
    //   cluster and thus created `secureprompt_app`. It fails on managed
    //   Postgres where an administrator created the role separately — a
    //   deployment shape, not a bug.
    // XX000 `tuple concurrently updated`: two migration steps altering the same
    //   cluster-global role at once. `run_migration_step` serialises on
    //   MIGRATION_STEP_LOCK_KEY so this cannot happen within one database;
    //   reaching it means two databases share the role.
    let outcome = sqlx::raw_sql(
        "DO $$
         BEGIN
             EXECUTE format('ALTER ROLE %I WITH LOGIN PASSWORD %L',
                            current_setting('sp.role'), current_setting('sp.pw'));
         END $$;",
    )
    .execute(&mut *tx)
    .await;

    if let Err(e) = outcome {
        let detail = if e.to_string().contains("tuple concurrently updated") {
            "Two migration steps altered this cluster-global role at the same \
             time. Within one database the step serialises on an advisory lock, \
             so this means two databases on this cluster share the role."
        } else {
            "In Postgres 16 a CREATEROLE role may only alter roles it created. \
             Either run this step as a superuser, or provision the role out of \
             band with scripts/db/setup-app-role.sh and leave \
             SECUREPROMPT_APP_DB_PASSWORD unset so this step does not try."
        };
        return Err(anyhow::anyhow!(
            "could not set the password on role `{role}`: {e}. {detail}"
        ));
    }

    tx.commit().await?;

    tracing::info!(role, "runtime role password set");
    Ok(())
}

/// The whole of `--migrate-only`: apply the schema as the owner, then make the
/// runtime role usable.
///
/// Refuses outright if the connected role cannot migrate. Without that check
/// `--migrate-only` pointed at the runtime URL would apply nothing and exit 0,
/// and the first sign of trouble would be the API refusing to boot against a
/// schema this step was supposed to have prepared.
pub async fn run_migration_step(pool: &PgPool, app_password: Option<&str>) -> anyhow::Result<()> {
    run_migration_step_for_role(pool, RUNTIME_ROLE, app_password).await
}

/// `run_migration_step` with the runtime role named explicitly.
///
/// Exists so the step's own guarantees can be tested against a throwaway role.
/// `RUNTIME_ROLE` is cluster-global and every other test in `db_role_split`
/// depends on its state, so a test that made `secureprompt_app` a member of a
/// BYPASSRLS role — the only way to reach the powerless assertion THROUGH this
/// function — would break the suite around it. With the role as a parameter the
/// assertion is reachable, and deleting it from here turns a test red.
pub async fn run_migration_step_for_role(
    pool: &PgPool,
    runtime_role: &str,
    app_password: Option<&str>,
) -> anyhow::Result<()> {
    let mut conn = pool.acquire().await?;

    if schema_authority_on(&mut conn).await? != SchemaAuthority::Owner {
        let who: String = sqlx::query_scalar("SELECT current_user::text")
            .fetch_one(&mut *conn)
            .await?;
        anyhow::bail!(
            "--migrate-only is connected as `{who}`, which has no CREATE on \
             schema public and therefore cannot apply migrations. Point \
             DATABASE_URL at the owner/migrator role for this step."
        );
    }

    // EVERYTHING below runs under one advisory lock, held on THIS connection,
    // which is also the connection the work is done on — so a caller cannot
    // deadlock itself by holding a lock connection while waiting for a second
    // one out of an exhausted pool. See MIGRATION_STEP_LOCK_KEY.
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(MIGRATION_STEP_LOCK_KEY)
        .execute(&mut *conn)
        .await?;

    let outcome = locked_migration_step(&mut conn, runtime_role, app_password).await;

    // Released explicitly rather than left to session teardown: this connection
    // goes back to a pool and may be reused, and a session-level advisory lock
    // outlives the transaction that took it.
    if let Err(e) = sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(MIGRATION_STEP_LOCK_KEY)
        .execute(&mut *conn)
        .await
    {
        tracing::warn!(error = %e, "could not release the migration-step advisory lock");
    }

    outcome
}

async fn locked_migration_step(
    conn: &mut PgConnection,
    runtime_role: &str,
    app_password: Option<&str>,
) -> anyhow::Result<()> {
    apply_as_owner(&mut *conn).await?;

    if let Some(password) = app_password {
        set_role_password_on(&mut *conn, runtime_role, password).await?;
    }

    assert_role_is_powerless_on(&mut *conn, runtime_role).await?;
    Ok(())
}

/// The mandated powerless-assertion, in the same shape as
/// `scripts/ci/create-nonsuperuser-role.sh`, `scripts/db/setup-app-role.sh` and
/// the closing block of `034_app_role_runtime_grants.sql` — all four ask the
/// same three questions, including the membership one, and
/// `scripts/ci/check-powerless-assertions-agree.sh` fails if one of them stops.
///
/// Repeated here rather than left to the migration because this is the last
/// thing that runs before a deployment starts serving, and because 034 only
/// executes when it is pending — on a database already at head it is a no-op,
/// so its assertion would never run again. A role that acquired SUPERUSER or
/// BYPASSRLS after 034 was applied would otherwise go unnoticed forever, and a
/// deployment that enforces no tenancy at all reports nothing by itself.
pub async fn assert_runtime_role_is_powerless(pool: &PgPool) -> anyhow::Result<()> {
    assert_role_is_powerless(pool, RUNTIME_ROLE).await
}

/// Three questions, because two of them are not enough.
///
/// 1. `rolsuper OR rolbypassrls` — the obvious one. Either exempts the role
///    from row-level security outright.
/// 2. **Role membership.** MEASURED while exercising
///    `scripts/db/setup-app-role.sh`: granting `secureprompt_app` membership of
///    a role holding `CREATE ON SCHEMA public` leaves question 3 answering
///    **false**, because the runtime role is NOINHERIT and does not pick the
///    privilege up automatically. Both attribute checks call it powerless.
///
///    NOINHERIT only means the privileges are not AUTOMATIC. `SET ROLE` still
///    reaches them, over an ordinary connection, with no password — so a
///    BYPASSRLS role the runtime role is a member of is BYPASSRLS, one
///    statement away. Membership is the escape hatch neither attribute
///    reports, so it is asked about directly.
/// 3. `has_schema_privilege(..., 'CREATE')` — a role that can create can own,
///    and `FORCE ROW LEVEL SECURITY` filters an owner rather than exempting it,
///    so ownership is a second undesigned access path.
///
/// Asked in that order on purpose. A membership-conferred privilege is
/// invisible to question 3, so if 3 fired first its message would have to guess
/// at the cause — which is exactly how 034's error came to blame membership for
/// the one thing membership provably cannot cause.
pub async fn assert_role_is_powerless(pool: &PgPool, role: &str) -> anyhow::Result<()> {
    let mut conn = pool.acquire().await?;
    assert_role_is_powerless_on(&mut conn, role).await
}

pub async fn assert_role_is_powerless_on(
    conn: &mut PgConnection,
    role: &str,
) -> anyhow::Result<()> {
    let privileged: Option<bool> =
        sqlx::query_scalar("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = $1")
            .bind(role)
            .fetch_optional(&mut *conn)
            .await?;

    match privileged {
        None => anyhow::bail!(
            "role `{role}` does not exist after the migrations ran. The \
             application has nothing to connect as."
        ),
        Some(true) => anyhow::bail!(
            "role `{role}` has SUPERUSER or BYPASSRLS. Every row-level security \
             policy in this schema would be inert at runtime, and nothing else \
             would report it. Refusing to complete the migration step."
        ),
        Some(false) => {}
    }

    let memberships: Vec<String> = sqlx::query_scalar(
        "SELECT grantee.rolname::text
           FROM pg_auth_members m
           JOIN pg_roles member  ON member.oid = m.member
           JOIN pg_roles grantee ON grantee.oid = m.roleid
          WHERE member.rolname = $1
          ORDER BY grantee.rolname",
    )
    .bind(role)
    .fetch_all(&mut *conn)
    .await?;

    if !memberships.is_empty() {
        anyhow::bail!(
            "role `{role}` is a member of: {}. NOINHERIT does not close this — \
             `SET ROLE` reaches those privileges from an ordinary connection, so \
             whatever they hold, the runtime role effectively holds. Revoke the \
             membership: REVOKE <role> FROM {role};",
            memberships.join(", ")
        );
    }

    let can_create: bool =
        sqlx::query_scalar("SELECT has_schema_privilege($1, 'public', 'CREATE')")
            .bind(role)
            .fetch_one(&mut *conn)
            .await?;
    if can_create {
        // Name the grantee rather than guess at it. Membership has already been
        // ruled out above, so the grant is a direct one or one held by PUBLIC.
        let grantees: Option<String> = sqlx::query_scalar(
            "SELECT string_agg(DISTINCT
                        CASE WHEN a.grantee = 0 THEN 'PUBLIC'
                             ELSE pg_get_userbyid(a.grantee) END, ', ')
               FROM pg_namespace n,
                    aclexplode(COALESCE(n.nspacl, acldefault('n', n.nspowner))) a
              WHERE n.nspname = 'public'
                AND a.privilege_type = 'CREATE'",
        )
        .fetch_one(&mut *conn)
        .await?;

        anyhow::bail!(
            "role `{role}` has CREATE on schema public. It can create — and \
             therefore own — a table, and an owner is filtered by FORCE ROW \
             LEVEL SECURITY rather than exempt from it. CREATE on schema public \
             is held by: {}. (PUBLIC reaches every role, and is the default on \
             any database created before PostgreSQL 15.)",
            grantees.unwrap_or_else(|| "(nothing in pg_namespace.nspacl)".into())
        );
    }

    tracing::info!(
        role,
        "runtime role verified NOSUPERUSER, NOBYPASSRLS, no role memberships, no CREATE on public"
    );
    Ok(())
}
