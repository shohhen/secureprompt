//! Applying the Postgres schema, and deciding whether this process may.
//!
//! Moved out of `main.rs` so it can be tested against a real non-owner
//! connection. `main.rs` is a binary crate: nothing there is reachable from
//! `tests/`, and the branch that matters here — what happens when the
//! connected role is NOT allowed to change the schema — cannot be exercised
//! any other way.

use sqlx::PgPool;

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
    let can_create: bool =
        sqlx::query_scalar("SELECT has_schema_privilege(current_user, 'public', 'CREATE')")
            .fetch_one(pool)
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
///    table by marking every embedded migration as already applied.
pub async fn ensure_pg_migrations(pool: &PgPool) -> anyhow::Result<()> {
    match schema_authority(pool).await? {
        SchemaAuthority::Owner => apply_as_owner(pool).await,
        SchemaAuthority::Runtime => {
            tracing::info!(
                "connected role has no CREATE on schema public — not applying \
                 migrations. This is the expected shape under the DB role \
                 split; the owner role applies them in a separate step."
            );
            verify_schema_at_head(pool).await
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
async fn verify_schema_at_head(pool: &PgPool) -> anyhow::Result<()> {
    let tracking_exists: bool =
        sqlx::query_scalar("SELECT to_regclass('public._sqlx_migrations') IS NOT NULL")
            .fetch_one(pool)
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
            .fetch_all(pool)
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

    tracing::info!(
        applied = applied.len(),
        "Postgres schema is at the embedded migration head"
    );
    Ok(())
}

/// The `Owner` branch. Byte-identical to what boot has always done.
async fn apply_as_owner(pool: &PgPool) -> anyhow::Result<()> {
    let workspaces_exists: bool =
        sqlx::query_scalar("SELECT to_regclass('public.workspaces') IS NOT NULL")
            .fetch_one(pool)
            .await?;
    let tracking_exists: bool =
        sqlx::query_scalar("SELECT to_regclass('public._sqlx_migrations') IS NOT NULL")
            .fetch_one(pool)
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
        .execute(pool)
        .await?;
        for m in MIGRATOR.iter() {
            sqlx::query(
                "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) \
                 VALUES ($1, $2, TRUE, $3, 0) ON CONFLICT (version) DO NOTHING",
            )
            .bind(m.version)
            .bind(m.description.as_ref())
            .bind(&m.checksum[..])
            .execute(pool)
            .await?;
        }
    }

    MIGRATOR.run(pool).await?;
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

/// Set a role's login password.
///
/// `ALTER ROLE ... PASSWORD` accepts no bind parameter, so the statement has to
/// be built as text. It is built BY THE SERVER — `format('%I', $1)` for the
/// identifier and `format('%L', $2)` for the literal — rather than by string
/// concatenation here, so a password containing a quote is quoted correctly
/// instead of ending the literal. The resulting statement is never logged: it
/// contains the credential.
///
/// This exists because there is nowhere else the runtime password can come
/// from. `001_init.sql` creates the role with a fixed placeholder, and a
/// migration cannot read a deployment's environment.
pub async fn set_role_password(pool: &PgPool, role: &str, password: &str) -> anyhow::Result<()> {
    let statement: String = sqlx::query_scalar(
        "SELECT format('ALTER ROLE %I WITH LOGIN PASSWORD %L', $1::text, $2::text)",
    )
    .bind(role)
    .bind(password)
    .fetch_one(pool)
    .await?;

    // MEASURED on postgres:16 — the failure worth naming. A CREATEROLE role may
    // alter only roles it CREATED (it gets ADMIN OPTION on those implicitly):
    //
    //   creator creates a role, then alters it   -> ALTER ROLE
    //   creator alters a role it did not create  -> 42501 permission denied
    //     "the current user must have the CREATEROLE attribute and the ADMIN
    //      option on the role"
    //
    // So this succeeds when the migration role is a superuser, or when it is
    // the role that ran 001_init.sql on a fresh cluster and thus created
    // `secureprompt_app`. It fails on managed Postgres where an administrator
    // created the role separately — a deployment shape, not a bug, and the raw
    // message does not tell the operator which of the two to fix.
    sqlx::raw_sql(&statement).execute(pool).await.map_err(|e| {
        anyhow::anyhow!(
            "could not set the password on role `{role}`: {e}. In Postgres 16 a \
             CREATEROLE role may only alter roles it created. Either run this \
             step as a superuser, or provision the role out of band with \
             scripts/db/setup-app-role.sh and leave SECUREPROMPT_APP_DB_PASSWORD \
             unset so this step does not try."
        )
    })?;

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
    if schema_authority(pool).await? != SchemaAuthority::Owner {
        let who: String = sqlx::query_scalar("SELECT current_user::text")
            .fetch_one(pool)
            .await?;
        anyhow::bail!(
            "--migrate-only is connected as `{who}`, which has no CREATE on \
             schema public and therefore cannot apply migrations. Point \
             DATABASE_URL at the owner/migrator role for this step."
        );
    }

    apply_as_owner(pool).await?;

    if let Some(password) = app_password {
        set_role_password(pool, RUNTIME_ROLE, password).await?;
    }

    assert_runtime_role_is_powerless(pool).await?;
    Ok(())
}

/// The mandated powerless-assertion, in the same shape as
/// `scripts/ci/create-nonsuperuser-role.sh` and the closing block of
/// `034_app_role_runtime_grants.sql`.
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
/// 2. `has_schema_privilege(..., 'CREATE')` — a role that can create can own,
///    and `FORCE ROW LEVEL SECURITY` filters an owner rather than exempting it,
///    so ownership is a second undesigned access path.
/// 3. **Role membership.** MEASURED while exercising
///    `scripts/db/setup-app-role.sh`: granting `secureprompt_app` membership of
///    a role holding `CREATE ON SCHEMA public` leaves question 2 answering
///    **false**, because the runtime role is NOINHERIT and does not pick the
///    privilege up automatically. Both attribute checks call it powerless.
///
///    NOINHERIT only means the privileges are not AUTOMATIC. `SET ROLE` still
///    reaches them, over an ordinary connection, with no password — so a
///    BYPASSRLS role the runtime role is a member of is BYPASSRLS, one
///    statement away. Membership is the escape hatch neither attribute
///    reports, so it is asked about directly.
pub async fn assert_role_is_powerless(pool: &PgPool, role: &str) -> anyhow::Result<()> {
    let privileged: Option<bool> =
        sqlx::query_scalar("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = $1")
            .bind(role)
            .fetch_optional(pool)
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

    let can_create: bool =
        sqlx::query_scalar("SELECT has_schema_privilege($1, 'public', 'CREATE')")
            .bind(role)
            .fetch_one(pool)
            .await?;
    if can_create {
        anyhow::bail!(
            "role `{role}` has CREATE on schema public. It can create — and \
             therefore own — a table, and an owner is filtered by FORCE ROW \
             LEVEL SECURITY rather than exempt from it."
        );
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
    .fetch_all(pool)
    .await?;

    if !memberships.is_empty() {
        anyhow::bail!(
            "role `{role}` is a member of: {}. NOINHERIT does not close this — \
             `SET ROLE` reaches those privileges from an ordinary connection, so \
             whatever they hold, the runtime role effectively holds. Revoke the \
             membership.",
            memberships.join(", ")
        );
    }

    tracing::info!(
        role,
        "runtime role verified NOSUPERUSER, NOBYPASSRLS, no CREATE on public, no role memberships"
    );
    Ok(())
}
