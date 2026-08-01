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
