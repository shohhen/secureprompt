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

/// Apply pending Postgres migrations on startup.
///
/// Two cases to handle:
/// 1. **Fresh DB** (no `workspaces` table): `MIGRATOR.run` creates everything
///    from scratch, including the `_sqlx_migrations` tracking table.
/// 2. **Existing DB without sqlx tracking** (the case we just hit — someone
///    applied migrations manually via `psql`, then redeployed): the tables
///    are already there, but `_sqlx_migrations` is missing, so a naive
///    `MIGRATOR.run` would try to recreate `workspaces` and fail. We
///    detect this and bootstrap the tracking table by marking every
///    embedded migration as already applied.
pub async fn ensure_pg_migrations(pool: &PgPool) -> anyhow::Result<()> {
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
