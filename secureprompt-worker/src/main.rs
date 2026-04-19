use anyhow::Context;
use secureprompt_common::{
    config::{
        AppConfig, ClickhouseConfig, DatabaseConfig, JwtConfig, RedisConfig, ServerConfig,
        TelemetryConfig,
    },
    telemetry::init_telemetry,
};
use tokio_cron_scheduler::{Job, JobScheduler};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = AppConfig {
        database: DatabaseConfig {
            url: std::env::var("DATABASE_URL").unwrap_or_else(|_| {
                "postgres://secureprompt:secureprompt@localhost:5432/secureprompt".into()
            }),
            max_connections: 10,
        },
        redis: RedisConfig {
            url: std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".into()),
            max_connections: 10,
        },
        telemetry: TelemetryConfig {
            otel_enabled: false,
            prometheus_enabled: false,
            log_level: std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".into()),
        },
        server: ServerConfig {
            host: "0.0.0.0".into(),
            port: 8081,
        },
        clickhouse: ClickhouseConfig {
            url: std::env::var("CLICKHOUSE_URL")
                .unwrap_or_else(|_| "http://localhost:8123".into()),
            database: std::env::var("CLICKHOUSE_DATABASE")
                .unwrap_or_else(|_| "secureprompt".into()),
        },
        // The worker doesn't issue or verify JWTs, but AppConfig is a shared
        // struct. Default placeholder TTLs + empty secret are acceptable here
        // because no JWT code path runs in the worker binary.
        jwt: JwtConfig {
            secret: std::env::var("SECUREPROMPT_JWT_SECRET").unwrap_or_default(),
            access_ttl_secs: JwtConfig::DEFAULT_ACCESS_TTL_SECS,
            refresh_ttl_secs: JwtConfig::DEFAULT_REFRESH_TTL_SECS,
        },
    };

    init_telemetry(&config.telemetry);

    let ch_client = clickhouse::Client::default()
        .with_url(&config.clickhouse.url)
        .with_database(&config.clickhouse.database)
        .with_setting("async_insert", "1")
        .with_setting("wait_for_async_insert", "1");

    // Apply ClickHouse DDL migrations on startup (D-06, D-12)
    apply_migrations(&ch_client)
        .await
        .context("ClickHouse migration failed")?;

    tracing::info!("ClickHouse migrations applied");

    // Daily OPTIMIZE FINAL on compliance tables (D-12)
    // Cron expression: "sec min hour day-of-month month day-of-week"
    // "0 0 2 * * *" = every day at 02:00:00
    let sched = JobScheduler::new().await?;
    let ch_optimize = ch_client.clone();

    sched.add(
        Job::new_async("0 0 2 * * *", move |_uuid, _l| {
            let ch = ch_optimize.clone();
            Box::pin(async move {
                for table in &["request_events", "policy_events"] {
                    let sql = format!("OPTIMIZE TABLE {table} FINAL");
                    match ch.query(&sql).execute().await {
                        Ok(()) => tracing::info!(table, "OPTIMIZE FINAL completed"),
                        Err(e) => tracing::error!(table, error = %e, "OPTIMIZE FINAL failed"),
                    }
                }
            })
        })
        .context("Failed to create OPTIMIZE FINAL job")?,
    )
    .await
    .context("Failed to schedule OPTIMIZE FINAL job")?;

    sched.start().await?;

    tracing::info!("secureprompt-worker running; OPTIMIZE FINAL scheduled at 02:00 daily");
    tokio::signal::ctrl_c().await?;
    tracing::info!("secureprompt-worker shutting down");

    Ok(())
}

/// Apply pending ClickHouse DDL migrations from the migrations directory.
/// Tracks applied migrations in the `_schema_migrations` table (idempotent).
/// MIGRATIONS_DIR default: "clickhouse/migrations" (relative to working directory at runtime).
async fn apply_migrations(client: &clickhouse::Client) -> anyhow::Result<()> {
    // Ensure the tracking table exists first (bootstrap)
    client
        .query(
            "CREATE TABLE IF NOT EXISTS _schema_migrations \
             (version String, applied_at DateTime DEFAULT now()) \
             ENGINE = MergeTree() ORDER BY version",
        )
        .execute()
        .await
        .context("Failed to create _schema_migrations table")?;

    let migrations_dir = std::env::var("CLICKHOUSE_MIGRATIONS_DIR")
        .unwrap_or_else(|_| "clickhouse/migrations".into());

    let mut entries: Vec<_> = std::fs::read_dir(&migrations_dir)
        .with_context(|| format!("Cannot read migrations dir: {migrations_dir}"))?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map_or(false, |ext| ext.eq_ignore_ascii_case("sql"))
        })
        .collect();

    // Sort lexicographically so 001_ < 002_ etc.
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let version = entry.file_name().to_string_lossy().into_owned();

        // Check if already applied
        let count: u64 = client
            .query("SELECT count() FROM _schema_migrations WHERE version = ?")
            .bind(&version)
            .fetch_one()
            .await
            .with_context(|| format!("Failed to check migration status for {version}"))?;

        if count > 0 {
            tracing::debug!(version, "migration already applied; skipping");
            continue;
        }

        let sql = std::fs::read_to_string(&path)
            .with_context(|| format!("Cannot read migration file: {}", path.display()))?;

        // Execute each statement separated by semicolons
        // ClickHouse HTTP interface handles one statement per request
        for statement in sql.split(';') {
            let stmt = statement.trim();
            if stmt.is_empty() || stmt.starts_with("--") {
                continue;
            }
            client
                .query(stmt)
                .execute()
                .await
                .with_context(|| format!("Migration {version} statement failed: {stmt:.80}"))?;
        }

        client
            .query("INSERT INTO _schema_migrations (version) VALUES (?)")
            .bind(&version)
            .execute()
            .await
            .with_context(|| format!("Failed to record migration {version}"))?;

        tracing::info!(version, "applied ClickHouse migration");
    }

    Ok(())
}

/// Acquire the dbt single-run lock (D-10 / DBT-05).
/// Inserts a row into `_dbt_lock` with a fixed lock_key.
/// Returns Ok(()) if the lock is not held.
/// Returns Err if the lock is already held — caller must abort the dbt invocation.
///
/// LIMITATION: ClickHouse ReplacingMergeTree async merges mean two near-simultaneous
/// inserts may both succeed before deduplication. In Phase 4, dbt runs are CI/operator-
/// triggered (not worker-triggered), so human coordination is the primary guard.
/// This function provides a best-effort check; see RESEARCH.md Open Question 2.
pub async fn try_acquire_dbt_lock(client: &clickhouse::Client) -> anyhow::Result<()> {
    const LOCK_KEY: &str = "global";

    // Check if lock row already exists (SELECT FINAL to force merge read)
    let count: u64 = client
        .query("SELECT count() FROM _dbt_lock FINAL WHERE lock_key = ?")
        .bind(LOCK_KEY)
        .fetch_one()
        .await
        .context("Failed to query _dbt_lock")?;

    if count > 0 {
        anyhow::bail!(
            "_dbt_lock is held (count={}); another dbt run may be in progress. \
             Delete the lock row to unblock: \
             ALTER TABLE _dbt_lock DELETE WHERE lock_key = 'global'",
            count
        );
    }

    // Insert lock row — INSERT-or-fail pattern (D-10)
    let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "secureprompt-worker".into());
    client
        .query("INSERT INTO _dbt_lock (lock_key, locked_by) VALUES (?, ?)")
        .bind(LOCK_KEY)
        .bind(hostname.as_str())
        .execute()
        .await
        .context("Failed to acquire _dbt_lock")?;

    tracing::info!("_dbt_lock acquired for dbt run");
    Ok(())
}

#[cfg(test)]
mod tests;
