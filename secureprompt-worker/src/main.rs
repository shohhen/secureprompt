mod metrics;
mod tasks;

use anyhow::Context;
use deadpool_redis::redis::cmd;
use metrics::WorkerMetrics;
use secureprompt_common::{
    config::{
        AppConfig, ClickhouseConfig, DatabaseConfig, JwtConfig, LicenseConfig, RedisConfig,
        ServerConfig, TelemetryConfig,
    },
    tasks::{TaskEnvelope, ALL_QUEUES},
    telemetry::init_telemetry,
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_cron_scheduler::{Job, JobScheduler};

/// Whether the `/metrics` endpoint should be bound.
/// `SECUREPROMPT_WORKER_METRICS_ENABLED` — default `true`; any of
/// `"false"`/`"0"`/`"no"` (case-insensitive) disables it.
fn metrics_enabled_from_env() -> bool {
    match std::env::var("SECUREPROMPT_WORKER_METRICS_ENABLED") {
        Ok(v) => !matches!(v.trim().to_ascii_lowercase().as_str(), "false" | "0" | "no"),
        Err(_) => true,
    }
}

/// Port the `/metrics` endpoint binds to. `WORKER_METRICS_PORT` — default
/// `9091`. Falls back to the default on missing/unparseable values.
fn metrics_port_from_env() -> u16 {
    std::env::var("WORKER_METRICS_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(9091)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let metrics_enabled = metrics_enabled_from_env();
    let metrics_port = metrics_port_from_env();

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
            prometheus_enabled: metrics_enabled,
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
        public_signup_enabled: AppConfig::public_signup_enabled_from_env(),
        // Worker doesn't serve `/v1/chat/completions`, so this is a no-op
        // here — populated for struct-init completeness.
        chat_debug_mode: AppConfig::chat_debug_mode_from_env(),
        // Same rationale: the policy-evaluation fallback only fires in the
        // gateway request path, but AppConfig is shared so the field has
        // to be set. Defer to the env var so worker + API agree.
        redact_when_no_rules: AppConfig::redact_when_no_rules_from_env(),
        // The worker never verifies licenses (no gateway request path), so the
        // empty/disabled default is correct here — no pubkey/token reads matter.
        license: LicenseConfig::default(),
    };

    init_telemetry(&config.telemetry);

    // Prometheus `/metrics` endpoint (KPI-2 monitoring, Task 4). The worker
    // previously bound no HTTP server at all, so nothing was scrapable.
    let metrics = Arc::new(WorkerMetrics::default());
    if config.telemetry.prometheus_enabled {
        let metrics_router = metrics::router(metrics.clone());
        tokio::spawn(async move {
            let addr = format!("0.0.0.0:{metrics_port}");
            match tokio::net::TcpListener::bind(&addr).await {
                Ok(listener) => {
                    tracing::info!(addr = %addr, "secureprompt-worker metrics endpoint listening");
                    if let Err(e) = axum::serve(listener, metrics_router).await {
                        tracing::error!(error = %e, "metrics server exited");
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, addr = %addr, "failed to bind metrics endpoint");
                }
            }
        });
    } else {
        tracing::info!(
            "secureprompt-worker metrics endpoint disabled (SECUREPROMPT_WORKER_METRICS_ENABLED=false)"
        );
    }

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
    let metrics_optimize = metrics.clone();

    sched.add(
        Job::new_async("0 0 2 * * *", move |_uuid, _l| {
            let ch = ch_optimize.clone();
            let metrics = metrics_optimize.clone();
            Box::pin(async move {
                let started = Instant::now();
                let mut all_ok = true;
                for table in &["request_events", "policy_events"] {
                    let sql = format!("OPTIMIZE TABLE {table} FINAL");
                    match ch.query(&sql).execute().await {
                        Ok(()) => tracing::info!(table, "OPTIMIZE FINAL completed"),
                        Err(e) => {
                            all_ok = false;
                            tracing::error!(table, error = %e, "OPTIMIZE FINAL failed");
                        }
                    }
                }
                metrics.record_job("optimize_final", started.elapsed(), all_ok);
            })
        })
        .context("Failed to create OPTIMIZE FINAL job")?,
    )
    .await
    .context("Failed to schedule OPTIMIZE FINAL job")?;

    // Phase 6 / Plan 06-01 — API key rotation cleanup cron (D-17, AUTH-08).
    // Runs daily at 03:00 to move expired-grace-window rotating keys to 'revoked'.
    let pg_pool_cleanup = sqlx::PgPool::connect(&config.database.url)
        .await
        .context("Worker: failed to connect to Postgres for rotation cleanup")?;

    let metrics_rotation = metrics.clone();
    sched.add(
        Job::new_async("0 0 3 * * *", move |_uuid, _l| {
            let pool = pg_pool_cleanup.clone();
            let metrics = metrics_rotation.clone();
            Box::pin(async move {
                let started = Instant::now();
                let result = sqlx::query(
                    "UPDATE api_keys
                     SET status = 'revoked', revoked_at = NOW()
                     WHERE status = 'rotating'
                       AND rotated_at + (rotation_grace_secs || ' seconds')::INTERVAL <= NOW()"
                )
                .execute(&pool)
                .await;
                let ok = result.is_ok();
                match result {
                    Ok(r) => tracing::info!(rows_affected = r.rows_affected(), "rotation cleanup complete"),
                    Err(e) => tracing::error!(error = %e, "rotation cleanup failed"),
                }
                metrics.record_job("rotation_cleanup", started.elapsed(), ok);
            })
        })
        .context("Failed to create rotation cleanup job")?,
    )
    .await
    .context("Failed to schedule rotation cleanup job")?;

    sched.start().await?;

    // Phase 6 / Plan 06-04 — Redis task queue drain loop (RDS-03, D-20).
    // Runs concurrently with the cron scheduler via tokio::spawn.
    let redis_pool_drain = {
        let cfg = &config.redis;
        deadpool_redis::Config::from_url(&cfg.url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .context("Worker: failed to create Redis pool for drain loop")?
    };

    // Phase 7 / Plan 07-04 — Qdrant client for RAG indexing (QD-01..03).
    let qdrant_url = std::env::var("QDRANT_URL")
        .unwrap_or_else(|_| "http://qdrant:6334".into());
    let qdrant = std::sync::Arc::new(
        qdrant_client::Qdrant::from_url(&qdrant_url)
            .build()
            .context("Failed to create Qdrant client")?,
    );

    let ml_sidecar_url = std::env::var("ML_SIDECAR_URL")
        .unwrap_or_else(|_| "http://secureprompt-ml:8080".into());
    let ml_http = reqwest::Client::new();

    let metrics_drain = metrics.clone();
    tokio::spawn(async move {
        run_queue_drain(redis_pool_drain, qdrant, ml_http, ml_sidecar_url, metrics_drain).await;
    });

    tracing::info!("Task queue drain loop started");

    tracing::info!("secureprompt-worker running; OPTIMIZE FINAL at 02:00 + rotation cleanup at 03:00 daily");
    tokio::signal::ctrl_c().await?;
    tracing::info!("secureprompt-worker shutting down");

    Ok(())
}

/// Blocking poll loop over all task queues.
/// Uses BLPOP with a 5-second timeout to multiplex queues without busy-waiting.
/// Runs forever in its own tokio task until the process exits.
async fn run_queue_drain(
    redis_pool: deadpool_redis::Pool,
    qdrant: std::sync::Arc<qdrant_client::Qdrant>,
    ml_client: reqwest::Client,
    ml_sidecar_url: String,
    metrics: Arc<WorkerMetrics>,
) {
    loop {
        let mut conn = match redis_pool.get().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "redis checkout failed in drain loop");
                metrics.record_drain_error();
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
        };

        // BLPOP blocks up to 5s on any of the queues.
        // Returns (queue_name, json_payload) or None on timeout.
        let result: Option<(String, String)> = cmd("BLPOP")
            .arg(ALL_QUEUES.as_slice())
            .arg(5u64) // timeout in seconds
            .query_async(&mut conn)
            .await
            .unwrap_or(None);

        if let Some((_queue_name, json)) = result {
            match serde_json::from_str::<TaskEnvelope>(&json) {
                Ok(task) => {
                    dispatch_task(task, &qdrant, &ml_client, &ml_sidecar_url, &metrics).await;
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        body_preview = %&json[..json.len().min(200)],
                        "invalid task envelope — dropping"
                    );
                    metrics.record_drain_error();
                }
            }
        }
        // On timeout (None): loop again immediately — no sleep needed.
    }
}

/// Dispatch a deserialized TaskEnvelope to the appropriate handler.
async fn dispatch_task(
    task: TaskEnvelope,
    qdrant: &qdrant_client::Qdrant,
    ml_client: &reqwest::Client,
    ml_sidecar_url: &str,
    metrics: &WorkerMetrics,
) {
    use secureprompt_common::tasks::task_types;

    tracing::info!(
        task_type = %task.task_type,
        workspace_id = %task.workspace_id,
        retry_count = task.retry_count,
        "dispatching task"
    );

    match task.task_type.as_str() {
        task_types::ANALYTICS_FLUSH => {
            tracing::debug!("analytics.flush — no-op stub (Phase 7 implementation)");
            metrics.record_task(task_types::ANALYTICS_FLUSH, "stub");
        }
        task_types::AUDIT_EXPORT => {
            tracing::debug!("audit.export — no-op stub (Phase 7 implementation)");
            metrics.record_task(task_types::AUDIT_EXPORT, "stub");
        }
        task_types::RETENTION_PURGE => {
            tracing::debug!("retention.purge — no-op stub (Phase 7 implementation)");
            metrics.record_task(task_types::RETENTION_PURGE, "stub");
        }
        task_types::API_KEY_ROTATION_CLEANUP => {
            tracing::debug!("api_key.rotation_cleanup — handled by cron in Plan 06-01");
            metrics.record_task(task_types::API_KEY_ROTATION_CLEANUP, "stub");
        }
        task_types::INDEX_POLICY_RULE => {
            let ok = tasks::index_policy_rule::handle_index_policy_rule(
                &task,
                ml_client,
                qdrant,
                ml_sidecar_url,
            )
            .await;
            metrics.record_task(
                task_types::INDEX_POLICY_RULE,
                if ok { "ok" } else { "error" },
            );
        }
        unknown => {
            tracing::warn!(task_type = %unknown, "unknown task type — dropping");
            // Fixed label, never the raw `unknown` string — task_type is
            // attacker/bug-controlled free text and would blow up label
            // cardinality if used directly.
            metrics.record_task("unknown", "unknown");
        }
    }
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

        // Execute each statement separated by semicolons.
        // ClickHouse HTTP interface handles one statement per request.
        //
        // Important: strip `--` line comments BEFORE splitting on `;`.
        // The previous splitter ran `sql.split(';')` directly, which broke
        // any migration whose comments contained a `;` (e.g.
        // "(debug mode; embeddings served by stubs)") — the splitter cut
        // mid-comment and ClickHouse choked on the orphaned tail. The
        // earlier `starts_with("--")` guard also dropped real DDL because
        // every statement in 001 opens with a `-- N. ...` header comment.
        // Rule: comments are advisory text, not a query-language token —
        // strip them first, then split.
        let stripped = strip_sql_line_comments(&sql);
        for statement in stripped.split(';') {
            let stmt = statement.trim();
            if stmt.is_empty() {
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

/// Strip `--`-style line comments from a SQL string, preserving the
/// surrounding statement structure (newlines kept, code untouched).
///
/// We only strip line comments because:
///   * Block comments (`/* ... */`) aren't used in our migrations.
///   * String literals in our migrations don't contain `--`, so a naive
///     "first `--` to end of line" pass is safe and avoids the cost of a
///     full SQL tokenizer for a few-hundred-line file.
fn strip_sql_line_comments(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    for line in sql.lines() {
        let cut = line.find("--").map_or(line.len(), |i| i);
        out.push_str(&line[..cut]);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod migration_tests {
    use super::strip_sql_line_comments;

    #[test]
    fn strips_full_line_comment() {
        let input = "-- header\nSELECT 1;\n";
        assert_eq!(strip_sql_line_comments(input).trim(), "SELECT 1;");
    }

    #[test]
    fn strips_trailing_inline_comment() {
        let got = strip_sql_line_comments("SELECT 1; -- trailing\n");
        assert!(got.contains("SELECT 1;"));
        assert!(!got.contains("trailing"));
    }

    #[test]
    fn comment_with_embedded_semicolon_does_not_split_statement() {
        // The exact failure mode that broke migration 003 in production:
        // a `;` inside a parenthetical comment must not be treated as a
        // statement terminator after stripping.
        let input =
            "-- (debug mode; embeddings served by stubs)\nALTER TABLE t ADD COLUMN x Nullable(UInt32);\n";
        let stripped = strip_sql_line_comments(input);
        let stmts: Vec<_> = stripped.split(';').filter(|s| !s.trim().is_empty()).collect();
        assert_eq!(stmts.len(), 1);
        assert!(stmts[0].contains("ALTER TABLE"));
    }

    #[test]
    fn preserves_inline_string_with_dashes() {
        // Defensive: dashes inside literal strings would still be cut by
        // this naive impl. Document the limit so future migration authors
        // know not to rely on it. Until that's needed, keep the simple
        // version.
        let got = strip_sql_line_comments("SELECT 'x--y';\n");
        assert_eq!(got.trim(), "SELECT 'x"); // known limitation
    }
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
