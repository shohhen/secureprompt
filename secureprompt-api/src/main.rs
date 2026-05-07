use secureprompt_api::{app_state::AppState, http::build_router, ml_sidecar::MlSidecarClient};
use secureprompt_common::{
    config::{
        AppConfig, ClickhouseConfig, DatabaseConfig, JwtConfig, RedisConfig, ServerConfig,
        TelemetryConfig,
    },
    telemetry::init_telemetry,
};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::sync::Arc;
use tokio::net::TcpListener;

/// Embedded sqlx migrations (all .sql files in `secureprompt-api/migrations/`).
/// Sorted by the leading numeric prefix in each filename.
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

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
async fn ensure_pg_migrations(pool: &PgPool) -> anyhow::Result<()> {
    let workspaces_exists: bool = sqlx::query_scalar(
        "SELECT to_regclass('public.workspaces') IS NOT NULL",
    )
    .fetch_one(pool)
    .await?;
    let tracking_exists: bool = sqlx::query_scalar(
        "SELECT to_regclass('public._sqlx_migrations') IS NOT NULL",
    )
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
            host: std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into()),
            port: std::env::var("PORT")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(8080),
        },
        clickhouse: ClickhouseConfig {
            url: std::env::var("CLICKHOUSE_URL")
                .unwrap_or_else(|_| "http://localhost:8123".into()),
            database: std::env::var("CLICKHOUSE_DATABASE")
                .unwrap_or_else(|_| "default".into()),
        },
        jwt: JwtConfig::from_env()
            .map_err(|msg| anyhow::anyhow!("invalid JWT configuration: {msg}"))?,
        public_signup_enabled: AppConfig::public_signup_enabled_from_env(),
        chat_debug_mode: AppConfig::chat_debug_mode_from_env(),
        redact_when_no_rules: AppConfig::redact_when_no_rules_from_env(),
    };

    init_telemetry(&config.telemetry);

    if config.public_signup_enabled {
        tracing::warn!(
            "public signup is enabled (SECUREPROMPT_PUBLIC_SIGNUP_ENABLED) — this should only be on for cloud/demo deployments"
        );
    }

    if config.chat_debug_mode {
        tracing::warn!(
            "chat debug mode is enabled (SECUREPROMPT_CHAT_DEBUG_MODE) — /v1/chat/completions will not forward to cloud providers"
        );
    }

    let db = PgPoolOptions::new()
        .max_connections(config.database.max_connections)
        .connect(&config.database.url)
        .await?;

    ensure_pg_migrations(&db).await?;

    let ml_sidecar_url = std::env::var("ML_SIDECAR_URL").unwrap_or_default();
    // Gateway path uses this client; 200 ms was too tight for cold-path NER —
    // the first GLiNER call reliably exceeds it and the circuit silently
    // returned empty detections. 5 s matches the ML sidecar's soft budget
    // for a single `/detect/ner` call and still trips the breaker quickly
    // enough if the sidecar is genuinely down.
    let ml_sidecar_timeout_ms: u64 = std::env::var("ML_SIDECAR_TIMEOUT_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5000);
    let ml_sidecar = Arc::new(MlSidecarClient::new(ml_sidecar_url, ml_sidecar_timeout_ms));

    let state = AppState::new(db, config.clone(), ml_sidecar);
    let app = build_router(state);
    let address = format!("{}:{}", config.server.host, config.server.port);
    let listener = TcpListener::bind(&address).await?;

    tracing::info!(addr = %address, "secureprompt-api listening");
    // `into_make_service_with_connect_info::<SocketAddr>()` exposes the
    // TCP peer address through `ConnectInfo<SocketAddr>` extractors so
    // handlers can record the originating IP even when the client
    // doesn't set `X-Forwarded-For` / `X-Real-IP` (e.g. LibreChat
    // talking to us directly over the docker network).
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}
