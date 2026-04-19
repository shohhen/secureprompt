use secureprompt_api::{app_state::AppState, http::build_router, ml_sidecar::MlSidecarClient};
use secureprompt_common::{
    config::{
        AppConfig, ClickhouseConfig, DatabaseConfig, JwtConfig, RedisConfig, ServerConfig,
        TelemetryConfig,
    },
    telemetry::init_telemetry,
};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tokio::net::TcpListener;

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
    };

    init_telemetry(&config.telemetry);

    let db = PgPoolOptions::new()
        .max_connections(config.database.max_connections)
        .connect(&config.database.url)
        .await?;

    let ml_sidecar_url = std::env::var("ML_SIDECAR_URL").unwrap_or_default();
    let ml_sidecar = Arc::new(MlSidecarClient::new(ml_sidecar_url, 200));

    let state = AppState::new(db, config.clone(), ml_sidecar);
    let app = build_router(state);
    let address = format!("{}:{}", config.server.host, config.server.port);
    let listener = TcpListener::bind(&address).await?;

    tracing::info!(addr = %address, "secureprompt-api listening");
    axum::serve(listener, app).await?;

    Ok(())
}
