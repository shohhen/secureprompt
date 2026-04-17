use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub telemetry: TelemetryConfig,
    pub server: ServerConfig,
    pub clickhouse: ClickhouseConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RedisConfig {
    pub url: String,
    pub max_connections: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TelemetryConfig {
    pub otel_enabled: bool,
    pub prometheus_enabled: bool,
    pub log_level: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MlSidecarConfig {
    pub url: String,
    /// Per-call timeout in milliseconds (D-04: 200ms).
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClickhouseConfig {
    pub url: String,
    pub database: String,
}
