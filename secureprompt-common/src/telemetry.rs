use crate::config::TelemetryConfig;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

pub fn init_telemetry(config: &TelemetryConfig) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log_level));

    fmt::Subscriber::builder()
        .with_env_filter(filter)
        .json()
        .with_target(true)
        .finish()
        .try_init()
        .ok();
}
