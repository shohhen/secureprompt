use crate::{
    analytics::AnalyticsHandle,
    http::{middleware::rate_limit::RateLimiter, model_router::ConfigCache},
    observability::metrics::MetricsRegistry,
    providers::ProviderCatalog,
    token_usage::pricing::PricingTable,
};
use secureprompt_common::config::AppConfig;
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: AppConfig,
    pub redis_rate_limiter: Arc<RateLimiter>,
    pub redis_config_cache: Arc<ConfigCache>,
    pub providers: ProviderCatalog,
    pub analytics: AnalyticsHandle,
    pub metrics: Arc<MetricsRegistry>,
    pub pricing: Arc<PricingTable>,
}

impl AppState {
    #[must_use]
    pub fn new(db: PgPool, config: AppConfig) -> Self {
        let metrics = Arc::new(MetricsRegistry::default());

        Self {
            db,
            config,
            redis_rate_limiter: Arc::new(RateLimiter::new(60, 60)),
            redis_config_cache: Arc::new(ConfigCache::default()),
            providers: ProviderCatalog::with_defaults(),
            analytics: AnalyticsHandle::new(metrics.clone()),
            metrics,
            pricing: Arc::new(PricingTable::with_defaults()),
        }
    }
}
