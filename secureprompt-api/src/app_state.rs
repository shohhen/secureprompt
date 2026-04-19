use crate::{
    analytics::AnalyticsHandle,
    db::refresh_token_repo::RefreshTokenRepository,
    http::{middleware::jwt_auth::JwtKeys, middleware::rate_limit::RateLimiter, model_router::ConfigCache},
    ml_sidecar::MlSidecarClient,
    observability::metrics::MetricsRegistry,
    providers::ProviderCatalog,
    token_usage::pricing::PricingTable,
};
use deadpool_redis::Pool as RedisPool;
use secureprompt_common::{config::AppConfig, errors::ApiError};
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
    pub ml_sidecar: Arc<MlSidecarClient>,
    /// Phase 5 / Plan 05-01 — HS256 JWT encode/decode keys and TTLs.
    pub jwt: Arc<JwtKeys>,
    /// Phase 5 / Plan 05-01 — real `deadpool-redis` pool.
    /// Currently used for the jti blacklist; Plans 03/05 add budget counters.
    pub redis_pool: RedisPool,
    /// Phase 5 / Plan 05-01 — refresh-token repository (populated by Task
    /// 5-01-C). Wrapped in `Arc` so handlers can clone cheaply.
    pub refresh_tokens: Arc<RefreshTokenRepository>,
}

impl AppState {
    /// Construct the full `AppState` from config + connection pools.
    ///
    /// # Errors
    /// Returns `ApiError::Internal` if the Redis pool cannot be initialized
    /// from `config.redis.url`.
    pub fn try_new(
        db: PgPool,
        config: AppConfig,
        ml_sidecar: Arc<MlSidecarClient>,
    ) -> Result<Self, ApiError> {
        let metrics = Arc::new(MetricsRegistry::default());
        let ch_url = config.clickhouse.url.clone();
        let ch_database = config.clickhouse.database.clone();
        let jwt = JwtKeys::from_config(&config.jwt);
        let redis_pool = crate::redis::build_pool(&config.redis.url)?;
        let refresh_tokens = Arc::new(RefreshTokenRepository::new(db.clone()));

        Ok(Self {
            db,
            config,
            redis_rate_limiter: Arc::new(RateLimiter::new(60, 60)),
            redis_config_cache: Arc::new(ConfigCache::default()),
            providers: ProviderCatalog::with_defaults(),
            analytics: AnalyticsHandle::new(metrics.clone(), &ch_url, &ch_database),
            metrics,
            pricing: Arc::new(PricingTable::with_defaults()),
            ml_sidecar,
            jwt,
            redis_pool,
            refresh_tokens,
        })
    }

    /// Convenience wrapper that panics on construction failure. Used by
    /// `main.rs` where a Redis misconfiguration is fatal anyway. Tests that
    /// want to surface the error prefer `try_new`.
    ///
    /// # Panics
    /// Panics if `try_new` fails. Callers that need graceful handling should
    /// use `try_new` directly.
    #[must_use]
    pub fn new(db: PgPool, config: AppConfig, ml_sidecar: Arc<MlSidecarClient>) -> Self {
        Self::try_new(db, config, ml_sidecar).expect("AppState::new must succeed")
    }
}
