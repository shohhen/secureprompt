use crate::{
    analytics::{
        clickhouse_writer::build_clickhouse_client, AnalyticsHandle, DashboardReader,
    },
    db::{budget_repo::BudgetRepository, refresh_token_repo::RefreshTokenRepository},
    http::{
        middleware::jwt_auth::{CachedAuthEntry, JwtKeys},
        middleware::rate_limit::RateLimiter,
        model_router::ConfigCache,
    },
    ml_sidecar::MlSidecarClient,
    observability::metrics::MetricsRegistry,
    providers::ProviderCatalog,
    token_usage::pricing::PricingTable,
};
use dashmap::DashMap;
use deadpool_redis::Pool as RedisPool;
use secureprompt_common::{config::AppConfig, errors::ApiError, kms::KmsBackend};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: AppConfig,
    pub redis_rate_limiter: Arc<RateLimiter>,
    /// Per-IP limiter for `POST /v1/auth/register` (10 requests / 1 hour).
    /// In-memory, process-local — sharing across replicas is a follow-up.
    pub signup_rate_limiter: Arc<RateLimiter>,
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
    /// Phase 5 / Plan 05-05 — workspace budgets repository. Consumed by the
    /// `/v1/workspaces/:id/budgets` handlers and by
    /// `rate_limit::budget_check` before dispatch.
    pub budgets: Arc<BudgetRepository>,
    /// Phase 5 / Plan 05-03 — read-only `ClickHouse` facade over the four dbt mart tables.
    /// Backed by a DISTINCT `clickhouse::Client` (not the writer's async-insert client).
    pub dashboard_reader: Arc<DashboardReader>,
    /// Phase 6 / Plan 06-01 — per-pod in-memory auth cache (D-14, PG-04).
    /// Key: user_id. TTL = 5 min (checked on read). Not Redis-backed by design.
    pub auth_cache: Arc<DashMap<Uuid, CachedAuthEntry>>,
    /// Phase 7 / Plan 07-01 — KMS backend for envelope encryption.
    /// Defaults to `FileKms` (AES-256-GCM). Switch to `VaultKms` via
    /// `KMS_BACKEND=vault` for regulated on-prem deployments.
    pub kms: Arc<dyn KmsBackend>,
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
        let budgets = Arc::new(BudgetRepository::new(db.clone()));
        // Distinct read-only client — no async_insert settings (RESEARCH A5).
        let ch_reader_client = build_clickhouse_client(&ch_url, &ch_database);
        let dashboard_reader = Arc::new(DashboardReader::new(ch_reader_client));

        let kms = secureprompt_common::kms::kms_backend_from_env()
            .map_err(|e| ApiError::Internal(format!("KMS init failed: {e}")))?;

        Ok(Self {
            db,
            config,
            redis_rate_limiter: Arc::new(RateLimiter::new(60, 60)),
            signup_rate_limiter: Arc::new(RateLimiter::new(10, 3600)),
            redis_config_cache: Arc::new(ConfigCache::default()),
            providers: ProviderCatalog::with_defaults(),
            analytics: AnalyticsHandle::new(metrics.clone(), &ch_url, &ch_database),
            metrics,
            pricing: Arc::new(PricingTable::with_defaults()),
            ml_sidecar,
            jwt,
            redis_pool,
            refresh_tokens,
            budgets,
            dashboard_reader,
            auth_cache: Arc::new(DashMap::new()),
            kms,
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
