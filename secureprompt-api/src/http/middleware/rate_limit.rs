//! Phase 1 — in-memory sliding-window rate limiter for the API-key gateway.
//! Phase 5 / Plan 05-05 — `budget_check` peer function + test probe router.
//!
//! Two distinct rate-control surfaces:
//!   1. `RateLimiter` / `enforce_rate_limit` — API-key-level in-memory sliding window.
//!      Called from the `openai.rs` gateway handlers. Unchanged from Phase 1.
//!   2. `budget_check` — workspace-level token-budget enforcement backed by
//!      Redis `INCRBY` counters. Called from the `/v1/internal/budget-probe` test
//!      route and will be called from the openai gateway in Phase 6.
//!
//! Pipeline ordering per CONTEXT D-04 (License → Audit → `RateLimit` → Budget → Policy):
//!   The `budget_check` function is a **peer** of `enforce_rate_limit`, not a layer.
//!   Callers invoke rate-limit first then budget-check.

use crate::{
    app_state::AppState,
    db::budget_repo::BudgetBehavior,
    http::{api_error_response, middleware::jwt_auth},
    redis,
};
use axum::{
    body::Body,
    extract::State,
    http::HeaderValue,
    middleware::from_fn_with_state,
    response::Response,
    routing::post,
    Extension, Json, Router,
};
use chrono::Utc;
use secureprompt_common::errors::ApiError;
use serde::Deserialize;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use uuid::Uuid;

// ── In-memory rate limiter (Phase 1, unchanged) ───────────────────────────────

#[derive(Debug)]
pub struct RateLimiter {
    window: Duration,
    max_requests: usize,
    buckets: Mutex<HashMap<String, Vec<Instant>>>,
}

impl RateLimiter {
    #[must_use]
    pub fn new(max_requests: usize, window_seconds: u64) -> Self {
        Self {
            window: Duration::from_secs(window_seconds),
            max_requests,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Check the rate-limit bucket for `key`, recording this instant.
    ///
    /// # Errors
    /// Returns `ApiError::Forbidden` when the per-window request count is exceeded
    /// or the global key-space cap (`100_000` buckets) is reached.
    // The MutexGuard must be held across all bucket operations in this function.
    #[allow(clippy::significant_drop_tightening)]
    pub async fn check(&self, key: &str) -> Result<(), ApiError> {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().await;

        // Trim expired timestamps.
        if let Some(entry) = buckets.get_mut(key) {
            entry.retain(|instant| now.duration_since(*instant) <= self.window);
        }

        // Evict the bucket when all timestamps have expired to prevent unbounded growth.
        if buckets.get(key).is_some_and(Vec::is_empty) {
            buckets.remove(key);
            return Ok(());
        }

        // Cap total tracked keys to avoid memory exhaustion from unique-key DoS.
        if buckets.len() > 100_000 {
            return Err(ApiError::Forbidden(
                "rate limiter capacity exceeded".into(),
            ));
        }

        let entry = buckets.entry(key.to_owned()).or_default();

        if entry.len() >= self.max_requests {
            return Err(ApiError::Forbidden(format!(
                "rate limit exceeded for {key}"
            )));
        }

        entry.push(now);
        Ok(())
    }
}

/// Enforce the in-memory rate limit for an authenticated API-key request.
///
/// # Errors
/// Returns `ApiError::Forbidden` when either the per-key or per-workspace
/// rate-limit bucket is exhausted.
pub async fn enforce_rate_limit(
    state: &AppState,
    auth: &crate::http::middleware::api_key_auth::AuthContext,
) -> Result<(), ApiError> {
    let limiter: Arc<RateLimiter> = state.redis_rate_limiter.clone();
    limiter
        .check(&format!("api_key:{}", auth.api_key_id))
        .await?;
    limiter
        .check(&format!("workspace:{}", auth.workspace_id))
        .await
}

// ── Budget enforcement (Phase 5 / Plan 05-05) ─────────────────────────────────

/// Which time bucket exceeded the limit.
#[derive(Debug, Clone, Copy)]
pub enum BudgetBucket {
    Daily,
    Monthly,
}

/// Result of a `budget_check` call.
#[derive(Debug)]
pub enum BudgetOutcome {
    /// Both buckets are within their limits (or no budget row exists).
    Allow,
    /// `behavior=warn` + at least one bucket exceeded — caller should add the
    /// `X-SecurePrompt-Budget-Warning` response header.
    Warn(BudgetBucket),
    /// `behavior=flag` + at least one bucket exceeded — caller logs silently,
    /// no client-visible change.
    Flag(BudgetBucket),
    /// `behavior=block` + at least one bucket exceeded — caller returns 402.
    Exceeded(BudgetBucket),
}

/// Redis key for daily budget counter.
///
/// Format: `budget:{workspace_id}:tokens:{YYYYMMDD}`
#[must_use]
pub fn budget_daily_key(workspace_id: Uuid) -> String {
    format!(
        "budget:{workspace_id}:tokens:{}",
        Utc::now().format("%Y%m%d")
    )
}

/// Redis key for monthly budget counter.
///
/// Format: `budget:{workspace_id}:tokens:{YYYYMM}`
#[must_use]
pub fn budget_monthly_key(workspace_id: Uuid) -> String {
    format!(
        "budget:{workspace_id}:tokens:{}",
        Utc::now().format("%Y%m")
    )
}

/// Atomically charge `estimated_tokens` against the workspace's daily and
/// monthly Redis `INCRBY` counters, then compare against the configured limits.
///
/// The "conservative reservation" semantics:
///   - `INCRBY` is called unconditionally — the counter grows even if the
///     request is ultimately blocked. A tiny overshoot is acceptable; the
///     monotonic counter prevents a second wave of requests from slipping
///     through (T-05-08, VALIDATION 5-07-05).
///   - Missing budget row → `Allow` (fail-open for workspaces with no budget).
///   - Redis failure → `Allow` + increment `budget_redis_failure_total` metric
///     (D-25 fail-open for analytics outage).
///
/// # Errors
/// Only returns `Err` for Postgres failure (budget row lookup). Redis errors
/// are absorbed into `Allow` to satisfy the fail-open contract.
pub async fn budget_check(
    state: &AppState,
    workspace_id: Uuid,
    estimated_tokens: u64,
) -> Result<BudgetOutcome, ApiError> {
    let start = std::time::Instant::now();

    // Load the budget row from Postgres via the RLS-aware repository.
    let Some(budget) = state.budgets.get(workspace_id).await? else {
        // No budget configured → always allow.
        state.metrics.record_budget_event("none", "allow");
        state.metrics.time_budget_check(start.elapsed());
        return Ok(BudgetOutcome::Allow);
    };

    let behavior_str = budget.behavior.as_db_str();
    let delta = i64::try_from(estimated_tokens).unwrap_or(i64::MAX);

    // Daily bucket — 2-day TTL so the key survives midnight without an abrupt gap.
    let daily_ttl: u64 = 2 * 24 * 3600;
    let monthly_ttl: u64 = 32 * 24 * 3600;

    let daily_key = budget_daily_key(workspace_id);
    let monthly_key = budget_monthly_key(workspace_id);

    let daily_used =
        match redis::incr_and_get(&state.redis_pool, &daily_key, delta, daily_ttl).await {
            Ok(v) => v,
            Err(_) => {
                state.metrics.record_budget_redis_failure();
                state.metrics.record_budget_event(behavior_str, "allow");
                state.metrics.time_budget_check(start.elapsed());
                return Ok(BudgetOutcome::Allow);
            }
        };

    let monthly_used =
        match redis::incr_and_get(&state.redis_pool, &monthly_key, delta, monthly_ttl).await {
            Ok(v) => v,
            Err(_) => {
                state.metrics.record_budget_redis_failure();
                state.metrics.record_budget_event(behavior_str, "allow");
                state.metrics.time_budget_check(start.elapsed());
                return Ok(BudgetOutcome::Allow);
            }
        };

    // Determine which bucket (if any) is exceeded.
    let exceeded_bucket: Option<BudgetBucket> =
        if budget.daily_token_limit.is_some_and(|limit| daily_used > limit) {
            Some(BudgetBucket::Daily)
        } else if budget
            .monthly_token_limit
            .is_some_and(|limit| monthly_used > limit)
        {
            Some(BudgetBucket::Monthly)
        } else {
            None
        };

    let outcome = match exceeded_bucket {
        None => {
            state.metrics.record_budget_event(behavior_str, "allow");
            BudgetOutcome::Allow
        }
        Some(bucket) => match budget.behavior {
            BudgetBehavior::Block => {
                state.metrics.record_budget_event("block", "exceeded");
                BudgetOutcome::Exceeded(bucket)
            }
            BudgetBehavior::Warn => {
                state.metrics.record_budget_event("warn", "warn");
                BudgetOutcome::Warn(bucket)
            }
            BudgetBehavior::Flag => {
                state.metrics.record_budget_event("flag", "flag");
                BudgetOutcome::Flag(bucket)
            }
        },
    };

    state.metrics.time_budget_check(start.elapsed());
    Ok(outcome)
}

/// Adjust the workspace's daily + monthly Redis counters by an arbitrary
/// signed delta. Negative deltas are valid — `INCRBY` accepts them and the
/// counter goes down. Used post-flight to reconcile the difference between
/// the pre-flight estimate (charged by `budget_check`) and the actual
/// `total_tokens` reported by the upstream provider.
///
/// `delta == 0` short-circuits.
///
/// Failure is non-fatal — Redis outage shouldn't block the response.
/// `budget_redis_failure_total` still reports the issue.
pub async fn adjust_workspace_tokens(
    state: &AppState,
    workspace_id: Uuid,
    delta: i64,
) {
    if delta == 0 {
        return;
    }
    let daily_ttl: u64 = 2 * 24 * 3600;
    let monthly_ttl: u64 = 32 * 24 * 3600;

    let daily_key = budget_daily_key(workspace_id);
    let monthly_key = budget_monthly_key(workspace_id);

    if redis::incr_and_get(&state.redis_pool, &daily_key, delta, daily_ttl)
        .await
        .is_err()
    {
        state.metrics.record_budget_redis_failure();
    }
    if redis::incr_and_get(&state.redis_pool, &monthly_key, delta, monthly_ttl)
        .await
        .is_err()
    {
        state.metrics.record_budget_redis_failure();
    }
}

/// Cheap input-token estimate from raw text. ~4 characters per token is
/// the OpenAI rule-of-thumb that holds for English-dominant prompts; the
/// pre-flight check only needs a number that's order-of-magnitude
/// correct because the post-flight reconcile applies the actual delta.
///
/// We deliberately don't run a real tokenizer here — the pipeline already
/// owns that path and pre-flight is hot.
#[must_use]
pub fn estimate_tokens_from_text(text: &str) -> u64 {
    let chars = text.chars().count() as u64;
    chars.div_ceil(4)
}

/// Pre-flight outcome the gateway hands to its response builder.
#[derive(Debug, Clone, Copy)]
pub enum BudgetGate {
    /// Continue. No warning header needed.
    Pass,
    /// Continue, but the caller must emit
    /// `x-secureprompt-budget-warning: daily|monthly`.
    Warn(BudgetBucket),
}

impl BudgetGate {
    #[must_use]
    pub const fn warning_bucket(self) -> Option<&'static str> {
        match self {
            Self::Warn(BudgetBucket::Daily) => Some("daily"),
            Self::Warn(BudgetBucket::Monthly) => Some("monthly"),
            Self::Pass => None,
        }
    }
}

/// Run the pre-flight budget check before the pipeline dispatches.
///
/// On success, returns `BudgetGate::Pass` (allow + no header) or
/// `BudgetGate::Warn(bucket)` (allow + warning header).
/// On hard block, returns `Err(ApiError::BudgetExceeded(...))` so the
/// caller can convert to a 402 response.
///
/// `behavior=flag` is logged but transparent to the client — returns
/// `BudgetGate::Pass`.
///
/// # Errors
/// `ApiError::BudgetExceeded` when `behavior=block` and a counter is over.
/// `ApiError::Database` for budget-row read failures (rare).
pub async fn pre_check_budget(
    state: &AppState,
    workspace_id: Uuid,
    estimated_input_tokens: u64,
) -> Result<BudgetGate, ApiError> {
    match budget_check(state, workspace_id, estimated_input_tokens).await? {
        BudgetOutcome::Allow => Ok(BudgetGate::Pass),
        BudgetOutcome::Flag(bucket) => {
            tracing::warn!(
                workspace_id = %workspace_id,
                bucket = ?bucket,
                "budget_flagged_silently"
            );
            Ok(BudgetGate::Pass)
        }
        BudgetOutcome::Warn(bucket) => Ok(BudgetGate::Warn(bucket)),
        BudgetOutcome::Exceeded(bucket) => {
            tracing::warn!(
                workspace_id = %workspace_id,
                bucket = ?bucket,
                "budget_exceeded_blocked"
            );
            let label = match bucket {
                BudgetBucket::Daily => "daily",
                BudgetBucket::Monthly => "monthly",
            };
            Err(ApiError::BudgetExceeded(format!(
                "{label} token budget exceeded"
            )))
        }
    }
}

// ── Test probe router ─────────────────────────────────────────────────────────
//
// Exposes `budget_check` through the full JWT middleware stack so integration
// tests can drive VALIDATION 5-07-01..05 without a live OpenAI provider.
//
// Route: POST /v1/internal/budget-probe
//   - Requires Bearer JWT (workspace_id extracted from token claims).
//   - Body: {"estimated_tokens": <u64>}
//   - Responses:
//       200 OK                        — Allow or Flag
//       200 OK + x-secureprompt-budget-warning: daily|monthly — Warn
//       402 Payment Required          — Exceeded (block)

#[derive(Debug, Deserialize)]
struct BudgetProbeRequest {
    estimated_tokens: u64,
}

async fn budget_probe_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<jwt_auth::JwtAuthContext>,
    Json(body): Json<BudgetProbeRequest>,
) -> Result<Response<Body>, Response<Body>> {
    let workspace_id = ctx.workspace_id.0;

    let outcome = budget_check(&state, workspace_id, body.estimated_tokens)
        .await
        .map_err(api_error_response)?;

    match outcome {
        BudgetOutcome::Allow => Ok(Response::new(Body::empty())),

        BudgetOutcome::Warn(bucket) => {
            let bucket_str = match bucket {
                BudgetBucket::Daily => "daily",
                BudgetBucket::Monthly => "monthly",
            };
            let mut res = Response::new(Body::empty());
            res.headers_mut().insert(
                "x-secureprompt-budget-warning",
                HeaderValue::from_static(bucket_str),
            );
            Ok(res)
        }

        BudgetOutcome::Flag(bucket) => {
            tracing::warn!(
                workspace_id = %workspace_id,
                bucket = ?bucket,
                "budget_flagged_silently"
            );
            Ok(Response::new(Body::empty()))
        }

        BudgetOutcome::Exceeded(bucket) => {
            tracing::warn!(
                workspace_id = %workspace_id,
                bucket = ?bucket,
                "budget_exceeded_blocked"
            );
            Err(api_error_response(ApiError::BudgetExceeded(format!(
                "{bucket:?} budget exceeded"
            ))))
        }
    }
}

/// Returns a router with the `/v1/internal/budget-probe` test route.
///
/// Always registered (not behind `#[cfg(test)]`) — requires a valid JWT
/// and only touches budget counters, which is safe in production.
#[must_use]
pub fn test_probe_router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/v1/internal/budget-probe", post(budget_probe_handler))
        .route_layer(from_fn_with_state(state, jwt_auth::require))
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rate_limiter_allows_requests_within_window() {
        let limiter = RateLimiter::new(5, 60);
        for _ in 0..5 {
            assert!(limiter.check("test_key").await.is_ok());
        }
    }

    #[tokio::test]
    async fn rate_limiter_blocks_after_exceeding_limit() {
        let limiter = RateLimiter::new(2, 60);
        assert!(limiter.check("test_key").await.is_ok());
        assert!(limiter.check("test_key").await.is_ok());
        let result = limiter.check("test_key").await;
        assert!(result.is_err());
        match result {
            Err(ApiError::Forbidden(msg)) => assert!(msg.contains("rate limit exceeded")),
            _ => panic!("expected Forbidden error"),
        }
    }

    #[tokio::test]
    async fn rate_limiter_tracks_different_keys_independently() {
        let limiter = RateLimiter::new(1, 60);
        assert!(limiter.check("key_a").await.is_ok());
        assert!(limiter.check("key_b").await.is_ok());
        assert!(limiter.check("key_a").await.is_err());
        assert!(limiter.check("key_b").await.is_err());
    }

    #[test]
    fn daily_key_format() {
        let ws = Uuid::parse_str("cafe0a00-0000-0000-0000-000000000000").unwrap();
        let key = budget_daily_key(ws);
        // Format: budget:{uuid}:tokens:{YYYYMMDD}
        assert!(key.starts_with("budget:cafe0a00-0000-0000-0000-000000000000:tokens:"));
        assert_eq!(
            key.len(),
            "budget:cafe0a00-0000-0000-0000-000000000000:tokens:20260419".len()
        );
    }

    #[test]
    fn monthly_key_format() {
        let ws = Uuid::parse_str("cafe0b00-0000-0000-0000-000000000000").unwrap();
        let key = budget_monthly_key(ws);
        assert!(key.starts_with("budget:cafe0b00-0000-0000-0000-000000000000:tokens:"));
        assert_eq!(
            key.len(),
            "budget:cafe0b00-0000-0000-0000-000000000000:tokens:202604".len()
        );
    }
}
