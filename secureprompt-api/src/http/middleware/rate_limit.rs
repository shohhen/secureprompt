use crate::{app_state::AppState, http::middleware::api_key_auth::AuthContext};
use secureprompt_common::errors::ApiError;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

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

    pub async fn check(&self, key: &str) -> Result<(), ApiError> {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().await;
        let entry = buckets.entry(key.to_owned()).or_default();

        entry.retain(|instant| now.duration_since(*instant) <= self.window);

        if entry.len() >= self.max_requests {
            return Err(ApiError::Forbidden(format!(
                "rate limit exceeded for {key}"
            )));
        }

        entry.push(now);
        Ok(())
    }
}

pub async fn enforce_rate_limit(state: &AppState, auth: &AuthContext) -> Result<(), ApiError> {
    let limiter: Arc<RateLimiter> = state.redis_rate_limiter.clone();
    limiter
        .check(&format!("api_key:{}", auth.api_key_id))
        .await?;
    limiter
        .check(&format!("workspace:{}", auth.workspace_id))
        .await
}
