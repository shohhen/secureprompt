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

        // Trim expired timestamps.
        if let Some(entry) = buckets.get_mut(key) {
            entry.retain(|instant| now.duration_since(*instant) <= self.window);
        }

        // Evict the bucket when all timestamps have expired to prevent unbounded growth.
        if buckets.get(key).map_or(false, |e| e.is_empty()) {
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

pub async fn enforce_rate_limit(state: &AppState, auth: &AuthContext) -> Result<(), ApiError> {
    let limiter: Arc<RateLimiter> = state.redis_rate_limiter.clone();
    limiter
        .check(&format!("api_key:{}", auth.api_key_id))
        .await?;
    limiter
        .check(&format!("workspace:{}", auth.workspace_id))
        .await
}

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
}
