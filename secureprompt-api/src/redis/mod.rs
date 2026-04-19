//! Phase 5 / Plan 05-01 — real `deadpool-redis` pool for the dashboard.
//!
//! Prior art: `http/middleware/rate_limit.rs` uses an in-memory `Mutex<HashMap>`
//! limiter. That stays for now (multi-pod correctness is flagged in auth.rs and
//! tracked for Phase 7). The jti blacklist and Plan 05 budget counters require
//! *real* Redis so state is shared across pods — this module is where that
//! first real client lives.

use deadpool_redis::{
    redis::{cmd, RedisError},
    Config, Pool, Runtime,
};
use secureprompt_common::errors::ApiError;

/// Build a `deadpool-redis` pool from the on-prem Redis URL.
///
/// # Errors
/// Returns `ApiError::Internal` when `Config::from_url` rejects the URL or
/// the pool cannot be constructed (misconfigured `max_size`, etc.).
pub fn build_pool(url: &str) -> Result<Pool, ApiError> {
    let cfg = Config::from_url(url);
    cfg.create_pool(Some(Runtime::Tokio1))
        .map_err(|error| ApiError::Internal(format!("redis pool init failed: {error}")))
}

/// Return `true` if the jti is blacklisted (i.e. the user has logged out and
/// the access token is revoked until its natural expiry).
///
/// # Errors
/// Returns `ApiError::Internal` if the Redis connection cannot be acquired or
/// the `EXISTS` command fails for any reason other than a non-existent key.
pub async fn jti_is_blacklisted(pool: &Pool, jti: &str) -> Result<bool, ApiError> {
    let mut conn = pool
        .get()
        .await
        .map_err(|error| ApiError::Internal(format!("redis checkout failed: {error}")))?;
    let exists: i64 = cmd("EXISTS")
        .arg(jti_key(jti))
        .query_async(&mut conn)
        .await
        .map_err(|error| redis_error(&error))?;
    Ok(exists == 1)
}

/// Persist `jti` in the blacklist with the given TTL in seconds.
///
/// TTL should match the *remaining* lifetime of the access token — longer is
/// wasted memory; shorter re-admits the token after Redis expiry.
///
/// # Errors
/// Returns `ApiError::Internal` if the Redis connection cannot be acquired or
/// the `SET ... EX` command fails.
pub async fn blacklist_jti(pool: &Pool, jti: &str, ttl_secs: u64) -> Result<(), ApiError> {
    let mut conn = pool
        .get()
        .await
        .map_err(|error| ApiError::Internal(format!("redis checkout failed: {error}")))?;
    // SET key value EX ttl — idempotent, bounded lifetime.
    cmd("SET")
        .arg(jti_key(jti))
        .arg(1_i64)
        .arg("EX")
        .arg(ttl_secs)
        .query_async::<()>(&mut conn)
        .await
        .map_err(|error| redis_error(&error))?;
    Ok(())
}

fn jti_key(jti: &str) -> String {
    format!("jti_blacklist:{jti}")
}

fn redis_error(error: &RedisError) -> ApiError {
    ApiError::Internal(format!("redis error: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ensure the key-derivation function is stable. Plans 03/04/05/06 and the
    /// integration tests in `tests/dashboard/auth_tests.rs` all rely on this
    /// exact `jti_blacklist:{jti}` shape; changing it silently would break
    /// the tamper / logout tests.
    #[test]
    fn jti_key_has_stable_shape() {
        assert_eq!(jti_key("abc"), "jti_blacklist:abc");
    }

    #[test]
    fn build_pool_rejects_invalid_url() {
        // `Config::from_url` panics or errors depending on scheme; either way
        // we expect `build_pool` to surface `ApiError::Internal` rather than
        // panic or succeed silently.
        let result = build_pool("not-a-url");
        assert!(
            result.is_err(),
            "invalid URL must return ApiError::Internal, got {result:?}"
        );
    }
}
