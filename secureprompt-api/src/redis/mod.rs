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

/// Stash a file-scan token→value map (JSON) under a random ref with a TTL, so
/// the chat pipeline can preload its vault and restore file PII in the response.
/// The ref (a UUID) travels in the message as an opaque `[[sp:v=…]]` marker — the
/// PII itself never touches LibreChat's DB.
///
/// # Errors
/// Returns `ApiError::Internal` on Redis connection or `SET … EX` failure.
pub async fn stash_file_vault(
    pool: &Pool,
    vault_ref: &str,
    map_json: &str,
    ttl_secs: u64,
) -> Result<(), ApiError> {
    let mut conn = pool
        .get()
        .await
        .map_err(|error| ApiError::Internal(format!("redis checkout failed: {error}")))?;
    cmd("SET")
        .arg(format!("filevault:{vault_ref}"))
        .arg(map_json)
        .arg("EX")
        .arg(ttl_secs)
        .query_async::<()>(&mut conn)
        .await
        .map_err(|error| redis_error(&error))?;
    Ok(())
}

/// Load a stashed file-scan token map JSON by ref. Returns `None` on any error
/// or if the ref has expired — the pipeline degrades to leaving the `{{Type_N}}`
/// tokens unrestored rather than failing the request.
pub async fn load_file_vault(pool: &Pool, vault_ref: &str) -> Option<String> {
    let mut conn = pool.get().await.ok()?;
    cmd("GET")
        .arg(format!("filevault:{vault_ref}"))
        .query_async::<Option<String>>(&mut conn)
        .await
        .ok()
        .flatten()
}

/// Atomically increment a counter by `delta` and return the new value.
///
/// If the key is newly created by this operation, sets its TTL to
/// `ttl_secs_on_new` seconds (using `EXPIRE key ttl NX` so an existing TTL
/// is never overwritten).
///
/// This is the building block for budget counters:
/// - Daily key: `budget:{workspace_id}:tokens:{YYYYMMDD}` — TTL = 2 days
/// - Monthly key: `budget:{workspace_id}:tokens:{YYYYMM}` — TTL = 32 days
///
/// The `INCRBY` is unconditional; a tiny overshoot is acceptable per the
/// "conservative reservation" semantics documented in Plan 05-05.
///
/// # Errors
/// Returns `ApiError::Internal` on Redis connection or command failure.
pub async fn incr_and_get(
    pool: &Pool,
    key: &str,
    delta: i64,
    ttl_secs_on_new: u64,
) -> Result<i64, ApiError> {
    let mut conn = pool
        .get()
        .await
        .map_err(|error| ApiError::Internal(format!("redis checkout failed: {error}")))?;

    // Execute INCRBY first — always atomic and returns the post-increment value.
    let new_value: i64 = cmd("INCRBY")
        .arg(key)
        .arg(delta)
        .query_async(&mut conn)
        .await
        .map_err(|error| redis_error(&error))?;

    // Set the TTL only if the key has no expiry yet (NX flag).
    // This is a best-effort call; if it fails we still have the counter value.
    let _: i64 = cmd("EXPIRE")
        .arg(key)
        .arg(ttl_secs_on_new)
        .arg("NX")
        .query_async(&mut conn)
        .await
        .unwrap_or(0);

    Ok(new_value)
}

/// Read the current value of a budget counter without incrementing it.
///
/// Returns `0` when the key does not exist (i.e. no usage in the current window).
///
/// # Errors
/// Returns `ApiError::Internal` on Redis connection or command failure.
pub async fn get_counter(pool: &Pool, key: &str) -> Result<i64, ApiError> {
    let mut conn = pool
        .get()
        .await
        .map_err(|error| ApiError::Internal(format!("redis checkout failed: {error}")))?;

    // GET returns nil for missing keys; map nil → 0.
    let raw: Option<i64> = cmd("GET")
        .arg(key)
        .query_async(&mut conn)
        .await
        .map_err(|error| redis_error(&error))?;

    Ok(raw.unwrap_or(0))
}

// ── OIDC PKCE state storage (Phase 6 / Plan 06-02, D-12, AUTH-03) ────────

/// Store PKCE verifier secret in Redis for `ttl_secs` (600 = 10 min).
/// Key: `oidc_state:{state_id}`.
///
/// # Errors
/// `ApiError::Internal` on Redis checkout or command failure.
pub async fn store_oidc_state(
    pool: &Pool,
    state_id: &str,
    pkce_verifier_secret: &str,
    ttl_secs: u64,
) -> Result<(), ApiError> {
    let mut conn = pool
        .get()
        .await
        .map_err(|e| ApiError::Internal(format!("redis checkout failed: {e}")))?;
    cmd("SET")
        .arg(oidc_state_key(state_id))
        .arg(pkce_verifier_secret)
        .arg("EX")
        .arg(ttl_secs)
        .query_async::<()>(&mut conn)
        .await
        .map_err(|e| redis_error(&e))?;
    Ok(())
}

/// Atomically get-and-delete the PKCE verifier secret (GETDEL).
/// Returns `None` if the key does not exist (expired or invalid state).
/// GETDEL prevents replay — the state can only be consumed once (D-12).
///
/// # Errors
/// `ApiError::Internal` on Redis failure.
pub async fn consume_oidc_state(
    pool: &Pool,
    state_id: &str,
) -> Result<Option<String>, ApiError> {
    let mut conn = pool
        .get()
        .await
        .map_err(|e| ApiError::Internal(format!("redis checkout failed: {e}")))?;
    // GETDEL: atomic get + delete. Returns nil if key absent.
    let value: Option<String> = cmd("GETDEL")
        .arg(oidc_state_key(state_id))
        .query_async(&mut conn)
        .await
        .map_err(|e| redis_error(&e))?;
    Ok(value)
}

/// Push a serialized task envelope onto a Redis list (RPUSH).
/// Used by `secureprompt-api` to enqueue work for `secureprompt-worker`.
///
/// # Errors
/// `ApiError::Internal` on Redis failure.
pub async fn enqueue_task(
    pool: &Pool,
    queue: &str,
    payload: &str,
) -> Result<(), ApiError> {
    let mut conn = pool
        .get()
        .await
        .map_err(|e| ApiError::Internal(format!("redis checkout failed: {e}")))?;
    cmd("RPUSH")
        .arg(queue)
        .arg(payload)
        .query_async::<i64>(&mut conn)
        .await
        .map_err(|e| redis_error(&e))?;
    Ok(())
}

// Private key derivation helper.
fn oidc_state_key(state_id: &str) -> String {
    format!("oidc_state:{state_id}")
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

    /// Ensure `oidc_state_key` produces the expected prefix shape. The OIDC
    /// callback and any integration tests depend on the `oidc_state:{id}` key
    /// pattern matching exactly.
    #[test]
    fn oidc_state_key_has_stable_shape() {
        assert_eq!(oidc_state_key("abc123"), "oidc_state:abc123");
    }
}
