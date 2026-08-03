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
use secureprompt_common::{errors::ApiError, kms::KmsBackend};

/// Build a `deadpool-redis` pool from the on-prem Redis URL.
///
/// # Why this sets no timeouts, MEASURED (MR3 F16)
///
/// F16 reported that an unanswering Redis — reachable at the IP level and not
/// replying, i.e. a partition or a blackholed SYN rather than a refusal —
/// "does not degrade, it stalls": that `pool.get()` would block until the
/// 150 s inbound `TimeoutLayer` returned a 504, so `jwt_auth`'s outage policy
/// would never run. Its suggested fix was to configure `deadpool`'s wait and
/// response timeouts, which are indeed all `None` here.
///
/// Both halves of that were measured, and both are wrong.
///
/// 1. **The checkout is already bounded at ~1.00 s.** `session_gates` against
///    TEST-NET-1 (`192.0.2.1`, RFC 5737, routed nowhere) returned
///    `Err(Internal("redis checkout failed: ... timed out"))` in 1.0017 s.
///    Against a fake server that COMPLETES the TCP handshake and then never
///    sends a byte — the "thrashing server" mode, which the blackhole does
///    not cover — it returned the same error in 1.0020 s. So the outage
///    policy IS reached, promptly, in both slow-fail modes.
/// 2. **Configuring `deadpool`'s timeouts would change nothing.** Setting
///    `Timeouts { wait, create, recycle }` to 60 s each still returned in
///    1.0018 s. `deadpool` timeouts are upper bounds; they cannot lengthen a
///    shorter one underneath, and they are not what is binding here.
///
/// What is binding is the `redis` client's own defaults, applied inside the
/// `get_multiplexed_async_connection()` that `deadpool-redis` 0.23 calls at
/// `src/lib.rs:155`: `DEFAULT_CONNECTION_TIMEOUT = 1 s` and
/// `DEFAULT_RESPONSE_TIMEOUT = 500 ms` (`redis` 1.2.0, `src/client.rs:180`
/// and `:182`). The response timeout is the one that covers a command issued
/// on an already-established connection, which is the case `deadpool` is not
/// in the path for at all.
///
/// So no timeout is set here, deliberately: adding one would be inert, and a
/// comment claiming it fixed the stall would be false.
///
/// THE REAL EXPOSURE, which is not the one F16 named: this bound is a
/// DEPENDENCY DEFAULT, not a decision this repository makes. If a future
/// `redis` release changes either constant to `None`, the gateway silently
/// acquires exactly the stall F16 described and nothing here would say so.
/// That is what `tests/redis_slow_outage.rs` exists to catch, and it is also
/// why that file asserts an OUTCOME (bounded, and an error the policy can
/// act on) rather than a number.
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

/// WS4-3 — read both session gates in ONE Redis round trip.
///
/// `jwt_auth::require` needs two facts about every presented access token:
/// whether its own `jti` was blacklisted by `POST /v1/auth/logout`, and
/// whether an administrator has since revoked all sessions for the user it
/// names. Fetching them separately would double the per-request Redis
/// checkouts on the hottest authenticated path; this issues `EXISTS` and `GET`
/// on one connection.
///
/// Returns `(jti_blacklisted, revoked_before_unix)`. The second value is
/// `None` when no revocation watermark exists for the user — the ordinary
/// case, and the reason the caller must not treat "no key" as "revoked".
///
/// # Errors
/// Returns `ApiError::Internal` if the connection cannot be acquired or
/// either command fails. The caller decides what an unreachable Redis means;
/// this function never guesses.
pub async fn session_gates(
    pool: &Pool,
    jti: &str,
    user_id: &uuid::Uuid,
) -> Result<(bool, Option<i64>), ApiError> {
    let mut conn = pool
        .get()
        .await
        .map_err(|error| ApiError::Internal(format!("redis checkout failed: {error}")))?;
    let blacklisted: i64 = cmd("EXISTS")
        .arg(jti_key(jti))
        .query_async(&mut conn)
        .await
        .map_err(|error| redis_error(&error))?;
    let revoked_before: Option<i64> = cmd("GET")
        .arg(session_revocation_key(user_id))
        .query_async(&mut conn)
        .await
        .map_err(|error| redis_error(&error))?;
    Ok((blacklisted == 1, revoked_before))
}

/// WS4-3 — plant the per-user revocation watermark.
///
/// Every access token for `user_id` whose `iat` is at or before `at_unix` is
/// refused from the next request onward. Keyed by USER, not by token id: the
/// jti blacklist can only revoke a token somebody is holding, and an
/// administrator terminating a lost laptop's session has never seen that
/// token's jti — it is not stored anywhere and no endpoint lists it.
///
/// `SET ... EX`, so a later revocation for the same user simply overwrites
/// with a later watermark. That is correct: watermarks only move forward, and
/// the newest one subsumes every earlier one.
///
/// # Errors
/// Returns `ApiError::Internal` on checkout or command failure. The caller
/// MUST surface that failure — a revocation whose watermark did not land is a
/// revocation that did not happen for already-minted access tokens.
pub async fn revoke_sessions_before(
    pool: &Pool,
    user_id: &uuid::Uuid,
    at_unix: i64,
    ttl_secs: u64,
) -> Result<(), ApiError> {
    let mut conn = pool
        .get()
        .await
        .map_err(|error| ApiError::Internal(format!("redis checkout failed: {error}")))?;
    cmd("SET")
        .arg(session_revocation_key(user_id))
        .arg(at_unix)
        .arg("EX")
        .arg(ttl_secs)
        .query_async::<()>(&mut conn)
        .await
        .map_err(|error| redis_error(&error))?;
    Ok(())
}

/// How long a revocation watermark must outlive the revocation itself.
///
/// The watermark exists only to refuse access tokens that were ALREADY minted
/// when the revocation happened; the refresh chain is closed in Postgres and
/// stays closed. The longest-lived such token is one minted in the same second
/// as the revocation, which `jwt_auth::require` accepts until
/// `iat + access_ttl_secs + leeway`, where the leeway is the 60 s
/// `Validation::leeway` that middleware sets. After that the token is expired
/// on its own terms and the watermark is dead weight, so the key is allowed to
/// expire rather than accumulating one entry per revoked user forever.
///
/// The extra 60 s beyond the leeway is slack for clock skew between the
/// gateway that wrote the watermark and the one that reads it.
#[must_use]
pub const fn revocation_watermark_ttl_secs(access_ttl_secs: u64) -> u64 {
    access_ttl_secs + 120
}

/// Stash a file-scan token→value map (JSON) under a random ref with a TTL, so
/// the chat pipeline can preload its vault and restore file PII in the response.
/// The ref (a UUID) travels in the message as an opaque `[[sp:v=…]]` marker — the
/// PII itself never touches LibreChat's DB.
///
/// # WS3 review — the map is ciphertext in Redis
///
/// The values in that map are the un-redacted PII the caller asked
/// SecurePrompt to protect: it is the SAME DATA CLASS as
/// `token_vault_entries.mapping`, which migration 022 replaced with
/// `mapping_ciphertext` for exactly this reason. WS3-3 encrypted that vault
/// and left this one writing raw JSON, so the file-scan path still put
/// customer PII in the clear into a store whose only protection was a 6h TTL.
///
/// It now goes through the same [`KmsBackend`] that
/// [`crate::analytics::capture::seal`] and
/// [`crate::db::token_vault_repo::TokenVaultRepository`] use, with the same
/// two rules:
///
/// 1. **Encrypt-or-fail.** A KMS outage makes this return an error, which
///    fails the stash request. It never degrades to writing the originals in
///    the clear.
/// 2. **No plaintext read path** — see [`load_file_vault`].
///
/// # Errors
/// Returns `ApiError::Internal` when the KMS refuses, when it returns
/// non-UTF-8 ciphertext, or on Redis connection / `SET … EX` failure.
pub async fn stash_file_vault(
    pool: &Pool,
    kms: &dyn KmsBackend,
    vault_ref: &str,
    map_json: &str,
    ttl_secs: u64,
) -> Result<(), ApiError> {
    // Encrypt BEFORE touching Redis, so a KMS failure leaves no key at all
    // rather than a key awaiting a repair that never comes.
    let ciphertext = kms.encrypt(map_json.as_bytes()).await.map_err(|error| {
        tracing::error!(
            alert = "file_vault_encrypt_failed",
            error = %error,
            "KMS encrypt failed; refusing the stash rather than storing the \
             file-scan originals in the clear"
        );
        ApiError::Internal(format!("file vault encrypt: {error}"))
    })?;
    let ciphertext = String::from_utf8(ciphertext).map_err(|error| {
        tracing::error!(
            alert = "file_vault_encrypt_failed",
            error = %error,
            "KMS returned non-UTF-8 ciphertext; refusing the stash"
        );
        ApiError::Internal("file vault encrypt: ciphertext not UTF-8".to_owned())
    })?;

    let mut conn = pool
        .get()
        .await
        .map_err(|error| ApiError::Internal(format!("redis checkout failed: {error}")))?;
    cmd("SET")
        .arg(format!("filevault:{vault_ref}"))
        .arg(ciphertext)
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
///
/// There is deliberately NO "if it does not decrypt, assume it is the old
/// plaintext JSON" fallback, mirroring `token_vault_repo`. Such a fallback
/// would re-admit the plaintext format forever and give an attacker who can
/// write to Redis a way to inject a map that never passes the KMS. The cost
/// is bounded to the stashes written before the upgrade: they stop restoring
/// and age out within `FILE_VAULT_TTL_SECS` (6h).
pub async fn load_file_vault(pool: &Pool, kms: &dyn KmsBackend, vault_ref: &str) -> Option<String> {
    let mut conn = pool.get().await.ok()?;
    let stored: Option<String> = cmd("GET")
        .arg(format!("filevault:{vault_ref}"))
        .query_async::<Option<String>>(&mut conn)
        .await
        .ok()
        .flatten();
    let stored = stored?;

    match kms.decrypt(stored.as_bytes()).await {
        Ok(plaintext) => String::from_utf8(plaintext).ok(),
        Err(error) => {
            // Logged rather than swallowed: a rotated key or a pre-upgrade
            // plaintext stash both land here, and both are worth seeing as
            // "restoration is silently off" instead of being inferred from a
            // reply full of `{{Person_1}}`.
            tracing::warn!(
                alert = "file_vault_decrypt_failed",
                error = %error,
                "stashed file vault could not be decrypted; leaving its \
                 placeholders unrestored"
            );
            None
        }
    }
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
pub async fn consume_oidc_state(pool: &Pool, state_id: &str) -> Result<Option<String>, ApiError> {
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
pub async fn enqueue_task(pool: &Pool, queue: &str, payload: &str) -> Result<(), ApiError> {
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

/// WS4-3 — the per-user revocation watermark key.
///
/// `pub` because `GET /v1/data-inventory` names the key shape to auditors and
/// the integration tests clean up after themselves; both must read the shape
/// from here rather than restating it.
#[must_use]
pub fn session_revocation_key(user_id: &uuid::Uuid) -> String {
    format!("session_revoked:{user_id}")
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

    /// WS4-3: the revocation key shape is quoted verbatim in
    /// `GET /v1/data-inventory` (`session_revoked:{user_id}`) and used by
    /// `tests/dashboard/session_revocation_tests.rs`. Changing it silently
    /// would leave the inventory describing a key class that no longer exists
    /// while a live deployment kept writing another.
    #[test]
    fn session_revocation_key_has_stable_shape() {
        let user =
            uuid::Uuid::parse_str("11111111-2222-3333-4444-555555555555").expect("valid uuid");
        assert_eq!(
            session_revocation_key(&user),
            "session_revoked:11111111-2222-3333-4444-555555555555"
        );
        // Distinct from the jti blacklist: two key classes, two lifetimes,
        // two meanings. A shared prefix would make one DEL clear the other.
        assert!(!session_revocation_key(&user).starts_with("jti_blacklist"));
    }

    /// The watermark must outlive every access token that existed when it was
    /// written: `access_ttl + 60 s` of `Validation::leeway`, plus slack. A TTL
    /// shorter than that re-admits a revoked token when the key expires, which
    /// is the failure nobody would see.
    #[test]
    fn watermark_ttl_outlives_the_tokens_it_must_refuse() {
        // The deployment default (`JwtConfig.access_ttl_secs = 900`).
        assert_eq!(revocation_watermark_ttl_secs(900), 1_020);
        for access_ttl in [1_u64, 60, 900, 3_600, 86_400] {
            let ttl = revocation_watermark_ttl_secs(access_ttl);
            assert!(
                ttl >= access_ttl + 60,
                "TTL {ttl} for access_ttl {access_ttl} expires before a token \
                 minted in the revocation second stops being accepted \
                 (access_ttl + 60s leeway)"
            );
        }
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
