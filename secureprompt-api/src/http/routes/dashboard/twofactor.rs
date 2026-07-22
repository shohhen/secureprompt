//! `/v1/auth/2fa/{enroll,verify,challenge}` — TOTP enrollment,
//! first-confirmation (2FA, Task 6), and the login challenge + lockout
//! (2FA, Task 7).
//!
//! `enroll`/`verify` accept EITHER a `2fa_enroll` purpose token (forced
//! first-time enrollment minted by `token()`'s `Enroll` branch — see
//! `auth.rs`) OR a normal (purposeless) access token (an already-logged-in
//! user opting in). `challenge` is narrower: it accepts ONLY a
//! `2fa_challenge` purpose token (minted by `token()`'s `Challenge` branch)
//! — never a normal access token (the caller doesn't have one yet — that's
//! the whole point of the challenge) and never a `2fa_enroll` token. None of
//! the three handlers uses `Extension<JwtAuthContext>` — the normal JWT auth
//! middleware (`jwt_auth::require`) rejects purpose tokens outright (Task
//! 4) — so the bearer token is decoded directly here via
//! `accept_enroll_or_access` (enroll/verify) or `accept_challenge`
//! (challenge).
//!
//! The plaintext TOTP secret and the plaintext backup codes are returned to
//! the client exactly once, in the `enroll` response body. From that point
//! on only the KMS-encrypted secret (`users.totp_secret_encrypted`) and the
//! Argon2 hashes (`user_backup_codes.code_hash`) exist at rest.

use argon2::password_hash::rand_core::{OsRng, RngCore};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json as JsonResponse, Response},
    routing::post,
    Json, Router,
};
use chrono::Utc;
use jsonwebtoken::{decode, Algorithm, Validation};
use secureprompt_common::errors::ApiError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    app_state::AppState,
    auth::totp,
    db::user_repo::{self, UserRepository},
    http::{
        api_error_response,
        middleware::jwt_auth::{self, Claims},
    },
    redis as sp_redis,
};

use super::auth::build_token_pair_body;

// ---------- Tunables ----------

/// Backup codes issued per enrollment (plan: "10 per user").
const BACKUP_CODE_COUNT: usize = 10;
/// Random characters per backup code before formatting.
const BACKUP_CODE_RAW_LEN: usize = 10;
/// Alphabet backup codes are drawn from: uppercase letters + digits, minus
/// visually-ambiguous characters (0/O, 1/I/L) so a user transcribing a code
/// by hand from a screen/printout doesn't misread it.
const BACKUP_CODE_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";

// ---------- DTOs ----------

/// `POST /v1/auth/2fa/enroll` response — the ONLY time the plaintext secret
/// and plaintext backup codes are ever shown.
///
/// `Debug` is hand-rolled (not derived) and redacts `secret_b32`,
/// `backup_codes`, AND `provisioning_uri` — the URI embeds the same secret
/// as a `secret=` query parameter (RFC otpauth format), so redacting only
/// the other two fields would still leak it via a stray
/// `tracing::debug!("{:?}", resp)` on this struct.
#[derive(Serialize)]
pub struct EnrollResponse {
    pub provisioning_uri: String,
    pub secret_b32: String,
    pub backup_codes: Vec<String>,
}

impl std::fmt::Debug for EnrollResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollResponse")
            .field("provisioning_uri", &"<redacted: embeds secret>")
            .field("secret_b32", &"<redacted>")
            .field(
                "backup_codes",
                &format!("<{} redacted>", self.backup_codes.len()),
            )
            .finish()
    }
}

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub code: String,
}

// ---------- Router ----------

/// 2FA enroll/verify routes.
///
/// Mounted by `http/mod.rs` under `/v1/auth/2fa` (Task 9) — deliberately NOT
/// wrapped in the `jwt_auth::require` layer, since that middleware rejects
/// the `2fa_enroll` purpose token these handlers must also accept; auth is
/// done per-handler via `accept_enroll_or_access` instead.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/enroll", post(enroll))
        .route("/verify", post(verify))
        .route("/challenge", post(challenge))
}

// ---------- Auth acceptance (enroll/verify share this) ----------

/// Decode `Authorization: Bearer <jwt>` into `Claims` without judging
/// `purpose` — the same signing key + validation rules as
/// `jwt_auth::require` / `auth::decode_purpose_token` (HS256, 60s leeway,
/// `exp`/`iat`/`sub` required), so verification stays on one code path
/// regardless of which token shape is presented.
fn decode_bearer_claims(state: &AppState, headers: &HeaderMap) -> Result<Claims, ApiError> {
    let token = jwt_auth::extract_bearer(headers)?;

    let mut validation = Validation::new(Algorithm::HS256);
    validation.leeway = 60;
    validation.validate_exp = true;
    validation.set_required_spec_claims(&["exp", "iat", "sub"]);

    let decoded = decode::<Claims>(&token, &state.jwt.decoding, &validation)
        .map_err(|_| ApiError::Unauthorized("Invalid credentials".into()))?;
    Ok(decoded.claims)
}

/// What a decoded bearer's `purpose` claim tells `accept_enroll_or_access`
/// to do next. Factored out as a pure/DB-free classification (as opposed to
/// the blacklist I/O the access-token branch still needs) so the
/// token-acceptance *decision* is unit-testable without a database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BearerPurposeDecision {
    /// `purpose == Some("2fa_enroll")` — accept immediately. Purpose tokens
    /// aren't tracked by the jti blacklist (logout only blacklists access
    /// tokens); they're already single-purpose and 5-minute-lived by
    /// construction (`encode_purpose_token`), so no further check is needed.
    AcceptEnrollmentToken,
    /// `purpose == None` — looks like a normal access token. The caller
    /// still must check the jti blacklist before trusting it: without this,
    /// a logged-out user's still-unexpired access token could be replayed
    /// here to silently re-enroll (overwrite) 2FA.
    CheckAccessTokenBlacklist,
    /// Any other purpose (e.g. `2fa_challenge`) is never valid on this
    /// surface — a challenge token may only be redeemed at
    /// `/v1/auth/2fa/challenge` (Task 7).
    Reject,
}

fn classify_bearer_purpose(purpose: Option<&str>) -> BearerPurposeDecision {
    match purpose {
        Some("2fa_enroll") => BearerPurposeDecision::AcceptEnrollmentToken,
        None => BearerPurposeDecision::CheckAccessTokenBlacklist,
        Some(_) => BearerPurposeDecision::Reject,
    }
}

/// Accept EITHER a valid `2fa_enroll` purpose token OR a normal
/// (purposeless) access token — the auth shape both `/v1/auth/2fa/enroll`
/// and `/v1/auth/2fa/verify` allow (forced first-time enrollment via the
/// `enrollment_token` from `token()`'s `Enroll` branch, OR an
/// already-logged-in user — e.g. a Viewer — opting in with their normal
/// access token).
///
/// Deliberately bypasses `Extension<JwtAuthContext>`: the normal JWT
/// middleware (`jwt_auth::require`) rejects purpose tokens outright
/// (Task 4), so this decodes the bearer token directly.
///
/// # Errors
/// Returns `ApiError::Unauthorized` for a missing/malformed header, bad
/// signature, expiry, a non-enroll purpose (e.g. `2fa_challenge`), or a
/// blacklisted access-token jti. Returns `ApiError::ServiceUnavailable` if
/// the jti-blacklist check itself cannot be performed — fail-closed rather
/// than silently trusting a token that might belong to a logged-out user.
pub(crate) async fn accept_enroll_or_access(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(Uuid, Uuid), ApiError> {
    let claims = decode_bearer_claims(state, headers)?;

    match classify_bearer_purpose(claims.purpose.as_deref()) {
        BearerPurposeDecision::AcceptEnrollmentToken => Ok((claims.sub, claims.ws)),
        BearerPurposeDecision::CheckAccessTokenBlacklist => {
            match sp_redis::jti_is_blacklisted(&state.redis_pool, &claims.jti).await {
                Ok(true) => Err(ApiError::Unauthorized("Invalid credentials".into())),
                Ok(false) => Ok((claims.sub, claims.ws)),
                Err(_) => Err(ApiError::ServiceUnavailable(
                    "auth service temporarily unavailable".into(),
                )),
            }
        }
        BearerPurposeDecision::Reject => Err(ApiError::Unauthorized("Invalid credentials".into())),
    }
}

// ---------- Auth acceptance (challenge only — Task 7) ----------

/// Whether a decoded bearer's `purpose` claim is exactly `2fa_challenge` —
/// the ONLY purpose `/v1/auth/2fa/challenge` accepts. Same shape as
/// `classify_bearer_purpose` above (a pure/DB-free classification) so the
/// decision is unit-testable without a database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChallengePurposeDecision {
    /// `purpose == Some("2fa_challenge")` — accept. Like enrollment tokens,
    /// challenge tokens aren't jti-blacklist-tracked (logout only
    /// blacklists access tokens): they're single-purpose and 5-minute-lived
    /// by construction (`encode_purpose_token`), so no further check is
    /// needed.
    Accept,
    /// Anything else — including `purpose == None` (a normal access token)
    /// and `purpose == Some("2fa_enroll")` — is rejected. Unlike
    /// `/enroll` and `/verify`, this endpoint IS the second step of login:
    /// the caller does not hold an access token yet, so (deliberately,
    /// unlike `classify_bearer_purpose`) there is no "fall back to
    /// access-token" branch here.
    Reject,
}

fn classify_challenge_purpose(purpose: Option<&str>) -> ChallengePurposeDecision {
    if purpose == Some("2fa_challenge") {
        ChallengePurposeDecision::Accept
    } else {
        ChallengePurposeDecision::Reject
    }
}

/// Accept ONLY a valid `2fa_challenge` purpose token.
///
/// Reuses `decode_bearer_claims` — the same signature/expiry verification
/// path `accept_enroll_or_access` uses — and layers the stricter
/// challenge-only purpose check on top via `classify_challenge_purpose`.
/// Deliberately does NOT accept a normal access token or a `2fa_enroll`
/// token: this handler is the login gate itself, not an opt-in surface for
/// an already-authenticated user.
///
/// # Errors
/// Returns `ApiError::Unauthorized` for a missing/malformed header, bad
/// signature, expiry, or any purpose other than `2fa_challenge`.
fn accept_challenge(state: &AppState, headers: &HeaderMap) -> Result<(Uuid, Uuid), ApiError> {
    let claims = decode_bearer_claims(state, headers)?;
    match classify_challenge_purpose(claims.purpose.as_deref()) {
        ChallengePurposeDecision::Accept => Ok((claims.sub, claims.ws)),
        ChallengePurposeDecision::Reject => {
            Err(ApiError::Unauthorized("Invalid credentials".into()))
        }
    }
}

// ---------- Backup codes ----------

/// Generate `BACKUP_CODE_COUNT` cryptographically-random, single-use backup
/// codes. Plaintext is returned to the caller for the one-time enroll
/// response; only Argon2 hashes of these are ever persisted
/// (`insert_backup_codes`).
fn generate_backup_codes() -> Vec<String> {
    (0..BACKUP_CODE_COUNT)
        .map(|_| format_backup_code(&random_backup_code_raw()))
        .collect()
}

/// `BACKUP_CODE_RAW_LEN` random characters drawn from `BACKUP_CODE_ALPHABET`
/// using OS randomness (`OsRng`, re-exported via `argon2` — the same source
/// `auth::random_refresh_token` uses, so no new RNG dependency is needed).
fn random_backup_code_raw() -> String {
    let mut buf = [0_u8; BACKUP_CODE_RAW_LEN];
    OsRng.fill_bytes(&mut buf);
    buf.iter()
        .map(|&byte| BACKUP_CODE_ALPHABET[usize::from(byte) % BACKUP_CODE_ALPHABET.len()] as char)
        .collect()
}

/// Insert a readability dash in the middle of a raw backup code, e.g.
/// `"A3F9K7QMPZ"` -> `"A3F9K-7QMPZ"`. Pure formatting, split out from the
/// RNG so it can be unit-tested deterministically.
fn format_backup_code(raw: &str) -> String {
    let mid = raw.len() / 2;
    let (left, right) = raw.split_at(mid);
    format!("{left}-{right}")
}

/// Strip the readability dash back out before hashing/verifying — codes are
/// stored and matched on their raw alphanumeric form so formatting is purely
/// cosmetic and never affects matching.
fn strip_backup_code_format(code: &str) -> String {
    code.chars().filter(|c| *c != '-').collect()
}

// ---------- Handlers ----------

/// `POST /v1/auth/2fa/enroll` — start (or restart, if unconfirmed) TOTP
/// enrollment.
///
/// Rejects with `409 Conflict` if the account already has CONFIRMED 2FA
/// (see the `totp_confirmed_at` check below) — resetting a confirmed
/// account must go through `/disable` (code-gated) first.
///
/// Generates a new secret, encrypts it via `state.kms` and stores it
/// unconfirmed (`set_totp_secret` clears `totp_confirmed_at` and — as of the
/// Task 6 review fix — atomically deletes any backup codes left over from a
/// prior enrollment), generates and stores 10 freshly hashed backup codes,
/// and returns the provisioning URI + plaintext secret + plaintext backup
/// codes — the only time either plaintext value is ever shown.
pub async fn enroll(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (user_id, _workspace_id) = match accept_enroll_or_access(&state, &headers).await {
        Ok(pair) => pair,
        Err(err) => return api_error_response(err),
    };

    let repo = UserRepository::new(state.db.clone());
    let user = match repo.find_by_id(user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return api_error_response(ApiError::Unauthorized("Invalid credentials".into()))
        }
        Err(err) => return api_error_response(err),
    };

    // Security fix (post-Task-6 review): a CONFIRMED account must not be
    // re-enrollable via a bare access token — `set_totp_secret` clears
    // `totp_confirmed_at`, so without this gate anyone holding an access
    // token (e.g. a Viewer who never needed 2FA) could call `/enroll` on
    // an already-2FA'd account and silently downgrade it back to
    // password-only login. Fresh enrollment (`totp_confirmed_at` was never
    // set) and forced re-enrollment (unconfirmed) are unaffected — only a
    // CONFIRMED account is blocked. The documented reset path is
    // `/disable` (which itself requires a valid code) followed by a fresh
    // `/enroll`.
    if user.totp_confirmed_at.is_some() {
        return api_error_response(ApiError::Conflict(
            "2FA is already enabled; disable it first".into(),
        ));
    }

    let secret_b32 = totp::generate_secret();

    let ciphertext = match state.kms.encrypt(secret_b32.as_bytes()).await {
        Ok(bytes) => bytes,
        Err(error) => {
            return api_error_response(ApiError::Internal(format!(
                "totp secret encrypt failed: {error}"
            )))
        }
    };
    if let Err(err) = repo.set_totp_secret(user_id, &ciphertext).await {
        return api_error_response(err);
    }

    let backup_codes = generate_backup_codes();
    let hashes: Vec<String> = match backup_codes
        .iter()
        .map(|code| user_repo::hash_password(&strip_backup_code_format(code)))
        .collect::<Result<_, _>>()
    {
        Ok(hashes) => hashes,
        Err(err) => return api_error_response(err),
    };
    if let Err(err) = repo.insert_backup_codes(user_id, &hashes).await {
        return api_error_response(err);
    }

    let provisioning_uri = match totp::provisioning_uri(&secret_b32, &user.email, "SecurePrompt") {
        Ok(uri) => uri,
        Err(_totp_error) => {
            return api_error_response(ApiError::Internal(
                "failed to build TOTP provisioning URI".into(),
            ))
        }
    };

    (
        StatusCode::OK,
        JsonResponse(EnrollResponse {
            provisioning_uri,
            secret_b32,
            backup_codes,
        }),
    )
        .into_response()
}

/// `POST /v1/auth/2fa/verify` — confirm enrollment with the first valid code.
///
/// Enforces `totp_locked_until` up front (Task 6 review fix — `429` without
/// attempting verification if still locked). On success, marks the account
/// fully enrolled and issues a real access/refresh pair so enrollment flows
/// straight into a logged-in session; on failure, records the attempt
/// (`totp_failed_attempts`/`totp_locked_until` — the same columns the Task 7
/// challenge endpoint shares) and returns 401.
pub async fn verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<VerifyRequest>,
) -> Response {
    let (user_id, workspace_id) = match accept_enroll_or_access(&state, &headers).await {
        Ok(pair) => pair,
        Err(err) => return api_error_response(err),
    };

    let repo = UserRepository::new(state.db.clone());
    let user = match repo.find_by_id(user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return api_error_response(ApiError::Unauthorized("Invalid credentials".into()))
        }
        Err(err) => return api_error_response(err),
    };

    // Security fix (post-Task-6 review): enforce the lockout `verify()`
    // itself writes via `record_totp_failure` below. Without this read,
    // `totp_locked_until` was written but never consulted, so a locked
    // account still allowed unthrottled code-guessing against this
    // endpoint — Task 7's `/challenge` checks the same column; this closes
    // the identical gap on `/verify`.
    if let Some(locked_until) = user.totp_locked_until {
        if locked_until > Utc::now() {
            return api_error_response(ApiError::TooManyRequests(format!(
                "too many attempts, locked until {}",
                locked_until.to_rfc3339()
            )));
        }
    }

    let Some(ciphertext) = user.totp_secret_encrypted.as_ref() else {
        // No enrollment in progress — same generic 401 as a bad code so the
        // failure reason doesn't leak (T-05-07 pattern).
        return api_error_response(ApiError::Unauthorized("Invalid credentials".into()));
    };

    let secret_bytes = match state.kms.decrypt(ciphertext).await {
        Ok(bytes) => bytes,
        Err(_error) => {
            return api_error_response(ApiError::Unauthorized("Invalid credentials".into()))
        }
    };
    let Ok(secret_b32) = String::from_utf8(secret_bytes) else {
        return api_error_response(ApiError::Unauthorized("Invalid credentials".into()));
    };

    let now_unix = u64::try_from(Utc::now().timestamp()).unwrap_or(0);
    let last_timestep = user.totp_last_timestep.map(|step| u64::try_from(step).unwrap_or(0));

    match totp::verify_code(&secret_b32, &body.code, last_timestep, now_unix) {
        Ok(step) => {
            if let Err(err) = repo.confirm_totp(user_id).await {
                return api_error_response(err);
            }
            let step_i64 = i64::try_from(step).unwrap_or(i64::MAX);
            if let Err(err) = repo.record_totp_success(user_id, step_i64).await {
                return api_error_response(err);
            }

            // Role isn't part of `UserRow` (established pattern — see
            // `users.rs`'s `POST /v1/users` / `workspace_repo.rs`'s
            // `set_workspace_owner`): fetch it directly so the freshly
            // issued access token carries the real role, not a placeholder.
            let role: String =
                match sqlx::query_scalar("SELECT role FROM users WHERE id = $1")
                    .bind(user_id)
                    .fetch_one(&state.db)
                    .await
                {
                    Ok(role) => role,
                    Err(error) => {
                        return api_error_response(ApiError::Database(error.to_string()))
                    }
                };

            match build_token_pair_body(&state, user_id, workspace_id, &role, &user.email).await {
                Ok(body) => (StatusCode::OK, JsonResponse(body)).into_response(),
                Err(err) => api_error_response(err),
            }
        }
        Err(_totp_error) => {
            // Lockout threshold/window matches Task 7's challenge endpoint
            // (5 failures / 15 minutes) — both surfaces share the same
            // `totp_failed_attempts`/`totp_locked_until` columns.
            let _ = repo.record_totp_failure(user_id, 5, 900).await;
            api_error_response(ApiError::Unauthorized("Invalid credentials".into()))
        }
    }
}

/// Try `code` as a TOTP against the user's stored (KMS-decrypted) secret.
///
/// Returns `None` — not `Err` — for EVERY failure mode: no secret on file,
/// KMS decrypt failure, non-UTF8 plaintext, or an invalid/replayed code.
/// `challenge()`'s next step is identical for all of these: fall through
/// and try `code` as a backup code instead (Task 7: "a 6-digit TOTP OR a
/// backup code", tried in that order).
async fn verify_totp_step(
    state: &AppState,
    user: &user_repo::UserRow,
    code: &str,
    now_unix: u64,
) -> Option<u64> {
    let ciphertext = user.totp_secret_encrypted.as_ref()?;
    let secret_bytes = state.kms.decrypt(ciphertext).await.ok()?;
    let secret_b32 = String::from_utf8(secret_bytes).ok()?;
    let last_timestep = user
        .totp_last_timestep
        .map(|step| u64::try_from(step).unwrap_or(0));
    totp::verify_code(&secret_b32, code, last_timestep, now_unix).ok()
}

/// `POST /v1/auth/2fa/challenge` — second step of a 2FA-gated login (Task 7).
///
/// Submit a TOTP code OR a backup code against the `2fa_challenge` purpose
/// token minted by `token()`'s `Challenge` branch, and receive a real
/// access/refresh pair.
///
/// Auth is `2fa_challenge`-only (`accept_challenge`) — see the module doc
/// and `ChallengePurposeDecision` for why a normal access token and a
/// `2fa_enroll` token are both rejected here, unlike `/enroll`/`/verify`.
///
/// Ordering mirrors `verify()` (Task 6 review): the account lockout
/// (`totp_locked_until`) is checked FIRST, before the per-IP rate limiter
/// and before any code is attempted — a locked account never reaches
/// `kms.decrypt`, `verify_code`, or `consume_backup_code`. The per-IP rate
/// limit is a second, independent brake (an attacker rotating target
/// accounts against one IP is throttled here even before any single
/// account trips its own 5-failure lock).
///
/// On success (TOTP or backup code) records the success (clears the
/// failure counter + lock) and issues access/refresh via
/// `build_token_pair_body`. On failure of BOTH the TOTP check and the
/// backup-code check, records the failure — locking the account for 15
/// minutes once it reaches 5 consecutive failures — and returns the same
/// generic 401 used everywhere else on this surface.
pub async fn challenge(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<VerifyRequest>,
) -> Response {
    let (user_id, workspace_id) = match accept_challenge(&state, &headers) {
        Ok(pair) => pair,
        Err(err) => return api_error_response(err),
    };

    let repo = UserRepository::new(state.db.clone());
    let user = match repo.find_by_id(user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return api_error_response(ApiError::Unauthorized("Invalid credentials".into()))
        }
        Err(err) => return api_error_response(err),
    };

    // Lockout check FIRST — same Task-6-review fix `verify()` applies:
    // reject a locked account WITHOUT attempting anything (no rate-limit
    // bump, no KMS call, no code check).
    if let Some(locked_until) = user.totp_locked_until {
        if locked_until > Utc::now() {
            return api_error_response(ApiError::TooManyRequests(format!(
                "too many attempts, locked until {}",
                locked_until.to_rfc3339()
            )));
        }
    }

    // Per-IP rate limit. Mirrors `register()`'s pattern in `auth.rs`: the
    // limiter's own `Forbidden` error is discarded in favor of an explicit
    // `TooManyRequests` so the client sees 429 (per plan), not 403.
    let ip_key = super::auth::client_ip_key(&headers);
    if state
        .redis_rate_limiter
        .check(&format!("2fa_challenge_ip:{ip_key}"))
        .await
        .is_err()
    {
        return api_error_response(ApiError::TooManyRequests(
            "rate limit exceeded for 2fa challenge".into(),
        ));
    }

    let now_unix = u64::try_from(Utc::now().timestamp()).unwrap_or(0);

    // TOTP first; if that doesn't verify, fall through and try the same
    // input as a backup code (stripping the display dash — codes are
    // stored/matched on their raw alphanumeric form).
    let success_timestep: Option<i64> =
        match verify_totp_step(&state, &user, &body.code, now_unix).await {
            Some(step) => Some(i64::try_from(step).unwrap_or(i64::MAX)),
            None => match repo
                .consume_backup_code(user_id, &strip_backup_code_format(&body.code))
                .await
            {
                // A backup code has no TOTP timestep to persist for replay
                // prevention; advance the watermark to "now" anyway so the
                // very next TOTP attempt still has to be for the current
                // (or a future) step, not an already-elapsed one.
                Ok(true) => Some(i64::try_from(now_unix / 30).unwrap_or(i64::MAX)),
                Ok(false) => None,
                Err(err) => return api_error_response(err),
            },
        };

    let Some(timestep) = success_timestep else {
        // Neither the TOTP code nor a backup code matched. Threshold/
        // window (5 failures / 15 minutes) matches `verify()` — both
        // surfaces share the same `totp_failed_attempts`/
        // `totp_locked_until` columns.
        let _ = repo.record_totp_failure(user_id, 5, 900).await;
        return api_error_response(ApiError::Unauthorized("Invalid credentials".into()));
    };

    if let Err(err) = repo.record_totp_success(user_id, timestep).await {
        return api_error_response(err);
    }

    // Role isn't part of `UserRow` — same fetch `verify()` does so the
    // freshly issued access token carries the real role.
    let role: String = match sqlx::query_scalar("SELECT role FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&state.db)
        .await
    {
        Ok(role) => role,
        Err(error) => return api_error_response(ApiError::Database(error.to_string())),
    };

    match build_token_pair_body(&state, user_id, workspace_id, &role, &user.email).await {
        Ok(body) => (StatusCode::OK, JsonResponse(body)).into_response(),
        Err(err) => api_error_response(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- classify_bearer_purpose (token-acceptance decision, DB-free) ----

    #[test]
    fn classify_enroll_purpose_is_accepted_directly() {
        assert_eq!(
            classify_bearer_purpose(Some("2fa_enroll")),
            BearerPurposeDecision::AcceptEnrollmentToken
        );
    }

    #[test]
    fn classify_no_purpose_requires_blacklist_check() {
        assert_eq!(
            classify_bearer_purpose(None),
            BearerPurposeDecision::CheckAccessTokenBlacklist
        );
    }

    #[test]
    fn classify_other_purposes_are_rejected() {
        for purpose in ["2fa_challenge", "something_else", ""] {
            assert_eq!(
                classify_bearer_purpose(Some(purpose)),
                BearerPurposeDecision::Reject,
                "purpose {purpose:?} must not be accepted on the enroll/verify surface"
            );
        }
    }

    // ---- classify_challenge_purpose (Task 7, token-acceptance decision, DB-free) ----

    #[test]
    fn classify_challenge_purpose_accepts_only_2fa_challenge() {
        assert_eq!(
            classify_challenge_purpose(Some("2fa_challenge")),
            ChallengePurposeDecision::Accept
        );
    }

    #[test]
    fn classify_challenge_purpose_rejects_access_and_enroll_tokens() {
        // The challenge endpoint IS the login gate itself — unlike
        // enroll/verify it must never fall back to accepting a normal
        // (purposeless) access token, and an enrollment token must not be
        // redeemable here either.
        for purpose in [None, Some("2fa_enroll"), Some("something_else"), Some("")] {
            assert_eq!(
                classify_challenge_purpose(purpose),
                ChallengePurposeDecision::Reject,
                "purpose {purpose:?} must not be accepted on the challenge surface"
            );
        }
    }

    // ---- backup-code generation/formatting (pure, DB-free) ----

    #[test]
    fn random_backup_code_raw_uses_only_the_safe_alphabet() {
        let code = random_backup_code_raw();
        assert_eq!(code.len(), BACKUP_CODE_RAW_LEN);
        for byte in code.bytes() {
            assert!(
                BACKUP_CODE_ALPHABET.contains(&byte),
                "byte {byte} not in backup-code alphabet"
            );
        }
        // Ambiguous characters must never appear.
        for bad in ['0', 'O', '1', 'I', 'L'] {
            assert!(!code.contains(bad), "ambiguous char {bad} leaked into backup code");
        }
    }

    #[test]
    fn format_backup_code_inserts_a_single_midpoint_dash() {
        let formatted = format_backup_code("ABCDEFGHIJ");
        assert_eq!(formatted, "ABCDE-FGHIJ");
        assert_eq!(formatted.matches('-').count(), 1);
    }

    #[test]
    fn strip_backup_code_format_reverses_formatting() {
        let raw = "ABCDEFGHIJ";
        let formatted = format_backup_code(raw);
        assert_eq!(strip_backup_code_format(&formatted), raw);
    }

    #[test]
    fn generate_backup_codes_returns_the_expected_count_and_shape() {
        let codes = generate_backup_codes();
        assert_eq!(codes.len(), BACKUP_CODE_COUNT);
        for code in &codes {
            let raw = strip_backup_code_format(code);
            assert_eq!(raw.len(), BACKUP_CODE_RAW_LEN);
            assert!(code.contains('-'));
        }
        // Overwhelmingly likely to be pairwise-distinct at this alphabet/length;
        // a collision would indicate a broken RNG, not bad luck.
        let unique: std::collections::HashSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), codes.len(), "backup codes must not collide");
    }
}
