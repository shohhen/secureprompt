//! Phase 5 / Plan 05-01 — `/v1/auth/{token,refresh,logout}` handlers.
//!
//! `/token` and `/refresh` are public; `/logout` is protected by a
//! per-route JWT middleware (axum `route_layer`) so the layer covers only
//! that single handler.
//!
//! Security notes:
//!   * Every error from the login path returns the same generic body
//!     `{"error":{"code":"invalid_credentials","message":"Invalid
//!     credentials"}}` so an attacker cannot distinguish bad-email vs
//!     bad-password (threats T-05-07 + 5-01-08 test).
//!   * Email + IP buckets share the same in-memory `RateLimiter` —
//!     flagged for Phase 7 migration to a Redis-backed sliding window.
//!   * Refresh tokens are single-use; replay triggers
//!     `revoke_all_for_user` (threat T-05-03).

use axum::{
    body::Body,
    extract::{Extension, State},
    http::{HeaderMap, StatusCode},
    middleware::from_fn_with_state,
    response::{IntoResponse, Json as JsonResponse, Response},
    routing::post,
    Json, Router,
};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, Header, Validation};
use secureprompt_common::{errors::ApiError, types::WorkspaceId};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::{
    app_state::AppState,
    db::{
        refresh_token_repo::RotationOutcome,
        user_repo::{self, UserRepository},
    },
    http::middleware::jwt_auth::{self, Claims, JwtAuthContext, UserRole},
    redis as sp_redis,
};

// ---------- DTOs ----------

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct UserDto {
    pub id: Uuid,
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub user: UserDto,
    pub workspace_id: Uuid,
    pub role: String,
    pub access_expires_at: i64,
    pub refresh_expires_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub workspace_name: String,
}

// ---------- Router ----------

/// Dashboard auth routes. `/logout` is wrapped in the JWT middleware so
/// only that endpoint requires a valid access token.
#[must_use]
pub fn routes() -> Router<AppState> {
    // `route_layer` accepts a `Layer`, and `from_fn_with_state` returns one
    // that needs the cloned state captured. Because `routes()` cannot see
    // the concrete state at construction time (Router<AppState> is generic
    // over it), we express the layer as a closure invoked with the state
    // inside `Router::route`'s `route_layer` helper using the
    // `.layer()` on the handler itself via `with_state` at build time.
    // In practice the idiomatic axum 0.8 pattern is to register the
    // middleware in `http/mod.rs` where `state` is concrete, but because
    // Plan 05-01 requires `route_layer` *inside* this `routes()` fn, we
    // delegate to a builder that takes the state.
    Router::new()
        .route("/token", post(token))
        .route("/refresh", post(refresh))
        .route(
            "/logout",
            post(logout).layer(axum::middleware::from_fn(stub_layer)),
        )
}

/// Real construction helper used by `build_router` — registers the
/// per-route JWT layer with the concrete `AppState`. Because Axum 0.8 ties
/// `route_layer` to a concrete state, the plan's `routes()` variant above
/// leaves `/logout` guarded by a stub layer that forwards the request; the
/// real guard is applied here so `http/mod.rs` can call
/// `dashboard::auth::build_router(state)` instead of `routes()`.
#[must_use]
pub fn build_router(state: AppState) -> Router<AppState> {
    let jwt_layer = from_fn_with_state(state.clone(), jwt_auth::require);
    Router::new()
        .route("/token", post(token))
        .route("/refresh", post(refresh))
        .route("/register", post(register))
        .route("/logout", post(logout).route_layer(jwt_layer))
}

async fn stub_layer(request: axum::extract::Request, next: axum::middleware::Next) -> Response {
    // When `routes()` is used directly (not `build_router`), `/logout`
    // rejects everything — callers must use `build_router` to get real
    // JWT protection. This keeps the default `routes()` fn safe against
    // accidental mounts without the middleware.
    let _ = request;
    let _ = next;
    (
        StatusCode::UNAUTHORIZED,
        JsonResponse(json!({
            "error": {
                "code": "invalid_credentials",
                "message": "Invalid credentials",
                "type": "secureprompt_error"
            }
        })),
    )
        .into_response()
}

// ---------- Handlers ----------

/// `POST /v1/auth/token` — exchange email+password for an access/refresh pair.
pub async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<TokenRequest>,
) -> Response {
    let email_normalized = body.email.trim().to_ascii_lowercase();
    let ip_key = client_ip_key(&headers);

    // Brute-force guards: 5/min/email, 30/min/IP. The existing RateLimiter
    // is a bounded in-memory Mutex<HashMap>; on multi-pod deployments
    // Phase 7 replaces this with a Redis-backed sliding window.
    if let Err(err) = state
        .redis_rate_limiter
        .check(&format!("auth_email:{email_normalized}"))
        .await
    {
        return generic_401(Some(err));
    }
    if let Err(err) = state
        .redis_rate_limiter
        .check(&format!("auth_ip:{ip_key}"))
        .await
    {
        return generic_401(Some(err));
    }

    let repo = UserRepository::new(state.db.clone());
    let creds = match repo.find_by_email_with_role(&email_normalized).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            // Dummy-verify to equalize bad-email vs bad-password timing.
            user_repo::verify_against_dummy(&body.password);
            return generic_401(None);
        }
        Err(err) => return api_error_to_response(err),
    };

    if !user_repo::verify_password(&creds.password_hash, &body.password) {
        return generic_401(None);
    }

    // 2FA (Task 5): parse the DB role string once so `decide_2fa` gets a
    // typed `UserRole` — same parser `jwt_auth::require` uses for the
    // `role` claim, so an unrecognised value fails the same way here as it
    // would fail on a subsequent authenticated request.
    let role = match UserRole::from_db_str(&creds.role) {
        Ok(role) => role,
        Err(err) => return api_error_to_response(err),
    };

    match decide_2fa(role, creds.totp_confirmed_at.is_some()) {
        TwoFaDecision::Access => {
            // Routed through `TokenOr2fa::Access` (not `issue_token_pair`
            // directly) so the 200 body is provably the same
            // `(StatusCode::OK, JsonResponse(TokenResponse))` shape as the
            // 202 branches below share a type with — see `TokenOr2fa`.
            match build_token_pair_body(&state, creds.id, creds.workspace_id, &creds.role, &creds.email)
                .await
            {
                Ok(body) => TokenOr2fa::Access(body).into_response(),
                Err(err) => api_error_to_response(err),
            }
        }
        TwoFaDecision::Challenge => {
            match encode_purpose_token(&state, creds.id, creds.workspace_id, "2fa_challenge", 300) {
                Ok(challenge_token) => TokenOr2fa::Challenge { challenge_token }.into_response(),
                Err(err) => api_error_to_response(err),
            }
        }
        TwoFaDecision::Enroll => {
            match encode_purpose_token(&state, creds.id, creds.workspace_id, "2fa_enroll", 300) {
                Ok(enrollment_token) => TokenOr2fa::Enroll { enrollment_token }.into_response(),
                Err(err) => api_error_to_response(err),
            }
        }
    }
}

// ---------- 2FA login-branch decision (Task 5) ----------

/// Outcome of `decide_2fa`: what `POST /v1/auth/token` should do once the
/// password has verified.
///
/// `pub(crate)` (Task: OIDC 2FA parity) so `oidc_callback` can drive the
/// exact same decision after an OIDC-authenticated lookup instead of
/// duplicating the branch — two divergent copies of this table is how the
/// bypass happened in the first place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TwoFaDecision {
    /// No 2FA in play — proceed straight to `build_token_pair_body` (200).
    Access,
    /// Already enrolled (`totp_confirmed_at` is some) — every login from
    /// here on is challenged, regardless of role. Issue a `2fa_challenge`
    /// purpose token (202) instead of access/refresh.
    Challenge,
    /// Role requires 2FA (Owner/Admin) but the user hasn't completed
    /// enrollment yet — issue a `2fa_enroll` purpose token (202) so the
    /// client can drive first-time enrollment before any access token is
    /// minted.
    Enroll,
}

/// Pure decision function — no I/O, no `AppState` — so the branch the login
/// handler takes is unit-testable without a database.
///
/// Truth table:
///   * `totp_confirmed = true`  → `Challenge`, for every role (once
///     enrolled, always challenged).
///   * `totp_confirmed = false` + role ∈ {Owner, Admin} → `Enroll` (forced
///     first-time enrollment for roles that must have 2FA).
///   * `totp_confirmed = false` + any other role → `Access` (2FA optional,
///     not enrolled).
///
/// `pub(crate)` (Task: OIDC 2FA parity) — shared by `token()` and
/// `oidc_callback` so both login paths enforce identically.
#[must_use]
pub(crate) const fn decide_2fa(role: UserRole, totp_confirmed: bool) -> TwoFaDecision {
    if totp_confirmed {
        TwoFaDecision::Challenge
    } else if matches!(role, UserRole::Owner | UserRole::Admin) {
        TwoFaDecision::Enroll
    } else {
        TwoFaDecision::Access
    }
}

/// `POST /v1/auth/token` response shape (2FA, Task 5). `Access` carries the
/// pre-existing `TokenResponse` unchanged — serializing it here is byte-
/// identical to the old `(StatusCode::OK, JsonResponse(TokenResponse))`
/// path the console + `/v1/auth/register` depend on. `Challenge`/`Enroll`
/// are new 202 bodies that carry a short-lived purpose token instead of
/// access/refresh.
///
/// `pub(crate)` (Task: OIDC 2FA parity) so `oidc_callback` returns byte-
/// identical `Challenge`/`Enroll` bodies to the password login path.
pub(crate) enum TokenOr2fa {
    Access(TokenResponse),
    Challenge { challenge_token: String },
    Enroll { enrollment_token: String },
}

impl IntoResponse for TokenOr2fa {
    fn into_response(self) -> Response {
        match self {
            Self::Access(body) => (StatusCode::OK, JsonResponse(body)).into_response(),
            Self::Challenge { challenge_token } => (
                StatusCode::ACCEPTED,
                JsonResponse(json!({
                    "twofa_required": true,
                    "challenge_token": challenge_token,
                })),
            )
                .into_response(),
            Self::Enroll { enrollment_token } => (
                StatusCode::ACCEPTED,
                JsonResponse(json!({
                    "enroll_required": true,
                    "enrollment_token": enrollment_token,
                })),
            )
                .into_response(),
        }
    }
}

/// `POST /v1/auth/refresh` — rotate a refresh token atomically.
pub async fn refresh(
    State(state): State<AppState>,
    Json(body): Json<RefreshRequest>,
) -> Response {
    // Generate the successor raw token up front so `rotate` can hash it.
    let new_raw = random_refresh_token();
    let now = Utc::now();
    let new_expires_at = now + Duration::seconds(state.jwt.refresh_ttl_secs as i64);

    let outcome = match state
        .refresh_tokens
        .rotate(&body.refresh_token, &new_raw, new_expires_at)
        .await
    {
        Ok(outcome) => outcome,
        Err(err) => return api_error_to_response(err),
    };

    match outcome {
        RotationOutcome::Rotated {
            user_id,
            workspace_id,
            ..
        } => {
            // Look up the user's current email+role for the response body.
            let repo = UserRepository::new(state.db.clone());
            let creds = match fetch_user_by_id(&repo.pool, user_id).await {
                Ok(Some(c)) => c,
                Ok(None) => return generic_401(None),
                Err(err) => return api_error_to_response(err),
            };

            // Mint fresh access token; refresh token already inserted by rotate.
            let access_exp = now + Duration::seconds(state.jwt.access_ttl_secs as i64);
            let jti = Uuid::new_v4().to_string();
            let access_claims = Claims {
                sub: user_id,
                ws: workspace_id,
                role: creds.role.clone(),
                iat: now.timestamp(),
                exp: access_exp.timestamp(),
                jti,
                purpose: None,
            };
            let access_token = match encode_access(&state, &access_claims) {
                Ok(token) => token,
                Err(err) => return api_error_to_response(err),
            };

            let body = TokenResponse {
                access_token,
                refresh_token: new_raw,
                user: UserDto {
                    id: user_id,
                    email: creds.email,
                },
                workspace_id,
                role: creds.role,
                access_expires_at: access_exp.timestamp(),
                refresh_expires_at: new_expires_at.timestamp(),
            };
            (StatusCode::OK, JsonResponse(body)).into_response()
        }
        RotationOutcome::ReplayDetected { user_id } => {
            // Best-effort revoke-all; even if it fails we still 401.
            let _ = state.refresh_tokens.revoke_all_for_user(user_id).await;
            generic_401(None)
        }
        RotationOutcome::NotFound | RotationOutcome::Expired => generic_401(None),
    }
}

/// `POST /v1/auth/logout` — blacklist the presented access-token jti and
/// revoke the user's active refresh token (best-effort).
///
/// The JWT middleware must have already inserted `JwtAuthContext`.
pub async fn logout(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
) -> Response {
    // Blacklist TTL = remaining access-token lifetime. Clamp negative to 1s
    // (defensive — middleware already enforces `validate_exp`, so exp should
    // be in the future, but a 1s minimum avoids a Redis error on a race).
    let now = Utc::now().timestamp();
    let remaining = (ctx.exp - now).max(1) as u64;
    // FU3 — this early return is load-bearing beyond its own request. The jti
    // blacklist is the ONE session control with no Redis-independent record,
    // so `jwt_auth::require` degrades rather than fails closed on it when Redis
    // is unreachable. That degrade is only defensible because a logout
    // attempted during the outage cannot report success: the error goes back to
    // the caller instead. A best-effort `let _ =` here would turn a logout the
    // user watched succeed into one that never happened.
    // `logout_during_a_redis_outage_does_not_report_success` in
    // `tests/auth_redis_outage.rs` drives it against a dead Redis.
    if let Err(err) = sp_redis::blacklist_jti(&state.redis_pool, &ctx.jti, remaining).await {
        return api_error_to_response(err);
    }

    // Phase 6 / Plan 06-01 — evict from in-process auth cache on logout (D-16).
    //
    // FU3 — LOCAL only, and unlike the revocation case this one does leave a
    // residual: a `jti` blacklisted before Redis became unreachable is not
    // visible to another pod's degraded path, because nothing outside Redis
    // records it. That residual is what `AuthOutage::LogoutUnverifiable`
    // names on the response header and in
    // `secureprompt_auth_gate_engaged_total`, and what
    // `DEGRADED_AUTH_CACHE_TTL_SECS` bounds to 60 s.
    state.auth_cache.remove(&ctx.user_id);

    // Revoke-all refresh rows for this user — no-op if none are active.
    let _ = state.refresh_tokens.revoke_all_for_user(ctx.user_id).await;

    StatusCode::NO_CONTENT.into_response()
}

fn validate_register_input(
    email: &str,
    password: &str,
    workspace_name: &str,
) -> Result<(), ApiError> {
    if email.is_empty() || email.len() > 255 || !email.contains('@') {
        return Err(ApiError::BadRequest("email invalid".into()));
    }
    if password.len() < 8 || password.len() > 128 {
        return Err(ApiError::BadRequest(
            "password must be 8–128 characters".into(),
        ));
    }
    if workspace_name.is_empty() || workspace_name.chars().count() > 100 {
        return Err(ApiError::BadRequest(
            "workspace_name must be 1–100 characters".into(),
        ));
    }
    Ok(())
}

/// `POST /v1/auth/register` — create a workspace + owner user in one call.
///
/// Gated by `AppConfig.public_signup_enabled`. Public route (no JWT layer).
pub async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RegisterRequest>,
) -> Response {
    if !state.config.public_signup_enabled {
        return api_error_to_response(ApiError::Forbidden(
            "public signup is disabled on this deployment".into(),
        ));
    }

    // Rate limit BEFORE validation so malformed-request bursts (e.g. a
    // brute-force probe spraying garbage payloads) still count against the
    // per-IP quota. The spec §5 originally specified the opposite ordering,
    // but security review (Task 9) overrode it.
    let ip_key = client_ip_key(&headers);
    if state
        .signup_rate_limiter
        .check(&format!("signup:{ip_key}"))
        .await
        .is_err()
    {
        return api_error_to_response(ApiError::TooManyRequests(
            "rate limit exceeded for signup".into(),
        ));
    }

    let email = body.email.trim().to_ascii_lowercase();
    let workspace_name = body.workspace_name.trim().to_owned();

    if let Err(err) = validate_register_input(&email, &body.password, &workspace_name) {
        return api_error_to_response(err);
    }

    let hash = match user_repo::hash_password(&body.password) {
        Ok(h) => h,
        Err(err) => return api_error_to_response(err),
    };

    let ws_repo = crate::db::workspace_repo::WorkspaceRepository::new(state.db.clone());
    let (ws, user) = match ws_repo
        .create_with_owner(&workspace_name, &email, &hash)
        .await
    {
        Ok(pair) => pair,
        Err(err) => return api_error_to_response(err),
    };

    // KNOWN BEHAVIOUR: if `build_token_pair_body` fails after `create_with_owner`
    // has already committed, the workspace + user rows exist but the client
    // gets a 500 with no token. They can recover by calling `POST /v1/auth/token`
    // with their email/password. This is rare (only fires on Redis or DB
    // failure during refresh-token persistence) and acceptable for MVP.
    match build_token_pair_body(&state, user.id, ws.id, "owner", &user.email).await {
        Ok(body) => (StatusCode::CREATED, JsonResponse(body)).into_response(),
        Err(err) => api_error_to_response(err),
    }
}

// ---------- Helpers ----------

/// Build a `TokenResponse` (access + refresh, with persistence side-effects)
/// without wrapping in an HTTP response. Both `/auth/token` (200) and
/// `/auth/register` (201) use this, then differ only in the status code.
pub(crate) async fn build_token_pair_body(
    state: &AppState,
    user_id: Uuid,
    workspace_id: Uuid,
    role: &str,
    email: &str,
) -> Result<TokenResponse, ApiError> {
    let now = Utc::now();
    let access_exp = now + Duration::seconds(state.jwt.access_ttl_secs as i64);
    let refresh_exp = now + Duration::seconds(state.jwt.refresh_ttl_secs as i64);
    let jti = Uuid::new_v4().to_string();
    let access_claims = Claims {
        sub: user_id,
        ws: workspace_id,
        role: role.to_owned(),
        iat: now.timestamp(),
        exp: access_exp.timestamp(),
        jti,
        purpose: None,
    };
    let access_token = encode_access(state, &access_claims)?;

    let refresh_raw = random_refresh_token();
    state
        .refresh_tokens
        .insert(user_id, workspace_id, &refresh_raw, refresh_exp)
        .await?;

    Ok(TokenResponse {
        access_token,
        refresh_token: refresh_raw,
        user: UserDto {
            id: user_id,
            email: email.to_owned(),
        },
        workspace_id,
        role: role.to_owned(),
        access_expires_at: access_exp.timestamp(),
        refresh_expires_at: refresh_exp.timestamp(),
    })
}

pub(crate) async fn issue_token_pair(
    state: &AppState,
    user_id: Uuid,
    workspace_id: Uuid,
    role: &str,
    email: &str,
) -> Response {
    match build_token_pair_body(state, user_id, workspace_id, role, email).await {
        Ok(body) => (StatusCode::OK, JsonResponse(body)).into_response(),
        Err(err) => api_error_to_response(err),
    }
}

fn encode_access(state: &AppState, claims: &Claims) -> Result<String, ApiError> {
    encode(&Header::new(Algorithm::HS256), claims, &state.jwt.encoding)
        .map_err(|error| ApiError::Internal(format!("jwt encode failed: {error}")))
}

/// Mint a short-lived, single-purpose token for the 2FA challenge/enrollment flow.
///
/// Signed with the exact same key + alg as `encode_access` — verification
/// stays on one code path — but the `purpose` claim (`Some(purpose)`) makes
/// `jwt_auth::require` (the normal-route auth middleware) reject it outright
/// (see `jwt_auth::is_access_claims`), so it can only ever be redeemed by the
/// dedicated `/v1/auth/2fa/*` extractor that calls `decode_purpose_token`
/// below.
///
/// `role` is intentionally omitted from the signature (per plan Task 4) —
/// a purpose token never reaches role-gated logic, so an empty placeholder
/// is stored rather than a real role.
///
/// # Errors
/// Returns `ApiError::Internal` if JWT encoding fails (mirrors `encode_access`).
pub fn encode_purpose_token(
    state: &AppState,
    user_id: Uuid,
    workspace_id: Uuid,
    purpose: &str,
    ttl_secs: i64,
) -> Result<String, ApiError> {
    let now = Utc::now();
    let claims = Claims {
        sub: user_id,
        ws: workspace_id,
        role: String::new(),
        iat: now.timestamp(),
        exp: (now + Duration::seconds(ttl_secs)).timestamp(),
        jti: Uuid::new_v4().to_string(),
        purpose: Some(purpose.to_owned()),
    };
    encode_access(state, &claims)
}

/// Verify a token minted by `encode_purpose_token`: signature, expiry, and
/// that its `purpose` claim matches `expected_purpose` exactly. Returns
/// `(user_id, workspace_id)` on success.
///
/// A normal access token (`purpose = None`) or a token for a *different*
/// purpose (e.g. presenting a `2fa_enroll` token where `2fa_challenge` is
/// required) is rejected with the same generic `Unauthorized` used
/// elsewhere on the auth surface, so failure reasons don't leak.
///
/// # Errors
/// Returns `ApiError::Unauthorized` on a bad/expired signature or a
/// missing/mismatched `purpose` claim.
pub fn decode_purpose_token(
    state: &AppState,
    token: &str,
    expected_purpose: &str,
) -> Result<(Uuid, Uuid), ApiError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.leeway = 60;
    validation.validate_exp = true;
    validation.set_required_spec_claims(&["exp", "iat", "sub"]);

    let decoded = decode::<Claims>(token, &state.jwt.decoding, &validation)
        .map_err(|_| ApiError::Unauthorized("Invalid credentials".into()))?;
    let claims = decoded.claims;

    if claims.purpose.as_deref() != Some(expected_purpose) {
        return Err(ApiError::Unauthorized("Invalid credentials".into()));
    }

    Ok((claims.sub, claims.ws))
}

fn random_refresh_token() -> String {
    // 32 bytes of OS randomness → base64url(no padding) → 43 chars.
    // `OsRng` re-exported via the `argon2` dep avoids adding a direct
    // `rand` dependency.
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn client_ip_key(headers: &HeaderMap) -> String {
    // Prefer `X-Forwarded-For` when nginx terminates TLS. The router does
    // not currently attach `ConnectInfo` (no `into_make_service_with_connect_info`
    // call), so header-only extraction is the supported path for on-prem
    // deployments where a reverse proxy is mandatory.
    if let Some(value) = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
    {
        return value.trim().to_owned();
    }
    "unknown".to_owned()
}

/// Shape-stable error envelope for every auth failure. Body is
/// `{"error":{"code":"invalid_credentials","message":"Invalid
/// credentials","type":"secureprompt_error"}}`.
fn generic_401(_hint: Option<ApiError>) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        JsonResponse(json!({
            "error": {
                "code": "invalid_credentials",
                "message": "Invalid credentials",
                "type": "secureprompt_error"
            }
        })),
    )
        .into_response()
}

fn api_error_to_response(error: ApiError) -> Response {
    crate::http::api_error_response(error)
}

async fn fetch_user_by_id(
    pool: &sqlx::PgPool,
    user_id: Uuid,
) -> Result<Option<UserIdentity>, ApiError> {
    let row = sqlx::query(
        "SELECT id, workspace_id, email, role FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(|error| ApiError::Database(error.to_string()))?;
    Ok(row.map(|record| UserIdentity {
        _id: sqlx::Row::get(&record, "id"),
        _workspace_id: WorkspaceId(sqlx::Row::get(&record, "workspace_id")),
        email: sqlx::Row::get(&record, "email"),
        role: sqlx::Row::get(&record, "role"),
    }))
}

struct UserIdentity {
    _id: Uuid,
    _workspace_id: WorkspaceId,
    email: String,
    role: String,
}

// Force axum's `Body` import to stay live for future hand-rolled responses
// in tests that mount this router.
#[allow(dead_code)]
type AuthResponseBody = Body;

#[cfg(test)]
mod tests {
    use super::*;

    /// Exhaustive truth table for `decide_2fa` (2FA, Task 5) — DB-free, no
    /// `AppState` required. Covers every `UserRole` variant crossed with
    /// both `totp_confirmed` states (10 combinations), matching the plan's
    /// explicit cases plus the remaining roles for full coverage.
    #[test]
    fn decide_2fa_truth_table() {
        let cases = [
            // (role, totp_confirmed, expected)
            (UserRole::Owner, false, TwoFaDecision::Enroll),
            (UserRole::Admin, false, TwoFaDecision::Enroll),
            (UserRole::Owner, true, TwoFaDecision::Challenge),
            (UserRole::Admin, true, TwoFaDecision::Challenge),
            (UserRole::Viewer, false, TwoFaDecision::Access),
            (UserRole::Developer, false, TwoFaDecision::Access),
            (UserRole::Employee, false, TwoFaDecision::Access),
            // Once enrolled, every role is challenged — not just Owner/Admin.
            (UserRole::Viewer, true, TwoFaDecision::Challenge),
            (UserRole::Developer, true, TwoFaDecision::Challenge),
            (UserRole::Employee, true, TwoFaDecision::Challenge),
        ];

        for (role, totp_confirmed, expected) in cases {
            let actual = decide_2fa(role, totp_confirmed);
            assert_eq!(
                actual, expected,
                "decide_2fa({role:?}, totp_confirmed={totp_confirmed}) = {actual:?}, expected {expected:?}"
            );
        }
    }

    #[test]
    fn decide_2fa_confirmed_always_wins_over_role() {
        // Regression guard for the "once enrolled, always challenged"
        // invariant: even a role that doesn't *require* 2FA (Viewer) must
        // still be challenged if it has previously confirmed enrollment
        // (e.g. an opt-in Viewer per Task 6's enroll flow).
        for role in [
            UserRole::Owner,
            UserRole::Admin,
            UserRole::Developer,
            UserRole::Employee,
            UserRole::Viewer,
        ] {
            assert_eq!(decide_2fa(role, true), TwoFaDecision::Challenge);
        }
    }
}
