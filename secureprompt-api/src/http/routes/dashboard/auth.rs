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
use jsonwebtoken::{encode, Algorithm, Header};
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
    http::middleware::jwt_auth::{self, Claims, JwtAuthContext},
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

    issue_token_pair(&state, creds.id, creds.workspace_id, &creds.role, &creds.email).await
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
    if let Err(err) = sp_redis::blacklist_jti(&state.redis_pool, &ctx.jti, remaining).await {
        return api_error_to_response(err);
    }

    // Phase 6 / Plan 06-01 — evict from in-process auth cache on logout (D-16).
    state.auth_cache.remove(&ctx.user_id);

    // Revoke-all refresh rows for this user — no-op if none are active.
    let _ = state.refresh_tokens.revoke_all_for_user(ctx.user_id).await;

    StatusCode::NO_CONTENT.into_response()
}

// ---------- Helpers ----------

pub(crate) async fn issue_token_pair(
    state: &AppState,
    user_id: Uuid,
    workspace_id: Uuid,
    role: &str,
    email: &str,
) -> Response {
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
    };
    let access_token = match encode_access(state, &access_claims) {
        Ok(token) => token,
        Err(err) => return api_error_to_response(err),
    };

    let refresh_raw = random_refresh_token();
    if let Err(err) = state
        .refresh_tokens
        .insert(user_id, workspace_id, &refresh_raw, refresh_exp)
        .await
    {
        return api_error_to_response(err);
    }

    let body = TokenResponse {
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
    };
    (StatusCode::OK, JsonResponse(body)).into_response()
}

fn encode_access(state: &AppState, claims: &Claims) -> Result<String, ApiError> {
    encode(&Header::new(Algorithm::HS256), claims, &state.jwt.encoding)
        .map_err(|error| ApiError::Internal(format!("jwt encode failed: {error}")))
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
