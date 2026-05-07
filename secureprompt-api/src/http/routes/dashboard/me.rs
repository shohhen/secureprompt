//! `/v1/me/*` — endpoints scoped to the authenticated workspace member.
//!
//! Currently exposes `GET /v1/me/api-key` for the LibreChat backend (and
//! any future trusted server-to-server caller) to retrieve the plaintext
//! API key assigned to the JWT-authed user. The plaintext lives encrypted
//! at rest in `api_keys.key_ciphertext` (009 migration); this endpoint
//! decrypts it via the configured KMS backend on each call.
//!
//! Why server-to-server only:
//!   * Members must NEVER type or see the raw key — that's the threat
//!     model that motivated assigning keys in the dashboard rather than
//!     emailing them.
//!   * LibreChat's auth proxy authenticates the user via SP's JWT
//!     (login flow), then immediately calls this endpoint once with that
//!     JWT to fetch the plaintext, and uses it as the bearer token for
//!     all downstream `/v1/chat/completions` calls. The plaintext lives
//!     in LibreChat's process memory for the session; never persisted.
//!
//! Returns 404 when the user has no assigned key (admin must create one
//! first via the dashboard) — never returns an empty 200, because callers
//! would otherwise have to disambiguate "fetched empty string" from
//! "decryption failed silently".

use axum::{
    extract::{Extension, State},
    http::HeaderMap,
    routing::get,
    Json, Router,
};
use secureprompt_common::errors::ApiError;
use serde::{Deserialize, Serialize};
use sqlx::Row;

use crate::{
    app_state::AppState,
    db::api_key_repo::ApiKeyRepository,
    http::{api_error_response, middleware::jwt_auth::JwtAuthContext},
};

#[derive(Debug, Serialize)]
pub struct MyApiKeyResponse {
    /// The full plaintext API key (e.g. `sp_…`). Caller must not log this.
    pub api_key: String,
}

#[derive(Debug, Serialize)]
pub struct MyProfileResponse {
    pub user_id: uuid::Uuid,
    pub workspace_id: uuid::Uuid,
    pub email: String,
    pub role: String,
    /// First name. `None` until the user fills out the profile form.
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub position: Option<String>,
    /// Convenience field for the dashboard sidebar — `"First Last"`,
    /// or the part of the email before `@` when the profile is empty.
    pub display_name: String,
    /// Self-reported MAC address from the Electron desktop wrapper.
    /// `None` for browser users; updated last-write-wins on every
    /// profile read where the request carries `X-SecurePrompt-Device-MAC`.
    pub device_mac: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateProfileRequest {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub position: Option<String>,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api-key", get(get_my_api_key))
        .route("/profile", get(get_my_profile).put(put_my_profile))
}

/// `GET /v1/me/api-key` — return the plaintext API key assigned to the
/// caller. Authenticated via JWT (any role).
async fn get_my_api_key(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
) -> Result<Json<MyApiKeyResponse>, axum::response::Response> {
    let repo = ApiKeyRepository::new(state.db.clone());
    let plaintext = repo
        .fetch_plaintext_for_user(ctx.workspace_id, ctx.user_id, state.kms.as_ref())
        .await
        .map_err(api_error_response)?;

    match plaintext {
        Some(api_key) => Ok(Json(MyApiKeyResponse { api_key })),
        None => Err(api_error_response(ApiError::NotFound(
            "no API key assigned to this user".into(),
        ))),
    }
}

/// `GET /v1/me/profile` — read the caller's profile fields + role.
///
/// Side effect: when the request carries `X-SecurePrompt-Device-MAC`
/// (set by the Electron desktop wrapper), persist the MAC to the user
/// row so audit-log lookups on this user pick it up. We accept the
/// header on read because the dashboard hits this endpoint on every
/// page load — that gives us a refresh path without needing a
/// dedicated `/v1/me/device` endpoint.
async fn get_my_profile(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    headers: HeaderMap,
) -> Result<Json<MyProfileResponse>, axum::response::Response> {
    if let Some(mac) = extract_device_mac(&headers) {
        // Best-effort write — failures are logged but don't fail the read.
        if let Err(e) = sqlx::query(
            "UPDATE users SET device_mac = $1, updated_at = NOW()
             WHERE id = $2 AND workspace_id = $3",
        )
        .bind(&mac)
        .bind(ctx.user_id)
        .bind(ctx.workspace_id.0)
        .execute(&state.db)
        .await
        {
            tracing::warn!(error = %e, user_id = %ctx.user_id, "device_mac update failed");
        }
    }

    let row = sqlx::query(
        "SELECT email, role, first_name, last_name, position, device_mac
         FROM users WHERE id = $1 AND workspace_id = $2",
    )
    .bind(ctx.user_id)
    .bind(ctx.workspace_id.0)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| api_error_response(ApiError::Database(e.to_string())))?
    .ok_or_else(|| api_error_response(ApiError::NotFound("user not found".into())))?;

    let email: String = row.get("email");
    let role: String = row.get("role");
    let first_name: Option<String> = row.get("first_name");
    let last_name: Option<String> = row.get("last_name");
    let position: Option<String> = row.get("position");
    let device_mac: Option<String> = row.get("device_mac");

    let display_name = build_display_name(&email, first_name.as_deref(), last_name.as_deref());

    Ok(Json(MyProfileResponse {
        user_id: ctx.user_id,
        workspace_id: ctx.workspace_id.0,
        email,
        role,
        first_name,
        last_name,
        position,
        display_name,
        device_mac,
    }))
}

/// Validate + normalise a `X-SecurePrompt-Device-MAC` header value.
/// Accepts the canonical 12-hex-with-colons form (`aa:bb:cc:dd:ee:ff`)
/// case-insensitive, and the `-` separator variant. Anything else is
/// dropped — we don't want unbounded user-controlled strings landing
/// in `users.device_mac` without basic shape-checking.
fn extract_device_mac(headers: &HeaderMap) -> Option<String> {
    let raw = headers
        .get("x-secureprompt-device-mac")
        .and_then(|v| v.to_str().ok())?
        .trim();
    if raw.is_empty() {
        return None;
    }
    // Accept either ':' or '-' separators; normalise to lowercase + ':'.
    let normalised = raw.replace('-', ":").to_ascii_lowercase();
    let parts: Vec<&str> = normalised.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    if !parts
        .iter()
        .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return None;
    }
    Some(normalised)
}

/// `PUT /v1/me/profile` — update the caller's own personal fields.
///
/// Any authenticated user can update their own profile regardless of
/// role. Empty strings are stored as NULL so the display-name fallback
/// kicks in — saves a "" → "John " bug.
async fn put_my_profile(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    headers: HeaderMap,
    Json(body): Json<UpdateProfileRequest>,
) -> Result<Json<MyProfileResponse>, axum::response::Response> {
    let normalize = |v: Option<String>| -> Option<String> {
        v.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty())
    };
    let first_name = normalize(body.first_name);
    let last_name = normalize(body.last_name);
    let position = normalize(body.position);

    sqlx::query(
        "UPDATE users
         SET first_name = $1, last_name = $2, position = $3, updated_at = NOW()
         WHERE id = $4 AND workspace_id = $5",
    )
    .bind(&first_name)
    .bind(&last_name)
    .bind(&position)
    .bind(ctx.user_id)
    .bind(ctx.workspace_id.0)
    .execute(&state.db)
    .await
    .map_err(|e| api_error_response(ApiError::Database(e.to_string())))?;

    get_my_profile(State(state), Extension(ctx), headers).await
}

fn build_display_name(email: &str, first: Option<&str>, last: Option<&str>) -> String {
    match (first, last) {
        (Some(f), Some(l)) => format!("{f} {l}"),
        (Some(f), None) => f.to_owned(),
        (None, Some(l)) => l.to_owned(),
        (None, None) => email
            .split('@')
            .next()
            .unwrap_or(email)
            .to_owned(),
    }
}
