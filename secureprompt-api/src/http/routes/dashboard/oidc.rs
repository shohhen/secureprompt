//! Phase 6 / Plan 06-02 — OAuth2/OIDC PKCE routes (AUTH-03, D-11..D-13).
//!
//! Routes:
//!   GET /v1/auth/oidc/authorize — generate PKCE challenge, return authorization_url
//!   GET /v1/auth/oidc/callback  — validate state, exchange code, issue SP token pair
//!
//! OIDC provider config env vars:
//!   SECUREPROMPT_OIDC_CLIENT_ID
//!   SECUREPROMPT_OIDC_CLIENT_SECRET
//!   SECUREPROMPT_OIDC_ISSUER_URL
//!   SECUREPROMPT_OIDC_REDIRECT_URI
//!
//! PKCE state is stored in Redis as `oidc_state:{csrf_token_secret}` with 600s TTL.
//! The callback uses GETDEL to consume the state atomically, preventing replay (D-12).

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Json as JsonResponse, Response},
    routing::get,
    Router,
};
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    EndpointNotSet, EndpointSet, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    app_state::AppState,
    http::middleware::jwt_auth::UserRole,
    http::routes::dashboard::auth::{
        decide_2fa, encode_purpose_token, issue_token_pair, TokenOr2fa, TwoFaDecision,
    },
    http::routes::dashboard::device::DeviceContext,
    redis as sp_redis,
};
use secureprompt_common::errors::ApiError;

// ── DTOs ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct AuthorizeResponse {
    authorization_url: String,
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: String,
    pub state: String,
}

#[derive(Debug, Deserialize)]
struct OidcUserInfo {
    pub sub: String,
    pub email: Option<String>,
}

// ── OIDC discovery ─────────────────────────────────────────────────────────────

/// Minimal OIDC discovery document (D-11 — manual reqwest fetch, no openid_connect crate).
#[derive(Debug, Deserialize)]
struct OidcDiscovery {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: Option<String>,
}

async fn discover_oidc(issuer_url: &str) -> Result<OidcDiscovery, ApiError> {
    let well_known = format!(
        "{}/.well-known/openid-configuration",
        issuer_url.trim_end_matches('/')
    );
    reqwest::get(&well_known)
        .await
        .map_err(|e| ApiError::Internal(format!("OIDC discovery fetch failed: {e}")))?
        .json::<OidcDiscovery>()
        .await
        .map_err(|e| ApiError::Internal(format!("OIDC discovery parse failed: {e}")))
}

// ── Router ─────────────────────────────────────────────────────────────────────

#[must_use]
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/oidc/authorize", get(oidc_authorize))
        .route("/oidc/callback", get(oidc_callback))
}

// ── Handlers ───────────────────────────────────────────────────────────────────

/// `GET /v1/auth/oidc/authorize`
///
/// 1. Reads OIDC env vars.
/// 2. Fetches `.well-known/openid-configuration` from the issuer.
/// 3. Generates PKCE challenge + CSRF token.
/// 4. Stores PKCE verifier secret in Redis: `oidc_state:{csrf_token}` EX 600.
/// 5. Returns `{"authorization_url": "https://idp.example.com/authorize?..."}`.
///    The frontend redirects the user to this URL.
pub async fn oidc_authorize(State(state): State<AppState>) -> Response {
    let (client_id, client_secret, issuer_url, redirect_uri) = match read_oidc_env() {
        Ok(v) => v,
        Err(e) => return api_error_to_response(e),
    };

    let discovery = match discover_oidc(&issuer_url).await {
        Ok(d) => d,
        Err(e) => return api_error_to_response(e),
    };

    let oauth_client = match build_oauth_client(
        &client_id,
        &client_secret,
        &discovery.authorization_endpoint,
        &discovery.token_endpoint,
        &redirect_uri,
    ) {
        Ok(c) => c,
        Err(e) => return api_error_to_response(e),
    };

    // Generate PKCE challenge + CSRF token (D-12).
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, csrf_token) = oauth_client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    // Store verifier secret in Redis with 10-min TTL.
    if let Err(e) = sp_redis::store_oidc_state(
        &state.redis_pool,
        csrf_token.secret(),
        pkce_verifier.secret(),
        600,
    )
    .await
    {
        return api_error_to_response(e);
    }

    (
        StatusCode::OK,
        JsonResponse(AuthorizeResponse {
            authorization_url: auth_url.to_string(),
        }),
    )
        .into_response()
}

/// `GET /v1/auth/oidc/callback?code=...&state=...`
///
/// 1. Validates `state` param against Redis (GETDEL — atomic, prevents replay).
/// 2. Reconstructs PKCE verifier.
/// 3. Exchanges authorization code for tokens with PKCE verifier.
/// 4. Fetches email from userinfo endpoint.
/// 5. Looks up a matching user record.
/// 6. Issues SecurePrompt JWT pair via `issue_token_pair` (same as credentials flow).
pub async fn oidc_callback(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(params): Query<CallbackQuery>,
) -> Response {
    let (client_id, client_secret, issuer_url, redirect_uri) = match read_oidc_env() {
        Ok(v) => v,
        Err(e) => return api_error_to_response(e),
    };

    let discovery = match discover_oidc(&issuer_url).await {
        Ok(d) => d,
        Err(e) => return api_error_to_response(e),
    };

    // Consume PKCE verifier from Redis (GETDEL — prevents replay attack).
    let verifier_secret = match sp_redis::consume_oidc_state(&state.redis_pool, &params.state).await
    {
        Ok(Some(v)) => v,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                JsonResponse(json!({
                    "error": {
                        "code": "invalid_state",
                        "message": "Invalid or expired OAuth state parameter",
                        "type": "secureprompt_error"
                    }
                })),
            )
                .into_response()
        }
        Err(e) => return api_error_to_response(e),
    };

    let pkce_verifier = PkceCodeVerifier::new(verifier_secret);

    let oauth_client = match build_oauth_client(
        &client_id,
        &client_secret,
        &discovery.authorization_endpoint,
        &discovery.token_endpoint,
        &redirect_uri,
    ) {
        Ok(c) => c,
        Err(e) => return api_error_to_response(e),
    };

    // Build an HTTP client that disables redirects (required to prevent SSRF).
    let http_client = match oauth2::reqwest::ClientBuilder::new()
        .redirect(oauth2::reqwest::redirect::Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return api_error_to_response(ApiError::Internal(format!(
                "oauth2 http client build failed: {e}"
            )))
        }
    };

    // Exchange authorization code for tokens using the PKCE verifier.
    let token_result = match oauth_client
        .exchange_code(AuthorizationCode::new(params.code))
        .set_pkce_verifier(pkce_verifier)
        .request_async(&http_client)
        .await
    {
        Ok(t) => t,
        Err(e) => {
            return api_error_to_response(ApiError::Unauthorized(format!(
                "OIDC token exchange failed: {e}"
            )))
        }
    };

    // Extract email: try userinfo endpoint if available.
    let email = match fetch_oidc_email(&discovery, token_result.access_token().secret()).await {
        Ok(email) => email,
        Err(e) => return api_error_to_response(e),
    };

    // Look up user by email (workspace must already exist for OIDC users).
    let row = match crate::db::user_repo::UserRepository::new(state.db.clone())
        .find_by_email_with_role(&email)
        .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            return (
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
        Err(e) => return api_error_to_response(e),
    };

    // 2FA parity (security review, whole-branch fix): OIDC used to mint a
    // full session unconditionally here, bypassing the TOTP gate that
    // `token()` (password login) enforces for Owner/Admin. Delegate to the
    // same decision `token()` uses instead of inlining it, both to keep
    // this function short and so the two login paths cannot drift apart.
    issue_token_or_2fa_response(&state, &row, &DeviceContext::from_headers(&headers)).await
}

/// Shared tail of `oidc_callback`: apply the exact same 2FA decision
/// `token()` applies after password verification — via the shared
/// `decide_2fa`/`TokenOr2fa`/`encode_purpose_token` machinery — so an
/// OIDC-authenticated Owner/Admin cannot skip 2FA by using this path
/// instead of `/v1/auth/token`.
/// `pub` rather than private so an integration test can drive it directly.
/// `oidc_callback` cannot be exercised without a live identity provider —
/// discovery, code exchange and a userinfo fetch all happen before this point —
/// and this is the whole of the callback that decides what an OIDC sign-in
/// does, so testing it here is testing the OIDC path with only the network
/// hops omitted.
pub async fn issue_token_or_2fa_response(
    state: &AppState,
    row: &crate::db::user_repo::UserCredentials,
    device: &DeviceContext,
) -> Response {
    let role = match UserRole::from_db_str(&row.role) {
        Ok(role) => role,
        Err(err) => return api_error_to_response(err),
    };

    match decide_2fa(role, row.totp_confirmed_at.is_some()) {
        TwoFaDecision::Access => {
            // Unchanged — same envelope as the credentials flow.
            issue_token_pair(
                state,
                row.id,
                row.workspace_id,
                &row.role,
                &row.email,
                device,
            )
            .await
        }
        TwoFaDecision::Challenge => {
            match encode_purpose_token(state, row.id, row.workspace_id, "2fa_challenge", 300) {
                Ok(challenge_token) => TokenOr2fa::Challenge { challenge_token }.into_response(),
                Err(err) => api_error_to_response(err),
            }
        }
        TwoFaDecision::Enroll => {
            match encode_purpose_token(state, row.id, row.workspace_id, "2fa_enroll", 300) {
                Ok(enrollment_token) => TokenOr2fa::Enroll { enrollment_token }.into_response(),
                Err(err) => api_error_to_response(err),
            }
        }
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────────

fn read_oidc_env() -> Result<(String, String, String, String), ApiError> {
    let client_id = std::env::var("SECUREPROMPT_OIDC_CLIENT_ID")
        .map_err(|_| ApiError::Internal("SECUREPROMPT_OIDC_CLIENT_ID not set".into()))?;
    let client_secret = std::env::var("SECUREPROMPT_OIDC_CLIENT_SECRET")
        .map_err(|_| ApiError::Internal("SECUREPROMPT_OIDC_CLIENT_SECRET not set".into()))?;
    let issuer_url = std::env::var("SECUREPROMPT_OIDC_ISSUER_URL")
        .map_err(|_| ApiError::Internal("SECUREPROMPT_OIDC_ISSUER_URL not set".into()))?;
    let redirect_uri = std::env::var("SECUREPROMPT_OIDC_REDIRECT_URI")
        .map_err(|_| ApiError::Internal("SECUREPROMPT_OIDC_REDIRECT_URI not set".into()))?;
    Ok((client_id, client_secret, issuer_url, redirect_uri))
}

/// Returns a `BasicClient` with both auth and token URIs set.
/// The concrete return type carries `EndpointSet` markers so `authorize_url`
/// and `exchange_code` are available on the returned value.
fn build_oauth_client(
    client_id: &str,
    client_secret: &str,
    auth_endpoint: &str,
    token_endpoint: &str,
    redirect_uri: &str,
) -> Result<
    BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>,
    ApiError,
> {
    // CRITICAL — use set_auth_uri / set_token_uri (oauth2 v5 names).
    // set_auth_url / set_token_url are v4 names and do NOT compile with oauth2 = "5".
    let auth_url = AuthUrl::new(auth_endpoint.to_owned())
        .map_err(|e| ApiError::Internal(format!("invalid auth_url: {e}")))?;
    let token_url = TokenUrl::new(token_endpoint.to_owned())
        .map_err(|e| ApiError::Internal(format!("invalid token_url: {e}")))?;

    Ok(BasicClient::new(ClientId::new(client_id.to_owned()))
        .set_client_secret(ClientSecret::new(client_secret.to_owned()))
        .set_auth_uri(auth_url) // v5 API — NOT set_auth_url
        .set_token_uri(token_url) // v5 API — NOT set_token_url
        .set_redirect_uri(
            RedirectUrl::new(redirect_uri.to_owned())
                .map_err(|e| ApiError::Internal(format!("invalid redirect_uri: {e}")))?,
        ))
}

async fn fetch_oidc_email(
    discovery: &OidcDiscovery,
    access_token: &str,
) -> Result<String, ApiError> {
    let Some(userinfo_endpoint) = &discovery.userinfo_endpoint else {
        return Err(ApiError::Internal(
            "OIDC provider does not expose userinfo_endpoint".into(),
        ));
    };

    let resp = reqwest::Client::new()
        .get(userinfo_endpoint)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| ApiError::Internal(format!("userinfo fetch failed: {e}")))?
        .json::<OidcUserInfo>()
        .await
        .map_err(|e| ApiError::Internal(format!("userinfo parse failed: {e}")))?;

    resp.email.ok_or_else(|| {
        ApiError::Internal("OIDC userinfo response does not include email claim".into())
    })
}

fn api_error_to_response(error: ApiError) -> Response {
    crate::http::api_error_response(error)
}

// Suppress unused-import warning: `sub` field exists for future use (token binding).
#[allow(dead_code)]
fn _use_sub_field(info: &OidcUserInfo) -> &str {
    &info.sub
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_oidc_env_returns_err_when_vars_missing() {
        // With no env vars set, every var lookup should fail.
        // Use a unique var name to avoid interference from real env.
        std::env::remove_var("SECUREPROMPT_OIDC_CLIENT_ID");
        let result = read_oidc_env();
        assert!(
            result.is_err(),
            "Expected Err when OIDC env vars are missing"
        );
    }

    #[test]
    fn build_oauth_client_rejects_invalid_auth_url() {
        let result = build_oauth_client(
            "id",
            "secret",
            "not-a-url",
            "https://token.example.com/token",
            "https://redirect.example.com/cb",
        );
        assert!(result.is_err(), "Expected Err for invalid auth_url");
    }

    #[test]
    fn build_oauth_client_rejects_invalid_token_url() {
        let result = build_oauth_client(
            "id",
            "secret",
            "https://auth.example.com/auth",
            "not-a-url",
            "https://redirect.example.com/cb",
        );
        assert!(result.is_err(), "Expected Err for invalid token_url");
    }

    #[test]
    fn build_oauth_client_rejects_invalid_redirect_uri() {
        let result = build_oauth_client(
            "id",
            "secret",
            "https://auth.example.com/auth",
            "https://token.example.com/token",
            "not-a-url",
        );
        assert!(result.is_err(), "Expected Err for invalid redirect_uri");
    }

    #[test]
    fn build_oauth_client_succeeds_with_valid_urls() {
        let result = build_oauth_client(
            "my-client-id",
            "my-client-secret",
            "https://idp.example.com/auth",
            "https://idp.example.com/token",
            "https://app.example.com/callback",
        );
        assert!(
            result.is_ok(),
            "Expected Ok for valid URLs, got: {result:?}"
        );
    }
}
