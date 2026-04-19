//! Phase 5 / Plan 05-01 — Bearer JWT middleware for the governance dashboard.
//!
//! Sibling of `api_key_auth.rs`. Per CONTEXT D-04 we do NOT modify
//! `api_key_auth.rs`; an endpoint belongs to exactly one auth family.
//!
//! The middleware:
//!   1. Extracts `Authorization: Bearer <jwt>`.
//!   2. Decodes the token with HS256 against `state.config.jwt.secret`.
//!      `jsonwebtoken::Validation` enforces `validate_exp=true`; the default
//!      leeway of 60 s stays unchanged.
//!   3. Checks `state.redis_pool` for `jti_blacklist:{jti}` — logged-out
//!      access tokens are rejected until natural expiry.
//!      On Redis failure, falls back to `state.auth_cache` (D-15, PG-04).
//!   4. Inserts `JwtAuthContext` into the request extensions so handlers can
//!      extract it via `axum::Extension<JwtAuthContext>`.
//!
//! All failure paths return `ApiError::Unauthorized(_)` with a generic copy
//! so an attacker cannot distinguish signature-fail from expiry-fail
//! (threat T-05-07 on the auth surface, T-05-02 on the JWT surface).
//!
//! Phase 6 / Plan 06-01 additions:
//!   * `UserRole` extended from 3 → 4 variants (Owner/Admin/Developer/Viewer)
//!   * `CachedAuthEntry` struct + 5-minute TTL in-memory auth cache (D-14, PG-04)
//!   * Write-through cache population on every successful auth (D-15)
//!   * Postgres/Redis failure fallback reads from `auth_cache` (D-15, PG-04)

use axum::{
    body::Body,
    extract::{Request, State},
    http::{header::AUTHORIZATION, HeaderMap},
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{decode, Algorithm, DecodingKey, EncodingKey, Validation};
use secureprompt_common::{config::JwtConfig, errors::ApiError, types::WorkspaceId};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::{app_state::AppState, http::api_error_response};

/// HS256 key material, cached on `AppState` so we only derive
/// `DecodingKey::from_secret` once per process.
///
/// Holds both halves because Task 5-01-C issues access tokens with the
/// `EncodingKey`; no sign/verify asymmetry is intended.
#[derive(Clone)]
pub struct JwtKeys {
    pub encoding: EncodingKey,
    pub decoding: DecodingKey,
    pub access_ttl_secs: u64,
    pub refresh_ttl_secs: u64,
}

impl JwtKeys {
    #[must_use]
    pub fn from_config(cfg: &JwtConfig) -> Arc<Self> {
        Arc::new(Self {
            encoding: EncodingKey::from_secret(cfg.secret.as_bytes()),
            decoding: DecodingKey::from_secret(cfg.secret.as_bytes()),
            access_ttl_secs: cfg.access_ttl_secs,
            refresh_ttl_secs: cfg.refresh_ttl_secs,
        })
    }
}

/// Role values permitted in `users.role`. Extended from 3→4 levels in Phase 6 (D-08, D-09).
/// `member` DB string is renamed `developer`; `owner` is added above `admin`.
/// Hierarchy: Owner > Admin > Developer > Viewer (highest to lowest privilege).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserRole {
    Owner,
    Admin,
    Developer, // renamed from Member (D-09)
    Viewer,
}

impl UserRole {
    #[must_use]
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Developer => "developer",
            Self::Viewer => "viewer",
        }
    }

    /// Parse from the `users.role` column value.
    ///
    /// # Errors
    /// Returns `ApiError::Internal` for unknown strings.
    pub fn from_db_str(value: &str) -> Result<Self, ApiError> {
        match value {
            "owner" => Ok(Self::Owner),
            "admin" => Ok(Self::Admin),
            "developer" => Ok(Self::Developer),
            // Backward compat: 'member' rows updated in migration 005, but accept during rollout.
            "member" => Ok(Self::Developer),
            "viewer" => Ok(Self::Viewer),
            other => Err(ApiError::Internal(format!("unknown role: {other}"))),
        }
    }
}

/// Extension type handlers consume via `Extension<JwtAuthContext>`.
/// Produced by `require` on every successful request.
#[derive(Debug, Clone)]
pub struct JwtAuthContext {
    pub user_id: Uuid,
    pub workspace_id: WorkspaceId,
    pub role: UserRole,
    pub jti: String,
    /// Unix-seconds at which the access token naturally expires. Used by
    /// `/v1/auth/logout` to size the Redis blacklist TTL (no point in
    /// blacklisting a jti past its own `exp`).
    pub exp: i64,
}

/// Phase 6 / Plan 06-01 — Per-pod in-memory auth cache entry (D-14, PG-04).
///
/// Stored in `AppState.auth_cache: Arc<DashMap<Uuid, CachedAuthEntry>>`.
/// TTL = 5 minutes, checked on every read (no background eviction).
/// Key: `user_id` (Uuid).
#[derive(Debug, Clone)]
pub struct CachedAuthEntry {
    pub user_id: uuid::Uuid,
    pub workspace_id: secureprompt_common::types::WorkspaceId,
    pub role: UserRole,
    pub cached_at: std::time::Instant,
}

impl CachedAuthEntry {
    /// Returns `true` if the entry is still within the 5-minute TTL.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.cached_at.elapsed().as_secs() < 300
    }
}

/// JWT payload. Short field names (`sub`, `ws`) keep the encoded token
/// compact on the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub ws: Uuid,
    pub role: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
}

/// Axum middleware compatible with `middleware::from_fn_with_state`.
///
/// Returns the pre-rendered error `Response` on failure rather than
/// propagating `ApiError` — `ApiError` does not implement `IntoResponse`
/// (the gateway deliberately routes every error through `api_error_response`
/// so the OpenAI-compatible envelope is preserved). Every failure path
/// yields 401 with the generic body `{"error":{"message":"Invalid
/// credentials","type":"secureprompt_error"}}` so an attacker cannot
/// distinguish signature / expiry / jti failures (threats T-05-02,
/// T-05-07).
pub async fn require(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, Response> {
    let token =
        extract_bearer(req.headers()).map_err(api_error_response)?;

    let mut validation = Validation::new(Algorithm::HS256);
    validation.leeway = 60;
    validation.validate_exp = true;
    // `sub` is a UUID string but `jsonwebtoken` deserializes it straight into
    // `Uuid`; `exp` + `iat` are default-required for HS256.
    validation.set_required_spec_claims(&["exp", "iat", "sub"]);

    let decoded = decode::<Claims>(&token, &state.jwt.decoding, &validation)
        .map_err(|_| api_error_response(ApiError::Unauthorized("Invalid credentials".into())))?;

    let claims = decoded.claims;

    // jti blacklist gate — `POST /v1/auth/logout` plants these entries.
    // On Redis failure, fall back to in-memory cache (D-15, PG-04).
    // PITFALL 4: clone out of the DashMap Ref before any await point.
    let blacklisted = match crate::redis::jti_is_blacklisted(&state.redis_pool, &claims.jti).await {
        Ok(b) => b,
        Err(_redis_err) => {
            // Redis/Postgres unavailable — fall back to in-memory cache (D-15, PG-04).
            // Pitfall 4: clone out of the Ref before doing anything else.
            if let Some(entry) = state.auth_cache.get(&claims.sub) {
                if entry.is_valid() {
                    // Cache hit — rebuild context from cache and short-circuit.
                    let cached_role = entry.role;
                    let cached_workspace = entry.workspace_id.clone();
                    drop(entry); // release DashMap shard lock before next operation
                    req.extensions_mut().insert(JwtAuthContext {
                        user_id: claims.sub,
                        workspace_id: cached_workspace,
                        role: cached_role,
                        jti: claims.jti,
                        exp: claims.exp,
                    });
                    return Ok(next.run(req).await);
                }
            }
            return Err(api_error_response(ApiError::ServiceUnavailable(
                "auth service temporarily unavailable".into(),
            )));
        }
    };

    if blacklisted {
        return Err(api_error_response(ApiError::Unauthorized(
            "Invalid credentials".into(),
        )));
    }

    let role = UserRole::from_db_str(&claims.role).map_err(|_| {
        api_error_response(ApiError::Unauthorized("Invalid credentials".into()))
    })?;

    // Write-through: populate cache on every successful auth (D-15, PG-04).
    // NOTE: do NOT hold the DashMap Ref across an await — clone out immediately (Pitfall 4).
    state.auth_cache.insert(claims.sub, CachedAuthEntry {
        user_id: claims.sub,
        workspace_id: WorkspaceId(claims.ws),
        role,
        cached_at: std::time::Instant::now(),
    });

    req.extensions_mut().insert(JwtAuthContext {
        user_id: claims.sub,
        workspace_id: WorkspaceId(claims.ws),
        role,
        jti: claims.jti,
        exp: claims.exp,
    });

    Ok(next.run(req).await)
}

/// Extract the raw JWT from `Authorization: Bearer <token>`.
///
/// # Errors
/// Generic `Unauthorized` for missing, malformed, or non-Bearer headers.
pub fn extract_bearer(headers: &HeaderMap) -> Result<String, ApiError> {
    let value = headers
        .get(AUTHORIZATION)
        .ok_or_else(|| ApiError::Unauthorized("Invalid credentials".into()))?
        .to_str()
        .map_err(|_| ApiError::Unauthorized("Invalid credentials".into()))?;
    let token = value
        .strip_prefix("Bearer ")
        .ok_or_else(|| ApiError::Unauthorized("Invalid credentials".into()))?;
    Ok(token.to_owned())
}

// `axum::body::Body` is imported purely so handlers that want to hand-roll
// responses inside tests have an easy path to build them; it is used by the
// integration tests in `tests/dashboard/jwt.rs`.
pub type ResponseBody = Body;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};
    use chrono::{Duration, Utc};
    use jsonwebtoken::{encode, Header};
    use uuid::Uuid;

    fn sample_claims(ttl: Duration) -> (Claims, DecodingKey, EncodingKey) {
        let secret = b"test-secret-value";
        let now = Utc::now();
        let claims = Claims {
            sub: Uuid::new_v4(),
            ws: Uuid::new_v4(),
            role: "admin".into(),
            iat: now.timestamp(),
            exp: (now + ttl).timestamp(),
            jti: Uuid::new_v4().to_string(),
        };
        (
            claims,
            DecodingKey::from_secret(secret),
            EncodingKey::from_secret(secret),
        )
    }

    #[test]
    fn extracts_bearer_token() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer abc.def.ghi"));
        let token = extract_bearer(&headers).expect("bearer token");
        assert_eq!(token, "abc.def.ghi");
    }

    #[test]
    fn rejects_missing_header() {
        let headers = HeaderMap::new();
        let result = extract_bearer(&headers);
        assert!(matches!(result, Err(ApiError::Unauthorized(_))));
    }

    #[test]
    fn rejects_non_bearer_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Basic abc"));
        let result = extract_bearer(&headers);
        assert!(matches!(result, Err(ApiError::Unauthorized(_))));
    }

    #[test]
    fn user_role_roundtrips_through_db_strings() {
        for value in ["owner", "admin", "developer", "viewer"] {
            let role = UserRole::from_db_str(value).expect("valid role");
            assert_eq!(role.as_db_str(), value);
        }
        // Legacy 'member' still accepted but maps to Developer.
        assert!(matches!(UserRole::from_db_str("member"), Ok(UserRole::Developer)));
        assert!(UserRole::from_db_str("root").is_err());
    }

    #[test]
    fn happy_path_decode_accepts_valid_token() {
        let (claims, decoding, encoding) = sample_claims(Duration::minutes(15));
        let token = encode(&Header::new(Algorithm::HS256), &claims, &encoding)
            .expect("encode test token");
        let mut validation = Validation::new(Algorithm::HS256);
        validation.leeway = 60;
        let decoded = decode::<Claims>(&token, &decoding, &validation).expect("decode");
        assert_eq!(decoded.claims.sub, claims.sub);
        assert_eq!(decoded.claims.jti, claims.jti);
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let (claims, decoding, encoding) = sample_claims(Duration::minutes(15));
        let token = encode(&Header::new(Algorithm::HS256), &claims, &encoding)
            .expect("encode test token");
        // Flip the last byte of the signature segment.
        let mut tampered = token.clone();
        let last = tampered.pop().expect("non-empty token");
        let replacement = if last == 'A' { 'B' } else { 'A' };
        tampered.push(replacement);
        let validation = Validation::new(Algorithm::HS256);
        let result = decode::<Claims>(&tampered, &decoding, &validation);
        assert!(result.is_err(), "tampered signature must fail decode");
    }

    #[test]
    fn expired_token_is_rejected() {
        let (claims, decoding, encoding) = sample_claims(Duration::seconds(-3600));
        let token = encode(&Header::new(Algorithm::HS256), &claims, &encoding)
            .expect("encode test token");
        let mut validation = Validation::new(Algorithm::HS256);
        validation.leeway = 0;
        let result = decode::<Claims>(&token, &decoding, &validation);
        assert!(result.is_err(), "expired token must fail decode");
    }
}
