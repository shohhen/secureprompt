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

/// Role values permitted in `users.role`.
///
/// Three primary roles surfaced on the dashboard:
///   * `Owner`     — full read + write across the workspace.
///   * `Developer` — full read across the workspace; no write.
///   * `Employee`  — read **only their own** audit rows; no write.
///
/// `Admin` and `Viewer` remain accepted for backwards compatibility with
/// pre-migration-010 rows: `Admin` collapses to Owner-equivalent privilege,
/// `Viewer` collapses to Employee-equivalent (read-only, scoped). The
/// dashboard role-picker only exposes the three primary names; old rows
/// are migrated lazily on next role edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserRole {
    Owner,
    Admin,
    Developer,
    Employee,
    Viewer,
}

impl UserRole {
    #[must_use]
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Developer => "developer",
            Self::Employee => "employee",
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
            "employee" => Ok(Self::Employee),
            // Backward compat: pre-migration-005 'member' rows.
            "member" => Ok(Self::Developer),
            "viewer" => Ok(Self::Viewer),
            other => Err(ApiError::Internal(format!("unknown role: {other}"))),
        }
    }

    /// True when the role is allowed to **write** workspace-shared
    /// resources (rules, providers, secure_mode, budgets, members).
    /// Owner + Admin (legacy) only.
    #[must_use]
    pub const fn can_write(self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }

    /// True when the role can read every audit row in the workspace.
    /// Employee/Viewer must self-filter to their own user_id.
    #[must_use]
    pub const fn can_read_all_audit(self) -> bool {
        matches!(self, Self::Owner | Self::Admin | Self::Developer)
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
///
/// `purpose` (2FA, Task 4): absent/`None` on every normal access token —
/// `#[serde(default, ...)]` means tokens minted before this field existed
/// (and any hand-built `Claims` that omit it) deserialize with
/// `purpose = None` and keep authorizing exactly as before
/// (BACKWARD COMPAT). `Some("2fa_challenge")` / `Some("2fa_enroll")` mark a
/// short-lived single-purpose token minted by `encode_purpose_token`
/// (`routes/dashboard/auth.rs`); `is_access_claims` — and therefore
/// `require` below — rejects those outright so a partial-login token can
/// never reach an authenticated route.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub ws: Uuid,
    pub role: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

/// True when `claims` represents a normal (purposeless) access token — the
/// only kind allowed to authorize protected routes. Challenge/enrollment
/// tokens (`purpose = Some(_)`) return `false` here.
///
/// Pure predicate (no I/O) so it can be unit-tested directly without
/// building a full request/response cycle.
#[must_use]
pub const fn is_access_claims(claims: &Claims) -> bool {
    claims.purpose.is_none()
}

/// WS4-3 — what the two session gates decided about one presented token.
///
/// Expressed as a pure function over plain values, following the shape
/// [`crate::http::middleware::license_gate::license_gate`] established: no
/// `AppState`, no HTTP, no Redis, so every combination is unit-testable
/// directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionGate {
    /// Neither gate objects. Continue to role parsing.
    Proceed,
    /// `POST /v1/auth/logout` blacklisted this specific token id.
    RejectLoggedOut,
    /// An administrator revoked every session for this user at a moment at or
    /// after this token was minted (WS4-3).
    RejectRevoked,
}

/// The whole session decision, as a pure function over plain values.
///
/// * `jti_blacklisted` — `jti_blacklist:{jti}` exists (self-service logout).
/// * `revoked_before_unix` — the value of `session_revoked:{user_id}`, or
///   `None` when no administrator has revoked this user's sessions.
/// * `token_iat` — the `iat` claim of the presented access token.
///
/// The comparison is `<=`, not `<`, and that is load-bearing. `iat` has
/// one-second granularity, so a token minted in the SAME second as the
/// revocation is indistinguishable from one minted just before it. Refusing
/// it is the safe direction: the cost is that a user re-authenticating within
/// the same second as the revocation must retry once, and the alternative
/// cost is a live session surviving the revocation that was meant to end it.
///
/// Logout outranks revocation only in which reason is reported — both refuse.
#[must_use]
pub const fn session_gate(
    jti_blacklisted: bool,
    revoked_before_unix: Option<i64>,
    token_iat: i64,
) -> SessionGate {
    if jti_blacklisted {
        return SessionGate::RejectLoggedOut;
    }
    match revoked_before_unix {
        Some(watermark) if token_iat <= watermark => SessionGate::RejectRevoked,
        _ => SessionGate::Proceed,
    }
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

    // 2FA (Task 4): a challenge/enrollment token (`purpose = Some(_)`) is
    // single-purpose and must never authorize a normal route — reject
    // before touching the jti blacklist / cache / role parsing below.
    if !is_access_claims(&claims) {
        return Err(api_error_response(ApiError::Unauthorized(
            "Invalid credentials".into(),
        )));
    }

    // Session gates, both read in one Redis round trip:
    //   * jti blacklist — `POST /v1/auth/logout` plants these entries.
    //   * revocation watermark (WS4-3) — `DELETE /v1/users/{id}/sessions`
    //     plants `session_revoked:{user_id}`, which refuses every access token
    //     for that user minted at or before the revocation second.
    //
    // On Redis failure, fall back to in-memory cache (D-15, PG-04).
    //
    // KNOWN, BOUNDED PROPAGATION GAP — measured, not assumed. When Redis
    // answers, revocation takes effect on the very next request: this read is
    // synchronous and on every authenticated path. When Redis is UNREACHABLE
    // the branch below serves from `auth_cache` instead, and that cache cannot
    // know about a revocation, so a revoked user's already-minted access token
    // is accepted for up to the remaining 5-minute `CachedAuthEntry` TTL on
    // each pod that has a warm entry for them. The revoking pod evicts its own
    // entry (see `dashboard::users::revoke_sessions`), so the bound applies to
    // OTHER pods only. It is the same gap the jti blacklist has always had
    // under the same condition; WS4-3 states it rather than widening it. The
    // refresh chain is unaffected — it is closed in Postgres, so a user in
    // this window cannot extend the session past that token's own expiry.
    // PITFALL 4: clone out of the DashMap Ref before any await point.
    let gates = crate::redis::session_gates(&state.redis_pool, &claims.jti, &claims.sub).await;
    let (blacklisted, revoked_before) = match gates {
        Ok(pair) => pair,
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

    // One decision, taken by the pure function above so every combination is
    // covered by unit tests rather than by reading this branch. Both refusals
    // return the same generic 401 body as every other failure here — an
    // attacker must not be able to tell "logged out" from "revoked" from
    // "bad signature" (T-05-02, T-05-07).
    match session_gate(blacklisted, revoked_before, claims.iat) {
        SessionGate::Proceed => {}
        SessionGate::RejectLoggedOut | SessionGate::RejectRevoked => {
            return Err(api_error_response(ApiError::Unauthorized(
                "Invalid credentials".into(),
            )));
        }
    }

    // 2FA (Task 4 review fix): self-enforcing ordering invariant. The
    // `is_access_claims` guard above must have already rejected any purpose
    // token before we reach role parsing — `claims.role` is an empty
    // placeholder on purpose tokens (see `encode_purpose_token`) and would
    // fail `from_db_str` anyway, but this makes a future reorder of the two
    // checks trip loudly in test/debug builds instead of silently relying on
    // that coincidence.
    debug_assert!(
        is_access_claims(&claims),
        "purpose tokens must be rejected before role parsing"
    );

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
            purpose: None,
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

    // ---- WS4-3: the session gate ------------------------------------------

    /// The full truth table. Eight rows: two blacklist states × (no
    /// watermark, watermark before / equal to / after the token's `iat`).
    #[test]
    fn session_gate_truth_table() {
        const IAT: i64 = 1_800_000_000;
        let cases = [
            // (blacklisted, watermark, expected)
            (false, None, SessionGate::Proceed),
            // A watermark planted BEFORE this token was minted belongs to an
            // older revocation; a session started afterwards is legitimate.
            (false, Some(IAT - 1), SessionGate::Proceed),
            // Same second: refused. See `session_gate`'s doc comment.
            (false, Some(IAT), SessionGate::RejectRevoked),
            (false, Some(IAT + 1), SessionGate::RejectRevoked),
            (true, None, SessionGate::RejectLoggedOut),
            (true, Some(IAT - 1), SessionGate::RejectLoggedOut),
            (true, Some(IAT), SessionGate::RejectLoggedOut),
            (true, Some(IAT + 1), SessionGate::RejectLoggedOut),
        ];
        for (blacklisted, watermark, expected) in cases {
            let actual = session_gate(blacklisted, watermark, IAT);
            assert_eq!(
                actual, expected,
                "session_gate({blacklisted}, {watermark:?}, {IAT}) = {actual:?}, \
                 expected {expected:?}"
            );
        }
    }

    /// The headline criterion, as a property: an access token that already
    /// existed when the revocation happened is refused, no matter how recently
    /// it was minted.
    #[test]
    fn every_token_minted_at_or_before_the_watermark_is_refused() {
        const WATERMARK: i64 = 1_800_000_000;
        for age in 0..600_i64 {
            assert_eq!(
                session_gate(false, Some(WATERMARK), WATERMARK - age),
                SessionGate::RejectRevoked,
                "a token minted {age}s before the revocation must be refused"
            );
        }
        // CONTROL THAT MUST DIFFER: after the watermark second, accepted.
        for age in 1..600_i64 {
            assert_eq!(
                session_gate(false, Some(WATERMARK), WATERMARK + age),
                SessionGate::Proceed,
                "a token minted {age}s AFTER the revocation must be accepted — \
                 revocation is a point in time, not a ban"
            );
        }
    }

    /// Absence of a watermark must never be read as a revocation. This is the
    /// direction that would take every session in the deployment down.
    #[test]
    fn no_watermark_means_no_revocation() {
        for iat in [0_i64, 1, 1_800_000_000, i64::MAX] {
            assert_eq!(session_gate(false, None, iat), SessionGate::Proceed);
        }
    }

    // ---- 2FA (Task 4): purpose-claim guard -------------------------------

    #[test]
    fn purposeless_claims_are_a_valid_access_token() {
        let (claims, _decoding, _encoding) = sample_claims(Duration::minutes(15));
        assert_eq!(claims.purpose, None);
        assert!(
            is_access_claims(&claims),
            "a normal access token (purpose = None) must authorize"
        );
    }

    #[test]
    fn purpose_claims_are_rejected_as_an_access_token() {
        let (mut claims, _decoding, _encoding) = sample_claims(Duration::minutes(5));
        for purpose in ["2fa_challenge", "2fa_enroll"] {
            claims.purpose = Some(purpose.to_string());
            assert!(
                !is_access_claims(&claims),
                "a {purpose} token must NOT be treated as an access token"
            );
        }
    }

    #[test]
    fn purpose_token_round_trips_and_is_rejected_by_the_guard() {
        // Full encode → decode round trip (same path `require` runs) proves
        // the rejection isn't an artifact of hand-building `Claims` — a
        // genuinely signed+decoded challenge token still fails the guard.
        let secret = b"test-secret-value";
        let now = Utc::now();
        let claims = Claims {
            sub: Uuid::new_v4(),
            ws: Uuid::new_v4(),
            role: String::new(),
            iat: now.timestamp(),
            exp: (now + Duration::minutes(5)).timestamp(),
            jti: Uuid::new_v4().to_string(),
            purpose: Some("2fa_challenge".to_string()),
        };
        let encoding = EncodingKey::from_secret(secret);
        let decoding = DecodingKey::from_secret(secret);
        let token = encode(&Header::new(Algorithm::HS256), &claims, &encoding)
            .expect("encode purpose token");
        let mut validation = Validation::new(Algorithm::HS256);
        validation.leeway = 60;
        let decoded = decode::<Claims>(&token, &decoding, &validation).expect("decode");
        assert_eq!(decoded.claims.purpose.as_deref(), Some("2fa_challenge"));
        assert!(!is_access_claims(&decoded.claims));
    }

    /// BACKWARD-COMPAT REGRESSION GUARD: a token minted before the `purpose`
    /// claim existed has no `purpose` key in its JSON payload at all. If
    /// `#[serde(default)]` were ever dropped from the field, this old-shape
    /// JSON would fail to deserialize and every already-issued access token
    /// would suddenly log its holder out. It must deserialize cleanly with
    /// `purpose = None`, i.e. still treated as a valid access token.
    #[test]
    fn old_access_token_json_without_purpose_key_deserializes_to_none() {
        let json = r#"{
            "sub": "11111111-1111-1111-1111-111111111111",
            "ws": "22222222-2222-2222-2222-222222222222",
            "role": "owner",
            "iat": 1700000000,
            "exp": 1700003600,
            "jti": "33333333-3333-3333-3333-333333333333"
        }"#;
        let claims: Claims =
            serde_json::from_str(json).expect("old-format claims (no purpose key) must deserialize");
        assert_eq!(claims.purpose, None);
        assert!(is_access_claims(&claims), "old token must still authorize");
    }

    /// Serializing a normal access token must NOT emit a `purpose` key at
    /// all (wire-format regression guard for `skip_serializing_if`) — keeps
    /// tokens minted post-2FA byte-shape-compatible with pre-2FA consumers.
    #[test]
    fn access_token_serialization_omits_purpose_key_when_none() {
        let (claims, _decoding, _encoding) = sample_claims(Duration::minutes(15));
        let value = serde_json::to_value(&claims).expect("serialize claims");
        assert!(
            value.get("purpose").is_none(),
            "purpose key must be omitted when None, got: {value}"
        );
    }
}
