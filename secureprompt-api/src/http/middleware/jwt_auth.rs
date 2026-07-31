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
//!      access tokens are rejected until natural expiry — and for the WS4-3
//!      revocation watermark `session_revoked:{user_id}`.
//!      On Redis failure the FU3 policy below applies.
//!   4. Inserts `JwtAuthContext` into the request extensions so handlers can
//!      extract it via `axum::Extension<JwtAuthContext>`.
//!
//! All failure paths return `ApiError::Unauthorized(_)` with a generic copy
//! so an attacker cannot distinguish signature-fail from expiry-fail
//! (threat T-05-07 on the auth surface, T-05-02 on the JWT surface).
//!
//! Phase 6 / Plan 06-01 additions:
//!   * `UserRole` extended from 3 → 4 variants (Owner/Admin/Developer/Viewer)
//!   * `CachedAuthEntry` struct + in-memory auth cache (D-14, PG-04)
//!   * Write-through cache population on every successful auth (D-15)
//!
//! # FU3 — what happens when the session store is unreachable
//!
//! Two facts, both established by reading this file and both previously
//! mis-stated in this header, set up the problem:
//!
//!   1. `require` makes exactly ONE I/O call before authorizing: the Redis
//!      session-gate read. It never queried Postgres, so the "Postgres/Redis
//!      failure fallback" this header used to claim was Redis-only.
//!   2. `auth_cache` is WRITE-ONLY on the healthy path. Nothing reads it while
//!      Redis answers, so its TTL was never a cache-freshness parameter — it
//!      was, and is, purely the width of the fail-open window.
//!
//! Both mechanisms that end a session live in Redis (`jti_blacklist:{jti}` from
//! `POST /v1/auth/logout`, `session_revoked:{user_id}` from WS4-3). So an
//! unreachable Redis used to mean: serve the request, from an entry that
//! predates any revocation, for up to five minutes, with nothing on the answer
//! or in any metric saying so. That is the fail-open FU3 replaces with a
//! decision.
//!
//! The decision uses the WS2-3 vocabulary — `block` / `degrade_with_alert` —
//! bound to [`SidecarUnavailablePolicy::as_str`] at compile time, exactly as
//! [`crate::http::middleware::license_gate`] does, so the three gates cannot
//! drift into three vocabularies. [`degraded_auth_gate`] is the whole policy as
//! a pure function:
//!
//!   * **Admin revocation now fails CLOSED.** The watermark WS4-3 publishes to
//!     Redis is also written, in the same transaction, to
//!     `session_revocation_audit`. That table has no TTL and does not depend on
//!     Redis, so [`SessionRevocationRepository::latest_watermark`] can answer
//!     the revocation question during a Redis outage — on EVERY pod, not just
//!     the one that served the revocation. The comparison is delegated back to
//!     WS4-3's [`session_gate`], not restated.
//!   * **Both stores unreachable fails CLOSED.** If Postgres cannot answer
//!     either, nothing in the deployment can say whether this session was
//!     ended, and it is refused (503). This costs almost no availability:
//!     every route behind this middleware queries Postgres in its handler, so a
//!     request refused here would have failed there.
//!   * **Self-service logout still cannot be checked, so it DEGRADES.** There
//!     is no Redis-independent record of a blacklisted `jti`. A warm session
//!     is served, and the answer says so: `tracing::error!` with a stable
//!     `alert=` key, the `secureprompt_auth_gate_engaged_total` counter, the
//!     [`AUTH_DEGRADED_HEADER`] response header, and a [`DegradedAuth`] marker
//!     in the request extensions so a handler can tell.
//!   * **The fail-open window is now 60 s, not 300** — see
//!     [`DEGRADED_AUTH_CACHE_TTL_SECS`].
//!   * **The context is built from the token's own signed claims**, never from
//!     the cached copy. The cache is populated FROM claims and carries no
//!     independent authority, but it is keyed by `user_id`, so a stale entry
//!     could hand a demoted user the role an earlier token had. It now serves
//!     only as the liveness fact it actually is.
//!
//! ## The availability trade, stated
//!
//! Failing closed here takes the DASHBOARD down when both stores are gone, not
//! the customer's LLM traffic: `/v1/chat/completions` and the rest of the data
//! plane are gated by `api_key_auth` (whose `redis_config_cache` is in-memory
//! despite the name), and `rate_limit::budget_check` already answers `Allow` on
//! a Redis failure. The blast radius of every refusal added here is the control
//! plane. Trading a security control for that is the right direction; trading
//! it for the data plane would not have been.

use axum::{
    body::Body,
    extract::{Request, State},
    http::{header::AUTHORIZATION, HeaderMap, HeaderValue},
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{decode, Algorithm, DecodingKey, EncodingKey, Validation};
use secureprompt_common::{config::JwtConfig, errors::ApiError, types::WorkspaceId};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    app_state::AppState,
    db::{
        session_revocation_repo::SessionRevocationRepository,
        sidecar_policy_repo::SidecarUnavailablePolicy,
    },
    http::api_error_response,
};

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
/// Written on every successful auth; read ONLY on the FU3 degraded path.
/// Key: `user_id` (Uuid). No background eviction — age is checked on read.
#[derive(Debug, Clone)]
pub struct CachedAuthEntry {
    pub user_id: uuid::Uuid,
    pub workspace_id: secureprompt_common::types::WorkspaceId,
    pub role: UserRole,
    pub cached_at: std::time::Instant,
}

impl CachedAuthEntry {
    /// Seconds since this entry was written by a fully-verified request.
    #[must_use]
    pub fn age_secs(&self) -> u64 {
        self.cached_at.elapsed().as_secs()
    }
}

/// FU3 — how long a cached session may be served after the session store
/// became unreachable.
///
/// This replaces the 5 minutes `CachedAuthEntry::is_valid` used to allow. That
/// number was never a cache-freshness parameter: the healthy path never reads
/// this cache, so the TTL only ever measured how long a pod would keep serving
/// sessions it could no longer check. 60 s is chosen against what the window
/// still exposes after the durable revocation read closes admin revocation —
/// a `jti` blacklisted BEFORE Redis went away, on a pod other than the one that
/// served the logout. A logout attempted DURING the outage is not exposed at
/// all: `dashboard::auth::logout` returns the Redis error to the caller rather
/// than reporting a logout that did not happen.
///
/// The cost of the shorter window is that a Redis outage lasting longer than a
/// minute starts refusing dashboard requests instead of serving them
/// unverifiably. That is the intended direction: a blip is seconds, and an
/// outage an operator has not noticed is exactly the state in which serving
/// unverifiable sessions is worst.
pub const DEGRADED_AUTH_CACHE_TTL_SECS: u64 = 60;

/// True when an entry of this age may still be served on the degraded path.
///
/// A pure function over the age rather than a method on `Instant`, so the
/// boundary is testable without a clock — the same seam
/// [`session_gate`] and `license_gate` use.
#[must_use]
pub const fn cached_session_usable(age_secs: u64) -> bool {
    age_secs < DEGRADED_AUTH_CACHE_TTL_SECS
}

/// Response header naming the auth condition an answer was served under.
///
/// Bounded values only — [`AuthOutage::as_str`]. Distinct from
/// `LICENSE_DEGRADED_HEADER` and `SIDECAR_DEGRADED_HEADER`: three
/// degradations, three causes, three remedies.
pub const AUTH_DEGRADED_HEADER: &str = "x-secureprompt-auth-degraded";

/// Metric/log `action` label for a condition the auth gate failed closed on.
/// Bound to the WS2-3 constant at compile time so a rename there is a compile
/// error here rather than a silent second metric series.
const ACTION_BLOCK: &str = SidecarUnavailablePolicy::Block.as_str();
/// Same, for a request served through the degraded path and marked.
const ACTION_DEGRADE: &str = SidecarUnavailablePolicy::DegradeWithAlert.as_str();

/// Why the auth gate acted while the session store was unreachable. These
/// strings reach Prometheus and the response header, so they are never free
/// text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthOutage {
    /// Redis is unreachable AND the durable revocation trail says an
    /// administrator revoked this user's sessions. Fail closed.
    RevokedDurably,
    /// Neither Redis nor Postgres could answer. Nothing in the deployment
    /// knows whether this session was ended. Fail closed.
    SessionStoreLost,
    /// Redis is unreachable and this pod has no cached session for the user
    /// within [`DEGRADED_AUTH_CACHE_TTL_SECS`]. Fail closed.
    NoWarmSession,
    /// Redis is unreachable, the durable trail says this session was NOT
    /// revoked, and a warm entry exists — but `jti_blacklist:{jti}` has no
    /// Redis-independent record, so a self-service logout cannot be checked.
    /// Serve, and say so.
    LogoutUnverifiable,
}

impl AuthOutage {
    /// Canonical metric-label / response-header form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RevokedDurably => "revoked_durably",
            Self::SessionStoreLost => "session_store_lost",
            Self::NoWarmSession => "no_warm_session",
            Self::LogoutUnverifiable => "logout_unverifiable",
        }
    }

    /// The refusal for a fail-closed outcome.
    ///
    /// `RevokedDurably` returns the SAME generic 401 body as every other
    /// refusal in this module, so an attacker cannot tell "revoked" from "bad
    /// signature" (T-05-02, T-05-07). The two infrastructure outages return
    /// 503, which is what this path returned before FU3 and is the honest
    /// status: the credential was not rejected, the gateway could not judge it.
    fn refusal(self) -> ApiError {
        match self {
            Self::RevokedDurably => ApiError::Unauthorized("Invalid credentials".into()),
            Self::SessionStoreLost | Self::NoWarmSession => {
                ApiError::ServiceUnavailable("auth service temporarily unavailable".into())
            }
            // Not a refusal — kept total so adding a variant is a compile
            // error rather than a silently-served request.
            Self::LogoutUnverifiable => {
                ApiError::ServiceUnavailable("auth service temporarily unavailable".into())
            }
        }
    }
}

/// What the auth gate decided about one request whose session-gate read failed.
///
/// Deliberately has no `Proceed`: this gate is consulted only AFTER the session
/// store has already failed, so "nothing is wrong" is not one of its answers.
/// The two it does have are the WS2-3 vocabulary, same meanings as
/// [`crate::http::middleware::license_gate::LicenseGate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthGate {
    /// Fail closed. `AuthOutage::refusal` gives the status.
    Block(AuthOutage),
    /// Serve, and say so: alert + counter + [`AUTH_DEGRADED_HEADER`] +
    /// [`DegradedAuth`].
    Degrade(AuthOutage),
}

/// What the Redis-independent revocation trail was able to say.
///
/// `Unavailable` is NOT `Known(None)`, and conflating them is the whole bug
/// class this type exists to prevent: "no revocation on record" and "could not
/// look" must not take the same branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableRevocation {
    /// Postgres answered. `None` means no revocation has ever been recorded
    /// for this user — the ordinary case.
    Known(Option<i64>),
    /// Postgres could not answer either.
    Unavailable,
}

/// Marker inserted into the request extensions when, and only when, the answer
/// is being produced without the session gates having been read.
///
/// Before FU3 a handler had no way to tell a cache-served request from a
/// fully-verified one — `JwtAuthContext` is byte-identical either way. A
/// handler that wants to refuse a privileged mutation on an unverifiable
/// session can now extract `Option<Extension<DegradedAuth>>` and see it.
#[derive(Debug, Clone, Copy)]
pub struct DegradedAuth(pub AuthOutage);

/// The whole Redis-unavailable policy, as a pure function over plain values —
/// no `AppState`, no HTTP, no Redis — so every combination is unit-testable.
///
/// * `durable` — what `session_revocation_audit` was able to say.
/// * `token_iat` — the `iat` claim of the presented access token.
/// * `cached_session_age_secs` — age of this pod's cache entry for the user,
///   `None` when there is no entry.
#[must_use]
pub fn degraded_auth_gate(
    durable: DurableRevocation,
    token_iat: i64,
    cached_session_age_secs: Option<u64>,
) -> AuthGate {
    let DurableRevocation::Known(watermark) = durable else {
        return AuthGate::Block(AuthOutage::SessionStoreLost);
    };
    // Compose with WS4-3 rather than restate its comparison — `<=`, the
    // same-second rule and the "absence is not revocation" rule all have to
    // mean the same thing on both paths, and the only way to guarantee that is
    // to run the same function.
    //
    // `false` for the blacklist is not an assumption that the jti is clean. It
    // is the fact that the blacklist CANNOT BE READ, which is precisely what
    // makes a surviving request `Degrade` rather than proceed.
    match session_gate(false, watermark, token_iat) {
        SessionGate::RejectRevoked | SessionGate::RejectLoggedOut => {
            AuthGate::Block(AuthOutage::RevokedDurably)
        }
        SessionGate::Proceed => match cached_session_age_secs {
            Some(age) if cached_session_usable(age) => {
                AuthGate::Degrade(AuthOutage::LogoutUnverifiable)
            }
            _ => AuthGate::Block(AuthOutage::NoWarmSession),
        },
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
    // When Redis answers, revocation takes effect on the very next request:
    // this read is synchronous and on every authenticated path. When Redis is
    // UNREACHABLE, `serve_degraded` applies the FU3 policy documented in the
    // module header — it does NOT fall through to a cached answer.
    let gates = crate::redis::session_gates(&state.redis_pool, &claims.jti, &claims.sub).await;
    let (blacklisted, revoked_before) = match gates {
        Ok(pair) => pair,
        Err(_redis_err) => return serve_degraded(&state, req, next, &claims).await,
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

/// Emit the operator-facing alert for one auth-gate action: a `tracing::error!`
/// carrying a stable `alert=` key for log-based alerting, and the Prometheus
/// counter `secureprompt_auth_gate_engaged_total`. Both metric labels are
/// bounded — an [`AuthOutage`] reason and one of the two `ACTION_*` constants.
/// `user_id` is logged for triage but never becomes a metric label.
fn alert(state: &AppState, user_id: Uuid, reason: AuthOutage, action: &'static str) {
    tracing::error!(
        alert = "auth_session_store_unreachable",
        user_id = %user_id,
        reason = reason.as_str(),
        action,
        "the session gates could not be read from Redis; JWT auth is running \
         on the degraded policy"
    );
    state.metrics.record_auth_gate_engaged(reason.as_str(), action);
}

/// FU3 — the Redis-unavailable path, reached only when
/// `crate::redis::session_gates` failed.
///
/// Consults the Redis-independent revocation trail, applies
/// [`degraded_auth_gate`], and either refuses or serves a marked answer. See
/// the module header for why each outcome is what it is.
async fn serve_degraded(
    state: &AppState,
    mut req: Request,
    next: Next,
    claims: &Claims,
) -> Result<Response, Response> {
    // The durable half of the WS4-3 watermark. An ERROR here is never read as
    // "not revoked" — it becomes `Unavailable`, which fails closed.
    let durable = match SessionRevocationRepository::new(state.db.clone())
        .latest_watermark(claims.ws, claims.sub)
        .await
    {
        Ok(watermark) => DurableRevocation::Known(watermark),
        Err(_db_err) => DurableRevocation::Unavailable,
    };

    // PITFALL 4: take a plain `u64` out of the DashMap and drop the `Ref`
    // before the `next.run(req).await` below; a shard lock held across an
    // await deadlocks every other request for that shard.
    let cached_age = state
        .auth_cache
        .get(&claims.sub)
        .map(|entry| entry.age_secs());

    match degraded_auth_gate(durable, claims.iat, cached_age) {
        AuthGate::Block(reason) => {
            alert(state, claims.sub, reason, ACTION_BLOCK);
            Err(api_error_response(reason.refusal()))
        }
        AuthGate::Degrade(reason) => {
            alert(state, claims.sub, reason, ACTION_DEGRADE);
            // From the token's own signed claims, NOT from the cache entry.
            // The cache is keyed by user_id and is only ever populated from
            // claims, so a stale entry carries no authority of its own — but it
            // CAN carry a higher role than the token being presented, which is
            // a privilege escalation dressed as a cache hit.
            let role = UserRole::from_db_str(&claims.role).map_err(|_| {
                api_error_response(ApiError::Unauthorized("Invalid credentials".into()))
            })?;
            // Deliberately NOT re-inserting into `auth_cache`. Refreshing
            // `cached_at` here would make the fail-open window unbounded for
            // any user who keeps sending requests through the outage.
            req.extensions_mut().insert(DegradedAuth(reason));
            req.extensions_mut().insert(JwtAuthContext {
                user_id: claims.sub,
                workspace_id: WorkspaceId(claims.ws),
                role,
                jti: claims.jti.clone(),
                exp: claims.exp,
            });
            let mut response = next.run(req).await;
            response.headers_mut().insert(
                AUTH_DEGRADED_HEADER,
                HeaderValue::from_static(reason.as_str()),
            );
            Ok(response)
        }
    }
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

    // ---- FU3: the Redis-unavailable policy -------------------------------

    /// The whole matrix. Every row is a state the gateway can actually be in
    /// when `session_gates` has just failed.
    #[test]
    fn degraded_auth_gate_truth_table() {
        const IAT: i64 = 1_800_000_000;
        const FRESH: Option<u64> = Some(0);
        const STALE: Option<u64> = Some(DEGRADED_AUTH_CACHE_TTL_SECS);
        let cases = [
            // (durable, cached age, expected)
            //
            // Postgres cannot answer either: nothing knows. Fail closed even
            // with a brand-new cache entry — that is the point.
            (
                DurableRevocation::Unavailable,
                FRESH,
                AuthGate::Block(AuthOutage::SessionStoreLost),
            ),
            (
                DurableRevocation::Unavailable,
                None,
                AuthGate::Block(AuthOutage::SessionStoreLost),
            ),
            // The durable trail says revoked: fail closed regardless of cache.
            (
                DurableRevocation::Known(Some(IAT)),
                FRESH,
                AuthGate::Block(AuthOutage::RevokedDurably),
            ),
            (
                DurableRevocation::Known(Some(IAT + 1)),
                FRESH,
                AuthGate::Block(AuthOutage::RevokedDurably),
            ),
            // Not revoked, warm entry: serve and say so.
            (
                DurableRevocation::Known(None),
                FRESH,
                AuthGate::Degrade(AuthOutage::LogoutUnverifiable),
            ),
            // A watermark older than the token is somebody else's older
            // revocation; this session started afterwards and is legitimate.
            (
                DurableRevocation::Known(Some(IAT - 1)),
                FRESH,
                AuthGate::Degrade(AuthOutage::LogoutUnverifiable),
            ),
            // Not revoked, but nothing warm to serve.
            (
                DurableRevocation::Known(None),
                None,
                AuthGate::Block(AuthOutage::NoWarmSession),
            ),
            (
                DurableRevocation::Known(None),
                STALE,
                AuthGate::Block(AuthOutage::NoWarmSession),
            ),
        ];
        for (durable, age, expected) in cases {
            let actual = degraded_auth_gate(durable, IAT, age);
            assert_eq!(
                actual, expected,
                "degraded_auth_gate({durable:?}, {IAT}, {age:?}) = {actual:?}, \
                 expected {expected:?}"
            );
        }
    }

    /// "No revocation on record" and "could not look" must never take the same
    /// branch. Collapsing them is how a security control becomes a no-op the
    /// day its store goes down.
    #[test]
    fn an_unreadable_trail_is_not_the_same_as_an_empty_one() {
        let looked = degraded_auth_gate(DurableRevocation::Known(None), 1_000, Some(0));
        let could_not_look = degraded_auth_gate(DurableRevocation::Unavailable, 1_000, Some(0));
        assert_eq!(looked, AuthGate::Degrade(AuthOutage::LogoutUnverifiable));
        assert_eq!(
            could_not_look,
            AuthGate::Block(AuthOutage::SessionStoreLost)
        );
        assert_ne!(
            looked, could_not_look,
            "an unreadable revocation trail must not be served like an empty one"
        );
    }

    /// The degraded path does not get its own revocation semantics: for every
    /// watermark/`iat` pair it refuses exactly when WS4-3's `session_gate`
    /// refuses. If someone changes the `<=` in one place, this fails.
    #[test]
    fn the_degraded_gate_agrees_with_ws4_3_on_every_watermark() {
        const IAT: i64 = 1_800_000_000;
        let mut blocked = 0;
        let mut served = 0;
        for offset in -600_i64..=600 {
            let watermark = IAT + offset;
            let ws4_3 = session_gate(false, Some(watermark), IAT);
            let fu3 = degraded_auth_gate(DurableRevocation::Known(Some(watermark)), IAT, Some(0));
            match ws4_3 {
                SessionGate::RejectRevoked => {
                    blocked += 1;
                    assert_eq!(
                        fu3,
                        AuthGate::Block(AuthOutage::RevokedDurably),
                        "watermark {watermark} is a WS4-3 refusal but FU3 gave {fu3:?}"
                    );
                }
                SessionGate::Proceed => {
                    served += 1;
                    assert_eq!(
                        fu3,
                        AuthGate::Degrade(AuthOutage::LogoutUnverifiable),
                        "watermark {watermark} is a WS4-3 pass but FU3 gave {fu3:?}"
                    );
                }
                SessionGate::RejectLoggedOut => {
                    unreachable!("session_gate(false, ..) cannot report a logout")
                }
            }
        }
        // PREMISE: the loop really did exercise both directions. Without this
        // a `session_gate` that returned one answer for everything would leave
        // the assertions above trivially satisfied.
        assert!(
            blocked > 0 && served > 0,
            "premise: the sweep must cover both outcomes (blocked={blocked}, served={served})"
        );
    }

    /// `degraded_auth_gate` passes `false` for the blacklist because it cannot
    /// read it, so the `RejectLoggedOut` arm is unreachable there. Asserted
    /// rather than asserted-in-a-comment.
    #[test]
    fn the_logout_arm_is_unreachable_when_the_blacklist_cannot_be_read() {
        for watermark in [None, Some(0_i64), Some(i64::MAX)] {
            for iat in [0_i64, 1_800_000_000, i64::MAX] {
                assert_ne!(
                    session_gate(false, watermark, iat),
                    SessionGate::RejectLoggedOut,
                    "session_gate(false, ..) must never report a logout"
                );
            }
        }
    }

    /// The window is 60 s and strictly shorter than the 300 s it replaces. The
    /// boundary is exclusive: an entry exactly at the TTL is already too old.
    #[test]
    fn the_degraded_window_is_sixty_seconds_and_shorter_than_it_was() {
        assert_eq!(DEGRADED_AUTH_CACHE_TTL_SECS, 60);
        assert!(
            DEGRADED_AUTH_CACHE_TTL_SECS < 300,
            "FU3 must not widen the pre-existing 5-minute fail-open window"
        );
        assert!(cached_session_usable(0));
        assert!(cached_session_usable(DEGRADED_AUTH_CACHE_TTL_SECS - 1));
        assert!(!cached_session_usable(DEGRADED_AUTH_CACHE_TTL_SECS));
        assert!(!cached_session_usable(u64::MAX));
    }

    /// The metric/log `action` labels are the WS2-3 vocabulary, not a third
    /// one. Bound at compile time; asserted here so the intent is executable.
    #[test]
    fn auth_action_labels_are_the_ws2_3_vocabulary() {
        assert_eq!(ACTION_BLOCK, "block");
        assert_eq!(ACTION_DEGRADE, "degrade_with_alert");
        assert_eq!(ACTION_BLOCK, SidecarUnavailablePolicy::Block.as_str());
        assert_eq!(
            ACTION_DEGRADE,
            SidecarUnavailablePolicy::DegradeWithAlert.as_str()
        );
    }

    /// Reason strings are bounded, distinct, and legal as a header value —
    /// `serve_degraded` uses `HeaderValue::from_static`, which panics on an
    /// invalid one, and that panic would be inside the auth path.
    #[test]
    fn auth_outage_reasons_are_bounded_and_header_safe() {
        let all = [
            AuthOutage::RevokedDurably,
            AuthOutage::SessionStoreLost,
            AuthOutage::NoWarmSession,
            AuthOutage::LogoutUnverifiable,
        ];
        let mut seen = std::collections::HashSet::new();
        for reason in all {
            let _ = HeaderValue::from_static(reason.as_str());
            assert!(
                seen.insert(reason.as_str()),
                "duplicate label {}: two conditions would share one metric series",
                reason.as_str()
            );
        }
        // The degrade reason is the one that reaches a client, so it is pinned
        // by name: `tests/auth_redis_outage.rs` asserts this exact string on
        // the response header.
        assert_eq!(AuthOutage::LogoutUnverifiable.as_str(), "logout_unverifiable");
    }

    /// Only the durable-revocation refusal may look like an authentication
    /// failure; the two infrastructure outages must stay 503, because the
    /// credential was not rejected — the gateway could not judge it.
    #[test]
    fn only_a_real_revocation_refuses_as_unauthorized() {
        assert!(matches!(
            AuthOutage::RevokedDurably.refusal(),
            ApiError::Unauthorized(_)
        ));
        assert!(matches!(
            AuthOutage::SessionStoreLost.refusal(),
            ApiError::ServiceUnavailable(_)
        ));
        assert!(matches!(
            AuthOutage::NoWarmSession.refusal(),
            ApiError::ServiceUnavailable(_)
        ));
        // And the revocation refusal is byte-identical to every other refusal
        // in this module, so it cannot be used as a revocation oracle.
        let ApiError::Unauthorized(revoked) = AuthOutage::RevokedDurably.refusal() else {
            panic!("checked above");
        };
        assert_eq!(revoked, "Invalid credentials");
    }

    /// A fresh entry reports an age inside the window. Guards against the
    /// `age_secs`/`cached_session_usable` pair being wired up inverted, which
    /// would serve only STALE entries.
    #[test]
    fn a_just_written_cache_entry_is_usable() {
        let entry = CachedAuthEntry {
            user_id: Uuid::new_v4(),
            workspace_id: WorkspaceId(Uuid::new_v4()),
            role: UserRole::Viewer,
            cached_at: std::time::Instant::now(),
        };
        assert_eq!(entry.age_secs(), 0);
        assert!(cached_session_usable(entry.age_secs()));
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
