//! User management — GET /v1/users, POST /v1/users, and the session surface.
//!
//! GET    — any authenticated role; lists users in the caller's workspace.
//! POST   — admin only; invites (creates) a new user in the same workspace.
//! GET    /{user_id}/sessions — FU4; the live sessions that user holds.
//! DELETE /{user_id}/sessions — WS4-3; admin/owner only; terminates every
//!          session that user currently holds.
//! DELETE /{user_id}/sessions/{session_id} — FU4; ends ONE of them.

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    routing::{delete, get},
    Json, Router,
};
use chrono::{DateTime, Duration, Utc};
use secureprompt_common::errors::ApiError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    app_state::AppState,
    db::admin_audit_repo::AdminActor,
    db::{
        session_repo::SessionRepository,
        session_revocation_repo::{
            RevocationRecord, RevocationTarget, SessionRevocationRepository,
        },
        user_repo::UserRepository,
    },
    http::{
        api_error_response,
        middleware::jwt_auth::{JwtAuthContext, UserRole},
        routes::dashboard::role::require_role,
    },
    redis as sp_redis,
};

// ── DTOs ──────────────────────────────────────────────────────────────────────

const VALID_ROLES: &[&str] = &["owner", "admin", "developer", "viewer"];

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub email: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
    pub role: String,
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_users).post(create_user))
        // WS4-3. Deliberately NOT added to the license gate's
        // `RECOVERY_ALLOWLIST`: terminating a session is ordinary governance
        // functionality, not the infrastructure needed to re-license a
        // bricked gateway, and allowlisting above a security gate is the
        // shape of change that opens a hole.
        // FU4 adds GET on the SAME path. The two verbs are the pair the WS4-3
        // report said was missing: an administrator could terminate everything
        // for a user and could not see what they were terminating.
        .route(
            "/{user_id}/sessions",
            delete(revoke_sessions).get(list_sessions),
        )
        // FU4 — the narrow lever. Also deliberately outside the license gate's
        // `RECOVERY_ALLOWLIST`, for the reason above.
        .route(
            "/{user_id}/sessions/{session_id}",
            delete(revoke_one_session),
        )
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `GET /v1/users` — list workspace members (any role).
async fn list_users(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
) -> Result<Json<Vec<UserResponse>>, axum::response::Response> {
    use sqlx::Row as _;

    let rows = sqlx::query(
        "SELECT id, workspace_id, email, role, created_at, updated_at
         FROM users
         WHERE workspace_id = $1
         ORDER BY created_at DESC",
    )
    .bind(ctx.workspace_id.0)
    .fetch_all(&state.db)
    .await
    .map_err(|e| api_error_response(ApiError::Database(e.to_string())))?;

    let result = rows
        .into_iter()
        .map(|r| UserResponse {
            id: r.get("id"),
            workspace_id: r.get("workspace_id"),
            email: r.get("email"),
            role: r.get("role"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        })
        .collect();

    Ok(Json(result))
}

/// `POST /v1/users` — create a user in the caller's workspace (admin only).
async fn create_user(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Json(body): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<UserResponse>), axum::response::Response> {
    require_role(&ctx, UserRole::Admin).map_err(api_error_response)?;

    if !VALID_ROLES.contains(&body.role.as_str()) {
        return Err(api_error_response(ApiError::BadRequest(format!(
            "role must be one of: {}",
            VALID_ROLES.join(", ")
        ))));
    }

    let repo = UserRepository::new(state.db.clone());

    // Enforce license seat limit (fail-open: only a Valid license enforces).
    if let Some(max) = state.license.max_seats() {
        let count = repo.count_total_users().await.map_err(api_error_response)?;
        if count >= i64::from(max) {
            return Err(api_error_response(ApiError::Forbidden(format!(
                "license seat limit ({max}) reached"
            ))));
        }
    }

    let actor = AdminActor::resolve(
        &state.db,
        ctx.workspace_id.0,
        ctx.user_id,
        ctx.role.as_db_str(),
    )
    .await;
    let row = repo
        .create_user(
            ctx.workspace_id,
            &body.email,
            &body.password,
            &body.role,
            &actor,
        )
        .await
        .map_err(api_error_response)?;

    // Fetch the role column (UserRow doesn't include it).
    let role: String = sqlx::query_scalar("SELECT role FROM users WHERE id = $1")
        .bind(row.id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| api_error_response(ApiError::Database(e.to_string())))?;

    Ok((
        StatusCode::CREATED,
        Json(UserResponse {
            id: row.id,
            workspace_id: row.workspace_id,
            email: row.email,
            role,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }),
    ))
}

// ── WS4-3: DELETE /v1/users/{user_id}/sessions ────────────────────────────

/// What the authorization table says about one revocation attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeDecision {
    Allowed,
    /// The actor is below Admin. Nobody at Developer/Viewer/Employee level may
    /// terminate anyone's session, including their own — `POST /v1/auth/logout`
    /// is the route for that, and it needs no privilege at all.
    ActorRoleTooLow,
    /// The actor outranks nobody here: the target sits ABOVE them on the
    /// privilege ladder.
    TargetOutranksActor,
}

/// The whole authorization decision, as a pure function over plain values —
/// no `AppState`, no HTTP, no database — so every (actor, target) pair is
/// unit-testable directly. Same shape as
/// [`crate::http::middleware::license_gate::license_gate`].
///
/// Two rules, and both are deliberate choices the WS4-3 report records:
///
/// * **Admin/Owner only.** Session termination is an administrative power over
///   another person's access; the read-only roles do not get it.
/// * **An actor may not revoke a target who outranks them.** Concretely: an
///   Admin may not revoke an Owner. The role hierarchy already places Admin
///   below Owner, so letting an Admin end the Owner's session is a privilege
///   inversion — in a workspace with several admins it is a lockout vector
///   against the account owner, and it would let an attacker who has taken one
///   admin account defend it by ejecting the person able to remove them.
///
/// **Self-revocation is ALLOWED**, and needs no special case: an actor never
/// outranks themselves. It is not extra privilege — `POST /v1/auth/logout`
/// already lets any authenticated user end their own session — and it is the
/// one-call answer to "I think my own laptop is compromised", which logout
/// (which only revokes the token it is presented with, plus that user's
/// refresh rows) does not fully give. It kills the calling token too: the
/// admin's very next request 401s and they sign in again.
#[must_use]
pub const fn may_revoke(actor: UserRole, target: UserRole) -> RevokeDecision {
    use crate::http::routes::dashboard::role::privilege_level;
    if privilege_level(actor) < privilege_level(UserRole::Admin) {
        return RevokeDecision::ActorRoleTooLow;
    }
    if privilege_level(target) > privilege_level(actor) {
        return RevokeDecision::TargetOutranksActor;
    }
    RevokeDecision::Allowed
}

/// What the caller gets back. Deliberately small: it reports the EFFECT
/// (which watermark was published, how many refresh rows closed) so the
/// dashboard can say something true, and echoes no personal data the caller
/// did not already supply.
#[derive(Debug, Serialize)]
pub struct RevokeSessionsResponse {
    pub user_id: Uuid,
    /// Unix seconds. Every access token for `user_id` minted at or before this
    /// second is refused from the caller's next request onward.
    pub revoked_before: i64,
    pub refresh_tokens_revoked: i64,
    pub audit_id: Uuid,
    pub revoked_at: DateTime<Utc>,
}

/// `DELETE /v1/users/{user_id}/sessions` — terminate every session the named
/// user currently holds.
///
/// # Why this is not the jti blacklist
///
/// `jti_blacklist:{jti}` can only revoke a token somebody is holding: the key
/// is the token's own random id, which is stored nowhere and listed by no
/// endpoint. `POST /v1/auth/logout` can use it because the caller presents the
/// token. An administrator terminating a lost laptop's session has never seen
/// that jti and never will. The watermark is keyed by USER for exactly that
/// reason.
///
/// # Ordering, which is load-bearing
///
/// Postgres first (close the refresh chain AND write the audit row, in one
/// transaction), Redis second (publish the watermark). If the Redis write
/// fails the caller gets a 500 and retries — the whole operation is
/// idempotent — and what has already happened is the durable, provable half.
/// The other order would allow a Postgres failure to leave a security action
/// performed and unrecorded, which is the half the acceptance criterion
/// forbids.
///
/// The residual window this ordering leaves, stated rather than implied: a
/// `POST /v1/auth/refresh` for the same user that commits between
/// `revoked_before` being read from the clock and this transaction's `UPDATE`
/// can mint one access token whose `iat` is later than the watermark. That
/// token's successor refresh row is closed by the same `UPDATE`, so the
/// session cannot renew past that one token's own expiry.
async fn revoke_sessions(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Path(target_user_id): Path<Uuid>,
) -> Result<(StatusCode, Json<RevokeSessionsResponse>), axum::response::Response> {
    // Role gate FIRST, before any lookup. A viewer must not be able to use the
    // 404-vs-403 difference to discover which user ids exist.
    require_role(&ctx, UserRole::Admin).map_err(api_error_response)?;

    let repo = SessionRevocationRepository::new(state.db.clone());
    let target = repo
        .find_target(ctx.workspace_id.0, target_user_id)
        .await
        .map_err(api_error_response)?
        .ok_or_else(|| {
            // A user in another workspace and a user that does not exist give
            // the identical answer — see `find_target`.
            api_error_response(ApiError::NotFound("user not found".into()))
        })?;

    // Parse with the same parser `jwt_auth::require` uses for the `role`
    // claim, so an unrecognised stored role fails here the same way it would
    // fail on the target's own next request rather than being silently
    // treated as low-privilege.
    let target_role = UserRole::from_db_str(&target.role).map_err(api_error_response)?;
    match may_revoke(ctx.role, target_role) {
        RevokeDecision::Allowed => {}
        RevokeDecision::ActorRoleTooLow | RevokeDecision::TargetOutranksActor => {
            return Err(api_error_response(ApiError::Forbidden(
                "insufficient role".into(),
            )));
        }
    }

    let actor_email = repo
        .actor_email(ctx.workspace_id.0, ctx.user_id)
        .await
        .map_err(api_error_response)?;

    let revoked_before = Utc::now().timestamp();
    let outcome = repo
        .revoke(&RevocationRecord {
            workspace_id: ctx.workspace_id.0,
            actor_user_id: ctx.user_id,
            actor_email: actor_email.as_deref(),
            actor_role: ctx.role.as_db_str(),
            target: &target,
            revoked_before_unix: revoked_before,
            // FU4 — NULL is what marks this row as the USER-WIDE lever, and it
            // is also what keeps `latest_watermark` reading it. See that
            // function: a narrow revocation must not be picked up as a
            // user-wide one when Redis is unreachable.
            session_id: None,
        })
        .await
        .map_err(api_error_response)?;

    sp_redis::revoke_sessions_before(
        &state.redis_pool,
        &target.user_id,
        revoked_before,
        sp_redis::revocation_watermark_ttl_secs(state.jwt.access_ttl_secs),
    )
    .await
    .map_err(api_error_response)?;

    // Evict this pod's cached auth entry for the target, exactly as
    // `/v1/auth/logout` does (D-16).
    //
    // FU3 — deliberately still LOCAL, and no longer load-bearing. Two facts
    // make cross-pod eviction unnecessary for THIS action, and both are
    // asserted in `tests/auth_redis_outage.rs`:
    //
    //   1. `auth_cache` is read only when Redis is unreachable. While Redis
    //      answers, `jwt_auth::require` consults the watermark this handler
    //      just published, on every pod, on the next request.
    //   2. When Redis is unreachable, `jwt_auth::require` reads the watermark
    //      from `session_revocation_audit` — the row the transaction above
    //      committed — so a pod with a warm cached entry refuses this target
    //      anyway. `a_revoked_session_is_refused_on_a_pod_that_cannot_reach_redis`
    //      drives exactly that, from a pod that never saw this request.
    //
    // So this line is now a small local optimisation rather than the thing
    // standing between a revoked token and a served request, and adding a
    // pub/sub fan-out to replicate it would buy nothing.
    state.auth_cache.remove(&target.user_id);

    tracing::warn!(
        alert = "session_revoked",
        workspace_id = %ctx.workspace_id.0,
        actor_user_id = %ctx.user_id,
        target_user_id = %target.user_id,
        refresh_tokens_revoked = outcome.refresh_tokens_revoked,
        "administrator terminated a user's sessions"
    );

    Ok((
        StatusCode::OK,
        Json(RevokeSessionsResponse {
            user_id: target.user_id,
            revoked_before,
            refresh_tokens_revoked: outcome.refresh_tokens_revoked,
            audit_id: outcome.audit_id,
            revoked_at: outcome.created_at,
        }),
    ))
}

// ── FU4: seeing sessions, and ending ONE ──────────────────────────────────

/// One live session as the caller sees it.
///
/// `client_ip` and `client` are `None` for a session opened before FU4, for a
/// client that sent nothing usable, and for a session whose device context
/// `retention.purge` has already scrubbed. The listing says "unknown" rather
/// than inventing one.
///
/// The refresh-token hash and the access-token `jti` are absent by
/// construction — [`crate::db::session_repo::SessionSummary`] does not carry
/// them, so no serializer change can start leaking them.
#[derive(Debug, Serialize)]
pub struct SessionDto {
    pub session_id: Uuid,
    pub started_at: DateTime<Utc>,
    /// The last rotation. An access token is used without touching Postgres,
    /// so this is the freshest evidence of use that exists — it is NOT a
    /// last-request timestamp and is not presented as one.
    pub last_seen_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub client_ip: Option<String>,
    pub client: Option<String>,
    /// The session whose access token is making this request.
    pub is_current: bool,
}

#[derive(Debug, Serialize)]
pub struct SessionListResponse {
    pub user_id: Uuid,
    pub sessions: Vec<SessionDto>,
}

#[derive(Debug, Serialize)]
pub struct EndSessionResponse {
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub refresh_tokens_revoked: i64,
    /// How many already-minted access tokens were blacklisted. Zero for a
    /// session that predates migration 027 and therefore recorded no `jti`;
    /// such a session still dies, at its current access token's own expiry
    /// rather than instantly, and this number is how a caller can tell.
    pub access_tokens_blacklisted: usize,
    pub audit_id: Uuid,
    pub revoked_at: DateTime<Utc>,
}

/// May this actor see and manage this target's sessions?
///
/// One new rule on top of WS4-3's ladder, and it DELEGATES rather than
/// restating: [`may_revoke`] still answers for everybody else, so there is one
/// privilege table (`role::privilege_level`) with two readers and not three.
///
/// **The new rule: an actor may always manage their OWN sessions.** This is not
/// a widening of WS4-3, which refused self-revocation below Admin on the stated
/// ground that "`POST /v1/auth/logout` is the route for that". Logout is
/// precisely what it cannot substitute for here: it revokes EVERY refresh row
/// the user holds and blacklists only the token it was presented with, so
/// "sign my other laptop out and keep me signed in here" is not expressible
/// through it. A user reading and ending their own sessions is strictly less
/// powerful than the logout they already have, and it is the commonest real use
/// of a session list.
///
/// WS4-3's user-wide `DELETE /v1/users/{id}/sessions` is untouched and still
/// calls `require_role(_, Admin)` before anything else;
/// `a_user_may_see_and_end_their_own_sessions_without_being_an_admin` asserts
/// that in the same test body that exercises the new rule.
#[must_use]
pub fn may_manage_sessions(actor: UserRole, target: UserRole, is_self: bool) -> RevokeDecision {
    if is_self {
        return RevokeDecision::Allowed;
    }
    may_revoke(actor, target)
}

/// Resolve the subject of a session request and decide whether the caller may
/// touch it. Shared by both FU4 handlers so the listing and the narrow
/// revocation cannot drift into two different answers about who may act.
///
/// # Ordering, which is load-bearing
///
/// For a NON-self target the role gate runs BEFORE any lookup, exactly as
/// `revoke_sessions` does, so a viewer cannot use the 404-vs-403 difference to
/// discover which user ids exist. The self case skips it because looking
/// yourself up is not an enumeration oracle: the caller's own id came from
/// their own signed token.
async fn resolve_subject(
    state: &AppState,
    ctx: &JwtAuthContext,
    target_user_id: Uuid,
) -> Result<RevocationTarget, axum::response::Response> {
    let is_self = ctx.user_id == target_user_id;
    if !is_self {
        require_role(ctx, UserRole::Admin).map_err(api_error_response)?;
    }

    let repo = SessionRevocationRepository::new(state.db.clone());
    let target = repo
        .find_target(ctx.workspace_id.0, target_user_id)
        .await
        .map_err(api_error_response)?
        .ok_or_else(|| api_error_response(ApiError::NotFound("user not found".into())))?;

    let target_role = UserRole::from_db_str(&target.role).map_err(api_error_response)?;
    match may_manage_sessions(ctx.role, target_role, is_self) {
        RevokeDecision::Allowed => Ok(target),
        RevokeDecision::ActorRoleTooLow | RevokeDecision::TargetOutranksActor => Err(
            api_error_response(ApiError::Forbidden("insufficient role".into())),
        ),
    }
}

/// `GET /v1/users/{user_id}/sessions` — the live sessions that user holds.
///
/// This is the half WS4-3 reported missing. Without it an administrator can
/// terminate everything for a user and cannot see what they are terminating,
/// cannot end one lost laptop while leaving a desktop signed in, and cannot
/// answer "where is this account signed in from?" — which is usually the
/// question that prompted the revocation.
async fn list_sessions(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Path(target_user_id): Path<Uuid>,
) -> Result<Json<SessionListResponse>, axum::response::Response> {
    let target = resolve_subject(&state, &ctx, target_user_id).await?;

    let sessions = SessionRepository::new(state.db.clone())
        .list_live(ctx.workspace_id.0, target.user_id, &ctx.jti)
        .await
        .map_err(api_error_response)?;

    Ok(Json(SessionListResponse {
        user_id: target.user_id,
        sessions: sessions
            .into_iter()
            .map(|s| SessionDto {
                session_id: s.session_id,
                started_at: s.started_at,
                last_seen_at: s.last_seen_at,
                expires_at: s.expires_at,
                client_ip: s.client_ip,
                client: s.client_descriptor,
                is_current: s.is_current,
            })
            .collect(),
    }))
}

/// `DELETE /v1/users/{user_id}/sessions/{session_id}` — end ONE session.
///
/// # Why this can use the jti blacklist when WS4-3 could not
///
/// WS4-3 rejected `jti_blacklist:{jti}` as the revocation seam, and was right
/// to: "the key is the token's own random id, which is stored nowhere and
/// listed by no endpoint … an administrator revoking a lost laptop has never
/// seen that jti". That objection is about DISCOVERABILITY, and it stops
/// applying the moment sessions are listable — the listing is where the session
/// id comes from, and migration 027 stores the jti beside it. So the two levers
/// compose rather than compete: WS4-3's per-user watermark still answers "end
/// everything for this person", and this one answers "end this device", through
/// the gate `jwt_auth::session_gate` already applies to both.
///
/// # Ordering, which is load-bearing (the same as WS4-3's)
///
/// Postgres first — close this chain and write the audit row in one
/// transaction — then Redis. A Redis failure gives the caller a 500 to retry,
/// and the operation is idempotent; what has already happened is the durable,
/// provable half. The other order would let a Postgres failure leave a security
/// action performed and unrecorded.
async fn revoke_one_session(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Path((target_user_id, session_id)): Path<(Uuid, Uuid)>,
) -> Result<(StatusCode, Json<EndSessionResponse>), axum::response::Response> {
    let target = resolve_subject(&state, &ctx, target_user_id).await?;

    // Only access tokens minted within one validity window can still be alive;
    // `jwt_auth::require` refuses anything older on `exp` with a 60 s leeway.
    // Anything before this instant is already dead on its own terms, so
    // blacklisting it would be wasted Redis.
    let minted_after = Utc::now()
        - Duration::seconds(i64::try_from(state.jwt.access_ttl_secs).unwrap_or(i64::MAX))
        - Duration::seconds(JWT_VALIDATION_LEEWAY_SECS);

    let sessions = SessionRepository::new(state.db.clone());
    let live = sessions
        .find_live_session(ctx.workspace_id.0, target.user_id, session_id, minted_after)
        .await
        .map_err(api_error_response)?
        .ok_or_else(|| {
            // Absent, another user's, another workspace's, and already-ended
            // all give the identical answer — see `find_live_session`.
            api_error_response(ApiError::NotFound("session not found".into()))
        })?;

    let repo = SessionRevocationRepository::new(state.db.clone());
    let actor_email = repo
        .actor_email(ctx.workspace_id.0, ctx.user_id)
        .await
        .map_err(api_error_response)?;

    let outcome = repo
        .revoke_one_session(
            &RevocationRecord {
                workspace_id: ctx.workspace_id.0,
                actor_user_id: ctx.user_id,
                actor_email: actor_email.as_deref(),
                actor_role: ctx.role.as_db_str(),
                target: &target,
                revoked_before_unix: Utc::now().timestamp(),
                session_id: Some(live.session_id),
            },
            live.session_id,
        )
        .await
        .map_err(api_error_response)?;

    // The blacklist TTL is the one `revocation_watermark_ttl_secs` already
    // computes and documents: long enough to outlive every access token that
    // existed when it was written, short enough that the key does not
    // accumulate forever.
    let ttl = sp_redis::revocation_watermark_ttl_secs(state.jwt.access_ttl_secs);
    for jti in &live.revocable_jtis {
        sp_redis::blacklist_jti(&state.redis_pool, jti, ttl)
            .await
            .map_err(api_error_response)?;
    }

    // NOT `auth_cache.remove(&target.user_id)`. That cache is keyed by USER and
    // evicting it would degrade every session that user holds, which is the
    // opposite of what this endpoint promises. FU3 established that the cache
    // is read only when Redis is unreachable, and the residual that leaves for
    // this lever is stated on `revoke_one_session` in the repository.

    tracing::warn!(
        alert = "session_revoked",
        scope = "session",
        workspace_id = %ctx.workspace_id.0,
        actor_user_id = %ctx.user_id,
        target_user_id = %target.user_id,
        session_id = %live.session_id,
        refresh_tokens_revoked = outcome.refresh_tokens_revoked,
        access_tokens_blacklisted = live.revocable_jtis.len(),
        "administrator terminated one session"
    );

    Ok((
        StatusCode::OK,
        Json(EndSessionResponse {
            user_id: target.user_id,
            session_id: live.session_id,
            refresh_tokens_revoked: outcome.refresh_tokens_revoked,
            access_tokens_blacklisted: live.revocable_jtis.len(),
            audit_id: outcome.audit_id,
            revoked_at: outcome.created_at,
        }),
    ))
}

/// `Validation::leeway` as `jwt_auth::require` sets it (`validation.leeway =
/// 60`). Named here rather than written as a bare `60` so the two cannot drift
/// silently; `the_jti_window_matches_the_middlewares_leeway` pins them
/// together.
const JWT_VALIDATION_LEEWAY_SECS: i64 = 60;

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_ROLES: [UserRole; 5] = [
        UserRole::Owner,
        UserRole::Admin,
        UserRole::Developer,
        UserRole::Employee,
        UserRole::Viewer,
    ];

    /// The complete 25-cell authorization matrix, spelled out rather than
    /// derived, so a change to the ladder shows up here as a diff and not as a
    /// still-green tautology.
    #[test]
    fn may_revoke_matrix() {
        use RevokeDecision::{ActorRoleTooLow, Allowed, TargetOutranksActor};
        let cases = [
            // Owner may revoke anyone, including another owner and themselves.
            (UserRole::Owner, UserRole::Owner, Allowed),
            (UserRole::Owner, UserRole::Admin, Allowed),
            (UserRole::Owner, UserRole::Developer, Allowed),
            (UserRole::Owner, UserRole::Employee, Allowed),
            (UserRole::Owner, UserRole::Viewer, Allowed),
            // Admin may revoke peers and below — but NOT an owner.
            (UserRole::Admin, UserRole::Owner, TargetOutranksActor),
            (UserRole::Admin, UserRole::Admin, Allowed),
            (UserRole::Admin, UserRole::Developer, Allowed),
            (UserRole::Admin, UserRole::Employee, Allowed),
            (UserRole::Admin, UserRole::Viewer, Allowed),
            // Nobody below Admin may revoke anyone at all.
            (UserRole::Developer, UserRole::Owner, ActorRoleTooLow),
            (UserRole::Developer, UserRole::Admin, ActorRoleTooLow),
            (UserRole::Developer, UserRole::Developer, ActorRoleTooLow),
            (UserRole::Developer, UserRole::Employee, ActorRoleTooLow),
            (UserRole::Developer, UserRole::Viewer, ActorRoleTooLow),
            (UserRole::Employee, UserRole::Owner, ActorRoleTooLow),
            (UserRole::Employee, UserRole::Admin, ActorRoleTooLow),
            (UserRole::Employee, UserRole::Developer, ActorRoleTooLow),
            (UserRole::Employee, UserRole::Employee, ActorRoleTooLow),
            (UserRole::Employee, UserRole::Viewer, ActorRoleTooLow),
            (UserRole::Viewer, UserRole::Owner, ActorRoleTooLow),
            (UserRole::Viewer, UserRole::Admin, ActorRoleTooLow),
            (UserRole::Viewer, UserRole::Developer, ActorRoleTooLow),
            (UserRole::Viewer, UserRole::Employee, ActorRoleTooLow),
            (UserRole::Viewer, UserRole::Viewer, ActorRoleTooLow),
        ];
        assert_eq!(
            cases.len(),
            ALL_ROLES.len() * ALL_ROLES.len(),
            "the matrix must cover every (actor, target) pair"
        );
        for (actor, target, expected) in cases {
            let actual = may_revoke(actor, target);
            assert_eq!(
                actual, expected,
                "may_revoke({actor:?}, {target:?}) = {actual:?}, expected {expected:?}"
            );
        }
    }

    /// Self-revocation is allowed for every role that may revoke at all, and
    /// refused for every role that may not — it is not a special case, it
    /// falls out of the ladder. Documented as a decision, asserted as code.
    #[test]
    fn self_revocation_is_allowed_exactly_for_admin_and_owner() {
        for role in ALL_ROLES {
            let expected = if matches!(role, UserRole::Owner | UserRole::Admin) {
                RevokeDecision::Allowed
            } else {
                RevokeDecision::ActorRoleTooLow
            };
            assert_eq!(may_revoke(role, role), expected, "self-revoke as {role:?}");
        }
    }

    /// FU4 — the narrow lever's table is WS4-3's table plus exactly one rule.
    ///
    /// Asserted by DERIVATION from `may_revoke` rather than by a second
    /// hand-written 25-cell matrix: a copied table is the defect this module
    /// already documents, and a copy that agreed today would be free to drift
    /// tomorrow. The one cell that differs is spelled out separately below.
    #[test]
    fn may_manage_sessions_is_may_revoke_plus_self_service() {
        let mut differing = 0_usize;
        for actor in ALL_ROLES {
            for target in ALL_ROLES {
                assert_eq!(
                    may_manage_sessions(actor, target, false),
                    may_revoke(actor, target),
                    "for a target who is not the actor, may_manage_sessions must \
                     BE may_revoke: {actor:?} -> {target:?}"
                );
                let with_self = may_manage_sessions(actor, target, true);
                assert_eq!(
                    with_self,
                    RevokeDecision::Allowed,
                    "an actor may always manage their own sessions ({actor:?})"
                );
                if with_self != may_revoke(actor, target) {
                    differing += 1;
                }
            }
        }
        // POSITIVE CONTROL: the new rule actually changes something. If
        // `is_self` were ignored, every cell would agree and the assertions
        // above would still pass.
        assert!(
            differing > 0,
            "the self-service rule changed no answer at all, so it is not being \
             applied"
        );
    }

    /// The one cell that FU4 adds, named rather than counted: a Viewer may end
    /// their OWN session, which WS4-3's `may_revoke` refuses. The control that
    /// must differ is in the same assertion — the same Viewer may not touch
    /// anybody else's.
    #[test]
    fn a_viewer_may_manage_their_own_sessions_and_nobody_elses() {
        assert_eq!(
            may_manage_sessions(UserRole::Viewer, UserRole::Viewer, true),
            RevokeDecision::Allowed
        );
        assert_eq!(
            may_revoke(UserRole::Viewer, UserRole::Viewer),
            RevokeDecision::ActorRoleTooLow,
            "premise: WS4-3's user-wide lever still refuses a viewer, so the \
             line above is a real change and not a restatement"
        );
        for target in ALL_ROLES {
            assert_eq!(
                may_manage_sessions(UserRole::Viewer, target, false),
                RevokeDecision::ActorRoleTooLow,
                "a viewer must not reach {target:?}'s sessions"
            );
        }
        // And the privilege inversion still holds for the narrow lever: an
        // Admin may not reach an Owner's sessions.
        assert_eq!(
            may_manage_sessions(UserRole::Admin, UserRole::Owner, false),
            RevokeDecision::TargetOutranksActor
        );
    }

    /// The window `revoke_one_session` uses to decide which access tokens are
    /// still worth blacklisting is `access_ttl + leeway`. The leeway half is a
    /// constant in this module and a `validation.leeway = 60` in
    /// `jwt_auth::require`; if they drift, the narrow revocation stops
    /// blacklisting a token the middleware would still accept.
    #[test]
    fn the_jti_window_matches_the_middlewares_leeway() {
        const JWT_AUTH_SOURCE: &str = include_str!("../../middleware/jwt_auth.rs");
        assert!(
            JWT_AUTH_SOURCE.contains("validation.leeway = 60"),
            "jwt_auth no longer sets a 60 s leeway, so \
             JWT_VALIDATION_LEEWAY_SECS = {JWT_VALIDATION_LEEWAY_SECS} is now a \
             guess. Update both together."
        );
        assert_eq!(JWT_VALIDATION_LEEWAY_SECS, 60);
    }

    /// The route's own role gate (`require_role(_, Admin)`) and `may_revoke`
    /// must not drift into two different answers about who may act. If they
    /// did, the handler would refuse callers the pure function admits, or
    /// worse, admit callers it refuses.
    #[test]
    fn the_actor_gate_agrees_with_require_role() {
        use crate::http::routes::dashboard::role::require_role;
        use secureprompt_common::types::WorkspaceId;
        for role in ALL_ROLES {
            let ctx = JwtAuthContext {
                user_id: Uuid::new_v4(),
                workspace_id: WorkspaceId(Uuid::new_v4()),
                role,
                jti: "test".into(),
                exp: 9_999_999_999,
            };
            let gate_admits = require_role(&ctx, UserRole::Admin).is_ok();
            let pure_admits = may_revoke(role, UserRole::Viewer) == RevokeDecision::Allowed;
            assert_eq!(
                gate_admits, pure_admits,
                "require_role and may_revoke disagree about {role:?}"
            );
        }
    }
}
