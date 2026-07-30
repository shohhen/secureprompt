//! User management — GET /v1/users, POST /v1/users,
//! DELETE /v1/users/{user_id}/sessions.
//!
//! GET    — any authenticated role; lists users in the caller's workspace.
//! POST   — admin only; invites (creates) a new user in the same workspace.
//! DELETE /{user_id}/sessions — WS4-3; admin/owner only; terminates every
//!          session that user currently holds.

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    routing::{delete, get},
    Json, Router,
};
use chrono::{DateTime, Utc};
use secureprompt_common::errors::ApiError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    app_state::AppState,
    db::{
        session_revocation_repo::{RevocationRecord, SessionRevocationRepository},
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
        .route("/{user_id}/sessions", delete(revoke_sessions))
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
            return Err(api_error_response(ApiError::Forbidden(
                format!("license seat limit ({max}) reached"),
            )));
        }
    }

    let row = repo
        .create_user(ctx.workspace_id, &body.email, &body.password, &body.role)
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
    // `/v1/auth/logout` does (D-16). It closes the degraded-mode window on the
    // pod that served the revocation; `jwt_auth::require` documents the bound
    // that remains on other pods when Redis is unreachable.
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
