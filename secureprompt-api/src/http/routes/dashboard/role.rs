//! Phase 5 / Plan 05-04 — Role-gate helper shared by keys, providers, and
//! policy_rules handlers.
//!
//! Role hierarchy (highest → lowest): Admin > Member > Viewer.

use secureprompt_common::errors::ApiError;

use crate::http::middleware::jwt_auth::{JwtAuthContext, UserRole};

/// Require that the authenticated user holds at least `minimum` role.
///
/// # Errors
/// Returns `ApiError::Forbidden("insufficient role")` when the caller's role
/// is below the required minimum.
pub fn require_role(ctx: &JwtAuthContext, minimum: UserRole) -> Result<(), ApiError> {
    match (ctx.role, minimum) {
        // Admin can do anything.
        (UserRole::Admin, _) => Ok(()),
        // Member satisfies Member or Viewer requirements.
        (UserRole::Member, UserRole::Member | UserRole::Viewer) => Ok(()),
        // Viewer satisfies only Viewer requirements.
        (UserRole::Viewer, UserRole::Viewer) => Ok(()),
        // All other combinations are insufficient.
        _ => Err(ApiError::Forbidden("insufficient role".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use secureprompt_common::types::WorkspaceId;

    fn ctx(role: UserRole) -> JwtAuthContext {
        JwtAuthContext {
            user_id: Uuid::new_v4(),
            workspace_id: WorkspaceId(Uuid::new_v4()),
            role,
            jti: "test".into(),
            exp: 9_999_999_999,
        }
    }

    #[test]
    fn admin_passes_all_levels() {
        assert!(require_role(&ctx(UserRole::Admin), UserRole::Admin).is_ok());
        assert!(require_role(&ctx(UserRole::Admin), UserRole::Member).is_ok());
        assert!(require_role(&ctx(UserRole::Admin), UserRole::Viewer).is_ok());
    }

    #[test]
    fn member_passes_member_and_viewer() {
        assert!(require_role(&ctx(UserRole::Member), UserRole::Member).is_ok());
        assert!(require_role(&ctx(UserRole::Member), UserRole::Viewer).is_ok());
        assert!(require_role(&ctx(UserRole::Member), UserRole::Admin).is_err());
    }

    #[test]
    fn viewer_passes_only_viewer() {
        assert!(require_role(&ctx(UserRole::Viewer), UserRole::Viewer).is_ok());
        assert!(require_role(&ctx(UserRole::Viewer), UserRole::Member).is_err());
        assert!(require_role(&ctx(UserRole::Viewer), UserRole::Admin).is_err());
    }
}
