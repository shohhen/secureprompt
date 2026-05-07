//! Phase 5 / Plan 05-04 — Role-gate helper shared by keys, providers, and
//! policy_rules handlers.
//!
//! Phase 6 / Plan 06-01 — Extended to 4-level hierarchy (D-08, D-09):
//! Owner(4) > Admin(3) > Developer(2) > Viewer(1).

use secureprompt_common::errors::ApiError;

use crate::http::middleware::jwt_auth::{JwtAuthContext, UserRole};

/// Enforce a minimum role requirement. Returns `Err(ApiError::Forbidden)` if
/// the caller's role is below the minimum.
///
/// Hierarchy (D-08): Owner(4) > Admin(3) > Developer(2) > Viewer(1).
pub fn require_role(ctx: &JwtAuthContext, minimum: UserRole) -> Result<(), ApiError> {
    // Employee = Viewer's privilege level. Both have read-only access
    // (Employee further restricted to own data at the query layer).
    let level = |r: UserRole| match r {
        UserRole::Owner => 4u8,
        UserRole::Admin => 3,
        UserRole::Developer => 2,
        UserRole::Employee => 1,
        UserRole::Viewer => 1,
    };
    if level(ctx.role) >= level(minimum) {
        Ok(())
    } else {
        Err(ApiError::Forbidden("insufficient role".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secureprompt_common::types::WorkspaceId;
    use uuid::Uuid;

    fn make_ctx(role: UserRole) -> JwtAuthContext {
        JwtAuthContext {
            user_id: Uuid::new_v4(),
            workspace_id: WorkspaceId(Uuid::new_v4()),
            role,
            jti: "test".into(),
            exp: 9_999_999_999,
        }
    }

    #[test]
    fn owner_passes_all_levels() {
        let ctx = make_ctx(UserRole::Owner);
        assert!(require_role(&ctx, UserRole::Owner).is_ok());
        assert!(require_role(&ctx, UserRole::Admin).is_ok());
        assert!(require_role(&ctx, UserRole::Developer).is_ok());
        assert!(require_role(&ctx, UserRole::Viewer).is_ok());
    }

    #[test]
    fn admin_passes_all_below_owner() {
        let ctx = make_ctx(UserRole::Admin);
        assert!(require_role(&ctx, UserRole::Admin).is_ok());
        assert!(require_role(&ctx, UserRole::Developer).is_ok());
        assert!(require_role(&ctx, UserRole::Viewer).is_ok());
        assert!(require_role(&ctx, UserRole::Owner).is_err());
    }

    #[test]
    fn developer_fails_admin() {
        let ctx = make_ctx(UserRole::Developer);
        assert!(require_role(&ctx, UserRole::Developer).is_ok());
        assert!(require_role(&ctx, UserRole::Viewer).is_ok());
        assert!(require_role(&ctx, UserRole::Admin).is_err());
        assert!(require_role(&ctx, UserRole::Owner).is_err());
    }

    #[test]
    fn viewer_passes_only_viewer() {
        let ctx = make_ctx(UserRole::Viewer);
        assert!(require_role(&ctx, UserRole::Viewer).is_ok());
        assert!(require_role(&ctx, UserRole::Developer).is_err());
        assert!(require_role(&ctx, UserRole::Admin).is_err());
        assert!(require_role(&ctx, UserRole::Owner).is_err());
    }
}
