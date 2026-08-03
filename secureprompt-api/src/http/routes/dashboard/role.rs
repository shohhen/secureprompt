//! Phase 5 / Plan 05-04 — Role-gate helper shared by keys, providers, and
//! policy_rules handlers.
//!
//! Phase 6 / Plan 06-01 — Extended to 4-level hierarchy (D-08, D-09):
//! Owner(4) > Admin(3) > Developer(2) > Viewer(1).

use secureprompt_common::errors::ApiError;

use crate::http::middleware::jwt_auth::{JwtAuthContext, UserRole};

/// The single privilege ladder (D-08): Owner(4) > Admin(3) > Developer(2) >
/// Viewer/Employee(1).
///
/// Employee shares Viewer's level. Both have read-only access; Employee is
/// further restricted to its own data at the query layer.
///
/// Extracted from inside `require_role` (WS4-3) because a second caller now
/// needs it: `dashboard::users::may_revoke` has to compare an ACTOR's rank
/// against a TARGET's, which "minimum role" cannot express. Two hand-written
/// copies of this table is precisely the defect `auth.rs::decide_2fa`
/// documents — one divergent copy is how a bypass gets shipped — so there is
/// one table and both callers read it.
#[must_use]
pub const fn privilege_level(role: UserRole) -> u8 {
    match role {
        UserRole::Owner => 4,
        UserRole::Admin => 3,
        UserRole::Developer => 2,
        UserRole::Employee | UserRole::Viewer => 1,
    }
}

/// Enforce a minimum role requirement. Returns `Err(ApiError::Forbidden)` if
/// the caller's role is below the minimum.
///
/// Hierarchy (D-08): Owner(4) > Admin(3) > Developer(2) > Viewer(1).
pub fn require_role(ctx: &JwtAuthContext, minimum: UserRole) -> Result<(), ApiError> {
    if privilege_level(ctx.role) >= privilege_level(minimum) {
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

    /// The extracted ladder is the SAME ladder `require_role` used inline
    /// before WS4-3. Asserted rather than assumed: this is a refactor of a
    /// security predicate, and a silent off-by-one here would widen every
    /// admin gate in the product.
    #[test]
    fn privilege_ladder_is_unchanged_by_the_extraction() {
        assert_eq!(privilege_level(UserRole::Owner), 4);
        assert_eq!(privilege_level(UserRole::Admin), 3);
        assert_eq!(privilege_level(UserRole::Developer), 2);
        assert_eq!(privilege_level(UserRole::Employee), 1);
        assert_eq!(privilege_level(UserRole::Viewer), 1);
        // And `require_role` still agrees with it on every ordered pair.
        for actor in [
            UserRole::Owner,
            UserRole::Admin,
            UserRole::Developer,
            UserRole::Employee,
            UserRole::Viewer,
        ] {
            for minimum in [
                UserRole::Owner,
                UserRole::Admin,
                UserRole::Developer,
                UserRole::Employee,
                UserRole::Viewer,
            ] {
                assert_eq!(
                    require_role(&make_ctx(actor), minimum).is_ok(),
                    privilege_level(actor) >= privilege_level(minimum),
                    "require_role({actor:?}, {minimum:?}) disagrees with the ladder"
                );
            }
        }
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
