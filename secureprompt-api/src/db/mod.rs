pub mod api_key_repo;
pub mod budget_repo;
pub mod license_repo;
pub mod policy_repo;
pub mod provider_repo;
pub mod raw_capture_repo;
pub mod refresh_token_repo;
pub mod secure_mode_repo;
// WS4-3 — admin-initiated session revocation + its append-only audit row.
pub mod session_revocation_repo;
pub mod sidecar_policy_repo;
pub mod token_vault_repo;
pub mod user_repo;
pub mod workspace_repo;

use secureprompt_common::errors::ApiError;

pub use api_key_repo::{ApiKeyRepository, AuthenticatedApiKey};
pub use budget_repo::{BudgetBehavior, BudgetRepository, WorkspaceBudgetRow};
pub use policy_repo::{PolicyRepository, PolicyRuleRow};
pub use provider_repo::{ProviderRepository, ResolvedModelTarget};
pub use raw_capture_repo::{RawCaptureRepository, RawCaptureSettings};
pub use refresh_token_repo::RefreshTokenRepository;
pub use session_revocation_repo::{
    RevocationOutcome, RevocationRecord, RevocationTarget, SessionRevocationRepository,
};
pub use sidecar_policy_repo::{SidecarPolicyRepository, SidecarUnavailablePolicy};
pub use user_repo::UserRepository;
pub use workspace_repo::WorkspaceRepository;

#[must_use]
pub fn api_error_from_sqlx(error: sqlx::Error) -> ApiError {
    ApiError::Database(error.to_string())
}
