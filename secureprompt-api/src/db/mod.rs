pub mod api_key_repo;
pub mod budget_repo;
pub mod license_repo;
pub mod policy_repo;
pub mod provider_repo;
pub mod refresh_token_repo;
pub mod secure_mode_repo;
pub mod token_vault_repo;
pub mod user_repo;
pub mod workspace_repo;

use secureprompt_common::errors::ApiError;

pub use api_key_repo::{ApiKeyRepository, AuthenticatedApiKey};
pub use budget_repo::{BudgetBehavior, BudgetRepository, WorkspaceBudgetRow};
pub use policy_repo::{PolicyRepository, PolicyRuleRow};
pub use provider_repo::{ProviderRepository, ResolvedModelTarget};
pub use refresh_token_repo::RefreshTokenRepository;
pub use user_repo::UserRepository;
pub use workspace_repo::WorkspaceRepository;

#[must_use]
pub fn api_error_from_sqlx(error: sqlx::Error) -> ApiError {
    ApiError::Database(error.to_string())
}
