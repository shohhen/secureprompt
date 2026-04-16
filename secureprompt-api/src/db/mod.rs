pub mod api_key_repo;
pub mod policy_repo;
pub mod provider_repo;
pub mod user_repo;
pub mod workspace_repo;

use secureprompt_common::errors::ApiError;

pub use api_key_repo::ApiKeyRepository;
pub use policy_repo::PolicyRepository;
pub use provider_repo::ProviderRepository;
pub use user_repo::UserRepository;
pub use workspace_repo::WorkspaceRepository;

#[must_use]
pub fn api_error_from_sqlx(error: sqlx::Error) -> ApiError {
    ApiError::Database(error.to_string())
}
