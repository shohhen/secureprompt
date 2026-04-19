use thiserror::Error;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("not implemented: {0}")]
    NotImplemented(String),
    #[error("internal error: {0}")]
    Internal(String),
    #[error("database error: {0}")]
    Database(String),
    /// HTTP 402 Payment Required — workspace exceeded its token budget.
    /// Emitted by Plan 05's budget_check when `workspace_budgets.behavior = 'block'`.
    #[error("budget exceeded: {0}")]
    BudgetExceeded(String),
}

#[derive(Error, Debug)]
pub enum AppError {
    #[error("pipeline error: {0}")]
    Pipeline(String),
    #[error("policy evaluation error: {0}")]
    Policy(String),
    #[error("detection error: {0}")]
    Detection(String),
}

impl From<AppError> for ApiError {
    fn from(error: AppError) -> Self {
        Self::Internal(error.to_string())
    }
}
