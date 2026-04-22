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
    /// HTTP 503 Service Unavailable — a backing service (Redis, Postgres) is
    /// temporarily unreachable and no cache fallback is available.
    /// Added Phase 6 / Plan 06-01 for auth-cache fallback exhaustion (D-15, PG-04).
    #[error("service unavailable: {0}")]
    ServiceUnavailable(String),
    /// HTTP 409 Conflict — e.g. duplicate email on user creation.
    #[error("conflict: {0}")]
    Conflict(String),
    /// HTTP 429 Too Many Requests — per-IP rate limit exceeded.
    /// Currently emitted by the public signup endpoint; other rate-limited
    /// surfaces keep their existing 403 mapping until a follow-up unifies them.
    #[error("too many requests: {0}")]
    TooManyRequests(String),
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
