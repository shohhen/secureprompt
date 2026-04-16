use secureprompt_common::errors::ApiError;

#[must_use]
pub fn api_error_from_sqlx(error: sqlx::Error) -> ApiError {
    ApiError::Database(error.to_string())
}
