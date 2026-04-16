pub mod middleware;
pub mod model_router;
pub mod routes;
pub mod streaming;

use crate::app_state::AppState;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use secureprompt_common::errors::ApiError;
use serde_json::json;

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route(
            "/v1/chat/completions",
            post(routes::openai::chat_completions),
        )
        .route("/v1/completions", post(routes::openai::completions))
        .route("/v1/embeddings", post(routes::openai::embeddings))
        .route("/metrics", get(routes::openai::metrics))
        .with_state(state)
}

pub fn api_error_response(error: ApiError) -> Response {
    let status = match error {
        ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
        ApiError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
        ApiError::Forbidden(_) => StatusCode::FORBIDDEN,
        ApiError::NotFound(_) => StatusCode::NOT_FOUND,
        ApiError::NotImplemented(_) => StatusCode::NOT_IMPLEMENTED,
        ApiError::Database(_) | ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };

    (
        status,
        Json(json!({
            "error": {
                "message": error.to_string(),
                "type": "secureprompt_error"
            }
        })),
    )
        .into_response()
}
