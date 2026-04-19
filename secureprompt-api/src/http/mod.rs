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
        // Phase 5 / Plan 05-01: workspace budget exhausted (LIM-02 / LIM-03).
        ApiError::BudgetExceeded(_) => StatusCode::PAYMENT_REQUIRED,
        ApiError::Database(_) | ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };

    // `BudgetExceeded` gets a structured error code for client-side branching
    // (dashboard shows the budget-exhausted banner). Other variants keep the
    // existing OpenAI-compatible envelope.
    let body = match &error {
        ApiError::BudgetExceeded(msg) => json!({
            "error": {
                "code": "budget_exceeded",
                "message": msg,
                "type": "secureprompt_error"
            }
        }),
        _ => json!({
            "error": {
                "message": error.to_string(),
                "type": "secureprompt_error"
            }
        }),
    };

    (status, Json(body)).into_response()
}
