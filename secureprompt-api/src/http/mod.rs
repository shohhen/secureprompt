pub mod middleware;
pub mod model_router;
pub mod routes;
pub mod streaming;

use crate::app_state::AppState;
use axum::{
    http::StatusCode,
    middleware::from_fn_with_state,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use secureprompt_common::errors::ApiError;
use serde_json::json;

pub fn build_router(state: AppState) -> Router {
    // Phase 5 / Plan 05-01 — dashboard auth routes nest under `/v1/auth`.
    // `/token` and `/refresh` are public; `/logout` gets the JWT middleware
    // applied per-route inside `dashboard::auth::routes` (Task 5-01-C).
    //
    // Phase 5 / Plan 05-03 — analytics routes nest under `/v1/analytics`
    // with the JWT middleware applied to all four GET routes.
    Router::new()
        .route(
            "/v1/chat/completions",
            post(routes::openai::chat_completions),
        )
        .route("/v1/completions", post(routes::openai::completions))
        .route("/v1/embeddings", post(routes::openai::embeddings))
        .route("/metrics", get(routes::openai::metrics))
        .nest("/v1/auth", routes::dashboard::auth::build_router(state.clone()))
        .nest(
            "/v1/analytics",
            routes::dashboard::analytics::routes()
                .route_layer(from_fn_with_state(
                    state.clone(),
                    middleware::jwt_auth::require,
                )),
        )
        .nest(
            "/v1/workspaces",
            routes::dashboard::budgets::build_router(state.clone()),
        )
        .nest(
            "/v1/requests",
            routes::dashboard::requests::routes()
                .route_layer(from_fn_with_state(
                    state.clone(),
                    middleware::jwt_auth::require,
                )),
        )
        .nest(
            "/v1/keys",
            routes::dashboard::keys::routes()
                .route_layer(from_fn_with_state(
                    state.clone(),
                    middleware::jwt_auth::require,
                )),
        )
        .nest(
            "/v1/providers",
            routes::dashboard::providers::routes()
                .route_layer(from_fn_with_state(
                    state.clone(),
                    middleware::jwt_auth::require,
                )),
        )
        .nest(
            "/v1/policy-rules",
            routes::dashboard::policy_rules::routes()
                .route_layer(from_fn_with_state(
                    state.clone(),
                    middleware::jwt_auth::require,
                )),
        )
        .nest(
            "/v1/telemetry",
            Router::new()
                .route(
                    "/client-error",
                    post(routes::telemetry::client_error),
                )
                .route_layer(from_fn_with_state(
                    state.clone(),
                    middleware::jwt_auth::require,
                )),
        )
        .merge(middleware::rate_limit::test_probe_router(state.clone()))
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
