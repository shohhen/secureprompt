pub mod middleware;
pub mod model_router;
/// WS6-4 — the served path/method table, read out of the live `axum::Router`
/// so the OpenAPI document can be checked against it instead of trusted.
pub mod route_table;
pub mod routes;
/// WS2-4 — `sidecar_unavailable` enforcement for the routes that answer the
/// caller directly instead of forwarding to a provider.
pub mod sidecar_coverage;
pub mod streaming;

use crate::app_state::AppState;
use axum::{
    extract::DefaultBodyLimit,
    http::{header, HeaderValue, Method, StatusCode},
    middleware::{from_fn, from_fn_with_state},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use secureprompt_common::errors::ApiError;
use serde_json::json;
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    limit::RequestBodyLimitLayer,
    timeout::TimeoutLayer,
    trace::TraceLayer,
};

pub fn build_router(state: AppState) -> Router {
    // MCP utility routes — registered below the OpenAI compat routes.
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
        .route("/openapi.json", get(openapi_json))
        .route("/v1/redact", post(routes::mcp_routes::redact))
        .route("/v1/vault/stash", post(routes::mcp_routes::vault_stash))
        .route(
            "/v1/tokens/estimate",
            post(routes::mcp_routes::tokens_estimate),
        )
        .route("/v1/policy/check", post(routes::mcp_routes::policy_check))
        .nest(
            "/v1/auth",
            routes::dashboard::auth::build_router(state.clone())
                .merge(routes::dashboard::oidc::routes())
                // 2FA: `/v1/auth/2fa/{enroll,verify,challenge}` are NOT
                // JWT-gated here (they accept purpose tokens instead — see
                // twofactor.rs); `/disable` (Task 8) IS JWT-gated, which is
                // why `build_router(state)` (not the bare `routes()`) is
                // used — it swaps in the real `jwt_auth::require` layer for
                // just that one route.
                .nest("/2fa", routes::dashboard::twofactor::build_router(state.clone())),
        )
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
            "/v1/me",
            routes::dashboard::me::routes()
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
            "/v1/license",
            routes::license::routes()
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
        .nest(
            "/v1/users",
            routes::dashboard::users::routes()
                .route_layer(from_fn_with_state(
                    state.clone(),
                    middleware::jwt_auth::require,
                )),
        )
        .nest(
            "/v1/leak-report",
            routes::dashboard::leak_report::routes()
                .route_layer(from_fn_with_state(
                    state.clone(),
                    middleware::jwt_auth::require,
                )),
        )
        .nest(
            "/v1/data-inventory",
            routes::dashboard::data_inventory::routes()
                .route_layer(from_fn_with_state(
                    state.clone(),
                    middleware::jwt_auth::require,
                )),
        )
        // WS4-1 — the signed audit-trail export. Admin-gated inside the
        // handlers, exactly like `data-inventory` and `leak-report`, and
        // deliberately NOT on the license gate's recovery allowlist: it is
        // ordinary dashboard functionality, not recovery infrastructure.
        .nest(
            "/v1/audit-exports",
            routes::dashboard::audit_export::routes()
                .route_layer(from_fn_with_state(
                    state.clone(),
                    middleware::jwt_auth::require,
                )),
        )
        .nest(
            "/v1/secure-mode",
            routes::dashboard::secure_mode::routes()
                .route_layer(from_fn_with_state(
                    state.clone(),
                    middleware::jwt_auth::require,
                )),
        )
        .route(
            "/internal/attestation",
            get(routes::internal::get_attestation),
        )
        .merge(middleware::rate_limit::test_probe_router(state.clone()))
        // Fail-closed license gate: blocks the data plane + dashboard with 403
        // once the revocation poller confirms the license is revoked. Wraps every
        // route above; an allowlist (health/auth/internal) stays open so a revoked
        // deployment can still authenticate and be re-licensed.
        .layer(from_fn_with_state(
            state.clone(),
            middleware::license_gate::enforce,
        ))
        .with_state(state)
        // ── WS4-5 — request-path hygiene ──────────────────────────────────
        //
        // Applied as separate `.layer()` calls, not one `ServiceBuilder`, and
        // that is load-bearing rather than stylistic: `RequestBodyLimitLayer`
        // rewrites the request body type to `Limited<Body>` and the response
        // type to `ResponseBody<_>`, which `axum::middleware::from_fn` (whose
        // `Next` is typed on `Request<Body>`/`Response<Body>`) will not accept
        // on either side. `Router::layer` re-normalizes through `IntoResponse`
        // after every call, so each layer composes with the router instead of
        // with its neighbour.
        //
        // INNERMOST FIRST — the last `.layer()` is the outermost:
        //
        //   1. inbound deadline   — backstop; see `request_hygiene` for why it
        //                           is set ABOVE the upstream deadline.
        //   2. body limit         — refuses on `Content-Length` before any
        //                           byte is read; `DefaultBodyLimit` keeps
        //                           axum's per-extractor limit in agreement so
        //                           a chunked body with no `Content-Length` is
        //                           cut at the same number.
        //   3. TraceLayer         — inside the span made below, so a 413 and a
        //                           504 are both logged WITH their request id.
        //   4. request id         — outermost hygiene layer on purpose: every
        //                           response, including the two rejections
        //                           above, carries `x-request-id`.
        //   5. CORS               — unchanged, still outermost overall. A
        //                           rejection a browser cannot read is not
        //                           useful to the dashboard.
        //
        // All five sit ABOVE the license gate, and above authentication and
        // rate-limiting (which run inside the handlers). That is the whole
        // point of a body limit: a limit that runs after the expensive work is
        // not a limit.
        .layer(TimeoutLayer::with_status_code(
            StatusCode::GATEWAY_TIMEOUT,
            inbound_deadline(),
        ))
        .layer(RequestBodyLimitLayer::new(max_body_bytes()))
        .layer(DefaultBodyLimit::max(max_body_bytes()))
        .layer(TraceLayer::new_for_http().make_span_with(middleware::request_hygiene::make_span))
        .layer(from_fn(middleware::request_hygiene::propagate))
        .layer(cors_layer())
}

/// Operator-configured maximum request body.
///
/// Read from the environment here for the same reason [`cors_layer`] does:
/// these are router-shaped knobs, not request-shaped ones, and threading them
/// through `AppConfig` would touch every construction site in the test suite
/// without making anything more testable — the decision itself is a pure
/// function in `middleware::request_hygiene`, unit-tested there.
fn max_body_bytes() -> usize {
    middleware::request_hygiene::parse_max_body_bytes(
        std::env::var(middleware::request_hygiene::MAX_BODY_ENV)
            .ok()
            .as_deref(),
    )
}

/// Operator-configured inbound deadline.
fn inbound_deadline() -> std::time::Duration {
    middleware::request_hygiene::parse_request_deadline(
        std::env::var(middleware::request_hygiene::DEADLINE_ENV)
            .ok()
            .as_deref(),
    )
}

/// Browser-facing CORS for the dashboard. Origins are comma-separated in
/// `SECUREPROMPT_CORS_ORIGINS` (e.g. `http://localhost:3000,https://app.example.com`).
/// Defaults to `http://localhost:3000` when unset so local dev "just works".
fn cors_layer() -> CorsLayer {
    let raw = std::env::var("SECUREPROMPT_CORS_ORIGINS")
        .unwrap_or_else(|_| "http://localhost:3000".to_string());
    let origins: Vec<HeaderValue> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| HeaderValue::from_str(s).ok())
        .collect();
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::ACCEPT,
            header::ORIGIN,
        ])
        .allow_credentials(true)
        .max_age(std::time::Duration::from_secs(600))
}

async fn openapi_json() -> impl IntoResponse {
    const SPEC: &str = include_str!(
        "../../../secureprompt-schemas/openapi/v1/openapi.json"
    );
    (
        [
            ("content-type", "application/json"),
            ("access-control-allow-origin", "*"),
        ],
        SPEC,
    )
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
        // Phase 6 / Plan 06-01: auth-cache fallback exhausted (D-15, PG-04).
        ApiError::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
        ApiError::Conflict(_) => StatusCode::CONFLICT,
        ApiError::TooManyRequests(_) => StatusCode::TOO_MANY_REQUESTS,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn too_many_requests_maps_to_429() {
        let err = ApiError::TooManyRequests("slow down".into());
        let resp = api_error_response(err);
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
