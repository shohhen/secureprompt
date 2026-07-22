//! Task 9 (2FA backend plan) — router-wiring smoke test.
//!
//! Proves `http::build_router` actually nests
//! `routes::dashboard::twofactor::build_router` under `/v1/auth/2fa`: each
//! of the four routes must RESOLVE (401, never 404) when hit without a
//! usable bearer token. A 404 here would mean the route isn't mounted; a
//! 401 proves axum found a matching route and the handler's own auth check
//! ran and rejected the request.
//!
//! `enroll`/`verify`/`challenge` reject a missing/invalid `Authorization`
//! header inside `accept_enroll_or_access` / `accept_challenge`
//! (`jwt_auth::extract_bearer` fails first, before any DB or Redis I/O), and
//! `disable` is rejected by the `jwt_auth::require` middleware layer itself
//! (same short-circuit) before its handler — and therefore its `Json<...>`
//! body extractor — ever runs. So this test exercises real route resolution
//! without depending on Redis being reachable, matching the "DB-free where
//! possible" ask (only Postgres — used solely to construct the pool the
//! router needs, never queried on this path — is required).

mod support;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use sqlx::PgPool;
use tower::ServiceExt;

/// `verify`/`challenge` extract `Json<VerifyRequest>` as a handler parameter,
/// which axum resolves BEFORE the handler body (and thus before the
/// handler's own auth check) runs. A body that fails to parse would 422
/// before ever reaching the auth check, which would defeat the point of this
/// test — so every request sends a syntactically valid `{"code": "..."}"`
/// body regardless of which route it targets.
const VALID_BODY: &str = r#"{"code":"000000"}"#;

#[sqlx::test]
async fn twofactor_routes_resolve_and_reject_missing_auth(pool: PgPool) -> sqlx::Result<()> {
    let app = support::router(pool);

    for path in [
        "/v1/auth/2fa/enroll",
        "/v1/auth/2fa/verify",
        "/v1/auth/2fa/challenge",
        "/v1/auth/2fa/disable",
    ] {
        let request = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(VALID_BODY))
            .expect("valid request");

        let response = app.clone().oneshot(request).await.expect("router runs");
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{path} must resolve as 401 (not 404) with no Authorization header — proves it is mounted"
        );
    }

    Ok(())
}

/// Same shape, but with a well-formed, syntactically-valid-yet-garbage
/// bearer token (not just a missing header) — confirms the handlers'
/// `decode_bearer_claims` / `jwt_auth::require` signature check rejects it
/// the same way, and that the route is not, say, accidentally matching a
/// wildcard/fallback that would 404 on a bad token but 401 on no token at
/// all.
#[sqlx::test]
async fn twofactor_routes_reject_garbage_bearer_token(pool: PgPool) -> sqlx::Result<()> {
    let app = support::router(pool);

    for path in [
        "/v1/auth/2fa/enroll",
        "/v1/auth/2fa/verify",
        "/v1/auth/2fa/challenge",
        "/v1/auth/2fa/disable",
    ] {
        let request = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header("authorization", "Bearer not-a-real-jwt")
            .body(Body::from(VALID_BODY))
            .expect("valid request");

        let response = app.clone().oneshot(request).await.expect("router runs");
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{path} must reject a garbage bearer token with 401 (not 404)"
        );
    }

    Ok(())
}
