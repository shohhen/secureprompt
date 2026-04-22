mod support;

use axum::http::{Method, Request, StatusCode};
use serde_json::json;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const API_KEY: &str = "sp_mcp_routes_test";

// ── /v1/tokens/estimate ──────────────────────────────────────────────────────

#[sqlx::test]
async fn tokens_estimate_returns_count_for_text(pool: PgPool) -> sqlx::Result<()> {
    let app = support::router(pool);
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/tokens/estimate")
        .header("Content-Type", "application/json")
        .body(axum::body::Body::from(
            serde_json::to_string(&json!({"text": "hello world this is a test"})).unwrap(),
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = support::response_json(response).await;
    assert!(
        body["estimated_tokens"].as_u64().unwrap_or(0) > 0,
        "should return positive token estimate"
    );
    assert!(
        body["model"].as_str().is_some(),
        "should return a model field"
    );
    Ok(())
}

#[sqlx::test]
async fn tokens_estimate_accepts_optional_model(pool: PgPool) -> sqlx::Result<()> {
    let app = support::router(pool);
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/tokens/estimate")
        .header("Content-Type", "application/json")
        .body(axum::body::Body::from(
            serde_json::to_string(&json!({"text": "short", "model": "gpt-4o"})).unwrap(),
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = support::response_json(response).await;
    assert_eq!(body["model"], "gpt-4o");
    Ok(())
}

// ── /v1/redact ───────────────────────────────────────────────────────────────

#[sqlx::test]
async fn redact_requires_api_key_auth(pool: PgPool) -> sqlx::Result<()> {
    let app = support::router(pool);
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/redact")
        .header("Content-Type", "application/json")
        .body(axum::body::Body::from(
            serde_json::to_string(&json!({"text": "my email is user@example.com"})).unwrap(),
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "unauthenticated /v1/redact must return 401"
    );
    Ok(())
}

#[sqlx::test]
async fn redact_returns_text_and_detections(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    support::seed_workspace(&pool, workspace_id, API_KEY).await?;

    let app = support::router(pool);
    let request = support::authorized_request(
        Request::builder()
            .method(Method::POST)
            .uri("/v1/redact"),
        API_KEY,
        json!({"text": "my AWS key is AKIAIOSFODNN7EXAMPLE and email is bob@example.com"}),
    );

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = support::response_json(response).await;
    assert!(
        body["redacted_text"].as_str().is_some(),
        "should have redacted_text field"
    );
    assert!(
        body["detections"].as_array().is_some(),
        "should have detections array"
    );
    assert!(
        body["vault_size"].as_u64().is_some(),
        "should have vault_size field"
    );
    Ok(())
}

// ── /v1/policy/check ─────────────────────────────────────────────────────────

#[sqlx::test]
async fn policy_check_requires_api_key_auth(pool: PgPool) -> sqlx::Result<()> {
    let app = support::router(pool);
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/policy/check")
        .header("Content-Type", "application/json")
        .body(axum::body::Body::from(
            serde_json::to_string(&json!({"text": "some prompt"})).unwrap(),
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "unauthenticated /v1/policy/check must return 401"
    );
    Ok(())
}

#[sqlx::test]
async fn policy_check_returns_allowed_and_action(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    support::seed_workspace(&pool, workspace_id, API_KEY).await?;

    let app = support::router(pool);
    let request = support::authorized_request(
        Request::builder()
            .method(Method::POST)
            .uri("/v1/policy/check"),
        API_KEY,
        json!({"text": "a safe prompt with no violations"}),
    );

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = support::response_json(response).await;
    assert!(
        body["allowed"].as_bool().is_some(),
        "should have allowed boolean"
    );
    assert!(
        body["action"].as_str().is_some(),
        "should have action string"
    );
    assert!(
        body["events"].as_array().is_some(),
        "should have events array"
    );
    Ok(())
}
