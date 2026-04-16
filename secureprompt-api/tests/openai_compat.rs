mod support;

use axum::http::{Method, Request, StatusCode};
use serde_json::json;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const API_KEY: &str = "sp_phase2_openai_compat";

#[sqlx::test]
async fn chat_completions_route_returns_openai_shape(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    support::seed_workspace(&pool, workspace_id, API_KEY).await?;
    support::seed_provider_and_model(
        &pool,
        workspace_id,
        Uuid::new_v4(),
        "openai-primary",
        "openai",
        None,
        "gpt-4o-mini",
    )
    .await?;

    let app = support::router(pool.clone());
    let request = support::authorized_request(
        Request::builder()
            .method(Method::POST)
            .uri("/v1/chat/completions"),
        API_KEY,
        json!({
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "hello gateway"}]
        }),
    );

    let response = app.oneshot(request).await.expect("router should respond");
    assert_eq!(response.status(), StatusCode::OK);

    let body = serde_json::from_str::<serde_json::Value>(&support::response_text(response).await)
        .expect("json response");
    assert_eq!(body["object"], "chat.completion");
    assert_eq!(body["model"], "gpt-4o-mini");
    assert!(body["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or_default()
        .contains("openai echo"));
    Ok(())
}

#[sqlx::test]
async fn completions_route_returns_legacy_shape(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    support::seed_workspace(&pool, workspace_id, API_KEY).await?;
    support::seed_provider_and_model(
        &pool,
        workspace_id,
        Uuid::new_v4(),
        "openai-primary",
        "openai",
        None,
        "gpt-4o-mini",
    )
    .await?;

    let app = support::router(pool.clone());
    let request = support::authorized_request(
        Request::builder()
            .method(Method::POST)
            .uri("/v1/completions"),
        API_KEY,
        json!({
            "model": "gpt-4o-mini",
            "prompt": "legacy completion"
        }),
    );

    let response = app.oneshot(request).await.expect("router should respond");
    assert_eq!(response.status(), StatusCode::OK);

    let body = serde_json::from_str::<serde_json::Value>(&support::response_text(response).await)
        .expect("json response");
    assert_eq!(body["object"], "text_completion");
    assert!(body["choices"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .contains("openai echo"));
    Ok(())
}

#[sqlx::test]
async fn embeddings_route_returns_embedding_list(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    support::seed_workspace(&pool, workspace_id, API_KEY).await?;
    support::seed_provider_and_model(
        &pool,
        workspace_id,
        Uuid::new_v4(),
        "openai-primary",
        "openai",
        None,
        "text-embedding-3-small",
    )
    .await?;

    let app = support::router(pool.clone());
    let request = support::authorized_request(
        Request::builder()
            .method(Method::POST)
            .uri("/v1/embeddings"),
        API_KEY,
        json!({
            "model": "text-embedding-3-small",
            "input": "embed me"
        }),
    );

    let response = app.oneshot(request).await.expect("router should respond");
    assert_eq!(response.status(), StatusCode::OK);

    let body = serde_json::from_str::<serde_json::Value>(&support::response_text(response).await)
        .expect("json response");
    assert_eq!(body["object"], "list");
    assert!(body["data"][0]["embedding"].as_array().is_some());
    Ok(())
}
