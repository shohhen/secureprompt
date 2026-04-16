mod support;

use axum::http::{Method, Request, StatusCode};
use serde_json::json;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const API_KEY: &str = "sp_phase2_usage_fallback";

#[sqlx::test]
async fn missing_provider_usage_falls_back_to_estimation(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    support::seed_workspace(&pool, workspace_id, API_KEY).await?;
    support::seed_provider_and_model(
        &pool,
        workspace_id,
        Uuid::new_v4(),
        "anthropic-primary",
        "anthropic",
        None,
        "claude-3-5-haiku",
    )
    .await?;

    let app = support::router(pool.clone());
    let request = support::authorized_request(
        Request::builder()
            .method(Method::POST)
            .uri("/v1/chat/completions"),
        API_KEY,
        json!({
            "model": "claude-3-5-haiku",
            "omit_usage": true,
            "messages": [{"role": "user", "content": "estimate my usage please"}]
        }),
    );

    let response = app.oneshot(request).await.expect("router should respond");
    assert_eq!(response.status(), StatusCode::OK);

    let body = serde_json::from_str::<serde_json::Value>(&support::response_text(response).await)
        .expect("json response");
    assert_eq!(body["usage"]["estimated"], true);
    assert!(body["usage"]["prompt_tokens"].as_u64().unwrap_or_default() > 0);
    assert!(
        body["usage"]["completion_tokens"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );
    Ok(())
}
