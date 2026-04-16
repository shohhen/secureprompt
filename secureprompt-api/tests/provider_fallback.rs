mod support;

use axum::http::{Method, Request, StatusCode};
use secureprompt_api::http::streaming::fallback_allowed;
use serde_json::json;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const API_KEY: &str = "sp_phase2_provider_fallback";

#[sqlx::test]
async fn retryable_provider_failure_falls_back_before_first_byte(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    support::seed_workspace(&pool, workspace_id, API_KEY).await?;
    support::seed_provider_and_model(
        &pool,
        workspace_id,
        Uuid::new_v4(),
        "openai-primary",
        "openai",
        Some("force_retryable"),
        "gpt-4o-mini",
    )
    .await?;
    support::seed_provider_and_model(
        &pool,
        workspace_id,
        Uuid::new_v4(),
        "ollama-fallback",
        "ollama",
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
            "messages": [{"role": "user", "content": "fallback me"}]
        }),
    );

    let response = app.oneshot(request).await.expect("router should respond");
    assert_eq!(response.status(), StatusCode::OK);

    let body = serde_json::from_str::<serde_json::Value>(&support::response_text(response).await)
        .expect("json response");
    assert!(body["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or_default()
        .contains("ollama echo"));
    Ok(())
}

#[test]
fn fallback_is_disallowed_after_streaming_starts() {
    assert!(fallback_allowed(0));
    assert!(!fallback_allowed(1));
}
