mod support;

use axum::http::{Method, Request, StatusCode};
use serde_json::json;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const API_KEY: &str = "sp_phase2_streaming_redaction";

#[sqlx::test]
async fn streaming_route_restores_redacted_values_and_includes_usage(
    pool: PgPool,
) -> sqlx::Result<()> {
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
    support::seed_policy_rule(
        &pool,
        workspace_id,
        "redact email",
        10,
        json!([{ "field": "detection_class", "op": "eq", "value": "email" }]),
        "redact",
        json!({}),
        false,
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
            "stream": true,
            "stream_options": { "include_usage": true },
            "messages": [{
                "role": "user",
                "content": "email alice@example.com should round trip"
            }]
        }),
    );

    let response = app.oneshot(request).await.expect("router should respond");
    assert_eq!(response.status(), StatusCode::OK);

    let body = support::response_text(response).await;
    assert!(body.contains("alice@example.com"));
    assert!(!body.contains("[REDACTED:"));
    assert!(body.contains("\"usage\""));
    Ok(())
}
