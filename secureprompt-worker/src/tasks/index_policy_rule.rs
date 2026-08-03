//! IndexPolicyRule task handler (Phase 7 / Plan 07-04 — QD-01..03).
//!
//! Embeds a policy rule's `condition_text` via the ML sidecar `/embed` endpoint
//! and upserts the resulting vector into the `policy_rag` Qdrant collection.
//! The point ID is the rule's UUID, making re-indexing idempotent.

use anyhow::{Context, Result};
use qdrant_client::qdrant::{PointStruct, UpsertPointsBuilder};
use secureprompt_common::tasks::TaskEnvelope;
use serde::Deserialize;
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Deserialize)]
struct EmbedResponse {
    embedding: Vec<f32>,
}

/// Public entry point — logs errors rather than propagating them so the
/// drain loop stays alive even if a single task fails. Returns `true` on
/// success / `false` on failure so callers can record a
/// `tasks_processed_total{outcome="ok"|"error"}` metric.
pub async fn handle_index_policy_rule(
    task: &TaskEnvelope,
    ml_client: &reqwest::Client,
    qdrant: &qdrant_client::Qdrant,
    ml_sidecar_url: &str,
    ml_sidecar_token: &str,
) -> bool {
    match index_policy_rule(task, ml_client, qdrant, ml_sidecar_url, ml_sidecar_token).await {
        Ok(()) => true,
        Err(e) => {
            tracing::error!(
                error = %e,
                rule_id = ?task.payload.get("rule_id"),
                workspace_id = %task.workspace_id,
                "failed to index policy rule"
            );
            false
        }
    }
}

async fn index_policy_rule(
    task: &TaskEnvelope,
    ml_client: &reqwest::Client,
    qdrant: &qdrant_client::Qdrant,
    ml_sidecar_url: &str,
    ml_sidecar_token: &str,
) -> Result<()> {
    let rule_id = task
        .payload
        .get("rule_id")
        .and_then(|v| v.as_str())
        .context("IndexPolicyRule: missing rule_id in payload")?
        .to_string();

    let condition_text = task
        .payload
        .get("condition_text")
        .and_then(|v| v.as_str())
        .context("IndexPolicyRule: missing condition_text in payload")?
        .to_string();

    // workspace_id comes from task.workspace_id — set by the API from the
    // authenticated JWT at enqueue time, never from user-supplied payload.
    let workspace_id = task.workspace_id.to_string();

    tracing::info!(
        rule_id = %rule_id,
        workspace_id = %workspace_id,
        text_len = condition_text.len(),
        "indexing policy rule"
    );

    // Step 1: Embed via ML sidecar. WS1-5 fix-round: /embed now requires
    // Authorization: Bearer <ML_SIDECAR_INTERNAL_TOKEN> — the same shared
    // secret the sidecar's other authenticated callers (gateway, dashboard
    // proxy) send.
    let embed_url = format!("{ml_sidecar_url}/embed");
    let embed_resp = ml_client
        .post(&embed_url)
        .header("Authorization", format!("Bearer {ml_sidecar_token}"))
        .json(&serde_json::json!({"text": condition_text}))
        .send()
        .await
        .context("IndexPolicyRule: failed to call ML sidecar /embed")?
        .error_for_status()
        .context("IndexPolicyRule: /embed returned error status")?
        .json::<EmbedResponse>()
        .await
        .context("IndexPolicyRule: failed to parse /embed response")?;

    // Step 2: Parse rule_id as UUID — this becomes the Qdrant point ID,
    // ensuring idempotent re-indexing via upsert.
    let point_uuid = Uuid::parse_str(&rule_id)
        .context("IndexPolicyRule: rule_id is not a valid UUID")?;

    // Step 3: Build payload.
    // qdrant_client::qdrant::Value implements From<String>, so .into() converts.
    let payload: HashMap<String, qdrant_client::qdrant::Value> = [
        ("workspace_id".to_string(), workspace_id.clone().into()),
        ("doc_type".to_string(), "policy_rule".to_string().into()),
        ("rule_id".to_string(), rule_id.clone().into()),
    ]
    .into_iter()
    .collect();

    // Step 4: Upsert into policy_rag collection.
    // PointStruct::new accepts id: impl Into<PointId> — Uuid implements that.
    let point = PointStruct::new(point_uuid, embed_resp.embedding, payload);

    qdrant
        .upsert_points(UpsertPointsBuilder::new("policy_rag", vec![point]))
        .await
        .context("IndexPolicyRule: Qdrant upsert failed")?;

    tracing::info!(
        rule_id = %rule_id,
        workspace_id = %workspace_id,
        "policy rule indexed successfully"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use secureprompt_common::tasks::TaskEnvelope;
    use serde_json::json;

    /// A `qdrant_client::Qdrant` handle that never actually connects — the
    /// gRPC channel is lazy, so building one against an address nothing
    /// listens on is safe as long as the test never reaches the upsert step.
    fn dummy_qdrant() -> qdrant_client::Qdrant {
        qdrant_client::Qdrant::from_url("http://127.0.0.1:1")
            .build()
            .expect("qdrant client build is lazy — no connection attempted here")
    }

    // --- WS1-5 fix-round: the ML sidecar now requires
    // `Authorization: Bearer <ML_SIDECAR_INTERNAL_TOKEN>` on /embed too.
    // Raw-TCP capture (same idiom as secureprompt-api's ml_sidecar::client
    // tests) so we assert on the literal bytes on the wire. The mock server
    // replies 500, so `index_policy_rule` errors out at
    // `.error_for_status()` — before ever touching the dummy Qdrant client. ---

    #[tokio::test]
    async fn test_index_policy_rule_attaches_authorization_header() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local addr");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 8192];
            let n = stream.read(&mut buf).unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            let body = b"{\"detail\":\"forced error for header-capture test\"}";
            let resp = format!(
                "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.write_all(body);
            request
        });

        let ml_client = reqwest::Client::new();
        let qdrant = dummy_qdrant();
        let task = TaskEnvelope::new(
            "index_policy_rule",
            json!({"rule_id": Uuid::new_v4().to_string(), "condition_text": "hello"}),
            Uuid::new_v4(),
        );
        let ml_sidecar_url = format!("http://{addr}");

        let result = index_policy_rule(
            &task,
            &ml_client,
            &qdrant,
            &ml_sidecar_url,
            "worker-shared-secret-xyz",
        )
        .await;
        assert!(
            result.is_err(),
            "mock server returns 500, so this must error before ever touching Qdrant"
        );

        let request = server
            .join()
            .expect("mock server thread panicked")
            .to_lowercase();
        assert!(
            request.contains("authorization: bearer worker-shared-secret-xyz"),
            "index_policy_rule must send the Authorization header; got request:\n{request}"
        );
        // Positive control: prove the capture mechanism itself is live by
        // asserting a DIFFERENT, always-present header — otherwise a broken
        // capture (e.g. reading 0 bytes) would make the assertion above
        // vacuously pass.
        assert!(
            request.contains("content-type: application/json"),
            "capture mechanism must see real request headers; got:\n{request}"
        );
    }
}
