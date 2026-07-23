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
) -> bool {
    match index_policy_rule(task, ml_client, qdrant, ml_sidecar_url).await {
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

    // Step 1: Embed via ML sidecar.
    let embed_url = format!("{ml_sidecar_url}/embed");
    let embed_resp = ml_client
        .post(&embed_url)
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
