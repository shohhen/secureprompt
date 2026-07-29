//! MCP utility routes (MCP-02, MCP-03, MCP-05).
//!
//! POST /v1/redact          — redact PII/secrets from text, return detections
//! POST /v1/tokens/estimate — approximate token count for a text+model pair
//! POST /v1/policy/check    — dry-run policy evaluation (no provider call)

use axum::{
    extract::State,
    http::HeaderMap,
    Json,
};
use secureprompt_common::types::{RequestId, TokenVault};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{
    app_state::AppState,
    db::PolicyRepository,
    detection::{detect_content, merge::merge_detections},
    http::{api_error_response, middleware::api_key_auth::authenticate_request},
    policy::engine::{evaluate, PolicyEvaluationInput},
    vault::apply_redaction,
};

// ── /v1/redact ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RedactRequest {
    pub text: String,
}

#[derive(Serialize)]
pub struct RedactResponse {
    pub redacted_text: String,
    pub detections: Vec<DetectionItem>,
    pub vault_size: usize,
}

#[derive(Serialize)]
pub struct DetectionItem {
    pub class: String,
    pub value: String,
}

// ── /v1/vault/stash ─────────────────────────────────────────────────────────
// Reversible file-scan support. A scanned file's `{{Type_N}}` → original-PII map
// is stashed here (Redis, TTL); the chat pipeline preloads its vault from the ref
// embedded as an opaque `[[sp:v=<ref>]]` marker in the message, and
// `restore_content` puts the real values back in the model's response. The map
// (with PII) lives only in Redis — never in LibreChat's message DB.

#[derive(Deserialize)]
pub struct VaultStashRequest {
    pub token_map: HashMap<String, String>,
}

#[derive(Serialize)]
pub struct VaultStashResponse {
    pub vault_ref: String,
}

/// TTL for a stashed file vault — long enough to upload then send the message,
/// short enough to bound memory.
const FILE_VAULT_TTL_SECS: u64 = 6 * 60 * 60;

pub async fn vault_stash(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<VaultStashRequest>,
) -> Result<Json<VaultStashResponse>, axum::response::Response> {
    // A stash holds PII — require the same per-user auth as every data route.
    let _auth = authenticate_request(&headers, &state)
        .await
        .map_err(api_error_response)?;
    if body.token_map.is_empty() {
        return Ok(Json(VaultStashResponse {
            vault_ref: String::new(),
        }));
    }
    let vault_ref = RequestId::new().to_string();
    let map_json = serde_json::to_string(&body.token_map).unwrap_or_default();
    crate::redis::stash_file_vault(&state.redis_pool, &vault_ref, &map_json, FILE_VAULT_TTL_SECS)
        .await
        .map_err(api_error_response)?;
    Ok(Json(VaultStashResponse { vault_ref }))
}

pub async fn redact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RedactRequest>,
) -> Result<axum::response::Response, axum::response::Response> {
    let auth = authenticate_request(&headers, &state)
        .await
        .map_err(api_error_response)?;

    let request_id = RequestId::new();
    let regex_detections = detect_content(&body.text);
    let ml_outcome = state.ml_sidecar.detect_if_available(&body.text).await;

    // WS2-4 — honour the workspace's `sidecar_unavailable` policy. The MCP
    // `redact` tool's answer is what the agent forwards to a model; a
    // floor-only redaction returned as an ordinary 200 is indistinguishable
    // from a fully-scanned one.
    let degraded = crate::http::sidecar_coverage::enforce(
        &state,
        request_id,
        auth.workspace_id,
        &ml_outcome.coverage,
    )
    .await
    .map_err(api_error_response)?;
    let detections = merge_detections(regex_detections, ml_outcome.detections);

    let mut vault = TokenVault::default();
    let mut redaction_map = HashMap::new();
    let redacted_text = apply_redaction(&body.text, &detections, &mut vault, &mut redaction_map);

    // Run policy engine to apply workspace rules (may further redact or block).
    let policy_repo = PolicyRepository::new(state.db.clone());
    let outcome = evaluate(
        &policy_repo,
        PolicyEvaluationInput {
            request_id,
            workspace_id: auth.workspace_id,
            provider_name: "none",
            model: "none",
            content: &body.text,
            detections: &detections,
            fail_closed: state.config.redact_when_no_rules,
        },
        &mut vault,
        &mut redaction_map,
    )
    .await
    .map_err(|e| api_error_response(e))?;

    let final_text = if outcome.denied {
        // Policy denied — return the redacted text (detections still visible)
        redacted_text
    } else {
        outcome.content
    };

    let vault_size = vault.len();
    let detection_items = detections
        .into_iter()
        .map(|d| DetectionItem {
            class: d.class,
            value: d.value,
        })
        .collect();

    Ok(crate::http::sidecar_coverage::with_sidecar_degraded(
        axum::response::IntoResponse::into_response(Json(RedactResponse {
            redacted_text: final_text,
            detections: detection_items,
            vault_size,
        })),
        degraded,
    ))
}

// ── /v1/tokens/estimate ───────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct EstimateRequest {
    pub text: String,
    pub model: Option<String>,
}

#[derive(Serialize)]
pub struct EstimateResponse {
    pub estimated_tokens: u64,
    pub model: String,
}

pub async fn tokens_estimate(
    Json(body): Json<EstimateRequest>,
) -> Json<EstimateResponse> {
    // Approximate: 1 token ≈ 4 characters (GPT-family heuristic).
    let estimated_tokens = (body.text.len() as f64 / 4.0).ceil() as u64;
    let model = body.model.unwrap_or_else(|| "unknown".to_owned());
    Json(EstimateResponse {
        estimated_tokens,
        model,
    })
}

// ── /v1/policy/check ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct PolicyCheckRequest {
    pub text: String,
    pub model: Option<String>,
}

#[derive(Serialize)]
pub struct PolicyCheckResponse {
    pub allowed: bool,
    pub action: String,
    pub events: Vec<String>,
}

pub async fn policy_check(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PolicyCheckRequest>,
) -> Result<axum::response::Response, axum::response::Response> {
    let auth = authenticate_request(&headers, &state)
        .await
        .map_err(api_error_response)?;

    let request_id = RequestId::new();
    let regex_detections = detect_content(&body.text);
    let ml_outcome = state.ml_sidecar.detect_if_available(&body.text).await;

    // WS2-4 — honour the workspace's `sidecar_unavailable` policy. This is
    // the sharpest of the three: the caller acts on `allowed`, and an
    // `allowed = true` derived from a detection set the ML layer never
    // contributed to is a permission slip for unscanned text.
    let degraded = crate::http::sidecar_coverage::enforce(
        &state,
        request_id,
        auth.workspace_id,
        &ml_outcome.coverage,
    )
    .await
    .map_err(api_error_response)?;
    let detections = merge_detections(regex_detections, ml_outcome.detections);

    let policy_repo = PolicyRepository::new(state.db.clone());
    let model = body.model.as_deref().unwrap_or("none");

    let mut vault = TokenVault::default();
    let mut redaction_map = HashMap::new();

    let outcome = evaluate(
        &policy_repo,
        PolicyEvaluationInput {
            request_id,
            workspace_id: auth.workspace_id,
            provider_name: "none",
            model,
            content: &body.text,
            detections: &detections,
            fail_closed: state.config.redact_when_no_rules,
        },
        &mut vault,
        &mut redaction_map,
    )
    .await
    .map_err(|e| api_error_response(e))?;

    let events: Vec<String> = outcome
        .result
        .events
        .iter()
        .map(|e| format!("{e:?}"))
        .collect();

    Ok(crate::http::sidecar_coverage::with_sidecar_degraded(
        axum::response::IntoResponse::into_response(Json(PolicyCheckResponse {
            allowed: !outcome.denied,
            action: outcome.result.final_action,
            events,
        })),
        degraded,
    ))
}
