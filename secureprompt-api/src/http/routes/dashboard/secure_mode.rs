//! Secure mode configuration — GET/PUT /v1/secure-mode, plus the
//! POST /v1/secure-mode/tokenize + POST /v1/secure-mode/detokenize
//! playground endpoints.
//!
//! GET  — any authenticated role; returns workspace secure mode config.
//! PUT  — admin only; upserts the config.
//! POST /tokenize   — any authenticated role; redacts PII in the supplied
//!                    text using the ML sidecar and stores the
//!                    placeholder → original mapping in the token vault.
//! POST /detokenize — any authenticated role; restores originals using a
//!                    vault entry the caller previously created.

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use secureprompt_common::{errors::ApiError, types::{Detection, TokenVault}};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::{
    app_state::AppState,
    db::{secure_mode_repo::SecureModeRepository, token_vault_repo::TokenVaultRepository},
    http::{
        api_error_response,
        middleware::jwt_auth::{JwtAuthContext, UserRole},
        routes::dashboard::role::require_role,
    },
    vault::{apply_redaction, restore_content},
};

// ── DTOs ──────────────────────────────────────────────────────────────────────

const VALID_LEVELS: &[&str] = &["permissive", "standard", "strict"];

#[derive(Debug, Serialize)]
pub struct SecureModeResponse {
    pub workspace_id: Uuid,
    pub enabled: bool,
    pub level: String,
    pub block_on_pii_detection: bool,
    pub block_on_injection_detection: bool,
    pub redact_pii_in_responses: bool,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct PutSecureModeRequest {
    pub enabled: Option<bool>,
    pub level: Option<String>,
    pub block_on_pii_detection: Option<bool>,
    pub block_on_injection_detection: Option<bool>,
    pub redact_pii_in_responses: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct TokenizeRequest {
    pub text: String,
    /// Optional filter — when present, only detections whose `class`
    /// (case-insensitive) appears in the list are tokenized.
    pub entity_labels: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct TokenizeResponse {
    pub tokenized_text: String,
    pub token_vault_id: Uuid,
    pub entity_counts: HashMap<String, u32>,
}

#[derive(Debug, Deserialize)]
pub struct DetokenizeRequest {
    pub token_vault_id: Uuid,
    pub text: String,
}

#[derive(Debug, Serialize)]
pub struct DetokenizeResponse {
    pub text: String,
}

/// Extract the class name from a `<Title_Case_N>` placeholder emitted by
/// `apply_redaction`, in SCREAMING_SNAKE form so the `entity_counts`
/// payload matches the class names the caller sent in `entity_labels`.
///
/// `{{Person_1}}` → `PERSON`, `{{Email_Address_2}}` → `EMAIL_ADDRESS`.
/// Returns `None` when the placeholder doesn't match the expected shape
/// (defensive — unknown placeholders just don't bump the counter).
///
/// Mustache-style double-curly placeholders are emitted by
/// `apply_redaction` so they survive every markdown renderer in the chain
/// (remark-directive parses `[X]`, rehype-highlight strips `<X>`; double
/// curlies aren't a token in any common plugin). This parser must stay in
/// lock-step with the format used there.
fn class_from_placeholder(placeholder: &str) -> Option<String> {
    let inner = placeholder.strip_prefix("{{")?.strip_suffix("}}")?;
    // Strip the `_N` counter suffix: rfind the last underscore whose
    // right-hand side is all digits.
    let idx = inner.rfind('_')?;
    let (class_part, index_part) = inner.split_at(idx);
    if class_part.is_empty() {
        return None;
    }
    let index_part = index_part.trim_start_matches('_');
    if index_part.is_empty() || !index_part.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(class_part.to_uppercase())
}

#[cfg(test)]
mod class_from_placeholder_tests {
    use super::class_from_placeholder;

    #[test]
    fn parses_single_word_class() {
        assert_eq!(class_from_placeholder("{{Person_1}}").as_deref(), Some("PERSON"));
    }

    #[test]
    fn parses_multi_word_class() {
        assert_eq!(
            class_from_placeholder("{{Email_Address_2}}").as_deref(),
            Some("EMAIL_ADDRESS")
        );
        assert_eq!(
            class_from_placeholder("{{Passport_Number_10}}").as_deref(),
            Some("PASSPORT_NUMBER")
        );
    }

    #[test]
    fn rejects_malformed() {
        assert!(class_from_placeholder("Person_1").is_none(), "no braces");
        assert!(class_from_placeholder("{{Person}}").is_none(), "no counter");
        assert!(class_from_placeholder("{{Person_abc}}").is_none(), "non-digit counter");
        assert!(class_from_placeholder("{{_1}}").is_none(), "empty class");
        // Older formats that LibreChat's markdown plugins ate must NOT
        // parse as valid — regression guard so reverting apply_redaction
        // here doesn't silently make the dashboard report "No PII detected".
        assert!(class_from_placeholder("<Person_1>").is_none(), "angle bracket form rejected");
        assert!(class_from_placeholder("[Person_1]").is_none(), "square bracket form rejected");
    }
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(get_secure_mode).put(put_secure_mode))
        .route("/tokenize", post(tokenize))
        .route("/detokenize", post(detokenize))
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `GET /v1/secure-mode` — read workspace secure mode config.
async fn get_secure_mode(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
) -> Result<Json<SecureModeResponse>, axum::response::Response> {
    let repo = SecureModeRepository::new(state.db.clone());
    let row = repo
        .get(ctx.workspace_id)
        .await
        .map_err(api_error_response)?;

    Ok(Json(SecureModeResponse {
        workspace_id: row.workspace_id,
        enabled: row.enabled,
        level: row.level,
        block_on_pii_detection: row.block_on_pii_detection,
        block_on_injection_detection: row.block_on_injection_detection,
        redact_pii_in_responses: row.redact_pii_in_responses,
        updated_at: row.updated_at,
    }))
}

/// `PUT /v1/secure-mode` — upsert workspace secure mode config (admin only).
async fn put_secure_mode(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Json(body): Json<PutSecureModeRequest>,
) -> Result<(StatusCode, Json<SecureModeResponse>), axum::response::Response> {
    require_role(&ctx, UserRole::Admin).map_err(api_error_response)?;

    if let Some(ref level) = body.level {
        if !VALID_LEVELS.contains(&level.as_str()) {
            return Err(api_error_response(ApiError::BadRequest(format!(
                "level must be one of: {}",
                VALID_LEVELS.join(", ")
            ))));
        }
    }

    let repo = SecureModeRepository::new(state.db.clone());
    let row = repo
        .upsert(
            ctx.workspace_id,
            body.enabled,
            body.level.as_deref(),
            body.block_on_pii_detection,
            body.block_on_injection_detection,
            body.redact_pii_in_responses,
        )
        .await
        .map_err(api_error_response)?;

    Ok((
        StatusCode::OK,
        Json(SecureModeResponse {
            workspace_id: row.workspace_id,
            enabled: row.enabled,
            level: row.level,
            block_on_pii_detection: row.block_on_pii_detection,
            block_on_injection_detection: row.block_on_injection_detection,
            redact_pii_in_responses: row.redact_pii_in_responses,
            updated_at: row.updated_at,
        }),
    ))
}

/// `POST /v1/secure-mode/tokenize` — redact PII in `text` via the ML sidecar
/// and persist the placeholder→original mapping so the caller can later
/// detokenize. Returns an empty `tokenized_text` + warning if the sidecar is
/// unavailable (circuit open / disabled).
async fn tokenize(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Json(body): Json<TokenizeRequest>,
) -> Result<Json<TokenizeResponse>, axum::response::Response> {
    if body.text.is_empty() {
        return Err(api_error_response(ApiError::BadRequest(
            "text must not be empty".into(),
        )));
    }
    if body.text.len() > 32 * 1024 {
        return Err(api_error_response(ApiError::BadRequest(
            "text exceeds 32 KiB limit".into(),
        )));
    }

    let raw = state.ml_sidecar.detect_if_available(&body.text).await;

    let allowed: Option<Vec<String>> = body
        .entity_labels
        .map(|labels| labels.into_iter().map(|l| l.to_uppercase()).collect());

    let detections: Vec<Detection> = raw
        .into_iter()
        .filter(|d| match &allowed {
            Some(list) => list.iter().any(|l| l.eq_ignore_ascii_case(&d.class)),
            None => true,
        })
        .map(|d| Detection {
            class: d.class,
            confidence: d.confidence,
            span: d.span,
            value: d.value,
        })
        .collect();

    let mut vault = TokenVault::default();
    let mut mapping: HashMap<String, String> = HashMap::new();
    let tokenized_text = apply_redaction(&body.text, &detections, &mut vault, &mut mapping);

    // Count unique placeholders actually emitted (one per distinct
    // (class, value) pair) rather than raw detections. When the case-
    // augmented pass + the Uzbek brand gazetteer both fire on the same
    // span, `apply_redaction` dedups to a single `<Organization_N>`, so
    // the count here should also be 1 — not 2 — to match what the caller
    // sees in `tokenized_text`.
    let mut entity_counts: HashMap<String, u32> = HashMap::new();
    for placeholder in mapping.keys() {
        if let Some(class) = class_from_placeholder(placeholder) {
            *entity_counts.entry(class).or_default() += 1;
        }
    }

    let vault_id = Uuid::new_v4();
    TokenVaultRepository::new(state.db.clone())
        .insert(vault_id, ctx.workspace_id.0, &mapping)
        .await
        .map_err(api_error_response)?;

    Ok(Json(TokenizeResponse {
        tokenized_text,
        token_vault_id: vault_id,
        entity_counts,
    }))
}

/// `POST /v1/secure-mode/detokenize` — reverse tokenize by looking up the
/// vault entry and substituting placeholders back into `text`.
async fn detokenize(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Json(body): Json<DetokenizeRequest>,
) -> Result<Json<DetokenizeResponse>, axum::response::Response> {
    let entry = TokenVaultRepository::new(state.db.clone())
        .get(body.token_vault_id, ctx.workspace_id.0)
        .await
        .map_err(api_error_response)?;

    let mut vault = TokenVault::default();
    for (placeholder, original) in entry.mapping {
        vault.insert(placeholder, original);
    }

    let text = restore_content(&body.text, &vault);
    Ok(Json(DetokenizeResponse { text }))
}
