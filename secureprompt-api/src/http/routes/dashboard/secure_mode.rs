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
    db::{
        secure_mode_repo::SecureModeRepository,
        sidecar_policy_repo::{SidecarPolicyRepository, SidecarUnavailablePolicy},
        token_vault_repo::TokenVaultRepository,
    },
    detection::{detect_content, merge::merge_detections},
    http::{
        api_error_response,
        middleware::jwt_auth::{JwtAuthContext, UserRole},
        routes::dashboard::role::require_role,
    },
    ml_sidecar::types::MlDetection,
    vault::{apply_redaction, restore_content},
};

// ── DTOs ──────────────────────────────────────────────────────────────────────

const VALID_LEVELS: &[&str] = &["permissive", "standard", "strict"];
/// WS2-3 — accepted values for `sidecar_unavailable`. Kept next to
/// `VALID_LEVELS` because both are validated by the same PUT handler.
const VALID_SIDECAR_POLICIES: &[&str] = &["block", "degrade_with_alert"];

#[derive(Debug, Serialize)]
pub struct SecureModeResponse {
    pub workspace_id: Uuid,
    pub enabled: bool,
    pub level: String,
    pub block_on_pii_detection: bool,
    pub block_on_injection_detection: bool,
    pub redact_pii_in_responses: bool,
    /// WS2-3 — `block` (default) or `degrade_with_alert`. Stored in its own
    /// table (`workspace_sidecar_policy`, migration 018) but surfaced here
    /// because it is part of the same per-workspace security posture an
    /// admin configures on one screen.
    pub sidecar_unavailable: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct PutSecureModeRequest {
    pub enabled: Option<bool>,
    pub level: Option<String>,
    pub block_on_pii_detection: Option<bool>,
    pub block_on_injection_detection: Option<bool>,
    pub redact_pii_in_responses: Option<bool>,
    pub sidecar_unavailable: Option<String>,
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
    // WS2-3 — returns `block` when the workspace has no row, matching the
    // fail-closed default the pipeline applies.
    let sidecar_unavailable = SidecarPolicyRepository::new(state.db.clone())
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
        sidecar_unavailable: sidecar_unavailable.as_str().to_owned(),
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

    if let Some(ref value) = body.sidecar_unavailable {
        if !VALID_SIDECAR_POLICIES.contains(&value.as_str()) {
            return Err(api_error_response(ApiError::BadRequest(format!(
                "sidecar_unavailable must be one of: {}",
                VALID_SIDECAR_POLICIES.join(", ")
            ))));
        }
    }

    let sidecar_repo = SidecarPolicyRepository::new(state.db.clone());
    let sidecar_unavailable = match body.sidecar_unavailable.as_deref() {
        Some(value) => sidecar_repo
            .upsert(ctx.workspace_id, SidecarUnavailablePolicy::from_db(value))
            .await
            .map_err(api_error_response)?,
        None => sidecar_repo
            .get(ctx.workspace_id)
            .await
            .map_err(api_error_response)?,
    };

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
            sidecar_unavailable: sidecar_unavailable.as_str().to_owned(),
            updated_at: row.updated_at,
        }),
    ))
}

/// Assemble the detection set backing `/tokenize`, then apply the caller's
/// optional `entity_labels` filter.
///
/// The deterministic regex floor runs first and unconditionally. This
/// endpoint used to source detections from the ML sidecar alone, so a
/// disabled sidecar, an unreachable one, or an open circuit breaker all
/// produced the same result: an empty detection set, nothing for
/// `apply_redaction` to replace, and a cheerful "no PII found" response
/// carrying the caller's PII back verbatim. Every other detection path
/// (chat completions, `/v1/redact`, `/v1/policy-check`) already merged the
/// regex floor in; this one was the outlier.
fn tokenize_detections(
    text: &str,
    ml: Vec<MlDetection>,
    allowed: Option<&[String]>,
) -> Vec<Detection> {
    merge_detections(detect_content(text), ml)
        .into_iter()
        .filter(|detection| {
            allowed.is_none_or(|list| {
                list.iter()
                    .any(|label| label.eq_ignore_ascii_case(&detection.class))
            })
        })
        .collect()
}

#[cfg(test)]
mod tokenize_detection_tests {
    use super::tokenize_detections;
    use crate::ml_sidecar::types::MlDetection;
    use secureprompt_common::types::TokenVault;
    use std::collections::HashMap;

    fn ml(class: &str, start: usize, end: usize, value: &str) -> MlDetection {
        MlDetection {
            class: class.to_owned(),
            confidence: 0.9,
            span: Some((start, end)),
            value: value.to_owned(),
            compliance_categories: vec![],
        }
    }

    /// The leak this guards: `/tokenize` used to build its detection set from
    /// the ML sidecar ALONE. With the sidecar disabled, unreachable, or its
    /// circuit breaker open, `detect_if_available` returns an empty vector,
    /// `apply_redaction` has nothing to replace, and the endpoint answers
    /// "no PII found" while echoing the caller's PII back verbatim.
    #[test]
    fn regex_floor_applies_when_sidecar_returns_nothing() {
        let detections = tokenize_detections("PINFL 50101901234567", vec![], None);
        assert!(
            detections
                .iter()
                .any(|detection| detection.class == "PINFL"),
            "expected the deterministic floor to find the PINFL with no ML \
             detections, got: {detections:?}"
        );
    }

    #[test]
    fn regex_floor_and_ml_detections_are_merged() {
        let text = "Ali Aliev, PINFL 50101901234567";
        let detections = tokenize_detections(text, vec![ml("PERSON", 0, 9, "Ali Aliev")], None);
        let classes: Vec<_> = detections
            .iter()
            .map(|detection| detection.class.as_str())
            .collect();
        assert!(classes.contains(&"PERSON"), "got: {classes:?}");
        assert!(classes.contains(&"PINFL"), "got: {classes:?}");
    }

    /// Round-1 review: adding the regex floor to this endpoint also made it
    /// inherit `merge_detections`' "regex wins on overlap" rule.
    ///
    /// When a short regex span sits INSIDE a longer ML span, dropping the ML
    /// detection redacts only the inner fragment and forwards the rest of the
    /// entity — a partial leak that is worse than either layer alone, and one
    /// that only appeared once this endpoint gained a regex layer.
    #[test]
    fn ml_span_containing_a_regex_span_is_fully_redacted() {
        let text = "Manzil: Toshkent shahri, AA1234567 blok, 5-uy";
        let address_start = text.find("Toshkent").expect("fixture");
        let address = &text[address_start..];

        let detections = tokenize_detections(
            text,
            vec![ml("ADDRESS", address_start, text.len(), address)],
            None,
        );

        let mut vault = TokenVault::default();
        let mut mapping: HashMap<String, String> = HashMap::new();
        let redacted = super::apply_redaction(text, &detections, &mut vault, &mut mapping);

        assert!(
            !redacted.contains("Toshkent"),
            "the ML address was dropped because a regex span sat inside it, \
             so only the inner fragment got redacted: {redacted:?}"
        );
        assert!(
            !redacted.contains("AA1234567"),
            "passport leaked: {redacted:?}"
        );
    }

    /// Round-2 review: the end-to-end form of the containment regression.
    /// An ML span that covers one regex detection but only PART of another
    /// must not leave the tail of the second one in the output.
    #[test]
    fn no_byte_of_a_regex_identifier_survives_a_partly_covering_ml_span() {
        let text = "Manzil: Toshkent, AA1234567 blok, STIR 300111222 raqami";
        let address_start = text.find("Toshkent").expect("fixture");
        // Deliberately ends mid-STIR: covers the passport in full and the
        // STIR only partly.
        let address_end = text.find("300111222").expect("fixture") + 4;

        let detections = tokenize_detections(
            text,
            vec![ml(
                "ADDRESS",
                address_start,
                address_end,
                &text[address_start..address_end],
            )],
            None,
        );

        let mut vault = TokenVault::default();
        let mut mapping: HashMap<String, String> = HashMap::new();
        let redacted = super::apply_redaction(text, &detections, &mut vault, &mut mapping);

        assert!(
            !redacted.contains("300111222"),
            "STIR leaked whole: {redacted:?}"
        );
        for tail in ["1222", "222", "22"] {
            assert!(
                !redacted.contains(tail),
                "a tail fragment of the STIR was forwarded: {redacted:?}"
            );
        }
        assert!(
            !redacted.contains("AA1234567"),
            "passport leaked: {redacted:?}"
        );
    }

    /// Round-3 review: the tokenize → detokenize round-trip must survive
    /// the overlapping-window fix. `detokenize` restores from the stored
    /// mapping, so a placeholder whose recorded original does not match the
    /// bytes it replaced would corrupt the caller's text.
    #[test]
    fn tokenize_detokenize_round_trips_over_overlapping_windows() {
        let text = "ИНН 12345 6789 01234 (ИНН), karta 8600 1234 5678 9012";
        let detections = tokenize_detections(text, vec![], None);

        let mut vault = TokenVault::default();
        let mut mapping: HashMap<String, String> = HashMap::new();
        let tokenized = super::apply_redaction(text, &detections, &mut vault, &mut mapping);

        // Placeholder counters contain digits; strip the `{{...}}` tokens
        // before checking that no identifier digit survived.
        let mut visible = tokenized.clone();
        while let (Some(open), Some(close)) = (visible.find("{{"), visible.find("}}")) {
            if close < open {
                break;
            }
            visible.replace_range(open..close + 2, "");
        }
        assert!(
            !visible.chars().any(|character| character.is_ascii_digit()),
            "a digit survived tokenize: {tokenized:?}"
        );

        // Exactly what the detokenize handler does: rebuild a vault from the
        // persisted mapping, then restore.
        let mut restored_vault = TokenVault::default();
        for (placeholder, original) in mapping {
            restored_vault.insert(placeholder, original);
        }
        assert_eq!(
            super::restore_content(&tokenized, &restored_vault),
            text,
            "detokenize did not reproduce the original text"
        );
    }

    #[test]
    fn entity_label_filter_still_applies_to_floor_detections() {
        let text = "PINFL 50101901234567 va STIR 300111222";
        let allowed = vec!["STIR".to_owned()];
        let detections = tokenize_detections(text, vec![], Some(&allowed));
        assert!(
            detections.iter().all(|detection| detection.class == "STIR"),
            "filter must apply to regex detections too, got: {detections:?}"
        );
        assert_eq!(detections.len(), 1, "got: {detections:?}");
    }
}

/// `POST /v1/secure-mode/tokenize` — redact PII in `text` using the
/// deterministic regex floor merged with the ML sidecar, and persist the
/// placeholder→original mapping so the caller can later detokenize.
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

    let raw = state.ml_sidecar.detect_if_available(&body.text).await.detections;

    let allowed: Option<Vec<String>> = body
        .entity_labels
        .map(|labels| labels.into_iter().map(|l| l.to_uppercase()).collect());

    let detections = tokenize_detections(&body.text, raw, allowed.as_deref());

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
