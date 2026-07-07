//! Phase 5 / Plan 05-04 — `/v1/providers` provider credential management.
//!
//! Routes:
//!   GET    /v1/providers        — list providers (any role)
//!   POST   /v1/providers        — create provider (admin only)
//!   PUT    /v1/providers/:id    — update/rotate credential (admin only)
//!   DELETE /v1/providers/:id    — delete provider (admin only)
//!
//! Security:
//!   * `ProviderResponse` NEVER includes ciphertext — only `has_credential: bool`
//!     + `last_rotated_at`.
//!   * Credentials are encrypted with AES-256-GCM using `AppState.provider_key`
//!     before storage. The nonce is prepended: `base64url(nonce || ciphertext)`.
//!   * `SECUREPROMPT_PROVIDER_KEY` is DISTINCT from `SECUREPROMPT_JWT_SECRET`
//!     (enforced in `JwtConfig::from_env`).

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    routing::{get, post, put},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use secureprompt_common::errors::ApiError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    app_state::AppState,
    db::provider_repo::ProviderRepository,
    http::{
        api_error_response,
        middleware::jwt_auth::{JwtAuthContext, UserRole},
        routes::dashboard::role::require_role,
    },
};

// ── DTOs ──────────────────────────────────────────────────────────────────────

/// Response for all provider endpoints — NEVER includes ciphertext.
#[derive(Debug, Serialize)]
pub struct ProviderResponse {
    pub id: Uuid,
    pub name: String,
    pub provider_type: String,
    /// Whether an encrypted credential is stored.
    pub has_credential: bool,
    /// When the credential was last written (`updated_at`).
    pub last_rotated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    /// Models registered for this provider. Used by LibreChat's discovery
    /// client to populate the model picker; omitted (empty array) when
    /// no models are registered yet — caller falls back to per-type
    /// defaults.
    #[serde(default)]
    pub models: Vec<ModelSummary>,
}

#[derive(Debug, Serialize)]
pub struct ModelSummary {
    pub id: Uuid,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct AddModelRequest {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateProviderRequest {
    pub name: String,
    pub provider_type: String,
    /// Optional plaintext credential (e.g. "sk-..."). Encrypted before storage.
    pub credential: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateProviderRequest {
    pub name: Option<String>,
    pub provider_type: Option<String>,
    /// New plaintext credential. `None` = leave existing unchanged.
    pub credential: Option<String>,
}

/// `POST /v1/providers/test-connection` body — tests credentials BEFORE
/// they're persisted. The dashboard's "Test Connection" button posts the
/// in-progress form values here so the user gets feedback before saving.
#[derive(Debug, Deserialize)]
pub struct TestConnectionRequest {
    pub provider_type: String,
    /// Plaintext credential to test. Never logged, never persisted by
    /// this handler. Only sent over the wire to the upstream provider's
    /// list-models endpoint.
    pub credential: String,
    /// Optional override for the provider's API base URL. Defaults to
    /// the provider_type's well-known endpoint when absent.
    #[serde(default)]
    pub base_url: Option<String>,
}

/// `POST /v1/providers/{id}/models/sync` response — what the dashboard
/// uses to render the "synced N models" toast and refresh the model panel.
#[derive(Debug, Serialize)]
pub struct SyncModelsResponse {
    pub added: Vec<String>,
    pub kept: Vec<String>,
    pub total: u32,
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_providers).post(create_provider))
        .route("/test-connection", post(test_connection_unsaved))
        .route("/{id}", put(update_provider).delete(delete_provider))
        .route("/{id}/test-connection", post(test_connection_stored))
        .route("/{id}/models", get(list_provider_models).post(add_provider_model))
        .route("/{id}/models/sync", post(sync_provider_models))
        .route("/{id}/models/{name}", axum::routing::delete(delete_provider_model))
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `GET /v1/providers` — list providers (any role).
async fn list_providers(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
) -> Result<Json<Vec<ProviderResponse>>, axum::response::Response> {
    let repo = ProviderRepository::new(state.db.clone());
    let rows = repo
        .list_providers(ctx.workspace_id)
        .await
        .map_err(api_error_response)?;

    // Eager-load model rows for each provider so the LibreChat discovery
    // client gets the full picture in one HTTP call. The `models` table is
    // small per-workspace (rarely more than a few dozen rows total) — N+1
    // here is acceptable, and the alternative (single JOIN) would require
    // a different shape that complicates per-provider permission checks.
    let mut items = Vec::with_capacity(rows.len());
    for r in rows {
        let models = repo
            .list_models_for_provider(ctx.workspace_id, r.id)
            .await
            .map_err(api_error_response)?
            .into_iter()
            .map(|m| ModelSummary { id: m.id, name: m.name })
            .collect();
        items.push(ProviderResponse {
            id: r.id,
            name: r.name,
            provider_type: r.provider_type,
            has_credential: r.encrypted_credential.is_some(),
            last_rotated_at: r.updated_at,
            created_at: r.created_at,
            models,
        });
    }

    Ok(Json(items))
}

/// `POST /v1/providers` — create a provider (admin only).
///
/// When a credential is supplied, immediately probes the upstream
/// `/models` endpoint and bulk-inserts every chat-capable model into
/// `provider_models`. The user asked for "register all models from my
/// API key" — this is the path that satisfies that. Failure is
/// non-fatal: the provider is created, the admin can retry via the
/// dashboard "Sync from upstream" button.
async fn create_provider(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Json(body): Json<CreateProviderRequest>,
) -> Result<(StatusCode, Json<ProviderResponse>), axum::response::Response> {
    require_role(&ctx, UserRole::Admin).map_err(api_error_response)?;

    let encrypted = encrypt_credential(body.credential.as_deref(), &state)
        .await
        .map_err(api_error_response)?;

    let repo = ProviderRepository::new(state.db.clone());
    let record = repo
        .create_provider(
            ctx.workspace_id,
            &body.name,
            &body.provider_type,
            encrypted,
            serde_json::json!({}),
        )
        .await
        .map_err(api_error_response)?;

    if let Some(plaintext) = body.credential.as_deref() {
        auto_sync_models(
            &state,
            &repo,
            ctx.workspace_id,
            record.id,
            &record.provider_type,
            plaintext,
        )
        .await;
    }

    let models = repo
        .list_models_for_provider(ctx.workspace_id, record.id)
        .await
        .map_err(api_error_response)?
        .into_iter()
        .map(|m| ModelSummary { id: m.id, name: m.name })
        .collect();

    Ok((
        StatusCode::CREATED,
        Json(ProviderResponse {
            id: record.id,
            name: record.name,
            provider_type: record.provider_type,
            has_credential: record.encrypted_credential.is_some(),
            last_rotated_at: record.updated_at,
            created_at: record.created_at,
            models,
        }),
    ))
}

/// `PUT /v1/providers/:id` — update/rotate credential (admin only).
async fn update_provider(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Path(provider_id): Path<Uuid>,
    Json(body): Json<UpdateProviderRequest>,
) -> Result<Json<ProviderResponse>, axum::response::Response> {
    require_role(&ctx, UserRole::Admin).map_err(api_error_response)?;

    // Encrypt new credential if provided; `None` = leave existing unchanged.
    let encrypted_update: Option<Option<String>> = if body.credential.is_some() {
        Some(
            encrypt_credential(body.credential.as_deref(), &state)
                .await
                .map_err(api_error_response)?,
        )
    } else {
        None
    };

    let repo = ProviderRepository::new(state.db.clone());
    let record = repo
        .update_provider(
            ctx.workspace_id,
            provider_id,
            body.name.as_deref(),
            body.provider_type.as_deref(),
            encrypted_update,
            None,
        )
        .await
        .map_err(api_error_response)?;

    // Credential rotation → re-sync upstream models. The new key may
    // unlock different model entitlements; an updated key for the same
    // upstream merges idempotently (the inserts are upserts).
    if let Some(plaintext) = body.credential.as_deref() {
        auto_sync_models(
            &state,
            &repo,
            ctx.workspace_id,
            record.id,
            &record.provider_type,
            plaintext,
        )
        .await;
    }

    let models = repo
        .list_models_for_provider(ctx.workspace_id, record.id)
        .await
        .map_err(api_error_response)?
        .into_iter()
        .map(|m| ModelSummary { id: m.id, name: m.name })
        .collect();
    Ok(Json(ProviderResponse {
        id: record.id,
        name: record.name,
        provider_type: record.provider_type,
        has_credential: record.encrypted_credential.is_some(),
        last_rotated_at: record.updated_at,
        created_at: record.created_at,
        models,
    }))
}

/// `DELETE /v1/providers/:id` — delete a provider (admin only).
async fn delete_provider(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Path(provider_id): Path<Uuid>,
) -> Result<StatusCode, axum::response::Response> {
    require_role(&ctx, UserRole::Admin).map_err(api_error_response)?;

    let repo = ProviderRepository::new(state.db.clone());
    repo.delete_provider(ctx.workspace_id, provider_id)
        .await
        .map_err(api_error_response)?;

    Ok(StatusCode::NO_CONTENT)
}

/// `GET /v1/providers/:id/models` — list models registered for one provider.
/// Any role; the dashboard renders this list when the user opens the provider's
/// model panel and the LibreChat discovery client also reads it via the
/// nested `models` field on `GET /v1/providers`.
async fn list_provider_models(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Path(provider_id): Path<Uuid>,
) -> Result<Json<Vec<ModelSummary>>, axum::response::Response> {
    let repo = ProviderRepository::new(state.db.clone());
    let rows = repo
        .list_models_for_provider(ctx.workspace_id, provider_id)
        .await
        .map_err(api_error_response)?;
    let items = rows
        .into_iter()
        .map(|m| ModelSummary { id: m.id, name: m.name })
        .collect();
    Ok(Json(items))
}

/// `POST /v1/providers/:id/models` body `{name}` — admin-only. Idempotent —
/// duplicate (provider_id, name) returns the existing row instead of erroring.
async fn add_provider_model(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Path(provider_id): Path<Uuid>,
    Json(body): Json<AddModelRequest>,
) -> Result<(StatusCode, Json<ModelSummary>), axum::response::Response> {
    require_role(&ctx, UserRole::Admin).map_err(api_error_response)?;
    let trimmed = body.name.trim();
    if trimmed.is_empty() {
        return Err(api_error_response(ApiError::BadRequest(
            "model name must not be empty".into(),
        )));
    }
    if trimmed.len() > 200 {
        return Err(api_error_response(ApiError::BadRequest(
            "model name too long (>200 chars)".into(),
        )));
    }
    let repo = ProviderRepository::new(state.db.clone());
    let row = repo
        .create_model(ctx.workspace_id, provider_id, trimmed)
        .await
        .map_err(api_error_response)?;
    Ok((
        StatusCode::CREATED,
        Json(ModelSummary { id: row.id, name: row.name }),
    ))
}

/// `DELETE /v1/providers/:id/models/:name` — admin-only.
async fn delete_provider_model(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Path((provider_id, name)): Path<(Uuid, String)>,
) -> Result<StatusCode, axum::response::Response> {
    require_role(&ctx, UserRole::Admin).map_err(api_error_response)?;
    let repo = ProviderRepository::new(state.db.clone());
    repo.delete_model(ctx.workspace_id, provider_id, &name)
        .await
        .map_err(api_error_response)?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/providers/test-connection` — admin-only. Tests a credential
/// BEFORE it's persisted. Body: `{provider_type, credential, base_url?}`.
/// Returns `TestResult { success, model_count?, error? }` so the dashboard
/// can show "Connected (N models)" or "Failed: <reason>" inline before the
/// admin clicks Save.
async fn test_connection_unsaved(
    State(_state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Json(body): Json<TestConnectionRequest>,
) -> Result<Json<crate::providers::credential_test::TestResult>, axum::response::Response> {
    require_role(&ctx, UserRole::Admin).map_err(api_error_response)?;
    let result = crate::providers::credential_test::test_connection(
        &body.provider_type,
        &body.credential,
        body.base_url.as_deref(),
    )
    .await;
    Ok(Json(result))
}

/// `POST /v1/providers/{id}/test-connection` — admin-only. Tests a
/// credential that's already stored — useful for verifying rotation /
/// expiration without exposing the plaintext to the dashboard. Decrypts
/// the stored ciphertext via KMS, probes the upstream, returns the same
/// `TestResult` shape as the unsaved variant.
async fn test_connection_stored(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Path(provider_id): Path<Uuid>,
) -> Result<Json<crate::providers::credential_test::TestResult>, axum::response::Response> {
    require_role(&ctx, UserRole::Admin).map_err(api_error_response)?;
    let repo = ProviderRepository::new(state.db.clone());
    let providers = repo
        .list_providers(ctx.workspace_id)
        .await
        .map_err(api_error_response)?;
    let Some(target) = providers.into_iter().find(|p| p.id == provider_id) else {
        return Err(api_error_response(ApiError::NotFound(format!(
            "provider {provider_id} not found"
        ))));
    };
    let Some(stored_credential) = target.encrypted_credential.as_deref() else {
        return Err(api_error_response(ApiError::BadRequest(
            "provider has no stored credential to test".into(),
        )));
    };
    let plaintext = decrypt_stored_credential(stored_credential, &state)
        .await
        .map_err(api_error_response)?;
    let result = crate::providers::credential_test::test_connection(
        &target.provider_type,
        &plaintext,
        None,
    )
    .await;
    Ok(Json(result))
}

/// `POST /v1/providers/{id}/models/sync` — admin-only.
///
/// Hits the upstream provider's `/models` endpoint with the stored
/// (decrypted) credential, filters to chat-capable model ids, and
/// bulk-inserts each one into `provider_models`. Idempotent: existing
/// rows are kept (so per-row delete decisions the admin made earlier
/// stick); only new ids are added. Returns the diff.
async fn sync_provider_models(
    State(state): State<AppState>,
    Extension(ctx): Extension<JwtAuthContext>,
    Path(provider_id): Path<Uuid>,
) -> Result<Json<SyncModelsResponse>, axum::response::Response> {
    require_role(&ctx, UserRole::Admin).map_err(api_error_response)?;
    let repo = ProviderRepository::new(state.db.clone());
    let providers = repo
        .list_providers(ctx.workspace_id)
        .await
        .map_err(api_error_response)?;
    let Some(target) = providers.into_iter().find(|p| p.id == provider_id) else {
        return Err(api_error_response(ApiError::NotFound(format!(
            "provider {provider_id} not found"
        ))));
    };
    let Some(stored_credential) = target.encrypted_credential.as_deref() else {
        return Err(api_error_response(ApiError::BadRequest(
            "provider has no stored credential to sync".into(),
        )));
    };
    let plaintext = decrypt_stored_credential(stored_credential, &state)
        .await
        .map_err(api_error_response)?;

    let upstream_ids = crate::providers::credential_test::list_upstream_models(
        &target.provider_type,
        &plaintext,
        None,
    )
    .await
    .map_err(|e| {
        api_error_response(ApiError::BadRequest(format!(
            "upstream model sync failed: {e}"
        )))
    })?;

    let result = persist_synced_models(&repo, ctx.workspace_id, target.id, &upstream_ids)
        .await
        .map_err(api_error_response)?;
    Ok(Json(result))
}

/// Persist a fetched upstream model list into `provider_models`. Idempotent
/// — `create_model` upserts. The diff (`added` / `kept`) is returned to the
/// caller so the dashboard can render what changed.
async fn persist_synced_models(
    repo: &ProviderRepository,
    workspace_id: secureprompt_common::types::WorkspaceId,
    provider_id: Uuid,
    upstream_ids: &[String],
) -> Result<SyncModelsResponse, ApiError> {
    let existing: std::collections::HashSet<String> = repo
        .list_models_for_provider(workspace_id, provider_id)
        .await?
        .into_iter()
        .map(|m| m.name)
        .collect();

    let mut added = Vec::new();
    let mut kept = Vec::new();
    for id in upstream_ids {
        let trimmed = id.trim();
        if trimmed.is_empty() || trimmed.len() > 200 {
            continue;
        }
        if existing.contains(trimmed) {
            kept.push(trimmed.to_owned());
            continue;
        }
        match repo.create_model(workspace_id, provider_id, trimmed).await {
            Ok(_) => added.push(trimmed.to_owned()),
            Err(e) => {
                tracing::warn!(model = trimmed, error = %e, "model insert failed during sync");
            }
        }
    }
    let total = (added.len() + kept.len()) as u32;
    Ok(SyncModelsResponse { added, kept, total })
}

/// Best-effort upstream model sync invoked after provider create / credential
/// rotation. Failures are logged at warn level — the caller should still
/// succeed the user-facing operation. The dashboard's "Sync from upstream"
/// button is the explicit retry path.
async fn auto_sync_models(
    _state: &AppState,
    repo: &ProviderRepository,
    workspace_id: secureprompt_common::types::WorkspaceId,
    provider_id: Uuid,
    provider_type: &str,
    credential: &str,
) {
    let upstream_ids = match crate::providers::credential_test::list_upstream_models(
        provider_type,
        credential,
        None,
    )
    .await
    {
        Ok(ids) => ids,
        Err(e) => {
            tracing::warn!(
                provider_id = %provider_id,
                provider_type,
                error = %e,
                "auto model sync skipped: upstream fetch failed"
            );
            return;
        }
    };
    match persist_synced_models(repo, workspace_id, provider_id, &upstream_ids).await {
        Ok(diff) => {
            tracing::info!(
                provider_id = %provider_id,
                added = diff.added.len(),
                kept = diff.kept.len(),
                "auto model sync complete"
            );
        }
        Err(e) => {
            tracing::warn!(provider_id = %provider_id, error = %e, "auto model sync persist failed");
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Encrypt a plaintext credential via `state.kms`. Returns `None` when `plaintext` is `None`.
/// Output is URL-safe base64 of the raw ciphertext bytes returned by the KMS backend.
async fn encrypt_credential(
    plaintext: Option<&str>,
    state: &AppState,
) -> Result<Option<String>, ApiError> {
    let Some(text) = plaintext else {
        return Ok(None);
    };
    let ciphertext = state
        .kms
        .encrypt(text.as_bytes())
        .await
        .map_err(|e| ApiError::Internal(format!("credential encryption failed: {e}")))?;
    Ok(Some(URL_SAFE_NO_PAD.encode(&ciphertext)))
}

/// Decrypt a stored credential string via `state.kms`.
/// Input is URL-safe base64 of the raw ciphertext bytes stored in the database.
///
/// # Errors
/// Returns `ApiError::Internal` when the ciphertext is invalid base64 or decryption fails.
#[allow(dead_code)]
pub async fn decrypt_stored_credential(
    stored: &str,
    state: &AppState,
) -> Result<String, ApiError> {
    let raw = URL_SAFE_NO_PAD
        .decode(stored)
        .map_err(|e| ApiError::Internal(format!("credential decode failed: {e}")))?;
    let plaintext = state
        .kms
        .decrypt(&raw)
        .await
        .map_err(|e| ApiError::Internal(format!("credential decryption failed: {e}")))?;
    String::from_utf8(plaintext)
        .map_err(|e| ApiError::Internal(format!("credential not valid UTF-8: {e}")))
}
