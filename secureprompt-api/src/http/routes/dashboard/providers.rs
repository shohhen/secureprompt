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
    routing::{get, put},
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

// ── Router ────────────────────────────────────────────────────────────────────

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_providers).post(create_provider))
        .route("/{id}", put(update_provider).delete(delete_provider))
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

    let items = rows
        .into_iter()
        .map(|r| ProviderResponse {
            id: r.id,
            name: r.name,
            provider_type: r.provider_type,
            has_credential: r.encrypted_credential.is_some(),
            last_rotated_at: r.updated_at,
            created_at: r.created_at,
        })
        .collect();

    Ok(Json(items))
}

/// `POST /v1/providers` — create a provider (admin only).
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
        .create_provider(ctx.workspace_id, &body.name, &body.provider_type, encrypted)
        .await
        .map_err(api_error_response)?;

    Ok((
        StatusCode::CREATED,
        Json(ProviderResponse {
            id: record.id,
            name: record.name,
            provider_type: record.provider_type,
            has_credential: record.encrypted_credential.is_some(),
            last_rotated_at: record.updated_at,
            created_at: record.created_at,
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
        )
        .await
        .map_err(api_error_response)?;

    Ok(Json(ProviderResponse {
        id: record.id,
        name: record.name,
        provider_type: record.provider_type,
        has_credential: record.encrypted_credential.is_some(),
        last_rotated_at: record.updated_at,
        created_at: record.created_at,
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
