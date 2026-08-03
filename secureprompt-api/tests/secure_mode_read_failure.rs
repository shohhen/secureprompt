//! MR5 C1 / MR6 F3 — what the request path does when the secure-mode row
//! cannot be read.
//!
//! `workspace_secure_mode` IS the redaction control: `enabled` gates the
//! injection check, `block_on_pii_detection`, `redact_pii_in_responses` and
//! the `strict`/`permissive` levels. `pipeline::service` is the only consumer
//! of [`SecureModeRepository::get`], and it used to resolve ANY error from
//! that read — a transient `ApiError::Database`, or the
//! `ApiError::Internal(SCOPE_NOT_ARMED)` that migration 031's read-back
//! exists to raise — to `SecureModeRow::default()`, whose `enabled` is
//! `false`. The security outcome was identical to the silent zero the
//! read-back was added to eliminate: redaction off, injection gate skipped,
//! HTTP 200, one `warn!` line.
//!
//! These two tests are a pair and only mean something together:
//!
//! * the CONTROL proves the workspace's secure-mode row is what produces the
//!   403 — without it, "the failure case does not return 200" could be true
//!   because nothing ever reached the pipeline;
//! * the FAILURE case renames the table out from under the running gateway,
//!   which is the most benign error shape there is (a plain
//!   `ApiError::Database` from the SELECT, not even the scope error), and
//!   asserts the gateway refuses rather than degrading to redaction-off.
//!
//! Renaming rather than mutating production code is deliberate: the error is
//! produced by Postgres on the real query, so this test cannot be satisfied
//! by a test-only hook that a refactor deletes.
//!
//! All fixture PII is synthetic.

mod support;

use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use serde_json::json;
use sqlx::PgPool;
use std::net::SocketAddr;
use tower::ServiceExt;
use uuid::Uuid;

const API_KEY: &str = "sp_secure_mode_read_failure";
/// Synthetic address; matched by the deterministic Rust `email` matcher, so
/// the detection does not depend on the ML sidecar being reachable.
const SYNTHETIC_EMAIL: &str = "anvar.karimov@example.com";

async fn seed(pool: &PgPool, workspace_id: Uuid) -> sqlx::Result<()> {
    support::seed_workspace(pool, workspace_id, API_KEY).await?;
    support::seed_provider_and_model(
        pool,
        workspace_id,
        Uuid::new_v4(),
        "anthropic-primary",
        // `anthropic` is an echo stub in this workspace, so a request that
        // gets all the way through returns 200 with the forwarded prompt in
        // the body — which is what makes "403 vs 200" and "the raw address is
        // absent from the body" both real signals.
        "anthropic",
        None,
        "claude-3-haiku",
    )
    .await?;

    // The sidecar is unconfigured in these tests (the floor registry supplies
    // the detection). Without this the deployment default `block` fails the
    // request at the NER coverage gate, 503, before the secure-mode read is
    // ever reached — and the failure case would pass for the wrong reason.
    sqlx::query(
        "INSERT INTO workspace_sidecar_policy (workspace_id, sidecar_unavailable, updated_at)
         VALUES ($1, 'degrade_with_alert', NOW())",
    )
    .bind(workspace_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Secure mode ON at `standard` with `block_on_pii_detection`, i.e. the
/// workspace has explicitly asked for a detection to stop the request.
async fn arm_secure_mode(pool: &PgPool, workspace_id: Uuid) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO workspace_secure_mode
            (workspace_id, enabled, level, block_on_pii_detection,
             block_on_injection_detection, redact_pii_in_responses, updated_at)
         VALUES ($1, true, 'standard', true, false, true, NOW())",
    )
    .bind(workspace_id)
    .execute(pool)
    .await
    .map(|_| ())
}

fn chat_request(api_key: &str) -> Request<axum::body::Body> {
    let mut request = support::authorized_request(
        Request::builder()
            .method(Method::POST)
            .uri("/v1/chat/completions"),
        api_key,
        json!({
            "model": "claude-3-haiku",
            "stream": false,
            "messages": [{
                "role": "user",
                "content": format!("Forward this to the vendor: {SYNTHETIC_EMAIL}"),
            }],
        }),
    );
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 50_000))));
    request
}

// ── POSITIVE CONTROL ──────────────────────────────────────────────────────

/// With the row readable, secure mode does its job: the detection blocks the
/// request. Every assertion in the failure test below is worthless without
/// this — it proves the 403 comes from `workspace_secure_mode` and not from
/// some unrelated gate.
#[sqlx::test]
async fn secure_mode_blocks_the_request_when_its_row_is_readable(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;
    arm_secure_mode(&pool, workspace_id).await?;

    let app = support::router_with(pool.clone(), "", "default");
    let response = app
        .oneshot(chat_request(API_KEY))
        .await
        .expect("router should respond");

    let status = response.status();
    let body = support::response_text(response).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "secure mode with block_on_pii_detection must deny a request carrying \
         a detection; body={body}"
    );
    Ok(())
}

// ── THE DEFECT ────────────────────────────────────────────────────────────

/// The secure-mode read fails. The gateway must NOT answer 200 having
/// silently switched redaction off.
///
/// Renaming the table makes the SELECT inside `SecureModeRepository::get`
/// fail with `ApiError::Database`; every other read on the request path
/// (auth, providers, models, policy rules, sidecar policy, raw capture) is
/// untouched, so this isolates exactly the one read whose failure used to be
/// swallowed.
#[sqlx::test]
async fn an_unreadable_secure_mode_row_refuses_the_request_instead_of_disabling_redaction(
    pool: PgPool,
) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;
    arm_secure_mode(&pool, workspace_id).await?;

    sqlx::query("ALTER TABLE workspace_secure_mode RENAME TO workspace_secure_mode_unreadable")
        .execute(&pool)
        .await?;

    let app = support::router_with(pool.clone(), "", "default");
    let response = app
        .oneshot(chat_request(API_KEY))
        .await
        .expect("router should respond");

    let status = response.status();
    let body = support::response_text(response).await;

    assert_ne!(
        status,
        StatusCode::OK,
        "a failed secure-mode read silently disabled the redaction control and \
         the request succeeded anyway; body={body}"
    );
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "the redaction control could not be resolved, so the gateway must \
         refuse with 503 (retryable) rather than serve unprotected; body={body}"
    );
    assert!(
        !body.contains(SYNTHETIC_EMAIL),
        "the raw address reached the provider and came back in the response — \
         this is the leak the fallback caused; body={body}"
    );
    Ok(())
}
