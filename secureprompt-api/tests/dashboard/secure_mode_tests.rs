//! TDD — secure mode: GET /v1/secure-mode, PUT /v1/secure-mode.
//!
//! RED phase: these tests fail until the route + repo + migration exist.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use secureprompt_api::{
    app_state::AppState, http::build_router, ml_sidecar::MlSidecarClient,
};
use secureprompt_api::http::middleware::jwt_auth::Claims;
use secureprompt_common::config::{
    AppConfig, ClickhouseConfig, DatabaseConfig, JwtConfig, LicenseConfig, RedisConfig,
    ServerConfig, TelemetryConfig,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

const TEST_JWT_SECRET: &str = "secure-mode-test-jwt-secret-32!!";

fn test_config() -> AppConfig {
    AppConfig {
        database: DatabaseConfig {
            url: "postgres://unused".into(),
            max_connections: 1,
        },
        redis: RedisConfig {
            url: std::env::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://localhost:6379".into()),
            max_connections: 4,
        },
        telemetry: TelemetryConfig {
            otel_enabled: false,
            prometheus_enabled: false,
            log_level: "error".into(),
        },
        server: ServerConfig {
            host: "127.0.0.1".into(),
            port: 0,
        },
        clickhouse: ClickhouseConfig {
            url: "http://localhost:8123".into(),
            database: "sp_analytics".into(),
        },
        jwt: JwtConfig {
            secret: TEST_JWT_SECRET.into(),
            access_ttl_secs: 900,
            refresh_ttl_secs: 3600,
        },
        public_signup_enabled: false,
        chat_debug_mode: false,
        redact_when_no_rules: false,
        sidecar_unavailable_default: "block".to_owned(),
        license: LicenseConfig::default(),
    }
}

fn build_app(pool: PgPool) -> axum::Router {
    let ml = Arc::new(MlSidecarClient::new(String::new(), 100));
    build_router(AppState::new(
        pool,
        test_config(),
        ml,
        Arc::new(secureprompt_api::license::LicenseState::unlicensed()),
    ))
}

fn make_jwt(workspace_id: Uuid, role: &str) -> String {
    let claims = Claims {
        sub: Uuid::new_v4(),
        ws: workspace_id,
        role: role.to_owned(),
        jti: Uuid::new_v4().to_string(),
        exp: (chrono::Utc::now() + chrono::Duration::seconds(900)).timestamp(),
        iat: chrono::Utc::now().timestamp(),
        purpose: None,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(TEST_JWT_SECRET.as_bytes()),
    )
    .expect("jwt encode")
}

async fn seed_workspace(pool: &PgPool) -> Uuid {
    let ws_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workspaces (id, name, created_at, updated_at)
         VALUES ($1, 'secure-mode-test-ws', NOW(), NOW())",
    )
    .bind(ws_id)
    .execute(pool)
    .await
    .unwrap();
    ws_id
}

async fn json_body(resp: axum::response::Response) -> Value {
    use http_body_util::BodyExt;
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

// ── GET /v1/secure-mode ───────────────────────────────────────────────────────

#[sqlx::test]
async fn get_secure_mode_requires_jwt(pool: PgPool) {
    let app = build_app(pool);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/secure-mode")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn get_secure_mode_returns_defaults_when_not_configured(pool: PgPool) {
    let ws_id = seed_workspace(&pool).await;
    let token = make_jwt(ws_id, "admin");
    let app = build_app(pool);

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/secure-mode")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    // Defaults: disabled, standard level
    assert_eq!(body["enabled"], false);
    assert_eq!(body["level"], "standard");
    assert_eq!(body["block_on_pii_detection"], false);
    assert_eq!(body["block_on_injection_detection"], false);
    assert_eq!(body["redact_pii_in_responses"], false);
    assert!(body["updated_at"].as_str().is_some());
}

// ── PUT /v1/secure-mode ───────────────────────────────────────────────────────

#[sqlx::test]
async fn put_secure_mode_requires_jwt(pool: PgPool) {
    let app = build_app(pool);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/secure-mode")
                .header("content-type", "application/json")
                .body(Body::from(json!({"enabled": true}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn put_secure_mode_requires_admin_role(pool: PgPool) {
    let ws_id = seed_workspace(&pool).await;
    let viewer_token = make_jwt(ws_id, "viewer");
    let app = build_app(pool);

    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/secure-mode")
                .header("authorization", format!("Bearer {viewer_token}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"enabled": true}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[sqlx::test]
async fn put_secure_mode_admin_can_enable(pool: PgPool) {
    let ws_id = seed_workspace(&pool).await;
    let token = make_jwt(ws_id, "admin");
    let app = build_app(pool);

    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/secure-mode")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "enabled": true,
                        "level": "strict",
                        "block_on_pii_detection": true,
                        "block_on_injection_detection": true,
                        "redact_pii_in_responses": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["enabled"], true);
    assert_eq!(body["level"], "strict");
    assert_eq!(body["block_on_pii_detection"], true);
    assert_eq!(body["block_on_injection_detection"], true);
    assert_eq!(body["redact_pii_in_responses"], true);
    assert!(body["updated_at"].as_str().is_some());
}

#[sqlx::test]
async fn get_secure_mode_reflects_put(pool: PgPool) {
    let ws_id = seed_workspace(&pool).await;
    let token = make_jwt(ws_id, "admin");

    // PUT to enable
    let app = build_app(pool.clone());
    app.oneshot(
        Request::builder()
            .method("PUT")
            .uri("/v1/secure-mode")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"enabled": true, "level": "permissive"}).to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    // GET should return updated value
    let app2 = build_app(pool);
    let resp = app2
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/secure-mode")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["enabled"], true);
    assert_eq!(body["level"], "permissive");
}

#[sqlx::test]
async fn put_secure_mode_rejects_invalid_level(pool: PgPool) {
    let ws_id = seed_workspace(&pool).await;
    let token = make_jwt(ws_id, "admin");
    let app = build_app(pool);

    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/secure-mode")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"enabled": true, "level": "maximum_power"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── WS2-3: sidecar_unavailable ────────────────────────────────────────────────

#[sqlx::test]
async fn get_secure_mode_reports_block_as_the_sidecar_default(pool: PgPool) {
    let ws_id = seed_workspace(&pool).await;
    let token = make_jwt(ws_id, "admin");
    let app = build_app(pool);

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/secure-mode")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(
        body["sidecar_unavailable"], "block",
        "a workspace that has never chosen must read back as fail-closed"
    );
}

#[sqlx::test]
async fn put_secure_mode_can_switch_to_degrade_with_alert(pool: PgPool) {
    let ws_id = seed_workspace(&pool).await;
    let token = make_jwt(ws_id, "admin");
    let app = build_app(pool);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/secure-mode")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"sidecar_unavailable": "degrade_with_alert"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(json_body(resp).await["sidecar_unavailable"], "degrade_with_alert");

    // Persisted, not just echoed.
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/secure-mode")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(json_body(resp).await["sidecar_unavailable"], "degrade_with_alert");
}

/// A PUT that does not mention `sidecar_unavailable` must leave it alone —
/// otherwise toggling an unrelated secure-mode switch would silently
/// re-open a workspace that had chosen to fail closed (or vice versa).
#[sqlx::test]
async fn put_secure_mode_preserves_sidecar_policy_when_unset(pool: PgPool) {
    let ws_id = seed_workspace(&pool).await;
    let token = make_jwt(ws_id, "admin");
    let app = build_app(pool);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/secure-mode")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"sidecar_unavailable": "degrade_with_alert"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/secure-mode")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"enabled": true}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["enabled"], true);
    assert_eq!(
        body["sidecar_unavailable"], "degrade_with_alert",
        "an unrelated PUT must not reset the sidecar policy"
    );
}

#[sqlx::test]
async fn put_secure_mode_rejects_unknown_sidecar_policy(pool: PgPool) {
    let ws_id = seed_workspace(&pool).await;
    let token = make_jwt(ws_id, "admin");
    let app = build_app(pool);

    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/secure-mode")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"sidecar_unavailable": "degrade"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "a near-miss value must be rejected, not silently coerced"
    );
}

// ── WS3-1: raw-content capture is opt-in, admin-only, and audited ─────────────

/// Mint a JWT for a REAL user row, so the audit trail's `actor_email` lookup
/// has something to find. `make_jwt` alone puts a synthetic `sub` in the
/// token, which is fine for role checks but would make every actor-identity
/// assertion below pass vacuously with `None`.
async fn seed_user_and_jwt(pool: &PgPool, ws_id: Uuid, role: &str) -> (Uuid, String, String) {
    let user_id = Uuid::new_v4();
    let email = format!("{role}-{user_id}@example.test");
    sqlx::query(
        "INSERT INTO users (id, workspace_id, email, password_hash, created_at, updated_at)
         VALUES ($1, $2, $3, 'x', NOW(), NOW())",
    )
    .bind(user_id)
    .bind(ws_id)
    .bind(&email)
    .execute(pool)
    .await
    .unwrap();

    let claims = Claims {
        sub: user_id,
        ws: ws_id,
        role: role.to_owned(),
        jti: Uuid::new_v4().to_string(),
        exp: (chrono::Utc::now() + chrono::Duration::seconds(900)).timestamp(),
        iat: chrono::Utc::now().timestamp(),
        purpose: None,
    };
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(TEST_JWT_SECRET.as_bytes()),
    )
    .expect("jwt encode");
    (user_id, email, token)
}

fn put_capture(token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri("/v1/secure-mode")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// Acceptance criterion: a fresh workspace reports capture OFF with the
/// default 30-day retention.
#[sqlx::test]
async fn get_secure_mode_reports_capture_off_by_default(pool: PgPool) {
    let ws_id = seed_workspace(&pool).await;

    // Premise: the workspace has never chosen. A stored row would make this
    // test assert the row's contents, not the DEFAULT.
    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM workspace_raw_capture WHERE workspace_id = $1")
            .bind(ws_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(rows, 0, "test premise: no stored capture choice");

    let token = make_jwt(ws_id, "admin");
    let resp = build_app(pool)
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/secure-mode")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(
        body["capture_raw_content"], false,
        "a fresh workspace must not capture raw content"
    );
    assert_eq!(
        body["raw_capture_retention_days"], 30,
        "WS3-2 default retention is 30 days"
    );
}

/// Acceptance criterion: "enabling requires admin role".
///
/// The POSITIVE CONTROL is the second half: the SAME request from an admin
/// must succeed AND actually flip the stored value. Without it, a 403 for the
/// viewer could mean the route rejects everyone, or that the field is ignored
/// entirely.
#[sqlx::test]
async fn enabling_capture_requires_admin(pool: PgPool) {
    let ws_id = seed_workspace(&pool).await;
    let (_, _, viewer_token) = seed_user_and_jwt(&pool, ws_id, "viewer").await;
    let (_, _, developer_token) = seed_user_and_jwt(&pool, ws_id, "developer").await;
    let (_, _, admin_token) = seed_user_and_jwt(&pool, ws_id, "admin").await;

    for (label, token) in [("viewer", &viewer_token), ("developer", &developer_token)] {
        let resp = build_app(pool.clone())
            .oneshot(put_capture(token, json!({"capture_raw_content": true})))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "{label} must not be able to switch on plaintext prompt retention"
        );
    }

    // Nothing was stored by the rejected attempts.
    let enabled: Option<bool> =
        sqlx::query_scalar("SELECT enabled FROM workspace_raw_capture WHERE workspace_id = $1")
            .bind(ws_id)
            .fetch_optional(&pool)
            .await
            .unwrap();
    assert!(
        enabled.is_none(),
        "a rejected PUT must not have written a settings row, got {enabled:?}"
    );

    // POSITIVE CONTROL.
    let resp = build_app(pool.clone())
        .oneshot(put_capture(&admin_token, json!({"capture_raw_content": true})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["capture_raw_content"], true);

    let enabled: bool =
        sqlx::query_scalar("SELECT enabled FROM workspace_raw_capture WHERE workspace_id = $1")
            .bind(ws_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(enabled, "the admin's PUT must have been persisted");
}

/// Acceptance criterion: "the enabling action is itself audited".
#[sqlx::test]
async fn enabling_capture_writes_an_audit_row_naming_the_actor(pool: PgPool) {
    let ws_id = seed_workspace(&pool).await;
    let (admin_id, admin_email, admin_token) = seed_user_and_jwt(&pool, ws_id, "admin").await;

    // Premise: nothing is in the audit table yet, so a row found afterwards
    // is definitely ours.
    let before: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM raw_capture_audit WHERE workspace_id = $1")
            .bind(ws_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(before, 0, "test premise: empty audit trail");

    let resp = build_app(pool.clone())
        .oneshot(put_capture(
            &admin_token,
            json!({"capture_raw_content": true, "raw_capture_retention_days": 7}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let (actor_user_id, actor_email, enabled_before, enabled_after, days_after): (
        Option<Uuid>,
        Option<String>,
        bool,
        bool,
        i32,
    ) = sqlx::query_as(
        "SELECT actor_user_id, actor_email, enabled_before, enabled_after,
                retention_days_after
         FROM raw_capture_audit WHERE workspace_id = $1",
    )
    .bind(ws_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(actor_user_id, Some(admin_id), "the audit row must name WHO");
    assert_eq!(
        actor_email.as_deref(),
        Some(admin_email.as_str()),
        "the audit row must carry the actor's email as it read at the time"
    );
    assert!(!enabled_before, "before-state must record that it was off");
    assert!(enabled_after, "after-state must record that it was turned on");
    assert_eq!(days_after, 7, "the retention choice is part of the record");
}

/// A PUT that touches unrelated fields must NOT append a capture audit row —
/// otherwise the trail fills with noise and "capture changed" stops meaning
/// anything. This is the differential control for the test above.
#[sqlx::test]
async fn unrelated_secure_mode_changes_do_not_touch_the_capture_audit(pool: PgPool) {
    let ws_id = seed_workspace(&pool).await;
    let (_, _, admin_token) = seed_user_and_jwt(&pool, ws_id, "admin").await;

    let resp = build_app(pool.clone())
        .oneshot(put_capture(&admin_token, json!({"level": "strict"})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM raw_capture_audit WHERE workspace_id = $1")
            .bind(ws_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(rows, 0, "a level change is not a capture change");

    // POSITIVE CONTROL: a capture change on the same workspace DOES append.
    let resp = build_app(pool.clone())
        .oneshot(put_capture(&admin_token, json!({"capture_raw_content": true})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM raw_capture_audit WHERE workspace_id = $1")
            .bind(ws_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(rows, 1, "a capture change must append exactly one row");
}

/// WS3-2 — retention is configurable, and out-of-range values are clamped to
/// the CHECK constraint's bounds rather than 500ing on a database error.
#[sqlx::test]
async fn retention_is_configurable_and_clamped(pool: PgPool) {
    let ws_id = seed_workspace(&pool).await;
    let (_, _, admin_token) = seed_user_and_jwt(&pool, ws_id, "admin").await;

    let resp = build_app(pool.clone())
        .oneshot(put_capture(
            &admin_token,
            json!({"capture_raw_content": true, "raw_capture_retention_days": 180}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        json_body(resp).await["raw_capture_retention_days"],
        180,
        "a retention LONGER than request_events' 90-day row TTL must be \
         accepted — captured content lives in its own table"
    );

    let resp = build_app(pool.clone())
        .oneshot(put_capture(&admin_token, json!({"raw_capture_retention_days": 0})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        json_body(resp).await["raw_capture_retention_days"],
        1,
        "zero days is clamped to the minimum, not rejected with a 500"
    );

    // Retention survives a PUT that does not mention it.
    let resp = build_app(pool.clone())
        .oneshot(put_capture(&admin_token, json!({"raw_capture_retention_days": 45})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = build_app(pool.clone())
        .oneshot(put_capture(&admin_token, json!({"capture_raw_content": false})))
        .await
        .unwrap();
    let body = json_body(resp).await;
    assert_eq!(body["capture_raw_content"], false);
    assert_eq!(
        body["raw_capture_retention_days"], 45,
        "turning capture off must not silently reset the configured window"
    );
}
