use axum::{
    body::Body,
    http::{self, Request},
    response::Response,
    Router,
};
use http_body_util::BodyExt;
use secureprompt_api::{
    app_state::AppState, db::api_key_repo::hash_api_key, http::build_router,
    ml_sidecar::MlSidecarClient,
};
use secureprompt_common::config::{
    AppConfig, ClickhouseConfig, DatabaseConfig, JwtConfig, LicenseConfig, RedisConfig,
    ServerConfig, TelemetryConfig,
};
use serde_json::Value;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

pub fn test_config() -> AppConfig {
    AppConfig {
        database: DatabaseConfig {
            url: "postgres://secureprompt:secureprompt@localhost:5432/postgres".to_owned(),
            max_connections: 5,
        },
        redis: RedisConfig {
            url: "redis://localhost:6379".to_owned(),
            max_connections: 5,
        },
        telemetry: TelemetryConfig {
            otel_enabled: false,
            prometheus_enabled: true,
            log_level: "info".to_owned(),
        },
        server: ServerConfig {
            host: "127.0.0.1".to_owned(),
            port: 0,
        },
        clickhouse: ClickhouseConfig {
            url: "http://localhost:8123".to_owned(),
            database: "default".to_owned(),
        },
        jwt: JwtConfig {
            secret: "test-jwt-secret-distinct-from-provider-key".to_owned(),
            access_ttl_secs: JwtConfig::DEFAULT_ACCESS_TTL_SECS,
            refresh_ttl_secs: JwtConfig::DEFAULT_REFRESH_TTL_SECS,
        },
        public_signup_enabled: false,
        chat_debug_mode: false,
        redact_when_no_rules: false,
        sidecar_unavailable_default: "block".to_owned(),
        license: LicenseConfig::default(),
    }
}

pub fn router(pool: PgPool) -> Router {
    let ml_sidecar = Arc::new(MlSidecarClient::new(String::new(), 200));
    build_router(AppState::new(
        pool,
        test_config(),
        ml_sidecar,
        std::sync::Arc::new(secureprompt_api::license::LicenseState::unlicensed()),
    ))
}

/// Router whose ML sidecar points at `sidecar_url` and whose analytics writer
/// targets `clickhouse_db`.
///
/// WS2-3 needs both knobs: the sidecar URL to drive the healthy / dead /
/// misconfigured cases the `sidecar_unavailable` policy branches on, and a
/// real ClickHouse database so the `floor_only` audit column can be asserted
/// end-to-end rather than inferred.
#[allow(dead_code)]
pub fn router_with(pool: PgPool, sidecar_url: &str, clickhouse_db: &str) -> Router {
    router_with_default(pool, sidecar_url, clickhouse_db, "block")
}

/// As `router_with`, but also sets the deployment-level
/// `sidecar_unavailable_default` (normally from
/// `SECUREPROMPT_SIDECAR_UNAVAILABLE_DEFAULT`) — the operator-facing
/// off-switch for the fail-closed default.
#[allow(dead_code)]
pub fn router_with_default(
    pool: PgPool,
    sidecar_url: &str,
    clickhouse_db: &str,
    sidecar_unavailable_default: &str,
) -> Router {
    let ml_sidecar = Arc::new(MlSidecarClient::new(sidecar_url.to_owned(), 500));
    let mut config = test_config();
    config.clickhouse.database = clickhouse_db.to_owned();
    config.sidecar_unavailable_default = sidecar_unavailable_default.to_owned();
    build_router(AppState::new(
        pool,
        config,
        ml_sidecar,
        std::sync::Arc::new(secureprompt_api::license::LicenseState::unlicensed()),
    ))
}

pub async fn seed_workspace(pool: &PgPool, workspace_id: Uuid, api_key: &str) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO workspaces (id, name, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(workspace_id)
    .bind(format!("workspace-{workspace_id}"))
    .execute(pool)
    .await?;

    sqlx::query(
        "INSERT INTO api_keys (id, workspace_id, name, key_hash, created_at)
         VALUES ($1, $2, $3, $4, NOW())",
    )
    .bind(Uuid::new_v4())
    .bind(workspace_id)
    .bind("default")
    .bind(hash_api_key(api_key))
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn seed_provider_and_model(
    pool: &PgPool,
    workspace_id: Uuid,
    provider_id: Uuid,
    provider_name: &str,
    provider_type: &str,
    credential: Option<&str>,
    public_model: &str,
) -> sqlx::Result<()> {
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, false)")
        .bind(workspace_id.to_string())
        .execute(pool)
        .await?;

    sqlx::query(
        "INSERT INTO providers (id, workspace_id, name, provider_type, encrypted_credential, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, NOW(), NOW())",
    )
    .bind(provider_id)
    .bind(workspace_id)
    .bind(provider_name)
    .bind(provider_type)
    .bind(credential)
    .execute(pool)
    .await?;

    sqlx::query(
        "INSERT INTO models (id, workspace_id, provider_id, name, created_at)
         VALUES ($1, $2, $3, $4, NOW())",
    )
    .bind(Uuid::new_v4())
    .bind(workspace_id)
    .bind(provider_id)
    .bind(public_model)
    .execute(pool)
    .await?;

    Ok(())
}

#[allow(dead_code)]
pub async fn seed_policy_rule(
    pool: &PgPool,
    workspace_id: Uuid,
    name: &str,
    priority: i32,
    conditions: Value,
    action: &str,
    action_params: Value,
    dry_run: bool,
) -> sqlx::Result<()> {
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, false)")
        .bind(workspace_id.to_string())
        .execute(pool)
        .await?;

    sqlx::query(
        "INSERT INTO policy_rules
            (id, workspace_id, name, priority, conditions, action, action_params, enabled, dry_run, created_at, updated_at)
         VALUES
            ($1, $2, $3, $4, $5, $6, $7, true, $8, NOW(), NOW())",
    )
    .bind(Uuid::new_v4())
    .bind(workspace_id)
    .bind(name)
    .bind(priority)
    .bind(conditions)
    .bind(action)
    .bind(action_params)
    .bind(dry_run)
    .execute(pool)
    .await?;

    Ok(())
}

pub fn authorized_request(
    builder: http::request::Builder,
    api_key: &str,
    body: Value,
) -> Request<Body> {
    builder
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {api_key}"))
        .body(Body::from(body.to_string()))
        .expect("request must build")
}

pub async fn response_text(response: Response) -> String {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body collection must succeed")
        .to_bytes();
    String::from_utf8(bytes.to_vec()).expect("body must be utf-8")
}

pub async fn response_json(response: Response) -> Value {
    let text = response_text(response).await;
    serde_json::from_str(&text).expect("response must be valid JSON")
}
