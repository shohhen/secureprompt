use axum::{
    body::Body,
    http::{self, Request},
    response::Response,
    Router,
};
use http_body_util::BodyExt;
use secureprompt_api::{
    app_state::AppState, db::api_key_repo::hash_api_key, db::scope::begin_scoped,
    http::build_router, ml_sidecar::MlSidecarClient,
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

/// MR1 review M4 — arm the tenancy scope the way production does, not the way
/// that only looks like it.
///
/// The seeds below used to run
/// `SELECT set_config('app.current_workspace_id', $1, false)` via
/// `.execute(pool)`. Two things were wrong with that, and both were invisible:
///
///  1. `.execute(pool)` takes its own checkout from the pool. The INSERTs that
///     followed took a DIFFERENT one, so the setting was never in scope for
///     the statements it was written for.
///  2. `false` is `is_local = false`, i.e. session-scoped. Even on one
///     connection that leaks the workspace id onto whatever the pool hands out
///     next — the precise thing `db::scope::begin_scoped`'s `true` avoids.
///
/// It was inert either way, because `#[sqlx::test]` connects as the role
/// `DATABASE_URL` names and for the compose stack that is a superuser, which
/// bypasses RLS including FORCE. So it changed no result — it only told the
/// next reader "this seed is RLS-aware" when it was not. The day these suites
/// run as `secureprompt_app` (the DB role split makes that a supported
/// configuration) the INSERTs below would start being rejected, and
/// `seed_workspace` did not even have the inert version despite `api_keys`
/// being armed and FORCEd since 001.
///
/// These now go through the production helper, `db::scope::begin_scoped`,
/// which sets the GUC transaction-locally AND READS IT BACK — so an unarmed
/// transaction fails loudly rather than seeding nothing.
fn scope_err(e: secureprompt_common::errors::ApiError) -> sqlx::Error {
    sqlx::Error::Protocol(format!("scoped seed transaction failed: {e}"))
}

pub async fn seed_workspace(pool: &PgPool, workspace_id: Uuid, api_key: &str) -> sqlx::Result<()> {
    // `workspaces` itself is NOT RLS-armed (no `workspace_id` column to key a
    // policy off), and the scope below names the row this INSERT creates, so
    // it has to land first — the same ordering constraint
    // `WorkspaceRepository::create_with_owner` documents.
    sqlx::query(
        "INSERT INTO workspaces (id, name, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(workspace_id)
    .bind(format!("workspace-{workspace_id}"))
    .execute(pool)
    .await?;

    // `api_keys` IS armed and FORCEd (001_init). This seed had no scoping at
    // all before.
    let mut tx = begin_scoped(pool, workspace_id).await.map_err(scope_err)?;
    sqlx::query(
        "INSERT INTO api_keys (id, workspace_id, name, key_hash, created_at)
         VALUES ($1, $2, $3, $4, NOW())",
    )
    .bind(Uuid::new_v4())
    .bind(workspace_id)
    .bind("default")
    .bind(hash_api_key(api_key))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

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
    // `providers` and `models` are both armed and FORCEd. One scoped
    // transaction covers both INSERTs — see `scope_err` above for what was
    // here before and why it did nothing.
    let mut tx = begin_scoped(pool, workspace_id).await.map_err(scope_err)?;

    sqlx::query(
        "INSERT INTO providers (id, workspace_id, name, provider_type, encrypted_credential, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, NOW(), NOW())",
    )
    .bind(provider_id)
    .bind(workspace_id)
    .bind(provider_name)
    .bind(provider_type)
    .bind(credential)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        "INSERT INTO models (id, workspace_id, provider_id, name, created_at)
         VALUES ($1, $2, $3, $4, NOW())",
    )
    .bind(Uuid::new_v4())
    .bind(workspace_id)
    .bind(provider_id)
    .bind(public_model)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

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
    // `policy_rules` is armed and FORCEd since 001_init.
    let mut tx = begin_scoped(pool, workspace_id).await.map_err(scope_err)?;

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
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

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
