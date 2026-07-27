use secureprompt_api::{app_state::AppState, http::build_router, ml_sidecar::MlSidecarClient};
use secureprompt_common::{
    config::{
        AppConfig, ClickhouseConfig, DatabaseConfig, JwtConfig, LicenseConfig, RedisConfig,
        ServerConfig, TelemetryConfig,
    },
    telemetry::init_telemetry,
};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::sync::Arc;
use tokio::net::TcpListener;

/// Embedded sqlx migrations (all .sql files in `secureprompt-api/migrations/`).
/// Sorted by the leading numeric prefix in each filename.
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Apply pending Postgres migrations on startup.
///
/// Two cases to handle:
/// 1. **Fresh DB** (no `workspaces` table): `MIGRATOR.run` creates everything
///    from scratch, including the `_sqlx_migrations` tracking table.
/// 2. **Existing DB without sqlx tracking** (the case we just hit — someone
///    applied migrations manually via `psql`, then redeployed): the tables
///    are already there, but `_sqlx_migrations` is missing, so a naive
///    `MIGRATOR.run` would try to recreate `workspaces` and fail. We
///    detect this and bootstrap the tracking table by marking every
///    embedded migration as already applied.
async fn ensure_pg_migrations(pool: &PgPool) -> anyhow::Result<()> {
    let workspaces_exists: bool = sqlx::query_scalar(
        "SELECT to_regclass('public.workspaces') IS NOT NULL",
    )
    .fetch_one(pool)
    .await?;
    let tracking_exists: bool = sqlx::query_scalar(
        "SELECT to_regclass('public._sqlx_migrations') IS NOT NULL",
    )
    .fetch_one(pool)
    .await?;

    if workspaces_exists && !tracking_exists {
        tracing::warn!(
            "Postgres has existing schema but no sqlx tracking table — bootstrapping _sqlx_migrations from embedded migration set"
        );
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS _sqlx_migrations (
                version         BIGINT PRIMARY KEY,
                description     TEXT NOT NULL,
                installed_on    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                success         BOOLEAN NOT NULL,
                checksum        BYTEA NOT NULL,
                execution_time  BIGINT NOT NULL
            )",
        )
        .execute(pool)
        .await?;
        for m in MIGRATOR.iter() {
            sqlx::query(
                "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) \
                 VALUES ($1, $2, TRUE, $3, 0) ON CONFLICT (version) DO NOTHING",
            )
            .bind(m.version)
            .bind(m.description.as_ref())
            .bind(&m.checksum[..])
            .execute(pool)
            .await?;
        }
    }

    MIGRATOR.run(pool).await?;
    tracing::info!(
        applied = MIGRATOR.iter().count(),
        "Postgres migrations up to date"
    );
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = AppConfig {
        database: DatabaseConfig {
            url: std::env::var("DATABASE_URL").unwrap_or_else(|_| {
                "postgres://secureprompt:secureprompt@localhost:5432/secureprompt".into()
            }),
            max_connections: 10,
        },
        redis: RedisConfig {
            url: std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".into()),
            max_connections: 10,
        },
        telemetry: TelemetryConfig {
            otel_enabled: false,
            prometheus_enabled: false,
            log_level: std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".into()),
        },
        server: ServerConfig {
            host: std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into()),
            port: std::env::var("PORT")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(8080),
        },
        clickhouse: ClickhouseConfig {
            url: std::env::var("CLICKHOUSE_URL")
                .unwrap_or_else(|_| "http://localhost:8123".into()),
            database: std::env::var("CLICKHOUSE_DATABASE")
                .unwrap_or_else(|_| "default".into()),
        },
        jwt: JwtConfig::from_env()
            .map_err(|msg| anyhow::anyhow!("invalid JWT configuration: {msg}"))?,
        public_signup_enabled: AppConfig::public_signup_enabled_from_env(),
        chat_debug_mode: AppConfig::chat_debug_mode_from_env(),
        redact_when_no_rules: AppConfig::redact_when_no_rules_from_env(),
        license: LicenseConfig::from_env(),
    };

    init_telemetry(&config.telemetry);

    if config.public_signup_enabled {
        tracing::warn!(
            "public signup is enabled (SECUREPROMPT_PUBLIC_SIGNUP_ENABLED) — this should only be on for cloud/demo deployments"
        );
    }

    if config.chat_debug_mode {
        tracing::warn!(
            "chat debug mode is enabled (SECUREPROMPT_CHAT_DEBUG_MODE) — /v1/chat/completions will not forward to cloud providers"
        );
    }

    let db = PgPoolOptions::new()
        .max_connections(config.database.max_connections)
        .connect(&config.database.url)
        .await?;

    ensure_pg_migrations(&db).await?;

    let ml_sidecar_url = std::env::var("ML_SIDECAR_URL").unwrap_or_default();
    // Gateway path uses this client; 200 ms was too tight for cold-path NER —
    // the first GLiNER call reliably exceeds it and the circuit silently
    // returned empty detections. 5 s matches the ML sidecar's soft budget
    // for a single `/detect/ner` call and still trips the breaker quickly
    // enough if the sidecar is genuinely down.
    let ml_sidecar_timeout_ms: u64 = std::env::var("ML_SIDECAR_TIMEOUT_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5000);
    // WS1-5: every ML-sidecar route except /health, /ready, /metrics now
    // requires this bearer token (secureprompt-ml/app/main.py's
    // `_require_internal_token` dependency). Same env var
    // (`ML_SIDECAR_INTERNAL_TOKEN`) the sidecar itself reads, already
    // surfaced here via `LicenseConfig::internal_token`.
    let ml_sidecar = Arc::new(
        MlSidecarClient::new(ml_sidecar_url, ml_sidecar_timeout_ms)
            .with_token(config.license.internal_token.clone()),
    );

    // Log whether keys are pinned at build time (boolean only — never log the key value).
    tracing::info!(
        "vendor key pinned at build: {}",
        option_env!("SECUREPROMPT_PINNED_VENDOR_PUBKEY").is_some()
    );
    tracing::info!(
        "attest KEK pinned at build: {}",
        option_env!("SECUREPROMPT_PINNED_ATTEST_KEK").is_some()
    );

    // Plan 3 — startup license verification. Fail-open: never fatal.
    let license = {
        let now = chrono::Utc::now().timestamp();
        let effective_pubkey = secureprompt_api::license::effective_vendor_pubkey(&config.license.pubkey_b64);
        // Task 2: prefer DB-stored token over env/config token; fall back on any error.
        let token = secureprompt_api::license::resolve_active_token(&db, &config.license.license_token).await;
        match secureprompt_api::license::parse_vendor_key(&effective_pubkey) {
            Some(vk) => std::sync::Arc::new(secureprompt_api::license::LicenseState::new(
                secureprompt_api::license::load_and_verify_token(
                    &token,
                    &vk,
                    now,
                ),
            )),
            None => {
                tracing::warn!(
                    "SECUREPROMPT_LICENSE_PUBKEY unset/invalid — running unlicensed (grace)"
                );
                std::sync::Arc::new(secureprompt_api::license::LicenseState::unlicensed())
            }
        }
    };

    let state = AppState::new(db, config.clone(), ml_sidecar, license);

    // Part B — boot seed: load persisted high-water from Postgres immediately
    // so a freshly-booted (or URL-less) gateway doesn't emit a spurious hard-stale.
    // Runs synchronously before any background task is spawned.
    if let Some(lic_id) = state.license.snapshot().lic_id {
        if let Ok(Some(row)) = secureprompt_api::license::freshness_store::load(&state.db, &lic_id).await {
            state.license.observe_freshness(row.last_assertion_at, row.highwater_at);
        }
    }

    // Tamper-evidence: check running image digest against the license's pinned digest.
    // Fail-open — NEVER crash, just warn.
    {
        let actual = std::env::var("SECUREPROMPT_IMAGE_DIGEST").unwrap_or_default();
        for flag in state.license.tamper_flags("api", &actual) {
            tracing::warn!(flag, "tamper evidence detected at startup");
        }
    }

    // Task 4 — best-effort relay of the wrapped model blob to the ML sidecar at startup.
    // Retries up to 10 times (sidecar may still be starting). NEVER aborts the gateway.
    // The gateway holds ONLY the ATTEST-KEK; the wrapped blob is forwarded as-is.
    let token = config.license.internal_token.clone();
    if !token.is_empty() {
        let st = std::sync::Arc::clone(&state.license);
        let client = std::sync::Arc::clone(&state.ml_sidecar);
        let token_clone = token.clone();
        tokio::spawn(async move {
            for attempt in 0..10u32 {
                let snap = st.snapshot();
                if let (Some(w), Some(lic)) = (snap.wrapped_model_key.as_ref(), snap.lic_id.as_ref()) {
                    match client.push_wrapped_model_key(w, lic, &token_clone).await {
                        Ok(()) => {
                            tracing::info!("relayed wrapped model blob to ML sidecar");
                            return;
                        }
                        Err(e) => tracing::warn!(
                            attempt,
                            error = %e,
                            "wrapped model blob relay failed; retrying"
                        ),
                    }
                } else {
                    tracing::warn!("no valid license wrapped model blob to relay");
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
        });
    }

    // Plan 3 — periodic license re-verify (only when a vendor key is configured).
    let effective_pubkey_for_recheck = secureprompt_api::license::effective_vendor_pubkey(&config.license.pubkey_b64);
    if let Some(vk) = secureprompt_api::license::parse_vendor_key(&effective_pubkey_for_recheck) {
        let st = std::sync::Arc::clone(&state.license);
        // Task 2: capture the env token so we can re-resolve DB vs env each tick.
        let env_token_for_recheck = config.license.license_token.clone();
        let secs = config.license.recheck_secs;
        // Task 4 — capture token/client for re-relay on re-verify (wrapped blob, not plaintext).
        let recheck_token = token.clone();
        let recheck_client = std::sync::Arc::clone(&state.ml_sidecar);
        // Capture digest once before the loop — reading the env var inside the
        // loop on every tick would work too, but a single capture is cheaper.
        let recheck_digest = std::env::var("SECUREPROMPT_IMAGE_DIGEST").unwrap_or_default();
        // Part C — capture db for freshness high-water persistence (URL-independent).
        // Also used by Task 2 for re-resolving DB token each tick.
        let recheck_db = state.db.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(std::time::Duration::from_secs(secs));
            t.tick().await; // skip immediate first tick (startup already verified / boot-seeded)
            loop {
                t.tick().await;
                // Task 2: re-resolve DB vs env on every tick so a token activated
                // mid-run takes effect without a restart.
                let token = secureprompt_api::license::resolve_active_token(&recheck_db, &env_token_for_recheck).await;
                let new_snapshot = secureprompt_api::license::load_and_verify_token(
                    &token,
                    &vk,
                    chrono::Utc::now().timestamp(),
                );
                st.set(new_snapshot);
                // Part C — advance + persist the high-water on every tick regardless of
                // whether the license-server URL is configured.  This is what makes the
                // offline countdown URL-independent: the clock advances here.
                let now = chrono::Utc::now().timestamp();
                if let Some(lic_id) = st.snapshot().lic_id {
                    let _ = secureprompt_api::license::freshness_store::record(&recheck_db, &lic_id, None, now).await;
                    if let Ok(Some(row)) = secureprompt_api::license::freshness_store::load(&recheck_db, &lic_id).await {
                        st.observe_freshness(row.last_assertion_at, row.highwater_at);
                    }
                }
                st.observe_clock(now); // advance in-memory high-water even if the DB write failed
                // Re-emit tamper-evidence flags after each periodic re-verify.
                // Fail-open — never panic, just warn.
                for flag in st.tamper_flags("api", &recheck_digest) {
                    tracing::warn!(flag, "tamper evidence detected on re-verify");
                }
                // Task 4 — re-relay the wrapped model blob after a license refresh (single attempt, best-effort).
                if !recheck_token.is_empty() {
                    let snap = st.snapshot();
                    if let (Some(w), Some(lic)) = (snap.wrapped_model_key.as_ref(), snap.lic_id.as_ref()) {
                        match recheck_client.push_wrapped_model_key(w, lic, &recheck_token).await {
                            Ok(()) => tracing::info!("re-relayed wrapped model blob to ML sidecar after license re-verify"),
                            Err(e) => tracing::warn!(error = %e, "wrapped model blob re-relay failed after license re-verify (ignored)"),
                        }
                    }
                }
            }
        });
    }

    // Online revocation poller (fail-closed). Only runs when a license server URL
    // is configured; otherwise the gateway stays fully offline as before. Polls
    // sp-admin's public status endpoint and, on a confirmed `revoked` verdict,
    // flips the license to a sticky Revoked state that the request-pipeline gate
    // turns into 403s. Soft-fail: an unreachable vendor keeps the last-known state.
    if let Some(server_url) = config.license.license_server_url.clone() {
        let st = std::sync::Arc::clone(&state.license);
        let secs = config.license.revocation_check_secs;
        // Derive the vendor verifying key once before the loop; if it's absent
        // the poller cannot verify signed assertions so we skip polling entirely.
        let poller_pubkey = secureprompt_api::license::effective_vendor_pubkey(&config.license.pubkey_b64);
        let poller_vk = secureprompt_api::license::parse_vendor_key(&poller_pubkey);
        // Part D — capture db for freshness persistence of verified assertions.
        let poller_db = state.db.clone();
        if let Some(vk) = poller_vk {
            tokio::spawn(async move {
                use secureprompt_api::license::freshness_store;
                use secureprompt_api::license::revocation::RevocationVerdict;
                let client = reqwest::Client::new();
                let mut t = tokio::time::interval(std::time::Duration::from_secs(secs));
                tracing::info!(server_url, interval_secs = secs, "online revocation checks enabled");
                loop {
                    t.tick().await; // first tick is immediate — check promptly at startup
                    if st.is_revoked() {
                        return; // terminal: vendor never un-revokes, stop polling
                    }
                    // lic_id is only present while the local file verifies (Valid).
                    let lic_id = match st.snapshot().lic_id {
                        Some(id) => id,
                        None => continue,
                    };
                    let (verdict, issued_at) = secureprompt_api::license::revocation::check(
                        &client, &server_url, &lic_id, &vk,
                    ).await;
                    // Part D — record the assertion in Postgres and advance in-memory atoms.
                    let now = chrono::Utc::now().timestamp();
                    match verdict {
                        RevocationVerdict::Revoked => {
                            st.mark_revoked();
                            tracing::error!(lic_id, "license REVOKED by vendor — gateway is now fail-closed (403)");
                            return;
                        }
                        RevocationVerdict::Active => {
                            // issued_at: Some(_) only when the server returned a sig-verified assertion.
                            let _ = freshness_store::record(&poller_db, &lic_id, issued_at, now).await;
                            if let Ok(Some(row)) = freshness_store::load(&poller_db, &lic_id).await {
                                st.observe_freshness(row.last_assertion_at, row.highwater_at);
                            }
                            tracing::debug!(lic_id, "revocation check: license active");
                        }
                        // Unknown already logged inside check() — bump highwater only (no assertion credit).
                        RevocationVerdict::Unknown => {
                            let _ = freshness_store::record(&poller_db, &lic_id, None, now).await;
                            if let Ok(Some(row)) = freshness_store::load(&poller_db, &lic_id).await {
                                st.observe_freshness(row.last_assertion_at, row.highwater_at);
                            }
                        }
                    }
                }
            });
        } else {
            tracing::warn!("online revocation checks configured but vendor key is absent/invalid — poller disabled");
        }
    }

    // Attestation heartbeat uploader (best-effort). Only runs when a license
    // server URL is configured (reuses SECUREPROMPT_LICENSE_SERVER_URL). Builds
    // + signs the same bundle as GET /internal/attestation and POSTs it to
    // sp-admin's public, signature-authenticated /v1/attestations every
    // SECUREPROMPT_ATTESTATION_INTERVAL_SECS. Never blocks, never panics; a
    // revoked/invalid license simply produces no bundle and the beat is skipped.
    if let Some(server_url) = config.license.license_server_url.clone() {
        let att_state = state.clone();
        let secs = config.license.attestation_interval_secs;
        tokio::spawn(async move {
            let client = reqwest::Client::new();
            let url = format!("{}/v1/attestations", server_url.trim_end_matches('/'));
            let mut t = tokio::time::interval(std::time::Duration::from_secs(secs));
            tracing::info!(url, interval_secs = secs, "attestation heartbeat enabled");
            loop {
                t.tick().await;
                let Some(signed) =
                    secureprompt_api::http::routes::internal::build_signed_attestation(&att_state)
                        .await
                else {
                    continue; // no valid license/key right now — skip this beat
                };
                match client
                    .post(&url)
                    .timeout(std::time::Duration::from_secs(10))
                    .json(&signed)
                    .send()
                    .await
                {
                    Ok(r) if r.status().is_success() => {
                        tracing::debug!("attestation heartbeat uploaded")
                    }
                    Ok(r) => tracing::warn!(status = %r.status(), "attestation upload rejected"),
                    Err(e) => tracing::warn!(error = %e, "attestation upload failed (ignored)"),
                }
            }
        });
    }

    let app = build_router(state);
    let address = format!("{}:{}", config.server.host, config.server.port);
    let listener = TcpListener::bind(&address).await?;

    tracing::info!(addr = %address, "secureprompt-api listening");
    // `into_make_service_with_connect_info::<SocketAddr>()` exposes the
    // TCP peer address through `ConnectInfo<SocketAddr>` extractors so
    // handlers can record the originating IP even when the client
    // doesn't set `X-Forwarded-For` / `X-Real-IP` (e.g. LibreChat
    // talking to us directly over the docker network).
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}
