use secureprompt_api::{app_state::AppState, http::build_router, ml_sidecar::MlSidecarClient};
use secureprompt_common::{
    config::{
        AppConfig, ClickhouseConfig, DatabaseConfig, JwtConfig, LicenseConfig, RedisConfig,
        ServerConfig, TelemetryConfig,
    },
    telemetry::init_telemetry,
};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tokio::net::TcpListener;

use secureprompt_api::db::migrations::{ensure_pg_migrations, run_migration_step};

/// The default DATABASE_URL. Points at the OWNER/MIGRATOR role, because a
/// developer running the binary by hand against a fresh database needs it to
/// create the schema. A deployment that has adopted the DB role split
/// overrides this with the runtime role's URL for the serving processes, and
/// keeps the owner URL only for `--migrate-only`.
const DEFAULT_DATABASE_URL: &str = "postgres://secureprompt:secureprompt@localhost:5432/secureprompt";

/// `secureprompt-api --migrate-only`: apply the Postgres schema as the
/// owner/migrator role, provision the runtime role, and exit.
///
/// This is the whole reason the API no longer migrates its own database in the
/// deployed shape. `sqlx::migrate!` needs `CREATE ON SCHEMA public` and table
/// ownership (measured: 018/021/023 fail without CREATE; 022 fails with `must
/// be owner of table token_vault_entries`), and the serving role must have
/// neither, because a NOBYPASSRLS role is the only kind row-level security
/// applies to. One connection cannot hold both sets of rights, so they are two
/// steps.
///
/// Run as a one-shot before the API and worker start — a compose service with
/// `service_completed_successfully`, a Kubernetes initContainer, or by hand.
/// The serving containers then never hold the owner credential at all, which a
/// second admin pool inside the API process could not have achieved.
///
/// Deliberately handled BEFORE `AppConfig` is built: this step needs
/// DATABASE_URL and nothing else, so the migration service does not have to be
/// given the JWT secret, the provider key or the ML sidecar token just to run
/// DDL.
async fn migrate_only() -> anyhow::Result<()> {
    init_telemetry(&TelemetryConfig {
        otel_enabled: false,
        prometheus_enabled: false,
        log_level: std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".into()),
    });

    let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| DEFAULT_DATABASE_URL.into());

    // One connection: this process applies DDL and exits. Nothing serves.
    let pool = PgPoolOptions::new().max_connections(1).connect(&url).await?;

    // Absent means "leave the password alone" — correct for a deployment that
    // manages the runtime role out of band (managed Postgres, an external
    // secret manager), and for a re-run where the password has not changed.
    let app_password = std::env::var("SECUREPROMPT_APP_DB_PASSWORD")
        .ok()
        .filter(|value| !value.is_empty());
    if let Some(value) = app_password.as_deref() {
        reject_placeholder_app_password(value).map_err(|msg| anyhow::anyhow!(msg))?;
    }
    if app_password.is_none() {
        tracing::info!(
            "SECUREPROMPT_APP_DB_PASSWORD unset — leaving the runtime role's \
             password unchanged"
        );
    }

    run_migration_step(&pool, app_password.as_deref()).await?;
    pool.close().await;

    tracing::info!("migration step complete");
    Ok(())
}

/// What the binary was asked to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Apply the schema as the owner role and exit.
    MigrateOnly,
    /// Serve HTTP.
    Serve,
}

/// Parse argv, REFUSING anything unrecognised.
///
/// The refusal is the point. `--migrate-only` is a new mode, and the 0.1.x
/// image tags are mutable, so a node-cached PRE-SPLIT image can be handed
/// `--migrate-only` by an initContainer. That binary had no argument parsing at
/// all: it ignored the flag and started the full API from a container given
/// only DATABASE_URL. Silently doing the wrong thing is the failure mode this
/// whole change exists to remove, so a mis-invocation must be loud.
fn parse_mode<I: IntoIterator<Item = String>>(args: I) -> Result<Mode, String> {
    let mut mode = Mode::Serve;
    for arg in args.into_iter().skip(1) {
        match arg.as_str() {
            "--migrate-only" => mode = Mode::MigrateOnly,
            other => {
                return Err(format!(
                    "unrecognised argument `{other}`. secureprompt-api takes \
                     either no arguments (serve HTTP) or `--migrate-only` \
                     (apply the schema as the owner role and exit). Refusing to \
                     guess: an image too old to know `--migrate-only` would \
                     otherwise start the API from a migration container."
                ))
            }
        }
    }
    Ok(mode)
}

/// The placeholder `.env.example` ships, rejected the way the JWT secret is.
///
/// MR7 I4: `SECUREPROMPT_APP_DB_PASSWORD=CHANGEME` shipped with neither a
/// hygiene-check entry nor a boot gate, and docker-compose builds BOTH the
/// password this step sets and the api/worker `DATABASE_URL` from that one
/// variable — so they agreed, and `cp .env.example .env` produced a stack that
/// came up green with the literal string CHANGEME as its database credential.
/// `scripts/init-env.sh` states the convention this repo relies on:
/// ".env.example keeps values the boot gate REJECTS." There was no gate.
fn reject_placeholder_app_password(value: &str) -> Result<(), String> {
    if value.trim().eq_ignore_ascii_case("CHANGEME") {
        return Err(
            "SECUREPROMPT_APP_DB_PASSWORD is still the .env.example placeholder \
             `CHANGEME`. That string would become the runtime role's actual \
             database password. Generate one: `openssl rand -hex 32`, or run \
             `./scripts/init-env.sh --fill-missing`."
                .to_string(),
        );
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match parse_mode(std::env::args()).map_err(|msg| anyhow::anyhow!(msg))? {
        Mode::MigrateOnly => return migrate_only().await,
        Mode::Serve => {}
    }

    let config = AppConfig {
        database: DatabaseConfig {
            url: std::env::var("DATABASE_URL").unwrap_or_else(|_| DEFAULT_DATABASE_URL.into()),
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
        sidecar_unavailable_default: AppConfig::sidecar_unavailable_default_from_env(),
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
            tracing::info!(server_url, interval_secs = secs, "online revocation checks enabled");
            // The loop body lives in `license::revocation` so its control flow
            // is reachable from a test — see `run_poller` there and the WS4-4
            // note on why a revocation must NOT end the poller. `LiveDeps` is
            // the only part of a tick that touches the outside world.
            let deps: std::sync::Arc<dyn secureprompt_api::license::revocation::PollerDeps> =
                std::sync::Arc::new(secureprompt_api::license::revocation::LiveDeps {
                    client: reqwest::Client::new(),
                    server_url,
                    vk,
                    db: poller_db,
                });
            tokio::spawn(secureprompt_api::license::revocation::run_poller(
                st,
                deps,
                std::time::Duration::from_secs(secs),
            ));
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
            // Why a skipped beat is logged, and only on change.
            //
            // This loop used to `continue` in silence. A deployment missing
            // SECUREPROMPT_ATTEST_KEK therefore uploaded nothing, forever,
            // while emitting "attestation heartbeat enabled" at boot and not
            // one line afterwards. From sp-admin the symptom is a customer
            // with no attestations; from the gateway log it is indistinguishable
            // from a healthy deployment. That is what actually happened in
            // production, and the diagnosis cost far more than this branch.
            //
            // The reason is logged when it CHANGES rather than every beat: at
            // the default hourly interval an unlicensed gateway would otherwise
            // emit the same warning 24 times a day, which is how a real signal
            // gets filtered out. Recovery is logged for the same reason — the
            // operator who fixed it wants confirmation, not silence.
            let mut last_skip: Option<&'static str> = None;
            loop {
                t.tick().await;
                let signed = match secureprompt_api::http::routes::internal::build_signed_attestation(
                    &att_state,
                )
                .await
                {
                    Some(s) => {
                        if last_skip.take().is_some() {
                            tracing::info!("attestation heartbeat recovered — resuming uploads");
                        }
                        s
                    }
                    None => {
                        // Re-derive the reason rather than plumbing it out of
                        // build_signed_attestation: that function is shared with
                        // GET /internal/attestation, which answers 503 and wants
                        // no opinion about logging.
                        let kek_ok = secureprompt_api::license::parse_kek(
                            &secureprompt_api::license::effective_attest_kek(
                                &att_state.config.license.attest_kek_b64,
                            ),
                        )
                        .is_some();
                        let reason = if !kek_ok {
                            "SECUREPROMPT_ATTEST_KEK is unset or not 32 base64 bytes — \
                             the attestation signing key cannot be unwrapped"
                        } else {
                            "no valid licence (unlicensed, expired or revoked) — \
                             the licence carries the attestation key"
                        };
                        if last_skip != Some(reason) {
                            tracing::warn!(
                                reason,
                                "attestation heartbeat skipped — sp-admin will show no attestations"
                            );
                            last_skip = Some(reason);
                        }
                        continue;
                    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(rest: &[&str]) -> Vec<String> {
        std::iter::once("secureprompt-api".to_string())
            .chain(rest.iter().map(|s| s.to_string()))
            .collect()
    }

    #[test]
    fn no_arguments_serves() {
        assert_eq!(parse_mode(argv(&[])), Ok(Mode::Serve));
    }

    #[test]
    fn the_migrate_flag_selects_the_migration_step() {
        assert_eq!(parse_mode(argv(&["--migrate-only"])), Ok(Mode::MigrateOnly));
    }

    /// MR7 I2. The old `main` did `args().any(|a| a == "--migrate-only")`, so a
    /// typo — or any other argument — silently started the HTTP server. In an
    /// initContainer that is a pod which never becomes ready, with no
    /// explanation anywhere.
    #[test]
    fn an_unrecognised_argument_is_refused_by_name() {
        let err = parse_mode(argv(&["--migrate-onlyy"])).expect_err(
            "a mis-typed flag must not silently fall through to serving HTTP",
        );
        assert!(err.contains("--migrate-onlyy"), "got: {err}");
        assert!(err.contains("--migrate-only"), "got: {err}");
    }

    #[test]
    fn an_unrecognised_argument_after_a_valid_one_is_still_refused() {
        assert!(parse_mode(argv(&["--migrate-only", "--serve"])).is_err());
    }

    /// MR7 I4.
    #[test]
    fn the_env_example_placeholder_is_not_a_database_password() {
        for placeholder in ["CHANGEME", "changeme", "  CHANGEME  "] {
            let err = reject_placeholder_app_password(placeholder).expect_err(
                "the placeholder .env.example ships must never become the \
                 runtime role's real password",
            );
            assert!(err.contains("CHANGEME"), "got: {err}");
        }
    }

    #[test]
    fn a_real_password_is_accepted() {
        assert_eq!(
            reject_placeholder_app_password(
                "9f2c1a4e8b7d6053f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708"
            ),
            Ok(())
        );
    }
}
