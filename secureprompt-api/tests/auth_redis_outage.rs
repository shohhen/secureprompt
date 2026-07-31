//! FU3 — what `jwt_auth::require` does when Redis is unreachable.
//!
//! `require` reads both session gates from Redis in one round trip
//! (`jti_blacklist:{jti}` and the WS4-3 `session_revoked:{user_id}` watermark).
//! Before FU3, ANY error from that read fell back to `AppState.auth_cache` — a
//! per-pod `DashMap` with a 5-minute TTL — and served the request. Both
//! mechanisms that end a session live in Redis, so the fallback served
//! sessions neither mechanism could be consulted about, silently.
//!
//! What these tests pin, in the WS2-3 `block`/`degrade_with_alert` vocabulary:
//!
//!   * admin revocation fails CLOSED, on every pod, read from
//!     `session_revocation_audit` rather than from Redis;
//!   * both stores unreachable fails CLOSED;
//!   * a warm session with only the jti blacklist unreadable DEGRADES —
//!     served, alerted, counted, and marked on the response;
//!   * the window is 60 s, does not renew itself, and grants only the role the
//!     presented token carries.
//!
//! These tests drive the REAL failure: a pod whose `redis.url` points at a
//! port nothing is listening on, sharing its `auth_cache` with a sibling pod
//! that has a live Redis. The cache is warmed by a genuine authenticated
//! request through the production middleware — nothing here stubs the cache or
//! stubs the failure. That pairing is exactly one pod whose Redis went away
//! after it had been serving.
//!
//! Fixtures are synthetic.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use dashmap::DashMap;
use deadpool_redis::{redis::cmd, Config as RedisPoolConfig, Pool as RedisPool, Runtime};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use secureprompt_api::{
    app_state::AppState,
    http::build_router,
    http::middleware::jwt_auth::{CachedAuthEntry, Claims, DEGRADED_AUTH_CACHE_TTL_SECS},
    ml_sidecar::MlSidecarClient,
};
use secureprompt_common::config::{
    AppConfig, ClickhouseConfig, DatabaseConfig, JwtConfig, LicenseConfig, RedisConfig,
    ServerConfig, TelemetryConfig,
};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::net::TcpListener;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

const TEST_JWT_SECRET: &str = "fu3-auth-redis-outage-test-secret";
/// The `users.password_hash` column is NOT NULL. Nothing here authenticates by
/// password, so a literal placeholder is enough and keeps argon2 out of the
/// test's cost.
const UNUSED_PASSWORD_HASH: &str = "$argon2id$unused-by-this-suite";

/// Response header that must name the degraded auth condition.
const AUTH_DEGRADED_HEADER: &str = "x-secureprompt-auth-degraded";
/// The reason the header must carry when the gateway served a request whose
/// jti-blacklist status it could not check.
const REASON_LOGOUT_UNVERIFIABLE: &str = "logout_unverifiable";

// ── Harness ───────────────────────────────────────────────────────────────

fn live_redis_url() -> String {
    std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".into())
}

/// A `redis://` URL for a port that was bound and immediately released, so a
/// connect gets ECONNREFUSED rather than hanging. This is the whole point of
/// the suite: the failure is a real socket failure inside `deadpool-redis`,
/// not a flag a test set.
fn dead_url(scheme: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    format!("{scheme}://127.0.0.1:{port}")
}

fn test_config(redis_url: String) -> AppConfig {
    AppConfig {
        database: DatabaseConfig {
            url: "postgres://unused".into(),
            max_connections: 1,
        },
        redis: RedisConfig {
            url: redis_url,
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

type AuthCache = Arc<DashMap<Uuid, CachedAuthEntry>>;

/// One gateway process. The `AppState` is returned alongside the router so a
/// test can assert on the pod's own auth cache and metrics registry.
struct Pod {
    app: axum::Router,
    state: AppState,
}

fn build_pod(db: PgPool, redis_url: String, cache: AuthCache) -> Pod {
    let ml = Arc::new(MlSidecarClient::new(String::new(), 100));
    let mut state = AppState::new(
        db,
        test_config(redis_url),
        ml,
        Arc::new(secureprompt_api::license::LicenseState::unlicensed()),
    );
    // Same process, same cache: the "live" and "dead" halves of a pair model
    // ONE pod before and after its Redis became unreachable.
    state.auth_cache = cache;
    Pod {
        app: build_router(state.clone()),
        state,
    }
}

/// A pod pair sharing one auth cache: `live` can reach Redis, `dead` cannot.
struct PodPair {
    live: Pod,
    dead: Pod,
    cache: AuthCache,
}

fn pod_pair(db: &PgPool) -> PodPair {
    let cache: AuthCache = Arc::new(DashMap::new());
    PodPair {
        live: build_pod(db.clone(), live_redis_url(), Arc::clone(&cache)),
        dead: build_pod(db.clone(), dead_url("redis"), Arc::clone(&cache)),
        cache,
    }
}

fn make_jwt(workspace_id: Uuid, user_id: Uuid, role: &str) -> String {
    let now = chrono::Utc::now();
    let claims = Claims {
        sub: user_id,
        ws: workspace_id,
        role: role.to_owned(),
        jti: Uuid::new_v4().to_string(),
        exp: (now + chrono::Duration::seconds(900)).timestamp(),
        iat: now.timestamp(),
        purpose: None,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(TEST_JWT_SECRET.as_bytes()),
    )
    .expect("jwt encode")
}

async fn redis_pool() -> RedisPool {
    RedisPoolConfig::from_url(live_redis_url())
        .create_pool(Some(Runtime::Tokio1))
        .expect("redis pool")
}

async fn forget_watermark(user_id: Uuid) {
    let pool = redis_pool().await;
    let mut conn = pool.get().await.expect("redis checkout");
    let _: i64 = cmd("DEL")
        .arg(format!("session_revoked:{user_id}"))
        .query_async(&mut conn)
        .await
        .unwrap_or(0);
}

struct Workspace {
    id: Uuid,
    admin: Uuid,
    viewer: Uuid,
    other: Uuid,
}

async fn seed_workspace(pool: &PgPool) -> Workspace {
    let id = Uuid::new_v4();
    let suffix = Uuid::new_v4().simple().to_string();
    sqlx::query(
        "INSERT INTO workspaces (id, name, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(id)
    .bind(format!("fu3 {suffix}"))
    .execute(pool)
    .await
    .expect("seed workspace");

    let mut ids = Vec::new();
    for role in ["admin", "viewer", "developer"] {
        let user_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (id, workspace_id, email, password_hash, role, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, NOW(), NOW())",
        )
        .bind(user_id)
        .bind(id)
        .bind(format!("{role}-{suffix}@example.com"))
        .bind(UNUSED_PASSWORD_HASH)
        .bind(role)
        .execute(pool)
        .await
        .expect("seed user");
        ids.push(user_id);
    }
    Workspace {
        id,
        admin: ids[0],
        viewer: ids[1],
        other: ids[2],
    }
}

/// A plain authenticated read. `GET /v1/users` is open to every role, so a
/// non-200 is the auth layer talking and not an RBAC decision.
async fn authenticated_read(app: &axum::Router, token: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/users")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("router runs")
}

/// A JWT-gated route that touches NO datastore (`telemetry.rs` documents that
/// it persists nothing). Used where a test must tell "the auth layer refused"
/// apart from "a handler could not reach its database".
async fn db_free_authenticated_write(app: &axum::Router, token: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/telemetry/client-error")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "component": "fu3",
                        "message": "probe",
                        "url": "https://example.invalid/probe"
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("router runs")
}

async fn revoke(app: &axum::Router, actor_token: &str, target: Uuid) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/users/{target}/sessions"))
                .header("authorization", format!("Bearer {actor_token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("router runs")
        .status()
}

/// `POST /v1/keys` is admin-only (`require_role(&ctx, UserRole::Admin)`), so
/// its status reports which ROLE the auth layer put in `JwtAuthContext`.
async fn admin_only_create_key(app: &axum::Router, token: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/keys")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "name": "fu3-probe" }).to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("router runs")
        .status()
}

/// PREMISE for every test below: the "dead" pod's Redis really is unreachable.
/// Without this assertion a green suite could mean Redis answered all along and
/// the fallback was never entered.
async fn assert_redis_is_unreachable(pod: &Pod) {
    let probe =
        secureprompt_api::redis::session_gates(&pod.state.redis_pool, "fu3-probe", &Uuid::new_v4())
            .await;
    assert!(
        probe.is_err(),
        "premise: the degraded pod must not be able to reach Redis, or every \
         assertion about the fallback path proves nothing (got {probe:?})"
    );
}

// ── The gap ───────────────────────────────────────────────────────────────

/// THE HEADLINE. An administrator terminates a user's sessions. On a pod that
/// cannot reach Redis, that user's already-minted access token is still
/// accepted, because the fallback serves from a cache that predates the
/// revocation and cannot be told about it.
///
/// The revocation is durable — `session_revocation_audit` records the same
/// watermark that goes to Redis — so "we could not reach Redis" is not the same
/// fact as "we cannot know whether this session was revoked".
#[sqlx::test]
async fn a_revoked_session_is_refused_on_a_pod_that_cannot_reach_redis(db: PgPool) {
    let ws = seed_workspace(&db).await;
    let pair = pod_pair(&db);
    // The revoking pod is a DIFFERENT pod with its own cache — local eviction
    // on the actor's pod must not be what makes this test pass.
    let actor_pod = build_pod(db.clone(), live_redis_url(), Arc::new(DashMap::new()));

    let victim = make_jwt(ws.id, ws.viewer, "viewer");
    let bystander = make_jwt(ws.id, ws.other, "developer");
    let admin = make_jwt(ws.id, ws.admin, "admin");

    // PREMISE: both tokens work through the live half, which also warms the
    // shared cache through the production write-through path.
    assert_eq!(
        authenticated_read(&pair.live.app, &victim).await.status(),
        StatusCode::OK,
        "premise: the victim's token must work before revocation"
    );
    assert_eq!(
        authenticated_read(&pair.live.app, &bystander)
            .await
            .status(),
        StatusCode::OK,
        "premise: the bystander's token must work too"
    );
    // PREMISE: the fallback has something to serve. A 401 below is only
    // interesting if the cache would otherwise have answered.
    assert!(
        pair.cache.contains_key(&ws.viewer),
        "premise: the shared auth cache must hold a warm entry for the victim"
    );
    assert_redis_is_unreachable(&pair.dead).await;

    assert_eq!(
        revoke(&actor_pod.app, &admin, ws.viewer).await,
        StatusCode::OK,
        "the revocation itself must succeed"
    );

    assert_eq!(
        authenticated_read(&pair.dead.app, &victim).await.status(),
        StatusCode::UNAUTHORIZED,
        "a session an administrator revoked must not be served just because \
         the pod cannot reach Redis — the revocation is durable in \
         session_revocation_audit"
    );

    // CONTROL THAT MUST DIFFER: the bystander, on the SAME unreachable-Redis
    // pod, is still served. Without this the assertion above would also pass
    // if a Redis outage simply 401'd everybody.
    assert_eq!(
        authenticated_read(&pair.dead.app, &bystander)
            .await
            .status(),
        StatusCode::OK,
        "control: a user nobody revoked must still be served while Redis is \
         down, or the fix has traded a security gap for an outage"
    );

    forget_watermark(ws.viewer).await;
}

/// An answer served without the session gates having been consulted must say
/// so. The license gate sets `x-secureprompt-license-degraded` for exactly this
/// reason: an unobserved fail-open is worse than an observed one.
#[sqlx::test]
async fn serving_through_the_auth_fallback_is_marked_on_the_response(db: PgPool) {
    let ws = seed_workspace(&db).await;
    let pair = pod_pair(&db);
    let token = make_jwt(ws.id, ws.viewer, "viewer");

    // PREMISE + CONTROL THAT MUST DIFFER: the healthy pod serves the identical
    // request and does NOT mark it.
    let healthy = authenticated_read(&pair.live.app, &token).await;
    assert_eq!(healthy.status(), StatusCode::OK, "premise: healthy 200");
    assert!(
        healthy.headers().get(AUTH_DEGRADED_HEADER).is_none(),
        "control: a fully verified answer must NOT carry the degraded marker, \
         or the marker means nothing"
    );
    assert_redis_is_unreachable(&pair.dead).await;

    let degraded = authenticated_read(&pair.dead.app, &token).await;
    assert_eq!(
        degraded.status(),
        StatusCode::OK,
        "a warm session must still be served during a Redis blip"
    );
    assert_eq!(
        degraded
            .headers()
            .get(AUTH_DEGRADED_HEADER)
            .map(|v| v.to_str().expect("header is ascii")),
        Some(REASON_LOGOUT_UNVERIFIABLE),
        "an answer served without the jti blacklist having been read must name \
         that condition on the response"
    );
}

/// With BOTH stores unreachable nothing in the deployment can say whether this
/// session was ended. Serving it then is a fail-open with no counterparty.
///
/// The probe route persists nothing, so its status separates "the auth layer
/// refused" (503) from "a handler could not reach its database" (500).
#[sqlx::test]
async fn both_stores_unreachable_refuses_rather_than_serving_from_cache(db: PgPool) {
    let ws = seed_workspace(&db).await;
    let cache: AuthCache = Arc::new(DashMap::new());
    let live = build_pod(db.clone(), live_redis_url(), Arc::clone(&cache));

    // A pool that will never connect: same shape as the dead Redis, one layer
    // down. `connect_lazy_with` does not dial, so building the pod succeeds.
    let dead_db: PgPool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(2))
        .connect_lazy(&format!("{}/secureprompt", dead_url("postgres")))
        .expect("lazy pool for an address nothing answers on");
    let dead = build_pod(dead_db, dead_url("redis"), Arc::clone(&cache));

    let token = make_jwt(ws.id, ws.viewer, "viewer");

    // PREMISE: warm the shared cache through the production path.
    assert_eq!(
        authenticated_read(&live.app, &token).await.status(),
        StatusCode::OK,
        "premise: the token must work on the healthy pod first"
    );
    assert!(
        cache.contains_key(&ws.viewer),
        "premise: the shared auth cache must hold a warm entry"
    );
    assert_redis_is_unreachable(&dead).await;
    // PREMISE: the probe route really is datastore-free on a HEALTHY pod, so a
    // non-204 from the dead pod below is the auth layer and not the route.
    assert_eq!(
        db_free_authenticated_write(&live.app, &token)
            .await
            .status(),
        StatusCode::NO_CONTENT,
        "premise: the probe route answers 204 without touching a datastore"
    );

    assert_eq!(
        db_free_authenticated_write(&dead.app, &token)
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "with Redis AND Postgres unreachable no store can confirm the session \
         is still valid; the request must be refused, not served from a cache"
    );
}

/// The cache carries a role, and the fallback used to build `JwtAuthContext`
/// from it. The token's own signed `role` claim can be LOWER than the cached
/// one — a user demoted after the cache was warmed — so the fallback could
/// grant a privilege the presented token does not carry.
#[sqlx::test]
async fn the_fallback_does_not_grant_a_role_the_presented_token_lacks(db: PgPool) {
    let ws = seed_workspace(&db).await;
    let pair = pod_pair(&db);

    // Warm the cache for this user while they still hold an admin token.
    let as_admin = make_jwt(ws.id, ws.admin, "admin");
    assert_eq!(
        authenticated_read(&pair.live.app, &as_admin).await.status(),
        StatusCode::OK,
        "premise: the admin token works and warms the cache"
    );
    assert_eq!(
        admin_only_create_key(&pair.live.app, &as_admin).await,
        StatusCode::CREATED,
        "premise: an admin token really can create a key, so a 403 below is \
         the role gate and not a broken route"
    );
    assert_redis_is_unreachable(&pair.dead).await;

    // The SAME user, now presenting a token whose signed role is viewer.
    let demoted = make_jwt(ws.id, ws.admin, "viewer");
    assert_eq!(
        admin_only_create_key(&pair.dead.app, &demoted).await,
        StatusCode::FORBIDDEN,
        "the degraded path must authorize the role the PRESENTED token carries, \
         not a higher one left in the cache by an earlier token"
    );
}

// ── The degraded path is observable, and bounded ──────────────────────────

/// Every action the gate takes must reach Prometheus with bounded labels, in
/// the WS2-3 vocabulary. Without a counter, a deployment can run for hours on
/// the degraded path and nobody finds out.
#[sqlx::test]
async fn every_auth_gate_action_is_counted_for_prometheus(db: PgPool) {
    let ws = seed_workspace(&db).await;
    let pair = pod_pair(&db);
    let token = make_jwt(ws.id, ws.viewer, "viewer");

    // PREMISE: a healthy request touches the counter for nothing at all.
    assert_eq!(
        authenticated_read(&pair.live.app, &token).await.status(),
        StatusCode::OK
    );
    for (reason, action) in [
        ("logout_unverifiable", "degrade_with_alert"),
        ("no_warm_session", "block"),
        ("revoked_durably", "block"),
    ] {
        assert_eq!(
            pair.live
                .state
                .metrics
                .auth_gate_engaged_count(reason, action),
            0,
            "premise: a fully verified request must not increment {reason}/{action}"
        );
    }
    assert_redis_is_unreachable(&pair.dead).await;

    // A served-but-unverifiable answer.
    assert_eq!(
        authenticated_read(&pair.dead.app, &token).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        pair.dead
            .state
            .metrics
            .auth_gate_engaged_count("logout_unverifiable", "degrade_with_alert"),
        1,
        "serving a session the gateway could not check must be counted"
    );

    // A refusal, on a pod that has never seen this user.
    let cold = build_pod(db.clone(), dead_url("redis"), Arc::new(DashMap::new()));
    assert_eq!(
        authenticated_read(&cold.app, &token).await.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "a pod with no warm entry has nothing to serve and must refuse"
    );
    assert_eq!(
        cold.state
            .metrics
            .auth_gate_engaged_count("no_warm_session", "block"),
        1,
        "a refusal must be counted too — block and degrade are both signals"
    );

    // And the exposition really carries the series, with the label names an
    // alert rule would match on.
    let exposed = cold.state.metrics.render_prometheus();
    assert!(
        exposed.contains(
            "secureprompt_auth_gate_engaged_total{reason=\"no_warm_session\",action=\"block\"} 1"
        ),
        "the counter must appear in /metrics; got:\n{exposed}"
    );
}

/// The window has to be bounded by something a reader can find. An entry older
/// than `DEGRADED_AUTH_CACHE_TTL_SECS` is no longer servable, and the age is
/// arranged rather than slept — the TTL seam is a pure function over seconds
/// precisely so this needs no 60-second test.
///
/// The Redis failure is still real: this pod's `redis.url` is a dead port.
#[sqlx::test]
async fn a_cached_session_older_than_the_window_is_refused(db: PgPool) {
    let ws = seed_workspace(&db).await;
    let pair = pod_pair(&db);
    let token = make_jwt(ws.id, ws.viewer, "viewer");

    // PREMISE + CONTROL: warmed normally, the same request is served.
    assert_eq!(
        authenticated_read(&pair.live.app, &token).await.status(),
        StatusCode::OK
    );
    assert_redis_is_unreachable(&pair.dead).await;
    assert_eq!(
        authenticated_read(&pair.dead.app, &token).await.status(),
        StatusCode::OK,
        "control: a fresh entry IS served, so the refusal below is the age"
    );

    // Age the existing entry past the window, changing nothing else.
    let entry = pair
        .cache
        .get(&ws.viewer)
        .expect("the warm entry written by the healthy path")
        .clone();
    pair.cache.insert(
        ws.viewer,
        CachedAuthEntry {
            cached_at: entry
                .cached_at
                .checked_sub(std::time::Duration::from_secs(
                    DEGRADED_AUTH_CACHE_TTL_SECS + 1,
                ))
                .expect("the host has been up longer than the auth window"),
            ..entry
        },
    );

    assert_eq!(
        authenticated_read(&pair.dead.app, &token).await.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "a session cached longer ago than the degraded window must not be \
         served — the window is what makes the fail-open bounded"
    );
}

/// A user who keeps sending requests through the outage must not thereby keep
/// their session alive forever. The degraded path serves from the entry; it
/// must not re-write it.
#[sqlx::test]
async fn the_degraded_path_does_not_extend_its_own_window(db: PgPool) {
    let ws = seed_workspace(&db).await;
    let pair = pod_pair(&db);
    let token = make_jwt(ws.id, ws.viewer, "viewer");

    assert_eq!(
        authenticated_read(&pair.live.app, &token).await.status(),
        StatusCode::OK
    );
    assert_redis_is_unreachable(&pair.dead).await;

    // Age the entry to the middle of the window, then spend three requests in
    // it. If the degraded path refreshed `cached_at`, the age would fall back
    // to ~0 and the window would restart on every request.
    let aged_by = DEGRADED_AUTH_CACHE_TTL_SECS / 2;
    let entry = pair.cache.get(&ws.viewer).expect("warm entry").clone();
    pair.cache.insert(
        ws.viewer,
        CachedAuthEntry {
            cached_at: entry
                .cached_at
                .checked_sub(std::time::Duration::from_secs(aged_by))
                .expect("the host has been up longer than the auth window"),
            ..entry
        },
    );

    for _ in 0..3 {
        assert_eq!(
            authenticated_read(&pair.dead.app, &token).await.status(),
            StatusCode::OK,
            "premise: each request really is being served on the degraded path"
        );
    }

    let age_after = pair
        .cache
        .get(&ws.viewer)
        .expect("the entry must still be there")
        .age_secs();
    assert!(
        age_after >= aged_by,
        "the degraded path reset the entry's age ({age_after}s < {aged_by}s), so \
         an active session would never age out of the window"
    );
}

/// The premise the whole `LogoutUnverifiable` degrade rests on.
///
/// Degrading on the jti blacklist is only defensible if a logout attempted
/// while Redis is down cannot report success — otherwise a user would watch
/// their session end and it would not have. `dashboard::auth::logout` returns
/// the Redis error rather than swallowing it, so the answer is never 204.
#[sqlx::test]
async fn logout_during_a_redis_outage_does_not_report_success(db: PgPool) {
    let ws = seed_workspace(&db).await;
    let pair = pod_pair(&db);
    let token = make_jwt(ws.id, ws.viewer, "viewer");

    let logout = |app: axum::Router, token: String| async move {
        app.oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/logout")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("router runs")
        .status()
    };

    // PREMISE + CONTROL THAT MUST DIFFER: with Redis up, this exact call
    // answers 204. So a non-204 below is the outage and not a broken route.
    assert_eq!(
        logout(pair.live.app.clone(), token.clone()).await,
        StatusCode::NO_CONTENT,
        "premise: logout succeeds against a live Redis"
    );
    assert_redis_is_unreachable(&pair.dead).await;

    // Warm the shared cache again so the request reaches the HANDLER on the
    // degraded path — otherwise the auth layer would refuse first and this
    // would prove nothing about logout.
    let fresh = make_jwt(ws.id, ws.viewer, "viewer");
    assert_eq!(
        authenticated_read(&pair.live.app, &fresh).await.status(),
        StatusCode::OK,
        "premise: the cache is warm, so logout reaches its handler"
    );

    let during_outage = logout(pair.dead.app.clone(), fresh).await;
    assert_ne!(
        during_outage,
        StatusCode::NO_CONTENT,
        "a logout that could not be recorded must not report success — the \
         degraded jti policy depends on this"
    );
    assert!(
        during_outage.is_server_error(),
        "and it must surface as a server error the caller can retry, got \
         {during_outage}"
    );
}

// ── The durable read, from a role that cannot bypass RLS ──────────────────

const RLS_ROLE: &str = "secureprompt_runner";
const RLS_PASSWORD: &str = "secureprompt";

async fn ensure_low_privilege_role(pool: &PgPool) {
    sqlx::raw_sql(&format!(
        "DO $$
         BEGIN
             CREATE ROLE {RLS_ROLE}
                 LOGIN PASSWORD '{RLS_PASSWORD}'
                 NOSUPERUSER CREATEDB CREATEROLE NOBYPASSRLS;
         EXCEPTION
             WHEN duplicate_object THEN NULL;
         END $$;"
    ))
    .execute(pool)
    .await
    .unwrap_or_else(|e| {
        panic!(
            "could not create the {RLS_ROLE} role ({e}). In CI this role is \
             created by scripts/ci/create-nonsuperuser-role.sh; locally the \
             connecting role needs CREATEROLE."
        )
    });

    sqlx::raw_sql(&format!(
        "GRANT USAGE ON SCHEMA public TO {RLS_ROLE};
         GRANT ALL ON ALL TABLES IN SCHEMA public TO {RLS_ROLE};
         GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO {RLS_ROLE};"
    ))
    .execute(pool)
    .await
    .expect("grants on the test database");
}

/// `session_revocation_audit` has FORCE ROW LEVEL SECURITY and a policy whose
/// predicate is NULL for every row when `app.current_workspace_id` is unset —
/// an unbound SELECT returns the EMPTY SET and reports no error. A watermark
/// read that hit that trap would answer "never revoked" for every user, and the
/// fail-closed behaviour this whole suite asserts would be silently off.
///
/// The `#[sqlx::test]` pool is a BYPASSRLS superuser and cannot observe the
/// mistake, so the read is repeated here through a NOSUPERUSER/NOBYPASSRLS
/// connection — the shape `session_revocation_tests.rs` established.
#[sqlx::test]
async fn the_durable_watermark_survives_row_level_security(db: PgPool) {
    use secureprompt_api::db::session_revocation_repo::SessionRevocationRepository;

    let ws = seed_workspace(&db).await;
    let actor_pod = build_pod(db.clone(), live_redis_url(), Arc::new(DashMap::new()));
    let admin = make_jwt(ws.id, ws.admin, "admin");
    assert_eq!(
        revoke(&actor_pod.app, &admin, ws.viewer).await,
        StatusCode::OK
    );

    // PREMISE: the superuser pool sees the row, so anything the low-privilege
    // pool cannot see is RLS and not an empty table.
    let rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM session_revocation_audit WHERE target_user_id = $1",
    )
    .bind(ws.viewer)
    .fetch_one(&db)
    .await
    .expect("premise count");
    assert_eq!(rows, 1, "premise: exactly one revocation row exists");

    ensure_low_privilege_role(&db).await;
    let options = (*db.connect_options())
        .clone()
        .username(RLS_ROLE)
        .password(RLS_PASSWORD);
    let low_privilege: PgPool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(options)
        .await
        .expect("low-privilege pool");

    // PREMISE: this connection really is powerless, or the assertion below
    // proves nothing.
    let (superuser, bypass): (bool, bool) =
        sqlx::query_as("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
            .fetch_one(&low_privilege)
            .await
            .expect("identity probe");
    assert!(!superuser, "premise: the probe role is a SUPERUSER");
    assert!(!bypass, "premise: the probe role has BYPASSRLS");

    // PREMISE: unbound, the table really does read as empty — the trap is live.
    let unbound: i64 = sqlx::query_scalar("SELECT count(*) FROM session_revocation_audit")
        .fetch_one(&low_privilege)
        .await
        .expect("an unbound read succeeds, which is the whole problem");
    assert_eq!(
        unbound, 0,
        "premise: with the GUC unset the policy hides every row and reports \
         no error"
    );

    let repo = SessionRevocationRepository::new(low_privilege.clone());
    let watermark = repo
        .latest_watermark(ws.id, ws.viewer)
        .await
        .expect("the durable read must succeed under RLS");
    assert!(
        watermark.is_some(),
        "the durable watermark read must bind the workspace GUC; without it \
         RLS returns the empty set and every user reads as never-revoked"
    );

    // CONTROL THAT MUST DIFFER: a user nobody revoked reads as None through
    // the same connection, so `Some` above is the row and not a constant.
    assert_eq!(
        repo.latest_watermark(ws.id, ws.other)
            .await
            .expect("read succeeds"),
        None,
        "control: an unrevoked user must read as no-watermark"
    );

    forget_watermark(ws.viewer).await;
}
