//! FU4 — listing the sessions a user holds, and ending ONE of them.
//!
//! # What WS4-3 left open, in its own words
//!
//! > no way to *list* sessions — revocation is all-or-nothing per user, since
//! > no session record exists.
//!
//! The premise of that sentence is what this suite disputes. A session record
//! DOES exist: `refresh_tokens` already gets exactly one row per sign-in
//! (`build_token_pair_body` → `RefreshTokenRepository::insert`) and one row per
//! rotation, linked by `replaced_by`. What was missing was not the record but
//! three things about it — a stable identity across rotation, the device that
//! opened it, and the access-token `jti` it is currently backing. FU4 adds
//! those three columns to the row that is already written, and no new table.
//!
//! Every test in this file fails at `c888b64`, before
//! `GET /v1/users/{id}/sessions` and `DELETE /v1/users/{id}/sessions/{sid}`
//! existed: the router answers 405 (the path `/{user_id}/sessions` was
//! registered for DELETE only) and 404 (the two-segment path was not
//! registered at all).
//!
//! Every "must be refused" test carries a POSITIVE CONTROL in the same body —
//! the same call, changed in exactly one dimension, that must succeed — for the
//! reason `session_revocation_tests.rs` gives: a 403 with no control could come
//! from a broken route, a bad fixture or the license gate, and the test would
//! pass while proving nothing.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use deadpool_redis::{redis::cmd, Config as RedisPoolConfig, Pool as RedisPool, Runtime};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use secureprompt_api::{
    app_state::AppState, db::refresh_token_repo::hash_refresh_token, http::build_router,
    http::middleware::jwt_auth::Claims, ml_sidecar::MlSidecarClient,
};
use secureprompt_common::config::{
    AppConfig, ClickhouseConfig, DatabaseConfig, JwtConfig, LicenseConfig, RedisConfig,
    ServerConfig, TelemetryConfig,
};
use serde_json::Value;
use sqlx::{postgres::PgConnectOptions, Connection, PgConnection, PgPool, Row};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

const TEST_JWT_SECRET: &str = "fu4-session-listing-test-secret";
const TEST_PASSWORD: &str = "test-password-1234";

// ── Harness ───────────────────────────────────────────────────────────────

fn redis_url() -> String {
    std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".into())
}

fn test_config() -> AppConfig {
    AppConfig {
        database: DatabaseConfig {
            url: "postgres://unused".into(),
            max_connections: 1,
        },
        redis: RedisConfig {
            url: redis_url(),
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
    RedisPoolConfig::from_url(redis_url())
        .create_pool(Some(Runtime::Tokio1))
        .expect("redis pool")
}

/// Tests share one real Redis. Keys are namespaced by fresh UUIDs so
/// collisions are impossible, but they are deleted anyway so a long local run
/// does not accumulate them.
async fn forget_keys(pool: &RedisPool, user_id: Uuid, jtis: &[String]) {
    let mut conn = pool.get().await.expect("redis checkout");
    let _: i64 = cmd("DEL")
        .arg(format!("session_revoked:{user_id}"))
        .query_async(&mut conn)
        .await
        .unwrap_or(0);
    for jti in jtis {
        let _: i64 = cmd("DEL")
            .arg(format!("jti_blacklist:{jti}"))
            .query_async(&mut conn)
            .await
            .unwrap_or(0);
    }
}

struct Workspace {
    id: Uuid,
    owner: Uuid,
    admin: Uuid,
    /// The subject whose sessions the tests list. A viewer on purpose:
    /// `decide_2fa` sends Owner/Admin logins down the 202 enrollment branch, so
    /// a viewer is the only fixture role that can complete a REAL
    /// `POST /v1/auth/token` and produce a real session row.
    viewer: Uuid,
    viewer_email: String,
}

async fn seed_workspace(pool: &PgPool) -> Workspace {
    let id = Uuid::new_v4();
    let suffix = Uuid::new_v4().simple().to_string();
    sqlx::query(
        "INSERT INTO workspaces (id, name, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(id)
    .bind(format!("fu4 {suffix}"))
    .execute(pool)
    .await
    .expect("seed workspace");

    let password_hash = super::fixtures::hash_password(TEST_PASSWORD);
    let mut ids = Vec::new();
    for role in ["owner", "admin", "viewer"] {
        let user_id = Uuid::new_v4();
        let email = format!("{role}-{suffix}@example.com");
        sqlx::query(
            "INSERT INTO users (id, workspace_id, email, password_hash, role, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, NOW(), NOW())",
        )
        .bind(user_id)
        .bind(id)
        .bind(&email)
        .bind(&password_hash)
        .bind(role)
        .execute(pool)
        .await
        .expect("seed user");
        ids.push((user_id, email));
    }
    Workspace {
        id,
        owner: ids[0].0,
        admin: ids[1].0,
        viewer: ids[2].0,
        viewer_email: ids[2].1.clone(),
    }
}

async fn json_body(resp: axum::response::Response) -> Value {
    use http_body_util::BodyExt;
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("json body")
    }
}

/// The access-token jtis a user's refresh rows carry, read from inside the
/// workspace's armed scope.
///
/// Purely a CLEANUP read — the tests use it to delete the Redis blacklist keys
/// a run leaves behind, and nothing asserts on it. It is scoped anyway because
/// the unscoped version does not merely return the wrong answer under a
/// non-bypassing role: it raises `22P02` and the old `unwrap_or_default()`
/// swallowed that into an empty list, so the keys silently survived into the
/// next test.
async fn jtis_of(pool: &PgPool, workspace_id: Uuid, user_id: Uuid) -> Vec<String> {
    let mut scope = super::fixtures::scoped(pool, workspace_id).await;
    sqlx::query_scalar(
        "SELECT access_jti FROM refresh_tokens WHERE user_id = $1 AND access_jti IS NOT NULL",
    )
    .bind(user_id)
    .fetch_all(&mut *scope)
    .await
    .unwrap_or_default()
}

/// What one sign-in gives back. `access` and `refresh` are the real tokens the
/// gateway minted, so the tests below drive the same loop a browser does.
struct SignIn {
    access: String,
    refresh: String,
}

/// A REAL `POST /v1/auth/token`, carrying the two headers that describe the
/// device. This is the only way a session row acquires device context — the
/// tests never write those columns directly, so a green assertion is evidence
/// the login path recorded them.
async fn sign_in(app: &axum::Router, email: &str, ip: &str, user_agent: &str) -> SignIn {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/token")
                .header("content-type", "application/json")
                .header("x-forwarded-for", ip)
                .header("user-agent", user_agent)
                .body(Body::from(
                    serde_json::json!({ "email": email, "password": TEST_PASSWORD }).to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("router runs");
    let status = response.status();
    let body = json_body(response).await;
    assert_eq!(status, StatusCode::OK, "sign-in must succeed: {body}");
    SignIn {
        access: body["access_token"]
            .as_str()
            .expect("access_token")
            .to_owned(),
        refresh: body["refresh_token"]
            .as_str()
            .expect("refresh_token")
            .to_owned(),
    }
}

async fn refresh(app: &axum::Router, refresh_token: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/refresh")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "refresh_token": refresh_token }).to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("router runs")
}

async fn list_sessions(
    app: &axum::Router,
    actor_token: &str,
    target: Uuid,
) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/users/{target}/sessions"))
                .header("authorization", format!("Bearer {actor_token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("router runs")
}

async fn end_session(
    app: &axum::Router,
    actor_token: &str,
    target: Uuid,
    session_id: Uuid,
) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/users/{target}/sessions/{session_id}"))
                .header("authorization", format!("Bearer {actor_token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("router runs")
}

/// A plain authenticated read. `GET /v1/users` is open to every role, so a 401
/// here is the auth layer talking and not an RBAC decision.
async fn authenticated_read(app: &axum::Router, token: &str) -> StatusCode {
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
        .status()
}

fn sessions_of(body: &Value) -> &Vec<Value> {
    body["sessions"]
        .as_array()
        .unwrap_or_else(|| panic!("response has no `sessions` array: {body}"))
}

fn session_id(entry: &Value) -> Uuid {
    Uuid::parse_str(
        entry["session_id"]
            .as_str()
            .unwrap_or_else(|| panic!("session entry has no session_id: {entry}")),
    )
    .expect("session_id is a uuid")
}

const CHROME_MAC: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
                          (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";
const FIREFOX_WINDOWS: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0";

// ── Criterion 1: an admin can SEE what they are about to terminate ─────────

/// The headline. Two sign-ins from two devices are two listed sessions, each
/// carrying the device that opened it — which is the difference between "you
/// have some sessions" and "one of these is the laptop you lost".
#[sqlx::test]
async fn two_sign_ins_are_two_listed_sessions_each_naming_its_own_device(pool: PgPool) {
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());

    let laptop = sign_in(&app, &ws.viewer_email, "203.0.113.7", CHROME_MAC).await;
    let desktop = sign_in(&app, &ws.viewer_email, "198.51.100.22", FIREFOX_WINDOWS).await;

    // PREMISE: both tokens really are live sessions. Without this, a listing of
    // two rows could be two dead rows.
    assert_eq!(
        authenticated_read(&app, &laptop.access).await,
        StatusCode::OK
    );
    assert_eq!(
        authenticated_read(&app, &desktop.access).await,
        StatusCode::OK
    );

    let admin_token = make_jwt(ws.id, ws.admin, "admin");
    let response = list_sessions(&app, &admin_token, ws.viewer).await;
    let status = response.status();
    let body = json_body(response).await;
    assert_eq!(status, StatusCode::OK, "listing must succeed: {body}");

    let sessions = sessions_of(&body);
    assert_eq!(
        sessions.len(),
        2,
        "two sign-ins must be two sessions, not one and not four: {body}"
    );

    let mut seen: Vec<(&str, &str)> = sessions
        .iter()
        .map(|s| {
            (
                s["client_ip"].as_str().unwrap_or("<none>"),
                s["client"].as_str().unwrap_or("<none>"),
            )
        })
        .collect();
    seen.sort_unstable();
    assert_eq!(
        seen,
        vec![
            ("198.51.100.22", "Firefox on Windows"),
            ("203.0.113.7", "Chrome on macOS"),
        ],
        "each session must name the device that opened it, or an admin cannot \
         tell which one to end: {body}"
    );

    // CONTROL THAT MUST DIFFER: the admin's own listing is empty. The viewer's
    // two sessions must not appear under every user id.
    let mine = list_sessions(&app, &admin_token, ws.admin).await;
    let mine_body = json_body(mine).await;
    assert!(
        sessions_of(&mine_body).is_empty(),
        "the admin has never signed in through /v1/auth/token, so their listing \
         must be empty — otherwise the query is not filtering by user: {mine_body}"
    );

    forget_keys(&redis_pool().await, ws.viewer, &[]).await;
}

/// A refresh is the SAME session continuing, not a new one. `refresh_tokens`
/// gets a new row per rotation, so a listing that counted rows would report a
/// browser open for a day as ninety-six devices.
#[sqlx::test]
async fn rotating_a_session_does_not_turn_it_into_two(pool: PgPool) {
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());

    let laptop = sign_in(&app, &ws.viewer_email, "203.0.113.7", CHROME_MAC).await;
    let admin_token = make_jwt(ws.id, ws.admin, "admin");

    let before = json_body(list_sessions(&app, &admin_token, ws.viewer).await).await;
    assert_eq!(
        sessions_of(&before).len(),
        1,
        "premise: one session: {before}"
    );
    let original = session_id(&sessions_of(&before)[0]);

    let rotated = refresh(&app, &laptop.refresh).await;
    assert_eq!(
        rotated.status(),
        StatusCode::OK,
        "premise: the refresh token must rotate"
    );

    // PREMISE: the rotation really did add a row. If it did not, "still one
    // session" below would be true for the wrong reason.
    let mut scope = super::fixtures::scoped(&pool, ws.id).await;
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM refresh_tokens WHERE user_id = $1")
        .bind(ws.viewer)
        .fetch_one(&mut *scope)
        .await
        .expect("count rows");
    assert_eq!(rows, 2, "premise: rotation writes a second refresh row");
    drop(scope);

    let after = json_body(list_sessions(&app, &admin_token, ws.viewer).await).await;
    assert_eq!(
        sessions_of(&after).len(),
        1,
        "two refresh rows in one rotation chain are ONE session: {after}"
    );
    assert_eq!(
        session_id(&sessions_of(&after)[0]),
        original,
        "the session keeps its identity across rotation, or an admin cannot \
         revoke the session they were just looking at: {after}"
    );

    forget_keys(&redis_pool().await, ws.viewer, &[]).await;
}

/// A session the server never saw end — closed laptop, killed browser — leaves
/// no orphan. Liveness is `revoked_at IS NULL AND expires_at > NOW()` on the
/// row that already exists, so an abandoned session ages out of the listing
/// without anything having to notice it stopped.
#[sqlx::test]
async fn a_session_the_server_never_saw_end_ages_out_of_the_listing(pool: PgPool) {
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());

    sign_in(&app, &ws.viewer_email, "203.0.113.7", CHROME_MAC).await;
    let still_open = sign_in(&app, &ws.viewer_email, "198.51.100.22", FIREFOX_WINDOWS).await;
    let admin_token = make_jwt(ws.id, ws.admin, "admin");

    let before = json_body(list_sessions(&app, &admin_token, ws.viewer).await).await;
    assert_eq!(sessions_of(&before).len(), 2, "premise: two: {before}");

    // The laptop was closed and never came back. Nothing tells the gateway;
    // the refresh row simply reaches its own expiry.
    let aged: u64 = {
        let mut scope = super::fixtures::scoped(&pool, ws.id).await;
        let affected = sqlx::query(
            "UPDATE refresh_tokens SET expires_at = NOW() - INTERVAL '1 second'
             WHERE user_id = $1 AND client_ip = '203.0.113.7'",
        )
        .bind(ws.viewer)
        .execute(&mut *scope)
        .await
        .expect("age the row")
        .rows_affected();
        scope.commit().await.expect("commit the aged row");
        affected
    };
    assert_eq!(aged, 1, "premise: exactly one row was aged out");

    let after = json_body(list_sessions(&app, &admin_token, ws.viewer).await).await;
    let sessions = sessions_of(&after);
    assert_eq!(
        sessions.len(),
        1,
        "an expired session must leave the listing on its own: {after}"
    );
    assert_eq!(
        sessions[0]["client_ip"], "198.51.100.22",
        "and it must be the OTHER one that survived: {after}"
    );

    // CONTROL THAT MUST DIFFER: the surviving session still works.
    assert_eq!(
        authenticated_read(&app, &still_open.access).await,
        StatusCode::OK
    );

    forget_keys(&redis_pool().await, ws.viewer, &[]).await;
}

/// The listing describes sessions; it must not hand out the material that
/// authenticates them.
#[sqlx::test]
async fn the_listing_never_returns_the_token_hash_or_the_jti(pool: PgPool) {
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());
    let signed_in = sign_in(&app, &ws.viewer_email, "203.0.113.7", CHROME_MAC).await;

    let admin_token = make_jwt(ws.id, ws.admin, "admin");
    let body = json_body(list_sessions(&app, &admin_token, ws.viewer).await).await;
    assert_eq!(sessions_of(&body).len(), 1, "premise: one session: {body}");

    // PREMISE: the values we are looking for really are stored, so their
    // absence from the response is the handler's doing and not an empty table.
    let stored: (String, Option<String>) = {
        let mut scope = super::fixtures::scoped(&pool, ws.id).await;
        sqlx::query_as("SELECT token_hash, access_jti FROM refresh_tokens WHERE user_id = $1")
            .bind(ws.viewer)
            .fetch_one(&mut *scope)
            .await
            .expect("the row stores a hash and a jti")
    };
    let jti = stored
        .1
        .expect("premise: the sign-in recorded its access jti");

    let rendered = body.to_string();
    assert!(
        !rendered.contains(&stored.0),
        "the refresh token hash must never appear in a listing: {rendered}"
    );
    assert!(
        !rendered.contains(&jti),
        "the access-token jti must never appear in a listing — it is the key of \
         the blacklist that revokes it: {rendered}"
    );
    assert!(
        !rendered.contains(&signed_in.refresh),
        "and certainly not the refresh token itself: {rendered}"
    );

    forget_keys(&redis_pool().await, ws.viewer, &[jti]).await;
}

// ── Criterion 2: revocation is no longer all-or-nothing ───────────────────

/// The gap WS4-3 named, closed. Ending ONE session must leave the others
/// signed in — otherwise this is the old lever with a longer URL.
#[sqlx::test]
async fn ending_one_session_leaves_the_other_signed_in(pool: PgPool) {
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());

    let lost = sign_in(&app, &ws.viewer_email, "203.0.113.7", CHROME_MAC).await;
    let kept = sign_in(&app, &ws.viewer_email, "198.51.100.22", FIREFOX_WINDOWS).await;
    let admin_token = make_jwt(ws.id, ws.admin, "admin");

    // PREMISE: both work now, so the 401 below is the revocation.
    assert_eq!(authenticated_read(&app, &lost.access).await, StatusCode::OK);
    assert_eq!(authenticated_read(&app, &kept.access).await, StatusCode::OK);

    let listed = json_body(list_sessions(&app, &admin_token, ws.viewer).await).await;
    let target = sessions_of(&listed)
        .iter()
        .find(|s| s["client_ip"] == "203.0.113.7")
        .unwrap_or_else(|| panic!("the lost laptop must be listed: {listed}"));
    let target_id = session_id(target);

    let response = end_session(&app, &admin_token, ws.viewer, target_id).await;
    let status = response.status();
    let ended = json_body(response).await;
    assert_eq!(status, StatusCode::OK, "ending one session: {ended}");

    assert_eq!(
        authenticated_read(&app, &lost.access).await,
        StatusCode::UNAUTHORIZED,
        "the ended session's NEXT request must 401"
    );
    // CONTROL THAT MUST DIFFER — this is the whole point of the task.
    assert_eq!(
        authenticated_read(&app, &kept.access).await,
        StatusCode::OK,
        "ending ONE session must leave the other signed in; if this 401s the \
         endpoint is WS4-3's all-or-nothing lever wearing a session id"
    );

    // And the ended session cannot reconstitute itself through refresh, while
    // the kept one still can.
    assert_eq!(
        refresh(&app, &lost.refresh).await.status(),
        StatusCode::UNAUTHORIZED,
        "the ended session's refresh chain must be closed too, or it mints a \
         replacement within the access-token lifetime"
    );
    assert_eq!(
        refresh(&app, &kept.refresh).await.status(),
        StatusCode::OK,
        "control: the surviving session must still rotate"
    );

    let remaining = json_body(list_sessions(&app, &admin_token, ws.viewer).await).await;
    assert_eq!(
        sessions_of(&remaining).len(),
        1,
        "the ended session must leave the listing: {remaining}"
    );

    let jtis: Vec<String> = jtis_of(&pool, ws.id, ws.viewer).await;
    forget_keys(&redis_pool().await, ws.viewer, &jtis).await;
}

/// An ended device retries its refresh once. That retry must not be read as a
/// stolen token, because the gateway's answer to a stolen token is
/// `revoke_all_for_user` — which would terminate every OTHER session the person
/// holds and undo the narrow revocation that had just been performed.
///
/// `replaced_by` is what separates the two cases, and this test drives BOTH
/// through the real `/v1/auth/refresh` in one body so the distinction cannot be
/// asserted by a mock.
#[sqlx::test]
async fn a_revoked_refresh_token_is_not_mistaken_for_a_stolen_one(pool: PgPool) {
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());

    let ended = sign_in(&app, &ws.viewer_email, "203.0.113.7", CHROME_MAC).await;
    let bystander = sign_in(&app, &ws.viewer_email, "198.51.100.22", FIREFOX_WINDOWS).await;
    let admin_token = make_jwt(ws.id, ws.admin, "admin");

    let listed = json_body(list_sessions(&app, &admin_token, ws.viewer).await).await;
    let target = sessions_of(&listed)
        .iter()
        .find(|s| s["client_ip"] == "203.0.113.7")
        .unwrap_or_else(|| panic!("the ended session must be listed: {listed}"));
    assert_eq!(
        end_session(&app, &admin_token, ws.viewer, session_id(target))
            .await
            .status(),
        StatusCode::OK
    );

    // The ended device retries. 401, and NOTHING else happens.
    assert_eq!(
        refresh(&app, &ended.refresh).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let survivors: i64 = {
        let mut scope = super::fixtures::scoped(&pool, ws.id).await;
        sqlx::query_scalar(
            "SELECT count(*) FROM refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL",
        )
        .bind(ws.viewer)
        .fetch_one(&mut *scope)
        .await
        .expect("count")
    };
    assert_eq!(
        survivors, 1,
        "retrying a revoked refresh token must not revoke the user's other \
         sessions — that is `revoke_all_for_user` firing on a token that was \
         never used twice"
    );

    // CONTROL THAT MUST DIFFER: a REAL replay — rotate first, then present the
    // spent token — still triggers revoke-all, so the branch above narrowed the
    // response without losing the detection (threat T-05-03).
    let rotated = refresh(&app, &bystander.refresh).await;
    assert_eq!(
        rotated.status(),
        StatusCode::OK,
        "premise: the bystander's token must rotate first, or the next call is \
         not a replay"
    );
    assert_eq!(
        refresh(&app, &bystander.refresh).await.status(),
        StatusCode::UNAUTHORIZED,
        "the spent token must not work twice"
    );
    let after_replay: i64 = {
        let mut scope = super::fixtures::scoped(&pool, ws.id).await;
        sqlx::query_scalar(
            "SELECT count(*) FROM refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL",
        )
        .bind(ws.viewer)
        .fetch_one(&mut *scope)
        .await
        .expect("count")
    };
    assert_eq!(
        after_replay, 0,
        "control: a genuine replay must still revoke every active refresh row"
    );

    let jtis: Vec<String> = jtis_of(&pool, ws.id, ws.viewer).await;
    forget_keys(&redis_pool().await, ws.viewer, &jtis).await;
}

/// Ending one session must be audited exactly as ending all of them is, and
/// the row must say WHICH session — otherwise the trail cannot distinguish
/// "ended one device" from "ended everything".
#[sqlx::test]
async fn ending_one_session_writes_an_audit_row_naming_that_session(pool: PgPool) {
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());
    let signed_in = sign_in(&app, &ws.viewer_email, "203.0.113.7", CHROME_MAC).await;
    let admin_token = make_jwt(ws.id, ws.admin, "admin");

    // PREMISE: the table starts empty, so a row found afterwards was written
    // by this action.
    let before: i64 = {
        let mut scope = super::fixtures::scoped(&pool, ws.id).await;
        sqlx::query_scalar("SELECT count(*) FROM session_revocation_audit")
            .fetch_one(&mut *scope)
            .await
            .expect("premise count")
    };
    assert_eq!(before, 0, "premise: the audit table starts empty");

    let listed = json_body(list_sessions(&app, &admin_token, ws.viewer).await).await;
    let target_id = session_id(&sessions_of(&listed)[0]);
    assert_eq!(
        end_session(&app, &admin_token, ws.viewer, target_id)
            .await
            .status(),
        StatusCode::OK
    );

    let mut scope = super::fixtures::scoped(&pool, ws.id).await;
    let row = sqlx::query(
        "SELECT workspace_id, actor_user_id, actor_role, target_user_id, target_role,
                session_id, refresh_tokens_revoked
         FROM session_revocation_audit",
    )
    .fetch_one(&mut *scope)
    .await
    .expect("exactly one audit row");
    drop(scope);
    assert_eq!(row.get::<Uuid, _>("workspace_id"), ws.id);
    assert_eq!(row.get::<Uuid, _>("actor_user_id"), ws.admin);
    assert_eq!(row.get::<String, _>("actor_role"), "admin");
    assert_eq!(row.get::<Uuid, _>("target_user_id"), ws.viewer);
    assert_eq!(row.get::<String, _>("target_role"), "viewer");
    assert_eq!(
        row.get::<Option<Uuid>, _>("session_id"),
        Some(target_id),
        "a per-session revocation must name the session it ended"
    );
    assert_eq!(
        row.get::<i64, _>("refresh_tokens_revoked"),
        1,
        "and count what it actually closed"
    );

    let _ = signed_in;
    let jtis: Vec<String> = jtis_of(&pool, ws.id, ws.viewer).await;
    forget_keys(&redis_pool().await, ws.viewer, &jtis).await;
}

/// WS4-3's user-wide lever writes `session_id = NULL`. The two shapes must be
/// distinguishable in the trail, or an auditor reading it cannot tell an
/// administrator who ended one laptop from one who ended a person's access.
#[sqlx::test]
async fn the_user_wide_lever_still_records_itself_as_user_wide(pool: PgPool) {
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());
    sign_in(&app, &ws.viewer_email, "203.0.113.7", CHROME_MAC).await;
    let admin_token = make_jwt(ws.id, ws.admin, "admin");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/users/{}/sessions", ws.viewer))
                .header("authorization", format!("Bearer {admin_token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("router runs");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "WS4-3's route must keep working unchanged"
    );

    let session_id: Option<Uuid> = {
        let mut scope = super::fixtures::scoped(&pool, ws.id).await;
        sqlx::query_scalar("SELECT session_id FROM session_revocation_audit")
            .fetch_one(&mut *scope)
            .await
            .expect("one audit row")
    };
    assert_eq!(
        session_id, None,
        "a user-wide revocation names no session; NULL is what distinguishes it"
    );

    forget_keys(&redis_pool().await, ws.viewer, &[]).await;
}

// ── Criterion 3: who may look, and who may end ────────────────────────────

/// Self-service. A viewer may see and end their OWN sessions without being an
/// administrator: it is their own data, "sign my other laptop out" is the
/// commonest real use of this feature, and `POST /v1/auth/logout` cannot do it
/// (it revokes every refresh row the user holds).
///
/// This does not widen WS4-3: the user-WIDE lever
/// `DELETE /v1/users/{id}/sessions` keeps its Admin-and-above gate, asserted
/// below in the same test.
#[sqlx::test]
async fn a_user_may_see_and_end_their_own_sessions_without_being_an_admin(pool: PgPool) {
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());

    let phone = sign_in(&app, &ws.viewer_email, "203.0.113.7", CHROME_MAC).await;
    let here = sign_in(&app, &ws.viewer_email, "198.51.100.22", FIREFOX_WINDOWS).await;

    let listed = json_body(list_sessions(&app, &here.access, ws.viewer).await).await;
    let sessions = sessions_of(&listed);
    assert_eq!(
        sessions.len(),
        2,
        "a user must be able to see their own sessions: {listed}"
    );

    // The session the caller is holding is marked, so "sign out my other
    // devices" does not mean "sign myself out and wonder why".
    let current: Vec<&Value> = sessions
        .iter()
        .filter(|s| s["is_current"] == Value::Bool(true))
        .collect();
    assert_eq!(
        current.len(),
        1,
        "exactly one listed session is the caller's own: {listed}"
    );
    assert_eq!(
        current[0]["client_ip"], "198.51.100.22",
        "and it is the one whose token is making this request: {listed}"
    );

    let other = sessions
        .iter()
        .find(|s| s["is_current"] != Value::Bool(true))
        .expect("the other session");
    assert_eq!(
        end_session(&app, &here.access, ws.viewer, session_id(other))
            .await
            .status(),
        StatusCode::OK,
        "a user may end their own other session"
    );
    assert_eq!(
        authenticated_read(&app, &phone.access).await,
        StatusCode::UNAUTHORIZED,
        "the other device is signed out"
    );
    // CONTROL THAT MUST DIFFER: the caller is still signed in.
    assert_eq!(
        authenticated_read(&app, &here.access).await,
        StatusCode::OK,
        "ending another device must not sign the caller out"
    );

    // WS4-3's user-wide lever is UNCHANGED: still Admin and above.
    let wide = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/users/{}/sessions", ws.viewer))
                .header("authorization", format!("Bearer {}", here.access))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("router runs");
    assert_eq!(
        wide.status(),
        StatusCode::FORBIDDEN,
        "per-session self-service must not have widened the user-wide lever"
    );

    let jtis: Vec<String> = jtis_of(&pool, ws.id, ws.viewer).await;
    forget_keys(&redis_pool().await, ws.viewer, &jtis).await;
}

/// A listing is a read of somebody's IP addresses and devices. It is gated by
/// the SAME ladder that gates ending their sessions — if you may not end it,
/// you may not look at it.
#[sqlx::test]
async fn a_viewer_cannot_read_another_members_sessions_but_an_admin_can(pool: PgPool) {
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());
    sign_in(&app, &ws.viewer_email, "203.0.113.7", CHROME_MAC).await;

    // A second viewer, so the actor and the target are different people at the
    // same rank — the case a bare "minimum role" gate would wave through.
    let nosy = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, workspace_id, email, password_hash, role, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'viewer', NOW(), NOW())",
    )
    .bind(nosy)
    .bind(ws.id)
    .bind(format!("nosy-{}@example.com", Uuid::new_v4().simple()))
    .bind(super::fixtures::hash_password(TEST_PASSWORD))
    .execute(&pool)
    .await
    .expect("seed second viewer");

    let nosy_token = make_jwt(ws.id, nosy, "viewer");
    assert_eq!(
        list_sessions(&app, &nosy_token, ws.viewer).await.status(),
        StatusCode::FORBIDDEN,
        "a viewer must not be able to read another member's devices"
    );

    // POSITIVE CONTROL: the identical call as an admin succeeds, so the 403 is
    // the role gate and not a broken route.
    let admin_token = make_jwt(ws.id, ws.admin, "admin");
    let allowed = list_sessions(&app, &admin_token, ws.viewer).await;
    assert_eq!(
        allowed.status(),
        StatusCode::OK,
        "control: an admin performing the same call must succeed"
    );
    let body = json_body(allowed).await;
    assert_eq!(
        sessions_of(&body).len(),
        1,
        "and must see the session: {body}"
    );

    // CONTROL THAT MUST DIFFER: the same viewer reading their OWN sessions is
    // allowed, so the 403 above is about WHOSE sessions and not about rank.
    assert_eq!(
        list_sessions(&app, &nosy_token, nosy).await.status(),
        StatusCode::OK,
        "control: a viewer reading their own sessions must be allowed"
    );

    // And unauthenticated is 401, not 403 — a different layer.
    let anonymous = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/users/{}/sessions", ws.viewer))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("router runs");
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);

    forget_keys(&redis_pool().await, ws.viewer, &[]).await;
}

/// WS4-3's privilege inversion rule holds for the narrow lever too: an Admin
/// may not end an Owner's session, and may not read the Owner's devices
/// either.
#[sqlx::test]
async fn an_admin_may_not_read_or_end_an_owners_sessions(pool: PgPool) {
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());

    // Give the owner a session without going through the 2FA-gated login path.
    // Seeded through the workspace's armed scope: `refresh_tokens` is
    // ENABLE + FORCE ROW LEVEL SECURITY, so on the bare pool this INSERT is
    // refused with 42501 under any role that cannot bypass RLS.
    let owner_session = Uuid::new_v4();
    let mut owner_scope = super::fixtures::scoped(&pool, ws.id).await;
    sqlx::query(
        "INSERT INTO refresh_tokens
             (id, user_id, workspace_id, token_hash, expires_at, created_at,
              session_id, access_jti, client_ip, client_descriptor)
         VALUES ($1, $2, $3, $4, NOW() + INTERVAL '1 hour', NOW(), $5, $6,
                 '203.0.113.9', 'Chrome on macOS')",
    )
    .bind(Uuid::new_v4())
    .bind(ws.owner)
    .bind(ws.id)
    .bind(hash_refresh_token(&format!(
        "rt-{}",
        Uuid::new_v4().simple()
    )))
    .bind(owner_session)
    .bind(Uuid::new_v4().to_string())
    .execute(&mut *owner_scope)
    .await
    .expect("seed owner session");
    owner_scope
        .commit()
        .await
        .expect("commit the seeded owner session");

    let admin_token = make_jwt(ws.id, ws.admin, "admin");
    assert_eq!(
        list_sessions(&app, &admin_token, ws.owner).await.status(),
        StatusCode::FORBIDDEN,
        "an admin must not read an owner's devices"
    );
    assert_eq!(
        end_session(&app, &admin_token, ws.owner, owner_session)
            .await
            .status(),
        StatusCode::FORBIDDEN,
        "an admin must not end an owner's session"
    );

    // CONTROL THAT MUST DIFFER: the same calls in the other direction work.
    let owner_token = make_jwt(ws.id, ws.owner, "owner");
    assert_eq!(
        list_sessions(&app, &owner_token, ws.admin).await.status(),
        StatusCode::OK,
        "control: an owner reading an admin's sessions must succeed"
    );
    let owner_reads_own = list_sessions(&app, &owner_token, ws.owner).await;
    assert_eq!(owner_reads_own.status(), StatusCode::OK);
    let body = json_body(owner_reads_own).await;
    assert_eq!(
        sessions_of(&body).len(),
        1,
        "control: the owner's session really exists, so the two 403s above are \
         the ladder and not an empty table: {body}"
    );
    assert_eq!(
        end_session(&app, &owner_token, ws.owner, owner_session)
            .await
            .status(),
        StatusCode::OK,
        "control: the owner may end their own session"
    );

    forget_keys(&redis_pool().await, ws.owner, &[]).await;
}

// ── TRAP: cross-tenant ────────────────────────────────────────────────────

/// Neither the listing nor the narrow revocation may reach across workspaces,
/// and the refusal must not confirm that the foreign user exists.
#[sqlx::test]
async fn sessions_cannot_be_read_or_ended_across_workspaces(pool: PgPool) {
    let a = seed_workspace(&pool).await;
    let b = seed_workspace(&pool).await;
    let app = build_app(pool.clone());

    let victim = sign_in(&app, &b.viewer_email, "203.0.113.7", CHROME_MAC).await;
    sign_in(&app, &a.viewer_email, "198.51.100.22", FIREFOX_WINDOWS).await;

    let admin_a = make_jwt(a.id, a.admin, "admin");
    let admin_b = make_jwt(b.id, b.admin, "admin");

    // Learn B's real session id as B's admin, so the cross-tenant attempt below
    // uses a REAL id rather than a random one that would 404 anyway.
    let b_listing = json_body(list_sessions(&app, &admin_b, b.viewer).await).await;
    let b_session = session_id(&sessions_of(&b_listing)[0]);

    assert_eq!(
        list_sessions(&app, &admin_a, b.viewer).await.status(),
        StatusCode::NOT_FOUND,
        "a foreign user must be indistinguishable from a nonexistent one"
    );
    assert_eq!(
        list_sessions(&app, &admin_a, Uuid::new_v4()).await.status(),
        StatusCode::NOT_FOUND,
        "and a nonexistent user must give the identical answer"
    );
    assert_eq!(
        end_session(&app, &admin_a, b.viewer, b_session)
            .await
            .status(),
        StatusCode::NOT_FOUND,
        "a real session id from another workspace must not be reachable"
    );

    assert_eq!(
        authenticated_read(&app, &victim.access).await,
        StatusCode::OK,
        "workspace B's session must be untouched"
    );
    // Read from INSIDE WORKSPACE B's OWN armed scope. A bare-pool read is
    // filtered to nothing under a non-bypassing role, which would make every
    // claim about workspace B below a claim about the reader instead.
    let active_b: i64 = {
        let mut b_scope = super::fixtures::scoped(&pool, b.id).await;
        sqlx::query_scalar(
            "SELECT count(*) FROM refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL",
        )
        .bind(b.viewer)
        .fetch_one(&mut *b_scope)
        .await
        .expect("count")
    };
    assert_eq!(active_b, 1, "workspace B's refresh row must survive");

    // POSITIVE CONTROL: the same admin inside their OWN workspace works, so the
    // 404s above are tenancy and not a broken route.
    let own = list_sessions(&app, &admin_a, a.viewer).await;
    assert_eq!(own.status(), StatusCode::OK);
    let own_body = json_body(own).await;
    assert_eq!(sessions_of(&own_body).len(), 1);
    assert_eq!(
        end_session(
            &app,
            &admin_a,
            a.viewer,
            session_id(&sessions_of(&own_body)[0])
        )
        .await
        .status(),
        StatusCode::OK,
        "control: in-workspace narrow revocation must succeed"
    );

    // CONTROL for the absence-claim: the identical query, on the identical
    // table, from workspace A's scope returns 1. Without it a zero from B's
    // scope would be equally well explained by a broken query or by an
    // end-session route that wrote no audit row at all.
    let rows_a: i64 = {
        let mut a_scope = super::fixtures::scoped(&pool, a.id).await;
        sqlx::query_scalar("SELECT count(*) FROM session_revocation_audit WHERE workspace_id = $1")
            .bind(a.id)
            .fetch_one(&mut *a_scope)
            .await
            .expect("count")
    };
    assert_eq!(
        rows_a, 1,
        "control: the in-workspace narrow revocation must have written A's \
         audit row, or the zero asserted for B below proves nothing"
    );

    let rows: i64 = {
        let mut b_scope = super::fixtures::scoped(&pool, b.id).await;
        sqlx::query_scalar("SELECT count(*) FROM session_revocation_audit WHERE workspace_id = $1")
            .bind(b.id)
            .fetch_one(&mut *b_scope)
            .await
            .expect("count")
    };
    assert_eq!(rows, 0, "no audit row may be written for workspace B");

    forget_keys(&redis_pool().await, a.viewer, &[]).await;
    forget_keys(&redis_pool().await, b.viewer, &[]).await;
}

// ── TRAP: RLS, proved from a role that cannot bypass it ───────────────────

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

async fn low_privilege_connection(pool: &PgPool) -> PgConnection {
    ensure_low_privilege_role(pool).await;
    let options: PgConnectOptions = (*pool.connect_options())
        .clone()
        .username(RLS_ROLE)
        .password(RLS_PASSWORD);
    let mut conn = PgConnection::connect_with(&options)
        .await
        .expect("low-privilege connection");

    let row = sqlx::query(
        "SELECT current_user::text AS who, rolsuper, rolbypassrls \
         FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&mut conn)
    .await
    .expect("identity probe");
    assert_eq!(row.get::<String, _>("who"), RLS_ROLE);
    assert!(
        !row.get::<bool, _>("rolsuper"),
        "premise: the probe role is a SUPERUSER, so this test proves nothing"
    );
    assert!(
        !row.get::<bool, _>("rolbypassrls"),
        "premise: the probe role has BYPASSRLS, so this test proves nothing"
    );
    conn
}

/// The session listing reads `refresh_tokens`, which has carried FORCE ROW
/// LEVEL SECURITY since migration 002. The silent-zero trap therefore applies
/// to it in full: with `app.current_workspace_id` unset the policy predicate is
/// NULL for every row, the SELECT SUCCEEDS, and it returns the EMPTY SET — an
/// admin would be told "this account has no active sessions" and believe it.
///
/// `#[sqlx::test]` connects as a BYPASSRLS superuser and cannot observe any of
/// that, which is why this test opens its own NOSUPERUSER/NOBYPASSRLS
/// connection.
///
/// STATED PLAINLY: this is the ONE test in this file that already passes at
/// `c888b64`, because migration 002 armed the policy long before FU4. It is
/// here as a premise, not as a claim of new work — the listing repository's
/// scope-arming is only worth anything if the policy underneath it is real, and
/// `the_listing_repository_refuses_an_unarmed_scope` is the test that covers
/// the half FU4 adds.
#[sqlx::test]
async fn migration_002_rls_hides_sessions_from_an_unscoped_read(pool: PgPool) {
    let a = seed_workspace(&pool).await;
    let b = seed_workspace(&pool).await;
    let app = build_app(pool.clone());
    sign_in(&app, &a.viewer_email, "203.0.113.7", CHROME_MAC).await;
    sign_in(&app, &b.viewer_email, "198.51.100.22", FIREFOX_WINDOWS).await;

    // PREMISE: both rows really exist, so anything the low-privilege
    // connection cannot see below is RLS and not an empty table.
    //
    // Counted from EACH workspace's own armed scope and summed. A single
    // unscoped `count(*)` over the pool only tells the truth while the pool is
    // a BYPASSRLS superuser; under `secureprompt_runner` it raises
    // `22P02 invalid input syntax for type uuid: ""` instead of answering.
    let mut total = 0_i64;
    for workspace in [a.id, b.id] {
        let mut scope = super::fixtures::scoped(&pool, workspace).await;
        // The explicit `WHERE workspace_id` is not redundant with the scope,
        // and must stay. Under `secureprompt_runner` the RLS policy already
        // restricts the read to this tenant; under the compose SUPERUSER
        // nothing does, and without the predicate this count would be 2 for
        // both workspaces. The premise being established is "both rows
        // exist", and it has to hold under either role.
        let seen: i64 =
            sqlx::query_scalar("SELECT count(*) FROM refresh_tokens WHERE workspace_id = $1")
                .bind(workspace)
                .fetch_one(&mut *scope)
                .await
                .expect("premise count");
        assert_eq!(
            seen, 1,
            "premise: workspace {workspace} must see exactly its own session row"
        );
        total += seen;
    }
    assert_eq!(total, 2, "premise: two session rows exist");

    let mut conn = low_privilege_connection(&pool).await;
    let armed: bool = sqlx::query_scalar(
        "SELECT relrowsecurity AND relforcerowsecurity \
         FROM pg_class WHERE relname = 'refresh_tokens'",
    )
    .fetch_one(&mut conn)
    .await
    .expect("pg_class probe");
    assert!(
        armed,
        "refresh_tokens must have ENABLE + FORCE row level security"
    );

    let unset: i64 = sqlx::query_scalar("SELECT count(*) FROM refresh_tokens")
        .fetch_one(&mut conn)
        .await
        .expect("unset read must succeed, which is the whole problem");
    assert_eq!(
        unset, 0,
        "with the GUC unset the policy must hide every session, and say so by \
         returning zero rows rather than an error"
    );

    sqlx::query("SELECT set_config('app.current_workspace_id', $1, false)")
        .bind(a.id.to_string())
        .execute(&mut conn)
        .await
        .expect("bind workspace");
    let visible: Vec<Uuid> = sqlx::query_scalar("SELECT workspace_id FROM refresh_tokens")
        .fetch_all(&mut conn)
        .await
        .expect("scoped read");
    assert_eq!(
        visible,
        vec![a.id],
        "only workspace A's sessions may be visible"
    );

    forget_keys(&redis_pool().await, a.viewer, &[]).await;
    forget_keys(&redis_pool().await, b.viewer, &[]).await;
}

/// FU3 made `jwt_auth` fail CLOSED on admin revocation when Redis is
/// unreachable, by reading the watermark out of `session_revocation_audit`
/// instead. FU4 writes into that same table for a NARROW revocation. If the
/// durable read picked those rows up, a revocation scoped to one lost laptop
/// would silently become a revocation of every session that person holds — but
/// only during a Redis outage, which is to say never in a green test run.
///
/// `latest_watermark` filters `session_id IS NULL` for exactly this. Asserted
/// against the real repository rather than through a simulated outage, because
/// the predicate is the thing under test.
#[sqlx::test]
async fn a_narrow_revocation_does_not_raise_the_user_wide_watermark(pool: PgPool) {
    use secureprompt_api::db::session_revocation_repo::SessionRevocationRepository;

    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());
    sign_in(&app, &ws.viewer_email, "203.0.113.7", CHROME_MAC).await;
    sign_in(&app, &ws.viewer_email, "198.51.100.22", FIREFOX_WINDOWS).await;
    let admin_token = make_jwt(ws.id, ws.admin, "admin");
    let repo = SessionRevocationRepository::new(pool.clone());

    // PREMISE: no watermark before anything happens, so a `Some` later is
    // something this test caused.
    assert_eq!(
        repo.latest_watermark(ws.id, ws.viewer)
            .await
            .expect("watermark read"),
        None,
        "premise: no revocation on record yet"
    );

    let listed = json_body(list_sessions(&app, &admin_token, ws.viewer).await).await;
    let target_id = session_id(&sessions_of(&listed)[0]);
    assert_eq!(
        end_session(&app, &admin_token, ws.viewer, target_id)
            .await
            .status(),
        StatusCode::OK
    );

    // PREMISE: the narrow revocation DID write a row, so the `None` below is
    // the filter and not an empty table.
    let rows: i64 = {
        let mut scope = super::fixtures::scoped(&pool, ws.id).await;
        sqlx::query_scalar(
            "SELECT count(*) FROM session_revocation_audit WHERE session_id IS NOT NULL",
        )
        .fetch_one(&mut *scope)
        .await
        .expect("count")
    };
    assert_eq!(rows, 1, "premise: the narrow revocation wrote an audit row");

    assert_eq!(
        repo.latest_watermark(ws.id, ws.viewer)
            .await
            .expect("watermark read"),
        None,
        "a per-session revocation must not raise the per-USER watermark — that \
         watermark is compared against `iat` for every token the user holds, so \
         a Redis outage would turn one ended laptop into a full sign-out"
    );

    // CONTROL THAT MUST DIFFER: the user-wide lever DOES raise it, so the
    // assertion above is the `session_id IS NULL` filter and not a broken read.
    assert_eq!(
        app.clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v1/users/{}/sessions", ws.viewer))
                    .header("authorization", format!("Bearer {admin_token}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("router runs")
            .status(),
        StatusCode::OK
    );
    assert!(
        repo.latest_watermark(ws.id, ws.viewer)
            .await
            .expect("watermark read")
            .is_some(),
        "control: the user-wide lever must still be readable durably, or FU3's \
         fail-closed path has been broken"
    );

    forget_keys(&redis_pool().await, ws.viewer, &[]).await;
}

/// The listing reads an RLS-protected table, so an unarmed transaction would
/// answer "no active sessions" and report no error. `scope_is_armed` is the
/// guard that turns that into a refusal — and a guard whose deletion changes no
/// test result is a guard that defends nothing, so it is exercised directly.
#[sqlx::test]
async fn the_listing_repository_refuses_an_unarmed_scope(pool: PgPool) {
    use secureprompt_api::db::scope::{begin_scoped, scope_is_armed, SCOPE_NOT_ARMED};

    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());
    sign_in(&app, &ws.viewer_email, "203.0.113.7", CHROME_MAC).await;

    // An unscoped transaction: the GUC was never set.
    let mut plain = pool.begin().await.expect("plain transaction");
    let unarmed = scope_is_armed(&mut plain, ws.id).await;
    let message = unarmed
        .expect_err("an unscoped transaction must be refused")
        .to_string();
    assert!(
        message.contains(SCOPE_NOT_ARMED),
        "the refusal must say what was wrong, got {message:?}"
    );
    plain.rollback().await.expect("rollback");

    // POSITIVE CONTROL: through `begin_scoped` the same check passes and the
    // listing really does see the session, so the refusal above is the guard
    // and not a broken fixture.
    let mut scoped = begin_scoped(&pool, ws.id).await.expect("scoped");
    scope_is_armed(&mut scoped, ws.id)
        .await
        .expect("control: an armed scope must pass its own check");
    scoped.commit().await.expect("commit");

    let sessions = secureprompt_api::db::session_repo::SessionRepository::new(pool.clone())
        .list_live(ws.id, ws.viewer, "no-such-jti")
        .await
        .expect("listing");
    assert_eq!(
        sessions.len(),
        1,
        "control: the armed listing must see the session"
    );

    // And arming for the WRONG workspace is refused too — a stale GUC left by
    // an earlier statement must not pass for a scope.
    let mut wrong = begin_scoped(&pool, Uuid::new_v4()).await.expect("scoped");
    assert!(
        scope_is_armed(&mut wrong, ws.id).await.is_err(),
        "a transaction armed for another workspace must not satisfy this check"
    );
    wrong.rollback().await.expect("rollback");

    forget_keys(&redis_pool().await, ws.viewer, &[]).await;
}

// ── Device context is bounded, not free text ──────────────────────────────

/// `User-Agent` and `X-Forwarded-For` are attacker-controlled headers of
/// unbounded length. Nothing they contain is stored verbatim: the User-Agent is
/// reduced to a closed-vocabulary descriptor and the IP is stored only if it
/// parses as an address. A raw copy of either would be both a fingerprint and
/// an unbounded write into the database on an unauthenticated route.
#[sqlx::test]
async fn a_hostile_user_agent_and_ip_are_not_stored_verbatim(pool: PgPool) {
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());

    let hostile_ua = format!("Mozilla/5.0 {}", "A".repeat(4000));
    sign_in(&app, &ws.viewer_email, "not-an-ip-address", &hostile_ua).await;

    let row: (Option<String>, Option<String>) = {
        let mut scope = super::fixtures::scoped(&pool, ws.id).await;
        sqlx::query_as("SELECT client_ip, client_descriptor FROM refresh_tokens WHERE user_id = $1")
            .bind(ws.viewer)
            .fetch_one(&mut *scope)
            .await
            .expect("the sign-in wrote a row")
    };

    assert_eq!(
        row.0, None,
        "a value that is not an IP address must be dropped, not stored"
    );
    assert!(
        row.1.as_deref().is_none_or(|d| d.len() <= 64),
        "the client descriptor must be bounded, got {:?}",
        row.1
    );
    assert!(
        row.1.as_deref().is_none_or(|d| !d.contains("AAAA")),
        "no part of the raw User-Agent may be stored verbatim, got {:?}",
        row.1
    );

    // CONTROL THAT MUST DIFFER: a well-formed device IS recorded, so the two
    // `None`s above are the validators and not a write path that stores
    // nothing at all.
    let second = seed_workspace(&pool).await;
    sign_in(&app, &second.viewer_email, "203.0.113.7", CHROME_MAC).await;
    let good: (Option<String>, Option<String>) = {
        let mut scope = super::fixtures::scoped(&pool, second.id).await;
        sqlx::query_as("SELECT client_ip, client_descriptor FROM refresh_tokens WHERE user_id = $1")
            .bind(second.viewer)
            .fetch_one(&mut *scope)
            .await
            .expect("the control sign-in wrote a row")
    };
    assert_eq!(good.0.as_deref(), Some("203.0.113.7"));
    assert_eq!(good.1.as_deref(), Some("Chrome on macOS"));

    forget_keys(&redis_pool().await, ws.viewer, &[]).await;
    forget_keys(&redis_pool().await, second.viewer, &[]).await;
}

/// The device context is recorded ONCE, at sign-in, and never re-recorded on
/// rotation. A column refreshed on every `/v1/auth/refresh` would turn this
/// table into a movement log: one IP address per fifteen minutes, per person,
/// for the life of the refresh chain.
#[sqlx::test]
async fn rotation_does_not_re_record_the_device(pool: PgPool) {
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());
    let signed_in = sign_in(&app, &ws.viewer_email, "203.0.113.7", CHROME_MAC).await;

    let rotated = refresh(&app, &signed_in.refresh).await;
    assert_eq!(
        rotated.status(),
        StatusCode::OK,
        "premise: the refresh must rotate"
    );

    let mut scope = super::fixtures::scoped(&pool, ws.id).await;
    let with_context: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM refresh_tokens
         WHERE user_id = $1 AND (client_ip IS NOT NULL OR client_descriptor IS NOT NULL)",
    )
    .bind(ws.viewer)
    .fetch_one(&mut *scope)
    .await
    .expect("count");
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM refresh_tokens WHERE user_id = $1")
        .bind(ws.viewer)
        .fetch_one(&mut *scope)
        .await
        .expect("count");
    drop(scope);

    assert_eq!(total, 2, "premise: rotation wrote a second row");
    assert_eq!(
        with_context, 1,
        "exactly ONE row per session carries device context — the sign-in. \
         {with_context} of {total} rows carry it, which makes this table a \
         record of where the person was every time their token rotated"
    );

    forget_keys(&redis_pool().await, ws.viewer, &[]).await;
}
