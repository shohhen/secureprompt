//! WS4-3 — admin-initiated session revocation.
//!
//! RED phase: every test here fails until `DELETE /v1/users/{id}/sessions`,
//! the per-user revocation watermark and `session_revocation_audit` exist.
//!
//! The three acceptance criteria, one test each (plus the traps):
//!   * a revoked session's NEXT request 401s — `revoked_sessions_next_request_401s`
//!   * the action is audited — `revocation_writes_an_audit_row_that_reads_alone`
//!   * only admin/owner may revoke — `viewer_is_refused_where_admin_succeeds`
//!
//! Every "must be refused" test carries a POSITIVE CONTROL in the same test
//! body: the same call, changed in exactly one dimension, that must succeed.
//! Without it a 403 could come from anywhere — a broken route, a bad fixture,
//! the license gate — and the test would pass while proving nothing.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use deadpool_redis::{redis::cmd, Config as RedisPoolConfig, Pool as RedisPool, Runtime};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use secureprompt_api::{
    app_state::AppState, db::refresh_token_repo::hash_refresh_token,
    http::build_router, http::middleware::jwt_auth::Claims, ml_sidecar::MlSidecarClient,
};
use secureprompt_common::config::{
    AppConfig, ClickhouseConfig, DatabaseConfig, JwtConfig, LicenseConfig, RedisConfig,
    ServerConfig, TelemetryConfig,
};
use serde_json::Value;
use sqlx::{PgPool, Row};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

const TEST_JWT_SECRET: &str = "ws4-3-session-revocation-test-secret";
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

/// Mint a normal access token for a specific user. `iat` is captured here so
/// the revocation watermark comparison is exercised against a real value.
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

/// Tests share one real Redis. Every watermark key is keyed by a fresh user
/// UUID so collisions are impossible, but the keys are deleted anyway so a
/// long local run does not accumulate them.
async fn forget_watermark(pool: &RedisPool, user_id: Uuid) {
    let mut conn = pool.get().await.expect("redis checkout");
    let _: i64 = cmd("DEL")
        .arg(format!("session_revoked:{user_id}"))
        .query_async(&mut conn)
        .await
        .unwrap_or(0);
}

struct Workspace {
    id: Uuid,
    owner: Uuid,
    admin: Uuid,
    viewer: Uuid,
    viewer_email: String,
    admin_email: String,
}

async fn seed_workspace(pool: &PgPool) -> Workspace {
    let id = Uuid::new_v4();
    let suffix = Uuid::new_v4().simple().to_string();
    sqlx::query(
        "INSERT INTO workspaces (id, name, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(id)
    .bind(format!("ws4-3 {suffix}"))
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
        admin_email: ids[1].1.clone(),
        viewer_email: ids[2].1.clone(),
    }
}

async fn revoke(app: &axum::Router, actor_token: &str, target: Uuid) -> axum::response::Response {
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
}

/// A plain authenticated read. `GET /v1/users` is open to every role, so a
/// 401 here is the auth layer talking and not an RBAC decision.
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

async fn json_body(resp: axum::response::Response) -> Value {
    use http_body_util::BodyExt;
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("json body")
    }
}

/// Insert an active refresh row for `user_id` and return the raw token, so a
/// test can attempt the full reconstitution loop through `/v1/auth/refresh`.
async fn issue_refresh_token(pool: &PgPool, workspace_id: Uuid, user_id: Uuid) -> String {
    let raw = format!("rt-{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO refresh_tokens (id, user_id, workspace_id, token_hash, expires_at, created_at)
         VALUES ($1, $2, $3, $4, NOW() + INTERVAL '1 hour', NOW())",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(workspace_id)
    .bind(hash_refresh_token(&raw))
    .execute(pool)
    .await
    .expect("seed refresh token");
    raw
}

// ── Criterion 1: the revoked session's NEXT request 401s ──────────────────

/// The headline criterion. Not "eventually", not "after the 5-minute auth
/// cache expires": the very next request on the same access token.
#[sqlx::test]
async fn revoked_sessions_next_request_401s(pool: PgPool) {
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());
    let victim_token = make_jwt(ws.id, ws.viewer, "viewer");
    let admin_token = make_jwt(ws.id, ws.admin, "admin");

    // PREMISE: the token works right now. Without this a 401 below could
    // simply mean the token was never valid.
    assert_eq!(
        authenticated_read(&app, &victim_token).await,
        StatusCode::OK,
        "premise: the victim's token must work BEFORE revocation, or the 401 \
         afterwards proves nothing"
    );

    let response = revoke(&app, &admin_token, ws.viewer).await;
    let status = response.status();
    let body = json_body(response).await;
    assert_eq!(status, StatusCode::OK, "revocation must succeed: {body}");

    assert_eq!(
        authenticated_read(&app, &victim_token).await,
        StatusCode::UNAUTHORIZED,
        "the revoked session's NEXT request must 401"
    );

    // CONTROL THAT MUST DIFFER: the admin who performed the revocation is
    // untouched. A revocation that logs out the whole workspace would satisfy
    // the assertion above and be useless.
    assert_eq!(
        authenticated_read(&app, &admin_token).await,
        StatusCode::OK,
        "revoking one user must not revoke the actor"
    );

    forget_watermark(&redis_pool().await, ws.viewer).await;
}

/// TRAP 1 — revoking the access token but not the refresh token leaves a
/// session that reconstitutes itself. Test the full loop.
#[sqlx::test]
async fn revocation_kills_the_refresh_token_too(pool: PgPool) {
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());
    let refresh_raw = issue_refresh_token(&pool, ws.id, ws.viewer).await;
    let admin_token = make_jwt(ws.id, ws.admin, "admin");

    // PREMISE: this refresh token really does mint a session today.
    let probe = issue_refresh_token(&pool, ws.id, ws.viewer).await;
    let probe_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/refresh")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "refresh_token": probe }).to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("router runs");
    assert_eq!(
        probe_response.status(),
        StatusCode::OK,
        "premise: an active refresh token must mint a session before revocation"
    );

    let response = revoke(&app, &admin_token, ws.viewer).await;
    assert_eq!(response.status(), StatusCode::OK);

    let after = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/refresh")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "refresh_token": refresh_raw }).to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("router runs");
    assert_eq!(
        after.status(),
        StatusCode::UNAUTHORIZED,
        "a revoked session must not be able to reconstitute itself through \
         /v1/auth/refresh"
    );

    let active: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(ws.viewer)
    .fetch_one(&pool)
    .await
    .expect("count refresh rows");
    assert_eq!(active, 0, "no active refresh row may survive revocation");

    forget_watermark(&redis_pool().await, ws.viewer).await;
}

// ── Criterion 2: the action is audited ────────────────────────────────────

/// The row must answer "who revoked what, when, and for which principal"
/// without any other table, because that is how an auditor will read it.
#[sqlx::test]
async fn revocation_writes_an_audit_row_that_reads_alone(pool: PgPool) {
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());
    let admin_token = make_jwt(ws.id, ws.admin, "admin");

    // PREMISE: nothing is in the table before the action, so a row found
    // afterwards was written by it.
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM session_revocation_audit")
        .fetch_one(&pool)
        .await
        .expect("premise count");
    assert_eq!(before, 0, "premise: the audit table starts empty");

    assert_eq!(revoke(&app, &admin_token, ws.viewer).await.status(), StatusCode::OK);

    let row = sqlx::query(
        "SELECT workspace_id, actor_user_id, actor_email, actor_role, target_user_id, \
                target_email, target_role, refresh_tokens_revoked, revoked_before_unix \
         FROM session_revocation_audit",
    )
    .fetch_one(&pool)
    .await
    .expect("exactly one audit row");

    assert_eq!(row.get::<Uuid, _>("workspace_id"), ws.id);
    assert_eq!(row.get::<Uuid, _>("actor_user_id"), ws.admin);
    assert_eq!(
        row.get::<Option<String>, _>("actor_email").as_deref(),
        Some(ws.admin_email.as_str()),
        "the actor's email as it read at the time — an id alone is not \
         readable months later"
    );
    assert_eq!(row.get::<String, _>("actor_role"), "admin");
    assert_eq!(row.get::<Uuid, _>("target_user_id"), ws.viewer);
    assert_eq!(
        row.get::<Option<String>, _>("target_email").as_deref(),
        Some(ws.viewer_email.as_str())
    );
    assert_eq!(row.get::<String, _>("target_role"), "viewer");
    assert!(row.get::<i64, _>("revoked_before_unix") > 0);

    forget_watermark(&redis_pool().await, ws.viewer).await;
}

/// The audit row must record the EFFECT, not just the intent: how many
/// refresh rows this revocation actually killed.
#[sqlx::test]
async fn the_audit_row_counts_the_refresh_rows_it_killed(pool: PgPool) {
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());
    for _ in 0..3 {
        issue_refresh_token(&pool, ws.id, ws.viewer).await;
    }
    // A row belonging to somebody else in the same workspace, which must NOT
    // be counted or revoked.
    issue_refresh_token(&pool, ws.id, ws.admin).await;

    let admin_token = make_jwt(ws.id, ws.admin, "admin");
    assert_eq!(revoke(&app, &admin_token, ws.viewer).await.status(), StatusCode::OK);

    let counted: i64 =
        sqlx::query_scalar("SELECT refresh_tokens_revoked FROM session_revocation_audit")
            .fetch_one(&pool)
            .await
            .expect("audit row");
    assert_eq!(counted, 3, "the audit row must count what it revoked");

    let others_still_active: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(ws.admin)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(
        others_still_active, 1,
        "revoking one member must not revoke another member's refresh rows"
    );

    forget_watermark(&redis_pool().await, ws.viewer).await;
}

// ── Criterion 3: only admin/owner may revoke ──────────────────────────────

/// A refusal is only evidence if the same call, changed in exactly one
/// dimension, succeeds.
#[sqlx::test]
async fn viewer_is_refused_where_admin_succeeds(pool: PgPool) {
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());
    let target = ws.owner;

    let viewer_token = make_jwt(ws.id, ws.viewer, "viewer");
    let refused = revoke(&app, &viewer_token, target).await;
    assert_eq!(
        refused.status(),
        StatusCode::FORBIDDEN,
        "a viewer must not be able to revoke anyone"
    );

    let developer_token = make_jwt(ws.id, ws.viewer, "developer");
    assert_eq!(
        revoke(&app, &developer_token, target).await.status(),
        StatusCode::FORBIDDEN,
        "a developer must not be able to revoke anyone either"
    );

    // POSITIVE CONTROL: the identical call as an owner succeeds, so the two
    // 403s above are the role gate and not a broken route.
    let owner_token = make_jwt(ws.id, ws.owner, "owner");
    let allowed = revoke(&app, &owner_token, ws.viewer).await;
    assert_eq!(
        allowed.status(),
        StatusCode::OK,
        "control: an owner performing the same call must succeed"
    );

    // And unauthenticated is 401, not 403 — a different layer.
    let anonymous = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/users/{target}/sessions"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("router runs");
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);

    forget_watermark(&redis_pool().await, ws.viewer).await;
}

/// TRAP 2, half one — an admin may not revoke an owner. The role hierarchy
/// already says Admin < Owner; letting the lower role terminate the higher
/// one's session is a privilege inversion and a lockout vector.
#[sqlx::test]
async fn an_admin_cannot_revoke_an_owner_but_an_owner_can_revoke_an_admin(pool: PgPool) {
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());

    let admin_token = make_jwt(ws.id, ws.admin, "admin");
    assert_eq!(
        revoke(&app, &admin_token, ws.owner).await.status(),
        StatusCode::FORBIDDEN,
        "an admin must not be able to revoke an owner's session"
    );
    let owner_still_works = make_jwt(ws.id, ws.owner, "owner");
    assert_eq!(
        authenticated_read(&app, &owner_still_works).await,
        StatusCode::OK,
        "the refused attempt must leave the owner's session intact"
    );

    // CONTROL THAT MUST DIFFER: the same call in the other direction works.
    let owner_token = make_jwt(ws.id, ws.owner, "owner");
    assert_eq!(
        revoke(&app, &owner_token, ws.admin).await.status(),
        StatusCode::OK,
        "control: an owner revoking an admin must succeed"
    );

    forget_watermark(&redis_pool().await, ws.admin).await;
}

/// TRAP 2, half two — self-revocation is ALLOWED, and it really does kill the
/// calling token. `POST /v1/auth/logout` already lets any user end their own
/// session, so refusing here would be a fiction.
#[sqlx::test]
async fn an_admin_may_revoke_their_own_sessions_including_the_calling_token(pool: PgPool) {
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());
    let admin_token = make_jwt(ws.id, ws.admin, "admin");

    assert_eq!(
        authenticated_read(&app, &admin_token).await,
        StatusCode::OK,
        "premise: the admin's own token works first"
    );
    assert_eq!(
        revoke(&app, &admin_token, ws.admin).await.status(),
        StatusCode::OK,
        "self-revocation is allowed"
    );
    assert_eq!(
        authenticated_read(&app, &admin_token).await,
        StatusCode::UNAUTHORIZED,
        "self-revocation must kill the calling token too — otherwise the \
         admin who suspects their own laptop is compromised keeps a live \
         session on it"
    );

    forget_watermark(&redis_pool().await, ws.admin).await;
}

// ── TRAP 4: cross-tenant ──────────────────────────────────────────────────

/// Revocation must not reach across workspaces, and the refusal must not
/// confirm that the foreign user exists.
#[sqlx::test]
async fn revocation_cannot_reach_into_another_workspace(pool: PgPool) {
    let a = seed_workspace(&pool).await;
    let b = seed_workspace(&pool).await;
    let app = build_app(pool.clone());
    let admin_a = make_jwt(a.id, a.admin, "admin");
    let victim_b_token = make_jwt(b.id, b.viewer, "viewer");
    issue_refresh_token(&pool, b.id, b.viewer).await;

    let cross = revoke(&app, &admin_a, b.viewer).await;
    assert_eq!(
        cross.status(),
        StatusCode::NOT_FOUND,
        "a foreign user must be indistinguishable from a nonexistent one"
    );
    let absent = revoke(&app, &admin_a, Uuid::new_v4()).await;
    assert_eq!(
        absent.status(),
        StatusCode::NOT_FOUND,
        "and a nonexistent user must give the identical answer"
    );

    assert_eq!(
        authenticated_read(&app, &victim_b_token).await,
        StatusCode::OK,
        "workspace B's session must be untouched"
    );
    let active_b: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(b.viewer)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(active_b, 1, "workspace B's refresh row must survive");

    // POSITIVE CONTROL: the same admin revoking inside their OWN workspace
    // works, so the 404s above are tenancy and not a broken route.
    assert_eq!(
        revoke(&app, &admin_a, a.viewer).await.status(),
        StatusCode::OK,
        "control: in-workspace revocation must succeed"
    );
    let rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM session_revocation_audit WHERE workspace_id = $1",
    )
    .bind(b.id)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(rows, 0, "no audit row may be written for workspace B");

    forget_watermark(&redis_pool().await, a.viewer).await;
}

// ── The watermark is a point in time, not a ban ───────────────────────────

/// Revocation must not lock the user out permanently: a fresh login after the
/// watermark second works. The one-second sleep is the `iat` granularity —
/// tokens minted in the SAME second as the revocation are refused, which is
/// the safe direction and is asserted here rather than assumed.
#[sqlx::test]
async fn a_session_minted_after_the_watermark_second_is_accepted(pool: PgPool) {
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());
    let admin_token = make_jwt(ws.id, ws.admin, "admin");

    assert_eq!(revoke(&app, &admin_token, ws.viewer).await.status(), StatusCode::OK);

    let same_second = make_jwt(ws.id, ws.viewer, "viewer");
    assert_eq!(
        authenticated_read(&app, &same_second).await,
        StatusCode::UNAUTHORIZED,
        "a token whose iat is the revocation second must be refused (iat has \
         one-second granularity; the safe direction is to refuse)"
    );

    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    let after = make_jwt(ws.id, ws.viewer, "viewer");
    assert_eq!(
        authenticated_read(&app, &after).await,
        StatusCode::OK,
        "revocation is a point in time, not a ban — the user must be able to \
         sign in again"
    );

    forget_watermark(&redis_pool().await, ws.viewer).await;
}
