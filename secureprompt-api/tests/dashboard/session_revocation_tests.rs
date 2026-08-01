//! WS4-3 — admin-initiated session revocation.
//!
//! Every test here failed at commit `1323fd7`, before the route, the per-user
//! revocation watermark and `session_revocation_audit` existed. Each of the
//! six load-bearing lines behind them has since been mutated one at a time,
//! grep-verified present in the file, and confirmed to turn the matching test
//! red — see the WS4-3 report for the transcript.
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
///
/// SEEDS THROUGH AN ARMED SCOPE. `refresh_tokens` is ENABLE + FORCE ROW LEVEL
/// SECURITY (migration 002), so on the bare pool this INSERT is refused with
/// `42501 new row violates row-level security policy for table
/// "refresh_tokens"` under any role that cannot bypass RLS — measured on
/// `secureprompt_runner`, three tests in this file.
async fn issue_refresh_token(pool: &PgPool, workspace_id: Uuid, user_id: Uuid) -> String {
    let raw = format!("rt-{}", Uuid::new_v4().simple());
    let mut tx = super::fixtures::scoped(pool, workspace_id).await;
    sqlx::query(
        "INSERT INTO refresh_tokens (id, user_id, workspace_id, token_hash, expires_at, created_at)
         VALUES ($1, $2, $3, $4, NOW() + INTERVAL '1 hour', NOW())",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(workspace_id)
    .bind(hash_refresh_token(&raw))
    .execute(&mut *tx)
    .await
    .expect("seed refresh token");
    tx.commit().await.expect("commit seeded refresh token");
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

    // Verify from INSIDE the workspace's own armed scope — the visibility the
    // product has. A bare-pool read is filtered to zero under a non-bypassing
    // role, which would satisfy `active == 0` because the reader cannot see
    // the row rather than because the row was revoked.
    let mut scope = super::fixtures::scoped(&pool, ws.id).await;

    // PREMISE / CONTROL: this scope can see this user's refresh rows at all.
    // Same table, same user, same transaction — only `revoked_at IS NULL`
    // differs between the two counts, so a zero below is the revocation and
    // not the reader.
    let all_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM refresh_tokens WHERE user_id = $1")
            .bind(ws.viewer)
            .fetch_one(&mut *scope)
            .await
            .expect("count refresh rows");
    assert!(
        all_rows >= 2,
        "premise: this scope must see the refresh rows seeded for the viewer \
         (two were issued, plus whatever the probe rotation minted), or the \
         active-row count below is vacuous. Saw {all_rows}"
    );

    let active: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(ws.viewer)
    .fetch_one(&mut *scope)
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
    //
    // BOTH reads run through the SAME armed scope, opened twice. That is what
    // makes the zero mean something: the identical query on the identical
    // scope returns 1 after the revocation, so the 0 before it is an empty
    // table and not a reader that cannot see. On the bare pool under
    // `secureprompt_runner` this read raises 22P02 rather than answering,
    // because a committed `set_config(..., true)` leaves the GUC as `''`.
    let before: i64 = {
        let mut scope = super::fixtures::scoped(&pool, ws.id).await;
        sqlx::query_scalar("SELECT count(*) FROM session_revocation_audit")
            .fetch_one(&mut *scope)
            .await
            .expect("premise count")
    };
    assert_eq!(before, 0, "premise: the audit table starts empty");

    assert_eq!(
        revoke(&app, &admin_token, ws.viewer).await.status(),
        StatusCode::OK
    );

    let mut scope = super::fixtures::scoped(&pool, ws.id).await;
    let row = sqlx::query(
        "SELECT workspace_id, actor_user_id, actor_email, actor_role, target_user_id, \
                target_email, target_role, refresh_tokens_revoked, revoked_before_unix \
         FROM session_revocation_audit",
    )
    .fetch_one(&mut *scope)
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
    assert_eq!(
        revoke(&app, &admin_token, ws.viewer).await.status(),
        StatusCode::OK
    );

    let mut scope = super::fixtures::scoped(&pool, ws.id).await;
    let counted: i64 =
        sqlx::query_scalar("SELECT refresh_tokens_revoked FROM session_revocation_audit")
            .fetch_one(&mut *scope)
            .await
            .expect("audit row");
    assert_eq!(counted, 3, "the audit row must count what it revoked");

    let others_still_active: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(ws.admin)
    .fetch_one(&mut *scope)
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
///
/// # Why every call below targets the ACTOR THEMSELVES
///
/// The earlier version of this test pointed both refusals at `ws.owner` and
/// its control at `ws.viewer`, and so could not be killed by any single-line
/// production change. Three independent rules each answer 403 to
/// viewer → owner: `require_role(&ctx, UserRole::Admin)`, the `ActorRoleTooLow`
/// floor, and `TargetOutranksActor`. Delete the first TWO — the entire actor
/// role floor this test is named for — and `TargetOutranksActor` still returns
/// 403 and the test stays green. Its own docstring stated the standard it
/// failed: the control changed two dimensions at once, the actor's role AND
/// the target.
///
/// Self-targeting isolates the floor, because `may_revoke`'s second rule is
/// `privilege_level(target) > privilege_level(actor)` and nobody outranks
/// themselves. So with the floor removed the answer is `Allowed`, not a
/// second 403 from a different rule.
///
/// ONE DIMENSION, literally: all three calls are made by the same user
/// (`ws.viewer`) against the same target (`ws.viewer`) on the same router.
/// Only the token's `role` claim changes — viewer, developer, admin. There is
/// nothing else left that could explain the difference in outcome.
///
/// Self-revocation succeeding is not a loophole introduced to make the test
/// work: `may_revoke`'s doc records it as a deliberate rule (an admin who
/// thinks their own laptop is compromised should not have to ask someone
/// else), and `may_revoke_matrix` pins it as a pure function.
#[sqlx::test]
async fn viewer_is_refused_where_admin_succeeds(pool: PgPool) {
    let ws = seed_workspace(&pool).await;
    let app = build_app(pool.clone());
    // The actor is also the target, throughout. See the doc above.
    let actor = ws.viewer;

    let viewer_token = make_jwt(ws.id, actor, "viewer");
    let refused = revoke(&app, &viewer_token, actor).await;
    assert_eq!(
        refused.status(),
        StatusCode::FORBIDDEN,
        "a viewer must not be able to revoke anyone, including themselves — \
         `POST /v1/auth/logout` is the route that needs no privilege"
    );

    let developer_token = make_jwt(ws.id, actor, "developer");
    assert_eq!(
        revoke(&app, &developer_token, actor).await.status(),
        StatusCode::FORBIDDEN,
        "a developer must not be able to revoke anyone either"
    );

    // POSITIVE CONTROL. Same actor, same target, same router; the ONLY
    // difference from the two refusals above is the `role` claim. If this is
    // not 200 the two 403s prove nothing, because a route that refuses
    // everybody refuses viewers too.
    let admin_token = make_jwt(ws.id, actor, "admin");
    let allowed = revoke(&app, &admin_token, actor).await;
    assert_eq!(
        allowed.status(),
        StatusCode::OK,
        "control: the identical call with an `admin` role claim must succeed"
    );

    // A SECOND refusal, from a DIFFERENT rule, so the two are not conflated.
    // An admin aiming at the owner is refused by `TargetOutranksActor`, not by
    // the actor floor — which is why the calls above cannot be pointed at the
    // owner if they are to measure the floor.
    let admin_at_owner = make_jwt(ws.id, ws.admin, "admin");
    assert_eq!(
        revoke(&app, &admin_at_owner, ws.owner).await.status(),
        StatusCode::FORBIDDEN,
        "an admin must not revoke the owner — a different rule from the floor \
         above, and `an_admin_cannot_revoke_an_owner_but_an_owner_can_revoke_\
         an_admin` is where it is measured in both directions"
    );

    // And unauthenticated is 401, not 403 — a different layer.
    let anonymous = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/users/{actor}/sessions"))
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
    // Everything about workspace B is read from INSIDE WORKSPACE B's OWN
    // armed scope — the only vantage point from which "workspace B has no
    // audit row" is a claim about the data rather than about the reader.
    // Each read opens its own short scope rather than holding one across the
    // HTTP calls below.
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

    // POSITIVE CONTROL: the same admin revoking inside their OWN workspace
    // works, so the 404s above are tenancy and not a broken route.
    assert_eq!(
        revoke(&app, &admin_a, a.viewer).await.status(),
        StatusCode::OK,
        "control: in-workspace revocation must succeed"
    );

    // CONTROL for the absence-claim below: the identical query, on the
    // identical table, from workspace A's scope must return 1. Without it a
    // zero from B's scope would be equally well explained by a broken query,
    // a missing table, or a revocation route that wrote nothing at all.
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
        "control: the in-workspace revocation must have written A's audit row, \
         or the zero asserted for B below proves nothing"
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

    forget_watermark(&redis_pool().await, a.viewer).await;
}

// ── TRAP 3: RLS, proved from a role that cannot bypass it ─────────────────

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

/// Open a connection to the SAME `#[sqlx::test]` database as `RLS_ROLE`, and
/// assert on the wire that it really is powerless. The `#[sqlx::test]` pool is
/// a BYPASSRLS superuser, so without these premise assertions the test below
/// would keep passing while exercising no RLS at all.
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

/// Migration 026's RLS policy is ARMED. This is the layer no other test in the
/// repository can see: the application connects as a BYPASSRLS superuser
/// today, so a missing, malformed, or wrong-column policy would leave every
/// `#[sqlx::test]` green.
///
/// It also demonstrates the silent-zero trap the brief names — with the GUC
/// unset the read returns the EMPTY SET and reports no error.
#[sqlx::test]
async fn migration_026_rls_isolates_the_revocation_trail_from_a_nonsuperuser(pool: PgPool) {
    let a = seed_workspace(&pool).await;
    let b = seed_workspace(&pool).await;
    let app = build_app(pool.clone());
    assert_eq!(
        revoke(&app, &make_jwt(a.id, a.admin, "admin"), a.viewer)
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        revoke(&app, &make_jwt(b.id, b.admin, "admin"), b.viewer)
            .await
            .status(),
        StatusCode::OK
    );

    // PREMISE: both rows really exist, so anything the low-privilege
    // connection cannot see below is RLS and not an empty table.
    //
    // Counted from EACH workspace's own armed scope and summed, rather than
    // with one unscoped `count(*)` over the pool. The unscoped read only tells
    // the truth when the pool happens to be a BYPASSRLS superuser; point
    // DATABASE_URL at `secureprompt_runner` and it raises
    // `22P02 invalid input syntax for type uuid: ""` instead of answering,
    // because a committed transaction-local `set_config` leaves the GUC as the
    // empty string rather than unsetting it.
    let mut total = 0_i64;
    for workspace in [a.id, b.id] {
        let mut scope = super::fixtures::scoped(&pool, workspace).await;
        // The explicit `WHERE workspace_id` is not redundant with the scope,
        // and must stay. Under `secureprompt_runner` the RLS policy already
        // restricts the read to this tenant; under the compose SUPERUSER
        // nothing does, and without the predicate this count would be 2 for
        // both workspaces. The premise being established is "both rows
        // exist", and it has to hold under either role.
        let seen: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM session_revocation_audit WHERE workspace_id = $1",
        )
        .bind(workspace)
        .fetch_one(&mut *scope)
        .await
        .expect("premise count");
        assert_eq!(
            seen, 1,
            "premise: workspace {workspace} must see exactly its own \
             revocation row"
        );
        total += seen;
    }
    assert_eq!(total, 2, "premise: two revocation rows exist");

    let mut conn = low_privilege_connection(&pool).await;

    let armed: bool = sqlx::query_scalar(
        "SELECT relrowsecurity AND relforcerowsecurity \
         FROM pg_class WHERE relname = 'session_revocation_audit'",
    )
    .fetch_one(&mut conn)
    .await
    .expect("pg_class probe");
    assert!(
        armed,
        "session_revocation_audit must have ENABLE + FORCE row level security"
    );

    // GUC unset -> nothing visible, and NO ERROR. That is the trap.
    let unset: i64 = sqlx::query_scalar("SELECT count(*) FROM session_revocation_audit")
        .fetch_one(&mut conn)
        .await
        .expect("unset read must succeed, which is the whole problem");
    assert_eq!(
        unset, 0,
        "with the GUC unset the policy must hide everything, not leak"
    );

    // GUC set -> exactly my workspace.
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, false)")
        .bind(a.id.to_string())
        .execute(&mut conn)
        .await
        .expect("bind workspace");
    let visible: Vec<Uuid> =
        sqlx::query_scalar("SELECT workspace_id FROM session_revocation_audit")
            .fetch_all(&mut conn)
            .await
            .expect("scoped read");
    assert_eq!(
        visible,
        vec![a.id],
        "only workspace A's revocation trail may be visible"
    );

    // And an INSERT for somebody else's workspace is REJECTED, not silently
    // written — the policy governs WITH CHECK too (no command on the policy,
    // so USING doubles as WITH CHECK).
    let forged = sqlx::query(
        "INSERT INTO session_revocation_audit
             (id, workspace_id, actor_user_id, actor_email, actor_role,
              target_user_id, target_email, target_role,
              revoked_before_unix, refresh_tokens_revoked)
         VALUES ($1, $2, $3, 'x@example.com', 'owner', $4, 'y@example.com', \
                 'viewer', 1, 0)",
    )
    .bind(Uuid::new_v4())
    .bind(b.id)
    .bind(b.admin)
    .bind(b.viewer)
    .execute(&mut conn)
    .await;
    assert!(
        forged.is_err(),
        "a bound connection must not be able to write into another \
         workspace's revocation trail"
    );

    forget_watermark(&redis_pool().await, a.viewer).await;
    forget_watermark(&redis_pool().await, b.viewer).await;
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

    assert_eq!(
        revoke(&app, &admin_token, ws.viewer).await.status(),
        StatusCode::OK
    );

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
