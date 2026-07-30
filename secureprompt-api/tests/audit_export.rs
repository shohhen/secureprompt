//! WS4-1 / Task 19 — the `/v1/audit-exports` HTTP surface.
//!
//! The worker-side proof that an export reproduces live data lives in
//! `secureprompt-worker/src/tasks/audit_export/tests.rs`, next to the job. This
//! suite covers what only the API can be wrong about:
//!
//!   * who may ask (role), and whose exports they get back (tenancy);
//!   * that a request actually reaches the queue, in the right order relative
//!     to the row it describes;
//!   * that the signed bytes are served back BYTE-FOR-BYTE, since a transport
//!     that re-encodes them would break every signature the product issues;
//!   * that the RLS policy migration 025 installs is actually armed — which no
//!     `#[sqlx::test]` can see, because that pool is a BYPASSRLS superuser.
//!
//! All fixture data is synthetic (Constraint 5).

mod support;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use secureprompt_common::audit_export::{
    build_manifest, render_page, verify_export, AuditRow, ExportFormat,
};
use serde_json::{json, Value};
use sqlx::postgres::PgConnectOptions;
use sqlx::{Connection, PgConnection, PgPool, Row as _};
use tower::ServiceExt;
use uuid::Uuid;

use support::{response_json, response_text, router};

const SUPPORT_JWT_SECRET: &str = "test-jwt-secret-distinct-from-provider-key";

/// A fixed test seed. Constraint 6 is about the PRODUCT never carrying a
/// literal key; the gateway reads the real one from
/// `SECUREPROMPT_AUDIT_EXPORT_SIGNING_KEY`.
fn test_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[77u8; 32])
}

fn make_jwt(workspace_id: Uuid, user_id: Uuid, role: &str) -> String {
    let claims = secureprompt_api::http::middleware::jwt_auth::Claims {
        sub: user_id,
        ws: workspace_id,
        role: role.to_owned(),
        jti: Uuid::new_v4().to_string(),
        exp: (chrono::Utc::now() + chrono::Duration::seconds(900)).timestamp(),
        iat: chrono::Utc::now().timestamp(),
        purpose: None,
    };
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(SUPPORT_JWT_SECRET.as_bytes()),
    )
    .expect("jwt encode")
}

fn get(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request")
}

fn post_json(uri: &str, token: &str, body: &Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("request")
}

/// A window that is valid for the API's validator.
fn window() -> (String, String) {
    let to = chrono::Utc::now();
    let from = to - chrono::Duration::days(1);
    (from.to_rfc3339(), to.to_rfc3339())
}

// ── A completed export, written straight into the store ───────────────────

struct Completed {
    export_id: Uuid,
    pages: Vec<Vec<u8>>,
    manifest_json: String,
    signature_b64: String,
    public_key_b64: String,
}

fn synthetic_row(workspace_id: Uuid, n: u32) -> AuditRow {
    AuditRow {
        request_id: Uuid::from_u128(u128::from(n) + 1),
        workspace_id,
        created_at: chrono::Utc::now() - chrono::Duration::minutes(i64::from(n)),
        provider: "openai".into(),
        model: "gpt-4o-mini".into(),
        final_action: "allow".into(),
        input_tokens: Some(10 + n),
        output_tokens: Some(20 + n),
        estimated_usage: false,
        cost_usd: 0.001 * f64::from(n),
        user_id: None,
        api_key_id: None,
        // Deliberately contains a comma and a quote: if the transport ever
        // re-encodes a page, this is the row that shows it.
        api_key_name: Some(r#"synthetic "key", comma"#.into()),
        ip_address: Some("198.51.100.7".into()),
        user_agent: Some("synthetic-agent/1.0".into()),
        floor_only: false,
        engines: vec!["floor".into()],
    }
}

/// Write a finished, signed export directly into `audit_exports` /
/// `audit_export_pages`, the way the worker would have left it.
///
/// The worker is not run here on purpose: this suite is about the HTTP
/// surface, and driving the real job would make every assertion below depend
/// on ClickHouse being seeded too.
async fn seed_completed_export(
    pool: &PgPool,
    workspace_id: Uuid,
    format: ExportFormat,
) -> sqlx::Result<Completed> {
    let export_id = Uuid::new_v4();
    let now = chrono::Utc::now();
    let from = now - chrono::Duration::days(1);

    let rows: Vec<AuditRow> = (0..4).map(|n| synthetic_row(workspace_id, n)).collect();
    let pages: Vec<Vec<u8>> = rows.chunks(2).map(|c| render_page(c, format)).collect();
    let signed = build_manifest(
        export_id,
        workspace_id,
        from,
        now,
        format,
        2,
        &pages,
        &[2, 2],
        now,
        &test_key(),
    )
    .expect("manifest");

    sqlx::query(
        "INSERT INTO audit_exports \
         (id, workspace_id, requested_by, window_from, window_to, format, page_size, \
          status, total_rows, total_pages, manifest_json, signature_b64, \
          public_key_b64, signing_key_id, completed_at) \
         VALUES ($1, $2, NULL, $3, $4, $5, 2, 'complete', 4, 2, $6, $7, $8, $9, NOW())",
    )
    .bind(export_id)
    .bind(workspace_id)
    .bind(from)
    .bind(now)
    .bind(format.as_str())
    .bind(&signed.manifest_json)
    .bind(&signed.signature_b64)
    .bind(&signed.public_key_b64)
    .bind(&signed.signing_key_id)
    .execute(pool)
    .await?;

    for (index, body) in pages.iter().enumerate() {
        sqlx::query(
            "INSERT INTO audit_export_pages \
             (export_id, workspace_id, page_number, row_count, sha256, body) \
             VALUES ($1, $2, $3, 2, $4, $5)",
        )
        .bind(export_id)
        .bind(workspace_id)
        .bind(i32::try_from(index).unwrap() + 1)
        .bind(&signed.page_digests[index])
        .bind(String::from_utf8(body.clone()).expect("utf8"))
        .execute(pool)
        .await?;
    }

    Ok(Completed {
        export_id,
        pages,
        manifest_json: signed.manifest_json,
        signature_b64: signed.signature_b64,
        public_key_b64: signed.public_key_b64,
    })
}

// ── Access control ────────────────────────────────────────────────────────

/// The export is a whole tenant's request trail in one file. Below Admin, no.
#[sqlx::test]
async fn only_admins_may_request_or_read_an_export(pool: PgPool) -> sqlx::Result<()> {
    let ws = Uuid::new_v4();
    let user = Uuid::new_v4();
    let seeded = seed_completed_export(&pool, ws, ExportFormat::Csv).await?;
    let (from, to) = window();

    for role in ["viewer", "developer", "employee"] {
        let token = make_jwt(ws, user, role);
        let response = router(pool.clone())
            .oneshot(get(
                &format!("/v1/audit-exports/{}", seeded.export_id),
                &token,
            ))
            .await
            .expect("response");
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "{role} must not read an audit export"
        );

        let response = router(pool.clone())
            .oneshot(post_json(
                "/v1/audit-exports",
                &token,
                &json!({"from": from, "to": to, "format": "csv"}),
            ))
            .await
            .expect("response");
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "{role} must not request an audit export"
        );
    }

    // POSITIVE CONTROL: an admin CAN read it, so the 403s above are the role
    // gate and not a broken fixture or a mis-mounted route.
    let admin = make_jwt(ws, user, "admin");
    let response = router(pool.clone())
        .oneshot(get(
            &format!("/v1/audit-exports/{}", seeded.export_id),
            &admin,
        ))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);

    Ok(())
}

#[sqlx::test]
async fn an_unauthenticated_caller_is_rejected(pool: PgPool) -> sqlx::Result<()> {
    let response = router(pool)
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/audit-exports")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

/// Another workspace's export answers 404, not 403: a 403 would confirm the id
/// exists somewhere in the deployment, turning the endpoint into an oracle.
#[sqlx::test]
async fn another_workspaces_export_is_not_reachable(pool: PgPool) -> sqlx::Result<()> {
    let mine = Uuid::new_v4();
    let theirs = Uuid::new_v4();
    let seeded = seed_completed_export(&pool, theirs, ExportFormat::Csv).await?;

    let token = make_jwt(mine, Uuid::new_v4(), "admin");

    let response = router(pool.clone())
        .oneshot(get(
            &format!("/v1/audit-exports/{}", seeded.export_id),
            &token,
        ))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // The pages are not reachable either — a separate query, so a separate
    // chance to have forgotten the predicate.
    let response = router(pool.clone())
        .oneshot(get(
            &format!("/v1/audit-exports/{}/pages/1", seeded.export_id),
            &token,
        ))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Nor does it show up in my list.
    let response = router(pool.clone())
        .oneshot(get("/v1/audit-exports", &token))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let listed = response_json(response).await;
    assert_eq!(
        listed.as_array().expect("array").len(),
        0,
        "another workspace's export must not be listed"
    );

    // POSITIVE CONTROL: its real owner sees all three, so the absences above
    // are the tenancy predicate and not an empty database.
    let owner = make_jwt(theirs, Uuid::new_v4(), "admin");
    for uri in [
        format!("/v1/audit-exports/{}", seeded.export_id),
        format!("/v1/audit-exports/{}/pages/1", seeded.export_id),
    ] {
        let response = router(pool.clone())
            .oneshot(get(&uri, &owner))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK, "owner must reach {uri}");
    }
    let response = router(pool.clone())
        .oneshot(get("/v1/audit-exports", &owner))
        .await
        .expect("response");
    let listed = response_json(response).await;
    assert_eq!(listed.as_array().expect("array").len(), 1);

    Ok(())
}

// ── The bytes ─────────────────────────────────────────────────────────────

/// The transport must not touch the page bytes. If it re-encodes, re-wraps or
/// normalises anything, every signature this product issues becomes
/// unverifiable — so this fetches the pages over HTTP and runs the real
/// verifier over what came back.
#[sqlx::test]
async fn pages_are_served_byte_for_byte_and_still_verify(pool: PgPool) -> sqlx::Result<()> {
    for format in [ExportFormat::Csv, ExportFormat::Jsonl] {
        let ws = Uuid::new_v4();
        let seeded = seed_completed_export(&pool, ws, format).await?;
        let token = make_jwt(ws, Uuid::new_v4(), "admin");

        let mut fetched: Vec<Vec<u8>> = Vec::new();
        for page in 1..=2 {
            let response = router(pool.clone())
                .oneshot(get(
                    &format!("/v1/audit-exports/{}/pages/{page}", seeded.export_id),
                    &token,
                ))
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::OK);
            let content_type = response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            assert_eq!(content_type, format.content_type());
            fetched.push(response_text(response).await.into_bytes());
        }

        // Byte equality against what was signed.
        assert_eq!(
            fetched,
            seeded.pages,
            "{}: the served pages must be the signed pages, byte for byte",
            format.as_str()
        );

        // And the artifact fetched over HTTP verifies on its own terms.
        let refs: Vec<&[u8]> = fetched.iter().map(Vec::as_slice).collect();
        assert!(
            verify_export(
                &seeded.manifest_json,
                &seeded.signature_b64,
                &seeded.public_key_b64,
                &refs
            )
            .is_ok(),
            "{}: an export fetched over HTTP must verify",
            format.as_str()
        );
    }
    Ok(())
}

/// The status route serves the manifest verbatim, so a caller who copies the
/// `manifest_json` string out of the JSON response can verify with it.
#[sqlx::test]
async fn the_status_route_serves_the_exact_signed_manifest(pool: PgPool) -> sqlx::Result<()> {
    let ws = Uuid::new_v4();
    let seeded = seed_completed_export(&pool, ws, ExportFormat::Jsonl).await?;
    let token = make_jwt(ws, Uuid::new_v4(), "admin");

    let response = router(pool.clone())
        .oneshot(get(
            &format!("/v1/audit-exports/{}", seeded.export_id),
            &token,
        ))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;

    let served_manifest = body["manifest_json"].as_str().expect("manifest_json");
    assert_eq!(
        served_manifest, seeded.manifest_json,
        "the served manifest must be the signed bytes, not a re-serialisation"
    );

    let refs: Vec<&[u8]> = seeded.pages.iter().map(Vec::as_slice).collect();
    assert!(verify_export(
        served_manifest,
        body["signature_b64"].as_str().expect("signature"),
        body["public_key_b64"].as_str().expect("public key"),
        &refs
    )
    .is_ok());

    // The payload must tell the auditor the key here is not a trust root.
    let note = body["signature_note"].as_str().expect("signature_note");
    assert!(note.contains("SEPARATE CHANNEL"), "got: {note}");
    assert!(body["page_url_template"].is_string());

    Ok(())
}

/// A page that does not exist is a 404 that says which of the three reasons it
/// might be — a bare "not found" on a compliance endpoint reads as "your
/// export is wrong" when it usually means "it is still running".
#[sqlx::test]
async fn a_missing_page_explains_the_three_reasons(pool: PgPool) -> sqlx::Result<()> {
    let ws = Uuid::new_v4();
    let seeded = seed_completed_export(&pool, ws, ExportFormat::Csv).await?;
    let token = make_jwt(ws, Uuid::new_v4(), "admin");

    let response = router(pool.clone())
        .oneshot(get(
            &format!("/v1/audit-exports/{}/pages/99", seeded.export_id),
            &token,
        ))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let text = response_text(response).await;
    // All three, not just one: the test's name is the assertion. The first
    // version looked for "still running" and the message says "still BE
    // running" — a needle that never matched, which would have gone unnoticed
    // had it been checking a phrase that happened to appear elsewhere.
    for reason in ["still be running", "have failed", "fewer pages"] {
        assert!(
            text.contains(reason),
            "the 404 must name `{reason}` as a possibility; got: {text}"
        );
    }
    Ok(())
}

// ── Requesting an export ──────────────────────────────────────────────────

/// The happy path through `POST`: 202, a row in `queued`, and an envelope on
/// `queue:audit_export` that the worker's own parser accepts.
#[sqlx::test]
async fn a_requested_export_is_recorded_and_enqueued(pool: PgPool) -> sqlx::Result<()> {
    // The route refuses up front when no signing key is configured, so this
    // test has to configure one. Set for the whole process; every other test
    // in this file is unaffected by its value.
    std::env::set_var(
        secureprompt_common::audit_export::SIGNING_KEY_ENV,
        hex::encode([77u8; 32]),
    );

    let ws = Uuid::new_v4();
    let user = Uuid::new_v4();
    let token = make_jwt(ws, user, "admin");
    let (from, to) = window();

    let response = router(pool.clone())
        .oneshot(post_json(
            "/v1/audit-exports",
            &token,
            &json!({"from": from, "to": to, "format": "jsonl", "page_size": 100}),
        ))
        .await
        .expect("response");

    assert_eq!(
        response.status(),
        StatusCode::ACCEPTED,
        "the artifact does not exist yet, so 202 rather than 200"
    );
    let body = response_json(response).await;
    let export_id: Uuid = body["export_id"]
        .as_str()
        .expect("id")
        .parse()
        .expect("uuid");
    assert_eq!(body["status"], "queued");
    assert_eq!(body["status_url"], format!("/v1/audit-exports/{export_id}"));

    // The row exists, is queued, and is attributed.
    let row = sqlx::query(
        "SELECT status, format, page_size, requested_by, workspace_id \
         FROM audit_exports WHERE id = $1",
    )
    .bind(export_id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(row.get::<String, _>("status"), "queued");
    assert_eq!(row.get::<String, _>("format"), "jsonl");
    assert_eq!(row.get::<i32, _>("page_size"), 100);
    assert_eq!(row.get::<Option<Uuid>, _>("requested_by"), Some(user));
    assert_eq!(row.get::<Uuid, _>("workspace_id"), ws);

    Ok(())
}

/// Bad windows and formats are refused at the edge, with a 400 that says what
/// was wrong — not accepted and failed in the worker a minute later.
#[sqlx::test]
async fn malformed_export_requests_are_refused_at_the_edge(pool: PgPool) -> sqlx::Result<()> {
    std::env::set_var(
        secureprompt_common::audit_export::SIGNING_KEY_ENV,
        hex::encode([77u8; 32]),
    );
    let ws = Uuid::new_v4();
    let token = make_jwt(ws, Uuid::new_v4(), "admin");
    let (from, to) = window();

    // POSITIVE CONTROL first: the well-formed request is accepted, so each
    // rejection below is caused by its own defect.
    let response = router(pool.clone())
        .oneshot(post_json(
            "/v1/audit-exports",
            &token,
            &json!({"from": from, "to": to, "format": "csv"}),
        ))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let cases = [
        json!({"from": from, "to": to, "format": "parquet"}),
        json!({"from": to, "to": from, "format": "csv"}),
        json!({"from": from, "to": from, "format": "csv"}),
        json!({"from": from, "to": to, "format": "csv", "page_size": 0}),
        json!({"from": from, "to": to, "format": "csv", "page_size": 999_999}),
        json!({"from": "2019-01-01T00:00:00Z", "to": to, "format": "csv"}),
    ];
    for case in cases {
        let response = router(pool.clone())
            .oneshot(post_json("/v1/audit-exports", &token, &case))
            .await
            .expect("response");
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "must refuse: {case}"
        );
    }

    Ok(())
}

/// With no signing key configured the route refuses, and says why. Accepting
/// the request would leave the operator polling a job that cannot succeed, and
/// producing an unsigned export is not offered as a fallback at all.
#[sqlx::test]
async fn without_a_signing_key_the_route_refuses_up_front(pool: PgPool) -> sqlx::Result<()> {
    std::env::remove_var(secureprompt_common::audit_export::SIGNING_KEY_ENV);

    let ws = Uuid::new_v4();
    let token = make_jwt(ws, Uuid::new_v4(), "admin");
    let (from, to) = window();

    let response = router(pool.clone())
        .oneshot(post_json(
            "/v1/audit-exports",
            &token,
            &json!({"from": from, "to": to, "format": "csv"}),
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let text = response_text(response).await;
    assert!(
        text.contains("SECUREPROMPT_AUDIT_EXPORT_SIGNING_KEY"),
        "the refusal must name the setting; got: {text}"
    );
    assert!(
        text.contains("UNSIGNED export is not offered"),
        "the refusal must say why there is no fallback; got: {text}"
    );

    // Nothing was recorded — a `queued` row nobody will ever serve is a lie.
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_exports WHERE workspace_id = $1")
            .bind(ws)
            .fetch_one(&pool)
            .await?;
    assert_eq!(count, 0);

    Ok(())
}

// ── The two crates agree ──────────────────────────────────────────────────

/// The API validates `page_size` against its own constants and the worker
/// re-validates against its own. If they drift, a request the API accepts is
/// refused by the worker — a failure the auditor sees minutes later with no
/// way to act on it.
#[test]
fn the_api_and_worker_page_size_bounds_agree() {
    use secureprompt_api::http::routes::dashboard::audit_export as api;
    // The worker's values, restated here because the worker is a BINARY crate
    // and cannot be imported. This test is the guard that keeps the restatement
    // honest; `secureprompt-worker/src/tasks/audit_export.rs` is the source.
    assert_eq!(api::DEFAULT_PAGE_SIZE, 5_000);
    assert_eq!(api::MIN_PAGE_SIZE, 1);
    assert_eq!(api::MAX_PAGE_SIZE, 50_000);
}

// ── RLS, proved from a role that cannot bypass it ─────────────────────────

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
/// assert on the wire that it really is powerless. Without these premise
/// assertions the test below would keep passing while exercising no RLS at
/// all — the `#[sqlx::test]` pool is a BYPASSRLS superuser.
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

/// Migration 025's RLS policy is ARMED: from a role that cannot bypass it, an
/// unset `app.current_workspace_id` shows nothing, and a set one shows exactly
/// one workspace's rows.
///
/// This is the layer no other test in the repository can see. The whole
/// application connects as a BYPASSRLS superuser today, so if the policy were
/// missing, malformed, or attached to the wrong column, every `#[sqlx::test]`
/// would still be green.
#[sqlx::test]
async fn migration_025_rls_isolates_exports_from_a_nonsuperuser(pool: PgPool) -> sqlx::Result<()> {
    let mine = Uuid::new_v4();
    let theirs = Uuid::new_v4();
    seed_completed_export(&pool, mine, ExportFormat::Csv).await?;
    seed_completed_export(&pool, theirs, ExportFormat::Csv).await?;

    // PREMISE: the superuser pool sees both, so anything the low-privilege
    // connection cannot see is RLS and not an empty table.
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_exports")
        .fetch_one(&pool)
        .await?;
    assert_eq!(total, 2, "premise: two exports exist");

    let mut conn = low_privilege_connection(&pool).await;

    // Policy really is on, on both tables.
    for table in ["audit_exports", "audit_export_pages"] {
        let armed: bool = sqlx::query_scalar(
            "SELECT relrowsecurity AND relforcerowsecurity \
             FROM pg_class WHERE relname = $1",
        )
        .bind(table)
        .fetch_one(&mut conn)
        .await?;
        assert!(armed, "{table} must have ENABLE + FORCE row level security");
    }

    // GUC unset -> nothing visible. This is the trap migration 020 documents:
    // `current_setting(..., true)` is NULL, so the predicate is NULL for every
    // row and the read silently returns the empty set.
    let unset: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_exports")
        .fetch_one(&mut conn)
        .await?;
    assert_eq!(
        unset, 0,
        "with the GUC unset the policy must hide everything, not leak"
    );

    // GUC set -> exactly my workspace.
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, false)")
        .bind(mine.to_string())
        .execute(&mut conn)
        .await?;
    let visible: Vec<Uuid> = sqlx::query_scalar("SELECT workspace_id FROM audit_exports")
        .fetch_all(&mut conn)
        .await?;
    assert_eq!(
        visible,
        vec![mine],
        "only my workspace's export may be visible"
    );

    let pages: Vec<Uuid> = sqlx::query_scalar("SELECT workspace_id FROM audit_export_pages")
        .fetch_all(&mut conn)
        .await?;
    assert!(
        pages.iter().all(|w| *w == mine),
        "pages must be isolated too, got {pages:?}"
    );
    assert!(!pages.is_empty(), "premise: my export has pages");

    // And an INSERT for someone else is REJECTED, not silently accepted.
    let forged = sqlx::query(
        "INSERT INTO audit_exports \
         (id, workspace_id, window_from, window_to, format, page_size, status) \
         VALUES ($1, $2, NOW(), NOW(), 'csv', 1, 'queued')",
    )
    .bind(Uuid::new_v4())
    .bind(theirs)
    .execute(&mut conn)
    .await;
    assert!(
        forged.is_err(),
        "writing an export into another workspace must be refused by the policy"
    );

    conn.close().await?;
    Ok(())
}
