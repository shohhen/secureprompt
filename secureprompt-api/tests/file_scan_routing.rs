//! WS4-2 — file scanning routed through the gateway, and audited.
//!
//! # What this suite is about
//!
//! Before WS4-2 the LibreChat backend POSTed uploaded bytes straight to the ML
//! sidecar's `/v1/scan-file` carrying `ML_SIDECAR_INTERNAL_TOKEN`, the
//! service-to-service secret. Two consequences, both measured at `fb5e1df`
//! before a line of this branch was written:
//!
//!   * `grep -rn 'file_scan\|scan_file' --include=*.rs --include=*.sql`
//!     returned NOTHING. No file scan produced an audit record of any kind —
//!     not in `admin_audit`, not in ClickHouse. A scan was attributable to the
//!     chat backend and to nobody else.
//!   * The sidecar token authenticates a SERVICE. Every LibreChat user shared
//!     it, so the dashboard's "a viewer may look, not scan" rule
//!     (`secureprompt-web/src/app/api/proxy/ml/[...path]/route.ts`) had no
//!     counterpart on the chat path.
//!
//! The sidecar's own door was already shut: WS1-5 put
//! `Depends(_require_internal_token)` on every route but `/health`, `/ready`
//! and `/metrics`, and `secureprompt-ml/tests/test_sidecar_route_auth.py`
//! passes 30/30 at `fb5e1df`. That half of WS4-2 was already met. This suite is
//! about the half that was not: an authenticated, role-gated, AUDITED gateway
//! route in front of it.
//!
//! # What every test here holds to
//!
//! Each refusal carries a POSITIVE CONTROL in the same body — the same call
//! changed in exactly one dimension, which must succeed — and each
//! absence-claim carries a PREMISE assertion that the thing really was absent
//! first. A mock sidecar records every request it is handed, so "the gateway
//! refused" is distinguished from "the gateway forwarded and the mock was
//! never reachable".
//!
//! All fixture data is synthetic.

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use secureprompt_api::db::api_key_repo::hash_api_key;
use secureprompt_api::http::routes::scan_file;
use secureprompt_api::{
    app_state::AppState, http::build_router, http::middleware::jwt_auth::UserRole,
    ml_sidecar::MlSidecarClient,
};
use secureprompt_common::config::{
    AppConfig, ClickhouseConfig, DatabaseConfig, JwtConfig, LicenseConfig, RedisConfig,
    ServerConfig, TelemetryConfig,
};
use serde_json::Value;
use sqlx::{PgPool, Row};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;
use uuid::Uuid;

// ── Harness ───────────────────────────────────────────────────────────────

fn test_config() -> AppConfig {
    AppConfig {
        database: DatabaseConfig {
            url: "postgres://secureprompt:secureprompt@localhost:5432/postgres".to_owned(),
            max_connections: 5,
        },
        redis: RedisConfig {
            url: std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".into()),
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
            secret: "ws4-2-file-scan-routing-secret".to_owned(),
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

fn app_with_sidecar(pool: PgPool, sidecar_url: &str) -> axum::Router {
    let ml = Arc::new(MlSidecarClient::new(sidecar_url.to_owned(), 5_000));
    build_router(AppState::new(
        pool,
        test_config(),
        ml,
        Arc::new(secureprompt_api::license::LicenseState::unlicensed()),
    ))
}

/// A loopback HTTP server speaking just enough of the sidecar's scan protocol.
///
/// Shape borrowed from `tests/sidecar_failure_policy.rs::MockSidecar`, with one
/// addition that matters here: it records the request line of everything it is
/// handed, so a test can assert the gateway did NOT forward. A refusal test
/// whose mock was simply unreachable would pass for the wrong reason.
struct MockScanSidecar {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
}

impl MockScanSidecar {
    fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local addr");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&requests);

        std::thread::spawn(move || loop {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let Some(request) = read_http_request(&mut stream) else {
                continue;
            };
            let first_line = request.lines().next().unwrap_or_default().to_owned();

            let body: &[u8] = if first_line.contains("/v1/scan-file/async") {
                br#"{"task_id":"mocktask0123456789abcdef"}"#
            } else if first_line.contains("/v1/scan-file/tasks/") {
                br#"{"status":"done","result":{"redacted_text":"<PERSON>","original_filename":"a.txt","mime_type":"text/plain"}}"#
            } else {
                br#"{"redacted_text":"<PERSON>","original_filename":"a.txt","mime_type":"text/plain"}"#
            };

            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body);
            sink.lock().expect("request sink mutex").push(first_line);
        });

        Self { addr, requests }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn seen(&self) -> Vec<String> {
        self.requests.lock().expect("request sink mutex").clone()
    }
}

/// Read one complete HTTP request: headers, then exactly `Content-Length`
/// bytes of body. A server that replies before draining a multi-megabyte
/// upload leaves the client writing into a closed socket, and the gateway then
/// records a transport failure rather than the 200 the test is about.
fn read_http_request(stream: &mut std::net::TcpStream) -> Option<String> {
    let mut raw: Vec<u8> = Vec::new();
    let mut buf = [0u8; 65536];

    let header_end = loop {
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        let n = stream.read(&mut buf).ok()?;
        if n == 0 {
            return None;
        }
        raw.extend_from_slice(&buf[..n]);
    };

    let headers = String::from_utf8_lossy(&raw[..header_end]).to_string();
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);

    let mut consumed = raw.len();
    while consumed < header_end + content_length {
        let n = stream.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        consumed += n;
    }
    Some(headers)
}

// ── Seeding ───────────────────────────────────────────────────────────────

struct Member {
    user_id: Uuid,
    email: String,
    api_key: String,
}

async fn seed_workspace(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workspaces (id, name, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(id)
    .bind(format!("ws4-2 {}", Uuid::new_v4().simple()))
    .execute(pool)
    .await
    .expect("seed workspace");
    id
}

/// A workspace member plus an API key ASSIGNED to them — the shape migration
/// 009 created for the LibreChat path and the only shape a file scan accepts.
async fn seed_member(pool: &PgPool, workspace_id: Uuid, role: &str) -> Member {
    let user_id = Uuid::new_v4();
    let suffix = Uuid::new_v4().simple().to_string();
    let email = format!("{role}-{suffix}@example.invalid");
    sqlx::query(
        "INSERT INTO users (id, workspace_id, email, password_hash, role, created_at, updated_at)
         VALUES ($1, $2, $3, 'x', $4, NOW(), NOW())",
    )
    .bind(user_id)
    .bind(workspace_id)
    .bind(&email)
    .bind(role)
    .execute(pool)
    .await
    .expect("seed user");

    let api_key = format!("sp_ws42_{suffix}");
    sqlx::query(
        "INSERT INTO api_keys (id, workspace_id, name, key_hash, assigned_user_id, created_at)
         VALUES ($1, $2, $3, $4, $5, NOW())",
    )
    .bind(Uuid::new_v4())
    .bind(workspace_id)
    .bind(format!("{role}-key"))
    .bind(hash_api_key(&api_key))
    .bind(user_id)
    .execute(pool)
    .await
    .expect("seed api key");

    Member {
        user_id,
        email,
        api_key,
    }
}

/// An API key with NO `assigned_user_id` — the legacy workspace-scoped shape.
async fn seed_unassigned_key(pool: &PgPool, workspace_id: Uuid) -> String {
    let api_key = format!("sp_ws42_unassigned_{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO api_keys (id, workspace_id, name, key_hash, created_at)
         VALUES ($1, $2, 'legacy', $3, NOW())",
    )
    .bind(Uuid::new_v4())
    .bind(workspace_id)
    .bind(hash_api_key(&api_key))
    .execute(pool)
    .await
    .expect("seed unassigned api key");
    api_key
}

const MULTIPART_CT: &str = "multipart/form-data; boundary=ws42boundary";

fn multipart_body(payload_len: usize) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(
        b"--ws42boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\n",
    );
    body.extend(std::iter::repeat(b'x').take(payload_len));
    body.extend_from_slice(b"\r\n--ws42boundary--\r\n");
    body
}

fn scan_request(uri: &str, api_key: Option<&str>, payload_len: usize) -> Request<Body> {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, MULTIPART_CT);
    if let Some(key) = api_key {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {key}"));
    }
    let body = multipart_body(payload_len);
    builder = builder.header(header::CONTENT_LENGTH, body.len().to_string());
    builder.body(Body::from(body)).expect("request must build")
}

// ── Audit reads ───────────────────────────────────────────────────────────

struct AuditRow {
    action: String,
    actor_user_id: Option<Uuid>,
    actor_email: Option<String>,
    actor_role: Option<String>,
    target_type: String,
    target_id: Option<Uuid>,
    target_label: Option<String>,
    target_user_id: Option<Uuid>,
    detail: Value,
}

async fn audit_rows(pool: &PgPool, workspace_id: Uuid) -> Vec<AuditRow> {
    sqlx::query(
        "SELECT action, actor_user_id, actor_email, actor_role, target_type,
                target_id, target_label, target_user_id, detail
           FROM admin_audit
          WHERE workspace_id = $1
          ORDER BY created_at, action",
    )
    .bind(workspace_id)
    .fetch_all(pool)
    .await
    .expect("read admin_audit")
    .into_iter()
    .map(|r| AuditRow {
        action: r.get("action"),
        actor_user_id: r.get("actor_user_id"),
        actor_email: r.get("actor_email"),
        actor_role: r.get("actor_role"),
        target_type: r.get("target_type"),
        target_id: r.get("target_id"),
        target_label: r.get("target_label"),
        target_user_id: r.get("target_user_id"),
        detail: r.get("detail"),
    })
    .collect()
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024)
        .await
        .expect("collect body");
    serde_json::from_slice(&bytes).expect("json body")
}

// ── Criterion: the unauthenticated path is closed at the gateway ──────────

/// A scan with no `Authorization` is refused BEFORE any byte reaches the
/// sidecar, and writes nothing.
///
/// The mock records what it is handed, so "refused" is separated from
/// "unreachable": the positive control at the end sends the SAME request with
/// a valid assigned key and the mock must then have seen exactly one scan.
#[sqlx::test]
async fn an_unauthenticated_scan_is_refused_before_the_sidecar_sees_a_byte(pool: PgPool) {
    let sidecar = MockScanSidecar::spawn();
    let ws = seed_workspace(&pool).await;
    let member = seed_member(&pool, ws, "admin").await;
    let app = app_with_sidecar(pool.clone(), &sidecar.url());

    // PREMISE: nothing has been audited for this workspace yet, so the
    // "still zero" claim below is about this request and not about an empty
    // table that was always going to be empty.
    assert!(
        audit_rows(&pool, ws).await.is_empty(),
        "premise: a freshly seeded workspace has no admin_audit rows"
    );

    let response = app
        .clone()
        .oneshot(scan_request("/v1/scan-file", None, 64))
        .await
        .expect("router responds");
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "a scan with no Authorization header must be refused at the gateway"
    );
    assert!(
        sidecar.seen().is_empty(),
        "the refused scan must not have been forwarded; sidecar saw {:?}",
        sidecar.seen()
    );
    assert!(
        audit_rows(&pool, ws).await.is_empty(),
        "a refused scan must not write an audit row"
    );

    // POSITIVE CONTROL — the same request, one dimension changed.
    let ok = app
        .oneshot(scan_request(
            "/v1/scan-file",
            Some(&member.api_key),
            64,
        ))
        .await
        .expect("router responds");
    assert_eq!(
        ok.status(),
        StatusCode::OK,
        "positive control: the same scan with an assigned API key must succeed"
    );
    assert_eq!(
        sidecar.seen().len(),
        1,
        "positive control: the mock sidecar really is reachable and really \
         does serve /v1/scan-file"
    );
}

/// A key that is not `sp_`-shaped, and a key that does not exist, are both 401
/// — the gateway does not fall back to the service-to-service token the chat
/// backend used to carry.
#[sqlx::test]
async fn a_bogus_api_key_cannot_scan(pool: PgPool) {
    let sidecar = MockScanSidecar::spawn();
    let ws = seed_workspace(&pool).await;
    let member = seed_member(&pool, ws, "developer").await;
    let app = app_with_sidecar(pool.clone(), &sidecar.url());

    for bogus in ["not-an-sp-key", "sp_this_key_was_never_issued"] {
        let response = app
            .clone()
            .oneshot(scan_request("/v1/scan-file", Some(bogus), 32))
            .await
            .expect("router responds");
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "`{bogus}` must not authenticate a file scan"
        );
    }
    assert!(sidecar.seen().is_empty(), "nothing may have been forwarded");
    assert!(audit_rows(&pool, ws).await.is_empty(), "nothing audited");

    // POSITIVE CONTROL.
    let ok = app
        .oneshot(scan_request("/v1/scan-file", Some(&member.api_key), 32))
        .await
        .expect("router responds");
    assert_eq!(ok.status(), StatusCode::OK, "positive control");
}

// ── Criterion: the role gate ─────────────────────────────────────────────

/// A viewer's key is refused where an employee's key is served.
///
/// `viewer` and `employee` sit at the SAME privilege level
/// (`role::privilege_level` gives both 1), so this gate cannot be expressed as
/// `require_role(ctx, Developer)` — that would refuse the employee too. The
/// dashboard's ML proxy draws the same line by naming the roles
/// (`SCAN_ROLES` in `secureprompt-web/src/app/api/proxy/ml/[...path]/route.ts`),
/// and this is that line on the gateway.
#[sqlx::test]
async fn a_viewer_may_not_scan_where_an_employee_may(pool: PgPool) {
    let sidecar = MockScanSidecar::spawn();
    let ws = seed_workspace(&pool).await;
    let viewer = seed_member(&pool, ws, "viewer").await;
    let employee = seed_member(&pool, ws, "employee").await;
    let app = app_with_sidecar(pool.clone(), &sidecar.url());

    let refused = app
        .clone()
        .oneshot(scan_request("/v1/scan-file", Some(&viewer.api_key), 64))
        .await
        .expect("router responds");
    assert_eq!(
        refused.status(),
        StatusCode::FORBIDDEN,
        "a viewer's API key must not be able to run a file scan"
    );
    assert!(
        sidecar.seen().is_empty(),
        "the viewer's bytes must not reach the sidecar; saw {:?}",
        sidecar.seen()
    );
    assert!(
        audit_rows(&pool, ws).await.is_empty(),
        "a refused scan writes no audit row"
    );

    // POSITIVE CONTROL — same call, role changed, and it must DIFFER.
    let served = app
        .oneshot(scan_request(
            "/v1/scan-file",
            Some(&employee.api_key),
            64,
        ))
        .await
        .expect("router responds");
    assert_ne!(
        served.status(),
        StatusCode::FORBIDDEN,
        "an employee shares the viewer's privilege LEVEL, so a level-based \
         gate would refuse them too — that is the defect this test pins"
    );
    assert_eq!(served.status(), StatusCode::OK);
    assert_eq!(sidecar.seen().len(), 1);
    assert_eq!(
        audit_rows(&pool, ws).await.len(),
        1,
        "exactly the served scan is audited"
    );
}

/// A workspace-scoped key with no `assigned_user_id` cannot scan.
///
/// The point of routing scans through the gateway is that the record names a
/// PERSON. An unassigned key names no member, so a row written for it would
/// carry a NULL actor — an audit record that cannot answer the question it
/// exists for. Refused instead.
#[sqlx::test]
async fn an_unassigned_workspace_key_cannot_scan(pool: PgPool) {
    let sidecar = MockScanSidecar::spawn();
    let ws = seed_workspace(&pool).await;
    let legacy = seed_unassigned_key(&pool, ws).await;
    let member = seed_member(&pool, ws, "owner").await;
    let app = app_with_sidecar(pool.clone(), &sidecar.url());

    let refused = app
        .clone()
        .oneshot(scan_request("/v1/scan-file", Some(&legacy), 64))
        .await
        .expect("router responds");
    assert_eq!(
        refused.status(),
        StatusCode::FORBIDDEN,
        "a key assigned to nobody must not be able to run an attributable scan"
    );
    assert!(sidecar.seen().is_empty());
    assert!(audit_rows(&pool, ws).await.is_empty());

    // POSITIVE CONTROL — an assigned key in the same workspace is served.
    let ok = app
        .oneshot(scan_request("/v1/scan-file", Some(&member.api_key), 64))
        .await
        .expect("router responds");
    assert_eq!(ok.status(), StatusCode::OK, "positive control");
}

// ── Criterion: every scan produces an audit record ───────────────────────

/// The row reads alone: who scanned, in which workspace, through which key,
/// how many bytes, and which endpoint.
#[sqlx::test]
async fn a_scan_writes_one_audit_row_that_names_the_person_who_ran_it(pool: PgPool) {
    let sidecar = MockScanSidecar::spawn();
    let ws = seed_workspace(&pool).await;
    let member = seed_member(&pool, ws, "developer").await;
    let app = app_with_sidecar(pool.clone(), &sidecar.url());

    assert!(
        audit_rows(&pool, ws).await.is_empty(),
        "premise: nothing audited before the scan"
    );

    let response = app
        .clone()
        .oneshot(scan_request(
            "/v1/scan-file",
            Some(&member.api_key),
            128,
        ))
        .await
        .expect("router responds");
    assert_eq!(response.status(), StatusCode::OK);

    let rows = audit_rows(&pool, ws).await;
    assert_eq!(rows.len(), 1, "exactly one row per scan");
    let row = &rows[0];
    assert_eq!(row.action, "file_scan.requested");
    assert_eq!(row.actor_user_id, Some(member.user_id));
    assert_eq!(row.actor_email.as_deref(), Some(member.email.as_str()));
    assert_eq!(row.actor_role.as_deref(), Some("developer"));
    assert_eq!(row.target_type, "file_scan");
    assert!(
        row.target_id.is_some(),
        "the row must point at the scan it records"
    );
    assert_eq!(
        row.target_user_id,
        Some(member.user_id),
        "the scan is a self-service action, so the export's user columns are \
         filled rather than the principal being buried in `detail`"
    );
    assert_eq!(
        row.detail["mode"], "sync",
        "the row must say which endpoint served it"
    );
    assert!(
        row.detail["request_bytes"].as_u64().unwrap_or(0) > 128,
        "the row must carry the size of what was scanned; got {}",
        row.detail["request_bytes"]
    );
    assert!(
        row.detail["api_key_id"].as_str().is_some(),
        "the row must name the key that authenticated the scan"
    );

    // A SECOND scan writes a SECOND row — the count moves with the action.
    let again = app
        .oneshot(scan_request("/v1/scan-file", Some(&member.api_key), 8))
        .await
        .expect("router responds");
    assert_eq!(again.status(), StatusCode::OK);
    assert_eq!(
        audit_rows(&pool, ws).await.len(),
        2,
        "one row per scan, not one row per workspace"
    );
}

/// No end-user text reaches the trail. The uploaded FILENAME in particular is
/// chat-user content, not an administrator's object name, so it must not land
/// in `target_label` — the one administrator-supplied string migration 028
/// admits.
#[sqlx::test]
async fn the_uploaded_filename_never_reaches_the_audit_trail(pool: PgPool) {
    let sidecar = MockScanSidecar::spawn();
    let ws = seed_workspace(&pool).await;
    let member = seed_member(&pool, ws, "admin").await;
    let app = app_with_sidecar(pool.clone(), &sidecar.url());

    // The multipart body names the file `a.txt` (see `multipart_body`) and
    // carries a run of `x` as its content. Both are searched for below.
    let response = app
        .oneshot(scan_request(
            "/v1/scan-file",
            Some(&member.api_key),
            64,
        ))
        .await
        .expect("router responds");
    assert_eq!(response.status(), StatusCode::OK);

    let rows = audit_rows(&pool, ws).await;
    assert_eq!(rows.len(), 1, "premise: there is a row to search");
    let row = &rows[0];
    assert_eq!(
        row.target_label, None,
        "`target_label` carries an administrator's object name; an uploaded \
         filename is a chat user's content"
    );
    let haystack = format!("{}{}", row.detail, row.target_label.clone().unwrap_or_default());
    assert!(
        !haystack.contains("a.txt"),
        "the uploaded filename must not reach the audit trail: {haystack}"
    );
    // POSITIVE CONTROL for the search itself: a string that IS in the row is
    // found by the same needle-in-haystack method, so a clean result above is
    // evidence rather than a broken search.
    assert!(
        haystack.contains("sync"),
        "positive control: the search method does find a value that is \
         genuinely in the row"
    );
}

// ── Criterion: the async endpoints, and task-poll tenancy ────────────────

/// The large-file path is routed and audited too, and its poll is scoped to
/// the workspace that started the scan.
#[sqlx::test]
async fn an_async_scan_is_audited_and_its_task_belongs_to_one_workspace(pool: PgPool) {
    let sidecar = MockScanSidecar::spawn();
    let ws_a = seed_workspace(&pool).await;
    let a = seed_member(&pool, ws_a, "employee").await;
    let ws_b = seed_workspace(&pool).await;
    let b = seed_member(&pool, ws_b, "admin").await;
    let app = app_with_sidecar(pool.clone(), &sidecar.url());

    let kickoff = app
        .clone()
        .oneshot(scan_request(
            "/v1/scan-file/async",
            Some(&a.api_key),
            256,
        ))
        .await
        .expect("router responds");
    assert_eq!(kickoff.status(), StatusCode::OK);
    let task_id = body_json(kickoff).await["task_id"]
        .as_str()
        .expect("kickoff returns a task_id")
        .to_owned();

    let rows = audit_rows(&pool, ws_a).await;
    assert_eq!(rows.len(), 1, "the async kickoff is audited too");
    assert_eq!(rows[0].action, "file_scan.requested");
    assert_eq!(
        rows[0].detail["mode"], "async",
        "the row must distinguish which endpoint ran the scan"
    );

    let forwarded_before_poll = sidecar.seen().len();

    // Workspace B knows the task id and is a perfectly good admin — in its own
    // workspace.
    let cross = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/v1/scan-file/tasks/{task_id}"))
                .header(header::AUTHORIZATION, format!("Bearer {}", b.api_key))
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router responds");
    assert_eq!(
        cross.status(),
        StatusCode::NOT_FOUND,
        "another workspace must not be able to read the result of this scan"
    );
    assert_eq!(
        sidecar.seen().len(),
        forwarded_before_poll,
        "the cross-tenant poll must not have been forwarded to the sidecar"
    );

    // POSITIVE CONTROL — the workspace that started it can poll it.
    let own = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/v1/scan-file/tasks/{task_id}"))
                .header(header::AUTHORIZATION, format!("Bearer {}", a.api_key))
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router responds");
    assert_eq!(
        own.status(),
        StatusCode::OK,
        "positive control: the owning workspace can poll its own scan"
    );
    assert_eq!(
        sidecar.seen().len(),
        forwarded_before_poll + 1,
        "positive control: that poll really did reach the sidecar"
    );
    assert_eq!(
        audit_rows(&pool, ws_a).await.len(),
        1,
        "polling a running scan is not a new scan and writes no new row"
    );
}

// ── Criterion: the body limit is per-purpose ─────────────────────────────

/// A file upload is not a chat request, and the gateway's 2 MiB request-hygiene
/// ceiling would refuse most PDFs.
///
/// Bidirectional on purpose: the scan route must ACCEPT a body the rest of the
/// gateway REFUSES, and must still refuse one above its own ceiling. A
/// one-directional version of this test passes on a gateway with no limit at
/// all.
#[sqlx::test]
async fn the_scan_route_carries_a_bigger_body_than_the_rest_of_the_gateway(pool: PgPool) {
    let sidecar = MockScanSidecar::spawn();
    let ws = seed_workspace(&pool).await;
    let member = seed_member(&pool, ws, "admin").await;
    let app = app_with_sidecar(pool.clone(), &sidecar.url());

    // PREMISE: the general ceiling really is where this test thinks it is.
    assert_eq!(
        secureprompt_api::http::middleware::request_hygiene::DEFAULT_MAX_BODY_BYTES,
        2 * 1024 * 1024,
        "premise: the gateway-wide body ceiling is 2 MiB"
    );
    assert!(
        scan_file::DEFAULT_SCAN_MAX_BODY_BYTES > 3 * 1024 * 1024,
        "premise: the scan ceiling is above the 3 MiB body used below"
    );

    // 3 MiB — over the gateway-wide ceiling, under the scan ceiling.
    let over_general = 3 * 1024 * 1024;
    let accepted = app
        .clone()
        .oneshot(scan_request(
            "/v1/scan-file",
            Some(&member.api_key),
            over_general,
        ))
        .await
        .expect("router responds");
    assert_eq!(
        accepted.status(),
        StatusCode::OK,
        "a 3 MiB upload must be scannable — the sidecar's own ceiling is \
         15 MiB and routing through the gateway must not lower it"
    );

    // The SAME body on a general route is still refused, so the raised ceiling
    // is scoped to the scan routes rather than applied to the whole gateway.
    let general = Request::builder()
        .method(Method::GET)
        .uri("/metrics")
        .header(header::CONTENT_LENGTH, over_general.to_string())
        .body(Body::from(vec![b'x'; over_general]))
        .expect("request builds");
    let refused = app
        .clone()
        .oneshot(general)
        .await
        .expect("router responds");
    assert_eq!(
        refused.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "the rest of the gateway must keep its 2 MiB ceiling"
    );

    // And above the scan ceiling the scan route refuses too.
    let too_big = scan_file::DEFAULT_SCAN_MAX_BODY_BYTES + 1;
    let over_scan = Request::builder()
        .method(Method::POST)
        .uri("/v1/scan-file")
        .header(header::CONTENT_TYPE, MULTIPART_CT)
        .header(header::AUTHORIZATION, format!("Bearer {}", member.api_key))
        .header(header::CONTENT_LENGTH, too_big.to_string())
        .body(Body::empty())
        .expect("request builds");
    let refused_scan = app
        .oneshot(over_scan)
        .await
        .expect("router responds");
    assert_eq!(
        refused_scan.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "the scan route has a ceiling of its own, refused on Content-Length \
         before a byte is read"
    );
}

// ── Unit: the role predicate ─────────────────────────────────────────────

/// Bidirectional over the whole role set: exactly `Viewer` is refused and
/// every other role is allowed. A one-sided version passes on a predicate that
/// returns `true` unconditionally.
#[test]
fn exactly_the_viewer_role_is_refused_a_file_scan() {
    let allowed = [
        UserRole::Owner,
        UserRole::Admin,
        UserRole::Developer,
        UserRole::Employee,
    ];
    for role in allowed {
        assert!(
            scan_file::may_run_file_scan(role),
            "{role:?} must be able to run a file scan"
        );
    }
    assert!(
        !scan_file::may_run_file_scan(UserRole::Viewer),
        "a viewer is the dashboard's read-only role and must not scan"
    );
}

/// The gateway's rule and the dashboard proxy's `SCAN_ROLES` are the same rule.
/// Read from the TypeScript so a change on one side fails here rather than
/// producing two doors with different locks.
#[test]
fn the_gateway_and_the_dashboard_proxy_refuse_the_same_roles() {
    let route_ts = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root")
            .join("secureprompt-web/src/app/api/proxy/ml/[...path]/route.ts"),
    )
    .expect("the dashboard ML proxy must exist");

    let line = route_ts
        .lines()
        .find(|l| l.contains("SCAN_ROLES"))
        .expect("premise: the dashboard proxy declares SCAN_ROLES");
    for role in [
        UserRole::Owner,
        UserRole::Admin,
        UserRole::Developer,
        UserRole::Employee,
        UserRole::Viewer,
    ] {
        let named = line.contains(&format!("\"{}\"", role.as_db_str()));
        assert_eq!(
            named,
            scan_file::may_run_file_scan(role),
            "`{}`: the dashboard proxy and the gateway disagree about whether \
             this role may run a file scan. SCAN_ROLES line: {line}",
            role.as_db_str()
        );
    }
}
