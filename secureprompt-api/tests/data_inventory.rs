//! WS3-5 — `GET /v1/data-inventory`, the transparency endpoint.
//!
//! This endpoint is a COMPLIANCE ATTESTATION: a bank auditor reads its output
//! and believes it. An inventory that omits an artifact class, or claims
//! encryption it does not have, is worse than no endpoint at all — it converts
//! an unknown into a false assurance. Every test in this file exists to make
//! one specific way of lying impossible:
//!
//! | Test | The lie it makes impossible |
//! |---|---|
//! | `row_counts_are_real_and_workspace_scoped` | counts that are constants, or another tenant's |
//! | `encryption_state_is_derived_from_stored_bytes_not_the_self_asserted_flag` | `encrypted: true` over a plaintext payload |
//! | `every_table_the_product_creates_appears_in_the_inventory` | a silently omitted artifact class |
//! | `retention_days_without_an_enforcement_mechanism_is_never_reported` | "90 days" enforced by nothing |
//! | `unenumerable_classes_are_declared_rather_than_omitted` | dropping the Redis file vault because it has no workspace id |
//! | `inventory_never_echoes_stored_content` | an attestation that leaks the thing it attests about |
//!
//! All fixture PII is synthetic.

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use secureprompt_api::http::middleware::jwt_auth::Claims;
use secureprompt_api::{app_state::AppState, http::build_router, ml_sidecar::MlSidecarClient};
use secureprompt_common::config::{
    AppConfig, ClickhouseConfig, DatabaseConfig, JwtConfig, LicenseConfig, RedisConfig,
    ServerConfig, TelemetryConfig,
};
use serde_json::Value;
use sqlx::PgPool;
use std::collections::BTreeSet;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

const TEST_JWT_SECRET: &str = "data-inventory-test-jwt-secret!!";

/// Synthetic PII. Never appears in any real corpus; it is the needle
/// `inventory_never_echoes_stored_content` hunts for in the response body.
const SYNTHETIC_NAME: &str = "Anvar Karimov";

// ── Harness ───────────────────────────────────────────────────────────────

fn clickhouse_url() -> String {
    std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://localhost:8123".into())
}

fn clickhouse_db() -> String {
    std::env::var("CLICKHOUSE_DB").unwrap_or_else(|_| "sp_analytics".into())
}

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
            url: clickhouse_url(),
            database: clickhouse_db(),
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

fn build_app(pool: PgPool) -> Router {
    build_app_with_ch_db(pool, &clickhouse_db())
}

/// As [`build_app`], but pointed at a named `ClickHouse` database.
///
/// Used to make every gateway-table count FAIL — the only way to execute the
/// `row_count_status: unavailable` path for `request_events`,
/// `request_content_captures` and the legacy-plaintext scan, which on a healthy
/// deployment always succeed.
fn build_app_with_ch_db(pool: PgPool, database: &str) -> Router {
    let ml = Arc::new(MlSidecarClient::new(String::new(), 100));
    let mut config = test_config();
    config.clickhouse.database = database.to_owned();
    build_router(AppState::new(
        pool,
        config,
        ml,
        Arc::new(secureprompt_api::license::LicenseState::unlicensed()),
    ))
}

fn make_jwt(workspace_id: Uuid, user_id: Uuid, role: &str) -> String {
    let claims = Claims {
        sub: user_id,
        ws: workspace_id,
        role: role.to_owned(),
        jti: Uuid::new_v4().to_string(),
        exp: (chrono::Utc::now() + chrono::Duration::seconds(900)).timestamp(),
        iat: chrono::Utc::now().timestamp(),
        purpose: None,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(TEST_JWT_SECRET.as_bytes()),
    )
    .expect("jwt encode")
}

async fn seed_workspace(pool: &PgPool) -> (Uuid, Uuid) {
    let ws_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workspaces (id, name, created_at, updated_at)
         VALUES ($1, 'data-inventory-test-ws', NOW(), NOW())",
    )
    .bind(ws_id)
    .execute(pool)
    .await
    .expect("seed workspace");
    sqlx::query(
        "INSERT INTO users (id, workspace_id, email, password_hash, role, created_at, updated_at)
         VALUES ($1, $2, $3, '$argon2id$v=19$m=1,t=1,p=1$c29tZXNhbHQ$aaaa', 'admin', NOW(), NOW())",
    )
    .bind(user_id)
    .bind(ws_id)
    .bind(format!("inv-{}@example.com", Uuid::new_v4().simple()))
    .execute(pool)
    .await
    .expect("seed user");
    (ws_id, user_id)
}

/// POST a statement to the test `ClickHouse`, failing loudly with the server's
/// own error text. Same "never skip" stance as the RLS matrix: an unreachable
/// datastore must fail the run, not silently weaken it.
async fn clickhouse_exec(sql: String, what: &str) -> String {
    let resp = reqwest::Client::new()
        .post(clickhouse_url())
        .body(sql)
        .send()
        .await
        .unwrap_or_else(|e| {
            panic!(
                "ClickHouse unreachable at {} while {what} — the data-inventory \
                 suite cannot verify row counts without it and must not be \
                 skipped: {e}",
                clickhouse_url()
            )
        });
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "ClickHouse {what} failed ({status}): {body}"
    );
    body
}

async fn clickhouse_count(table: &str, predicate: &str) -> u64 {
    let body = clickhouse_exec(
        format!(
            "SELECT count() FROM {db}.{table} WHERE {predicate}",
            db = clickhouse_db()
        ),
        "counting rows",
    )
    .await;
    body.trim()
        .parse()
        .unwrap_or_else(|e| panic!("count() did not return a number ({body:?}): {e}"))
}

async fn seed_request_events(ws: Uuid, n: usize) {
    for i in 0..n {
        clickhouse_exec(
            format!(
                "INSERT INTO {db}.request_events \
                 (request_id, workspace_id, provider, model, final_action, cost_usd, \
                  estimated_usage, created_at) \
                 VALUES ('{rid}', '{ws}', 'openai', 'inv-model-{i}', 'allow', 1.5, false, now())",
                db = clickhouse_db(),
                rid = Uuid::new_v4(),
            ),
            "seeding request_events",
        )
        .await;
    }
}

async fn seed_policy_events(ws: Uuid, n: usize) {
    for i in 0..n {
        clickhouse_exec(
            format!(
                "INSERT INTO {db}.policy_events \
                 (request_id, workspace_id, rule_id, rule_name, action, dry_run, created_at) \
                 VALUES ('{rid}', '{ws}', '{rule}', 'inv-rule-{i}', 'redact', false, now())",
                db = clickhouse_db(),
                rid = Uuid::new_v4(),
                rule = Uuid::new_v4(),
            ),
            "seeding policy_events",
        )
        .await;
    }
}

async fn seed_latency_samples(ws: Uuid, n: usize) {
    for i in 0..n {
        clickhouse_exec(
            format!(
                "INSERT INTO {db}.latency_samples \
                 (request_id, workspace_id, model, latency_ms, created_at) \
                 VALUES ('{rid}', '{ws}', 'inv-model-{i}', 42, now())",
                db = clickhouse_db(),
                rid = Uuid::new_v4(),
            ),
            "seeding latency_samples",
        )
        .await;
    }
}

/// Distinct `model` per row so `SummingMergeTree` cannot collapse two seeded
/// rows into one between the premise assertion and the request.
async fn seed_token_usage(ws: Uuid, n: usize) {
    for i in 0..n {
        clickhouse_exec(
            format!(
                "INSERT INTO {db}.token_usage \
                 (workspace_id, model, date, input_tokens, output_tokens, cost_usd) \
                 VALUES ('{ws}', 'inv-tok-{tag}-{i}', today(), 10, 20, 0.5)",
                db = clickhouse_db(),
                tag = Uuid::new_v4().simple(),
            ),
            "seeding token_usage",
        )
        .await;
    }
}

/// Insert a `request_content_captures` row with a payload supplied verbatim,
/// and an `encrypted` flag supplied verbatim. Both are caller-controlled so a
/// test can build the exact row the WS3 reviewer found in production: the flag
/// saying `true` over a payload that is plainly not ciphertext.
async fn seed_capture(ws: Uuid, payload: &str, encrypted: bool) {
    clickhouse_exec(
        format!(
            "INSERT INTO {db}.request_content_captures \
             (request_id, workspace_id, created_at, expires_at, encrypted, \
              raw_prompt, raw_response, restored_response) \
             VALUES ('{rid}', '{ws}', now(), now() + INTERVAL 30 DAY, {enc}, \
                     '{payload}', NULL, NULL)",
            db = clickhouse_db(),
            rid = Uuid::new_v4(),
            enc = u8::from(encrypted),
            payload = payload.replace('\\', "\\\\").replace('\'', "\\'"),
        ),
        "seeding request_content_captures",
    )
    .await;
}

/// A `request_content_captures` row with NO payload in any of the three
/// content columns. The writer produces one whenever a capture-enabled
/// workspace makes a request that carried no user message it could keep.
async fn seed_capture_with_no_payload(ws: Uuid) {
    clickhouse_exec(
        format!(
            "INSERT INTO {db}.request_content_captures \
             (request_id, workspace_id, created_at, expires_at, encrypted, \
              raw_prompt, raw_response, restored_response) \
             VALUES ('{rid}', '{ws}', now(), now() + INTERVAL 30 DAY, 1, \
                     NULL, NULL, NULL)",
            db = clickhouse_db(),
            rid = Uuid::new_v4(),
        ),
        "seeding an empty request_content_captures row",
    )
    .await;
}

async fn get_inventory(app: &Router, token: &str) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/data-inventory")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("router");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 4 << 20)
        .await
        .expect("read body");
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}

/// The artifact entry for `class`, or a panic naming every class that IS
/// present — so a rename shows up as a readable diff instead of `None`.
fn artifact<'a>(body: &'a Value, class: &str) -> &'a Value {
    body["artifacts"]
        .as_array()
        .unwrap_or_else(|| panic!("`artifacts` must be an array, got: {body}"))
        .iter()
        .find(|entry| entry["class"] == Value::String(class.to_owned()))
        .unwrap_or_else(|| {
            panic!(
                "no artifact class `{class}` in the inventory. Present: {:?}",
                class_names(body)
            )
        })
}

/// Every class name the response declares, across BOTH lists. An artifact is
/// "covered" if it appears in either — enumerable with a count, or declared
/// un-enumerable with a reason.
fn class_names(body: &Value) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for key in ["artifacts", "not_enumerable"] {
        if let Some(entries) = body[key].as_array() {
            for entry in entries {
                if let Some(name) = entry["class"].as_str() {
                    names.insert(name.to_owned());
                }
            }
        }
    }
    names
}

fn row_count(body: &Value, class: &str) -> u64 {
    let entry = artifact(body, class);
    entry["row_count"]
        .as_u64()
        .unwrap_or_else(|| panic!("class `{class}` reported no numeric row_count: {entry}"))
}

// ── 1. Row counts ─────────────────────────────────────────────────────────

/// Counts must be REAL — queried live, per workspace.
///
/// Three separate defences against a vacuous pass:
///
/// 1. **Premise** — every seeded count is confirmed by a direct query against
///    the store BEFORE the endpoint is called, so "the endpoint reports 3"
///    cannot be true merely because 3 rows happened to exist.
/// 2. **Positive control that must differ** — a SECOND workspace is seeded
///    with a different, larger count in every table. A query missing its
///    tenancy predicate reports `mine + theirs` and fails; the two are never
///    equal because the other workspace's counts are all non-zero.
/// 3. **Distinguishing constants** — every class is seeded a DIFFERENT number
///    of rows (3/5/7/2/4), so a hardcoded constant fails, and so does a
///    copy-paste that counts the wrong table.
///
/// Falsifier: delete `AND workspace_id = ...` from any per-table count in
/// `clickhouse_counts` (or the `WHERE workspace_id = $1` in
/// `postgres_counts`) — this test then reports the two-workspace total.
#[sqlx::test]
async fn row_counts_are_real_and_workspace_scoped(pool: PgPool) {
    let (mine, my_user) = seed_workspace(&pool).await;
    let (theirs, _) = seed_workspace(&pool).await;

    // Deliberately different per class AND per workspace.
    seed_request_events(mine, 3).await;
    seed_request_events(theirs, 11).await;
    seed_policy_events(mine, 5).await;
    seed_policy_events(theirs, 13).await;
    seed_latency_samples(mine, 7).await;
    seed_latency_samples(theirs, 17).await;
    seed_token_usage(mine, 2).await;
    seed_token_usage(theirs, 19).await;
    for _ in 0..4 {
        seed_capture(
            mine,
            "ZmFrZS1jaXBoZXJ0ZXh0LXBhZGRpbmctdG8tMzgtY2hhcnM",
            true,
        )
        .await;
    }
    for _ in 0..23 {
        seed_capture(
            theirs,
            "ZmFrZS1jaXBoZXJ0ZXh0LXBhZGRpbmctdG8tMzgtY2hhcnM",
            true,
        )
        .await;
    }

    // Postgres: 6 vault entries for me, 29 for them.
    for (ws, n) in [(mine, 6), (theirs, 29)] {
        for _ in 0..n {
            sqlx::query(
                "INSERT INTO token_vault_entries (id, workspace_id, mapping_ciphertext)
                 VALUES ($1, $2, 'ZmFrZS1jaXBoZXJ0ZXh0LXBhZGRpbmctdG8tMzgtY2hhcnM')",
            )
            .bind(Uuid::new_v4())
            .bind(ws)
            .execute(&pool)
            .await
            .expect("seed token_vault_entries");
        }
    }

    // ---- Premise assertions, before anything is asserted about the API ----
    for (table, expected_mine, expected_theirs) in [
        ("request_events", 3_u64, 11_u64),
        ("policy_events", 5, 13),
        ("latency_samples", 7, 17),
        ("token_usage", 2, 19),
        ("request_content_captures", 4, 23),
    ] {
        assert_eq!(
            clickhouse_count(table, &format!("workspace_id = toUUID('{mine}')")).await,
            expected_mine,
            "premise failed: {table} does not hold the rows this test seeded \
             for its own workspace, so an equal report from the endpoint would \
             prove nothing"
        );
        assert_eq!(
            clickhouse_count(table, &format!("workspace_id = toUUID('{theirs}')")).await,
            expected_theirs,
            "premise failed: {table} holds no OTHER tenant's rows, so a query \
             missing its tenancy predicate would return the same number as a \
             correct one and this test could not tell them apart"
        );
    }
    let vault_theirs: i64 =
        sqlx::query_scalar("SELECT count(*) FROM token_vault_entries WHERE workspace_id = $1")
            .bind(theirs)
            .fetch_one(&pool)
            .await
            .expect("premise count");
    assert_eq!(
        vault_theirs, 29,
        "premise failed: no other tenant's vault rows exist"
    );

    let app = build_app(pool);
    let (status, body) = get_inventory(&app, &make_jwt(mine, my_user, "admin")).await;
    assert_eq!(status, StatusCode::OK, "data-inventory failed: {body}");

    for (class, expected) in [
        ("request_events", 3_u64),
        ("policy_events", 5),
        ("latency_samples", 7),
        ("token_usage", 2),
        ("request_content_captures", 4),
        ("token_vault_entries", 6),
    ] {
        assert_eq!(
            row_count(&body, class),
            expected,
            "class `{class}` must report exactly this workspace's rows. \
             Reporting {} (the two-workspace total) means the count query is \
             missing its tenancy predicate. Response: {body}",
            expected
                + match class {
                    "request_events" => 11,
                    "policy_events" => 13,
                    "latency_samples" => 17,
                    "token_usage" => 19,
                    "request_content_captures" => 23,
                    _ => 29,
                }
        );
    }

    // Positive control on the OTHER direction: the workspace's own row in
    // `workspaces` and its own user are counted too, so a response of all
    // zeroes (an endpoint that queries nothing) cannot pass.
    assert_eq!(
        row_count(&body, "users"),
        1,
        "the seeded admin user was not counted, so this workspace's Postgres \
         counts are not live: {body}"
    );
}

// ── 2. Encryption state ───────────────────────────────────────────────────

/// The encryption claim must be DERIVED FROM THE STORED BYTES, not read off
/// the row's own `encrypted` flag.
///
/// The WS3 review found a `request_content_captures` row carrying
/// `encrypted = true` over a plaintext payload. That flag is written by the
/// same code path that writes the payload, so it can only ever repeat what
/// that path believed — it is self-attestation, and an inventory that
/// republishes it launders a lie into an auditor's evidence pack.
///
/// Defences:
///
/// 1. **Premise** — the lying row is confirmed in `ClickHouse` to have
///    `encrypted = 1` AND a payload equal to the plaintext this test wrote.
///    Without that, "the endpoint said mixed" could be true because the row
///    never landed.
/// 2. **Positive control that MUST DIFFER** — a second workspace holds a row
///    sealed by the real `AppState` KMS. It must report `ciphertext`. The two
///    workspaces differ only in the bytes of the payload, so any
///    implementation that answers from the flag returns `ciphertext` for both
///    and fails here.
/// 3. **Bidirectional** — both the "honest ciphertext" and the "lying
///    plaintext" verdicts are asserted, so an implementation hardcoded to
///    either verdict fails.
///
/// Falsifier: make `capture_encryption_state` read the `encrypted` column
/// (`countIf(encrypted)`) instead of shape-checking the payload — the lying
/// workspace then reports `ciphertext` and this test fails.
#[sqlx::test]
async fn encryption_state_is_derived_from_stored_bytes_not_the_self_asserted_flag(pool: PgPool) {
    let (liar, liar_user) = seed_workspace(&pool).await;
    let (honest, honest_user) = seed_workspace(&pool).await;

    // The exact defect: flag says encrypted, payload is the user's prose.
    let plaintext = format!("Please summarise the contract for {SYNTHETIC_NAME}");
    seed_capture(liar, &plaintext, true).await;

    // The control: the same class, sealed by the process's real KMS.
    let kms = secureprompt_common::kms::kms_backend_from_env()
        .expect("KMS_FILE_KEY must be set for this suite — see .env");
    let sealed = String::from_utf8(
        kms.encrypt(plaintext.as_bytes())
            .await
            .expect("kms encrypt"),
    )
    .expect("ciphertext is UTF-8");
    seed_capture(honest, &sealed, true).await;

    // ---- Premise assertions ------------------------------------------------
    assert_eq!(
        clickhouse_count(
            "request_content_captures",
            &format!("workspace_id = toUUID('{liar}') AND encrypted = 1")
        )
        .await,
        1,
        "premise failed: the lying row is not flagged encrypted, so this test \
         does not exercise the flag-versus-bytes disagreement it is named for"
    );
    assert_eq!(
        clickhouse_count(
            "request_content_captures",
            &format!(
                "workspace_id = toUUID('{liar}') AND raw_prompt = '{}'",
                plaintext.replace('\'', "\\'")
            )
        )
        .await,
        1,
        "premise failed: the lying row's payload is not the plaintext this \
         test wrote, so 'the inventory noticed plaintext' proves nothing"
    );
    assert_ne!(
        sealed, plaintext,
        "premise failed: the KMS returned its input unchanged, so the control \
         row is not actually ciphertext"
    );

    let app = build_app(pool);

    let (status, liar_body) = get_inventory(&app, &make_jwt(liar, liar_user, "admin")).await;
    assert_eq!(status, StatusCode::OK, "data-inventory failed: {liar_body}");
    let liar_entry = artifact(&liar_body, "request_content_captures");

    let (status, honest_body) = get_inventory(&app, &make_jwt(honest, honest_user, "admin")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "data-inventory failed: {honest_body}"
    );
    let honest_entry = artifact(&honest_body, "request_content_captures");

    // ---- Positive control: honest ciphertext IS reported as ciphertext -----
    assert_eq!(
        honest_entry["encryption"]["at_rest"],
        Value::String("ciphertext".into()),
        "a genuinely KMS-sealed capture must report `ciphertext`, otherwise \
         the `plaintext` verdict below is just this endpoint refusing to \
         claim anything: {honest_entry}"
    );
    assert_eq!(
        honest_entry["encryption"]["verification"]["rows_not_matching"],
        Value::from(0),
        "a KMS-sealed payload failed the endpoint's own ciphertext predicate — \
         the predicate is wrong, not the data: {honest_entry}"
    );

    // ---- The assertion this test exists for --------------------------------
    assert_eq!(
        liar_entry["encryption"]["at_rest"],
        Value::String("plaintext".into()),
        "the inventory republished the row's self-asserted `encrypted = true` \
         over a plaintext payload. The encryption claim must be derived from \
         the stored bytes: {liar_entry}"
    );
    assert_eq!(
        liar_entry["encryption"]["verification"]["rows_not_matching"],
        Value::from(1),
        "the plaintext row was not counted as failing the ciphertext \
         predicate: {liar_entry}"
    );
}

/// The claim is only as good as the mechanism behind it, so the response must
/// say what the mechanism IS and whether it is working right now.
///
/// The workspace is seeded with a real sealed row in EACH ciphertext-bearing
/// class first. An earlier version of this test ran against an empty
/// workspace, where every such class reports `empty` and is skipped by the
/// loop below — it passed with `basis::KMS_SELF_TEST` deleted from
/// `Encryption::sealed`, because the only class it ever examined was `users`,
/// whose basis is assembled separately. The `covered` set at the bottom is
/// what makes that recurrence impossible.
///
/// Falsifier: remove `basis::KMS_SELF_TEST` from `Encryption::sealed`.
/// Whether the probe itself is real is proved separately, by
/// `kms_self_test_passes_only_on_a_true_round_trip` in the module's own unit
/// tests — asserting `kms_self_test == "ok"` here cannot distinguish a live
/// round trip from a hardcoded string.
#[sqlx::test]
async fn encryption_claims_name_their_basis_and_prove_the_kms_works_now(pool: PgPool) {
    let (ws, user) = seed_workspace(&pool).await;

    // Give every ciphertext-bearing class something genuinely sealed, so the
    // loop below actually reaches the `Encryption::sealed` path.
    let kms = secureprompt_common::kms::kms_backend_from_env()
        .expect("KMS_FILE_KEY must be set for this suite — see .env");
    let sealed = String::from_utf8(kms.encrypt(b"synthetic").await.expect("kms encrypt"))
        .expect("ciphertext is UTF-8");
    seed_capture(ws, &sealed, true).await;
    sqlx::query(
        "INSERT INTO token_vault_entries (id, workspace_id, mapping_ciphertext)
         VALUES ($1, $2, $3)",
    )
    .bind(Uuid::new_v4())
    .bind(ws)
    .bind(&sealed)
    .execute(&pool)
    .await
    .expect("seed vault");
    // And a provider credential. Without one, `providers` reports `empty` and
    // the loop below never examines the ONE class in this product that is not
    // sealed by the KMS — which is how it kept passing while that class cited
    // a KMS round trip performed against a different key.
    sqlx::query(
        "INSERT INTO providers (id, workspace_id, name, provider_type, encrypted_credential,
                                config, created_at, updated_at)
         VALUES ($1, $2, 'inv-basis-provider', 'openai',
                 'ZmFrZS1jaXBoZXJ0ZXh0LXBhZGRpbmctdG8tMzgtY2hhcnM', '{}'::jsonb, NOW(), NOW())",
    )
    .bind(Uuid::new_v4())
    .bind(ws)
    .execute(&pool)
    .await
    .expect("seed provider");

    let app = build_app(pool);
    let (status, body) = get_inventory(&app, &make_jwt(ws, user, "admin")).await;
    assert_eq!(status, StatusCode::OK, "data-inventory failed: {body}");

    // Premise: this deployment has a KMS at all.
    assert!(
        body["encryption_basis"]["kms_backend"].is_string(),
        "the response does not name a KMS backend: {body}"
    );
    assert_eq!(
        body["encryption_basis"]["kms_self_test"],
        Value::String("ok".into()),
        "the live encrypt→decrypt round trip failed or was never run; an \
         encryption claim resting on a KMS nobody probed is an assertion: {body}"
    );

    // Every class claiming ciphertext must name the substantiation.
    let entries = body["artifacts"].as_array().expect("artifacts array");
    let mut covered: BTreeSet<String> = BTreeSet::new();
    for entry in entries {
        let at_rest = entry["encryption"]["at_rest"].as_str().unwrap_or("");
        if at_rest != "ciphertext" && at_rest != "mixed" {
            continue;
        }
        let class = entry["class"].as_str().unwrap_or_default().to_owned();
        let basis: Vec<&str> = entry["encryption"]["basis"]
            .as_array()
            .unwrap_or_else(|| panic!("class {class} has no `basis` list: {entry}"))
            .iter()
            .filter_map(Value::as_str)
            .collect();
        // A LIVE KEY PROBE, and specifically the probe for the key that
        // actually sealed this class. `providers` is AES-256-GCM under
        // SECUREPROMPT_PROVIDER_KEY, never the KMS, and it used to cite
        // `kms_self_test` — a round trip against a key it does not use.
        assert!(
            basis.contains(&"kms_self_test") || basis.contains(&"provider_key_self_test"),
            "class {class} claims {at_rest} without resting on a live probe of \
             the key that sealed it: {basis:?}"
        );
        assert!(
            basis.contains(&"stored_payload_shape"),
            "class {class} claims {at_rest} without checking the bytes \
             actually on disk: {basis:?}"
        );
        covered.insert(class);
    }

    // The two probes must be about DIFFERENT keys, or the disjunction above is
    // an alias and `providers` is back to citing the KMS.
    let providers = artifact(&body, "providers");
    let provider_basis: Vec<&str> = providers["encryption"]["basis"]
        .as_array()
        .expect("providers basis")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        provider_basis.contains(&"provider_key_self_test")
            && !provider_basis.contains(&"kms_self_test"),
        "`providers` must rest on the provider-key probe and NOT on the KMS \
         probe: {provider_basis:?}"
    );
    assert!(
        body["encryption_basis"]["provider_key_self_test"].is_string(),
        "the provider key was never probed, so the basis it names is a label \
         and not a measurement: {body}"
    );

    // Positive controls. The loop above passes vacuously over an empty set,
    // and it passed for months of nothing if the only class it ever saw was
    // one whose basis is assembled elsewhere. Every seeded ciphertext class
    // must have been examined — including `providers`, whose absence from this
    // list is exactly how its wrong basis survived.
    for class in [
        "request_content_captures",
        "token_vault_entries",
        "providers",
    ] {
        assert!(
            covered.contains(class),
            "`{class}` was seeded with a genuinely sealed row and did not \
             report ciphertext, so the basis assertions never ran against the \
             sealed code path. Examined: {covered:?}. Response: {body}"
        );
    }
}

/// A row with NOTHING stored in it must never be reported as encrypted.
///
/// `ch_sealed` wraps its predicate in `ifNull(..., 1)`, so a NULL payload
/// column reads as SEALED. A `request_content_captures` row whose three
/// content columns are all NULL therefore counted as `matching`, and a
/// workspace holding only such rows reported `at_rest: ciphertext` with
/// `rows_not_matching: 0` — the strongest verdict this endpoint can give,
/// resting on zero bytes of evidence. The vocabulary already has the honest
/// answer for that state (`empty`: "nothing stored, so nothing was verified"),
/// and it was unreachable.
///
/// PREMISE: the payload-free row is confirmed on disk, all three columns NULL.
/// POSITIVE CONTROL: a second workspace holding a genuinely sealed row must
/// still report `ciphertext`, so `empty` below is a verdict about the bytes and
/// not this endpoint refusing to claim anything.
#[sqlx::test]
async fn a_capture_row_with_no_payload_is_not_reported_as_encrypted(pool: PgPool) {
    let (hollow, hollow_user) = seed_workspace(&pool).await;
    let (sealed_ws, sealed_user) = seed_workspace(&pool).await;

    seed_capture_with_no_payload(hollow).await;

    let kms = secureprompt_common::kms::kms_backend_from_env()
        .expect("KMS_FILE_KEY must be set for this suite — see .env");
    let sealed = String::from_utf8(kms.encrypt(b"synthetic").await.expect("kms encrypt"))
        .expect("ciphertext is UTF-8");
    seed_capture(sealed_ws, &sealed, true).await;

    // ---- Premise ----------------------------------------------------------
    assert_eq!(
        clickhouse_count(
            "request_content_captures",
            &format!(
                "workspace_id = toUUID('{hollow}') AND raw_prompt IS NULL \
                 AND raw_response IS NULL AND restored_response IS NULL"
            )
        )
        .await,
        1,
        "premise failed: the payload-free row is not on disk in the shape this \
         test is named for"
    );

    let app = build_app(pool);

    let (status, body) = get_inventory(&app, &make_jwt(hollow, hollow_user, "admin")).await;
    assert_eq!(status, StatusCode::OK, "data-inventory failed: {body}");
    let entry = artifact(&body, "request_content_captures");

    // The row still EXISTS and must still be counted — this is about the
    // encryption verdict, not about hiding the row.
    assert_eq!(
        row_count(&body, "request_content_captures"),
        1,
        "the payload-free row must still be inventoried: {entry}"
    );
    assert_eq!(
        entry["encryption"]["at_rest"],
        Value::String("empty".into()),
        "a row with no payload in any content column was reported as \
         `{}` — `ifNull(..., 1)` makes an absent column read as ciphertext, so \
         this verdict rests on nothing: {entry}",
        entry["encryption"]["at_rest"]
    );

    // ---- POSITIVE CONTROL --------------------------------------------------
    let (status, sealed_body) =
        get_inventory(&app, &make_jwt(sealed_ws, sealed_user, "admin")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "data-inventory failed: {sealed_body}"
    );
    let sealed_entry = artifact(&sealed_body, "request_content_captures");
    assert_eq!(
        sealed_entry["encryption"]["at_rest"],
        Value::String("ciphertext".into()),
        "a genuinely sealed payload must still report ciphertext, or the \
         `empty` above is just this endpoint declining to answer: {sealed_entry}"
    );
    assert_eq!(
        sealed_entry["encryption"]["verification"]["rows_matching"],
        Value::from(1),
        "the sealed row must be counted as verified evidence: {sealed_entry}"
    );
}

/// `at_rest` is advertised as COMPUTED from `verification`, never declared per
/// class. Two classes contradicted that, and an auditor reading the caveat had
/// no way to know which:
///
/// * `redis:filevault` is a bare `CIPHERTEXT` literal with `verification:
///   None` — and its own note admits stashes written before the encryption
///   upgrade are plaintext JSON.
/// * `users` has its computed verdict OVERWRITTEN by hand, so it reports
///   `mixed` whether every password hash is Argon2id or none of them is.
///
/// This test does not forbid either. It requires the caveat to STOP CLAIMING
/// what is not true: any class asserting a protective verdict (`ciphertext`,
/// `hashed`, `mixed`) whose verdict the documented rule does not reproduce
/// from its own `verification` block must be NAMED in the caveat as an
/// exception, with what it actually rests on.
///
/// PREMISE + POSITIVE CONTROL: at least one class must be genuinely computed,
/// otherwise "every declared class is named" is satisfied by an endpoint that
/// declares everything; and a class name that does not exist must NOT be found
/// in the caveat, otherwise the substring search says yes to anything.
#[sqlx::test]
async fn encryption_verdicts_are_computed_or_named_as_exceptions(pool: PgPool) {
    let (ws, user) = seed_workspace(&pool).await;

    // Give the endpoint something genuinely verifiable, so the "computed" set
    // below cannot be empty.
    let kms = secureprompt_common::kms::kms_backend_from_env()
        .expect("KMS_FILE_KEY must be set for this suite — see .env");
    let sealed = String::from_utf8(kms.encrypt(b"synthetic").await.expect("kms encrypt"))
        .expect("ciphertext is UTF-8");
    seed_capture(ws, &sealed, true).await;

    let app = build_app(pool);
    let (status, body) = get_inventory(&app, &make_jwt(ws, user, "admin")).await;
    assert_eq!(status, StatusCode::OK, "data-inventory failed: {body}");

    let at_rest_caveat = body["caveats"]
        .as_array()
        .expect("caveats array")
        .iter()
        .filter_map(Value::as_str)
        .find(|c| c.contains("at_rest"))
        .unwrap_or_else(|| panic!("no caveat explains `at_rest`: {body}"))
        .to_owned();

    // POSITIVE CONTROL on the search itself.
    assert!(
        !at_rest_caveat.contains("redis:not_a_real_class"),
        "the caveat search matches classes that do not exist: {at_rest_caveat}"
    );

    let mut computed: BTreeSet<String> = BTreeSet::new();
    let mut declared: Vec<(String, String)> = Vec::new();
    for key in ["artifacts", "not_enumerable"] {
        for entry in body[key].as_array().expect("array") {
            let class = entry["class"].as_str().unwrap_or_default().to_owned();
            let verdict = entry["encryption"]["at_rest"].as_str().unwrap_or_default();
            // Only PROTECTIVE claims. `plaintext_by_design` and `empty` claim
            // nothing and need no verification to be honest.
            if !matches!(verdict, "ciphertext" | "hashed" | "mixed") {
                continue;
            }
            let verification = &entry["encryption"]["verification"];
            let (Some(matching), Some(not_matching)) = (
                verification["rows_matching"].as_u64(),
                verification["rows_not_matching"].as_u64(),
            ) else {
                declared.push((class, format!("no verification block: {verdict}")));
                continue;
            };
            // The rule the caveat states, applied to the class's own numbers.
            // `ciphertext` and `hashed` are the same shape — the difference is
            // which predicate ran, not which counts came back.
            let expected: &[&str] = if matching + not_matching == 0 {
                &["empty"]
            } else if not_matching == 0 {
                &["ciphertext", "hashed"]
            } else if matching == 0 {
                &["plaintext"]
            } else {
                &["mixed"]
            };
            if expected.contains(&verdict) {
                computed.insert(class);
            } else {
                declared.push((
                    class,
                    format!(
                        "reports `{verdict}` on {matching} matching / \
                         {not_matching} not matching, where the stated rule \
                         gives {expected:?}"
                    ),
                ));
            }
        }
    }

    // PREMISE + POSITIVE CONTROL: the rule reproduces at least one verdict.
    assert!(
        computed.contains("request_content_captures"),
        "a genuinely sealed capture row was seeded and its verdict is not \
         reproducible from its own verification block, so the check below is \
         not measuring what it claims. Computed: {computed:?}"
    );

    let unexplained: Vec<&(String, String)> = declared
        .iter()
        .filter(|(class, _)| !at_rest_caveat.contains(class.as_str()))
        .collect();
    assert!(
        unexplained.is_empty(),
        "these classes assert a protective `at_rest` verdict that is NOT \
         computed from their own `verification`, while the caveat claims \
         `at_rest` is \"COMPUTED from `verification`, never declared per \
         class\":\n  {unexplained:#?}\nEither compute them or name them in the \
         caveat with what the verdict actually rests on.\nCaveat: \
         {at_rest_caveat}"
    );
}

/// `providers` claimed `kms_self_test` as part of its basis. It does not use
/// the KMS at all.
///
/// `providers.encrypted_credential` is sealed with AES-256-GCM under
/// `SECUREPROMPT_PROVIDER_KEY`, a SEPARATE key from the one the KMS backend
/// holds — and `ProviderKeyConfig::from_env_or_zero` substitutes an ALL-ZERO
/// key when that variable is unset, which is the default. So the class could
/// report `ciphertext`, cite a live KMS round trip that had nothing to do with
/// it, and be sealed under a key every reader of the source knows.
/// Zero-key ciphertext passes `pg_sealed` too, because the shape check inspects
/// the envelope and not the key.
///
/// PREMISE: a provider row whose credential passes the shape check is seeded,
/// so the class reaches a protective verdict and its basis is actually
/// examined.
/// POSITIVE CONTROL: the classes that DO rest on the KMS must still say so, so
/// this is not just the basis list being emptied.
#[sqlx::test]
async fn the_provider_credential_key_is_probed_separately_from_the_kms(pool: PgPool) {
    let (ws, user) = seed_workspace(&pool).await;

    let kms = secureprompt_common::kms::kms_backend_from_env()
        .expect("KMS_FILE_KEY must be set for this suite — see .env");
    let sealed = String::from_utf8(kms.encrypt(b"synthetic").await.expect("kms encrypt"))
        .expect("ciphertext is UTF-8");
    seed_capture(ws, &sealed, true).await;

    // A provider credential shaped like the deployment's envelope. It is NOT
    // KMS output — provider credentials never are — which is the whole point.
    sqlx::query(
        "INSERT INTO providers (id, workspace_id, name, provider_type, encrypted_credential,
                                config, created_at, updated_at)
         VALUES ($1, $2, 'inv-provider', 'openai',
                 'ZmFrZS1jaXBoZXJ0ZXh0LXBhZGRpbmctdG8tMzgtY2hhcnM', '{}'::jsonb, NOW(), NOW())",
    )
    .bind(Uuid::new_v4())
    .bind(ws)
    .execute(&pool)
    .await
    .expect("seed provider");

    let app = build_app(pool);
    let (status, body) = get_inventory(&app, &make_jwt(ws, user, "admin")).await;
    assert_eq!(status, StatusCode::OK, "data-inventory failed: {body}");

    let providers = artifact(&body, "providers");
    let basis: Vec<&str> = providers["encryption"]["basis"]
        .as_array()
        .unwrap_or_else(|| panic!("providers has no basis list: {providers}"))
        .iter()
        .filter_map(Value::as_str)
        .collect();

    // PREMISE: the seeded credential took the class to a protective verdict,
    // so its basis is a live claim rather than an unexamined default.
    assert_eq!(
        providers["encryption"]["at_rest"],
        Value::String("ciphertext".into()),
        "premise: the seeded provider credential must reach a protective \
         verdict, or this class's basis claims nothing: {providers}"
    );

    assert!(
        !basis.contains(&"kms_self_test"),
        "`providers` rests its ciphertext claim on the KMS self-test. The \
         credential is sealed with AES-256-GCM under SECUREPROMPT_PROVIDER_KEY, \
         a different key the KMS probe never touches: {basis:?}"
    );

    // The substitute claim must be substantiated, not merely renamed.
    assert!(
        body["encryption_basis"]["provider_key_self_test"].is_string(),
        "the response does not report whether the provider credential key \
         itself works: {body}"
    );
    let note = providers["encryption"]["note"].as_str().unwrap_or_default();
    for needle in ["SECUREPROMPT_PROVIDER_KEY", "zero"] {
        assert!(
            note.contains(needle),
            "the note does not mention {needle:?} — an auditor cannot tell that \
             this class is sealed under a separate key with an all-zero \
             fallback: {note}"
        );
    }

    // ---- POSITIVE CONTROL: the KMS-backed classes still cite the KMS -------
    let capture = artifact(&body, "request_content_captures");
    let capture_basis: Vec<&str> = capture["encryption"]["basis"]
        .as_array()
        .expect("basis array")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        capture_basis.contains(&"kms_self_test"),
        "the class that IS sealed by the KMS stopped citing it, so the \
         assertion above was satisfied by emptying every basis list: \
         {capture_basis:?}"
    );
}

// ── 3. Completeness ───────────────────────────────────────────────────────

/// Extract every `CREATE TABLE [IF NOT EXISTS] <name>` from a migration dir.
fn tables_declared_in(dir: &str) -> BTreeSet<String> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(dir);
    let mut tables = BTreeSet::new();
    let entries = std::fs::read_dir(&root)
        .unwrap_or_else(|e| panic!("cannot read migration dir {}: {e}", root.display()));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("sql") {
            continue;
        }
        let sql = std::fs::read_to_string(&path).expect("read migration");
        for line in sql.lines() {
            // Skip comment lines — several migrations discuss `CREATE TABLE`
            // in prose, and a prose mention is not a table.
            let trimmed = line.trim_start();
            if trimmed.starts_with("--") {
                continue;
            }
            let Some(rest) = trimmed.strip_prefix("CREATE TABLE ") else {
                continue;
            };
            let rest = rest.strip_prefix("IF NOT EXISTS ").unwrap_or(rest);
            let name = rest
                .split(|c: char| c.is_whitespace() || c == '(')
                .next()
                .unwrap_or("")
                .trim();
            if !name.is_empty() {
                tables.insert(name.to_owned());
            }
        }
    }
    tables
}

/// An inventory that omits an artifact class is worse than no inventory: it
/// converts an unknown into a false assurance. This test derives the expected
/// set from the migrations themselves, so a future `CREATE TABLE` that nobody
/// adds to the inventory reddens the suite — the omission cannot be silent.
///
/// A class is "covered" if it appears in `artifacts` (enumerable, with a
/// count) OR in `not_enumerable` (declared, with a reason). Both are honest;
/// silence is not.
///
/// Falsifier: delete any single entry from `POSTGRES_CLASSES` or
/// `CLICKHOUSE_CLASSES` in the handler.
#[sqlx::test]
async fn every_table_the_product_creates_appears_in_the_inventory(pool: PgPool) {
    let postgres_tables = tables_declared_in("migrations");
    let clickhouse_tables = tables_declared_in("clickhouse/migrations");

    // Premise: the extractor found the schema. A regex that silently matches
    // nothing would make the loop below pass over an empty set.
    assert!(
        postgres_tables.len() >= 18,
        "premise failed: only {} Postgres tables extracted from migrations/, \
         so this test would pass vacuously. Found: {postgres_tables:?}",
        postgres_tables.len()
    );
    assert!(
        clickhouse_tables.len() >= 9,
        "premise failed: only {} ClickHouse tables extracted, so this test \
         would pass vacuously. Found: {clickhouse_tables:?}",
        clickhouse_tables.len()
    );
    assert!(
        postgres_tables.contains("token_vault_entries")
            && clickhouse_tables.contains("request_content_captures"),
        "premise failed: the extractor missed a table this suite seeds \
         directly, so its output cannot be trusted as the expected set"
    );

    let (ws, user) = seed_workspace(&pool).await;
    let app = build_app(pool);
    let (status, body) = get_inventory(&app, &make_jwt(ws, user, "admin")).await;
    assert_eq!(status, StatusCode::OK, "data-inventory failed: {body}");

    let declared = class_names(&body);
    // Positive control: the response declares SOMETHING, so `missing` being
    // empty cannot be an artefact of an empty expected set meeting an empty
    // response.
    assert!(
        declared.len() >= 20,
        "the inventory declares only {} classes, which cannot cover the \
         product's {} Postgres + {} ClickHouse tables: {declared:?}",
        declared.len(),
        postgres_tables.len(),
        clickhouse_tables.len()
    );

    let missing: Vec<&String> = postgres_tables
        .iter()
        .chain(clickhouse_tables.iter())
        .filter(|table| !declared.contains(*table))
        .collect();
    assert!(
        missing.is_empty(),
        "the product stores these tables and the inventory does not mention \
         them, in `artifacts` or in `not_enumerable`:\n  {missing:?}\n\
         An omitted artifact class is a false assurance. Declared: {declared:?}"
    );
}

/// Every Redis key prefix the gateway writes must be accounted for too. Redis
/// has no schema to derive from, so the expected set is spelled out here and
/// pinned to the source line that builds each key — if a key prefix is
/// renamed, `grep` finds this list.
#[sqlx::test]
async fn every_redis_key_class_the_gateway_writes_is_accounted_for(pool: PgPool) {
    let (ws, user) = seed_workspace(&pool).await;
    let app = build_app(pool);
    let (status, body) = get_inventory(&app, &make_jwt(ws, user, "admin")).await;
    assert_eq!(status, StatusCode::OK, "data-inventory failed: {body}");

    let declared = class_names(&body);
    for (class, written_by) in [
        ("redis:filevault", "redis/mod.rs stash_file_vault"),
        ("redis:jti_blacklist", "redis/mod.rs blacklist_jti"),
        ("redis:oidc_state", "redis/mod.rs store_oidc_state"),
        ("redis:budget", "dashboard/budgets.rs daily_key/monthly_key"),
        ("redis:queues", "redis/mod.rs enqueue_task"),
    ] {
        assert!(
            declared.contains(class),
            "Redis key class `{class}` (written by {written_by}) is absent \
             from the inventory: {declared:?}"
        );
    }
}

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
        .to_path_buf()
}

/// The directories dbt builds RELATIONS out of, read from `dbt_project.yml`
/// rather than hardcoded.
///
/// This walked `models/` alone, which is only one of the three. `dbt_project.yml`
/// also declares `snapshot-paths` and `seed-paths`, and both materialise a
/// TABLE: a snapshot is precisely the un-TTL'd row-level copy of
/// `request_events` that `int_requests_enriched` turned out to be, and a seed
/// is a CSV loaded into one. Verified by mutation — a
/// `snapshots/snap_request_events.sql` declaring a timestamp-strategy snapshot
/// of `request_events` was invisible to this scrape and the guard passed.
///
/// `test-paths` and `analysis-paths` are deliberately excluded: neither
/// materialises anything.
fn dbt_relation_dirs() -> BTreeSet<String> {
    let path = repo_root().join("secureprompt-analytics/dbt_project.yml");
    let yaml = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let mut dirs = BTreeSet::new();
    for line in yaml.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if !matches!(key.trim(), "model-paths" | "snapshot-paths" | "seed-paths") {
            continue;
        }
        for chunk in value.split('"').skip(1).step_by(2) {
            dirs.insert(chunk.to_owned());
        }
    }
    dirs
}

/// Every relation dbt MATERIALISES, derived from the files themselves.
///
/// `tables_declared_in` cannot see these: it greps `CREATE TABLE` out of the
/// two migration directories, and a dbt model is a `SELECT` in a `.sql` file
/// under `secureprompt-analytics/`. dbt names the relation after the FILE, so
/// the file stem is the relation name — for a seed too, which is a `.csv`.
///
/// A declared directory that does not exist yet is skipped rather than
/// panicking: `snapshots/` and `seeds/` are declared in `dbt_project.yml` and
/// absent from the repo today, and the point of reading the declaration is to
/// catch the first file dropped into one.
fn dbt_relations() -> BTreeSet<String> {
    fn walk(dir: &std::path::Path, out: &mut BTreeSet<String>) {
        let entries = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("cannot read dbt dir {}: {e}", dir.display()));
        for entry in entries {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else if matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("sql" | "csv")
            ) {
                let stem = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or_else(|| panic!("un-nameable dbt relation {}", path.display()));
                out.insert(stem.to_owned());
            }
        }
    }
    let analytics = repo_root().join("secureprompt-analytics");
    let mut relations = BTreeSet::new();
    for dir in dbt_relation_dirs() {
        let path = analytics.join(&dir);
        if path.is_dir() {
            walk(&path, &mut relations);
        }
    }
    relations
}

/// Every compose file the repo ships. A store is a store whichever profile
/// starts it.
///
/// This read `docker-compose.yml` alone, so a persistent store declared only in
/// the on-prem or the simple profile was invisible to the guard. Verified by
/// mutation: a `mysql` service with a `mysql_data:` volume added to
/// `docker-compose.simple.yml` was not seen and the guard passed.
const COMPOSE_FILES: [&str; 3] = [
    "docker-compose.yml",
    "docker-compose.onprem.yml",
    "docker-compose.simple.yml",
];

/// Every compose service that mounts a NAMED volume — i.e. every store the
/// product's own deployment starts and keeps across a restart.
///
/// A bind mount (`./backups:/backups`) is host state the operator chose and is
/// deliberately excluded; a named volume is one a compose file creates.
///
/// The named-volume set is the UNION across the files before any service is
/// matched, because an overlay (`docker-compose.onprem.yml`) legitimately
/// mounts a volume the base file declares.
fn compose_persistent_services() -> BTreeSet<String> {
    let sources: Vec<String> = COMPOSE_FILES
        .iter()
        .map(|file| {
            let path = repo_root().join(file);
            std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
        })
        .collect();

    // The top-level `volumes:` block of every file. Matched WITHOUT
    // indentation, so the per-service `    volumes:` keys cannot be mistaken
    // for it.
    let mut named: BTreeSet<&str> = BTreeSet::new();
    for yaml in &sources {
        let mut in_volumes = false;
        for line in yaml.lines() {
            if line.starts_with("volumes:") {
                in_volumes = true;
                continue;
            }
            if in_volumes {
                if !line.starts_with("  ") {
                    if !line.trim().is_empty() {
                        in_volumes = false;
                    }
                    continue;
                }
                let entry = line.trim();
                if let Some(name) = entry.strip_suffix(':') {
                    named.insert(name);
                }
            }
        }
    }

    let mut services = BTreeSet::new();
    for yaml in &sources {
        let mut current: Option<&str> = None;
        let mut in_services = false;
        for line in yaml.lines() {
            if line.starts_with("services:") {
                in_services = true;
                continue;
            }
            if in_services && !line.starts_with(' ') && !line.trim().is_empty() {
                in_services = false;
            }
            if !in_services {
                continue;
            }
            // A service key: exactly two spaces of indent, then `name:`.
            if let Some(rest) = line.strip_prefix("  ") {
                if !rest.starts_with([' ', '-', '#']) {
                    if let Some(name) = rest.strip_suffix(':') {
                        current = Some(name);
                    }
                }
            }
            if let Some(mount) = line.trim().strip_prefix("- ") {
                if let Some((volume, _)) = mount.split_once(':') {
                    if named.contains(volume) {
                        if let Some(service) = current {
                            services.insert(service.to_owned());
                        }
                    }
                }
            }
        }
    }
    services
}

/// Every identifier the attestation NAMES, as opposed to every string whose
/// letters it happens to contain.
///
/// "Accounted for" used to be `text.contains(service)` over one lowercased
/// blob of every field. That blob already contains `librechat-mongo`,
/// `mongodb`, `librechat_mongo_data`, the class `mongo:librechat` and the
/// sentence "the gateway API process holds no Mongo client" — five separate
/// substrings of `mongo`. So a compose service literally named `mongo`, a
/// wholly different store, was "accounted for" by collision. Verified by
/// mutation: adding one to `docker-compose.yml` left the guard green.
///
/// Word boundaries alone do not close it — "no Mongo client" is a bounded
/// whole word. What distinguishes naming a store from mentioning a technology
/// is the repo's own convention, so that is what this reads:
///
/// * a WHOLE field value (`store: "postgres"`, `store: "qdrant"`), and
/// * every BACKTICKED token in the prose (``the `backup` compose service``,
///   ``docker-compose service `librechat-mongo` ``).
///
/// `mongo:librechat` and `librechat_mongo_data` are backticked tokens in their
/// own right and neither of them is `mongo`, which is the whole point.
fn attestation_identifiers(body: &Value) -> BTreeSet<String> {
    fn absorb(raw: &str, out: &mut BTreeSet<String>) {
        out.insert(raw.trim().to_lowercase());
        // Odd-indexed pieces of a backtick split are what was between a pair.
        for quoted in raw.split('`').skip(1).step_by(2) {
            out.insert(quoted.trim().to_lowercase());
        }
    }
    let mut names = BTreeSet::new();
    for key in ["artifacts", "not_enumerable"] {
        for entry in body[key].as_array().into_iter().flatten() {
            for field in ["class", "store", "location", "description", "reason"] {
                if let Some(value) = entry[field].as_str() {
                    absorb(value, &mut names);
                }
            }
        }
    }
    for caveat in body["caveats"].as_array().into_iter().flatten() {
        if let Some(value) = caveat.as_str() {
            absorb(value, &mut names);
        }
    }
    names
}

/// THE ROOT CAUSE of WS3-5's two omissions, not the omissions themselves.
///
/// `every_table_the_product_creates_appears_in_the_inventory` derives its
/// expected set by grepping `CREATE TABLE` out of the two migration
/// directories. A dbt model is a `SELECT` in `secureprompt-analytics/models/`
/// and a Mongo instance is a service in `docker-compose.yml`, so NEITHER is
/// visible to it — which is how `int_requests_enriched` (a row-level, un-TTL'd
/// copy of `request_events`) and `librechat-mongo` (the only store in the
/// deployment holding PRE-redaction prompts and POST-restoration replies) were
/// absent from `artifacts`, from `not_enumerable`, and from the out-of-scope
/// caveat, all at once.
///
/// This test closes the class of omission rather than the two instances:
/// a future dbt model, or a future compose service with a named volume, fails
/// here until somebody declares it or scopes it out.
///
/// # It was narrowed, not closed, and three holes were measured
///
/// Each was reproduced by mutation against the version of this test that
/// preceded it — the mutation was applied, the guard was run, and the guard
/// said `ok`:
///
/// 1. A dbt SNAPSHOT (`snapshots/`, declared in `dbt_project.yml`) was not
///    seen: the scrape walked `models/` only. A snapshot is exactly the
///    un-TTL'd row-level copy of `request_events` that `int_requests_enriched`
///    turned out to be. Closed by reading the relation directories out of
///    `dbt_project.yml` — `model-paths`, `snapshot-paths`, `seed-paths`.
/// 2. A compose service named `mongo` was not seen: "accounted for" was
///    `text.contains(service)` over a lowercased blob that already contains
///    `librechat-mongo`, `mongodb`, `librechat_mongo_data` and the class
///    `mongo:librechat` and the sentence "holds no Mongo client". Closed by
///    [`attestation_identifiers`].
/// 3. A store declared only in `docker-compose.simple.yml` (or the on-prem
///    overlay) was not seen: only `docker-compose.yml` was parsed. Closed by
///    [`COMPOSE_FILES`].
///
/// PREMISE: both scrapes are asserted to have found the real thing before
/// anything is asserted about the response, so a parser that silently matched
/// nothing cannot make this pass over an empty expected set. The dbt scrape
/// additionally asserts that the DECLARED directory list still contains the
/// snapshot and seed paths, because those directories do not exist in the repo
/// today and a walk that quietly skipped them would look identical to a walk
/// that covered them.
/// POSITIVE CONTROL: a relation and a service that do NOT exist must come back
/// uncovered, so "everything is covered" is not the coverage check saying yes
/// to everything; and [`attestation_identifiers`] is asserted against a FIXED
/// body carrying every real collision, in both directions, so the tightened
/// check is proved to discriminate rather than proved to be strict.
#[sqlx::test]
async fn every_dbt_relation_and_compose_backed_store_is_accounted_for(pool: PgPool) {
    let relations = dbt_relations();
    let services = compose_persistent_services();

    // ---- Premise on the two scrapes ---------------------------------------
    let relation_dirs = dbt_relation_dirs();
    for declared in ["models", "snapshots", "seeds"] {
        assert!(
            relation_dirs.contains(declared),
            "premise failed: `{declared}` is not among the relation-producing \
             directories read out of dbt_project.yml, so a file dropped into \
             it would never be scraped. Found: {relation_dirs:?}"
        );
    }
    assert!(
        relations.len() >= 7,
        "premise failed: only {} dbt relations found under \
         secureprompt-analytics — the scrape is broken, so this test \
         would pass vacuously. Found: {relations:?}",
        relations.len()
    );
    for expected in [
        "int_requests_enriched",
        "stg_request_events",
        "mart_usage_daily",
    ] {
        assert!(
            relations.contains(expected),
            "premise failed: the dbt scrape missed `{expected}`, which is a \
             file on disk. Found: {relations:?}"
        );
    }
    assert!(
        services.len() >= 5,
        "premise failed: only {} compose services with a named volume found — \
         the parser is broken. Found: {services:?}",
        services.len()
    );
    for expected in ["librechat-mongo", "postgres", "clickhouse"] {
        assert!(
            services.contains(expected),
            "premise failed: the compose parser missed `{expected}`, which \
             mounts a named volume in docker-compose.yml. Found: {services:?}"
        );
    }

    let (ws, user) = seed_workspace(&pool).await;
    let app = build_app(pool);
    let (status, body) = get_inventory(&app, &make_jwt(ws, user, "admin")).await;
    assert_eq!(status, StatusCode::OK, "data-inventory failed: {body}");

    let declared = class_names(&body);
    let named = attestation_identifiers(&body);

    // ---- Positive controls: the checks below can say NO -------------------
    assert!(
        !declared.contains("mart_that_does_not_exist"),
        "the class-name check matches relations that do not exist, so the \
         assertion below proves nothing"
    );
    assert!(
        !named.contains("totally-not-a-real-service"),
        "the coverage check matches services that do not exist, so the \
         assertion below proves nothing"
    );

    // CONTROL on the extractor, over a FIXED body rather than the live prose,
    // so it cannot drift when a caveat is reworded. Every string here is one
    // this attestation really contains, and every one of them made
    // `text.contains("mongo")` true.
    let probe = serde_json::json!({
        "artifacts": [{
            "class": "mongo:librechat",
            "store": "mongodb",
            "location": "docker-compose service `librechat-mongo`, named volume \
                         `librechat_mongo_data` mounted at /data/db",
            "description": "The gateway API process holds no Mongo client.",
        }],
        "not_enumerable": [],
        "caveats": ["the `backup` compose service and its `clickhouse_backups` volume"],
    });
    let probe_names = attestation_identifiers(&probe);
    for found in [
        "librechat-mongo",
        "librechat_mongo_data",
        "backup",
        "mongodb",
    ] {
        assert!(
            probe_names.contains(found),
            "the extractor misses `{found}`, which this attestation names \
             either as a whole field value or in backticks — so every \
             assertion below would fail for the wrong reason: {probe_names:?}"
        );
    }
    assert!(
        !probe_names.contains("mongo"),
        "five substrings of `mongo` are in that body — `librechat-mongo`, \
         `mongodb`, `librechat_mongo_data`, `mongo:librechat` and the phrase \
         \"no Mongo client\" — and NONE of them names a compose service called \
         `mongo`. Accepting any of them is how a guard passes on the thing it \
         exists to catch: {probe_names:?}"
    );

    // ---- THE ASSERTIONS ---------------------------------------------------
    let undeclared: Vec<&String> = relations
        .iter()
        .filter(|relation| !declared.contains(*relation))
        .collect();
    assert!(
        undeclared.is_empty(),
        "dbt MATERIALISES these relations and the inventory does not mention \
         them, in `artifacts` or in `not_enumerable`:\n  {undeclared:?}\n\
         `int_requests_enriched` in particular is a ROW-LEVEL per-request copy \
         of request_events with NO TTL, so it outlives the 90-day window on \
         its own source. Declared: {declared:?}"
    );

    let unaccounted: Vec<&String> = services
        .iter()
        .filter(|service| !named.contains(*service))
        .collect();
    assert!(
        unaccounted.is_empty(),
        "these compose services mount a named volume — they are stores \
         a plain `docker compose up -d` starts and keeps — and the inventory \
         neither declares them nor scopes them out with a reason:\n  \
         {unaccounted:?}\n`librechat-mongo` in particular persists \
         PRE-redaction prompts and POST-restoration replies, and has no \
         `profiles:` gate. Scanned: {COMPOSE_FILES:?}"
    );
}

/// dbt does NOT materialise the marts in the gateway's `CLICKHOUSE_DB`.
///
/// `secureprompt-analytics/dbt_project.yml` puts every mart in the
/// `secureprompt_marts` database (staging in `secureprompt_staging`,
/// intermediate in `secureprompt_intermediate`). The inventory resolved
/// `location` and its count query against `{CLICKHOUSE_DB}.mart_*` instead, so
/// `row_count_status` was `unavailable` STRUCTURALLY — not on a fresh install,
/// but always, on every deployment, no matter how many times dbt had run —
/// while the code comment attributed it to "absent until `dbt build` has run".
/// A permanently-unknown number in a compliance attestation, blamed on the
/// deployment rather than on the query.
///
/// PREMISE: the mart table is created and seeded in the REAL dbt database and
/// the row count is confirmed by a direct query, before the endpoint is asked.
/// POSITIVE CONTROL: a second workspace gets a different, larger count, so a
/// query missing its tenancy predicate reports the total and fails; and
/// `mart_usage_daily` must come back `counted` while a mart that dbt has NOT
/// built stays `unavailable`, so this cannot pass by reporting a constant.
#[sqlx::test]
async fn mart_counts_resolve_to_the_database_dbt_actually_builds_into(pool: PgPool) {
    let (mine, my_user) = seed_workspace(&pool).await;
    let (theirs, _) = seed_workspace(&pool).await;

    clickhouse_exec(
        "CREATE DATABASE IF NOT EXISTS secureprompt_marts".to_owned(),
        "creating the dbt marts database",
    )
    .await;
    // Columns as `models/marts/mart_usage_daily.sql` selects them.
    clickhouse_exec(
        "CREATE TABLE IF NOT EXISTS secureprompt_marts.mart_usage_daily (
             workspace_id UUID, model String, usage_date Date,
             total_input_tokens UInt64, total_output_tokens UInt64,
             total_reasoning_tokens UInt64, total_cost_usd Float64,
             request_count UInt64, estimated_request_count UInt64
         ) ENGINE = MergeTree() ORDER BY (workspace_id, model, usage_date)"
            .to_owned(),
        "creating mart_usage_daily",
    )
    .await;
    for (ws, n) in [(mine, 3), (theirs, 8)] {
        for i in 0..n {
            clickhouse_exec(
                format!(
                    "INSERT INTO secureprompt_marts.mart_usage_daily \
                     (workspace_id, model, usage_date, total_input_tokens, \
                      total_output_tokens, total_reasoning_tokens, total_cost_usd, \
                      request_count, estimated_request_count) \
                     VALUES ('{ws}', 'mart-model-{i}', today(), 1, 1, 0, 0.5, 1, 0)"
                ),
                "seeding mart_usage_daily",
            )
            .await;
        }
    }

    // ---- Premise, against the store itself --------------------------------
    for (ws, expected) in [(mine, "3"), (theirs, "8")] {
        let got = clickhouse_exec(
            format!(
                "SELECT count() FROM secureprompt_marts.mart_usage_daily \
                 WHERE workspace_id = toUUID('{ws}')"
            ),
            "counting mart rows",
        )
        .await;
        assert_eq!(
            got.trim(),
            expected,
            "premise failed: the mart rows this test seeded are not in \
             secureprompt_marts, so an `unavailable` from the endpoint would \
             be correct and this test would prove nothing"
        );
    }
    // Premise: the database the endpoint USED to query really does not hold
    // the table, so "unavailable" was never a transient state.
    let wrong_db = clickhouse_exec(
        format!(
            "SELECT count() FROM system.tables WHERE database = '{}' \
             AND name = 'mart_usage_daily'",
            clickhouse_db()
        ),
        "checking the gateway database for a mart",
    )
    .await;
    assert_eq!(
        wrong_db.trim(),
        "0",
        "premise failed: a `mart_usage_daily` exists in the gateway's own \
         database, so querying the wrong database would have worked by \
         accident and this test could not tell the two apart"
    );

    let app = build_app(pool);
    let (status, body) = get_inventory(&app, &make_jwt(mine, my_user, "admin")).await;
    assert_eq!(status, StatusCode::OK, "data-inventory failed: {body}");

    let usage = artifact(&body, "mart_usage_daily");
    assert_eq!(
        usage["row_count_status"],
        Value::String("counted".into()),
        "the mart exists and holds this workspace's rows, and the inventory \
         still cannot count it — `location` and the count query must name the \
         database dbt builds into: {usage}"
    );
    assert_eq!(
        row_count(&body, "mart_usage_daily"),
        3,
        "the mart count must be this workspace's rows. Reporting 11 means the \
         count query lost its tenancy predicate: {usage}"
    );
    assert!(
        usage["location"]
            .as_str()
            .unwrap_or_default()
            .starts_with("secureprompt_marts."),
        "`location` must name the database an auditor would have to query to \
         reproduce the number: {usage}"
    );

    // POSITIVE CONTROL: a mart dbt has NOT built must still report the honest
    // unknown, so `counted` above is a live query and not a hardcoded status.
    let unbuilt = artifact(&body, "mart_policy_violations");
    assert_eq!(
        unbuilt["row_count_status"],
        Value::String("unavailable".into()),
        "a mart that does not exist reported a count anyway, so the status \
         above is not derived from the store: {unbuilt}"
    );
    assert_eq!(
        unbuilt["row_count"],
        Value::Null,
        "an uncountable class must report null, never a fabricated zero: {unbuilt}"
    );
}

/// Every free-text field an unreachable store can write into: the two
/// `row_count_detail`s and the `encryption.note` the legacy-plaintext scan
/// fills in. All three interpolated the store's exception.
fn failure_details(body: &Value) -> Vec<String> {
    let mut out = Vec::new();
    for entry in body["artifacts"].as_array().into_iter().flatten() {
        if let Some(detail) = entry["row_count_detail"].as_str() {
            out.push(detail.to_owned());
        }
        if let Some(note) = entry["encryption"]["note"].as_str() {
            out.push(note.to_owned());
        }
    }
    out
}

/// `row_count_detail` must not echo `ClickHouse`'s own exception text.
///
/// Commit 42c99f4 was titled "stop echoing ClickHouse exceptions". It fixed
/// `leak_report::ch_err` and left three sites in `data_inventory.rs`
/// interpolating `{e}` — `clickhouse::error::Error::to_string()`, which carries
/// the server's message verbatim — into `row_count_detail` IN THE RESPONSE
/// BODY: `counted()`, the legacy-plaintext scan, and the capture shape check.
/// The justification for leaving them (every query selects aggregates, so no
/// row data can appear) is the same statement about the SELECT list that
/// `ch_err` was fixed for; a ClickHouse exception is not bounded by the select
/// list and routinely quotes schema, identifiers and, in some error classes,
/// values.
///
/// This is not a hypothetical path. It is reached on ANY deployment where dbt
/// has not run: the staging views and the four marts are counted in
/// `secureprompt_staging` / `secureprompt_marts`, and a missing relation raises
/// `Code: 81. DB::Exception: Database ... does not exist`.
///
/// PREMISE 1: at least one class must actually report `unavailable` on the
/// healthy app, or "no exception text in the body" is true because the failure
/// path never ran.
/// PREMISE 2: with the gateway's own database pointed at a database that does
/// not exist, `request_events` must report `unavailable` too — that is what
/// executes `counted()`, the legacy scan and the capture shape check.
/// POSITIVE CONTROL: on the healthy app `request_events` must be `counted`
/// with no detail, so `unavailable` is a live verdict and not a constant; and
/// the refusal must still name the store and the reason, or the fix has taken
/// away what the operator debugs with.
#[sqlx::test]
async fn an_unreachable_store_does_not_echo_the_stores_own_message(pool: PgPool) {
    let (ws, user) = seed_workspace(&pool).await;
    let token = make_jwt(ws, user, "admin");

    // ---- The healthy app: the dbt relations are the reachable case ---------
    let healthy = build_app(pool.clone());
    let (status, body) = get_inventory(&healthy, &token).await;
    assert_eq!(status, StatusCode::OK, "data-inventory failed: {body}");

    // POSITIVE CONTROL: a table that DOES exist is counted, so `unavailable`
    // below is a real answer from the store.
    let events = artifact(&body, "request_events");
    assert_eq!(
        events["row_count_status"],
        Value::String("counted".into()),
        "premise: the gateway's own tables must be countable on the healthy \
         app, or this test is measuring a broken harness: {events}"
    );
    assert_eq!(
        events["row_count_detail"],
        Value::Null,
        "a successful count must carry no detail at all: {events}"
    );

    // PREMISE 1: the failure path really ran on this response.
    let unavailable: Vec<String> = body["artifacts"]
        .as_array()
        .expect("artifacts array")
        .iter()
        .filter(|entry| entry["row_count_status"] == Value::String("unavailable".into()))
        .filter_map(|entry| entry["class"].as_str().map(str::to_owned))
        .collect();
    assert!(
        !unavailable.is_empty(),
        "premise failed: every class was countable, so the `unavailable` \
         branch never executed and the absence asserted below proves nothing. \
         This test needs at least one dbt relation that has not been built: \
         {body}"
    );

    // ---- The broken app: every gateway-table count fails -------------------
    let broken = build_app_with_ch_db(pool, "sp_no_such_database");
    let (broken_status, broken_body) = get_inventory(&broken, &token).await;
    assert_eq!(
        broken_status,
        StatusCode::OK,
        "an unreachable analytics store must still yield an inventory with \
         stated gaps, not a 500: {broken_body}"
    );

    // PREMISE 2: the three sites under test executed.
    for class in ["request_events", "request_content_captures"] {
        assert_eq!(
            artifact(&broken_body, class)["row_count_status"],
            Value::String("unavailable".into()),
            "premise failed: `{class}` was counted against a database that \
             does not exist, so the failure path did not run: {broken_body}"
        );
    }

    // ---- THE ASSERTION ----------------------------------------------------
    for (label, response) in [("healthy", &body), ("unreachable store", &broken_body)] {
        let text = response.to_string();
        for leak in [
            "DB::Exception",
            "Code:",
            "SELECT",
            "countIf",
            "toUUID",
            "UNKNOWN_DATABASE",
        ] {
            assert!(
                !text.contains(leak),
                "the {label} response carries the store's own exception text or \
                 this module's SQL ({leak:?}) inside `row_count_detail`. A \
                 ClickHouse exception quotes schema, identifiers and in some \
                 error classes the value it choked on, so this path can hand \
                 stored bytes back to the caller: {text}"
            );
        }
        // The workspace id is interpolated into every count query, so an
        // echoed exception carries it. It is checked per-detail rather than
        // over the whole body, which legitimately carries `workspace_id`.
        for detail in failure_details(response) {
            assert!(
                !detail.contains(&ws.to_string()),
                "the {label} response echoed the interpolated workspace id \
                 back inside a failure detail: {detail}"
            );
        }
    }

    // The operator keeps what they can act on: WHICH store failed, and that
    // the gap is a stated unknown rather than a zero.
    let failed = artifact(&broken_body, "request_events");
    let detail = failed["row_count_detail"]
        .as_str()
        .unwrap_or_else(|| panic!("an unavailable class must explain itself: {failed}"));
    assert!(
        detail.contains("request_events"),
        "the refusal does not name the store that could not be read, so an \
         operator cannot act on it: {detail}"
    );
    assert!(
        detail.contains("log"),
        "the detail must say where the store's own message went, or a reader \
         will assume it was discarded: {detail}"
    );
    assert_eq!(
        failed["row_count"],
        Value::Null,
        "an uncountable class must report null, never a fabricated zero: {failed}"
    );
}

/// The analytics counts cover GATEWAY traffic only, and the inventory must say
/// which surfaces that excludes.
///
/// `request_events` and everything derived from it are written from exactly one
/// place, the gateway request pipeline. `/v1/redact`,
/// `/v1/secure-mode/tokenize`, the MCP server and file scanning run the same
/// detection pass and emit no event — so an auditor reading
/// "request_events: 4,812 rows" has no way to know the number is not the
/// product's traffic. (The premise that there is exactly one emitting call site
/// is asserted against the source in
/// `leak_report.rs::the_report_states_that_it_covers_gateway_traffic_only`, so
/// it reddens if a future endpoint starts emitting.)
///
/// POSITIVE CONTROL: the caveat must also name what IS covered. A statement
/// that only lists exclusions reads as "nothing is covered".
#[sqlx::test]
async fn the_inventory_states_which_surfaces_its_analytics_counts_cover(pool: PgPool) {
    let (ws, user) = seed_workspace(&pool).await;
    let app = build_app(pool);
    let (status, body) = get_inventory(&app, &make_jwt(ws, user, "admin")).await;
    assert_eq!(status, StatusCode::OK, "data-inventory failed: {body}");

    let caveats: Vec<&str> = body["caveats"]
        .as_array()
        .expect("caveats array")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let scope = caveats
        .iter()
        .find(|c| c.contains("request_events") && c.contains("/v1/redact"))
        .unwrap_or_else(|| {
            panic!(
                "no caveat says the analytics counts cover gateway traffic \
                 only. An auditor reading a `request_events` row count has no \
                 way to know it excludes /v1/redact, tokenize, MCP and file \
                 scanning: {caveats:#?}"
            )
        });

    for needle in ["tokenize", "MCP"] {
        assert!(
            scope.contains(needle),
            "the scope caveat does not name {needle:?} among the surfaces its \
             counts exclude: {scope}"
        );
    }
    assert!(
        scope.contains("/v1/chat/completions"),
        "positive control: the caveat must name what IS covered, or it reads \
         as excluding everything: {scope}"
    );
    // The surfaces that emit no ANALYTICS event still leave artifacts, and the
    // caveat must not be read as "those are absent too" — they are inventoried
    // above with live counts.
    for class in ["token_vault_entries", "redis:filevault"] {
        assert!(
            class_names(&body).contains(class),
            "the caveat points at `{class}` as the store a non-gateway surface \
             does write, and it is not declared: {body}"
        );
    }
}

// ── 4. Retention ──────────────────────────────────────────────────────────

/// A retention NUMBER with no enforcement MECHANISM is the exact shape of a
/// false assurance: it reads as a guarantee and is enforced by nothing.
///
/// This is a whole-response invariant rather than a spot check, so a class
/// added later with `days: 90` and no mechanism fails too.
///
/// Falsifier: report `refresh_tokens` with `days: 30` while leaving its
/// mechanism `none` (it genuinely has no purge — see the assertion below).
#[sqlx::test]
async fn retention_days_without_an_enforcement_mechanism_is_never_reported(pool: PgPool) {
    let (ws, user) = seed_workspace(&pool).await;
    let app = build_app(pool);
    let (status, body) = get_inventory(&app, &make_jwt(ws, user, "admin")).await;
    assert_eq!(status, StatusCode::OK, "data-inventory failed: {body}");

    let mut with_days = 0_usize;
    let mut with_mechanism = 0_usize;
    let mut checked = 0_usize;

    for key in ["artifacts", "not_enumerable"] {
        for entry in body[key].as_array().expect("array") {
            checked += 1;
            let retention = &entry["retention"];
            let mechanism = retention["mechanism"].as_str().unwrap_or_else(|| {
                panic!(
                    "class {} has no retention mechanism: {entry}",
                    entry["class"]
                )
            });
            let days = retention["days"].as_i64();

            if days.is_some() {
                with_days += 1;
                assert_ne!(
                    mechanism, "none",
                    "class {} advertises a {:?}-day retention enforced by \
                     nothing. Either name the mechanism or report no window: \
                     {entry}",
                    entry["class"], days
                );
            }
            if mechanism != "none" {
                with_mechanism += 1;
                assert!(
                    !retention["mechanism_detail"]
                        .as_str()
                        .unwrap_or("")
                        .is_empty(),
                    "class {} names mechanism `{mechanism}` without saying \
                     what it does; an auditor needs the mechanism, not just \
                     the number: {entry}",
                    entry["class"]
                );
            }
        }
    }

    // Positive controls: the loop must have seen both shapes, otherwise the
    // invariant above passed over nothing.
    assert!(checked >= 20, "only {checked} classes examined: {body}");
    assert!(
        with_days > 0,
        "no class reports a retention window at all, so the invariant above \
         never fired: {body}"
    );
    assert!(
        with_mechanism > 0,
        "no class reports an enforcement mechanism at all: {body}"
    );

    // A ClickHouse TTL is a background merge, not a delete at the instant of
    // expiry. An auditor who reads "90 days" and assumes "gone on day 91" has
    // been misled by an omission.
    let events = artifact(&body, "request_events");
    assert_eq!(events["retention"]["days"], Value::from(90));
    let detail = events["retention"]["mechanism_detail"]
        .as_str()
        .unwrap_or("");
    assert!(
        detail.contains("merge"),
        "request_events reports a 90-day TTL without saying it is applied by \
         a background merge rather than at the instant of expiry: {detail:?}"
    );

    // `refresh_tokens` is the class this invariant was written to expose: it
    // has an `expires_at` column and NOTHING deletes the rows.
    let refresh = artifact(&body, "refresh_tokens");
    assert_eq!(
        refresh["retention"]["mechanism"],
        Value::String("none".into()),
        "nothing in this repository deletes refresh_tokens rows — \
         `grep -rn 'DELETE FROM refresh_tokens'` is empty. Reporting a \
         mechanism here would be a false assurance: {refresh}"
    );
    assert_eq!(
        refresh["retention"]["days"],
        Value::Null,
        "refresh_tokens has an expires_at column, but expiry is checked at \
         READ time and no row is ever removed. A day count here would read as \
         a deletion guarantee: {refresh}"
    );
}

// ── 5. What the endpoint cannot say ───────────────────────────────────────

/// The Redis file vault carries no workspace id in its key, so it can neither
/// be counted nor erased per tenant. That limitation is exactly what an
/// auditor needs to know, and it is the one thing an omission would hide.
///
/// Falsifier: give `redis:filevault` a `row_count` and move it into
/// `artifacts` — the assertions below fail in both directions.
#[sqlx::test]
async fn unenumerable_classes_are_declared_rather_than_omitted(pool: PgPool) {
    let (ws, user) = seed_workspace(&pool).await;
    let app = build_app(pool);
    let (status, body) = get_inventory(&app, &make_jwt(ws, user, "admin")).await;
    assert_eq!(status, StatusCode::OK, "data-inventory failed: {body}");

    let enumerable: BTreeSet<String> = body["artifacts"]
        .as_array()
        .expect("artifacts array")
        .iter()
        .filter_map(|entry| entry["class"].as_str().map(str::to_owned))
        .collect();

    // Positive control: the endpoint DOES enumerate things. Without this,
    // "filevault is not in artifacts" would also pass on an empty list.
    assert!(
        enumerable.contains("request_events") && enumerable.contains("token_vault_entries"),
        "the enumerable list is missing classes that certainly are \
         enumerable, so the exclusion below proves nothing: {enumerable:?}"
    );

    assert!(
        !enumerable.contains("redis:filevault"),
        "the Redis file vault appears among the ENUMERABLE artifacts. Its key \
         is `filevault:{{ref}}` with no workspace id (redis/mod.rs), so any \
         count attributed to a workspace is fabricated: {enumerable:?}"
    );

    let vault = body["not_enumerable"]
        .as_array()
        .expect("not_enumerable array")
        .iter()
        .find(|entry| entry["class"] == Value::String("redis:filevault".into()))
        .unwrap_or_else(|| panic!("the Redis file vault is not declared at all: {body}"));

    for needle in ["workspace", "key"] {
        assert!(
            vault["reason"]
                .as_str()
                .unwrap_or("")
                .to_lowercase()
                .contains(needle),
            "the declared reason does not explain that the KEY carries no \
             WORKSPACE id — an auditor cannot act on `not enumerable`: {vault}"
        );
    }
    assert_eq!(
        vault["per_workspace_erasure"],
        Value::String("not_possible".into()),
        "the file vault cannot be erased for one tenant (its keys are not \
         partitioned by workspace); the inventory must say so: {vault}"
    );
    assert_eq!(
        vault["row_count"],
        Value::Null,
        "a class declared un-enumerable must not also carry a count: {vault}"
    );
}

// ── 6. No PII ─────────────────────────────────────────────────────────────

/// Counts, classes, retention and encryption state only — never a sample of
/// the content being inventoried.
///
/// Defences: the PII is confirmed present in BOTH stores before the request
/// (premise), and the response is confirmed to be a real inventory of those
/// same rows (positive control), so "the needle is absent" cannot be true
/// because the response was empty or errored.
#[sqlx::test]
async fn inventory_never_echoes_stored_content(pool: PgPool) {
    let (ws, user) = seed_workspace(&pool).await;

    let plaintext = format!("Please summarise the contract for {SYNTHETIC_NAME}");
    seed_capture(ws, &plaintext, true).await;
    sqlx::query(
        "INSERT INTO token_vault_entries (id, workspace_id, mapping_ciphertext)
         VALUES ($1, $2, $3)",
    )
    .bind(Uuid::new_v4())
    .bind(ws)
    .bind(&plaintext)
    .execute(&pool)
    .await
    .expect("seed vault");

    // ---- Premise: the needle really is in both stores ----------------------
    assert_eq!(
        clickhouse_count(
            "request_content_captures",
            &format!(
                "workspace_id = toUUID('{ws}') AND position(raw_prompt, '{SYNTHETIC_NAME}') > 0"
            )
        )
        .await,
        1,
        "premise failed: the synthetic PII is not in ClickHouse, so its \
         absence from the response proves nothing"
    );
    let in_pg: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM token_vault_entries
         WHERE workspace_id = $1 AND mapping_ciphertext LIKE '%' || $2 || '%'",
    )
    .bind(ws)
    .bind(SYNTHETIC_NAME)
    .fetch_one(&pool)
    .await
    .expect("premise count");
    assert_eq!(
        in_pg, 1,
        "premise failed: the synthetic PII is not in Postgres"
    );

    let app = build_app(pool);
    let (status, body) = get_inventory(&app, &make_jwt(ws, user, "admin")).await;
    assert_eq!(status, StatusCode::OK, "data-inventory failed: {body}");

    // ---- Positive control: the response IS an inventory of those rows ------
    assert_eq!(
        row_count(&body, "request_content_captures"),
        1,
        "the capture row was not inventoried, so this response is not the one \
         under test: {body}"
    );
    assert_eq!(
        row_count(&body, "token_vault_entries"),
        1,
        "the vault row was not inventoried: {body}"
    );

    let serialized = body.to_string();
    assert!(
        !serialized.contains(SYNTHETIC_NAME),
        "the inventory echoed stored content back to the caller"
    );
    for fragment in ["Anvar", "Karimov", "summarise the contract"] {
        assert!(
            !serialized.contains(fragment),
            "the inventory leaked the fragment {fragment:?} of stored content"
        );
    }
}

// ── 7. Auth ───────────────────────────────────────────────────────────────

/// Authentication is not authorisation. This attestation reports live row
/// counts for every store, which credential classes hold verified ciphertext
/// and which do not, the deployment's KMS backend and whether its self-test
/// passed — i.e. exactly the map an attacker with a low-privilege token would
/// use to choose a target. It was readable by any authenticated role.
///
/// Admin is the minimum, for consistency with every other workspace-wide
/// dashboard route (`users.rs`, `keys.rs`, `secure_mode.rs`, `license.rs`) and
/// with the `role_required: "admin"` this very response advertises for the
/// raw-capture control.
///
/// The BOUNDARY is asserted, not just the bottom of it. POSITIVE CONTROLS:
/// `admin` and `owner` still get a real inventory through the same path.
#[sqlx::test]
async fn data_inventory_requires_admin_role(pool: PgPool) {
    let (ws, user) = seed_workspace(&pool).await;
    let app = build_app(pool);

    for role in ["admin", "owner"] {
        let (status, body) = get_inventory(&app, &make_jwt(ws, user, role)).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "positive control: `{role}` must still be able to read the \
             inventory: {body}"
        );
        assert_eq!(
            row_count(&body, "users"),
            1,
            "positive control: `{role}` must get the real inventory, not an \
             empty shell: {body}"
        );
    }

    for role in ["viewer", "developer", "employee"] {
        let (status, body) = get_inventory(&app, &make_jwt(ws, user, role)).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a `{role}` read the full data inventory — live row counts for \
             every store, which credential classes hold verified ciphertext, \
             and the deployment's KMS state: {body}"
        );
        assert!(
            body["artifacts"].as_array().is_none(),
            "the refusal still returned the inventory body: {body}"
        );
    }
}

#[sqlx::test]
async fn data_inventory_requires_authentication(pool: PgPool) {
    let app = build_app(pool);
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/data-inventory")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("router");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// The capture toggle is NOT moved here (see the WS3-5 report). The inventory
/// must therefore point at the control that governs it, by name, or an
/// auditor reading "capture: enabled" has no way to find who can change it.
#[sqlx::test]
async fn capture_toggle_is_attributed_to_the_control_that_governs_it(pool: PgPool) {
    let (ws, user) = seed_workspace(&pool).await;
    let app = build_app(pool);
    let (status, body) = get_inventory(&app, &make_jwt(ws, user, "admin")).await;
    assert_eq!(status, StatusCode::OK, "data-inventory failed: {body}");

    let capture = artifact(&body, "request_content_captures");
    let governance = &capture["governed_by"];
    assert_eq!(
        governance["endpoint"],
        Value::String("PUT /v1/secure-mode".into()),
        "the inventory does not name the endpoint that switches raw capture \
         on: {capture}"
    );
    assert_eq!(
        governance["field"],
        Value::String("capture_raw_content".into()),
        "the inventory does not name the field: {capture}"
    );
    assert_eq!(
        governance["role_required"],
        Value::String("admin".into()),
        "the inventory does not state the admin gate: {capture}"
    );
    assert_eq!(
        governance["audit_table"],
        Value::String("raw_capture_audit".into()),
        "the inventory does not point at the append-only record of who \
         switched it: {capture}"
    );
    // Derived, not asserted: capture is OFF for a workspace that never opted in.
    assert_eq!(
        capture["enabled"],
        Value::Bool(false),
        "a fresh workspace must report capture disabled: {capture}"
    );
}

// ── WS3-5: the self-test details are response fields too ──────────────────
//
// 42c99f4 stopped `leak_report::ch_err` echoing ClickHouse's message; 38f2a7b
// did the same for this file's three `counted()` sites and `redis:budget`,
// through the `unavailable` helper. The two `_self_test_detail` fields were
// missed both times, and they are the same defect: a `String` on the response
// struct, built with `format!("… failed: {e}")`, over an error type nothing
// bounds. `KmsBackend::encrypt` returns `anyhow::Result`, so the message is
// whatever the backend attached — `FileKms` interpolates the AES layer's
// error, `VaultKms` attaches its own context, and a backend added later is
// unconstrained by anything but the trait.

/// What a backend can attach to its own error, and what must therefore never
/// reach an HTTP caller. Synthetic: no such host exists.
const KMS_ENDPOINT_MARKER: &str =
    "https://vault.internal.example:8200/v1/transit/keys/sp-master-key";

/// A backend that fails the way a misconfigured real one does — with its
/// configuration in the message.
struct HostileKms {
    mode: &'static str,
}

#[async_trait::async_trait]
impl secureprompt_common::kms::KmsBackend for HostileKms {
    async fn encrypt(&self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        if self.mode == "encrypt_fails" {
            anyhow::bail!("transit engine at {KMS_ENDPOINT_MARKER} refused: permission denied");
        }
        Ok(plaintext.to_vec())
    }
    async fn decrypt(&self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        if self.mode == "decrypt_fails" {
            anyhow::bail!("transit engine at {KMS_ENDPOINT_MARKER} refused: permission denied");
        }
        Ok(ciphertext.to_vec())
    }
}

fn build_app_with_kms(pool: PgPool, mode: &'static str) -> Router {
    let ml = Arc::new(MlSidecarClient::new(String::new(), 100));
    let mut state = AppState::new(
        pool,
        test_config(),
        ml,
        Arc::new(secureprompt_api::license::LicenseState::unlicensed()),
    );
    state.kms = Arc::new(HostileKms { mode });
    build_router(state)
}

/// A KMS that fails must not put its own message in the attestation.
///
/// PREMISE for the absence claim — and this is the point of it: the marker is
/// asserted to be IN the backend's error first. `report_contains_no_detected_\
/// value` and `counts_never_store_the_detected_values` hunt for strings no
/// code path on their route could ever emit, so they could not have caught the
/// defect they were written for. This one hunts for a string the route
/// demonstrably DID emit.
///
/// POSITIVE CONTROL: the same router with a working backend must report `ok`,
/// so `failed` is the probe reacting rather than a constant.
#[sqlx::test]
async fn a_failing_kms_does_not_echo_its_own_message_into_the_response(pool: PgPool) {
    // PREMISE: the marker really is in what the backend hands the handler.
    for mode in ["encrypt_fails", "decrypt_fails"] {
        let backend = HostileKms { mode };
        let err = if mode == "encrypt_fails" {
            secureprompt_common::kms::KmsBackend::encrypt(&backend, b"x")
                .await
                .expect_err("this stub must fail")
        } else {
            secureprompt_common::kms::KmsBackend::decrypt(&backend, b"x")
                .await
                .expect_err("this stub must fail")
        };
        assert!(
            err.to_string().contains(KMS_ENDPOINT_MARKER),
            "premise failed: the stub's `{mode}` error does not carry the \
             marker, so the assertion below proves nothing: {err}"
        );
    }

    let (ws, user) = seed_workspace(&pool).await;
    let token = make_jwt(ws, user, "admin");

    // POSITIVE CONTROL first: an identity backend answers `ok`.
    let healthy = build_app_with_kms(pool.clone(), "identity");
    let (status, body) = get_inventory(&healthy, &token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["encryption_basis"]["kms_self_test"],
        Value::String("ok".into()),
        "positive control: a working backend must pass, or `failed` below is \
         a constant: {body}"
    );

    for mode in ["encrypt_fails", "decrypt_fails"] {
        let app = build_app_with_kms(pool.clone(), mode);
        let (status, body) = get_inventory(&app, &token).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["encryption_basis"]["kms_self_test"],
            Value::String("failed".into()),
            "a `{mode}` backend must be reported as failed: {body}"
        );
        let detail = body["encryption_basis"]["kms_self_test_detail"]
            .as_str()
            .unwrap_or_else(|| panic!("kms_self_test_detail must be a string: {body}"));
        assert!(
            detail.len() > 60,
            "`{mode}` must still SAY something — a bounded sentence is the fix, \
             an empty one is a regression: {detail:?}"
        );
        let text = body.to_string();
        assert!(
            !text.contains(KMS_ENDPOINT_MARKER),
            "the KMS backend's own error message reached the response body of a \
             compliance attestation, carrying the endpoint it was configured \
             with. mode={mode} detail={detail}"
        );
        assert!(
            !text.contains("permission denied"),
            "the backend's message reached the body. mode={mode} detail={detail}"
        );
    }
}

/// The FOURTH site of the same defect, and the one no earlier pass looked at.
///
/// `postgres_counts` built all four of its error arms with
/// `ApiError::Database(e.to_string())`, and `http::api_error_response` renders
/// an `ApiError`'s message straight into the response body. `leak_report`
/// already had `pg_err` for exactly this, over the same store.
///
/// POSITIVE CONTROL first: the same router, same workspace, answers 200 before
/// the table is dropped — so the 500 below is the query failing and not the
/// harness.
///
/// PREMISE: the 500 is asserted before the body is inspected, so the
/// "no store message" claim is made about an error this route really produced.
#[sqlx::test]
async fn a_postgres_failure_does_not_echo_the_stores_own_message(pool: PgPool) {
    let (ws, user) = seed_workspace(&pool).await;
    let token = make_jwt(ws, user, "admin");
    let app = build_app(pool.clone());

    let (status, body) = get_inventory(&app, &token).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "positive control: a healthy deployment must answer 200, or the 500 \
         below proves nothing: {body}"
    );

    // Break exactly one relation the counts query reads. `#[sqlx::test]` gives
    // this test its own database, so nothing else sees it.
    sqlx::query("DROP TABLE raw_capture_audit CASCADE")
        .execute(&pool)
        .await
        .expect("premise: the table must exist to be dropped");

    let (status, body) = get_inventory(&app, &token).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "premise: the counts query must actually fail once its relation is \
         gone, or the assertions below run against a healthy body: {body}"
    );
    let text = body.to_string();
    for leaked in [
        "raw_capture_audit",
        "does not exist",
        "app.current_workspace_id",
        "PgDatabaseError",
    ] {
        assert!(
            !text.contains(leaked),
            "the Postgres error reached the response body of a compliance \
             attestation, carrying {leaked:?}: {text}"
        );
    }
    let message = body["error"]["message"]
        .as_str()
        .unwrap_or_else(|| panic!("the error envelope must carry a message: {text}"));
    assert!(
        message.len() > 100,
        "the bounded form must still tell an operator what is now unknown and \
         where the real message went: {message:?}"
    );
}
