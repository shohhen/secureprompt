//! WS3-3 — the token vault stores originals as CIPHERTEXT, not plaintext.
//!
//! # The defect
//!
//! `migrations/008_token_vault.sql` created `mapping JSONB NOT NULL` holding
//! a `{placeholder → original_text}` object — that is, the raw PII the
//! product exists to keep out of other people's hands — and shipped a comment
//! saying so:
//!
//! > IMPORTANT: originals live in plain JSONB here. Production deployments
//! > should encrypt `mapping` via the configured KMS before inserting
//!
//! A plan is not a control. Every `/v1/secure-mode/tokenize` call wrote the
//! caller's PII to Postgres in the clear, where it sat for 24 hours (and,
//! before WS3-4, forever, because nothing enforced `expires_at`).
//!
//! # How these tests prove it
//!
//! The leak assertion reads the row back out of Postgres AS TEXT — the whole
//! row, via `to_jsonb(t)::text`, not one named column. That matters twice
//! over: it is what "what is actually on disk" means rather than "what my own
//! decrypt path hands back", and it does not care which column the mapping
//! ends up in, so it caught the defect before the fix and guards every column
//! of the table after it.
//!
//! All fixture PII is synthetic.

mod support;

use axum::http::{Method, Request, StatusCode};
use serde_json::json;
use sqlx::{PgPool, Row as _};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;
use uuid::Uuid;

/// Synthetic name. It sits at byte 0 of every fixture text so the mock
/// sidecar's fixed `PERSON` span lines up with it, and it is the string every
/// leak assertion hunts for in Postgres.
const SYNTHETIC_NAME: &str = "Anvar Karimov";

/// Prose that follows the name. NOT PII: it is not part of any detection, so
/// it never enters the vault mapping and must never appear in the stored row
/// either. Used to keep the fixture realistic.
const PROSE: &str = "shartnomani imzoladi";

fn fixture_text() -> String {
    format!("{SYNTHETIC_NAME} {PROSE}")
}

// ── Mock ML sidecar ───────────────────────────────────────────────────────

/// Reports `PERSON` at bytes 0..13 — exactly `SYNTHETIC_NAME` — for any text
/// it is sent. `PERSON` is ML-only (no deterministic Rust recognizer emits
/// it), so its presence in the response proves the sidecar was really
/// reached rather than the deterministic floor having run alone.
struct MockSidecar {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
}

impl MockSidecar {
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
            let body: &[u8] = if request.contains("/detect/ner") {
                br#"{"entities":[{"entity_type":"PERSON","start":0,"end":13,"score":0.97,"text":"Anvar Karimov","compliance_categories":[]}]}"#
            } else if request.contains("/detect/injection") {
                br#"{"is_injection":false,"score":0.0}"#
            } else {
                b"{}"
            };
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body);
            sink.lock().expect("request sink mutex").push(request);
        });

        Self { addr, requests }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn ner_requests(&self) -> Vec<String> {
        self.requests
            .lock()
            .expect("request sink mutex")
            .iter()
            .filter(|r| r.contains("/detect/ner"))
            .cloned()
            .collect()
    }
}

/// Read one complete HTTP request: headers, then exactly `Content-Length`
/// bytes of body. A single fixed-size read truncates larger `/detect/ner`
/// bodies and turns "the sidecar answered" into "the call failed".
fn read_http_request(stream: &mut std::net::TcpStream) -> Option<String> {
    let mut raw: Vec<u8> = Vec::new();
    let mut buf = [0u8; 8192];

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

    while raw.len() < header_end + content_length {
        let n = stream.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&buf[..n]);
    }
    Some(String::from_utf8_lossy(&raw).to_string())
}

// ── Fixtures ──────────────────────────────────────────────────────────────

async fn seed(pool: &PgPool, workspace_id: Uuid) -> sqlx::Result<()> {
    support::seed_workspace(
        pool,
        workspace_id,
        &format!("sp_ws3_3_{}", Uuid::new_v4().simple()),
    )
    .await
}

/// `/v1/secure-mode/*` is JWT-gated, not API-key-gated. Signed with the same
/// secret `support::test_config` hands the router.
fn dashboard_jwt(workspace_id: Uuid) -> String {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use secureprompt_api::http::middleware::jwt_auth::Claims;

    let claims = Claims {
        sub: Uuid::new_v4(),
        ws: workspace_id,
        role: "owner".to_owned(),
        jti: Uuid::new_v4().to_string(),
        iat: chrono::Utc::now().timestamp(),
        exp: (chrono::Utc::now() + chrono::Duration::seconds(900)).timestamp(),
        purpose: None,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(support::test_config().jwt.secret.as_bytes()),
    )
    .expect("jwt must encode")
}

fn tokenize_request(jwt: &str, text: &str) -> Request<axum::body::Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/v1/secure-mode/tokenize")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {jwt}"))
        .body(axum::body::Body::from(json!({ "text": text }).to_string()))
        .expect("request must build")
}

fn detokenize_request(jwt: &str, vault_id: Uuid, text: &str) -> Request<axum::body::Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/v1/secure-mode/detokenize")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {jwt}"))
        .body(axum::body::Body::from(
            json!({ "token_vault_id": vault_id, "text": text }).to_string(),
        ))
        .expect("request must build")
}

/// THE PROOF QUERY. Serialises the ENTIRE stored row to text and hands it
/// back, so an assertion can ask what is on disk without naming a column and
/// without going anywhere near the application's own decrypt path. A test
/// that round-tripped through `TokenVaultRepository::get` would pass just as
/// happily against plaintext storage.
async fn stored_row_text(pool: &PgPool, vault_id: Uuid) -> sqlx::Result<String> {
    let row = sqlx::query(
        "SELECT to_jsonb(t)::text AS row_text FROM token_vault_entries t WHERE t.id = $1",
    )
    .bind(vault_id)
    .fetch_one(pool)
    .await?;
    Ok(row.get::<String, _>("row_text"))
}

// ── WS3-3: nothing readable is written to Postgres ────────────────────────

/// Acceptance criterion: "No plaintext PII in `token_vault_entries.mapping`
/// — asserted by querying Postgres directly."
///
/// PREMISE + POSITIVE CONTROLS, in order, so the absence assertion cannot
/// pass trivially:
///   1. tokenize returned 200 — a 4xx/5xx would leave no row at all and make
///      "no plaintext in the row" true for the boring reason;
///   2. the mock sidecar was called with the REAL text — the request went
///      down the full pipeline rather than short-circuiting;
///   3. the response redacted the name — so the name really was detected and
///      really did enter the vault mapping. If nothing was detected the
///      mapping would be `{}` and of course contain no PII;
///   4. a row exists in Postgres for the returned vault id;
///   5. POSITIVE CONTROL: the same `to_jsonb(t)::text` search, over the same
///      row, DOES find the vault id and the workspace id. The search method
///      demonstrably finds a string in this row when the string is there.
///
/// Only then does step 6 — the synthetic name is absent — mean anything.
#[sqlx::test]
async fn tokenize_stores_no_plaintext_original_in_postgres(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;

    let sidecar = MockSidecar::spawn();
    let app = support::router_with(pool.clone(), &sidecar.url(), "default");
    let response = app
        .oneshot(tokenize_request(
            &dashboard_jwt(workspace_id),
            &fixture_text(),
        ))
        .await
        .expect("router should respond");

    // Premise 1.
    let status = response.status();
    let body = support::response_json(response).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "tokenize must succeed — otherwise no row is written and every \
         assertion below is vacuously true; body={body}"
    );

    // Premise 2.
    let ner = sidecar.ner_requests();
    assert!(
        ner.iter().any(|r| r.contains(SYNTHETIC_NAME)),
        "premise: tokenize must have asked the sidecar about the REAL text; \
         captured:\n{ner:?}"
    );

    // Premise 3: the name was detected, redacted, and therefore IS in the
    // mapping this test claims is encrypted.
    let tokenized = body["tokenized_text"]
        .as_str()
        .expect("tokenize must return tokenized_text");
    assert!(
        !tokenized.contains(SYNTHETIC_NAME),
        "premise: the name must have been redacted out of the response, \
         proving it was detected and stored in the vault mapping; got {tokenized:?}"
    );
    assert_eq!(
        body["entity_counts"]["PERSON"].as_u64(),
        Some(1),
        "premise: PERSON is ML-only, so exactly one must be reported; body={body}"
    );

    // Premise 4.
    let vault_id: Uuid = body["token_vault_id"]
        .as_str()
        .expect("tokenize must return token_vault_id")
        .parse()
        .expect("token_vault_id must be a uuid");
    let row_text = stored_row_text(&pool, vault_id).await?;

    // Premise 5 / POSITIVE CONTROL. If these fail, the absence assertion
    // below proves nothing, because the search method itself does not work.
    assert!(
        row_text.contains(&vault_id.to_string()),
        "positive control: the row text must contain the vault id — the same \
         substring search that is about to assert an absence has to be able \
         to find something first; got {row_text}"
    );
    assert!(
        row_text.contains(&workspace_id.to_string()),
        "positive control: the row text must contain the workspace id; got {row_text}"
    );

    // 6. THE ASSERTION.
    assert!(
        !row_text.contains(SYNTHETIC_NAME),
        "the synthetic original is stored in the clear in token_vault_entries: {row_text}"
    );
    assert!(
        !row_text.contains(PROSE),
        "non-PII fixture prose also leaked into the stored row: {row_text}"
    );
    Ok(())
}

/// Acceptance criterion: "Tokenize → detokenize round-trip still works."
///
/// This is the POSITIVE CONTROL for the whole workstream at the API level:
/// storing an unreadable blob is easy, and a test that only asserted "no
/// plaintext on disk" would pass for a repository that dropped the mapping on
/// the floor. The round-trip is what distinguishes encryption from data loss.
#[sqlx::test]
async fn tokenize_detokenize_round_trip_restores_the_original(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;
    let jwt = dashboard_jwt(workspace_id);

    let sidecar = MockSidecar::spawn();
    let app = support::router_with(pool.clone(), &sidecar.url(), "default");

    let response = app
        .clone()
        .oneshot(tokenize_request(&jwt, &fixture_text()))
        .await
        .expect("router should respond");
    assert_eq!(response.status(), StatusCode::OK);
    let body = support::response_json(response).await;

    let tokenized = body["tokenized_text"]
        .as_str()
        .expect("tokenized_text")
        .to_owned();
    let vault_id: Uuid = body["token_vault_id"]
        .as_str()
        .expect("token_vault_id")
        .parse()
        .expect("uuid");

    // Premise: the round-trip is not trivial — the tokenized text really is
    // different from the input, so "detokenize returned the original" cannot
    // be satisfied by an identity function.
    assert_ne!(
        tokenized,
        fixture_text(),
        "premise: tokenization must actually have changed the text"
    );
    assert!(!tokenized.contains(SYNTHETIC_NAME));

    let response = app
        .oneshot(detokenize_request(&jwt, vault_id, &tokenized))
        .await
        .expect("router should respond");
    let status = response.status();
    let body = support::response_json(response).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "detokenize must succeed; body={body}"
    );
    assert_eq!(
        body["text"].as_str(),
        Some(fixture_text().as_str()),
        "detokenize must restore the original text verbatim; body={body}"
    );
    Ok(())
}

/// The strongest available POSITIVE CONTROL for
/// `tokenize_stores_no_plaintext_original_in_postgres`: put the synthetic
/// name into the very column that test asserts is free of it, using a direct
/// INSERT that bypasses the repository, and prove the same
/// `to_jsonb(t)::text` query finds it.
///
/// The other test's controls show the query can find *a* string (the vault
/// id) in *a* row. This one shows it finds *this exact synthetic name* in
/// *this exact column* — closing the gap where the absence assertion could
/// pass because of some encoding quirk of the search rather than because the
/// data is encrypted.
#[sqlx::test]
async fn the_leak_query_finds_plaintext_when_plaintext_is_present(
    pool: PgPool,
) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;

    let planted_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO token_vault_entries (id, workspace_id, mapping_ciphertext)
         VALUES ($1, $2, $3)",
    )
    .bind(planted_id)
    .bind(workspace_id)
    // Deliberately NOT ciphertext — this row exists to be found.
    .bind(format!(r#"{{"{{{{Person_1}}}}":"{SYNTHETIC_NAME}"}}"#))
    .execute(&pool)
    .await?;

    let row_text = stored_row_text(&pool, planted_id).await?;
    assert!(
        row_text.contains(SYNTHETIC_NAME),
        "the leak query must find plaintext that IS there — if this fails, the \
         absence assertion in tokenize_stores_no_plaintext_original_in_postgres \
         proves nothing; got {row_text}"
    );
    Ok(())
}

/// A KMS outage must fail the insert, never fall back to writing the original
/// in the clear — the same fail-closed rule `analytics::capture::seal` applies
/// to captured content.
///
/// Drives the repository directly rather than the HTTP route because the
/// router builds its KMS from the environment, and this test needs a KMS that
/// refuses.
#[sqlx::test]
async fn kms_failure_writes_no_row_rather_than_plaintext(pool: PgPool) -> sqlx::Result<()> {
    use anyhow::Result;
    use async_trait::async_trait;
    use secureprompt_api::db::token_vault_repo::TokenVaultRepository;
    use secureprompt_common::kms::KmsBackend;
    use std::collections::HashMap;

    struct BrokenKms;
    #[async_trait]
    impl KmsBackend for BrokenKms {
        async fn encrypt(&self, _plaintext: &[u8]) -> Result<Vec<u8>> {
            anyhow::bail!("vault unreachable")
        }
        async fn decrypt(&self, _ciphertext: &[u8]) -> Result<Vec<u8>> {
            anyhow::bail!("vault unreachable")
        }
    }

    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;

    let mapping: HashMap<String, String> = [("{{Person_1}}".to_owned(), SYNTHETIC_NAME.to_owned())]
        .into_iter()
        .collect();

    // POSITIVE CONTROL: the identical call with a WORKING KMS must succeed,
    // so the failure below is attributable to the KMS and not to the fixture,
    // the schema, or the workspace seed.
    let working = TokenVaultRepository::new(
        pool.clone(),
        secureprompt_common::kms::kms_backend_from_env().expect("KMS_FILE_KEY must be set"),
    );
    let ok_id = Uuid::new_v4();
    working
        .insert(ok_id, workspace_id, &mapping)
        .await
        .expect("positive control: a working KMS must produce a row");
    let ok_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM token_vault_entries WHERE id = $1")
        .bind(ok_id)
        .fetch_one(&pool)
        .await?;
    assert_eq!(
        ok_rows, 1,
        "positive control: the working insert wrote a row"
    );
    // ...and it round-trips, so "no plaintext" below is not just "no data".
    let restored = working
        .get(ok_id, workspace_id)
        .await
        .expect("positive control: the sealed row must decrypt");
    assert_eq!(
        restored.mapping.get("{{Person_1}}").map(String::as_str),
        Some(SYNTHETIC_NAME),
        "positive control: the round-trip must return the original"
    );

    // THE ASSERTION.
    let broken = TokenVaultRepository::new(pool.clone(), Arc::new(BrokenKms));
    let broken_id = Uuid::new_v4();
    let result = broken.insert(broken_id, workspace_id, &mapping).await;
    assert!(
        result.is_err(),
        "a failed encrypt must surface as an error, never a plaintext insert"
    );

    let leaked: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM token_vault_entries t WHERE t.workspace_id = $1
           AND to_jsonb(t)::text LIKE '%' || $2 || '%'",
    )
    .bind(workspace_id)
    .bind(SYNTHETIC_NAME)
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        leaked, 0,
        "the original was written in the clear after the KMS refused"
    );
    Ok(())
}
