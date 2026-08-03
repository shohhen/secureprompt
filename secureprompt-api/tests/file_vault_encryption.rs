//! WS3 review — the file-scan stash in Redis holds PII and must be
//! ciphertext.
//!
//! # The defect
//!
//! `POST /v1/vault/stash` writes a `{placeholder → ORIGINAL PII}` map to
//! Redis as raw JSON under `filevault:{ref}`, TTL 6h, with no KMS anywhere in
//! the path. The route's own comment says so:
//!
//! > A stash holds PII — require the same per-user auth as every data route.
//!
//! That is the SAME DATA CLASS as `token_vault_entries.mapping`, which
//! migration 022 replaced with `mapping_ciphertext` precisely because storing
//! it in the clear was unacceptable. WS3-3 encrypted one of the two vaults.
//!
//! # How these tests prove it
//!
//! The leak assertion reads the value back out of Redis over a RAW TCP
//! SOCKET, speaking RESP directly — not through `load_file_vault`, not
//! through any client library this crate uses. A round-trip through our own
//! decrypt path would pass just as happily against plaintext, and a client
//! library in the path is one more place a transform could hide. This is
//! "what is on disk", as literally as the test can make it.
//!
//! All fixture PII is synthetic.

mod support;

use axum::http::{Method, Request, StatusCode};
use serde_json::json;
use sqlx::PgPool;
use std::io::{Read, Write};
use std::net::TcpStream;
use tower::ServiceExt;
use uuid::Uuid;

const API_KEY: &str = "sp_ws3_file_vault";
/// Synthetic PII — the original a placeholder maps back to, and the string
/// every leak assertion hunts for in Redis.
const SYNTHETIC_NAME: &str = "Anvar Karimov";
/// The placeholder it maps from. Asserted absent too: the whole mapping is
/// encrypted, not just its values, so neither side of the pair may be
/// readable.
const PLACEHOLDER: &str = "{{Person_1}}";

// ── Redis, read directly ──────────────────────────────────────────────────

fn redis_addr() -> String {
    std::env::var("REDIS_URL")
        .unwrap_or_else(|_| "redis://localhost:6379".to_owned())
        .trim_start_matches("redis://")
        .trim_end_matches('/')
        .to_owned()
}

/// Send one command as a RESP array and return the bulk-string reply.
///
/// `None` distinguishes a missing key (`$-1`) from an empty one (`$0`), which
/// matters: "no plaintext found" in a key that does not exist is not a
/// result, and the premise assertions below rely on telling them apart.
fn redis_command(args: &[&str]) -> Option<String> {
    let mut stream = TcpStream::connect(redis_addr())
        .expect("Redis must be reachable — see the task env (REDIS_URL)");

    let mut request = format!("*{}\r\n", args.len());
    for arg in args {
        request.push_str(&format!("${}\r\n{arg}\r\n", arg.len()));
    }
    stream
        .write_all(request.as_bytes())
        .expect("write redis command");

    let mut raw: Vec<u8> = Vec::new();
    let mut buf = [0u8; 4096];

    // Header line first: `$<len>` / `$-1` / `+OK` / `-ERR …`.
    let header_end = loop {
        if let Some(pos) = raw.windows(2).position(|w| w == b"\r\n") {
            break pos + 2;
        }
        let n = stream.read(&mut buf).expect("read redis reply");
        assert!(n > 0, "redis closed the connection before replying");
        raw.extend_from_slice(&buf[..n]);
    };
    let header = String::from_utf8_lossy(&raw[..header_end - 2]).to_string();

    assert!(
        !header.starts_with('-'),
        "redis returned an error for {args:?}: {header}"
    );
    if !header.starts_with('$') {
        // Simple string / integer reply (`+OK`, `:1`).
        return Some(header[1..].to_owned());
    }
    let len: i64 = header[1..].parse().expect("bulk length");
    if len < 0 {
        return None;
    }
    let want = header_end + usize::try_from(len).expect("bulk length fits") + 2;
    while raw.len() < want {
        let n = stream.read(&mut buf).expect("read redis bulk body");
        assert!(n > 0, "redis truncated a bulk reply");
        raw.extend_from_slice(&buf[..n]);
    }
    Some(String::from_utf8_lossy(&raw[header_end..want - 2]).to_string())
}

// ── Mock ML sidecar ───────────────────────────────────────────────────────

/// Answers every sidecar endpoint with an empty result, so NER coverage is
/// COMPLETE and the request is not rejected by the `sidecar_unavailable`
/// gate. It reports no detections on purpose: this file is about the vault
/// round-trip, and any placeholder in the reply must come from the STASH, not
/// from a fresh redaction.
struct MockSidecar {
    addr: std::net::SocketAddr,
}

impl MockSidecar {
    fn spawn() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local addr");
        std::thread::spawn(move || loop {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut buf = [0u8; 8192];
            let _ = stream.read(&mut buf);
            let body = br#"{"entities":[],"matches":[],"is_match":false,"is_injection":false,"score":0.0}"#;
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body);
        });
        Self { addr }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

// ── Fixtures ──────────────────────────────────────────────────────────────

async fn seed(pool: &PgPool, workspace_id: Uuid) -> sqlx::Result<()> {
    support::seed_workspace(pool, workspace_id, API_KEY).await?;
    support::seed_provider_and_model(
        pool,
        workspace_id,
        Uuid::new_v4(),
        "anthropic-primary",
        // Echo stub, so a request that reaches a provider comes back with the
        // prompt in the reply — which is what makes the restore observable.
        "anthropic",
        None,
        "claude-3-haiku",
    )
    .await
}

/// Stash one `{placeholder → PII}` pair through the real route and return its
/// ref.
async fn stash(pool: &PgPool) -> String {
    let request = support::authorized_request(
        Request::builder()
            .method(Method::POST)
            .uri("/v1/vault/stash"),
        API_KEY,
        json!({ "token_map": { PLACEHOLDER: SYNTHETIC_NAME } }),
    );
    let response = support::router(pool.clone())
        .oneshot(request)
        .await
        .expect("router should respond");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "premise: the stash route must succeed, or there is nothing on disk \
         to make assertions about"
    );
    let body = support::response_json(response).await;
    let vault_ref = body["vault_ref"]
        .as_str()
        .expect("stash returns a vault_ref")
        .to_owned();
    assert!(
        !vault_ref.is_empty(),
        "premise: a non-empty token_map must produce a real ref"
    );
    vault_ref
}

// ── The assertions ────────────────────────────────────────────────────────

/// THE LEAK. Read `filevault:{ref}` straight out of Redis and require that
/// neither the original PII nor its placeholder is legible.
///
/// PREMISES, so an absence cannot pass trivially:
///   1. the key EXISTS and is non-empty — "no plaintext in nothing" is not a
///      result, and a stash that silently failed would satisfy any absence;
///   2. POSITIVE CONTROL — the identical read-and-search method, over a key
///      this test writes itself with the identical plaintext, DOES find both
///      needles. Without it a broken RESP parser would report "clean" for
///      every key in the database.
#[sqlx::test]
async fn stash_route_stores_ciphertext_in_redis(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;

    let vault_ref = stash(&pool).await;

    // Premise 1.
    let stored = redis_command(&["GET", &format!("filevault:{vault_ref}")])
        .expect("premise: the stash must have written the key");
    assert!(
        !stored.is_empty(),
        "premise: the stashed value must be non-empty"
    );

    // Premise 2 — positive control, written and read by this test.
    let control_key = format!("sp-test-control:{}", Uuid::new_v4());
    let control_value = format!(r#"{{"{PLACEHOLDER}":"{SYNTHETIC_NAME}"}}"#);
    redis_command(&["SET", &control_key, &control_value, "EX", "60"]);
    let control = redis_command(&["GET", &control_key]).expect("control key must exist");
    for needle in [SYNTHETIC_NAME, PLACEHOLDER] {
        assert!(
            control.contains(needle),
            "positive control: the same raw-socket read must FIND '{needle}' \
             when it is really there. If this fails the assertion below \
             proves nothing about the stash."
        );
    }
    redis_command(&["DEL", &control_key]);

    // THE ASSERTION.
    for needle in [SYNTHETIC_NAME, PLACEHOLDER] {
        assert!(
            !stored.contains(needle),
            "'{needle}' is stored in the clear in Redis under \
             filevault:{vault_ref}. This map is the same data class as \
             token_vault_entries.mapping, which migration 022 encrypted.\n\
             stored value: {stored}"
        );
    }

    Ok(())
}

/// The stash must still be USABLE. Encryption that breaks restoration is not
/// a fix, and a test that only asserts an absence would call an unconditional
/// `stash_file_vault` failure a success.
///
/// End to end through the real pipeline: the message carries the opaque
/// `[[sp:v=…]]` marker and the PLACEHOLDER — never the PII — so the name
/// appearing in the reply can only have come from decrypting the stash and
/// restoring through the vault.
#[sqlx::test]
async fn stashed_file_vault_still_restores_pii_end_to_end(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    seed(&pool, workspace_id).await?;

    let vault_ref = stash(&pool).await;

    let prompt = format!("Summarise [[sp:v={vault_ref}]] {PLACEHOLDER}");
    // Premise: the request itself carries no PII, so finding the name in the
    // reply cannot be an echo of what we sent.
    assert!(
        !prompt.contains(SYNTHETIC_NAME),
        "premise: the prompt must reference the PII only by placeholder"
    );

    let mut request = support::authorized_request(
        Request::builder()
            .method(Method::POST)
            .uri("/v1/chat/completions"),
        API_KEY,
        json!({
            "model": "claude-3-haiku",
            "stream": false,
            "messages": [{ "role": "user", "content": prompt }],
        }),
    );
    request
        .extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            50_000,
        ))));

    let sidecar = MockSidecar::spawn();
    let response = support::router_with(pool.clone(), &sidecar.url(), "sp_analytics")
        .oneshot(request)
        .await
        .expect("router should respond");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "premise: the request must be served, or nothing was restored into \
         anything"
    );
    let body = support::response_text(response).await;

    assert!(
        body.contains(SYNTHETIC_NAME),
        "the stashed PII must be restored into the reply — the stash is \
         useless if it cannot be read back. body: {body}"
    );

    Ok(())
}
