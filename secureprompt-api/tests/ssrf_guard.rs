//! End-to-end egress guard checks.
//!
//! Uses raw loopback `TcpListener`s rather than a mock-HTTP crate, matching
//! the existing idiom in `secureprompt-api/src/ml_sidecar/client.rs` tests.

use secureprompt_api::providers::credential_test::test_connection;

/// A `base_url` whose host is loopback is refused by the egress guard's
/// pre-flight address screening BEFORE any socket is opened. Loopback is
/// blocked unconditionally — `SECUREPROMPT_ALLOW_PRIVATE_PROVIDER_URLS` does
/// not relax it — so this exercises the pre-flight refusal path of
/// `test_connection`, not the redirect policy (see
/// `pinned_client_does_not_follow_redirects` for that).
#[tokio::test]
async fn base_url_at_loopback_is_refused_preflight() {
    let r = test_connection("openai", "sk-test", Some("http://127.0.0.1:9/models"), None, None).await;
    assert!(!r.success, "loopback base_url must be refused");
    let err = r.error.unwrap_or_default();
    assert!(
        err.contains("loopback"),
        "error should name the loopback refusal, got: {err}"
    );
}

/// The guard's pinned client is built with `redirect::Policy::none()`, so a
/// 302 pointing at the cloud metadata endpoint is NOT chased — the caller
/// receives the 302 status itself. This exercises the redirect policy
/// directly: it constructs the `ValidatedUrl` for a loopback listener
/// explicitly, since `build_pinned_client` does not re-screen addresses
/// (that is `validate_outbound_url`'s job, tested separately).
#[tokio::test]
async fn pinned_client_does_not_follow_redirects() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    use secureprompt_api::security::{build_pinned_client, ValidatedUrl};

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");

    let server = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf);
            let resp = "HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(resp.as_bytes());
        }
    });

    let url = reqwest::Url::parse(&format!("http://127.0.0.1:{}/models", addr.port()))
        .expect("valid url");
    let validated = ValidatedUrl {
        url: url.clone(),
        host: "127.0.0.1".to_owned(),
        addrs: vec![addr],
    };
    let client = build_pinned_client(&validated, std::time::Duration::from_secs(5))
        .expect("pinned client builds");

    let resp = client.get(url).send().await.expect("request completes");
    assert_eq!(
        resp.status().as_u16(),
        302,
        "redirect must NOT be followed (Policy::none)"
    );

    server.join().expect("server thread panicked");
}
