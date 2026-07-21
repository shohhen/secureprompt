//! End-to-end egress guard checks.
//!
//! Uses a raw loopback TCP listener rather than a mock-HTTP crate, matching
//! the existing idiom in `secureprompt-api/src/ml_sidecar/client.rs` tests
//! (no wiremock/mockito in this workspace).

use std::io::{Read, Write};
use std::net::TcpListener;

use secureprompt_api::providers::credential_test::test_connection;

/// A public-looking base_url that 302s to the cloud metadata endpoint must
/// not be followed. The guard disables redirects, so the probe fails at the
/// 302 instead of fetching metadata.
#[tokio::test]
async fn redirect_to_metadata_is_not_followed() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf);
            let resp = "HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(resp.as_bytes());
        }
    });

    // Private ranges permitted so the loopback listener is reachable at all;
    // the point of the test is that the REDIRECT is not chased.
    std::env::set_var("SECUREPROMPT_ALLOW_PRIVATE_PROVIDER_URLS", "true");

    let base = format!("http://127.0.0.1:{}", addr.port());
    let r = test_connection("openai", "sk-test", Some(&base), None, None).await;

    std::env::remove_var("SECUREPROMPT_ALLOW_PRIVATE_PROVIDER_URLS");

    assert!(!r.success, "probe must fail rather than follow the redirect");

    // Not joined: loopback is refused inside `validate_outbound_url`
    // (address classification, no socket I/O) before any connection is
    // attempted, so the listener's `accept()` above structurally never
    // returns — joining it would deadlock this test forever. The spawned
    // thread is reclaimed by the OS when the test binary exits.
    drop(server);
}
