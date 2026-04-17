use secureprompt_api::{http::streaming::placeholder_safe_chunks, vault::apply_redaction};
use secureprompt_common::types::{Detection, TokenVault};
use std::collections::HashMap;

#[test]
fn placeholder_boundaries_restore_cleanly_across_chunk_sizes() {
    let content = "prefix alice@example.com suffix";
    let detections = vec![Detection {
        class: "email".to_owned(),
        confidence: 0.99,
        span: Some((7, 24)),
        value: "alice@example.com".to_owned(),
    }];

    let mut vault = TokenVault::default();
    let mut redaction_map = HashMap::new();
    let redacted = apply_redaction(content, &detections, &mut vault, &mut redaction_map);
    let provider_echo = format!("stream {redacted}");
    let expected = "stream prefix alice@example.com suffix";

    for chunk_size in 1..=provider_echo.len() {
        let raw_chunks = split_chunks(&provider_echo, chunk_size);
        let restored = placeholder_safe_chunks(&raw_chunks, &vault).concat();

        assert_eq!(restored, expected, "failed at chunk size {chunk_size}");
        assert!(
            !restored.contains("[REDACTED:"),
            "placeholder leaked at chunk size {chunk_size}"
        );
    }
}

#[test]
fn multibyte_utf8_content_redacts_and_restores_cleanly() {
    // "café" contains a multi-byte UTF-8 character (é = 2 bytes).
    // The email starts at byte offset 7 (after "prefix ").
    let content = "prefix café@example.com suffix";
    let email = "café@example.com";
    let email_start = content.find(email).expect("email present in content");
    let email_end = email_start + email.len();

    // Verify span aligns to char boundaries (guards the is_char_boundary check).
    assert!(content.is_char_boundary(email_start));
    assert!(content.is_char_boundary(email_end));

    let detections = vec![Detection {
        class: "email".to_owned(),
        confidence: 0.99,
        span: Some((email_start, email_end)),
        value: email.to_owned(),
    }];

    let mut vault = TokenVault::default();
    let mut redaction_map = HashMap::new();
    let redacted = apply_redaction(content, &detections, &mut vault, &mut redaction_map);

    assert!(
        !redacted.contains(email),
        "multi-byte email must be redacted: {redacted}"
    );
    assert!(
        redacted.contains("[REDACTED:"),
        "placeholder must be present: {redacted}"
    );

    // Verify chunk-safe restoration works for all chunk sizes.
    let provider_echo = format!("stream {redacted}");
    let expected = format!("stream prefix {email} suffix");

    for chunk_size in 1..=provider_echo.len() {
        let raw_chunks = split_chunks(&provider_echo, chunk_size);
        let restored = placeholder_safe_chunks(&raw_chunks, &vault).concat();
        assert_eq!(
            restored, expected,
            "multi-byte restoration failed at chunk size {chunk_size}"
        );
    }
}

fn split_chunks(content: &str, chunk_size: usize) -> Vec<String> {
    let chars: Vec<char> = content.chars().collect();
    let mut chunks = Vec::new();
    let mut start = 0usize;

    while start < chars.len() {
        let end = (start + chunk_size).min(chars.len());
        chunks.push(chars[start..end].iter().collect());
        start = end;
    }

    chunks
}
