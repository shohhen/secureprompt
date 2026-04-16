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
