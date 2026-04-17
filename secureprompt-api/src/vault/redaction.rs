use secureprompt_common::types::{Detection, TokenVault};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[must_use]
pub fn placeholder_for(class: &str, value: &str) -> String {
    let digest = hex::encode(Sha256::digest(value.as_bytes()));
    // Use 16 hex characters (64 bits) to reduce birthday-collision probability
    // from ~2^16 to ~2^32 distinct secrets before a collision is expected.
    format!("[REDACTED:{}:{}]", class.to_uppercase(), &digest[..16])
}

#[must_use]
pub fn apply_redaction(
    content: &str,
    detections: &[Detection],
    vault: &mut TokenVault,
    redaction_map: &mut HashMap<String, String>,
) -> String {
    let mut ordered = detections.to_vec();
    ordered.sort_by_key(|detection| detection.span.map_or(usize::MAX, |(start, _)| start));

    let mut cursor = 0usize;
    let mut redacted = String::new();

    for detection in ordered {
        let Some((start, end)) = detection.span else {
            continue;
        };

        if start < cursor || end > content.len() {
            continue;
        }

        // Reject spans that do not align to UTF-8 character boundaries.
        // Byte-indexed slicing panics on non-boundary offsets; skipping the
        // detection is safer than corrupting the output or crashing.
        if !content.is_char_boundary(start) || !content.is_char_boundary(end) {
            continue;
        }

        redacted.push_str(&content[cursor..start]);
        let placeholder = placeholder_for(&detection.class, &detection.value);
        vault.insert(placeholder.clone(), detection.value.clone());
        redaction_map.insert(placeholder.clone(), detection.value.clone());
        redacted.push_str(&placeholder);
        cursor = end;
    }

    redacted.push_str(&content[cursor..]);
    redacted
}

#[must_use]
pub fn apply_transform(content: &str, detections: &[Detection], template: &str) -> String {
    let mut ordered = detections.to_vec();
    ordered.sort_by_key(|detection| detection.span.map_or(usize::MAX, |(start, _)| start));

    let mut cursor = 0usize;
    let mut transformed = String::new();

    for detection in ordered {
        let Some((start, end)) = detection.span else {
            continue;
        };

        if start < cursor || end > content.len() {
            continue;
        }

        if !content.is_char_boundary(start) || !content.is_char_boundary(end) {
            continue;
        }

        transformed.push_str(&content[cursor..start]);
        transformed.push_str(&render_template(template, &detection.value));
        cursor = end;
    }

    transformed.push_str(&content[cursor..]);
    transformed
}

#[must_use]
pub fn restore_content(content: &str, vault: &TokenVault) -> String {
    vault.restore(content)
}

fn render_template(template: &str, value: &str) -> String {
    let value_tail = if value.len() > 4 {
        &value[value.len() - 4..]
    } else {
        value
    };

    template
        .replace("{value[-4:]}", value_tail)
        .replace("{value}", value)
}
