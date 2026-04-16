use secureprompt_common::types::TokenVault;
use serde_json::{json, Value};

pub fn force_include_usage(extra_params: &mut Value) {
    if !extra_params.is_object() {
        *extra_params = json!({});
    }

    let stream_options = extra_params
        .as_object_mut()
        .expect("stream options container is an object")
        .entry("stream_options")
        .or_insert_with(|| json!({}));

    if !stream_options.is_object() {
        *stream_options = json!({});
    }

    stream_options["include_usage"] = Value::Bool(true);
}

#[must_use]
pub fn placeholder_safe_chunks(chunks: &[String], vault: &TokenVault) -> Vec<String> {
    const PLACEHOLDER_PREFIX: &str = "[REDACTED:";
    let mut pending = String::new();
    let mut safe_chunks = Vec::new();

    for chunk in chunks {
        pending.push_str(chunk);

        loop {
            if let Some(start) = pending.find(PLACEHOLDER_PREFIX) {
                if let Some(end_offset) = pending[start..].find(']') {
                    let emit_end = start + end_offset + 1;
                    if emit_end == 0 {
                        break;
                    }
                    let safe = pending[..emit_end].to_owned();
                    if !safe.is_empty() {
                        safe_chunks.push(vault.restore(&safe));
                    }
                    pending = pending[emit_end..].to_owned();
                    continue;
                }

                if start > 0 {
                    let safe = pending[..start].to_owned();
                    if !safe.is_empty() {
                        safe_chunks.push(vault.restore(&safe));
                    }
                    pending = pending[start..].to_owned();
                }
                break;
            }

            let keep = trailing_placeholder_prefix_len(&pending, PLACEHOLDER_PREFIX);
            let emit_len = pending.len().saturating_sub(keep);
            if emit_len > 0 {
                let safe = pending[..emit_len].to_owned();
                safe_chunks.push(vault.restore(&safe));
                pending = pending[emit_len..].to_owned();
            }
            break;
        }
    }

    if !pending.is_empty() {
        safe_chunks.push(vault.restore(&pending));
    }

    safe_chunks
}

#[must_use]
pub fn fallback_allowed(emitted_chunks: usize) -> bool {
    emitted_chunks == 0
}

fn trailing_placeholder_prefix_len(content: &str, placeholder_prefix: &str) -> usize {
    for len in (1..placeholder_prefix.len()).rev() {
        if content.ends_with(&placeholder_prefix[..len]) {
            return len;
        }
    }
    0
}
