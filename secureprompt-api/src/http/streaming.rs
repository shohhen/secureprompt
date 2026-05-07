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

/// Chunk-assembly buffer for placeholder-aware streaming.
///
/// Placeholders emitted by `apply_redaction` look like `{{Class_N}}` (e.g.
/// `{{Person_1}}`, `{{Email_Address_2}}`). When the LLM echoes them back in
/// a streamed response, a single placeholder may straddle chunk boundaries;
/// we must keep the fragment buffered until the closing `}}` arrives,
/// otherwise `TokenVault::restore` would miss it and the raw placeholder
/// would leak to the client.
///
/// Detection rule: a candidate placeholder starts at any byte offset where
/// `{{` is followed by an ASCII uppercase letter. Bare `{` is emitted
/// immediately so `{ "json": "value" }` flows through normally.
#[must_use]
pub fn placeholder_safe_chunks(chunks: &[String], vault: &TokenVault) -> Vec<String> {
    let mut pending = String::new();
    let mut safe_chunks = Vec::new();

    for chunk in chunks {
        pending.push_str(chunk);

        loop {
            match find_placeholder_start(&pending) {
                Some(start) => {
                    if let Some(end_offset) = pending[start..].find("}}") {
                        let emit_end = start + end_offset + 2;
                        let safe = pending[..emit_end].to_owned();
                        if !safe.is_empty() {
                            safe_chunks.push(vault.restore(&safe));
                        }
                        pending = pending[emit_end..].to_owned();
                        continue;
                    }

                    // Placeholder's opener is in-buffer but closer hasn't
                    // arrived — flush everything before the `{{` and hold.
                    if start > 0 {
                        let safe = pending[..start].to_owned();
                        if !safe.is_empty() {
                            safe_chunks.push(vault.restore(&safe));
                        }
                        pending = pending[start..].to_owned();
                    }
                    break;
                }
                None => {
                    // No placeholder candidate in buffer. Hold back a
                    // trailing `{` (or `{{`) in case the next chunk
                    // completes the opener; otherwise emit.
                    let hold = if pending.ends_with("{{") {
                        2
                    } else if pending.ends_with('{') {
                        1
                    } else {
                        0
                    };
                    let emit_len = pending.len().saturating_sub(hold);
                    if emit_len > 0 {
                        let safe = pending[..emit_len].to_owned();
                        safe_chunks.push(vault.restore(&safe));
                        pending = pending[emit_len..].to_owned();
                    }
                    break;
                }
            }
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

/// Return the byte offset of the first `{{X…` sequence where X is ASCII
/// uppercase. All our placeholder classes are Title_Case so the opening
/// letter is always uppercase; this keeps benign `{{` (e.g. mustache
/// templates that aren't ours) from triggering chunk-buffer hold-back.
fn find_placeholder_start(content: &str) -> Option<usize> {
    let bytes = content.as_bytes();
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == b'{' && bytes[i + 1] == b'{' && bytes[i + 2].is_ascii_uppercase() {
            return Some(i);
        }
        i += 1;
    }
    None
}
