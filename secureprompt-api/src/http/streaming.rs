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

/// Stateful, incremental sibling of [`placeholder_safe_chunks`] for true
/// token-by-token streaming.
///
/// `placeholder_safe_chunks` takes the whole chunk list at once; when we
/// stream upstream tokens one at a time we instead feed each delta through a
/// `PlaceholderStreamer`, which carries the partial-placeholder buffer
/// (`pending`) across calls. A `{{Person_1}}` placeholder echoed back by the
/// model can be split across several upstream tokens (`{{Per`, `son_1`, `}}`);
/// `pending` holds the fragment until the closing `}}` arrives so
/// `vault.restore` never sees — and never leaks — a half-placeholder.
#[derive(Default)]
pub struct PlaceholderStreamer {
    pending: String,
}

impl PlaceholderStreamer {
    #[must_use]
    pub fn new() -> Self {
        Self { pending: String::new() }
    }

    /// Feed one raw upstream delta; return the restored text that is safe to
    /// emit to the client right now (may be empty when a placeholder opener
    /// is still being buffered).
    pub fn push(&mut self, delta: &str, vault: &TokenVault) -> String {
        self.pending.push_str(delta);
        let mut out = String::new();
        loop {
            match find_placeholder_start(&self.pending) {
                Some(start) => {
                    if let Some(end_offset) = self.pending[start..].find("}}") {
                        let emit_end = start + end_offset + 2;
                        let safe = self.pending[..emit_end].to_owned();
                        if !safe.is_empty() {
                            out.push_str(&vault.restore(&safe));
                        }
                        self.pending = self.pending[emit_end..].to_owned();
                        continue;
                    }
                    // Opener present but closer not yet — flush text before it.
                    if start > 0 {
                        let safe = self.pending[..start].to_owned();
                        if !safe.is_empty() {
                            out.push_str(&vault.restore(&safe));
                        }
                        self.pending = self.pending[start..].to_owned();
                    }
                    break;
                }
                None => {
                    // Hold back a trailing `{`/`{{` that could open a
                    // placeholder once the next delta arrives.
                    let hold = if self.pending.ends_with("{{") {
                        2
                    } else if self.pending.ends_with('{') {
                        1
                    } else {
                        0
                    };
                    let emit_len = self.pending.len().saturating_sub(hold);
                    if emit_len > 0 {
                        let safe = self.pending[..emit_len].to_owned();
                        out.push_str(&vault.restore(&safe));
                        self.pending = self.pending[emit_len..].to_owned();
                    }
                    break;
                }
            }
        }
        out
    }

    /// Emit any remaining buffered text once the upstream stream ends.
    #[must_use]
    pub fn flush(self, vault: &TokenVault) -> String {
        if self.pending.is_empty() {
            String::new()
        } else {
            vault.restore(&self.pending)
        }
    }
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

/// Byte length of the prefix of `buf` that is *safe to flush* when
/// response-side PII redaction is on (the hold-back streaming mode).
///
/// In that mode the gateway must scan each segment for PII *before* the
/// client sees it, so we can only emit text up to a boundary that no PII
/// entity could straddle. We use sentence/line boundaries:
///
///   * any `\n` — a newline never appears inside a PII entity; and
///   * a `.`, `!` or `?` that is **immediately followed by whitespace** —
///     a true clause break. The "followed by whitespace" guard is what
///     keeps `john.doe@x.com`, `192.168.0.1`, and `3.14` intact: the dots
///     inside those tokens have no trailing space, so they are not treated
///     as boundaries and the whole token stays buffered until it is fully
///     formed and can be scanned as one unit.
///
/// Returns the byte offset (exclusive) up to the last such boundary, or `0`
/// when the buffer has no complete segment yet (caller holds everything and
/// waits for more tokens). On stream end the caller flushes the remainder
/// unconditionally.
#[must_use]
pub fn settled_prefix_len(buf: &str) -> usize {
    let chars: Vec<(usize, char)> = buf.char_indices().collect();
    let mut last = 0usize;
    for (k, (bi, c)) in chars.iter().enumerate() {
        let flush_to = match c {
            '\n' => Some(bi + c.len_utf8()),
            '.' | '!' | '?' => {
                let next_is_ws = chars
                    .get(k + 1)
                    .map(|(_, nc)| nc.is_whitespace())
                    .unwrap_or(false);
                if next_is_ws {
                    Some(bi + c.len_utf8())
                } else {
                    None
                }
            }
            _ => None,
        };
        if let Some(end) = flush_to {
            last = end;
        }
    }
    last
}

#[cfg(test)]
mod settled_prefix_tests {
    use super::settled_prefix_len;

    #[test]
    fn no_boundary_holds_everything() {
        assert_eq!(settled_prefix_len("the answer is forty"), 0);
    }

    #[test]
    fn flushes_through_last_sentence_terminator() {
        let s = "First sentence. Second one";
        let n = settled_prefix_len(s);
        assert_eq!(&s[..n], "First sentence.");
        assert_eq!(&s[n..], " Second one");
    }

    #[test]
    fn newline_is_a_boundary() {
        let s = "line one\nline two";
        let n = settled_prefix_len(s);
        assert_eq!(&s[..n], "line one\n");
    }

    #[test]
    fn dot_inside_email_is_not_a_boundary() {
        // The dot in john.doe and in x.com has no trailing whitespace, so the
        // whole address stays buffered — never split mid-entity.
        let s = "reach me at john.doe@x.com now";
        assert_eq!(settled_prefix_len(s), 0);
    }

    #[test]
    fn dot_in_ipv4_and_decimal_is_not_a_boundary() {
        assert_eq!(settled_prefix_len("host 192.168.0.1 pings"), 0);
        assert_eq!(settled_prefix_len("pi is 3.14 today"), 0);
    }

    #[test]
    fn email_then_real_sentence_break_flushes_after_the_break() {
        let s = "Email john.doe@x.com. Then more";
        let n = settled_prefix_len(s);
        // The boundary is the period after `.com` (followed by a space), not
        // the dots inside the address — so the full email is in the prefix.
        assert_eq!(&s[..n], "Email john.doe@x.com.");
    }

    #[test]
    fn handles_multibyte_cyrillic() {
        let s = "Привет мир. Это тест";
        let n = settled_prefix_len(s);
        assert_eq!(&s[..n], "Привет мир.");
        // n must land on a char boundary (slicing above would panic otherwise).
        assert!(s.is_char_boundary(n));
    }
}

#[cfg(test)]
mod placeholder_streamer_tests {
    use super::PlaceholderStreamer;
    use secureprompt_common::types::TokenVault;

    fn drive(tokens: &[&str], vault: &TokenVault) -> String {
        let mut s = PlaceholderStreamer::new();
        let mut out = String::new();
        for t in tokens {
            out.push_str(&s.push(t, vault));
        }
        out.push_str(&s.flush(vault));
        out
    }

    #[test]
    fn plain_text_streams_through_unchanged() {
        let v = TokenVault::default();
        assert_eq!(drive(&["hel", "lo ", "world"], &v), "hello world");
    }

    #[test]
    fn placeholder_split_into_single_chars_is_restored() {
        // Real tokenization format is `{{Class_N}}` (see vault/redaction.rs).
        let mut v = TokenVault::default();
        v.insert("{{Email_Address_1}}".to_owned(), "user@example.com".to_owned());
        let full = "Mail: {{Email_Address_1}} ok";
        let toks: Vec<String> = full.chars().map(|c| c.to_string()).collect();
        let refs: Vec<&str> = toks.iter().map(String::as_str).collect();
        assert_eq!(drive(&refs, &v), "Mail: user@example.com ok");
    }

    #[test]
    fn partial_opener_is_held_then_restored() {
        let mut v = TokenVault::default();
        v.insert("{{Person_1}}".to_owned(), "Alice".to_owned());
        let mut s = PlaceholderStreamer::new();
        // Opener arrives without the entity name yet → must not leak `{{`.
        assert_eq!(s.push("Hi {{", &v), "Hi ");
        // Completion arrives → the whole placeholder resolves to the original.
        assert_eq!(s.push("Person_1}}!", &v), "Alice!");
        assert_eq!(s.flush(&v), "");
    }
}
