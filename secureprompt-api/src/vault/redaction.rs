use secureprompt_common::types::{Detection, TokenVault};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Legacy stateless placeholder used only by `placeholder_for`'s own tests
/// and any external caller that still imports this symbol. New redaction
/// goes through `apply_redaction`, which emits readable `<Class_N>` tokens
/// with per-call stable indexing — same (class, value) inside one call
/// returns the same placeholder, which is what users and LLMs expect when
/// a name repeats.
#[must_use]
pub fn placeholder_for(class: &str, value: &str) -> String {
    let digest = hex::encode(Sha256::digest(value.as_bytes()));
    // Use 16 hex characters (64 bits) to reduce birthday-collision probability
    // from ~2^16 to ~2^32 distinct secrets before a collision is expected.
    format!("[REDACTED:{}:{}]", class.to_uppercase(), &digest[..16])
}

/// Turn `SCREAMING_SNAKE_CASE` into `Title_Case` for placeholder output.
/// `PERSON` → `Person`, `EMAIL_ADDRESS` → `Email_Address`, `US_SSN` → `Us_Ssn`.
fn title_case(class: &str) -> String {
    class
        .split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => {
                    first.to_uppercase().to_string() + chars.as_str().to_lowercase().as_str()
                }
            }
        })
        .collect::<Vec<_>>()
        .join("_")
}

#[must_use]
pub fn apply_redaction(
    content: &str,
    detections: &[Detection],
    vault: &mut TokenVault,
    redaction_map: &mut HashMap<String, String>,
) -> String {
    let mut ordered = detections.to_vec();
    // Sort by start position ascending; for ties, longer spans win so a
    // multi-token detection like "Ali Aliev" beats a single-token gazetteer
    // match on "Ali" that would otherwise leave " Aliev" dangling.
    ordered.sort_by(|a, b| {
        let a_span = a.span.unwrap_or((usize::MAX, usize::MAX));
        let b_span = b.span.unwrap_or((usize::MAX, usize::MAX));
        a_span.0.cmp(&b_span.0).then_with(|| {
            let a_len = a_span.1.saturating_sub(a_span.0);
            let b_len = b_span.1.saturating_sub(b_span.0);
            b_len.cmp(&a_len)
        })
    });

    // Per-call state: same (class, value) → same placeholder so repeated
    // mentions of "Shohjahon" both become `<Person_1>` and two different
    // people become `<Person_1>` / `<Person_2>`. Counters are per-class so
    // an email after a person becomes `<Email_1>`, not `<Person_2>`.
    let mut assigned: HashMap<(String, String), String> = HashMap::new();
    let mut counters: HashMap<String, u32> = HashMap::new();

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

        let class_upper = detection.class.to_uppercase();
        let key = (class_upper.clone(), detection.value.clone());
        let placeholder = match assigned.get(&key) {
            Some(existing) => existing.clone(),
            None => {
                let counter = counters.entry(class_upper.clone()).or_insert(0);
                *counter += 1;
                // Double curly braces (mustache/handlebars style) so the
                // placeholders survive every downstream renderer pass.
                //
                // Why not angle brackets `<Person_1>`: LibreChat's
                // rehype-highlight Prism stage strips them as unknown XML.
                //
                // Why not square brackets `[Person_1]`: LibreChat ships
                // remark-directive + a custom unicodeCitation plugin that
                // parses bare `[text]` patterns as link references /
                // directives / citations and either rewrites or drops them.
                //
                // Double curlies `{{Person_1}}` aren't tokens in CommonMark,
                // GFM, remark-directive, rehype-highlight, or any common
                // markdown plugin. ASCII-safe, easy to grep, well-known.
                let token = format!("{{{{{}_{}}}}}", title_case(&class_upper), counter);
                assigned.insert(key, token.clone());
                token
            }
        };

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
    // Sort by start position ascending; for ties, longer spans win so a
    // multi-token detection like "Ali Aliev" beats a single-token gazetteer
    // match on "Ali" that would otherwise leave " Aliev" dangling.
    ordered.sort_by(|a, b| {
        let a_span = a.span.unwrap_or((usize::MAX, usize::MAX));
        let b_span = b.span.unwrap_or((usize::MAX, usize::MAX));
        a_span.0.cmp(&b_span.0).then_with(|| {
            let a_len = a_span.1.saturating_sub(a_span.0);
            let b_len = b_span.1.saturating_sub(b_span.0);
            b_len.cmp(&a_len)
        })
    });

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
