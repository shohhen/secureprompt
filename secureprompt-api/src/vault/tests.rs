/// Tests for the vault module: request-scoped redaction and restoration.
///
/// `apply_redaction` emits `<Class_N>` placeholders with per-call stable
/// indexing — same (class, value) → same placeholder, different values get
/// the next index. The legacy `placeholder_for` helper keeps its
/// `[REDACTED:CLASS:hash]` format for backward compatibility.

#[cfg(test)]
mod placeholder_tests {
    use crate::vault::redaction::placeholder_for;

    // ---- legacy hash-based helper (kept for BC) --------------------------

    #[test]
    fn placeholder_uses_redacted_prefix() {
        let ph = placeholder_for("email", "user@example.com");
        assert!(
            ph.starts_with("[REDACTED:"),
            "Placeholder must start with [REDACTED:, got: {ph}"
        );
    }

    #[test]
    fn placeholder_ends_with_bracket() {
        let ph = placeholder_for("email", "user@example.com");
        assert!(
            ph.ends_with(']'),
            "Placeholder must end with ], got: {ph}"
        );
    }

    #[test]
    fn placeholder_contains_class_uppercase() {
        let ph = placeholder_for("aws_access_key", "AKIAIOSFODNN7EXAMPLE");
        assert!(
            ph.contains("AWS_ACCESS_KEY"),
            "Placeholder must contain uppercase class name, got: {ph}"
        );
    }

    #[test]
    fn placeholder_contains_hash16() {
        let ph = placeholder_for("email", "user@example.com");
        // Format: [REDACTED:EMAIL:xxxxxxxxxxxxxxxx] where the suffix is 16 hex chars (64-bit)
        let parts: Vec<&str> = ph.trim_matches(|c| c == '[' || c == ']').split(':').collect();
        assert_eq!(parts.len(), 3, "Placeholder must have 3 colon-separated parts: {ph}");
        assert_eq!(parts[2].len(), 16, "Hash suffix must be 16 chars, got: {}", parts[2]);
    }

    #[test]
    fn same_value_same_placeholder() {
        let ph1 = placeholder_for("email", "test@example.com");
        let ph2 = placeholder_for("email", "test@example.com");
        assert_eq!(ph1, ph2, "Same input must produce same placeholder (deterministic)");
    }

    #[test]
    fn different_values_different_placeholders() {
        let ph1 = placeholder_for("email", "a@example.com");
        let ph2 = placeholder_for("email", "b@example.com");
        assert_ne!(ph1, ph2, "Different values must produce different placeholders");
    }
}

#[cfg(test)]
mod redaction_tests {
    use crate::vault::redaction::{apply_redaction, restore_content};
    use secureprompt_common::types::{Detection, TokenVault};
    use std::collections::HashMap;

    fn make_detection(class: &str, value: &str, start: usize, end: usize) -> Detection {
        Detection {
            class: class.to_owned(),
            confidence: 0.99,
            span: Some((start, end)),
            value: value.to_owned(),
        }
    }

    // ---- new placeholder format -----------------------------------------

    #[test]
    fn apply_redaction_replaces_detected_value() {
        let content = "My email is user@example.com and it's mine.";
        let email_start = content.find("user@example.com").unwrap();
        let email_end = email_start + "user@example.com".len();
        let detections = vec![make_detection(
            "EMAIL_ADDRESS",
            "user@example.com",
            email_start,
            email_end,
        )];

        let mut vault = TokenVault::default();
        let mut map = HashMap::new();
        let redacted = apply_redaction(content, &detections, &mut vault, &mut map);

        assert!(
            !redacted.contains("user@example.com"),
            "Original value must not appear in redacted output: {redacted}"
        );
        assert!(
            redacted.contains("{{Email_Address_1}}"),
            "Indexed placeholder must appear in redacted output: {redacted}"
        );
    }

    #[test]
    fn vault_stores_mapping_in_memory_only() {
        let content = "key: AKIAIOSFODNN7EXAMPLE";
        let key_start = content.find("AKIAIOSFODNN7EXAMPLE").unwrap();
        let key_end = key_start + "AKIAIOSFODNN7EXAMPLE".len();
        let detections = vec![make_detection(
            "AWS_ACCESS_KEY",
            "AKIAIOSFODNN7EXAMPLE",
            key_start,
            key_end,
        )];

        let mut vault = TokenVault::default();
        let mut map = HashMap::new();
        let _ = apply_redaction(content, &detections, &mut vault, &mut map);

        assert!(!vault.is_empty(), "Vault must contain the placeholder mapping");
        assert_eq!(map.len(), 1, "redaction_map must have exactly 1 entry");
    }

    #[test]
    fn restore_recovers_original_value() {
        let content = "My email is user@example.com and it's mine.";
        let email_start = content.find("user@example.com").unwrap();
        let email_end = email_start + "user@example.com".len();
        let detections = vec![make_detection(
            "EMAIL_ADDRESS",
            "user@example.com",
            email_start,
            email_end,
        )];

        let mut vault = TokenVault::default();
        let mut map = HashMap::new();
        let redacted = apply_redaction(content, &detections, &mut vault, &mut map);
        let restored = restore_content(&redacted, &vault);

        assert_eq!(restored, content, "Restored content must match original");
    }

    #[test]
    fn unresolved_placeholder_stays_redacted() {
        let vault = TokenVault::default();
        let redacted_content = "Contact {{Email_Address_1}} please.";
        let restored = restore_content(redacted_content, &vault);
        assert!(
            restored.contains("{{Email_Address_1}}"),
            "Unresolved placeholder must stay in redacted form: {restored}"
        );
    }

    #[test]
    fn multiple_detections_all_redacted() {
        let content = "Email: a@test.com and b@test.com";
        let a_start = content.find("a@test.com").unwrap();
        let a_end = a_start + "a@test.com".len();
        let b_start = content.find("b@test.com").unwrap();
        let b_end = b_start + "b@test.com".len();

        let detections = vec![
            make_detection("EMAIL_ADDRESS", "a@test.com", a_start, a_end),
            make_detection("EMAIL_ADDRESS", "b@test.com", b_start, b_end),
        ];

        let mut vault = TokenVault::default();
        let mut map = HashMap::new();
        let redacted = apply_redaction(content, &detections, &mut vault, &mut map);

        assert!(!redacted.contains("a@test.com"), "First email must be redacted");
        assert!(!redacted.contains("b@test.com"), "Second email must be redacted");
        assert!(redacted.contains("{{Email_Address_1}}"));
        assert!(redacted.contains("{{Email_Address_2}}"));
        assert_eq!(vault.len(), 2, "Vault must have 2 entries");
    }

    // ---- new indexed-identity behavior ----------------------------------

    #[test]
    fn repeated_value_keeps_same_index_within_call() {
        // "Shohjahon Karimberganov" appears twice → both become {{Person_1}}.
        let name = "Shohjahon Karimberganov";
        let content = "First mention: Shohjahon Karimberganov. Later: Shohjahon Karimberganov.";
        let (a_start, b_start) = {
            let first = content.find(name).unwrap();
            let second = content.rfind(name).unwrap();
            assert_ne!(first, second, "test setup: two distinct spans required");
            (first, second)
        };

        let detections = vec![
            make_detection("PERSON", name, a_start, a_start + name.len()),
            make_detection("PERSON", name, b_start, b_start + name.len()),
        ];

        let mut vault = TokenVault::default();
        let mut map = HashMap::new();
        let redacted = apply_redaction(content, &detections, &mut vault, &mut map);

        assert!(
            redacted.contains("{{Person_1}}"),
            "First person mention should become {{Person_1}}: {redacted}"
        );
        assert!(
            !redacted.contains("{{Person_2}}"),
            "Repeated identical person should NOT create {{Person_2}}: {redacted}"
        );
        assert_eq!(
            redacted.matches("{{Person_1}}").count(),
            2,
            "Same identity must produce the same placeholder twice: {redacted}"
        );
        assert_eq!(vault.len(), 1, "Vault should dedupe by (class, value)");
    }

    #[test]
    fn different_values_increment_index_per_class() {
        // Shohjahon → {{Person_1}}, Ali Aliev → {{Person_2}}, Shohjahon again → {{Person_1}}.
        let content = "Meeting: Shohjahon Karimberganov, Ali Aliev, and again Shohjahon Karimberganov.";
        let s1 = content.find("Shohjahon Karimberganov").unwrap();
        let ali = content.find("Ali Aliev").unwrap();
        let s2 = content.rfind("Shohjahon Karimberganov").unwrap();

        let detections = vec![
            make_detection("PERSON", "Shohjahon Karimberganov", s1, s1 + "Shohjahon Karimberganov".len()),
            make_detection("PERSON", "Ali Aliev", ali, ali + "Ali Aliev".len()),
            make_detection("PERSON", "Shohjahon Karimberganov", s2, s2 + "Shohjahon Karimberganov".len()),
        ];

        let mut vault = TokenVault::default();
        let mut map = HashMap::new();
        let redacted = apply_redaction(content, &detections, &mut vault, &mut map);

        // Order of appearance drives the counter; first distinct person → _1, second → _2.
        assert!(redacted.contains("{{Person_1}}"));
        assert!(redacted.contains("{{Person_2}}"));
        assert_eq!(
            redacted.matches("{{Person_1}}").count(),
            2,
            "Shohjahon should map to the same token both times: {redacted}"
        );
        assert_eq!(
            redacted.matches("{{Person_2}}").count(),
            1,
            "Ali should map to a single {{Person_2}}: {redacted}"
        );
        assert_eq!(vault.len(), 2, "Vault dedups repeated identity");

        // Restoring must put both originals back verbatim.
        let restored = restore_content(&redacted, &vault);
        assert_eq!(restored, content);
    }

    #[test]
    fn counters_are_per_class() {
        // A person and an email should each start at _1.
        let content = "Hi Bob, email me at bob@example.com.";
        let bob_s = content.find("Bob").unwrap();
        let email_s = content.find("bob@example.com").unwrap();
        let detections = vec![
            make_detection("PERSON", "Bob", bob_s, bob_s + "Bob".len()),
            make_detection(
                "EMAIL_ADDRESS",
                "bob@example.com",
                email_s,
                email_s + "bob@example.com".len(),
            ),
        ];

        let mut vault = TokenVault::default();
        let mut map = HashMap::new();
        let redacted = apply_redaction(content, &detections, &mut vault, &mut map);

        assert!(redacted.contains("{{Person_1}}"), "{redacted}");
        assert!(redacted.contains("{{Email_Address_1}}"), "{redacted}");
    }

    #[test]
    fn overlapping_detections_are_skipped_safely() {
        let content = "AKIAIOSFODNN7EXAMPLE";
        let detections = vec![
            make_detection("AWS_ACCESS_KEY", content, 0, content.len()),
            make_detection(
                "AWS_ACCESS_KEY_OVERLAP",
                &content[2..],
                2,
                content.len(),
            ),
        ];

        let mut vault = TokenVault::default();
        let mut map = HashMap::new();
        let redacted = apply_redaction(content, &detections, &mut vault, &mut map);
        assert!(
            !redacted.contains("AKIAIOSFODNN7EXAMPLE"),
            "Value must be redacted: {redacted}"
        );
    }
}

#[cfg(test)]
mod transform_tests {
    use crate::vault::redaction::apply_transform;
    use secureprompt_common::types::Detection;

    fn make_detection(class: &str, value: &str, start: usize, end: usize) -> Detection {
        Detection {
            class: class.to_owned(),
            confidence: 0.99,
            span: Some((start, end)),
            value: value.to_owned(),
        }
    }

    #[test]
    fn transform_applies_last4_template() {
        let content = "SSN: 123-45-6789";
        let ssn_start = content.find("123-45-6789").unwrap();
        let ssn_end = ssn_start + "123-45-6789".len();
        let detections = vec![make_detection("ssn", "123-45-6789", ssn_start, ssn_end)];

        let transformed = apply_transform(content, &detections, "***-**-{value[-4:]}");

        assert!(
            transformed.contains("6789"),
            "Last 4 chars of SSN must be preserved: {transformed}"
        );
        assert!(
            !transformed.contains("123-45"),
            "First 6 chars of SSN must be masked: {transformed}"
        );
    }

    #[test]
    fn transform_applies_value_template() {
        let content = "secret: mysecretvalue";
        let val_start = content.find("mysecretvalue").unwrap();
        let val_end = val_start + "mysecretvalue".len();
        let detections = vec![make_detection("generic", "mysecretvalue", val_start, val_end)];

        let transformed = apply_transform(content, &detections, "MASKED:{value}");

        assert!(
            transformed.contains("MASKED:mysecretvalue"),
            "Template substitution must work: {transformed}"
        );
    }
}
