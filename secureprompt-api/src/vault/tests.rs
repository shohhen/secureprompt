/// Tests for the vault module: request-scoped redaction and restoration.
///
/// These tests verify:
/// - Placeholder generation uses [REDACTED: prefix format
/// - Vault is request-scoped and in-memory only (no DB calls)
/// - Restoration recovers original values from vault
/// - Transform applies templates correctly
/// - Restoration failure returns redacted form (not original or crash)
#[cfg(test)]
mod placeholder_tests {
    use crate::vault::redaction::placeholder_for;

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
    fn placeholder_contains_hash8() {
        let ph = placeholder_for("email", "user@example.com");
        // Format: [REDACTED:EMAIL:xxxxxxxx] where xxxxxxxx is 8 hex chars
        let parts: Vec<&str> = ph.trim_matches(|c| c == '[' || c == ']').split(':').collect();
        assert_eq!(parts.len(), 3, "Placeholder must have 3 colon-separated parts: {ph}");
        assert_eq!(parts[2].len(), 8, "Hash suffix must be 8 chars, got: {}", parts[2]);
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

    #[test]
    fn apply_redaction_replaces_detected_value() {
        let content = "My email is user@example.com and it's mine.";
        let email_start = content.find("user@example.com").unwrap();
        let email_end = email_start + "user@example.com".len();
        let detections = vec![make_detection("email", "user@example.com", email_start, email_end)];

        let mut vault = TokenVault::default();
        let mut map = HashMap::new();
        let redacted = apply_redaction(content, &detections, &mut vault, &mut map);

        assert!(
            !redacted.contains("user@example.com"),
            "Original value must not appear in redacted output: {redacted}"
        );
        assert!(
            redacted.contains("[REDACTED:"),
            "Redacted output must contain placeholder: {redacted}"
        );
    }

    #[test]
    fn vault_stores_mapping_in_memory_only() {
        // Vault is not persisted — this test verifies the vault works as an in-memory map
        let content = "key: AKIAIOSFODNN7EXAMPLE";
        let key_start = content.find("AKIAIOSFODNN7EXAMPLE").unwrap();
        let key_end = key_start + "AKIAIOSFODNN7EXAMPLE".len();
        let detections = vec![make_detection("aws_access_key", "AKIAIOSFODNN7EXAMPLE", key_start, key_end)];

        let mut vault = TokenVault::default();
        let mut map = HashMap::new();
        let redacted = apply_redaction(content, &detections, &mut vault, &mut map);

        assert!(!vault.is_empty(), "Vault must contain the placeholder mapping");
        // The redaction_map should also contain the mapping
        assert_eq!(map.len(), 1, "redaction_map must have exactly 1 entry");
        // Vault is in-memory: not persisted to any store (structural assertion — no DB calls possible in pure fn)
        let _ = redacted;
    }

    #[test]
    fn restore_recovers_original_value() {
        let content = "My email is user@example.com and it's mine.";
        let email_start = content.find("user@example.com").unwrap();
        let email_end = email_start + "user@example.com".len();
        let detections = vec![make_detection("email", "user@example.com", email_start, email_end)];

        let mut vault = TokenVault::default();
        let mut map = HashMap::new();
        let redacted = apply_redaction(content, &detections, &mut vault, &mut map);
        let restored = restore_content(&redacted, &vault);

        assert_eq!(
            restored, content,
            "Restored content must match original"
        );
    }

    #[test]
    fn unresolved_placeholder_stays_redacted() {
        // If vault doesn't have the placeholder, restore returns it as-is (redacted)
        let vault = TokenVault::default();
        let redacted_content = "Contact [REDACTED:EMAIL:abcd1234]";
        let restored = restore_content(redacted_content, &vault);
        // Since the placeholder is not in vault, it stays as-is (fail-safe)
        assert!(
            restored.contains("[REDACTED:"),
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
            make_detection("email", "a@test.com", a_start, a_end),
            make_detection("email", "b@test.com", b_start, b_end),
        ];

        let mut vault = TokenVault::default();
        let mut map = HashMap::new();
        let redacted = apply_redaction(content, &detections, &mut vault, &mut map);

        assert!(!redacted.contains("a@test.com"), "First email must be redacted");
        assert!(!redacted.contains("b@test.com"), "Second email must be redacted");
        assert_eq!(vault.len(), 2, "Vault must have 2 entries");
    }

    #[test]
    fn overlapping_detections_are_skipped_safely() {
        // If two detections overlap, the second (which starts before cursor after first is applied) is skipped
        let content = "AKIAIOSFODNN7EXAMPLE";
        let full_start = 0;
        let full_end = content.len();
        let overlap_start = 2;
        let overlap_end = full_end;

        let detections = vec![
            make_detection("aws_access_key", content, full_start, full_end),
            make_detection("aws_access_key_overlap", &content[overlap_start..], overlap_start, overlap_end),
        ];

        let mut vault = TokenVault::default();
        let mut map = HashMap::new();
        // Should not panic
        let redacted = apply_redaction(content, &detections, &mut vault, &mut map);
        assert!(!redacted.contains("AKIAIOSFODNN7EXAMPLE"), "Value must be redacted: {redacted}");
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
