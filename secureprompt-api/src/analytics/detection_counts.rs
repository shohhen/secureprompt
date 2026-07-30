//! WS3-6 — turning a request's detections into the per-class counts the
//! shadow-mode leak report aggregates.
//!
//! # Why this is not a one-line `HashMap` fold
//!
//! The whole justification for `detection_class_counts` existing WITHOUT the
//! WS3-1 capture opt-in gate is that it stores a class name and an integer,
//! and a class name is a TYPE, not a VALUE. `PINFL` says a prompt contained a
//! national identifier; it does not say whose.
//!
//! That claim is only true if the strings reaching the column are bounded.
//! They are not, by default:
//!
//! * The deterministic Rust floor's classes are `&'static str` literals in
//!   `detection::registry` — those are fine by construction.
//! * The ML sidecar's are not. `MlDetection::entity_type` is a `String`
//!   deserialised from the sidecar's JSON response
//!   (`ml_sidecar/types.rs`), and `merge_detections` only uppercases it. A
//!   retrained model with a new label, a misconfigured sidecar, or a
//!   compromised one can put ARBITRARY BYTES in that field, and a naive fold
//!   would write them straight into a table this product advertises as
//!   content-free — and then into a compliance report, and then into a bank's
//!   PDF.
//!
//! So every class is mapped through [`CANONICAL_CLASSES`] and anything else
//! becomes the literal [`OTHER`]. The set of strings the column can hold is
//! therefore exactly `CANONICAL_CLASSES ∪ {"other"}`, all of them string
//! literals in this binary. That is what makes "no opt-in gate needed"
//! a property of the code rather than a hope about the model.
//!
//! Bucketing rather than dropping is deliberate: an unrecognised label is
//! still a detection, and a report whose total silently excluded it would
//! under-state the leak. `other` is also the signal to extend the list.
//!
//! # What a "count" counts
//!
//! DISTINCT `(class, value)` pairs, not raw detections. The merged detection
//! set routinely contains the same entity twice — the case-augmented pass and
//! the Uzbek brand gazetteer both firing on one span, a subsuming ML span kept
//! alongside the floor detection it covers — and `apply_redaction` collapses
//! those to a single placeholder. Counting distinct pairs makes this agree
//! with what the tokenize endpoint reports in `entity_counts` and with the
//! number of placeholders a reader would actually see.
//!
//! The values are used as map keys inside this function and dropped when it
//! returns. Nothing derived from them is stored.

use secureprompt_common::types::Detection;
use std::collections::{BTreeMap, BTreeSet};

/// The bucket for any class name this binary does not recognise.
///
/// Lowercase on purpose: every canonical class is UPPERCASE (they arrive
/// through `detection::merge::normalize_class`, which uppercases), so `other`
/// can never collide with a real class name.
pub const OTHER: &str = "other";

/// Every class name that may be written to `detection_class_counts`.
///
/// Two origins, deliberately in one list because the column does not
/// distinguish them:
///
/// * The deterministic Rust floor (`detection::registry`), uppercased by
///   `merge::normalize_class`. `tests::every_floor_class_is_canonical` derives
///   the expected set from the registry itself, so adding a recogniser without
///   adding it here reddens rather than silently bucketing to `other`.
/// * The ML sidecar's label set (`secureprompt-ml/app/detection/xlmr_ner.py`,
///   `_V2_RAW_LABELS`) plus the Presidio-canonical forms `_LABEL_SYNONYMS`
///   maps them to. That file is in another language in another process, so
///   this half CANNOT be derived by a Rust test — it is a transcription, and
///   a model that gains a label ships it as `other` until someone adds it.
///   Stated plainly rather than implied: this is the list's weak half.
pub const CANONICAL_CLASSES: &[&str] = &[
    // ── Rust floor: credentials and secrets ──────────────────────────────
    "ANTHROPIC_API_KEY",
    "API_TOKEN_GENERIC",
    "AWS_ACCESS_KEY",
    "AZURE_STORAGE_CONNECTION_STRING",
    "BASIC_AUTH_HEADER",
    "BEARER_TOKEN",
    "GCP_SERVICE_ACCOUNT_EMAIL",
    "GITHUB_FINE_GRAINED_PAT",
    "GITHUB_OAUTH_TOKEN",
    "GITHUB_PAT",
    "GITHUB_REFRESH_TOKEN",
    "GOOGLE_API_KEY",
    "JWT",
    "MONGODB_URI",
    "OAUTH_CLIENT_SECRET",
    "OPENAI_API_KEY",
    "OPENSSH_PRIVATE_KEY",
    "PASSWORD_ASSIGNMENT",
    "POSTGRESQL_URI",
    "PRIVATE_KEY_PEM",
    "RSA_PRIVATE_KEY",
    "SLACK_APP_TOKEN",
    "SLACK_BOT_TOKEN",
    "SLACK_USER_TOKEN",
    "STRIPE_PUBLISHABLE_KEY",
    "STRIPE_SECRET_KEY",
    "WEBHOOK_URL",
    // ── Rust floor: identifiers, incl. the Uzbek/CIS set from WS2-1 ──────
    "CREDIT_CARD",
    "EMAIL_ADDRESS",
    "HUMO",
    "IBAN",
    "MFO",
    "PASSPORT_NUMBER",
    "PHONE_NUMBER",
    "PINFL",
    "SSN",
    "STIR",
    "UZCARD",
    // ── ML sidecar: v2 label set ─────────────────────────────────────────
    "ADDRESS",
    "BANK_ACCOUNT_NUMBER",
    "BIRTH_CERTIFICATE_NUMBER",
    "BLOOD_TYPE",
    "CNPJ",
    "CPF",
    "CREDIT_AGREEMENT_ID",
    "CREDIT_CARD_BRAND",
    "CREDIT_CARD_EXPIRATION_DATE",
    "CREDIT_CARD_NUMBER",
    "CVV",
    "DATE_OF_BIRTH",
    "DRIVERS_LICENSE_NUMBER",
    "FLIGHT_NUMBER",
    "HEALTH_INSURANCE_NUMBER",
    "IDENTITY_CARD_NUMBER",
    "INSURANCE_COMPANY",
    "INSURANCE_NUMBER",
    "IP_ADDRESS",
    "LICENSE_PLATE_NUMBER",
    "LOAN_AMOUNT",
    "MEDICAL_CONDITION",
    "MEDICATION",
    "NATIONAL_HEALTH_INSURANCE_NUMBER",
    "ORGANIZATION",
    "PASSPORT_EXPIRATION_DATE",
    "PERSON",
    "POSTAL_CODE",
    "REGISTRATION_NUMBER",
    "RESERVATION_NUMBER",
    "SALARY",
    "SERIAL_NUMBER",
    "SOCIAL_SECURITY_NUMBER",
    "STUDENT_ID_NUMBER",
    "TAX_IDENTIFICATION_NUMBER",
    "TRAIN_TICKET_NUMBER",
    "TRANSACTION_NUMBER",
    "USERNAME",
    "VEHICLE_REGISTRATION_NUMBER",
    "VISA_NUMBER",
    // ── ML sidecar: Presidio-canonical forms `_LABEL_SYNONYMS` maps to ───
    "DATE_TIME",
    "IBAN_CODE",
    "US_DRIVER_LICENSE",
    "US_SSN",
    // ── Presidio built-ins the compliance map names ──────────────────────
    "AZURE_KEY",
    "GCP_KEY",
    "GPE",
    "LOCATION",
    "MEDICAL_LICENSE",
];

/// The canonical form of `class`, or [`OTHER`].
///
/// Matching is case-insensitive because the two producers disagree: the floor
/// registry declares lowercase literals and `merge::normalize_class`
/// uppercases them, but the tokenize path feeds ML detections to redaction
/// without passing through the merge. Normalising here means the counts do not
/// depend on which of those ran.
#[must_use]
pub fn canonicalize(class: &str) -> &'static str {
    let upper = class.to_uppercase();
    CANONICAL_CLASSES
        .iter()
        .find(|known| **known == upper)
        .copied()
        .unwrap_or(OTHER)
}

/// Per-class counts of DISTINCT `(class, value)` pairs in `detections`.
///
/// `BTreeMap` rather than `HashMap` so the rows a request writes are in a
/// stable order — an insert order that varies run to run makes a ClickHouse
/// part diff unreadable and makes tests order-dependent for no benefit.
#[must_use]
pub fn per_class(detections: &[Detection]) -> BTreeMap<&'static str, u32> {
    let mut seen: BTreeSet<(&'static str, &str)> = BTreeSet::new();
    let mut counts: BTreeMap<&'static str, u32> = BTreeMap::new();
    for detection in detections {
        let class = canonicalize(&detection.class);
        if seen.insert((class, detection.value.as_str())) {
            *counts.entry(class).or_default() += 1;
        }
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detection(class: &str, value: &str) -> Detection {
        Detection {
            class: class.to_owned(),
            confidence: 0.9,
            span: None,
            value: value.to_owned(),
        }
    }

    /// Every class the deterministic floor can emit must be canonical, so a
    /// new recogniser cannot land silently bucketed as `other`.
    ///
    /// The expected set is derived from `registry.rs` itself rather than
    /// restated, so this cannot drift.
    #[test]
    fn every_floor_class_is_canonical() {
        const REGISTRY: &str = include_str!("../detection/registry.rs");
        let declared: Vec<String> = REGISTRY
            .lines()
            .filter_map(|line| {
                let rest = line.trim().strip_prefix("class: \"")?;
                let name = rest.split('"').next()?;
                (!name.is_empty()).then(|| name.to_owned())
            })
            .collect();
        assert!(
            declared.len() >= 30,
            "premise failed: only {} classes extracted from registry.rs — the \
             scrape is broken, so this test proves nothing",
            declared.len()
        );

        // `merge::normalize_class` rewrites these two before anything sees
        // them, so the registry's spelling is not what reaches the column.
        let synonyms = |c: &str| match c {
            "PHONE" => "PHONE_NUMBER".to_owned(),
            "EMAIL" => "EMAIL_ADDRESS".to_owned(),
            other => other.to_owned(),
        };
        let missing: Vec<String> = declared
            .iter()
            .map(|c| synonyms(&c.to_uppercase()))
            .filter(|c| canonicalize(c) == OTHER)
            .collect();
        assert!(
            missing.is_empty(),
            "these detection classes exist in registry.rs but are not in \
             CANONICAL_CLASSES, so the leak report would bucket them as \
             `other`: {missing:?}"
        );
    }

    /// The property the migration's "no opt-in gate needed" argument rests on.
    #[test]
    fn a_class_name_carrying_a_value_is_bucketed() {
        assert_eq!(canonicalize("PERSON_Anvar_Karimov_30107030010011"), OTHER);
        assert_eq!(canonicalize("30107030010011"), OTHER);
        assert_eq!(canonicalize("anvar.karimov@example.uz"), OTHER);
        // Positive control: a real class must NOT be bucketed, or the
        // assertions above would hold for a function that returned `other`
        // unconditionally.
        assert_eq!(canonicalize("PERSON"), "PERSON");
        assert_eq!(canonicalize("pinfl"), "PINFL");
    }

    #[test]
    fn distinct_values_are_counted_once_each() {
        let counts = per_class(&[
            detection("PERSON", "Anvar Karimov"),
            detection("PERSON", "Dilnoza Rashidova"),
            // Same entity found twice (floor + ML overlap) — one placeholder,
            // one count.
            detection("PERSON", "Anvar Karimov"),
            detection("EMAIL_ADDRESS", "anvar.karimov@example.uz"),
        ]);
        assert_eq!(
            counts,
            BTreeMap::from([("PERSON", 2_u32), ("EMAIL_ADDRESS", 1)])
        );
    }

    #[test]
    fn unrecognised_classes_are_counted_under_other_not_dropped() {
        let counts = per_class(&[
            detection("SOMETHING_NEW", "a"),
            detection("SOMETHING_ELSE", "b"),
            detection("PERSON", "c"),
        ]);
        assert_eq!(counts, BTreeMap::from([("other", 2_u32), ("PERSON", 1)]));
    }

    #[test]
    fn no_detections_means_no_rows() {
        assert!(per_class(&[]).is_empty());
    }
}
