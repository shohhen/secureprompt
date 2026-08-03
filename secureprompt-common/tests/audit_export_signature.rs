//! WS4-1 / Task 19 — what the `audit.export` signature has to survive.
//!
//! This suite is the reason the export is a CONTROL rather than a feature. A
//! bank auditor holds N page files, a manifest and a public key, and nothing
//! else — no database, no gateway, no vendor. Every test below is written from
//! that position: it only ever touches bytes the auditor would have.
//!
//! The attack the design is aimed at is **a row removed from the middle of a
//! paginated export**, and its two relatives — a whole page dropped, and a
//! page from a different export spliced in. A per-page signature does not stop
//! any of them: each surviving page still verifies on its own. So the signed
//! object is a MANIFEST that carries a per-page SHA-256 and a hash CHAIN over
//! those digests in order, seeded from the export's own header. Every test
//! here corresponds to one link in that argument.
//!
//! # FU1: a second class of attacker
//!
//! Since schema version 2 an export carries two planes — the ClickHouse
//! request log and the Postgres control-plane audit trail — as two sections of
//! one chain. That adds an attack the earlier tests do not reach, because the
//! attacker is the party who HOLDS THE SIGNING KEY: the gateway operator can
//! hand over an export with the control-plane section removed and RE-SIGN the
//! shorter manifest, and every signature check then passes. [`resign`] is that
//! attacker, and the four tests that use it —
//! `an_export_with_the_control_plane_removed_fails_verification`,
//! `a_page_relabelled_into_the_other_section_fails_verification`,
//! `a_moved_section_boundary_fails_verification` and
//! `a_section_row_count_that_its_pages_do_not_sum_to_fails_verification` —
//! measure the STRUCTURAL checks, the only ones that can catch them.

use secureprompt_common::audit_export::{
    build_manifest, control_section, no_expiry_for, render_page, request_section, retention_for,
    verify_export, AuditRow, ControlRow, ExportFormat, SourceRetention, VerifyError,
    CONTROL_SOURCE_TABLES, EVENT_RAW_CAPTURE_CHANGED, EVENT_SESSION_REVOKED, SECTION_CONTROL_PLANE,
};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, TimeZone, Utc};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use uuid::Uuid;

// ── Fixtures ──────────────────────────────────────────────────────────────
//
// Constraint 5: no real PII. Every value below is either a nil-ish UUID, a
// documentation-range address (RFC 5737 / RFC 3849) or an obviously synthetic
// label.

fn key_a() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn key_b() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

fn ws() -> Uuid {
    Uuid::from_u128(0x0000_0000_0000_0000_0000_0000_0000_00aa)
}

/// `n` minutes past a fixed base instant. Deliberately an OFFSET rather than
/// `with_ymd_and_hms(.., minute, ..)`: the foreign-export fixture below uses
/// row indices past 59, and a literal minute field panics with "No such local
/// time" there.
fn at(n: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap() + chrono::Duration::minutes(i64::from(n))
}

fn row(n: u32) -> AuditRow {
    AuditRow {
        request_id: Uuid::from_u128(u128::from(n)),
        workspace_id: ws(),
        created_at: at(n),
        provider: "openai".into(),
        model: "gpt-4o-mini".into(),
        final_action: "allow".into(),
        input_tokens: Some(10 + n),
        output_tokens: Some(20 + n),
        estimated_usage: false,
        cost_usd: 0.001 * f64::from(n),
        user_id: None,
        api_key_id: None,
        api_key_name: Some(format!("synthetic-key-{n}")),
        ip_address: Some("198.51.100.7".into()),
        user_agent: Some("synthetic-agent/1.0".into()),
        floor_only: false,
        engines: vec!["floor".into()],
    }
}

/// One synthetic control-plane row. `n` picks the event type so the fixture
/// exercises more than one shape of `detail`.
fn control(n: u32) -> ControlRow {
    if n % 2 == 0 {
        ControlRow {
            event_id: Uuid::from_u128(0x1000 + u128::from(n)),
            workspace_id: ws(),
            occurred_at: at(n),
            event_type: EVENT_SESSION_REVOKED.into(),
            source_table: "session_revocation_audit".into(),
            actor_user_id: Some(Uuid::from_u128(0x2000 + u128::from(n))),
            actor_email: Some("synthetic-admin@example.invalid".into()),
            actor_role: Some("admin".into()),
            target_user_id: Some(Uuid::from_u128(0x3000 + u128::from(n))),
            target_email: Some("synthetic-target@example.invalid".into()),
            target_role: Some("member".into()),
            detail: serde_json::json!({
                "revoked_before_unix": 1_780_000_000_i64 + i64::from(n),
                "refresh_tokens_revoked": n,
            }),
        }
    } else {
        ControlRow {
            event_id: Uuid::from_u128(0x1000 + u128::from(n)),
            workspace_id: ws(),
            occurred_at: at(n),
            event_type: EVENT_RAW_CAPTURE_CHANGED.into(),
            source_table: "raw_capture_audit".into(),
            actor_user_id: Some(Uuid::from_u128(0x2000 + u128::from(n))),
            actor_email: Some("synthetic-admin@example.invalid".into()),
            actor_role: None,
            target_user_id: None,
            target_email: None,
            target_role: None,
            detail: serde_json::json!({
                "enabled_before": false,
                "enabled_after": true,
                "retention_days_before": 30,
                "retention_days_after": 7,
            }),
        }
    }
}

fn control_sources() -> Vec<SourceRetention> {
    CONTROL_SOURCE_TABLES
        .iter()
        .map(|t| no_expiry_for(t))
        .collect()
}

/// Four pages: two data-plane pages of two rows, then two control-plane pages
/// of one row.
///
/// The smallest shape in which every case this suite has to separate is
/// distinct: "a row removed from the MIDDLE" (page 2) is not "the export was
/// truncated"; a page dropped from the control plane (page 3) is not a page
/// dropped from the data plane; and the section boundary falls between pages 2
/// and 3, so a chain that did not span it would be caught.
fn pages_of(format: ExportFormat) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let data = (0..2)
        .map(|p| {
            let rows: Vec<AuditRow> = (0..2).map(|i| row(p * 2 + i)).collect();
            render_page(&rows, format)
        })
        .collect();
    let control = (0..2).map(|p| render_page(&[control(p)], format)).collect();
    (data, control)
}

struct Export {
    manifest_json: String,
    signature_b64: String,
    public_key_b64: String,
    pages: Vec<Vec<u8>>,
}

fn export(format: ExportFormat, key: &SigningKey) -> Export {
    let (data, control) = pages_of(format);
    let signed = build_manifest(
        Uuid::from_u128(0xfeed),
        ws(),
        at(0),
        at(59),
        format,
        2,
        &[
            request_section(
                data.clone(),
                vec![2, 2],
                vec![retention_for(at(0), at(59), at(59))],
            ),
            control_section(control.clone(), vec![1, 1], control_sources()),
        ],
        at(59),
        key,
    )
    .expect("manifest");
    let mut pages = data;
    pages.extend(control);
    Export {
        manifest_json: signed.manifest_json,
        signature_b64: signed.signature_b64,
        public_key_b64: signed.public_key_b64,
        pages,
    }
}

fn check(e: &Export) -> Result<(), VerifyError> {
    let refs: Vec<&[u8]> = e.pages.iter().map(Vec::as_slice).collect();
    verify_export(&e.manifest_json, &e.signature_b64, &e.public_key_b64, &refs).map(|_| ())
}

/// Re-serialise a mutated manifest and re-sign it with `key`.
///
/// This is the attacker who HOLDS THE SIGNING KEY — the gateway operator, the
/// party an auditor is checking. Every test that uses it is asking whether a
/// structural check catches something the signature cannot, because the
/// signature over a re-signed document is valid by construction.
fn resign(manifest: &serde_json::Value, key: &SigningKey) -> (String, String) {
    let json = serde_json::to_string(manifest).expect("manifest json");
    let signature = key.sign(json.as_bytes());
    (json, B64.encode(signature.to_bytes()))
}

// ── The positive control ──────────────────────────────────────────────────

/// Constraint 2: a positive control that MUST differ from every negative
/// below. If this ever fails, none of the tamper tests below prove anything —
/// they would be passing because verification rejects everything.
#[test]
fn an_untampered_export_verifies_in_both_formats() {
    for format in [ExportFormat::Csv, ExportFormat::Jsonl] {
        let e = export(format, &key_a());
        assert_eq!(
            check(&e),
            Ok(()),
            "an untouched {} export must verify",
            format.as_str()
        );
    }
}

// ── The attack this design exists for ─────────────────────────────────────

/// A row removed from the MIDDLE page. The page still parses, still looks like
/// a page, and every other page is byte-identical to what was signed.
#[test]
fn a_row_removed_from_the_middle_page_fails_verification() {
    for format in [ExportFormat::Csv, ExportFormat::Jsonl] {
        let mut e = export(format, &key_a());

        // Premise assertion (Constraint 2): the middle page really does hold
        // more than one line before we remove one, so "removed a row" is what
        // this test does rather than "emptied the page".
        let before = String::from_utf8(e.pages[1].clone()).expect("utf8");
        let lines: Vec<&str> = before.lines().collect();
        assert!(
            lines.len() >= 2,
            "premise: middle page must carry >= 2 lines to remove one, got {}",
            lines.len()
        );

        let tampered: String = lines[..lines.len() - 1].join("\n") + "\n";
        assert_ne!(tampered, before, "premise: the mutation must change bytes");
        e.pages[1] = tampered.into_bytes();

        assert_eq!(
            check(&e),
            Err(VerifyError::PageDigestMismatch { page: 2 }),
            "{}: a row removed from page 2 must be caught",
            format.as_str()
        );
    }
}

/// A row removed from a CONTROL-PLANE page. Same attack, other plane — the
/// digest chain does not care which store a page came from, and this is the
/// test that says so rather than assuming it.
#[test]
fn a_row_removed_from_a_control_plane_page_fails_verification() {
    for format in [ExportFormat::Csv, ExportFormat::Jsonl] {
        let mut e = export(format, &key_a());

        // Premise: page 3 really is the first control-plane page and really
        // does carry a row.
        let manifest: serde_json::Value = serde_json::from_str(&e.manifest_json).expect("json");
        assert_eq!(
            manifest["pages"][2]["section"].as_str(),
            Some(SECTION_CONTROL_PLANE),
            "premise: page 3 must be a control-plane page"
        );
        assert_eq!(manifest["pages"][2]["rows"].as_u64(), Some(1));

        let before = e.pages[2].clone();
        let text = String::from_utf8(before.clone()).expect("utf8");
        let lines: Vec<&str> = text.lines().collect();
        let tampered: String = lines[..lines.len() - 1].join("\n") + "\n";
        assert_ne!(
            tampered.as_bytes(),
            before.as_slice(),
            "premise: the mutation must change bytes"
        );
        e.pages[2] = tampered.into_bytes();

        assert_eq!(
            check(&e),
            Err(VerifyError::PageDigestMismatch { page: 3 }),
            "{}: an administrative action removed from page 3 must be caught",
            format.as_str()
        );
    }
}

/// A WHOLE page dropped. This is the case a per-page signature cannot catch:
/// the remaining pages are untouched and would each verify individually.
///
/// The signed `total_pages` is what catches it — `PageCountMismatch`, not the
/// chain. Named here because the module header of `audit_export.rs` cites this
/// test, and a reader who takes it as chain evidence will draw the wrong
/// conclusion from a green run.
#[test]
fn a_whole_page_removed_fails_verification() {
    let mut e = export(ExportFormat::Jsonl, &key_a());
    assert_eq!(e.pages.len(), 4, "premise: four pages before removal");
    e.pages.remove(1);
    assert_eq!(
        check(&e),
        Err(VerifyError::PageCountMismatch {
            expected: 4,
            got: 3
        })
    );
}

/// **The whole control plane removed, by someone holding the signing key.**
///
/// This is the failure the gap was: an export that carries only what requests
/// happened, handed over as the audit trail. The signature cannot catch it —
/// the operator re-signs — so `verify_export` refuses any manifest whose
/// section list is not exactly the two this schema version requires. "Nothing
/// was silently omitted" is therefore a CHECK, not a promise in a document.
#[test]
fn an_export_with_the_control_plane_removed_fails_verification() {
    let e = export(ExportFormat::Jsonl, &key_a());
    let mut manifest: serde_json::Value = serde_json::from_str(&e.manifest_json).expect("json");

    // Premise: the genuine export really does declare both planes, so the
    // rejection below is the removal's doing.
    assert_eq!(
        manifest["sections"]
            .as_array()
            .expect("sections")
            .iter()
            .filter_map(|s| s["section"].as_str())
            .collect::<Vec<_>>(),
        vec!["request_events", "control_plane_events"]
    );

    // Drop the control section and its two pages, then rewrite every count so
    // the document is internally consistent — an attacker who does less than
    // this is caught by a check that predates this task.
    manifest["sections"] = serde_json::json!([manifest["sections"][0].clone()]);
    manifest["pages"] =
        serde_json::json!([manifest["pages"][0].clone(), manifest["pages"][1].clone()]);
    manifest["total_pages"] = serde_json::json!(2);
    manifest["total_rows"] = serde_json::json!(4);
    manifest["chain_root"] = manifest["pages"][1]["chain"].clone();

    let (json, signature) = resign(&manifest, &key_a());
    let refs: Vec<&[u8]> = e.pages[..2].iter().map(Vec::as_slice).collect();

    // Positive control: the SAME re-signing machinery, applied to an unaltered
    // manifest, produces something that verifies — so the failure below is the
    // missing section and not a broken re-signature.
    let (honest_json, honest_signature) = resign(
        &serde_json::from_str::<serde_json::Value>(&e.manifest_json).expect("json"),
        &key_a(),
    );
    let all: Vec<&[u8]> = e.pages.iter().map(Vec::as_slice).collect();
    assert!(
        verify_export(&honest_json, &honest_signature, &e.public_key_b64, &all).is_ok(),
        "positive control: a re-signed but unaltered export must still verify"
    );

    assert_eq!(
        verify_export(&json, &signature, &e.public_key_b64, &refs),
        Err(VerifyError::SectionSetUnexpected)
    );
}

/// A page RELABELLED into the other section, again by the key holder. The
/// bytes and the digests are untouched; only the label moved. It is caught
/// because every page's section is cross-checked against the range of the
/// section that owns its number.
#[test]
fn a_page_relabelled_into_the_other_section_fails_verification() {
    let e = export(ExportFormat::Jsonl, &key_a());
    let mut manifest: serde_json::Value = serde_json::from_str(&e.manifest_json).expect("json");
    assert_eq!(
        manifest["pages"][1]["section"].as_str(),
        Some("request_events"),
        "premise: page 2 is a data-plane page before relabelling"
    );
    manifest["pages"][1]["section"] = serde_json::json!(SECTION_CONTROL_PLANE);

    let (json, signature) = resign(&manifest, &key_a());
    let refs: Vec<&[u8]> = e.pages.iter().map(Vec::as_slice).collect();
    assert_eq!(
        verify_export(&json, &signature, &e.public_key_b64, &refs),
        Err(VerifyError::PageSectionMismatch { page: 2 })
    );
}

/// The section BOUNDARY moved, so the control plane appears to start a page
/// later than it does and one of its pages is read as data-plane. Caught as a
/// gap in the partition of `1..=total_pages`.
#[test]
fn a_moved_section_boundary_fails_verification() {
    let e = export(ExportFormat::Jsonl, &key_a());
    let mut manifest: serde_json::Value = serde_json::from_str(&e.manifest_json).expect("json");
    assert_eq!(manifest["sections"][1]["first_page"].as_u64(), Some(3));
    manifest["sections"][1]["first_page"] = serde_json::json!(4);
    manifest["sections"][1]["pages"] = serde_json::json!(1);

    let (json, signature) = resign(&manifest, &key_a());
    let refs: Vec<&[u8]> = e.pages.iter().map(Vec::as_slice).collect();
    assert_eq!(
        verify_export(&json, &signature, &e.public_key_b64, &refs),
        Err(VerifyError::SectionPagesNotContiguous { section_index: 1 })
    );
}

/// A section's declared row count edited to hide a row. `total_rows` still
/// sums, because the attacker moved the row between the two sections' totals;
/// the per-section sum is what catches it.
#[test]
fn a_section_row_count_that_its_pages_do_not_sum_to_fails_verification() {
    let e = export(ExportFormat::Jsonl, &key_a());
    let mut manifest: serde_json::Value = serde_json::from_str(&e.manifest_json).expect("json");
    assert_eq!(manifest["sections"][1]["rows"].as_u64(), Some(2));
    manifest["sections"][1]["rows"] = serde_json::json!(1);
    manifest["sections"][0]["rows"] = serde_json::json!(5);

    let (json, signature) = resign(&manifest, &key_a());
    let refs: Vec<&[u8]> = e.pages.iter().map(Vec::as_slice).collect();
    assert_eq!(
        verify_export(&json, &signature, &e.public_key_b64, &refs),
        Err(VerifyError::SectionRowCountMismatch { section_index: 0 })
    );
}

/// An archived version-1 export — data plane only — is REFUSED by name, not
/// reported as malformed. The distinction matters to the person holding it: a
/// version they need another tool for is not a tampered artifact.
#[test]
fn a_schema_version_1_manifest_is_refused_by_version_not_as_malformed() {
    let e = export(ExportFormat::Jsonl, &key_a());
    let mut manifest: serde_json::Value = serde_json::from_str(&e.manifest_json).expect("json");
    manifest["schema_version"] = serde_json::json!(1);
    // A real v1 manifest also lacks `sections`, which is what would otherwise
    // make this a deserialization failure.
    manifest.as_object_mut().expect("object").remove("sections");

    let (json, signature) = resign(&manifest, &key_a());
    let refs: Vec<&[u8]> = e.pages.iter().map(Vec::as_slice).collect();
    assert_eq!(
        verify_export(&json, &signature, &e.public_key_b64, &refs),
        Err(VerifyError::UnsupportedSchemaVersion { got: 1 })
    );
}

/// Each section states its own retention, and for the same window the two
/// disagree — ClickHouse `request_events` has a 90-day TTL, the three Postgres
/// audit tables have none. An export that reported one verdict would be
/// telling an auditor something false about half of itself.
#[test]
fn each_section_carries_its_own_per_source_retention() {
    let e = export(ExportFormat::Jsonl, &key_a());
    let manifest: serde_json::Value = serde_json::from_str(&e.manifest_json).expect("json");

    let data_sources = manifest["sections"][0]["sources"]
        .as_array()
        .expect("data sources");
    assert_eq!(data_sources.len(), 1);
    assert_eq!(
        data_sources[0]["source_table"].as_str(),
        Some("request_events")
    );
    assert_eq!(data_sources[0]["ttl_days"].as_u64(), Some(90));
    assert!(data_sources[0]["boundary"].is_string());

    let control_sources = manifest["sections"][1]["sources"]
        .as_array()
        .expect("control sources");
    assert_eq!(
        control_sources
            .iter()
            .filter_map(|s| s["source_table"].as_str())
            .collect::<Vec<_>>(),
        CONTROL_SOURCE_TABLES.to_vec(),
        "every control-plane relation must state its own retention"
    );
    for source in control_sources {
        assert!(
            source["ttl_days"].is_null(),
            "a Postgres audit table has no TTL; got {source}"
        );
        assert_eq!(source["window_status"].as_str(), Some("no_expiry"));
    }
}

/// Pages reordered — the case a plain "set of per-page digests" manifest would
/// miss, because the multiset of pages is unchanged.
///
/// What catches it is that the page list is POSITIONAL: `pages[i]` describes
/// the (i+1)th file, so a swap makes both pages fail their own digest. This
/// doc used to credit the chain, and that was wrong: make `chain_step` ignore
/// its `prev` argument, destroying the chain's ordering entirely, and this
/// test stays GREEN. The assertion below is `PageDigestMismatch` and always
/// was.
#[test]
fn pages_reordered_fail_verification() {
    let mut e = export(ExportFormat::Jsonl, &key_a());
    e.pages.swap(0, 2);
    assert!(
        matches!(check(&e), Err(VerifyError::PageDigestMismatch { .. })),
        "a reordered export must not verify"
    );
}

/// A page lifted from a DIFFERENT export of the same shape.
///
/// Caught by the positional digest list: the foreign page's SHA-256 is not the
/// one `pages[1]` publishes, so it fails at page 2. NOT by the genesis seed —
/// this doc used to say the seed was what stopped it, and destroying the chain
/// leaves this test green. The seed's real contribution is that `chain_root`
/// differs between two exports whose PAGES are byte-identical, which is a
/// different property and is pinned by
/// `a_chain_genesis_the_header_does_not_imply_fails_verification`.
#[test]
fn a_page_from_another_export_cannot_be_spliced_in() {
    let e = export(ExportFormat::Jsonl, &key_a());
    let other_pages = (0..2)
        .map(|p| {
            let rows: Vec<AuditRow> = (0..2).map(|i| row(100 + p * 2 + i)).collect();
            render_page(&rows, ExportFormat::Jsonl)
        })
        .collect::<Vec<_>>();
    assert_ne!(
        e.pages[1], other_pages[1],
        "premise: the foreign page must differ"
    );
    let mut spliced = e.pages.clone();
    spliced[1] = other_pages[1].clone();
    let refs: Vec<&[u8]> = spliced.iter().map(Vec::as_slice).collect();
    assert_eq!(
        verify_export(&e.manifest_json, &e.signature_b64, &e.public_key_b64, &refs),
        Err(VerifyError::PageDigestMismatch { page: 2 })
    );
}

// ── The chain itself ──────────────────────────────────────────────────────
//
// MEASURED, and the reason this section exists: with `verify_export`'s genesis
// check, chain-link check, chain-root check and total-rows check ALL FOUR
// deleted, the suite above was 22 unit + 16 integration tests green. Four
// checks of a published verification recipe, and nothing in the repository
// observed their removal.
//
// So be exact about what the chain does and does not do here, because the
// tests above were credited with more than they measure:
//
//   * A page tampered, reordered, or lifted from another export is caught by
//     the POSITIONAL per-page digest list (`PageDigestMismatch`), not by the
//     chain. A whole page dropped is caught by the signed `total_pages`
//     (`PageCountMismatch`), not by the chain. Destroying `chain_step` — making
//     it ignore its `prev` argument entirely — leaves every one of those tests
//     green.
//   * What the chain adds is a SINGLE value, `chain_root`, that commits to the
//     whole ordered digest list and is seeded from this export's own header, so
//     one 32-byte string identifies this export and no other — including
//     another export with byte-identical pages. That is the value an auditor
//     can pin, quote in a report and compare a year later without holding N
//     digests, and it is what `docs/audit-export-format.md`'s recipe has them
//     recompute from the manifest text with nothing but SHA-256.
//
// The four tests below are what make that recipe's steps 6, 7 and 8 executable
// rather than published. Each corrupts exactly ONE field of a re-signed
// manifest — the attacker who holds the signing key, since a signature over a
// re-signed document is valid by construction — and each is caught by exactly
// one check: delete that check and this test, alone, goes red.

/// The re-signing machinery applied to an UNALTERED manifest must still
/// verify.
///
/// Every test in this section mutates one field and re-signs. Without this
/// control a rejection below could be the re-signature rather than the
/// mutation, and all four would be measuring `resign` instead of the verifier.
fn resigning_alone_changes_nothing(e: &Export) {
    let (json, signature) = resign(
        &serde_json::from_str::<serde_json::Value>(&e.manifest_json).expect("json"),
        &key_a(),
    );
    let refs: Vec<&[u8]> = e.pages.iter().map(Vec::as_slice).collect();
    assert!(
        verify_export(&json, &signature, &e.public_key_b64, &refs).is_ok(),
        "positive control: a re-signed but unaltered export must still verify"
    );
}

/// One hex digit of `value` changed.
///
/// The string stays well-formed 64-character hex, so only its VALUE is wrong.
/// Truncating it or putting a non-hex character in would be refused by the
/// parse (`ManifestMalformed`) and would pin nothing about the check under
/// test.
fn flip_one_hex_digit(value: &str) -> String {
    let mut out: Vec<char> = value.chars().collect();
    let last = out.len() - 1;
    out[last] = if out[last] == '0' { '1' } else { '0' };
    out.into_iter().collect()
}

/// **Step 6 of the published recipe.** `chain_genesis` no longer matches the
/// header it is derived from.
///
/// Nothing else in the manifest is touched: `verify_export` recomputes the seed
/// from the header and chains from THAT, so every page digest, every chain link
/// and the root still agree with each other. The published `chain_genesis`
/// string is the only thing wrong, and the genesis comparison is the only check
/// that looks at it.
///
/// This matters precisely because an auditor following the recipe recomputes
/// the seed and compares it to this field. A product that accepted a manifest
/// whose own `chain_genesis` it disagreed with would hand out artifacts that
/// fail the documented procedure while passing the vendor's verifier — which is
/// the failure `the_chain_is_recomputable_from_the_manifest_text_alone` was
/// written for, one field along.
#[test]
fn a_chain_genesis_the_header_does_not_imply_fails_verification() {
    let e = export(ExportFormat::Jsonl, &key_a());
    resigning_alone_changes_nothing(&e);

    let mut manifest: serde_json::Value = serde_json::from_str(&e.manifest_json).expect("json");
    let genuine = manifest["chain_genesis"]
        .as_str()
        .expect("chain_genesis")
        .to_owned();
    let corrupted = flip_one_hex_digit(&genuine);
    assert_ne!(
        corrupted, genuine,
        "premise: the mutation must change bytes"
    );
    assert_eq!(
        corrupted.len(),
        genuine.len(),
        "premise: the field must stay a well-formed digest, or the parse \
         catches this instead of the genesis check"
    );
    manifest["chain_genesis"] = serde_json::json!(corrupted);

    let (json, signature) = resign(&manifest, &key_a());
    let refs: Vec<&[u8]> = e.pages.iter().map(Vec::as_slice).collect();
    assert_eq!(
        verify_export(&json, &signature, &e.public_key_b64, &refs),
        Err(VerifyError::GenesisMismatch),
        "a manifest whose chain seed is not the one its own header implies \
         must be refused; delete the genesis check in `verify_export` and this \
         export verifies clean"
    );
}

/// **Step 7 of the published recipe.** One link of the chain edited.
///
/// The page bytes and every `sha256` are untouched, so the positional digest
/// loop passes; `chain_root` is untouched, so the root still matches the chain
/// recomputed from the digests. Only `pages[1].chain` is wrong, and the
/// per-link comparison is the only check that reads it — which is also what
/// makes the error LOCAL: it names page 2 rather than saying "something is
/// wrong somewhere".
#[test]
fn a_broken_chain_link_fails_verification_and_names_the_page() {
    let e = export(ExportFormat::Jsonl, &key_a());
    resigning_alone_changes_nothing(&e);

    let mut manifest: serde_json::Value = serde_json::from_str(&e.manifest_json).expect("json");
    assert_eq!(
        manifest["pages"][1]["page"].as_u64(),
        Some(2),
        "premise: pages[1] is page 2, so the error below names the right file"
    );
    let genuine = manifest["pages"][1]["chain"]
        .as_str()
        .expect("chain")
        .to_owned();
    manifest["pages"][1]["chain"] = serde_json::json!(flip_one_hex_digit(&genuine));

    let (json, signature) = resign(&manifest, &key_a());
    let refs: Vec<&[u8]> = e.pages.iter().map(Vec::as_slice).collect();
    assert_eq!(
        verify_export(&json, &signature, &e.public_key_b64, &refs),
        Err(VerifyError::ChainBroken { page: 2 }),
        "a chain link that does not follow from the previous one must be \
         refused, and must name the page; delete the per-link check and this \
         export verifies clean"
    );
}

/// **Step 8 of the published recipe.** The published root does not match the
/// chain the manifest's own links build.
///
/// Every link is internally consistent, so the loop above passes. `chain_root`
/// is the one value an auditor is told to pin and quote, and this is the check
/// that makes the published one binding rather than decorative.
#[test]
fn a_chain_root_that_the_links_do_not_build_fails_verification() {
    let e = export(ExportFormat::Jsonl, &key_a());
    resigning_alone_changes_nothing(&e);

    let mut manifest: serde_json::Value = serde_json::from_str(&e.manifest_json).expect("json");
    let genuine = manifest["chain_root"]
        .as_str()
        .expect("chain_root")
        .to_owned();
    let last_link = manifest["pages"]
        .as_array()
        .expect("pages")
        .last()
        .expect("at least one page")["chain"]
        .as_str()
        .expect("chain")
        .to_owned();
    assert_eq!(
        genuine, last_link,
        "premise: the genuine root IS the last link, so the mutation below \
         separates them rather than restating one of them"
    );
    manifest["chain_root"] = serde_json::json!(flip_one_hex_digit(&genuine));

    let (json, signature) = resign(&manifest, &key_a());
    let refs: Vec<&[u8]> = e.pages.iter().map(Vec::as_slice).collect();
    assert_eq!(
        verify_export(&json, &signature, &e.public_key_b64, &refs),
        Err(VerifyError::ChainRootMismatch),
        "a published root that the manifest's own links do not build must be \
         refused; delete the root check and this export verifies clean"
    );
}

/// `total_rows` edited to a figure the pages do not sum to.
///
/// The fourth unpinned check, and the one with a consequence outside
/// cryptography: `total_rows` is the number a compliance report quotes ("this
/// export covers 4,812 requests"). The per-SECTION row sums are already pinned
/// by `a_section_row_count_that_its_pages_do_not_sum_to_fails_verification`;
/// this is the export-wide total, which that test cannot see because it moves
/// the same row between the two sections and leaves the total intact.
#[test]
fn a_total_row_count_the_pages_do_not_sum_to_fails_verification() {
    let e = export(ExportFormat::Jsonl, &key_a());
    resigning_alone_changes_nothing(&e);

    let mut manifest: serde_json::Value = serde_json::from_str(&e.manifest_json).expect("json");
    let genuine = manifest["total_rows"].as_u64().expect("total_rows");
    assert_eq!(
        genuine, 6,
        "premise: the fixture is two data pages of two rows and two \
         control pages of one"
    );
    manifest["total_rows"] = serde_json::json!(genuine - 1);

    let (json, signature) = resign(&manifest, &key_a());
    let refs: Vec<&[u8]> = e.pages.iter().map(Vec::as_slice).collect();
    assert_eq!(
        verify_export(&json, &signature, &e.public_key_b64, &refs),
        Err(VerifyError::RowCountMismatch {
            declared: 5,
            summed: 6
        }),
        "an export whose declared total does not match its pages must be \
         refused; delete the total-rows check and this export verifies clean"
    );
}

// ── The manifest itself ───────────────────────────────────────────────────

/// Editing the manifest to match a tampered export breaks the SIGNATURE. This
/// is what stops the obvious follow-up to every test above: recompute the
/// digests and rewrite the manifest.
#[test]
fn a_manifest_edited_to_match_a_tampered_export_fails_the_signature() {
    let mut e = export(ExportFormat::Jsonl, &key_a());
    e.pages[1] = b"{}\n".to_vec();

    // Recompute an honest manifest over the tampered pages...
    let honest = build_manifest(
        Uuid::from_u128(0xfeed),
        ws(),
        at(0),
        at(59),
        ExportFormat::Jsonl,
        2,
        &[
            request_section(
                e.pages[..2].to_vec(),
                vec![2, 1],
                vec![retention_for(at(0), at(59), at(59))],
            ),
            control_section(e.pages[2..].to_vec(), vec![1, 1], control_sources()),
        ],
        at(59),
        &key_b(),
    )
    .expect("manifest");

    // ...and serve it under the ORIGINAL signature and public key. The
    // signature no longer covers these bytes.
    let refs: Vec<&[u8]> = e.pages.iter().map(Vec::as_slice).collect();
    assert_eq!(
        verify_export(
            &honest.manifest_json,
            &e.signature_b64,
            &e.public_key_b64,
            &refs
        ),
        Err(VerifyError::SignatureInvalid)
    );
}

/// The whole export re-signed with an attacker's key. This is the case that
/// makes the auditor's out-of-band possession of the public key load-bearing,
/// and it is why `verify_export` takes the key as an argument rather than
/// reading it out of the manifest.
#[test]
fn an_export_resigned_with_a_different_key_fails_against_the_published_key() {
    let genuine = export(ExportFormat::Jsonl, &key_a());
    let forged = export(ExportFormat::Jsonl, &key_b());

    assert_ne!(
        genuine.public_key_b64, forged.public_key_b64,
        "premise: the two keys must differ"
    );

    let refs: Vec<&[u8]> = forged.pages.iter().map(Vec::as_slice).collect();
    assert_eq!(
        verify_export(
            &forged.manifest_json,
            &forged.signature_b64,
            // the key the auditor holds, not the one shipped with the forgery
            &genuine.public_key_b64,
            &refs
        ),
        Err(VerifyError::SignatureInvalid)
    );
}

// ── The auditor's position ────────────────────────────────────────────────

/// Recompute the chain seed and the whole chain from the manifest's **own
/// text**, exactly as `docs/audit-export-format.md` tells an auditor to, using
/// nothing but SHA-256 and the JSON strings.
///
/// # The bug this exists for
///
/// `genesis` used to hash `DateTime::to_rfc3339()` (`...T12:00:00+00:00`)
/// while the manifest's JSON carried chrono's serde form (`...T12:00:00Z`), so
/// the seed was NOT derivable from the document an auditor holds. Independent
/// verification — the entire point of the scheme — was impossible.
///
/// Every Rust test still passed, because `verify_export` recomputed the seed
/// from the same typed values with the same spelling on both sides. A
/// signature scheme graded only against itself is self-consistent and worth
/// nothing; it was caught by running the DOCUMENTED verifier against a real
/// export. This test is that check, in-gate and without a Python dependency:
/// it reads strings out of the JSON rather than reusing the typed inputs.
#[test]
fn the_chain_is_recomputable_from_the_manifest_text_alone() {
    for format in [ExportFormat::Csv, ExportFormat::Jsonl] {
        let e = export(format, &key_a());
        let m: serde_json::Value = serde_json::from_str(&e.manifest_json).expect("json");

        let header = [
            "secureprompt.audit_export.v1",
            m["export_id"].as_str().expect("export_id"),
            m["workspace_id"].as_str().expect("workspace_id"),
            m["window"]["from"].as_str().expect("window.from"),
            m["window"]["to"].as_str().expect("window.to"),
            m["format"].as_str().expect("format"),
            &m["page_size"].as_u64().expect("page_size").to_string(),
        ]
        .join("\n")
            + "\n";

        let seed = Sha256::digest(header.as_bytes());
        assert_eq!(
            hex::encode(seed),
            m["chain_genesis"].as_str().expect("chain_genesis"),
            "{}: the chain seed must be derivable from the manifest's own text",
            format.as_str()
        );

        // And the whole chain, page by page, over raw 32-byte digests.
        let mut chain: [u8; 32] = seed.into();
        for (index, page) in e.pages.iter().enumerate() {
            let digest = Sha256::digest(page);
            assert_eq!(
                hex::encode(digest),
                m["pages"][index]["sha256"].as_str().expect("sha256"),
                "page {} digest",
                index + 1
            );
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&chain);
            buf[32..].copy_from_slice(&digest);
            chain = Sha256::digest(buf).into();
            assert_eq!(
                hex::encode(chain),
                m["pages"][index]["chain"].as_str().expect("chain"),
                "page {} chain link",
                index + 1
            );
        }
        assert_eq!(
            hex::encode(chain),
            m["chain_root"].as_str().expect("chain_root")
        );
    }
}

// ── No content in the export ──────────────────────────────────────────────

/// The export carries request METADATA, never prompt or response bytes.
/// `request_events` holds `raw_prompt`, `raw_response`, `redacted_prompt` and
/// `restored_response`; a compliance artifact that shipped those would be a
/// PII export wearing an audit label.
#[test]
fn the_export_carries_no_content_columns() {
    let header = String::from_utf8(render_page(&[row(1)], ExportFormat::Csv)).expect("utf8");
    for forbidden in [
        "raw_prompt",
        "raw_response",
        "redacted_prompt",
        "restored_response",
    ] {
        assert!(
            !header.contains(forbidden),
            "column `{forbidden}` must never appear in an audit export"
        );
    }
}
