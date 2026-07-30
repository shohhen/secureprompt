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

use secureprompt_common::audit_export::{
    build_manifest, render_page, verify_export, AuditRow, ExportFormat, VerifyError,
};

use chrono::{DateTime, TimeZone, Utc};
use ed25519_dalek::SigningKey;
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

/// Three pages of two rows each — the smallest shape in which "a row was
/// removed from the MIDDLE" is a distinct case from "the export was truncated".
fn pages_of(format: ExportFormat) -> Vec<Vec<u8>> {
    (0..3)
        .map(|p| {
            let rows: Vec<AuditRow> = (0..2).map(|i| row(p * 2 + i)).collect();
            render_page(&rows, format)
        })
        .collect()
}

struct Export {
    manifest_json: String,
    signature_b64: String,
    public_key_b64: String,
    pages: Vec<Vec<u8>>,
}

fn export(format: ExportFormat, key: &SigningKey) -> Export {
    let pages = pages_of(format);
    let signed = build_manifest(
        Uuid::from_u128(0xfeed),
        ws(),
        at(0),
        at(59),
        format,
        2,
        &pages,
        &[2u32, 2, 2],
        at(59),
        key,
    )
    .expect("manifest");
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

/// A WHOLE page dropped. This is the case a per-page signature cannot catch:
/// the two remaining pages are untouched and would each verify individually.
#[test]
fn a_whole_page_removed_fails_verification() {
    let mut e = export(ExportFormat::Jsonl, &key_a());
    assert_eq!(e.pages.len(), 3, "premise: three pages before removal");
    e.pages.remove(1);
    assert_eq!(
        check(&e),
        Err(VerifyError::PageCountMismatch {
            expected: 3,
            got: 2
        })
    );
}

/// Pages reordered. The chain is over digests IN ORDER, so a swap breaks it
/// even though the multiset of pages is unchanged — the case a plain
/// "set of per-page digests" manifest would miss.
#[test]
fn pages_reordered_fail_verification() {
    let mut e = export(ExportFormat::Jsonl, &key_a());
    e.pages.swap(0, 2);
    assert!(
        matches!(check(&e), Err(VerifyError::PageDigestMismatch { .. })),
        "a reordered export must not verify"
    );
}

/// A page lifted from a DIFFERENT export of the same shape. The chain is
/// seeded from this export's own header (id, workspace, window, format, page
/// size), so a foreign page cannot be spliced in even if its digest happened
/// to be chosen to fit.
#[test]
fn a_page_from_another_export_cannot_be_spliced_in() {
    let e = export(ExportFormat::Jsonl, &key_a());
    let other_pages = (0..3)
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

// ── The manifest itself ───────────────────────────────────────────────────

/// Editing the manifest to match a tampered export breaks the SIGNATURE. This
/// is what stops the obvious follow-up to every test above: recompute the
/// digests and rewrite the manifest.
#[test]
fn a_manifest_edited_to_match_a_tampered_export_fails_the_signature() {
    let mut e = export(ExportFormat::Jsonl, &key_a());
    e.pages[1] = b"{}\n".to_vec();

    // Recompute an honest manifest over the tampered pages...
    let rows_per_page = vec![2u32, 1, 2];
    let honest = build_manifest(
        Uuid::from_u128(0xfeed),
        ws(),
        at(0),
        at(59),
        ExportFormat::Jsonl,
        2,
        &e.pages,
        &rows_per_page,
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
