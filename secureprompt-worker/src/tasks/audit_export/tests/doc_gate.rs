//! P2A — `docs/audit-export-format.md`, EXECUTED.
//!
//! # Why this file exists
//!
//! `docs/audit-export-format.md` is the only artifact in the product a third
//! party uses to check our integrity claims. It carries a runnable Python
//! verifier, and until this file landed nothing tested it. It drifted four
//! times in one day.
//!
//! Executing it has already caught two bugs every Rust test missed:
//!
//! * WS4-1 — the chain seed hashed `to_rfc3339()` (`+00:00`) while the manifest
//!   carried chrono's serde `Z`. All 53 tests passed, because `verify_export`
//!   used the same wrong spelling on BOTH sides: the implementation was
//!   verifying against itself. An auditor writing a verifier from the published
//!   spelling could not have reproduced the seed.
//! * FU5 — the document asserted "three audited actions" in six places, in one
//!   case inside the worked verifier output, when there were twelve.
//!
//! # What "executed" has to mean, and what it must not mean
//!
//! The predecessor task re-extracted the verifier and compiled it, and
//! disclosed honestly that it never produced a fresh signed export. A verifier
//! that compiles proves the Markdown is syntactically intact and nothing else.
//! So every Python run below is against bytes a REAL export produced:
//! `run_with` — the same entry point `run` calls in production — over a seeded
//! ClickHouse `request_events` window and a seeded Postgres control-plane
//! trail, paginated into six pages across both sections, signed with a real
//! Ed25519 key.
//!
//! And the verifier is EXTRACTED from the Markdown at run time
//! ([`extract_verifier`]) rather than copied into this file. A copy would drift
//! from the document and defeat the entire purpose. The bytes an auditor reads
//! are the bytes that run.
//!
//! # Tampering is re-signed
//!
//! Every tampered copy below is re-signed with the private key — that is,
//! standing where the deployment operator stands. Testing against a broken
//! signature would only test Ed25519. Re-signing tests the CHAIN and the
//! MANIFEST, which is where the export's real guarantees live.
//! `resigned-unaltered` is run first as the control: an unaltered manifest,
//! re-serialised and re-signed, still verifies, so the failures below it are
//! the mutations and not the re-signing.
//!
//! # No real PII
//!
//! Every seeded value is synthetic, and the seeding helpers are the ones
//! `super` already uses: RFC 5737 documentation addresses, invented labels,
//! `example.invalid` emails, and per-test random UUIDs.

use super::*;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::Signer as _;
use secureprompt_common::audit_export::{
    CONTROL_COLUMNS, CONTROL_SOURCE_TABLES, PLANE_CONTROL, PLANE_DATA, REQUEST_COLUMNS,
    REQUIRED_SECTIONS, SCHEMA_VERSION, SOURCE_TABLE, SOURCE_TTL_DAYS,
};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::Command;

// ── The document ──────────────────────────────────────────────────────────

/// The document under test, relative to this crate's manifest directory.
fn doc_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("docs")
        .join("audit-export-format.md")
}

fn doc_text() -> String {
    let path = doc_path();
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "the document under test must exist at {}: {e}",
            path.display()
        )
    });
    // PREMISE. An empty or truncated file would make every parse below return
    // nothing and every assertion pass vacuously.
    assert!(
        text.len() > 10_000 && text.contains("## 5. Verifying an export"),
        "premise: {} does not look like the audit-export format document ({} bytes)",
        path.display(),
        text.len()
    );
    text
}

const PYTHON_FENCE: &str = "\n```python\n";
const FENCE_CLOSE: &str = "\n```\n";

/// Pull the reference verifier out of the Markdown.
///
/// THIS IS THE POINT OF THE FILE. The verifier is not duplicated here; it is
/// parsed out of the document, so the code that runs below is character for
/// character the code an auditor is handed. A second copy in this file could
/// pass while the published one was broken — which is precisely the failure
/// WS4-1 found, one level up.
///
/// Exactly one ```` ```python ```` block is required. Two would mean the
/// document grew a second listing and this gate silently started checking only
/// the first.
fn extract_verifier(doc: &str) -> String {
    let mut blocks: Vec<String> = Vec::new();
    let mut rest = doc;
    while let Some(open) = rest.find(PYTHON_FENCE) {
        let after = &rest[open + PYTHON_FENCE.len()..];
        let close = after
            .find(FENCE_CLOSE)
            .expect("an opened ```python fence must be closed");
        blocks.push(after[..close].to_owned());
        rest = &after[close..];
    }
    assert_eq!(
        blocks.len(),
        1,
        "the document must carry exactly one ```python block — the reference \
         verifier. Found {}. If a second listing was added, this gate has to be \
         told which one an auditor runs.",
        blocks.len()
    );
    let verifier = blocks.remove(0);
    // PREMISE: it is the verifier and not some other listing.
    for anchor in [
        "Ed25519PublicKey",
        "chain_genesis",
        "REQUIRED_SECTIONS",
        "sys.exit",
    ] {
        assert!(
            verifier.contains(anchor),
            "the extracted block does not contain `{anchor}`, so it is not the \
             reference verifier"
        );
    }
    verifier
}

/// The verifier with its own steps 5 and 6 CUT OUT.
///
/// §5 of the document claims, in its worked output, that "if you skip steps 5
/// and 6, the first four of those five pass". That is a claim about which
/// checks are load-bearing, and it is checked by
/// [`the_documents_steps_5_and_6_are_load_bearing`] by running this reduced
/// verifier against the same tampered copies.
fn without_steps_5_and_6(verifier: &str) -> String {
    let start = verifier
        .find("# 5. BOTH PLANES ARE PRESENT.")
        .expect("the document's step 5 must start with the comment this gate cuts on");
    let end = verifier
        .find("print(f\"OK:")
        .expect("the document's summary print must follow steps 5 and 6");
    assert!(start < end, "step 5 must precede the summary print");
    let reduced = format!("{}{}", &verifier[..start], &verifier[end..]);

    // The cut is verified rather than assumed: a no-op edit here would make
    // every "passes without steps 5-6" assertion below prove nothing.
    assert!(
        reduced.len() < verifier.len(),
        "premise: the cut removed nothing"
    );
    for gone in [
        "part of this export is missing",
        "does not \"\n                 \"continue the page sequence",
        "continue the page sequence",
        "falls inside",
    ] {
        assert!(
            !reduced.contains(gone),
            "premise: `{gone}` survived the cut, so steps 5-6 were not removed"
        );
    }
    // POSITIVE CONTROL: steps 1-4 are still there, so a pass from the reduced
    // verifier means "steps 1-4 did not object", not "the file was emptied".
    for kept in [
        "Ed25519PublicKey",
        "chain is broken at page",
        "chain_genesis",
    ] {
        assert!(
            reduced.contains(kept),
            "the cut removed `{kept}`, which belongs to steps 1-4"
        );
    }
    reduced
}

// ── Python ────────────────────────────────────────────────────────────────

const PYTHON: &str = "python3";

/// Require the interpreter, LOUDLY.
///
/// This deliberately panics instead of returning `false` for the caller to skip
/// on. A test that skips when its interpreter is missing is a test that never
/// runs, and the whole reason this file exists is that "we ran the document"
/// was believed while nobody had. See the `#[ignore]` note on the two tests
/// that call this for where the interpreter comes from in CI.
fn require_python() {
    let probe = Command::new(PYTHON)
        .args([
            "-c",
            "import cryptography.hazmat.primitives.asymmetric.ed25519",
        ])
        .output();
    match probe {
        Ok(out) if out.status.success() => {}
        Ok(out) => panic!(
            "`{PYTHON}` cannot import `cryptography`, which the document's \
             verifier needs for the signature check. Install it \
             (`apt-get install -y python3-cryptography`) and re-run — do not \
             skip this test.\nstderr: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) => panic!(
            "`{PYTHON}` is not runnable ({e}). The document's verifier is \
             Python and this gate runs it; there is no fallback."
        ),
    }
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run_verifier(script: &Path, args: &[PathBuf]) -> Run {
    let out = Command::new(PYTHON)
        .arg(script)
        .args(args)
        .output()
        .expect("python3 must run the extracted verifier");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

// ── Laying an export out the way an auditor holds it ──────────────────────

/// Write the four artifact kinds into `dir` and return the verifier's argv.
///
/// The manifest is written as EXACT BYTES with no trailing newline — §5's
/// "do not reformat the manifest before verifying" is a real constraint, and
/// writing it through anything that re-serialises would break the signature.
fn lay_out(
    dir: &Path,
    manifest: &[u8],
    signature_b64: &str,
    public_key_b64: &str,
    pages: &[Vec<u8>],
) -> Vec<PathBuf> {
    std::fs::create_dir_all(dir).expect("case directory");
    let manifest_path = dir.join("manifest.json");
    std::fs::write(&manifest_path, manifest).expect("manifest.json");
    let signature_path = dir.join("signature.b64");
    std::fs::write(&signature_path, signature_b64).expect("signature.b64");
    let key_path = dir.join("pubkey.b64");
    std::fs::write(&key_path, public_key_b64).expect("pubkey.b64");

    let mut argv = vec![manifest_path, signature_path, key_path];
    for (index, body) in pages.iter().enumerate() {
        let page_path = dir.join(format!("page-{}.csv", index + 1));
        std::fs::write(&page_path, body).expect("page file");
        argv.push(page_path);
    }
    argv
}

/// Sign tampered manifest bytes with the deployment's PRIVATE key.
///
/// This is what makes the tamper cases mean anything: the operator who alters
/// an export also holds the signing key, so a test that left the old signature
/// in place would only be re-testing Ed25519.
fn resign(manifest: &[u8], key: &ed25519_dalek::SigningKey) -> (String, String) {
    (
        B64.encode(key.sign(manifest).to_bytes()),
        B64.encode(key.verifying_key().to_bytes()),
    )
}

/// A tampered manifest, back to bytes.
///
/// `serde_json` orders a `Value`'s keys alphabetically, so these bytes differ
/// from the producer's even for an unaltered clone. That is exactly why
/// `resigned-unaltered` is run as a control.
fn serialise(manifest: &Value) -> Vec<u8> {
    serde_json::to_vec(manifest).expect("a manifest round-trips through serde_json")
}

// ── Producing a genuine export ────────────────────────────────────────────

/// Rows per page. Small on purpose: the export must span MULTIPLE PAGES in
/// BOTH sections, because "a page was dropped", "two pages were reordered" and
/// "the section boundary moved" are not expressible on a one-page export.
const DOC_GATE_PAGE_SIZE: u32 = 3;

struct Produced {
    manifest_bytes: Vec<u8>,
    manifest: Value,
    signature_b64: String,
    public_key_b64: String,
    pages: Vec<Vec<u8>>,
}

/// The five `admin_audit` actions the control plane is seeded with. Any subset
/// of migration 028/029's vocabulary would do — the exhaustive check over the
/// WHOLE vocabulary is `super::every_audited_action_reaches_the_signed_export`,
/// and the doc's own list is checked against the database by
/// [`the_documented_action_list_matches_the_database`].
const SEEDED_ADMIN_ACTIONS: &[&str] = &[
    "api_key.created",
    "api_key.revoked",
    "user.created",
    "budget.updated",
    "license.activated",
];

/// Seed both planes for `workspace_id` and run the REAL job over them.
///
/// Not a fixture. `run_with` is the function `run` calls in production, with
/// only the signing key, the row cap and the clock passed in rather than read
/// from the environment.
async fn produce_real_export(
    pool: &PgPool,
    workspace_id: Uuid,
    format: &'static str,
) -> sqlx::Result<Produced> {
    seed_workspace(pool, workspace_id).await?;

    // Data plane: seven requests, so page 1 is full (3), page 2 is full (3) and
    // page 3 is short (1). The first three carry `allow` so the flipped-field
    // case has a same-length value to flip on page 1.
    let seeds: Vec<Seed> = (1u32..=7)
        .map(|minute| Seed {
            request_id: Uuid::new_v4(),
            minute,
            model: "synthetic-model-a",
            final_action: if minute <= 3 { "allow" } else { "redact" },
            cost_usd: f64::from(minute) / 1000.0,
            api_key_name: Some("synthetic-key"),
        })
        .collect();
    seed_events(workspace_id, &seeds).await;

    // Control plane: three rows from the per-event tables plus five
    // `admin_audit` rows — eight rows, three pages.
    seed_control_plane(pool, workspace_id, 10).await?;
    let (from, _) = window();
    for (index, action) in SEEDED_ADMIN_ACTIONS.iter().enumerate() {
        sqlx::query(
            "INSERT INTO admin_audit \
             (id, workspace_id, action, actor_user_id, actor_email, actor_role, \
              target_type, target_id, target_label, detail, created_at) \
             VALUES ($1, $2, $3, $4, 'synthetic-admin@example.invalid', 'admin', \
                     'synthetic', $5, 'synthetic-object', '{\"synthetic\": true}'::jsonb, $6)",
        )
        .bind(Uuid::new_v4())
        .bind(workspace_id)
        .bind(*action)
        .bind(Uuid::new_v4())
        .bind(Uuid::new_v4())
        .bind(from + chrono::Duration::minutes(20 + i64::try_from(index).unwrap_or(0)))
        .execute(pool)
        .await?;
    }

    let export_id = Uuid::new_v4();
    seed_export_row(
        pool,
        export_id,
        workspace_id,
        format,
        i32::try_from(DOC_GATE_PAGE_SIZE).expect("page size fits an i32"),
    )
    .await?;
    let outcome = run_with(
        pool,
        &ch_client(),
        &envelope(export_id, workspace_id, format, DOC_GATE_PAGE_SIZE),
        Ok(test_key()),
        MAX_EXPORT_ROWS,
        Utc::now(),
    )
    .await;

    let stored = load_export(pool, export_id).await?;
    assert!(
        outcome.ok(),
        "the export must complete before it can be verified; error: {:?}",
        stored.error
    );

    let manifest_json = stored
        .manifest_json
        .expect("a complete export carries a manifest");
    let manifest: Value = serde_json::from_str(&manifest_json).expect("the manifest is JSON");
    let pages = load_pages(pool, export_id).await?;

    // PREMISES. Each of the tamper cases below needs a specific shape, and a
    // one-page single-section export would make most of them unexpressible
    // while still "passing".
    assert_eq!(
        pages.len(),
        6,
        "premise: this gate needs 3 data pages + 3 control pages, got {}",
        pages.len()
    );
    let sections = manifest["sections"]
        .as_array()
        .expect("a v2 manifest carries sections");
    assert_eq!(sections.len(), 2, "premise: both planes must be present");
    for section in sections {
        assert!(
            section["pages"].as_u64().unwrap_or(0) >= 2,
            "premise: section {} has fewer than two pages, so `a page was \
             dropped` and `two pages were reordered` cannot be expressed inside it",
            section["section"]
        );
    }

    Ok(Produced {
        manifest_bytes: manifest_json.into_bytes(),
        manifest,
        signature_b64: stored
            .signature_b64
            .expect("a complete export carries a signature"),
        public_key_b64: stored
            .public_key_b64
            .expect("a complete export carries a public key"),
        pages,
    })
}

fn scratch_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sp-audit-doc-gate-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("scratch directory");
    dir
}

/// One tampered copy: what it is called, what §5 must say about it, the
/// manifest to re-sign and the page files to hand over, in order.
struct Tamper {
    name: &'static str,
    expected: &'static str,
    manifest: Value,
    pages: Vec<Vec<u8>>,
}

/// Build every tampered copy from a produced export plus a SECOND produced
/// export to splice from.
#[allow(clippy::too_many_lines)]
fn tamper_matrix(produced: &Produced, other: &Produced) -> Vec<Tamper> {
    let mut cases = Vec::new();
    let entries = produced.manifest["pages"]
        .as_array()
        .expect("pages")
        .clone();
    let sections = produced.manifest["sections"]
        .as_array()
        .expect("sections")
        .clone();
    let data_last = usize::try_from(sections[0]["last_page"].as_u64().expect("last_page"))
        .expect("page count fits a usize");
    let control_name = sections[1]["section"].clone();

    // ── 1. A row cut from the MIDDLE of a page ───────────────────────────
    // The attack §4 says a paginated export invites. Nothing about the page's
    // shape changes: it is still a valid CSV file with its own header.
    {
        let mut pages = produced.pages.clone();
        let text = String::from_utf8(pages[0].clone()).expect("a CSV page is utf-8");
        let lines: Vec<&str> = text.split_inclusive('\n').collect();
        assert!(
            lines.len() >= 4,
            "premise: page 1 must be a header plus at least three rows to have \
             a middle row to cut, has {} lines",
            lines.len()
        );
        let cut: String = lines
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != 2)
            .map(|(_, line)| *line)
            .collect();
        assert!(
            cut.len() < text.len() && cut.starts_with("\"request_id\""),
            "premise: the cut must remove a data row and leave the header"
        );
        pages[0] = cut.into_bytes();
        cases.push(Tamper {
            name: "row-cut-from-mid-page",
            expected: "does not match its digest",
            manifest: produced.manifest.clone(),
            pages,
        });
    }

    // ── 2. A whole page DROPPED ──────────────────────────────────────────
    // Dropped from the artifact AND from the manifest, with the remaining
    // pages renumbered and both sections' ranges and row totals repaired, so
    // neither the page count (step 3) nor the section checks (step 6) can be
    // what notices. Only the CHAIN is left — which is §4's first row.
    {
        let mut manifest = produced.manifest.clone();
        let dropped_rows = entries[1]["rows"].as_u64().expect("rows");
        {
            let pages_mut = manifest["pages"].as_array_mut().expect("pages");
            pages_mut.remove(1);
            for (index, entry) in pages_mut.iter_mut().enumerate() {
                entry["page"] = json!(index + 1);
            }
        }
        manifest["total_pages"] = json!(entries.len() - 1);
        manifest["total_rows"] = json!(
            produced.manifest["total_rows"]
                .as_u64()
                .expect("total_rows")
                - dropped_rows
        );
        manifest["chain_root"] = manifest["pages"][entries.len() - 2]["chain"].clone();
        {
            let sections_mut = manifest["sections"].as_array_mut().expect("sections");
            sections_mut[0]["last_page"] = json!(data_last - 1);
            sections_mut[0]["pages"] = json!(data_last - 1);
            sections_mut[0]["rows"] =
                json!(sections[0]["rows"].as_u64().expect("rows") - dropped_rows);
            sections_mut[1]["first_page"] = json!(data_last);
            sections_mut[1]["last_page"] =
                json!(sections[1]["last_page"].as_u64().expect("last_page") - 1);
        }
        let mut pages = produced.pages.clone();
        pages.remove(1);
        cases.push(Tamper {
            name: "whole-page-dropped",
            expected: "chain is broken at page",
            manifest,
            pages,
        });
    }

    // ── 3. Two pages REORDERED ───────────────────────────────────────────
    // Both inside the data section and both full, so their row counts match
    // and their manifest entries travel with them: every per-page digest still
    // matches its entry. §4's second row — order is meaning — and the chain is
    // the only thing that can see it.
    {
        assert_eq!(
            entries[0]["rows"], entries[1]["rows"],
            "premise: the two swapped pages must carry the same row count, or \
             the row total rather than the chain would be what objects"
        );
        assert_eq!(
            entries[0]["section"], entries[1]["section"],
            "premise: the two swapped pages must be in the same section, or \
             step 6 rather than the chain would be what objects"
        );
        let mut manifest = produced.manifest.clone();
        {
            let pages_mut = manifest["pages"].as_array_mut().expect("pages");
            pages_mut.swap(0, 1);
            for (index, entry) in pages_mut.iter_mut().enumerate() {
                entry["page"] = json!(index + 1);
            }
        }
        let mut pages = produced.pages.clone();
        pages.swap(0, 1);
        cases.push(Tamper {
            name: "two-pages-reordered",
            expected: "chain is broken at page",
            manifest,
            pages,
        });
    }

    // ── 4. A page SPLICED IN from a different export ─────────────────────
    // §4: "the genesis seed binds the export's identity and window, so a page
    // lifted from a DIFFERENT export of the same shape cannot be spliced in."
    // The other export's manifest entry comes with it, so its digest matches
    // and its own chain value is present — and still cannot reconcile, because
    // the seed it was folded from is a different export's.
    {
        let foreign = other.manifest["pages"][0].clone();
        assert_ne!(
            foreign["sha256"], entries[0]["sha256"],
            "premise: the spliced page must differ from the one it replaces"
        );
        assert_eq!(
            foreign["rows"], entries[0]["rows"],
            "premise: the spliced page must carry the same row count, or the \
             row total rather than the chain would be what objects"
        );
        assert_eq!(
            foreign["section"], entries[0]["section"],
            "premise: the spliced page must claim the same section"
        );
        let mut manifest = produced.manifest.clone();
        manifest["pages"][0] = foreign;
        manifest["pages"][0]["page"] = json!(1);
        let mut pages = produced.pages.clone();
        pages[0] = other.pages[0].clone();
        cases.push(Tamper {
            name: "page-spliced-from-another-export",
            expected: "chain is broken at page 1",
            manifest,
            pages,
        });
    }

    // ── 5. A FIELD FLIPPED ───────────────────────────────────────────────
    // `allow` -> `block`: five bytes for five bytes, so the page's length, row
    // count and CSV shape are all unchanged and only the digest can notice.
    {
        let mut pages = produced.pages.clone();
        let text = String::from_utf8(pages[0].clone()).expect("a CSV page is utf-8");
        assert!(
            text.contains("\"allow\""),
            "premise: page 1 must carry an `allow` to flip"
        );
        let flipped = text.replacen("\"allow\"", "\"block\"", 1);
        assert_eq!(
            flipped.len(),
            text.len(),
            "premise: the flip must not change the page's length"
        );
        assert_ne!(flipped, text, "premise: the flip must change the page");
        pages[0] = flipped.into_bytes();
        cases.push(Tamper {
            name: "field-flipped",
            expected: "does not match its digest",
            manifest: produced.manifest.clone(),
            pages,
        });
    }

    // ── 6. The whole CONTROL PLANE removed, honestly re-signed ───────────
    // §4's "the attack the signature alone cannot stop". The data pages are the
    // chain's first links, so their chain values are already correct for a
    // shorter export: steps 1-4 pass with nothing recomputed. Step 5 is the
    // only thing standing between an auditor and an audit trail with the
    // administrative half quietly missing.
    {
        let mut manifest = produced.manifest.clone();
        manifest["sections"] = json!([sections[0].clone()]);
        manifest["pages"] = json!(entries[..data_last].to_vec());
        manifest["total_pages"] = json!(data_last);
        manifest["total_rows"] = sections[0]["rows"].clone();
        manifest["chain_root"] = entries[data_last - 1]["chain"].clone();
        cases.push(Tamper {
            name: "control-plane-removed",
            expected: "part of this export is missing",
            manifest,
            pages: produced.pages[..data_last].to_vec(),
        });
    }

    // ── 7. A page RELABELLED into the other section ──────────────────────
    {
        let mut manifest = produced.manifest.clone();
        manifest["pages"][1]["section"] = control_name.clone();
        cases.push(Tamper {
            name: "page-relabelled",
            expected: "claims section",
            manifest,
            pages: produced.pages.clone(),
        });
    }

    // ── 8. The SECTION BOUNDARY moved ────────────────────────────────────
    // The data section gives up its last page without the control section
    // claiming it, so the two no longer partition `1..total_pages`.
    {
        let mut manifest = produced.manifest.clone();
        let surrendered = entries[data_last - 1]["rows"].as_u64().expect("rows");
        let sections_mut = manifest["sections"].as_array_mut().expect("sections");
        sections_mut[0]["last_page"] = json!(data_last - 1);
        sections_mut[0]["pages"] = json!(data_last - 1);
        sections_mut[0]["rows"] = json!(sections[0]["rows"].as_u64().expect("rows") - surrendered);
        cases.push(Tamper {
            name: "section-boundary-moved",
            expected: "does not continue the page sequence",
            manifest,
            pages: produced.pages.clone(),
        });
    }

    // ── 9. ROWS MOVED between the sections' totals ───────────────────────
    // `total_rows` still adds up, so step 4 is satisfied and only the
    // per-section sum in step 6 disagrees.
    {
        let mut manifest = produced.manifest.clone();
        let sections_mut = manifest["sections"].as_array_mut().expect("sections");
        sections_mut[0]["rows"] = json!(sections[0]["rows"].as_u64().expect("rows") + 1);
        sections_mut[1]["rows"] = json!(sections[1]["rows"].as_u64().expect("rows") - 1);
        cases.push(Tamper {
            name: "section-rows-moved",
            expected: "declares",
            manifest,
            pages: produced.pages.clone(),
        });
    }

    cases
}

// ── The gate ──────────────────────────────────────────────────────────────

/// **The document, executed against a real export.**
///
/// `#[ignore]` — and it is not skipped. The shared `test` job's image
/// (`rust:1.89-bookworm`) ships python3 3.11.2 but NOT `cryptography`, which
/// the document's verifier needs for the signature check; measured by running
/// the image. So this test is run by its own CI job,
/// `test:audit-export-doc` in `.gitlab-ci.yml`, which installs
/// `python3-cryptography` and invokes it by name with `--ignored`. See
/// `scripts/ci/quarantine.tsv`. [`require_python`] PANICS rather than skipping
/// if the interpreter is missing, so the job cannot pass by doing nothing.
#[sqlx::test(migrations = "../secureprompt-api/migrations")]
#[ignore = "runs in the test:audit-export-doc CI job, which installs python3-cryptography"]
async fn the_documents_verifier_accepts_a_real_export_and_rejects_every_tampering(
    pool: PgPool,
) -> sqlx::Result<()> {
    require_python();
    let doc = doc_text();
    let dir = scratch_dir();
    let script = dir.join("verify.py");
    std::fs::write(&script, extract_verifier(&doc)).expect("the extracted verifier");

    let produced = produce_real_export(&pool, Uuid::new_v4(), "csv").await?;
    let other = produce_real_export(&pool, Uuid::new_v4(), "csv").await?;
    assert_ne!(
        produced.manifest["chain_genesis"], other.manifest["chain_genesis"],
        "premise: the export spliced FROM must have a different chain seed, or \
         the splice case proves nothing"
    );

    // ── The artifact as the gateway produced it, with the gateway's own
    //    signature and public key, untouched. If this fails, the published
    //    document cannot verify what the product emits.
    let argv = lay_out(
        &dir.join("as-produced"),
        &produced.manifest_bytes,
        &produced.signature_b64,
        &produced.public_key_b64,
        &produced.pages,
    );
    let run = run_verifier(&script, &argv);
    assert_eq!(
        run.code, 0,
        "the document's own verifier REJECTED an export this product produced.\n\
         stdout: {}\nstderr: {}",
        run.stdout, run.stderr
    );
    assert!(
        run.stdout.starts_with("OK: "),
        "the verifier must report OK on a genuine export, said: {}",
        run.stdout
    );
    println!(
        "as-produced            exit=0  {}",
        run.stdout.lines().next().unwrap_or("")
    );

    // ── CONTROL: re-serialised and re-signed but otherwise unaltered. Every
    //    case below is built and signed the same way, so this is what proves
    //    their failures are the mutations and not the re-signing.
    let key = test_key();
    let unaltered = serialise(&produced.manifest);
    let (signature, public_key) = resign(&unaltered, &key);
    let argv = lay_out(
        &dir.join("resigned-unaltered"),
        &unaltered,
        &signature,
        &public_key,
        &produced.pages,
    );
    let control = run_verifier(&script, &argv);
    assert_eq!(
        control.code, 0,
        "the re-signed but unaltered control must still verify, or every \
         tamper case below is just testing the re-signing.\nstderr: {}",
        control.stderr
    );

    // ── The tampered copies.
    let cases = tamper_matrix(&produced, &other);
    assert_eq!(
        cases.len(),
        9,
        "premise: the matrix must carry every case this gate claims to cover"
    );
    for case in cases {
        let bytes = serialise(&case.manifest);
        let (signature, public_key) = resign(&bytes, &key);
        let argv = lay_out(
            &dir.join(case.name),
            &bytes,
            &signature,
            &public_key,
            &case.pages,
        );
        let run = run_verifier(&script, &argv);
        assert_ne!(
            run.code, 0,
            "`{}` was ACCEPTED by the document's verifier. It was re-signed \
             with the deployment's own key, so the signature cannot be what \
             catches it — and nothing else did.\nstdout: {}",
            case.name, run.stdout
        );
        assert!(
            run.stderr.contains(case.expected),
            "`{}` failed, but not for the reason §5 says it should.\n\
             expected the message to contain: {}\nactual: {}",
            case.name,
            case.expected,
            run.stderr.trim()
        );
        println!(
            "{:<32} exit={}  {}",
            case.name,
            run.code,
            run.stderr.trim().replace('\n', " ")
        );
    }

    std::fs::remove_dir_all(&dir).ok();
    Ok(())
}

/// **§5's claim that its own steps 5 and 6 are load-bearing, executed.**
///
/// The document states, under its worked tamper output: "If you skip steps 5
/// and 6, the first four of those five pass." That is the justification for
/// four checks that look like bookkeeping, and it is the difference between an
/// auditor who refuses a half-export and one who signs off on it.
///
/// `#[ignore]` for the same reason as
/// [`the_documents_verifier_accepts_a_real_export_and_rejects_every_tampering`].
#[sqlx::test(migrations = "../secureprompt-api/migrations")]
#[ignore = "runs in the test:audit-export-doc CI job, which installs python3-cryptography"]
async fn the_documents_steps_5_and_6_are_load_bearing(pool: PgPool) -> sqlx::Result<()> {
    require_python();
    let doc = doc_text();
    let verifier = extract_verifier(&doc);
    let dir = scratch_dir();
    let reduced = dir.join("verify-without-5-6.py");
    std::fs::write(&reduced, without_steps_5_and_6(&verifier)).expect("the reduced verifier");

    let produced = produce_real_export(&pool, Uuid::new_v4(), "csv").await?;
    let other = produce_real_export(&pool, Uuid::new_v4(), "csv").await?;
    let key = test_key();

    // The four the document says slip through, and the one it says does not.
    // Named rather than counted, so a renamed or removed case fails here
    // instead of quietly shrinking the claim.
    const SLIPS_THROUGH: &[&str] = &[
        "control-plane-removed",
        "page-relabelled",
        "section-boundary-moved",
        "section-rows-moved",
    ];
    const STILL_CAUGHT: &str = "row-cut-from-mid-page";

    let cases = tamper_matrix(&produced, &other);
    let mut slipped = Vec::new();
    let mut caught = false;
    for case in cases {
        if !SLIPS_THROUGH.contains(&case.name) && case.name != STILL_CAUGHT {
            continue;
        }
        let bytes = serialise(&case.manifest);
        let (signature, public_key) = resign(&bytes, &key);
        let argv = lay_out(
            &dir.join(format!("reduced-{}", case.name)),
            &bytes,
            &signature,
            &public_key,
            &case.pages,
        );
        let run = run_verifier(&reduced, &argv);
        if case.name == STILL_CAUGHT {
            // POSITIVE CONTROL. Without this, "they all pass" would also be
            // the result of a verifier the cut had broken into uselessness.
            assert_ne!(
                run.code, 0,
                "the reduced verifier must still catch `{}` — steps 1-4 are \
                 what catch it. It passing would mean the cut broke the \
                 verifier rather than removing steps 5-6.\nstdout: {}",
                case.name, run.stdout
            );
            caught = true;
        } else {
            assert_eq!(
                run.code,
                0,
                "§5 claims `{}` slips through a verifier without steps 5 and 6, \
                 but it was still caught: {}",
                case.name,
                run.stderr.trim()
            );
            slipped.push(case.name);
        }
        println!("without steps 5-6: {:<26} exit={}", case.name, run.code);
    }

    assert!(
        caught,
        "premise: the positive control case must have been run"
    );
    assert_eq!(
        slipped.len(),
        SLIPS_THROUGH.len(),
        "premise: every case §5 names must have been run, ran {slipped:?}"
    );

    std::fs::remove_dir_all(&dir).ok();
    Ok(())
}

// ── The document's factual claims, derived rather than restated ───────────

/// Every `` `backticked` `` token in `text`, in order.
fn backticked(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find('`') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('`') else { break };
        out.push(after[..close].to_owned());
        rest = &after[close + 1..];
    }
    out
}

/// The rows of the first Markdown table at or after `anchor`, as cells.
///
/// Stops at the first blank line after the table starts, so a section holding
/// more than one table cannot bleed into the answer.
fn table_rows(doc: &str, anchor: &str) -> Vec<Vec<String>> {
    let start = doc
        .find(anchor)
        .unwrap_or_else(|| panic!("the document must contain `{anchor}`"));
    let mut rows = Vec::new();
    let mut started = false;
    for line in doc[start..].lines() {
        if line.starts_with('|') {
            started = true;
            let cells: Vec<String> = line
                .trim_matches('|')
                .split('|')
                .map(|c| c.trim().to_owned())
                .collect();
            // The `|---|---|` separator carries no data.
            if cells
                .iter()
                .all(|c| c.chars().all(|ch| ch == '-' || ch == ':'))
            {
                continue;
            }
            rows.push(cells);
        } else if started {
            break;
        }
    }
    assert!(
        rows.len() >= 2,
        "premise: the table at `{anchor}` has {} rows, so nothing below it is \
         being checked",
        rows.len()
    );
    // Drop the header row.
    rows.remove(0);
    rows
}

fn unbacktick(cell: &str) -> String {
    cell.trim_matches('`').to_owned()
}

/// Every run of whitespace collapsed to one space.
///
/// Prose in the document is hard-wrapped, so a sentence that carries a number
/// this gate checks may be split across two lines at any word. Comparing the
/// raw bytes would fail on a re-wrap and pass on a changed number that happened
/// to land mid-line — the wrong test in both directions.
fn flatten(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// **The audited-action list, derived from the database.**
///
/// FU5's lesson, applied to the document rather than to the exporter: the list
/// in §7 is not restated here. It is compared against
/// `admin_audit_action_known` — migration 028/029's CHECK constraint, the
/// closed list of actions the product may store — plus the three event types
/// the per-event control tables contribute. A twenty-third action joins this
/// assertion on the next run without anybody remembering to edit it, and the
/// document goes red until it names it.
///
/// The document also STATES its own count (`(N actions)`), which is checked
/// against the derived length: a list and a count that disagree is how FU5's
/// "three audited actions" survived alongside twelve.
#[sqlx::test(migrations = "../secureprompt-api/migrations")]
async fn the_documented_action_list_matches_the_database(pool: PgPool) -> sqlx::Result<()> {
    let doc = doc_text();

    const MARKER: &str = "**Audited, and therefore in this export**";
    let start = doc
        .find(MARKER)
        .expect("§7 must state which actions are audited");
    let block = &doc[start..];
    let end = block
        .find("\n\n")
        .expect("the audited-action list must end at a paragraph break");
    let block = &block[..end];

    let declared: usize = block
        .split('(')
        .nth(1)
        .and_then(|after| after.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .expect("§7 must state the count as `(N actions)`");
    let mut documented = backticked(block);
    documented.sort_unstable();
    documented.dedup();

    let mut expected = audited_actions(&pool).await?;
    // PREMISE: the constraint exists and is populated. An empty vocabulary
    // would make the comparison below pass against an empty document.
    assert!(
        expected.len() >= 12,
        "premise: `admin_audit_action_known` must declare the audited actions, \
         found {}",
        expected.len()
    );
    for event in [
        EVENT_RAW_CAPTURE_CHANGED,
        EVENT_RETENTION_PURGE,
        EVENT_SESSION_REVOKED,
    ] {
        expected.push(event.to_owned());
    }
    expected.sort_unstable();
    expected.dedup();

    assert!(
        !documented.is_empty(),
        "premise: no actions were parsed out of §7's list"
    );
    assert_eq!(
        documented,
        expected,
        "§7's audited-action list has drifted from the database. An auditor \
         reads that list as the complete set of administrative actions this \
         artifact can carry.\n  documented but not audited: {:?}\n  audited but \
         not documented: {:?}",
        documented
            .iter()
            .filter(|a| !expected.contains(a))
            .collect::<Vec<_>>(),
        expected
            .iter()
            .filter(|a| !documented.contains(a))
            .collect::<Vec<_>>(),
    );
    assert_eq!(
        declared,
        expected.len(),
        "§7 says `({declared} actions)` but names {} — the count and the list \
         must not drift apart",
        expected.len()
    );

    Ok(())
}

/// The two anchors under §3.2 that introduce the per-`event_type` `detail`
/// key tables. Two tables rather than one because the second is scoped to
/// `admin_audit` events, which carry three extra merged keys.
const DETAIL_TABLE_ANCHORS: [&str; 2] =
    ["`detail` keys, per `event_type`:", "event-specific keys:"];

/// Every `event_type` §3.2's `detail` tables give a row to, and the keys each
/// row names.
fn documented_detail_rows(doc: &str) -> Vec<(String, Vec<String>)> {
    let mut rows = Vec::new();
    for anchor in DETAIL_TABLE_ANCHORS {
        for cells in table_rows(doc, anchor) {
            assert!(
                cells.len() >= 2,
                "a `detail` key table row must have an event type and a key list, got {cells:?}"
            );
            rows.push((unbacktick(&cells[0]), backticked(&cells[1])));
        }
    }
    rows
}

/// **§3.2's `detail` tables must cover every action the product audits.**
///
/// The same derivation as [`the_documented_action_list_matches_the_database`],
/// pointed at the other list in the document. §7 says WHICH actions reach the
/// artifact; §3.2 says WHAT each one carries, and an auditor reading a `detail`
/// object for an event §3.2 does not name has nothing to interpret it with.
///
/// One row per event type is required — no globs, no combined rows. That is not
/// a formatting preference: `provider_credential.created` and
/// `.updated` do not carry the same keys, and neither do `policy_rule.created`
/// and `.deleted`, so a row covering several event types at once can only be
/// right about one of them.
#[sqlx::test(migrations = "../secureprompt-api/migrations")]
async fn the_documented_detail_tables_cover_every_audited_action(pool: PgPool) -> sqlx::Result<()> {
    let doc = doc_text();

    let mut documented: Vec<String> = documented_detail_rows(&doc)
        .into_iter()
        .map(|(event, _)| event)
        .collect();
    // PREMISE: the tables were found and parsed. An empty list would make the
    // comparison below "pass" against an empty vocabulary.
    assert!(
        documented.len() >= 12,
        "premise: §3.2's `detail` tables parsed to {} rows",
        documented.len()
    );
    let before_dedup = documented.len();
    documented.sort_unstable();
    documented.dedup();
    assert_eq!(
        documented.len(),
        before_dedup,
        "§3.2's `detail` tables name an event type twice"
    );

    let mut expected = audited_actions(&pool).await?;
    assert!(
        expected.len() >= 12,
        "premise: `admin_audit_action_known` must declare the audited actions, \
         found {}",
        expected.len()
    );
    for event in [
        EVENT_RAW_CAPTURE_CHANGED,
        EVENT_RETENTION_PURGE,
        EVENT_SESSION_REVOKED,
    ] {
        expected.push(event.to_owned());
    }
    expected.sort_unstable();

    assert_eq!(
        documented,
        expected,
        "§3.2's `detail` tables have drifted from the audited vocabulary.\n  \
         documented but not audited: {:?}\n  audited but NOT given a `detail` \
         row: {:?}",
        documented
            .iter()
            .filter(|a| !expected.contains(a))
            .collect::<Vec<_>>(),
        expected
            .iter()
            .filter(|a| !documented.contains(a))
            .collect::<Vec<_>>(),
    );
    Ok(())
}

/// **§3.2's `detail` claims, read off a real export.**
///
/// The three per-event source tables are rendered by the exporter itself, so
/// what they carry is checkable end to end: seed one row in each, export, and
/// read the keys back out of the signed bytes. `admin_audit`'s `detail` is
/// stored by the API rather than built here, so what is checkable from this
/// side is the claim §3.2 makes about EVERY such row — that the exporter merges
/// `target_type`, `target_id` and `target_label` into it — and that the
/// exporter does not merge them into the other three sources' rows.
#[sqlx::test(migrations = "../secureprompt-api/migrations")]
async fn the_documented_detail_keys_match_a_real_export(pool: PgPool) -> sqlx::Result<()> {
    let doc = doc_text();
    let documented = documented_detail_rows(&doc);
    let workspace_id = Uuid::new_v4();
    let produced = produce_real_export(&pool, workspace_id, "jsonl").await?;
    let rows = section_objects(&produced.manifest, &produced.pages, SECTION_CONTROL_PLANE);
    assert!(
        !rows.is_empty(),
        "premise: the export carries no control-plane rows to read"
    );

    // ── The three the exporter builds itself.
    for event in [
        EVENT_RAW_CAPTURE_CHANGED,
        EVENT_RETENTION_PURGE,
        EVENT_SESSION_REVOKED,
    ] {
        let row = rows
            .iter()
            .find(|r| r["event_type"].as_str() == Some(event))
            .unwrap_or_else(|| panic!("premise: the export must carry a `{event}` row"));
        let mut actual: Vec<String> = row["detail"]
            .as_object()
            .unwrap_or_else(|| panic!("`{event}`'s detail must be a JSON object"))
            .keys()
            .cloned()
            .collect();
        let mut claimed = documented
            .iter()
            .find(|(name, _)| name == event)
            .unwrap_or_else(|| panic!("§3.2 must give `{event}` a row"))
            .1
            .clone();
        actual.sort_unstable();
        claimed.sort_unstable();
        assert_eq!(
            actual, claimed,
            "§3.2's `detail` keys for `{event}` do not match what the export \
             actually carries"
        );
    }

    // ── The merge §3.2 claims for every `admin_audit` event.
    const MERGED: [&str; 3] = ["target_type", "target_id", "target_label"];
    let admin: Vec<&Value> = rows
        .iter()
        .filter(|r| r["source_table"].as_str() == Some("admin_audit"))
        .collect();
    assert_eq!(
        admin.len(),
        SEEDED_ADMIN_ACTIONS.len(),
        "premise: every seeded `admin_audit` row must have reached the export"
    );
    for row in &admin {
        let detail = row["detail"].as_object().expect("detail is a JSON object");
        for key in MERGED {
            assert!(
                detail.contains_key(key),
                "§3.2 says every `admin_audit` event carries `{key}` merged into \
                 `detail`; `{}` does not",
                row["event_type"]
            );
        }
    }

    // POSITIVE CONTROL, and the differential the claim implies: the merge is
    // scoped to `admin_audit`. If the other three sources' rows carried these
    // keys too, the assertion above would pass for a reason that has nothing to
    // do with the code it is describing.
    for row in rows
        .iter()
        .filter(|r| r["source_table"].as_str() != Some("admin_audit"))
    {
        let detail = row["detail"].as_object().expect("detail is a JSON object");
        for key in MERGED {
            assert!(
                !detail.contains_key(key),
                "`{}` is not an `admin_audit` event, so §3.2's merge claim does \
                 not cover it, yet its `detail` carries `{key}`",
                row["event_type"]
            );
        }
    }

    Ok(())
}

/// **§1's section table, §3's column tables, §5's `REQUIRED_SECTIONS`, §8's
/// schema version and §2's limits — all derived from the implementation.**
///
/// Pure: no database, no Python, so it runs in the ordinary gate. Every value
/// checked here is one that has already rotted at least once in this
/// document's history.
#[test]
fn the_documented_shape_matches_the_implementation() {
    let doc = doc_text();
    let verifier = extract_verifier(&doc);

    // §5's own REQUIRED_SECTIONS literal, which is what an auditor's verifier
    // refuses on.
    let literal = verifier
        .lines()
        .find(|l| l.starts_with("REQUIRED_SECTIONS"))
        .expect("the verifier must declare REQUIRED_SECTIONS");
    assert_eq!(
        backticked(&literal.replace('"', "`")),
        REQUIRED_SECTIONS
            .iter()
            .map(|s| (*s).to_owned())
            .collect::<Vec<_>>(),
        "the verifier's REQUIRED_SECTIONS has drifted from \
         `audit_export::REQUIRED_SECTIONS`"
    );

    // §1's section table: names, planes, and the relations each reads from.
    let sections = table_rows(&doc, "| Section | Plane | Store | Source relations |");
    assert_eq!(sections.len(), REQUIRED_SECTIONS.len(), "§1 section count");
    assert_eq!(
        sections
            .iter()
            .map(|r| unbacktick(&r[0]))
            .collect::<Vec<_>>(),
        REQUIRED_SECTIONS,
        "§1's section names have drifted"
    );
    assert_eq!(
        sections
            .iter()
            .map(|r| unbacktick(&r[1]))
            .collect::<Vec<_>>(),
        vec![PLANE_DATA, PLANE_CONTROL],
        "§1's plane names have drifted"
    );
    assert_eq!(
        backticked(&sections[0][3]),
        vec![SOURCE_TABLE],
        "§1 names the wrong data-plane source relation"
    );
    assert_eq!(
        backticked(&sections[1][3]),
        CONTROL_SOURCE_TABLES
            .iter()
            .map(|s| (*s).to_owned())
            .collect::<Vec<_>>(),
        "§1's control-plane source relations have drifted from \
         `CONTROL_SOURCE_TABLES`"
    );

    // §3.1 / §3.2 column tables, in order — the manifest carries these too, so
    // a drift here is a drift between two published descriptions of one file.
    for (anchor, columns) in [
        ("### 3.1 Section `request_events`", REQUEST_COLUMNS),
        ("### 3.2 Section `control_plane_events`", CONTROL_COLUMNS),
    ] {
        let documented: Vec<String> = table_rows(&doc, anchor)
            .iter()
            .map(|r| unbacktick(&r[0]))
            .collect();
        assert_eq!(
            documented,
            columns
                .iter()
                .map(|(name, _)| (*name).to_owned())
                .collect::<Vec<_>>(),
            "the column table under `{anchor}` has drifted"
        );
    }

    // §5 and §8 must name the same schema version the code emits.
    assert!(
        verifier.contains(&format!("m[\"schema_version\"] != {SCHEMA_VERSION}")),
        "the verifier refuses a schema version other than {SCHEMA_VERSION}, \
         which is what `build_manifest` writes"
    );
    let flat = flatten(&doc);
    assert!(
        flat.contains(&format!(
            "This document describes **version {SCHEMA_VERSION}**"
        )),
        "§8 must describe schema version {SCHEMA_VERSION}"
    );

    // §2's and §7's numbers. Every one of these is a figure the document
    // states in prose and the code enforces in a constant.
    assert!(
        flat.contains(&format!(
            "`page_size` defaults to {DEFAULT_PAGE_SIZE} and may be between \
             {MIN_PAGE_SIZE} and {MAX_PAGE_SIZE}"
        )),
        "§2's page_size limits have drifted from DEFAULT/MIN/MAX_PAGE_SIZE \
         ({DEFAULT_PAGE_SIZE}/{MIN_PAGE_SIZE}/{MAX_PAGE_SIZE})"
    );
    assert!(
        flat.contains(&format!("**{SOURCE_TTL_DAYS}-day TTL**")),
        "§7 must state `request_events`' TTL as {SOURCE_TTL_DAYS} days"
    );
    // The document spells the cap with a thin-space group separator, the way a
    // reader wants it; the constant is the same number.
    let capped = MAX_EXPORT_ROWS.to_string();
    let grouped = format!(
        "{} {}",
        &capped[..capped.len() - 3],
        &capped[capped.len() - 3..]
    );
    assert!(
        flat.contains(&format!("more than {grouped} rows")),
        "§7's row cap has drifted from MAX_EXPORT_ROWS ({MAX_EXPORT_ROWS})"
    );
}
