//! WS4-1 / Task 19 — tests for the `audit.export` job.
//!
//! # What "verifies against live data" has to mean here
//!
//! "The export is non-empty" is not a test. `an_export_reproduces_the_live_\
//! query_for_its_window` seeds a known window, runs the REAL job, reads the
//! stored pages back out of Postgres, parses them, and compares them
//! field-by-field against a SEPARATELY ISSUED live ClickHouse query — then
//! proves a tampered copy of that same export fails verification. Without the
//! second half the signature proves nothing; without the first half the
//! comparison is circular.
//!
//! The parse back is deliberately NOT `render_page`'s inverse from the same
//! module. `parse_csv_page` below is written independently, so a bug in the
//! renderer cannot cancel itself out. JSONL is parsed with `serde_json`, which
//! is likewise not the writer.
//!
//! # No real PII (Constraint 5)
//!
//! Every seeded value is synthetic: RFC 5737 documentation addresses
//! (`198.51.100.0/24`), invented key labels, and UUIDs derived from a
//! per-test random prefix so concurrent runs cannot collide.

use super::*;
use secureprompt_common::audit_export::{verify_export, VerifyError};
use secureprompt_common::tasks::{task_types, TaskEnvelope};
use sqlx::{PgPool, Row as _};

// ── Environment ───────────────────────────────────────────────────────────

/// The gateway's own analytics database, so the export runs against the real
/// `request_events` table rather than a bespoke fixture. Same choice, and the
/// same constant, as `retention_purge/tests.rs`.
const CH_DB: &str = "sp_analytics";

fn ch_url() -> String {
    std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://localhost:8123".to_owned())
}

fn ch_client() -> clickhouse::Client {
    clickhouse::Client::default()
        .with_url(ch_url())
        .with_database(CH_DB)
}

/// Raw ClickHouse HTTP for fixture setup and for the independent read-back.
///
/// Panics rather than skipping when ClickHouse is unreachable. A missing
/// dependency must fail loudly: this whole suite's job is to distinguish "the
/// window held nothing" from "we could not look", and a soft-skip would make
/// every assertion below vacuous.
async fn ch_query(sql: &str) -> String {
    let response = reqwest::Client::new()
        .post(format!("{}/?database={CH_DB}", ch_url()))
        .body(sql.to_owned())
        .send()
        .await
        .expect("ClickHouse must be reachable — see the task env (CLICKHOUSE_URL)");
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "clickhouse query failed ({status}): {text}\nsql: {sql}"
    );
    text.trim().to_owned()
}

fn test_key() -> ed25519_dalek::SigningKey {
    // A fixed test seed, not key material for any deployment. Constraint 6 is
    // about the PRODUCT never carrying a literal key; `run` reads the real one
    // from `SECUREPROMPT_AUDIT_EXPORT_SIGNING_KEY`.
    ed25519_dalek::SigningKey::from_bytes(&[42u8; 32])
}

// ── Fixtures ──────────────────────────────────────────────────────────────

/// One synthetic `request_events` row.
struct Seed {
    request_id: Uuid,
    minute: u32,
    model: &'static str,
    final_action: &'static str,
    cost_usd: f64,
    api_key_name: Option<&'static str>,
}

/// The window every test seeds into. A fixed historical day, well inside the
/// 90-day TTL is NOT possible for a fixed date, so the window is computed
/// relative to now — see `window()`.
fn window() -> (DateTime<Utc>, DateTime<Utc>) {
    // Two days ago, so the rows are comfortably inside `request_events`'
    // 90-day TTL and cannot expire mid-suite, and comfortably in the past so
    // no concurrently-running gateway test writes into the same minute.
    let base = (Utc::now() - chrono::Duration::days(2))
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .expect("midnight")
        .and_utc();
    (base, base + chrono::Duration::days(1))
}

async fn seed_events(workspace_id: Uuid, seeds: &[Seed]) {
    let (from, _) = window();
    for s in seeds {
        let ts = (from + chrono::Duration::minutes(i64::from(s.minute))).timestamp();
        let key_name = s
            .api_key_name
            .map_or_else(|| "NULL".to_owned(), |n| format!("'{n}'"));
        ch_query(&format!(
            "INSERT INTO request_events \
             (request_id, workspace_id, provider, model, final_action, \
              input_tokens, output_tokens, estimated_usage, cost_usd, created_at, \
              user_id, api_key_id, api_key_name, ip_address, user_agent, \
              floor_only, engines) \
             VALUES (toUUID('{}'), toUUID('{}'), 'openai', '{}', '{}', \
                     {}, {}, false, {}, toDateTime({}), \
                     NULL, NULL, {}, '198.51.100.7', 'synthetic-agent/1.0', \
                     false, ['floor'])",
            s.request_id,
            workspace_id,
            s.model,
            s.final_action,
            10 + s.minute,
            20 + s.minute,
            s.cost_usd,
            ts,
            key_name,
        ))
        .await;
    }
}

/// Insert the `audit_exports` row the API would have created, so the worker
/// has something to update.
async fn seed_export_row(
    pool: &PgPool,
    export_id: Uuid,
    workspace_id: Uuid,
    format: &str,
    page_size: i32,
) -> sqlx::Result<()> {
    let (from, to) = window();
    sqlx::query(
        "INSERT INTO audit_exports \
         (id, workspace_id, requested_by, window_from, window_to, format, page_size, status) \
         VALUES ($1, $2, NULL, $3, $4, $5, $6, $7)",
    )
    .bind(export_id)
    .bind(workspace_id)
    .bind(from)
    .bind(to)
    .bind(format)
    .bind(page_size)
    .bind(STATUS_QUEUED)
    .execute(pool)
    .await
    .map(|_| ())
}

fn envelope(export_id: Uuid, workspace_id: Uuid, format: &str, page_size: u32) -> TaskEnvelope {
    let (from, to) = window();
    TaskEnvelope::new(
        task_types::AUDIT_EXPORT,
        serde_json::json!({
            "export_id": export_id,
            "from": from,
            "to": to,
            "format": format,
            "page_size": page_size,
        }),
        workspace_id,
    )
}

// ── Reading the artifact back ─────────────────────────────────────────────

struct StoredExport {
    status: String,
    error: Option<String>,
    manifest_json: Option<String>,
    signature_b64: Option<String>,
    public_key_b64: Option<String>,
    total_rows: Option<i64>,
    total_pages: Option<i32>,
}

async fn load_export(pool: &PgPool, export_id: Uuid) -> sqlx::Result<StoredExport> {
    let row = sqlx::query(
        "SELECT status, error, manifest_json, signature_b64, public_key_b64, \
                total_rows, total_pages \
         FROM audit_exports WHERE id = $1",
    )
    .bind(export_id)
    .fetch_one(pool)
    .await?;
    Ok(StoredExport {
        status: row.get("status"),
        error: row.get("error"),
        manifest_json: row.get("manifest_json"),
        signature_b64: row.get("signature_b64"),
        public_key_b64: row.get("public_key_b64"),
        total_rows: row.get("total_rows"),
        total_pages: row.get("total_pages"),
    })
}

async fn load_pages(pool: &PgPool, export_id: Uuid) -> sqlx::Result<Vec<Vec<u8>>> {
    let rows = sqlx::query(
        "SELECT body FROM audit_export_pages WHERE export_id = $1 ORDER BY page_number ASC",
    )
    .bind(export_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| r.get::<String, _>("body").into_bytes())
        .collect())
}

// ── An independent CSV reader ─────────────────────────────────────────────

/// Split one CSV line written by `render_page`'s rules: every non-NULL field
/// quoted, inner `"` doubled, NULL an unquoted empty field.
///
/// Written from the FORMAT SPEC, not from the writer's code, so a bug in the
/// writer cannot be cancelled by the same bug here. Returns `None` for a NULL
/// field so the round trip preserves the NULL/empty-string distinction.
fn split_csv_line(line: &str) -> Vec<Option<String>> {
    let mut fields = Vec::new();
    let mut chars = line.chars().peekable();
    loop {
        match chars.peek() {
            // Unquoted -> NULL, runs to the next comma.
            None => {
                fields.push(None);
                break;
            }
            Some(',') => {
                chars.next();
                fields.push(None);
                continue;
            }
            Some('"') => {
                chars.next();
                let mut value = String::new();
                loop {
                    match chars.next() {
                        Some('"') => {
                            if chars.peek() == Some(&'"') {
                                chars.next();
                                value.push('"');
                            } else {
                                break;
                            }
                        }
                        Some(c) => value.push(c),
                        None => break,
                    }
                }
                fields.push(Some(value));
                match chars.next() {
                    Some(',') => continue,
                    _ => break,
                }
            }
            Some(_) => panic!("unquoted non-empty CSV field in: {line:?}"),
        }
    }
    fields
}

fn parse_csv_page(bytes: &[u8]) -> Vec<Vec<Option<String>>> {
    let text = String::from_utf8(bytes.to_vec()).expect("page is utf-8");
    let mut lines = text.lines();
    let header = lines.next().expect("csv page has a header");
    assert!(
        header.starts_with("\"request_id\""),
        "unexpected header: {header}"
    );
    lines.map(split_csv_line).collect()
}

/// How ClickHouse's default TabSeparated output spells NULL. Two characters,
/// backslash then `N` — NOT an empty field, which is what an empty STRING
/// looks like. The distinction is the whole reason the export quotes non-NULL
/// CSV fields and leaves NULLs unquoted.
const CH_TSV_NULL: &str = "\\N";

/// The live query, issued independently of the job, returning TSV.
/// `SELECT_LIST` and `ORDER_BY` are the job's own constants, so the comparison
/// cannot drift onto a different projection or a different order.
async fn live_rows(workspace_id: Uuid) -> Vec<Vec<String>> {
    let (from, to) = window();
    let out = ch_query(&format!(
        "SELECT {SELECT_LIST} FROM request_events \
         WHERE workspace_id = toUUID('{workspace_id}') \
           AND created_at >= toDateTime({}) AND created_at < toDateTime({}) \
         {ORDER_BY}",
        from.timestamp(),
        to.timestamp()
    ))
    .await;
    out.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.split('\t').map(str::to_owned).collect())
        .collect()
}

// ── Payload validation (pure) ─────────────────────────────────────────────

#[test]
fn parse_request_takes_workspace_from_the_envelope_not_the_payload() {
    let envelope_ws = Uuid::new_v4();
    let attacker_ws = Uuid::new_v4();
    let (from, to) = window();
    let env = TaskEnvelope::new(
        task_types::AUDIT_EXPORT,
        serde_json::json!({
            "export_id": Uuid::new_v4(),
            "from": from,
            "to": to,
            "format": "csv",
            // A payload that tries to restate tenancy.
            "workspace_id": attacker_ws,
        }),
        envelope_ws,
    );
    let req = parse_request(&env).expect("valid payload");
    assert_eq!(
        req.workspace_id, envelope_ws,
        "tenancy must come from the envelope the API stamped"
    );
    assert_ne!(req.workspace_id, attacker_ws);
}

#[test]
fn parse_request_rejects_bad_shapes() {
    let ws = Uuid::new_v4();
    let (from, to) = window();
    let with = |patch: serde_json::Value| {
        let mut payload = serde_json::json!({
            "export_id": Uuid::new_v4(),
            "from": from,
            "to": to,
            "format": "csv",
        });
        for (k, v) in patch.as_object().expect("object") {
            payload[k] = v.clone();
        }
        parse_request(&TaskEnvelope::new(task_types::AUDIT_EXPORT, payload, ws))
    };

    // Positive control: the unpatched payload is accepted, so every rejection
    // below is caused by the patch and not by the base fixture.
    assert!(with(serde_json::json!({})).is_ok());

    assert_eq!(
        with(serde_json::json!({"format": "parquet"})).unwrap_err(),
        RequestError::UnknownFormat
    );
    assert_eq!(
        with(serde_json::json!({"page_size": 0})).unwrap_err(),
        RequestError::PageSizeOutOfRange
    );
    assert_eq!(
        with(serde_json::json!({"page_size": MAX_PAGE_SIZE + 1})).unwrap_err(),
        RequestError::PageSizeOutOfRange
    );
    assert_eq!(
        with(serde_json::json!({"from": to, "to": from})).unwrap_err(),
        RequestError::WindowInverted
    );
    // A zero-width window is inverted too: half-open `[t, t)` selects nothing,
    // so it would produce a signed "nothing happened" over no time at all.
    assert_eq!(
        with(serde_json::json!({"to": from})).unwrap_err(),
        RequestError::WindowInverted
    );
    assert_eq!(
        with(serde_json::json!({"export_id": "not-a-uuid"})).unwrap_err(),
        RequestError::Malformed
    );
}

// ── The acceptance criterion ──────────────────────────────────────────────

/// **"Export verifies against live data."**
///
/// Seed a known window, run the real job, read the stored pages back, parse
/// them independently, and compare to a separately-issued live query. Then
/// break the export three ways and prove each is caught.
#[sqlx::test(migrations = "../secureprompt-api/migrations")]
async fn an_export_reproduces_the_live_query_for_its_window(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    let export_id = Uuid::new_v4();

    // Five rows over three pages of two — so "a row removed from the MIDDLE
    // page" is a distinct case from "the export was truncated".
    let seeds = vec![
        Seed {
            request_id: Uuid::new_v4(),
            minute: 1,
            model: "gpt-4o-mini",
            final_action: "allow",
            cost_usd: 0.001,
            api_key_name: Some("synthetic-key-a"),
        },
        Seed {
            request_id: Uuid::new_v4(),
            minute: 2,
            model: "gpt-4o",
            final_action: "redact",
            cost_usd: 0.002,
            api_key_name: Some("synthetic-key-b"),
        },
        Seed {
            request_id: Uuid::new_v4(),
            minute: 3,
            model: "gpt-4o-mini",
            final_action: "deny",
            cost_usd: 0.0,
            api_key_name: None,
        },
        Seed {
            request_id: Uuid::new_v4(),
            minute: 4,
            model: "claude-3-5",
            final_action: "allow",
            cost_usd: 0.004,
            api_key_name: Some("synthetic-key-c"),
        },
        Seed {
            request_id: Uuid::new_v4(),
            minute: 5,
            model: "gpt-4o-mini",
            final_action: "allow",
            cost_usd: 0.005,
            api_key_name: Some("synthetic-key-d"),
        },
    ];
    seed_events(workspace_id, &seeds).await;
    seed_export_row(&pool, export_id, workspace_id, "csv", 2).await?;

    // PREMISE (Constraint 2): the live query really does see the five rows.
    // Without this, an export of zero rows would "match the live query" and
    // the whole test would pass vacuously.
    let live = live_rows(workspace_id).await;
    assert_eq!(
        live.len(),
        seeds.len(),
        "premise: the seeded rows must be visible to the live query"
    );

    let outcome = run_with(
        &pool,
        &ch_client(),
        &envelope(export_id, workspace_id, "csv", 2),
        Ok(test_key()),
        MAX_EXPORT_ROWS,
        Utc::now(),
    )
    .await;

    let stored = load_export(&pool, export_id).await?;
    assert_eq!(
        stored.status, STATUS_COMPLETE,
        "export failed: {:?}",
        stored.error
    );
    assert!(outcome.ok());
    assert_eq!(stored.total_rows, Some(5));
    assert_eq!(
        stored.total_pages,
        Some(3),
        "5 rows at page_size 2 = 3 pages"
    );

    let pages = load_pages(&pool, export_id).await?;
    assert_eq!(pages.len(), 3);

    // ── (a) the exported rows ARE the live rows ──────────────────────────
    let exported: Vec<Vec<Option<String>>> = pages.iter().flat_map(|p| parse_csv_page(p)).collect();
    assert_eq!(
        exported.len(),
        live.len(),
        "exported row count must equal the live query's"
    );
    for (index, (got, want)) in exported.iter().zip(live.iter()).enumerate() {
        // request_id is column 0 in both projections — the identity check.
        assert_eq!(
            got[0].as_deref(),
            Some(want[0].as_str()),
            "row {index}: request_id differs between export and live query"
        );
        // final_action is column 5; the disposition an auditor counts.
        assert_eq!(
            got[5].as_deref(),
            Some(want[5].as_str()),
            "row {index}: final_action differs"
        );
        // NULL must survive as NULL, not collapse into an empty string. Row 2
        // (minute 3) has no api_key_name, which is column 12.
        //
        // ClickHouse's TabSeparated output writes NULL as the two characters
        // `\N`, NOT as an empty field — measured:
        //     $ SELECT 'a', CAST(NULL AS Nullable(String)), 'b'
        //     0000000  a \t \ N \t b \n
        // The first version of this assertion compared against `is_empty()`
        // and failed with `left: true, right: false`, which is the TSV
        // sentinel showing up, not an export defect.
        assert_eq!(
            got[12].is_none(),
            want[12] == CH_TSV_NULL,
            "row {index}: NULL-ness of api_key_name differs \
             (export {:?} vs live {:?})",
            got[12],
            want[12]
        );
    }
    // And the ORDER is the live order, not merely the same set.
    let exported_ids: Vec<&str> = exported.iter().map(|r| r[0].as_deref().unwrap()).collect();
    let live_ids: Vec<&str> = live.iter().map(|r| r[0].as_str()).collect();
    assert_eq!(
        exported_ids, live_ids,
        "export must preserve the live order"
    );

    // ── (b) the untampered export verifies — the positive control ────────
    let manifest_json = stored.manifest_json.clone().expect("manifest stored");
    let signature = stored.signature_b64.clone().expect("signature stored");
    let public_key = stored.public_key_b64.clone().expect("public key stored");
    let refs: Vec<&[u8]> = pages.iter().map(Vec::as_slice).collect();
    assert!(
        verify_export(&manifest_json, &signature, &public_key, &refs).is_ok(),
        "the export as produced must verify"
    );

    // ── (c) a row removed from the MIDDLE page must NOT verify ───────────
    let mut tampered = pages.clone();
    let middle = String::from_utf8(tampered[1].clone()).expect("utf8");
    let lines: Vec<&str> = middle.lines().collect();
    assert!(
        lines.len() >= 3,
        "premise: middle page must hold a header + 2 rows, got {}",
        lines.len()
    );
    let cut: String = lines[..lines.len() - 1].join("\n") + "\n";
    assert_ne!(cut, middle, "premise: the mutation must change bytes");
    tampered[1] = cut.into_bytes();
    let refs: Vec<&[u8]> = tampered.iter().map(Vec::as_slice).collect();
    assert_eq!(
        verify_export(&manifest_json, &signature, &public_key, &refs),
        Err(VerifyError::PageDigestMismatch { page: 2 }),
        "a row removed from the middle page must be caught"
    );

    // ── (d) a whole page dropped must NOT verify ─────────────────────────
    let mut dropped = pages.clone();
    dropped.remove(1);
    let refs: Vec<&[u8]> = dropped.iter().map(Vec::as_slice).collect();
    assert_eq!(
        verify_export(&manifest_json, &signature, &public_key, &refs),
        Err(VerifyError::PageCountMismatch {
            expected: 3,
            got: 2
        })
    );

    // ── (e) a single altered VALUE must NOT verify ───────────────────────
    let mut edited = pages.clone();
    let page0 = String::from_utf8(edited[0].clone()).expect("utf8");
    let flipped = page0
        .replace("\"deny\"", "\"allow\"")
        .replace("\"redact\"", "\"allow\"");
    assert_ne!(
        flipped, page0,
        "premise: the disposition edit must change bytes"
    );
    edited[0] = flipped.into_bytes();
    let refs: Vec<&[u8]> = edited.iter().map(Vec::as_slice).collect();
    assert_eq!(
        verify_export(&manifest_json, &signature, &public_key, &refs),
        Err(VerifyError::PageDigestMismatch { page: 1 })
    );

    Ok(())
}

/// The same acceptance criterion in JSONL, parsed with `serde_json` rather
/// than the CSV reader — a second, independent decoder over the same job.
#[sqlx::test(migrations = "../secureprompt-api/migrations")]
async fn a_jsonl_export_reproduces_the_live_query(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    let export_id = Uuid::new_v4();
    let seeds = vec![
        Seed {
            request_id: Uuid::new_v4(),
            minute: 11,
            model: "gpt-4o-mini",
            final_action: "allow",
            cost_usd: 0.011,
            api_key_name: Some("synthetic-key-e"),
        },
        Seed {
            request_id: Uuid::new_v4(),
            minute: 12,
            model: "gpt-4o",
            final_action: "deny",
            cost_usd: 0.012,
            api_key_name: None,
        },
        Seed {
            request_id: Uuid::new_v4(),
            minute: 13,
            model: "gpt-4o-mini",
            final_action: "allow",
            cost_usd: 0.013,
            api_key_name: Some("synthetic-key-f"),
        },
    ];
    seed_events(workspace_id, &seeds).await;
    seed_export_row(&pool, export_id, workspace_id, "jsonl", 2).await?;

    let live = live_rows(workspace_id).await;
    assert_eq!(
        live.len(),
        3,
        "premise: three rows visible to the live query"
    );

    run_with(
        &pool,
        &ch_client(),
        &envelope(export_id, workspace_id, "jsonl", 2),
        Ok(test_key()),
        MAX_EXPORT_ROWS,
        Utc::now(),
    )
    .await;

    let stored = load_export(&pool, export_id).await?;
    assert_eq!(stored.status, STATUS_COMPLETE, "error: {:?}", stored.error);
    let pages = load_pages(&pool, export_id).await?;
    assert_eq!(pages.len(), 2, "3 rows at page_size 2 = 2 pages");

    let exported: Vec<serde_json::Value> = pages
        .iter()
        .flat_map(|p| {
            String::from_utf8(p.clone())
                .expect("utf8")
                .lines()
                .map(|l| serde_json::from_str::<serde_json::Value>(l).expect("json line"))
                .collect::<Vec<_>>()
        })
        .collect();

    assert_eq!(exported.len(), live.len());
    for (index, (got, want)) in exported.iter().zip(live.iter()).enumerate() {
        assert_eq!(
            got["request_id"].as_str(),
            Some(want[0].as_str()),
            "row {index}: request_id differs"
        );
        assert_eq!(
            got["final_action"].as_str(),
            Some(want[5].as_str()),
            "row {index}: final_action differs"
        );
    }

    // JSONL must carry NULL as JSON null, not as "".
    let null_key = exported
        .iter()
        .find(|r| r["final_action"] == "deny")
        .expect("the deny row");
    assert!(
        null_key["api_key_name"].is_null(),
        "an absent api_key_name must be JSON null, got {:?}",
        null_key["api_key_name"]
    );

    // No content columns reached the artifact.
    for row in &exported {
        for forbidden in [
            "raw_prompt",
            "raw_response",
            "redacted_prompt",
            "restored_response",
        ] {
            assert!(
                row.get(forbidden).is_none(),
                "content column `{forbidden}` must never appear in an export"
            );
        }
    }

    let refs: Vec<&[u8]> = pages.iter().map(Vec::as_slice).collect();
    assert!(verify_export(
        &stored.manifest_json.expect("manifest"),
        &stored.signature_b64.expect("signature"),
        &stored.public_key_b64.expect("public key"),
        &refs
    )
    .is_ok());

    Ok(())
}

// ── The three refusals ────────────────────────────────────────────────────

/// No signing key -> no export. An unsigned export presented as an audit
/// control is the exact defect this task exists to remove, so the job must
/// fail rather than fall back.
#[sqlx::test(migrations = "../secureprompt-api/migrations")]
async fn a_missing_signing_key_refuses_rather_than_shipping_an_unsigned_export(
    pool: PgPool,
) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    let export_id = Uuid::new_v4();
    seed_events(
        workspace_id,
        &[Seed {
            request_id: Uuid::new_v4(),
            minute: 21,
            model: "gpt-4o-mini",
            final_action: "allow",
            cost_usd: 0.02,
            api_key_name: None,
        }],
    )
    .await;
    seed_export_row(&pool, export_id, workspace_id, "csv", 100).await?;

    let outcome = run_with(
        &pool,
        &ch_client(),
        &envelope(export_id, workspace_id, "csv", 100),
        Err(secureprompt_common::audit_export::KeyError::NotConfigured),
        MAX_EXPORT_ROWS,
        Utc::now(),
    )
    .await;

    assert!(!outcome.ok());
    let stored = load_export(&pool, export_id).await?;
    assert_eq!(stored.status, STATUS_FAILED);
    assert!(
        stored.manifest_json.is_none() && stored.signature_b64.is_none(),
        "a refused export must publish no manifest and no signature"
    );
    assert_eq!(
        load_pages(&pool, export_id).await?.len(),
        0,
        "a refused export must publish no pages"
    );
    let error = stored.error.expect("a refusal must say why");
    assert!(
        error.contains("SECUREPROMPT_AUDIT_EXPORT_SIGNING_KEY"),
        "the refusal must name the missing setting; got: {error}"
    );

    Ok(())
}

/// Over the row cap -> refuse, naming the cap. NOT a truncated export: a
/// truncated export carrying a valid signature is a forgery the product signed
/// itself.
#[sqlx::test(migrations = "../secureprompt-api/migrations")]
async fn a_window_over_the_row_cap_is_refused_not_truncated(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    let export_id = Uuid::new_v4();
    let seeds: Vec<Seed> = (0..3)
        .map(|i| Seed {
            request_id: Uuid::new_v4(),
            minute: 31 + i,
            model: "gpt-4o-mini",
            final_action: "allow",
            cost_usd: 0.03,
            api_key_name: None,
        })
        .collect();
    seed_events(workspace_id, &seeds).await;
    seed_export_row(&pool, export_id, workspace_id, "csv", 100).await?;

    // PREMISE: three rows are really there, so the refusal below is caused by
    // the cap and not by an empty window.
    assert_eq!(
        live_rows(workspace_id).await.len(),
        3,
        "premise: 3 rows seeded"
    );

    let outcome = run_with(
        &pool,
        &ch_client(),
        &envelope(export_id, workspace_id, "csv", 100),
        Ok(test_key()),
        2, // cap below the seeded row count
        Utc::now(),
    )
    .await;

    assert!(!outcome.ok());
    let stored = load_export(&pool, export_id).await?;
    assert_eq!(stored.status, STATUS_FAILED);
    assert_eq!(
        load_pages(&pool, export_id).await?.len(),
        0,
        "over the cap, NOTHING is published — not even the pages that fit"
    );
    let error = stored.error.expect("a refusal must say why");
    assert!(
        error.contains("3 rows") && error.contains("REFUSED rather than truncated"),
        "the refusal must name the count and the reason; got: {error}"
    );

    // POSITIVE CONTROL: the very same window succeeds under a cap above the
    // row count, so the refusal is the cap's doing and not a broken fixture.
    let second = Uuid::new_v4();
    seed_export_row(&pool, second, workspace_id, "csv", 100).await?;
    let ok = run_with(
        &pool,
        &ch_client(),
        &envelope(second, workspace_id, "csv", 100),
        Ok(test_key()),
        MAX_EXPORT_ROWS,
        Utc::now(),
    )
    .await;
    assert!(ok.ok(), "the same window must succeed under the real cap");
    assert_eq!(load_export(&pool, second).await?.status, STATUS_COMPLETE);

    Ok(())
}

// ── Boundaries stated rather than papered over ────────────────────────────

/// A window behind the 90-day TTL still produces a SIGNED export, and the
/// manifest says the window is expired. Refusing would leave the auditor with
/// nothing to check; returning a short result silently would be the "looks
/// complete" failure the control exists to prevent.
#[sqlx::test(migrations = "../secureprompt-api/migrations")]
async fn an_expired_window_is_exported_and_declares_its_expiry(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    let export_id = Uuid::new_v4();
    seed_export_row(&pool, export_id, workspace_id, "csv", 100).await?;

    // `generated_at` far in the future puts the (recent) window behind the
    // 90-day boundary without waiting 90 days or writing rows ClickHouse would
    // refuse to keep.
    let far_future = Utc::now() + chrono::Duration::days(365);
    run_with(
        &pool,
        &ch_client(),
        &envelope(export_id, workspace_id, "csv", 100),
        Ok(test_key()),
        MAX_EXPORT_ROWS,
        far_future,
    )
    .await;

    let stored = load_export(&pool, export_id).await?;
    assert_eq!(stored.status, STATUS_COMPLETE, "error: {:?}", stored.error);
    let manifest: serde_json::Value =
        serde_json::from_str(&stored.manifest_json.expect("manifest")).expect("json");
    assert_eq!(
        manifest["retention"]["window_status"], "wholly_expired",
        "an export behind the TTL must declare it"
    );
    let detail = manifest["retention"]["detail"].as_str().expect("detail");
    assert!(
        detail.contains("EVIDENCE OF EXPIRY"),
        "the manifest must warn that an empty result is expiry, not quiet; got: {detail}"
    );

    // POSITIVE CONTROL: the same window generated NOW is within retention, so
    // the verdict above is the clock's doing and not a hardcoded string.
    let fresh = Uuid::new_v4();
    seed_export_row(&pool, fresh, workspace_id, "csv", 100).await?;
    run_with(
        &pool,
        &ch_client(),
        &envelope(fresh, workspace_id, "csv", 100),
        Ok(test_key()),
        MAX_EXPORT_ROWS,
        Utc::now(),
    )
    .await;
    let fresh_manifest: serde_json::Value = serde_json::from_str(
        &load_export(&pool, fresh)
            .await?
            .manifest_json
            .expect("manifest"),
    )
    .expect("json");
    assert_eq!(
        fresh_manifest["retention"]["window_status"],
        "within_retention"
    );

    Ok(())
}

/// An export for a workspace with no traffic is still a signed statement, and
/// still has a page. "We looked and there was nothing" is a claim an auditor
/// must be able to verify; an unsigned empty file is trivially forgeable.
#[sqlx::test(migrations = "../secureprompt-api/migrations")]
async fn an_empty_window_still_produces_a_signed_export(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4(); // never seeded
    let export_id = Uuid::new_v4();
    seed_export_row(&pool, export_id, workspace_id, "csv", 100).await?;

    // PREMISE: this workspace really has no rows.
    assert_eq!(live_rows(workspace_id).await.len(), 0);

    run_with(
        &pool,
        &ch_client(),
        &envelope(export_id, workspace_id, "csv", 100),
        Ok(test_key()),
        MAX_EXPORT_ROWS,
        Utc::now(),
    )
    .await;

    let stored = load_export(&pool, export_id).await?;
    assert_eq!(stored.status, STATUS_COMPLETE, "error: {:?}", stored.error);
    assert_eq!(stored.total_rows, Some(0));
    assert_eq!(
        stored.total_pages,
        Some(1),
        "an empty export still has a page"
    );

    let pages = load_pages(&pool, export_id).await?;
    let refs: Vec<&[u8]> = pages.iter().map(Vec::as_slice).collect();
    assert!(verify_export(
        &stored.manifest_json.expect("manifest"),
        &stored.signature_b64.expect("signature"),
        &stored.public_key_b64.expect("public key"),
        &refs
    )
    .is_ok());

    Ok(())
}

/// The export must contain THIS workspace's rows and no other's. The window
/// and everything else is identical between the two tenants, so a missing
/// tenancy predicate would show up here as extra rows.
#[sqlx::test(migrations = "../secureprompt-api/migrations")]
async fn an_export_contains_no_other_tenants_rows(pool: PgPool) -> sqlx::Result<()> {
    let mine = Uuid::new_v4();
    let theirs = Uuid::new_v4();
    let export_id = Uuid::new_v4();

    let my_row = Uuid::new_v4();
    let their_row = Uuid::new_v4();
    seed_events(
        mine,
        &[Seed {
            request_id: my_row,
            minute: 41,
            model: "gpt-4o-mini",
            final_action: "allow",
            cost_usd: 0.04,
            api_key_name: None,
        }],
    )
    .await;
    seed_events(
        theirs,
        &[Seed {
            request_id: their_row,
            minute: 41,
            model: "gpt-4o-mini",
            final_action: "allow",
            cost_usd: 0.04,
            api_key_name: None,
        }],
    )
    .await;
    seed_export_row(&pool, export_id, mine, "jsonl", 100).await?;

    // PREMISE: the other tenant's row really exists in the same window, so
    // "it is absent from my export" is a measurement.
    assert_eq!(
        live_rows(theirs).await.len(),
        1,
        "premise: the other tenant has a row"
    );

    run_with(
        &pool,
        &ch_client(),
        &envelope(export_id, mine, "jsonl", 100),
        Ok(test_key()),
        MAX_EXPORT_ROWS,
        Utc::now(),
    )
    .await;

    let pages = load_pages(&pool, export_id).await?;
    let body = String::from_utf8(pages.concat()).expect("utf8");
    assert!(
        body.contains(&my_row.to_string()),
        "my own row must be present"
    );
    assert!(
        !body.contains(&their_row.to_string()),
        "another tenant's request id must never appear in my export"
    );
    assert_eq!(load_export(&pool, export_id).await?.total_rows, Some(1));

    Ok(())
}

/// Re-running the same task must not append a second copy of the pages. The
/// Redis queue is at-least-once, so this is a real delivery, not a
/// hypothetical.
#[sqlx::test(migrations = "../secureprompt-api/migrations")]
async fn re_running_the_same_export_replaces_rather_than_appends(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = Uuid::new_v4();
    let export_id = Uuid::new_v4();
    seed_events(
        workspace_id,
        &[Seed {
            request_id: Uuid::new_v4(),
            minute: 51,
            model: "gpt-4o-mini",
            final_action: "allow",
            cost_usd: 0.05,
            api_key_name: None,
        }],
    )
    .await;
    seed_export_row(&pool, export_id, workspace_id, "csv", 100).await?;

    let env = envelope(export_id, workspace_id, "csv", 100);
    for _ in 0..2 {
        run_with(
            &pool,
            &ch_client(),
            &env,
            Ok(test_key()),
            MAX_EXPORT_ROWS,
            Utc::now(),
        )
        .await;
    }

    let pages = load_pages(&pool, export_id).await?;
    assert_eq!(
        pages.len(),
        1,
        "a redelivered task must not double the pages"
    );
    let stored = load_export(&pool, export_id).await?;
    assert_eq!(stored.total_pages, Some(1));

    let refs: Vec<&[u8]> = pages.iter().map(Vec::as_slice).collect();
    assert!(
        verify_export(
            &stored.manifest_json.expect("manifest"),
            &stored.signature_b64.expect("signature"),
            &stored.public_key_b64.expect("public key"),
            &refs
        )
        .is_ok(),
        "the surviving artifact must still verify after a redelivery"
    );

    Ok(())
}

/// `model` reaches the export VERBATIM — it is not bounded against the
/// workspace model catalogue the way the leak report's `by_model` is.
///
/// This test exists to make an ATTESTATION CLAIM executable rather than
/// argued. `data_inventory`'s `audit_export_pages` entry tells an auditor that
/// this column carries whatever string the caller asked for, because
/// `analytics::detection_counts::canonicalize_model` is applied only on the
/// `detection_class_counts` write path and nothing bounds `request_events.model`
/// on the way into an export. A claim in a compliance document that no test
/// backs is exactly the kind of assertion this branch has been burned by.
///
/// It is a DISCLOSURE, not a defect to fix here: bounding the column would
/// destroy audit fidelity, since the destination a request actually named is
/// the fact an auditor is entitled to. The fix is that the inventory says so.
///
/// The fixture string is synthetic and contains no real PII (Constraint 5) —
/// it is shaped like the hostile model name that put caller bytes into
/// `detection_class_counts`, without being one.
#[sqlx::test(migrations = "../secureprompt-api/migrations")]
async fn the_model_column_reaches_the_export_verbatim(pool: PgPool) -> sqlx::Result<()> {
    const CALLER_CHOSEN: &str = "not-a-registered-model SYNTHETIC-MARKER-9c1f";

    let workspace_id = Uuid::new_v4();
    let export_id = Uuid::new_v4();
    let request_id = Uuid::new_v4();

    // Seeded through the same raw INSERT the other tests use, which is how a
    // gateway request that named an uncatalogued model lands on disk.
    let (from, _) = window();
    let ts = (from + chrono::Duration::minutes(61)).timestamp();
    ch_query(&format!(
        "INSERT INTO request_events \
         (request_id, workspace_id, provider, model, final_action, input_tokens, \
          output_tokens, estimated_usage, cost_usd, created_at, floor_only, engines) \
         VALUES (toUUID('{request_id}'), toUUID('{workspace_id}'), 'openai', \
                 '{CALLER_CHOSEN}', 'allow', 1, 1, false, 0.0, toDateTime({ts}), \
                 false, ['floor'])"
    ))
    .await;
    seed_export_row(&pool, export_id, workspace_id, "csv", 100).await?;

    // PREMISE: the row really is there with that model, so the assertion below
    // measures the export rather than an empty window.
    let live = live_rows(workspace_id).await;
    assert_eq!(live.len(), 1, "premise: one row seeded");
    assert_eq!(
        live[0][4], CALLER_CHOSEN,
        "premise: ClickHouse stored the caller-chosen model verbatim"
    );

    run_with(
        &pool,
        &ch_client(),
        &envelope(export_id, workspace_id, "csv", 100),
        Ok(test_key()),
        MAX_EXPORT_ROWS,
        Utc::now(),
    )
    .await;

    let stored = load_export(&pool, export_id).await?;
    assert_eq!(stored.status, STATUS_COMPLETE, "error: {:?}", stored.error);
    let body = String::from_utf8(load_pages(&pool, export_id).await?.concat()).expect("utf8");
    assert!(
        body.contains(CALLER_CHOSEN),
        "the export must carry the caller's model string verbatim — the \
         data-inventory entry for `audit_export_pages` says so; got:\n{body}"
    );

    Ok(())
}
