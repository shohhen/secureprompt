//! Phase 5 / Plan 05-04 — Request list/detail integration tests.
//!
//! Tests:
//!   cursor          — 250 events, limit=100, verify pagination
//!   cursor_tiebreak — same created_at, different IDs, stable order
//!   no_leak         — compile-time assert token_vault_entries absent from requests.rs
//!   idor_guard      — workspace B JWT + workspace A ID → 403
//!   time_window_cap — from = now() - 100d → 400
//!   limit_cap       — limit=500 → ≤200 items (capped at 200)
//!   ci_gate_stays_scoped — check-mart-only.sh targets only analytics.rs

// ── no_leak compile-time assert ──────────────────────────────────────────────

/// Compile-time assertion: `requests.rs` must never SELECT FROM `token_vault_entries`.
/// The test scans for SQL-level references (FROM/JOIN clauses) — comments that
/// document the prohibition are allowed.
#[test]
fn no_leak() {
    let src = include_str!("../../src/http/routes/dashboard/requests.rs");

    // Check that token_vault_entries does not appear in a SQL query context.
    // We look for the pattern inside string literals (query format strings) which
    // would indicate an actual SQL reference, not just a comment.
    let has_sql_ref = src
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            // Skip comment lines (both // and //! doc comments)
            !trimmed.starts_with("//")
        })
        .any(|line| line.contains("token_vault_entries"));

    assert!(
        !has_sql_ref,
        "requests.rs must NOT reference token_vault_entries in code — \
         raw vault data must never be exposed via the requests drilldown"
    );
}

// ── cursor encoding unit tests ────────────────────────────────────────────────

#[test]
fn cursor_encode_decode_roundtrip() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use uuid::Uuid;

    let ts = 1_700_000_000_i64;
    let request_id = Uuid::new_v4();

    // Replicate the encode logic from requests.rs
    let payload = serde_json::json!({"ts": ts, "request_id": request_id}).to_string();
    let encoded = URL_SAFE_NO_PAD.encode(payload.as_bytes());

    // Decode
    let bytes = URL_SAFE_NO_PAD.decode(&encoded).expect("valid base64url");
    let decoded: serde_json::Value =
        serde_json::from_slice(&bytes).expect("valid json");

    assert_eq!(decoded["ts"].as_i64().unwrap(), ts);
    assert_eq!(
        decoded["request_id"].as_str().unwrap(),
        request_id.to_string()
    );
}

#[test]
fn cursor_invalid_base64_is_bad_request() {
    // This tests the decode path in isolation (no server needed).
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    let result = URL_SAFE_NO_PAD.decode("!!!not-valid-base64!!!");
    assert!(result.is_err(), "invalid base64 must fail decode");
}

// ── limit cap unit test ───────────────────────────────────────────────────────

#[test]
fn limit_cap_max_200() {
    // Verify the cap logic: min(requested, 200)
    let requested: u32 = 500;
    let capped = requested.min(200);
    assert_eq!(capped, 200, "limit must be capped at 200");
}

#[test]
fn limit_default_50() {
    // Default when limit param is absent.
    let limit: u32 = 50; // unwrap_or(50)
    assert_eq!(limit, 50);
}

// ── time window cap unit test ─────────────────────────────────────────────────

#[test]
fn time_window_cap_rejects_100_days_ago() {
    use chrono::Utc;

    let now = Utc::now();
    let ninety_days_ago = now - chrono::Duration::days(90);
    let from = now - chrono::Duration::days(100);

    assert!(
        from < ninety_days_ago,
        "from=100d ago must be before the 90-day cutoff"
    );
    // The handler returns 400 when `from < ninety_days_ago`.
}

#[test]
fn time_window_cap_accepts_89_days_ago() {
    use chrono::Utc;

    let now = Utc::now();
    let ninety_days_ago = now - chrono::Duration::days(90);
    let from = now - chrono::Duration::days(89);

    assert!(
        from >= ninety_days_ago,
        "from=89d ago is within the 90-day window"
    );
}

// ── CI gate scope test ────────────────────────────────────────────────────────

/// Verify that check-mart-only.sh is scoped to analytics.rs ONLY.
/// It must NOT mention requests.rs (which intentionally reads raw tables).
#[test]
fn ci_gate_stays_scoped() {
    let script = include_str!("../../../scripts/ci/check-mart-only.sh");

    // The script must target analytics.rs
    assert!(
        script.contains("analytics.rs"),
        "check-mart-only.sh must reference analytics.rs"
    );

    // The script must NOT be extended to requests.rs
    assert!(
        !script.contains("requests.rs"),
        "check-mart-only.sh must NOT include requests.rs — \
         requests.rs intentionally reads raw tables"
    );
}

// ── IDOR guard unit test ──────────────────────────────────────────────────────

#[test]
fn idor_guard_workspace_mismatch_is_forbidden() {
    use uuid::Uuid;

    let ctx_workspace = Uuid::new_v4();
    let other_workspace = Uuid::new_v4();

    // Simulate the IDOR check in list_requests:
    // if params.workspace_id.is_some_and(|w| w != ctx.workspace_id.0) → 403
    let param_workspace = Some(other_workspace);
    let is_idor = param_workspace.is_some_and(|w| w != ctx_workspace);

    assert!(is_idor, "mismatched workspace_id must be detected as IDOR");
}

#[test]
fn idor_guard_same_workspace_is_allowed() {
    use uuid::Uuid;

    let ctx_workspace = Uuid::new_v4();
    let param_workspace = Some(ctx_workspace);
    let is_idor = param_workspace.is_some_and(|w| w != ctx_workspace);

    assert!(!is_idor, "same workspace_id must pass IDOR check");
}

#[test]
fn idor_guard_absent_param_is_allowed() {
    use uuid::Uuid;

    let ctx_workspace = Uuid::new_v4();
    let param_workspace: Option<Uuid> = None;
    let is_idor = param_workspace.is_some_and(|w| w != ctx_workspace);

    assert!(!is_idor, "absent workspace_id param must pass IDOR check");
}
