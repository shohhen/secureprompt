//! The structural seam, second axis: arming `app.current_workspace_id` and
//! VERIFYING it took may not be separated.
//!
//! # What this guards that `tests/rls_call_site_guard.rs` does not
//!
//! That file asks "is this statement on a transaction?". This one asks "did
//! anyone check that the transaction is actually armed?". They are different
//! questions and a site can pass the first while failing the second: a
//! `pool.begin()` followed by a bare `set_config` produces a transaction, so
//! the bare-pool scan is satisfied, and nothing anywhere establishes that the
//! setting took.
//!
//! # Why the second question started to matter
//!
//! Migration 033 rewrote fifteen `workspace_isolation` policies with `NULLIF`,
//! so an unscoped read of an armed table is now INVISIBLE — zero rows, no
//! exception — instead of raising `22P02` on a connection that had previously
//! served a scoped transaction. That is the semantics `001_init.sql` intended
//! and it is the right change. It also removed an ACCIDENTAL backstop: before
//! 033, a mis-scoped read on a recycled pooled connection would sometimes
//! shout. Now it never does.
//!
//! `db::scope::begin_scoped` is what replaced that accident with a control. It
//! sets the GUC and READS IT BACK inside the same transaction, so an unarmed
//! tenancy scope is a RECORDED FAILURE rather than a silent empty success.
//! What it cannot do is make anyone use it — and at the time this guard was
//! written, twenty-nine statements in eight files did the `set_config` by hand
//! with no read-back anywhere.
//!
//! The consequence is not hypothetical on this branch. A silent zero has
//! already produced a migration that no-op'd while reporting success, a
//! retention purge that skips plaintext while reporting `ok`, and an API-key
//! rotation sweep that never revokes. Two of the hand-rolled sites sit on the
//! same shape:
//!
//!   * `PolicyRepository::list_rules` feeds `policy::engine::evaluate` through
//!     `list_enabled_rules`. An empty list is not an error there — it is "this
//!     workspace has no rules", and the engine redacts nothing.
//!   * `BudgetRepository::get` resolves "no row" to `None`, which is "no spend
//!     limit configured".
//!
//! Both read as a deliberate configuration choice. Neither raises.
//!
//! # The invariant, stated before it is asserted
//!
//! Every `set_config('app.current_workspace_id', …)` in application code must
//! be FOLLOWED, within [`READBACK_WINDOW`] lines, by either a
//! `current_setting('app.current_workspace_id', …)` read-back or a call to a
//! helper that performs one (`scope_is_armed`). Arming and verifying travel
//! together or the site is not a seam.
//!
//! This is deliberately a PROXIMITY rule and not a per-file allowlist with
//! exact counts. An allowlist pins the shape of code in three crates, two of
//! which this change does not own, and it would go red on a correct refactor
//! that merely moved a seam. The proximity rule goes red on exactly one thing:
//! an arming with no verification near it.
//!
//! # Known limit, stated rather than discovered later
//!
//! The scan is textual. It can be defeated by assembling the GUC name from
//! fragments, and it cannot tell a read-back that is on the success path from
//! one behind a branch that never runs. It is a supplement to
//! `begin_scoped`'s runtime check, not a replacement.
//! [`the_detector_actually_detects`] is the positive control that keeps the
//! scanner itself honest — without it, a scan that matched nothing would make
//! this gate green and silent, which is the exact failure mode it exists to
//! prevent, one level up.

use std::path::{Path, PathBuf};

/// The GUC every `workspace_isolation` policy in this schema reads.
const SCOPE_GUC: &str = "app.current_workspace_id";

/// Lines after an arming within which its verification must appear.
///
/// MEASURED against the four seams that exist, so the window is derived rather
/// than guessed: `db::scope::arm_scope` sets at its line 1 and calls
/// `scope_is_armed` 5 lines later; `tasks::api_key_rotation::begin_scoped` and
/// `tasks::retention_purge::begin_scoped` read back 5 lines later;
/// `tasks::audit_export::begin_scoped` — the widest — 18 lines later, because
/// the read-back is a separate `scope_is_armed` fn call after a `map_err`
/// chain. 25 leaves headroom for a `.map_err` that grows a line without
/// admitting a site that arms at the top of a function and checks at the
/// bottom.
const READBACK_WINDOW: usize = 25;

/// An arming of the tenancy GUC with no verification within
/// [`READBACK_WINDOW`] lines of it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct UnverifiedArming {
    file: String,
    line: usize,
}

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is <root>/secureprompt-api.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("secureprompt-api must have a parent directory")
        .to_path_buf()
}

fn rs_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// Find every arming of [`SCOPE_GUC`] that is not verified within
/// [`READBACK_WINDOW`] lines.
///
/// Shared by the real scan and by [`the_detector_actually_detects`], so the
/// positive control exercises the same code the gate runs.
fn scan(source: &str, file: &str) -> Vec<UnverifiedArming> {
    // Unit tests live behind `#[cfg(test)]` and are not application paths.
    // Their fixtures arm the scope deliberately to set up the very condition
    // the application code must never be in.
    let body = match source.find("\n#[cfg(test)]") {
        Some(cut) => &source[..cut],
        None => source,
    };
    let lines: Vec<&str> = body.lines().collect();

    let arms = |line: &str| line.contains("set_config") && line.contains(SCOPE_GUC);
    // Either the read-back itself, or a call to the helper that performs one.
    // `scope_is_armed` is named rather than matched loosely because it is the
    // ONLY helper in this workspace whose contract is "the GUC reads back as
    // this value or you get an error" — `db::scope::scope_is_armed` and the
    // worker's private copies of it.
    let verifies = |line: &str| {
        (line.contains("current_setting") && line.contains(SCOPE_GUC))
            || line.contains("scope_is_armed")
    };

    let mut found = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        if !arms(line) {
            continue;
        }
        // A doc comment or a `//` note that merely NAMES the call is prose, not
        // an arming. Several of these files explain the pattern at length.
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with("*") {
            continue;
        }
        let end = usize::min(idx + READBACK_WINDOW, lines.len().saturating_sub(1));
        let verified = lines[idx..=end].iter().any(|l| verifies(l));
        if !verified {
            found.push(UnverifiedArming {
                file: file.to_owned(),
                line: idx + 1,
            });
        }
    }
    found
}

// ===========================================================================
// The gate
// ===========================================================================

/// THE GATE. No application path may arm the tenancy scope without verifying
/// it took.
///
/// A plain `#[test]`, not `#[sqlx::test]`: this claim is about source text and
/// needs no database. Making it DB-backed would make it slower and would give
/// it a way to be skipped.
#[test]
fn no_application_path_arms_the_tenancy_scope_without_reading_it_back() {
    let root = repo_root();
    let mut armings = 0_usize;
    let mut unverified: Vec<UnverifiedArming> = Vec::new();

    for crate_dir in [
        "secureprompt-api/src",
        "secureprompt-worker/src",
        "secureprompt-mcp/src",
    ] {
        for path in rs_files(&root.join(crate_dir)) {
            let rel = path
                .strip_prefix(&root)
                .expect("scanned paths are under the repo root")
                .to_string_lossy()
                .replace('\\', "/");
            // Test modules are not application paths, on the same rule
            // `rls_call_site_guard.rs` uses.
            if rel.contains("/tests/") || rel.ends_with("_tests.rs") || rel.ends_with("/tests.rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).expect("readable source file");
            armings += source
                .lines()
                .filter(|l| {
                    let t = l.trim_start();
                    !t.starts_with("//")
                        && !t.starts_with('*')
                        && l.contains("set_config")
                        && l.contains(SCOPE_GUC)
                })
                .count();
            unverified.extend(scan(&source, &rel));
        }
    }

    // PREMISE. If the scan found no armings at all — a moved crate, a renamed
    // GUC, a read that silently failed — every claim below would be true of
    // nothing. There are four seams in this workspace and there must be at
    // least the one in `db::scope`.
    assert!(
        armings >= 4,
        "premise: the scanner found {armings} armings of `{SCOPE_GUC}` in \
         application code. There are four seams (db::scope::arm_scope and the \
         worker's audit_export / api_key_rotation / retention_purge copies), \
         so fewer than four means the scanner is broken, not the code."
    );

    let report: Vec<String> = unverified
        .iter()
        .map(|a| format!("  {}:{}", a.file, a.line))
        .collect();
    assert!(
        unverified.is_empty(),
        "{} statement(s) arm `{SCOPE_GUC}` and never check that it took:\n{}\n\n\
         Since migration 033 an unscoped read of an armed table returns the \
         EMPTY SET and raises nothing, and zero rows is a plausible answer to \
         almost every question this product asks — `PolicyRepository::list_rules` \
         answers it to the redaction engine, `BudgetRepository::get` answers it \
         to the spend limiter. Route the transaction through \
         `db::scope::begin_scoped` (or `arm_scope`, when the workspace is \
         created inside the same transaction), so the scope that did not arm \
         is a recorded failure instead of a quiet nothing.",
        unverified.len(),
        report.join("\n")
    );
}

/// POSITIVE CONTROL for the scanner. The three halves must DIFFER, or the gate
/// above is measuring nothing.
#[test]
fn the_detector_actually_detects() {
    // FLAGGED: the hand-rolled shape this change exists to remove.
    let hand_rolled = r#"
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
            .bind(workspace_id.to_string())
            .execute(&mut *tx)
            .await?;
        let rows = sqlx::query("SELECT id FROM policy_rules WHERE workspace_id = $1")
            .bind(workspace_id.0)
            .fetch_all(&mut *tx)
            .await?;
    "#;
    let hits = scan(hand_rolled, "synthetic.rs");
    assert_eq!(
        hits.len(),
        1,
        "the scanner must flag an arming with no read-back, got {hits:?}"
    );

    // NEGATIVE CONTROL 1 — the seam itself: arm, then verify via the helper.
    // Must NOT be flagged, or `db::scope` could never satisfy its own gate.
    let seam = r#"
        sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
            .bind(workspace_id.to_string())
            .execute(&mut **tx)
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?;
        scope_is_armed(tx, workspace_id).await
    "#;
    assert!(
        scan(seam, "synthetic.rs").is_empty(),
        "an arming followed by `scope_is_armed` is the seam and must not be flagged"
    );

    // NEGATIVE CONTROL 2 — an inline read-back, the worker's shape.
    let inline = r#"
        sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
            .bind(workspace_id.to_string())
            .execute(&mut *tx)
            .await?;
        let armed: Option<String> =
            sqlx::query_scalar("SELECT current_setting('app.current_workspace_id', true)")
                .fetch_one(&mut *tx)
                .await?;
    "#;
    assert!(
        scan(inline, "synthetic.rs").is_empty(),
        "an arming followed by an inline `current_setting` read-back must not be flagged"
    );

    // NEGATIVE CONTROL 3 — PROSE. Half a dozen files in this workspace explain
    // the pattern in doc comments. Flagging those would make the gate a
    // nuisance that gets deleted.
    let prose = r#"
        /// `true` on `set_config('app.current_workspace_id', …)` makes the
        /// setting local to this transaction.
        // Equivalent to `SET LOCAL app.current_workspace_id = $1`, but safe.
    "#;
    assert!(
        scan(prose, "synthetic.rs").is_empty(),
        "a comment naming set_config('app.current_workspace_id') is prose, not an arming"
    );

    // FLAGGED, and the reason `verifies` filters comments the way `arms`
    // already does. PROSE CANNOT VERIFY.
    //
    // MEASURED, not imagined: a reviewer deleted the real
    // `scope_is_armed(tx, workspace_id).await` from `db::scope::arm_scope` —
    // the gate went RED, naming `db/scope.rs:107` — then added exactly the one
    // `//` line below inside the window, and the gate went GREEN. The single
    // compensating control the whole 033 sweep is justified by was gone and
    // the guard that exists to prove it is present said nothing. A guard that
    // a comment can switch off is not a guard.
    //
    // This is the same asymmetry, one level up, that the gate itself measures:
    // naming a check is not performing one.
    let commented_away = r#"
        sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
            .bind(workspace_id.to_string())
            .execute(&mut **tx)
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?;
        // NOTE: the value is verified by reading
        // current_setting('app.current_workspace_id', true) — see scope_is_armed.
        Ok(())
    "#;
    assert_eq!(
        scan(commented_away, "synthetic.rs").len(),
        1,
        "an arming whose only verification is a COMMENT naming \
         current_setting/scope_is_armed must still be flagged"
    );

    // NEGATIVE CONTROL 4 — DISTANCE. A read-back far below the arming does not
    // count, or the rule would be satisfied by any file that happens to
    // contain both tokens anywhere.
    let far = format!(
        "sqlx::query(\"SELECT set_config('app.current_workspace_id', $1, true)\")\n{}\
         let armed = sqlx::query_scalar(\"SELECT current_setting('app.current_workspace_id', true)\");\n",
        "    // filler\n".repeat(READBACK_WINDOW + 5)
    );
    assert_eq!(
        scan(&far, "synthetic.rs").len(),
        1,
        "a read-back more than {READBACK_WINDOW} lines below the arming must not satisfy the rule"
    );
}
