//! The structural seam: no statement may touch an RLS-ARMED table on a bare
//! pool.
//!
//! # Why a guard and not eighteen fixes
//!
//! `db::scope::begin_scoped` sets `app.current_workspace_id` AND reads it back,
//! so a transaction that is not armed fails loudly instead of answering
//! nothing. That is the mitigation. What it cannot do is make anyone USE it.
//!
//! The failure it exists to stop is silent in exactly the places it matters.
//! With the GUC unset, `current_setting(..., true)` is NULL, the
//! `workspace_isolation` predicate is NULL for every row, and:
//!
//!   * a WRITE is rejected — loud, and someone fixes it within the hour;
//!   * a READ returns the EMPTY SET — and zero rows is a plausible answer to
//!     nearly every question this product asks.
//!
//! A query that says `WHERE workspace_id = $1` LOOKS scoped and is not. It
//! reads correctly today only because the compose role is a SUPERUSER and
//! superusers bypass RLS unconditionally. The moment the deployment stops
//! connecting as one, each becomes a silent zero. Remembering `begin_scoped` at
//! eighteen call sites is not a control; this file is.
//!
//! # What it actually checks
//!
//! The armed-table list is READ FROM THE DATABASE
//! (`pg_class.relforcerowsecurity`), never hardcoded. That is the load-bearing
//! choice: a future migration that arms `users` immediately puts every bare-pool
//! `users` query in this crate in front of a reviewer, without anyone
//! remembering to update a list. Sixteen tables are armed as of migration 031.
//!
//! The allowlist below is exact in BOTH directions, like
//! `scripts/ci/fmt-gate.sh`: a new unlisted site fails, and a listed site that
//! no longer exists ALSO fails, so the list can only shrink and cannot rot into
//! a permanent excuse column.
//!
//! # Known limit, stated rather than discovered later
//!
//! The scan is textual — a line-oriented regex over the source, not a parse. It
//! can therefore MISS a statement whose SQL is assembled from fragments or
//! whose executor is aliased through a helper, and it can FLAG something
//! harmless. A false positive costs a reviewer one allowlist line with a
//! reason, which is a prompt for a decision rather than a wrong answer; a false
//! negative is a gap, which is why this guard supplements `begin_scoped`'s
//! runtime read-back rather than replacing it.
//! `the_detector_actually_detects` is the positive control that keeps the
//! scanner itself honest.
//!
//! Two limits were STATED here and were wrong in the same direction, so they
//! are named individually now rather than left inside "the scan is textual":
//!
//!   * MR6 F4 — the executor filter was `contains("tx") || contains("conn")`,
//!     which skipped `&ctx.pool` and `&self.conn_pool`. Closed;
//!     `executor_is_scoped` tests the trailing identifier and
//!     `the_executor_filter_skips_transactions_and_not_pools_that_merely_spell_them`
//!     pins both directions.
//!   * MR5 I-3 — everything after a file's FIRST `#[cfg(test)]` was discarded,
//!     whether or not it introduced a module; three files lost application
//!     source that way, one of them 967 lines. Closed; `strip_test_modules`
//!     removes modules only, and `only_test_modules_are_removed_from_the_scan`
//!     pins it.
//!
//! ONE limit of that family is still OPEN and is not claimed closed: the
//! executor regex is applied PER LINE, so `.fetch_all(\n    &self.pool,\n)`
//! split across lines is invisible. Measured at the tip: the only multi-line
//! `.execute(` calls in application source are `openai.rs:278` and `:379`,
//! which are `PipelineService::execute` and not sqlx, so there is no live false
//! negative — but rustfmt will produce that shape as soon as an executor
//! expression grows past the line budget, and closing it needs a parse rather
//! than a wider regex.

use regex::Regex;
use sqlx::PgPool;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// A statement that touches an armed table on something that is not a
/// transaction.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CallSite {
    file: String,
    table: String,
    line: usize,
}

/// Every bare-pool statement on an armed table that is KNOWN and accepted, with
/// the reason it is accepted. `count` is exact so that adding a second one to
/// the same file fails even though the pair already appears here.
///
/// Entries are of TWO kinds and each says which it is, because conflating them
/// is how an excuse list forms:
///
///   * REAL DEFECT under a non-bypassing role — listed rather than fixed
///     because the fix needs a design decision this change does not own, and
///     listed rather than ignored because the silent zero is a security or
///     privacy failure that raises nothing. The consequence is spelled out so
///     whoever picks it up does not have to re-derive it.
///   * FALSE POSITIVE of the textual scanner — the statement is correctly
///     scoped by construction in a way a line-oriented regex cannot see.
const ALLOWED: &[(&str, &str, usize, &str)] = &[
    // FIXED and therefore GONE, recorded here in prose because the entry
    // itself may not stay: `secureprompt-api/src/db/refresh_token_repo.rs` /
    // `refresh_tokens`, two statements, `rotate`'s pre-lookup and
    // `find_active_by_hash`. Both now run inside
    // `db::scope::begin_refresh_token_probe`, a transaction armed with the
    // token hash that migration 032's `refresh_token_possession` policy admits
    // for SELECT only. `tests/rls_refresh_token_scope.rs` drives both through a
    // NOSUPERUSER/NOBYPASSRLS pool.
    //
    // The entry graded `find_active_by_hash` the severe one because "it is the
    // logout path's best-effort revoke". It is not, and never was: the method
    // has no callers anywhere in the repository and `dashboard::auth::logout`
    // calls `revoke_all_for_user`. The claim came from the method's own doc
    // comment, which was false from `bc2b586`. Logout's revoke was measured
    // under the non-bypassing role BEFORE any fix and was already correct;
    // `logout_revokes_the_refresh_token_under_a_non_bypassing_role` pins it.
    //
    // ALSO FIXED and therefore GONE (P1G): `secureprompt-worker/src/main.rs` /
    // `api_keys`, one statement. It now lives in
    // `secureprompt-worker/src/tasks/api_key_rotation.rs` and runs once per
    // workspace inside a scope-armed, read-back transaction, so nothing of it
    // remains on a bare pool.
    //
    // Its reason string was wrong, and wrong in the direction that stops the
    // next reader looking. It called the site "the worker's startup key-cache
    // warm", a READ that "fails CLOSED", and graded it least severe on that
    // basis. There is no key-cache warm anywhere in the worker: `grep -rn
    // api_keys secureprompt-worker/src` returned that one line and nothing
    // else, and it was a WRITE — the 03:00 rotation-cleanup
    // `UPDATE api_keys SET status = 'revoked'`.
    //
    // Its CONSEQUENCE was wrong too, in both directions, so it is recorded
    // here as measured rather than as argued. Under `SET ROLE
    // secureprompt_runner` the unarmed UPDATE reports `UPDATE 0` and does NOT
    // error, while the armed one reports `UPDATE 1` — so the sweep was a
    // permanent no-op that recorded `record_job(..., ok = true)`. But the
    // rotated key did NOT stay usable: `authenticate_api_key` re-derives the
    // same boundary in its own WHERE (`rotated_at + grace > NOW()`), the exact
    // complement of the sweep's predicate, so the key stops authenticating at
    // the boundary whether the sweep ran or not. Measured on a past-grace
    // 'rotating' row: `authenticates = 0`, against an in-grace control row on
    // the same connection at `1`. What rotted was the RECORD — `status` stayed
    // `'rotating'` and `revoked_at` stayed NULL, so `GET /v1/keys` showed a
    // dead credential as never-revoked and a re-rotation of it took
    // `ApiKeyRepository::rotate`'s idempotent branch forever: 200 OK,
    // `grace_expires_at` already in the past, no new key, no admin-audit row.
    // `secureprompt-api/tests/rls_api_key_grace_window.rs` and
    // `tasks::api_key_rotation::tests` pin both halves.
    //
    // ALSO FIXED and therefore GONE (P1H):
    // `secureprompt-worker/src/tasks/retention_purge.rs` /
    // `workspace_raw_capture`, one statement — the bare-pool
    // `SELECT workspace_id, retention_days` that told the capture purge what
    // each tenant's CURRENT retention is. `purge_content_captures` now
    // enumerates `workspaces` and reads each workspace's setting inside a
    // scope-armed, read-back transaction, so nothing of it remains on a bare
    // pool. This guard is what proved the site was gone: it failed
    // `allowlist says 1, found 0` before this entry was deleted.
    //
    // Its reason string was RIGHT about the consequence and WRONG about the
    // severity, in the direction that understates it. It ended
    // "...so the run reports success AND the proof-of-purge trail simply omits
    // the scope" — which was correct, and was itself a correction of an
    // earlier tail claiming "the record still says `ok`". What it did not say
    // is that the omission was TOTAL: `records` was empty, so `all_ok()` was
    // an `all(...)` over the EMPTY SET, `total_deleted()` was 0, and
    // `main.rs`'s `record_job("retention_purge", …, ok = true)` fired on a run
    // in which captured plaintext prompts — the most sensitive rows this
    // product stores — were retained indefinitely with no alert of any kind.
    // MEASURED under `secureprompt_runner` before the fix, in
    // `captured_plaintext_is_purged_under_a_non_bypassing_role`: `all_ok()`
    // TRUE, records `[token_vault_entries, refresh_tokens.device_context]`,
    // and a 30-day-old capture still on disk under a 7-day retention.
    //
    // ALSO FIXED and therefore GONE (P1J):
    // `secureprompt-worker/src/tasks/retention_purge.rs` / `refresh_tokens`,
    // TWO statements — the FU4 device-context scrub's UPDATE and the recount
    // beside it. `scrub_session_device_context` now enumerates `workspaces` and
    // scrubs each one inside a scope-armed, read-back transaction, with the
    // recount in a SECOND armed transaction over committed state. This guard is
    // what proved the site was gone: it failed `allowlist says 2, found 0`
    // before this entry was deleted.
    //
    // Its reason string was RIGHT, including the second half — which is the
    // only allowlist reason on this branch that understated nothing. Recorded
    // here because the entry does not survive to say it: under
    // `secureprompt_runner` the UPDATE matched zero rows, which is not an
    // error, so the IP addresses stayed on disk; and the recount — the field
    // migration 023 offers as the one an auditor re-derives — was filtered by
    // the SAME predicate, returned zero, and AGREED. The emitted record was
    // `rows_deleted = 0`, `rows_remaining_past_cutoff = 0`, `status = 'ok'`:
    // byte-identical to a genuine no-op's, with the check designed to catch the
    // error confirming it.
    //
    // MEASURED under the runner role before the fix, in
    // `session_device_context_is_scrubbed_under_a_non_bypassing_role`: two
    // ended sessions still reading `(1, 1)`, `all_ok()` TRUE, the trail
    // reporting `[0]` rows past the boundary, and an independent re-derivation
    // from the workspace's own armed scope answering 2. The suggested fix in
    // the entry ("loop over `workspaces` arming the scope per workspace") is
    // what was done.
    (
        "secureprompt-worker/src/tasks/retention_purge.rs",
        "retention_purge_audit",
        1,
        "FALSE POSITIVE, verified by reading `write_audit` above it. \
         `insert_audit_row` is GENERIC over `sqlx::Executor`, and the scanner \
         is line-oriented so it sees the parameter name and not the two things \
         actually passed. `write_audit` passes a scope-armed, read-back \
         transaction for a per-workspace record, and the bare pool ONLY for a \
         global record — where `workspace_id IS NULL` satisfies migration \
         030's `workspace_isolation_or_global` policy on its own and there is \
         no workspace to arm to. Making the scanner understand this needs a \
         parse, not a regex.",
    ),
];

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is <root>/secureprompt-api.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("secureprompt-api must have a parent directory")
        .to_path_buf()
}

/// The tables Postgres is ACTUALLY forcing row-level security on, right now.
///
/// `relforcerowsecurity` and not `relrowsecurity`: ENABLE alone exempts the
/// table owner, and the application role is expected to own its tables, so
/// FORCE is the flag that decides whether a policy binds the connection this
/// crate opens.
async fn armed_tables(pool: &PgPool) -> BTreeSet<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT c.relname
         FROM pg_class c
         JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public' AND c.relforcerowsecurity",
    )
    .fetch_all(pool)
    .await
    .expect("armed-table probe")
    .into_iter()
    .collect()
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

/// Is this executor expression an already-scoped unit — a transaction, or a
/// connection whose scope its caller owns?
///
/// MR6 F4: this used to be `executor.contains("tx") || executor.contains("conn")`,
/// which skips any expression containing those two letter-runs ANYWHERE.
/// `&ctx.pool`, `&self.conn_pool` and `&context.db` are bare pools that the
/// substring test waves through, and a guard that cannot see a whole naming
/// convention is one rename away from being blind.
///
/// A plain `\btx\b` is not the fix either, and this is why it is written out
/// rather than left to a regex: `&mut *probe_tx` (`refresh_token_repo.rs:203`
/// and `:386`, both real transactions) has no word boundary before `tx`, so a
/// word-boundary rule turns two correct call sites into false positives and the
/// allowlist grows to accommodate the scanner. MEASURED: substring → 1 hit,
/// `\btx\b` → 3 hits, this rule → the same 1 hit, which is the documented
/// generic-parameter false positive in `retention_purge.rs`.
///
/// So the test is on the TRAILING IDENTIFIER, with `_` treated as the word
/// separator Rust uses: exactly `tx`/`conn`, or a suffix `_tx`/`_conn`.
fn executor_is_scoped(executor: &str) -> bool {
    let ident: String = executor
        .chars()
        .rev()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    ident == "tx" || ident == "conn" || ident.ends_with("_tx") || ident.ends_with("_conn")
}

/// Remove `#[cfg(test)]`-gated MODULES, and nothing else.
///
/// MR5 I-3: this used to be `source.find("\n#[cfg(test)]")` and a truncation to
/// that point, which drops everything after the FIRST such marker whether or
/// not it introduces a module. MEASURED at the tip, that silently removed
/// application source from the scan in three files —
/// `worker/tasks/audit_export.rs` cut at line 108 of 1075 (the marker sits on a
/// `pub const`), `db/license_repo.rs` at 110 of 155 (on a `pub async fn`), and
/// `dashboard/secure_mode.rs` at 148 of 703 (on a real but NON-FINAL test
/// module, with every handler in the file below it). The guard's header
/// promises it is exact in both directions; ~2,000 lines of application source
/// were outside it.
///
/// It happened to miss no violation — verified by running the scan with and
/// without the cut: the only difference is `db/workspace_repo.rs:408`, which is
/// genuinely inside its own `mod tests`. That is luck, not a property.
///
/// Column-0 `}` ends a top-level item in rustfmt-formatted source, and every
/// scanned crate is under the fmt gate, so brace COUNTING is not needed — which
/// matters, because a SQL literal containing an unbalanced brace would defeat
/// counting and this repository writes `{{placeholder}}` strings.
///
/// Removed lines are BLANKED rather than deleted. `scan` reports `file:line`
/// and an engineer opens that line; dropping lines would shift every number
/// after a stripped module and point them at the wrong statement.
fn strip_test_modules(source: &str) -> String {
    let mut lines: Vec<&str> = source.lines().collect();
    let mut idx = 0usize;
    while idx < lines.len() {
        if lines[idx] != "#[cfg(test)]" {
            idx += 1;
            continue;
        }
        let mut next = idx + 1;
        while next < lines.len() && lines[next].trim().is_empty() {
            next += 1;
        }
        let introduces_module = next < lines.len()
            && lines[next]
                .strip_prefix("pub(crate) ")
                .or_else(|| lines[next].strip_prefix("pub "))
                .unwrap_or(lines[next])
                .starts_with("mod ");
        if !introduces_module {
            idx += 1;
            continue;
        }
        // `#[cfg(test)] mod tests;` is a file-level declaration and owns only
        // its own two lines; anything else owns up to its column-0 `}`.
        let end = if lines[next].trim_end().ends_with(';') {
            next
        } else {
            let mut close = next + 1;
            while close < lines.len() && lines[close] != "}" {
                close += 1;
            }
            close.min(lines.len().saturating_sub(1))
        };
        for line in lines.iter_mut().take(end + 1).skip(idx) {
            *line = "";
        }
        idx = end + 1;
    }
    lines.join("\n")
}

/// Find every statement on one of `armed` executed against something that is
/// not a transaction or an explicit connection.
///
/// Shared by the real scan and by `the_detector_actually_detects`, so the
/// positive control exercises the same code the guard runs.
fn scan(source: &str, file: &str, armed: &BTreeSet<String>) -> Vec<CallSite> {
    let exec =
        Regex::new(r"\.(?:execute|fetch_one|fetch_all|fetch_optional)\(\s*(&?[\w*&. ]+?)\s*\)")
            .expect("executor regex");
    let table = Regex::new(r"(?i)(?:FROM|INTO|UPDATE|JOIN)\s+([A-Za-z_][A-Za-z_0-9]*)")
        .expect("table regex");

    // Unit tests live behind `#[cfg(test)]` and are not application paths.
    let body = strip_test_modules(source);
    let lines: Vec<&str> = body.lines().collect();

    let mut found = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        let Some(caps) = exec.captures(line) else {
            continue;
        };
        let executor = caps[1].trim();
        // A transaction is already the scoped unit; an explicit connection is
        // managed by its caller. Only pools are unscoped by construction.
        if executor_is_scoped(executor) {
            continue;
        }

        // Walk back to the statement this executor belongs to.
        let mut start = idx;
        while start > 0
            && !lines[start].contains("sqlx::query")
            && !lines[start].contains("sqlx::raw_sql")
            && idx - start < 80
        {
            start -= 1;
        }
        let block = lines[start..=idx].join("\n");

        let mut tables: BTreeSet<String> = BTreeSet::new();
        for m in table.captures_iter(&block) {
            let name = m[1].to_lowercase();
            if armed.contains(&name) {
                tables.insert(name);
            }
        }
        for name in tables {
            found.push(CallSite {
                file: file.to_owned(),
                table: name,
                line: start + 1,
            });
        }
    }
    found
}

// ===========================================================================
// The guard
// ===========================================================================

/// THE GATE. Every bare-pool statement on an armed table must be on the
/// allowlist with a reason, and every allowlist entry must still describe
/// something that exists.
#[sqlx::test]
async fn no_unreviewed_statement_touches_an_armed_table_on_a_bare_pool(pool: PgPool) {
    let armed = armed_tables(&pool).await;

    // PREMISE. If the probe came back empty — wrong database, migrations not
    // applied, a future Postgres renaming the column — the scan below would
    // match nothing and this test would pass while checking NOTHING.
    assert!(
        armed.contains("policy_rules"),
        "premise: policy_rules has been under FORCE ROW LEVEL SECURITY since \
         001_init.sql:78-95. It is absent from {armed:?}, so the armed-table \
         probe is broken and this guard is vacuous."
    );
    assert!(
        armed.len() >= 16,
        "premise: 16 tables are armed as of migration 031; the probe found \
         {} ({armed:?}). Fewer means the test database is not fully migrated.",
        armed.len()
    );

    let root = repo_root();
    let mut found: Vec<CallSite> = Vec::new();
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
            // Test modules are not application paths. Their fixtures insert
            // into armed tables deliberately and are covered by the suites
            // that own them.
            if rel.contains("/tests/") || rel.ends_with("_tests.rs") || rel.ends_with("/tests.rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).expect("readable source file");
            found.extend(scan(&source, &rel, &armed));
        }
    }

    // PREMISE: the scanner found SOMETHING. A refactor that moved every
    // repository, or a regex that stopped matching, would otherwise read as
    // "no violations".
    assert!(
        !found.is_empty(),
        "premise: the scanner found no bare-pool statements on armed tables at \
         all. That is not plausible while ALLOWED is non-empty — the scanner \
         is broken, not the code."
    );

    let mut unlisted: Vec<String> = Vec::new();
    let mut wrong_count: Vec<String> = Vec::new();

    for (file, table, expected, _reason) in ALLOWED {
        let actual = found
            .iter()
            .filter(|c| c.file == *file && c.table == *table)
            .count();
        if actual != *expected {
            wrong_count.push(format!(
                "  {file} / {table}: allowlist says {expected}, found {actual}"
            ));
        }
    }

    for site in &found {
        let listed = ALLOWED
            .iter()
            .any(|(file, table, _, _)| *file == site.file && *table == site.table);
        if !listed {
            unlisted.push(format!(
                "  {}:{} touches armed table `{}` on a bare pool",
                site.file, site.line, site.table
            ));
        }
    }

    assert!(
        unlisted.is_empty(),
        "A statement on an RLS-ARMED table runs on a bare pool with no \
         `app.current_workspace_id` set:\n{}\n\nUnder a role that does not \
         bypass RLS this does not error — it returns the EMPTY SET, and zero \
         rows is a plausible answer to almost every question this product \
         asks. Route it through `db::scope::begin_scoped` (or `arm_scope` if \
         the transaction is already open). If it is genuinely cross-tenant, \
         add it to ALLOWED with the consequence of the silent zero spelled \
         out.",
        unlisted.join("\n")
    );

    assert!(
        wrong_count.is_empty(),
        "The allowlist no longer matches the code:\n{}\n\nThis fails in BOTH \
         directions on purpose. If you FIXED one, delete or decrement its \
         entry so the list keeps shrinking; if you ADDED one, say why.",
        wrong_count.join("\n")
    );
}

/// POSITIVE CONTROL for the scanner itself. Without this, a regex that matched
/// nothing would make the gate above green and silent — the exact failure mode
/// the gate exists to prevent, one level up.
///
/// The two halves must DIFFER: the bare-pool statement is flagged, the
/// transaction-scoped one is not.
#[test]
fn the_detector_actually_detects() {
    let armed: BTreeSet<String> = ["policy_rules".to_owned()].into_iter().collect();

    let unscoped = r#"
        let rows = sqlx::query("SELECT name FROM policy_rules WHERE workspace_id = $1")
            .bind(workspace_id)
            .fetch_all(&self.pool)
            .await?;
    "#;
    let hits = scan(unscoped, "synthetic.rs", &armed);
    assert_eq!(
        hits.len(),
        1,
        "the scanner must flag a bare-pool read of an armed table, got {hits:?}"
    );
    assert_eq!(hits[0].table, "policy_rules");

    // NEGATIVE CONTROL — same statement, same table, executed on a
    // transaction. Must NOT be flagged, or the guard would demand an allowlist
    // entry for every correctly scoped query in the crate and be useless.
    let scoped = r#"
        let mut tx = begin_scoped(&self.pool, workspace_id).await?;
        let rows = sqlx::query("SELECT name FROM policy_rules WHERE workspace_id = $1")
            .bind(workspace_id)
            .fetch_all(&mut *tx)
            .await?;
    "#;
    assert!(
        scan(scoped, "synthetic.rs", &armed).is_empty(),
        "a transaction-scoped statement must not be flagged"
    );

    // NEGATIVE CONTROL, second axis: an UNARMED table on a bare pool is fine.
    // This is what keeps the guard tracking the database instead of a static
    // list — `users` is not armed today and must not be reported today.
    let unarmed = r#"
        let row = sqlx::query("SELECT id FROM users WHERE email = $1")
            .bind(email)
            .fetch_optional(&self.pool)
            .await?;
    "#;
    assert!(
        scan(unarmed, "synthetic.rs", &armed).is_empty(),
        "a table that is not armed must not be reported"
    );
}

/// MR6 F4 — the executor filter must skip transactions and NOTHING ELSE.
///
/// The old `contains("tx") || contains("conn")` skipped any expression with
/// those letter-runs anywhere in it. Each pool below is a bare pool the guard
/// must see; each transaction below is one it must not report, including
/// `&mut *probe_tx`, which a naive `\btx\b` rule would wrongly flag.
#[test]
fn the_executor_filter_skips_transactions_and_not_pools_that_merely_spell_them() {
    let armed: BTreeSet<String> = ["policy_rules".to_owned()].into_iter().collect();

    let statement = |executor: &str| {
        format!(
            "\n        let rows = sqlx::query(\"SELECT name FROM policy_rules WHERE workspace_id = $1\")\n\
             \x20           .bind(workspace_id)\n\
             \x20           .fetch_all({executor})\n\
             \x20           .await?;\n"
        )
    };

    // MUST BE FLAGGED. Every one of these is a pool.
    for pool in [
        "&ctx.pool",
        "&self.conn_pool",
        "&context.db",
        "&self.pool",
        "&state.db",
        "pg",
    ] {
        assert_eq!(
            scan(&statement(pool), "synthetic.rs", &armed).len(),
            1,
            "`{pool}` is a bare pool and must be flagged; the substring filter \
             this replaced skipped the first three of these"
        );
    }

    // MUST NOT BE FLAGGED. Every one of these is an already-scoped unit, and
    // `&mut *probe_tx` is a real call site (`db/refresh_token_repo.rs`).
    for scoped in [
        "&mut *tx",
        "&mut **tx",
        "&mut *probe_tx",
        "&mut conn",
        "&mut probe_conn",
    ] {
        assert!(
            scan(&statement(scoped), "synthetic.rs", &armed).is_empty(),
            "`{scoped}` is a transaction or caller-managed connection and must \
             not be reported; a rule that flags it grows the allowlist to \
             accommodate the scanner"
        );
    }
}

/// MR5 I-3 — only `#[cfg(test)]` MODULES are removed, and application source
/// after one is still scanned.
///
/// The old truncation cut at the first `\n#[cfg(test)]` and discarded the rest
/// of the file. `dashboard/secure_mode.rs` puts a test module at line 148 of
/// 703 and every handler below it; `worker/tasks/audit_export.rs` carries the
/// marker on a `pub const` at line 108 of 1075.
#[test]
fn only_test_modules_are_removed_from_the_scan() {
    let armed: BTreeSet<String> = ["policy_rules".to_owned()].into_iter().collect();

    // A test module in the MIDDLE of a file, with an application statement
    // after it. The statement after must be flagged; the one inside must not.
    let mid_file_module = "\
fn before() {}

#[cfg(test)]
mod inline_tests {
    fn fixture() {
        sqlx::query(\"INSERT INTO policy_rules (id) VALUES ($1)\")
            .execute(&pool)
            .await
            .unwrap();
    }
}

pub async fn after(&self) {
    let rows = sqlx::query(\"SELECT name FROM policy_rules WHERE workspace_id = $1\")
        .fetch_all(&self.pool)
        .await?;
}
";
    let hits = scan(mid_file_module, "synthetic.rs", &armed);
    assert_eq!(
        hits.len(),
        1,
        "application source AFTER a test module must still be scanned, and the \
         fixture INSIDE it must not be reported, got {hits:?}"
    );
    // And the reported line is the line in the ORIGINAL file, not in a
    // compacted copy: `sqlx::query` is line 14 of the fixture above. Blanking
    // rather than deleting is what keeps `file:line` openable.
    assert_eq!(
        hits[0].line, 14,
        "the surviving hit must be the statement below the module, reported at \
         its real line number"
    );

    // `#[cfg(test)]` on a NON-module item must not remove anything.
    let marker_on_a_function = "\
#[cfg(test)]
pub fn helper() -> u8 { 1 }

pub async fn application(&self) {
    let rows = sqlx::query(\"SELECT name FROM policy_rules WHERE workspace_id = $1\")
        .fetch_all(&self.pool)
        .await?;
}
";
    assert_eq!(
        scan(marker_on_a_function, "synthetic.rs", &armed).len(),
        1,
        "a `#[cfg(test)]` on a function must not truncate the file; that cut \
         removed 967 lines of `worker/tasks/audit_export.rs` from the scan"
    );

    // `#[cfg(test)] mod tests;` — the path-declaration form.
    let declaration_form = "\
#[cfg(test)]
mod tests;

pub async fn application(&self) {
    let rows = sqlx::query(\"SELECT name FROM policy_rules WHERE workspace_id = $1\")
        .fetch_all(&self.pool)
        .await?;
}
";
    assert_eq!(
        scan(declaration_form, "synthetic.rs", &armed).len(),
        1,
        "a `mod tests;` declaration removes two lines, not the rest of the file"
    );
}
