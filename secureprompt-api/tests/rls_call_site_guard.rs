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
    (
        "secureprompt-api/src/db/refresh_token_repo.rs",
        "refresh_tokens",
        2,
        "REAL DEFECT. Cross-tenant BY NECESSITY: a refresh token is an opaque random string \
         and does not name its workspace, so `rotate`'s pre-lookup and \
         `find_active_by_hash` must find the row before they can know which \
         scope to arm. Under a non-bypassing role both return None. `rotate` \
         then reports NotFound and every session refresh 401s — loud, and \
         fail-closed. `find_active_by_hash` is the dangerous one: it is the \
         logout path's best-effort revoke, so None means LOGOUT SILENTLY DOES \
         NOT REVOKE THE REFRESH TOKEN and the session survives the sign-out. \
         Fixing it needs one of: a SECURITY DEFINER lookup owned by a \
         BYPASSRLS role (blocked on the ownership decision this workstream \
         does not own), or making the caller pass the workspace it already \
         holds in its JWT.",
    ),
    (
        "secureprompt-worker/src/tasks/retention_purge.rs",
        "refresh_tokens",
        2,
        "REAL DEFECT. Cross-tenant BY DESIGN: `scrub_session_device_context` erases client \
         IP and device strings for ENDED sessions across every workspace. \
         Under a non-bypassing role the UPDATE matches zero rows, so the IP \
         addresses stay on disk indefinitely — and the second statement, the \
         re-derivation an auditor recomputes and which `must be zero`, is \
         filtered by the SAME predicate and also returns zero. Both halves \
         lie consistently and the job reports status `ok`. Fix: loop over \
         `workspaces` arming the scope per workspace, as migrations 019/020 do.",
    ),
    (
        "secureprompt-worker/src/tasks/retention_purge.rs",
        "workspace_raw_capture",
        1,
        "REAL DEFECT. Cross-tenant BY DESIGN: reads every workspace's CURRENT retention \
         setting to decide what captured content to purge. Under a \
         non-bypassing role it returns no rows, which this code cannot \
         distinguish from `no workspace has enabled capture`, so captured \
         PLAINTEXT PROMPTS are never purged and the record still says `ok`. \
         Same fix: drive it from a loop over `workspaces` with the scope armed.",
    ),
    (
        "secureprompt-worker/src/main.rs",
        "api_keys",
        1,
        "REAL DEFECT, least severe. Cross-tenant BY DESIGN: the worker's \
         startup key-cache warm reads every workspace's keys. Under a \
         non-bypassing role it loads nothing; that direction fails CLOSED \
         (requests miss the cache and fall through to a scoped lookup) which \
         is why it is last in this list.",
    ),
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
    let body = match source.find("\n#[cfg(test)]") {
        Some(cut) => &source[..cut],
        None => source,
    };
    let lines: Vec<&str> = body.lines().collect();

    let mut found = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        let Some(caps) = exec.captures(line) else {
            continue;
        };
        let executor = caps[1].trim();
        // A transaction is already the scoped unit; an explicit connection is
        // managed by its caller. Only pools are unscoped by construction.
        if executor.contains("tx") || executor.contains("conn") {
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
