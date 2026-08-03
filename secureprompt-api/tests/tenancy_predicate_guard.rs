//! The second structural seam: a statement that is ARMED must also FILTER.
//!
//! # Why this exists next to `rls_call_site_guard.rs` rather than inside it
//!
//! That guard answers "is this statement on an armed transaction?".
//! `rls_scope_readback.rs` answers "did anyone verify the arming took?".
//! Neither can see this:
//!
//! ```ignore
//! pub async fn list_models(&self, workspace_id: WorkspaceId) -> ... {
//!     let mut tx = begin_scoped(&self.pool, workspace_id.0).await?;   // armed
//!     sqlx::query("SELECT ... FROM models WHERE excluded = FALSE")    // unfiltered
//! }
//! ```
//!
//! The transaction is armed, the arming is read back, and the function still
//! returns every workspace's rows. `workspace_id` is spent entirely on
//! `begin_scoped` and never reaches the SQL. That is a missing PREDICATE, and
//! P1K found four of them plus one on a table no policy covers.
//!
//! # Why the bug is invisible exactly where the product runs
//!
//! With the scope armed, the `workspace_isolation` policy supplies the missing
//! predicate, so on `secureprompt_runner` these functions read correctly. The
//! compose role is a SUPERUSER and bypasses every policy unconditionally —
//! `tests/rls_missing_predicate.rs` measures all four leaks under it, and one,
//! `list_models_for_provider`, was reachable from `GET /v1/providers/{id}/models`
//! with nothing but a valid JWT and another tenant's provider UUID.
//!
//! # What this checks, exactly
//!
//! For every function whose SIGNATURE takes a tenancy parameter, every SQL
//! string literal in its BODY that names a table carrying a `workspace_id`
//! column must mention `workspace_id` in a PREDICATE position:
//!
//!   * `INSERT` — anywhere in the statement. The column list is the scoping.
//!   * everything else — after the first `WHERE`. This distinction is the
//!     whole rule and not a detail: two of the four defects read
//!     `SELECT id, workspace_id, provider_id, ... FROM models WHERE
//!     provider_id = $1`, which a "does the statement mention workspace_id"
//!     check calls scoped. `the_detector_actually_detects` pins that case.
//!
//! The tenant-table list is READ FROM THE DATABASE
//! (`information_schema.columns`), never hardcoded, for the same reason
//! `rls_call_site_guard` reads `pg_class.relforcerowsecurity`: a migration that
//! adds `workspace_id` to a new table puts every unfiltered query against it in
//! front of a reviewer without anyone remembering to update a list. It is
//! deliberately NOT the RLS-armed list — `users` and `token_vault_entries`
//! carry `workspace_id` and are at `relforcerowsecurity = false`, so they are
//! the tables where a missing predicate has NO policy behind it on any role.
//! `self_actor` was exactly that, and is why the probe keys on the column.
//!
//! # Known limits, stated rather than discovered later
//!
//! The scan is TEXTUAL — regex over source, not a parse. Three consequences,
//! each measured while building this:
//!
//!   1. SQL assembled from fragments, or issued through a helper that takes the
//!      table name, is invisible. So is a query in a function that receives its
//!      tenancy through a struct field rather than a parameter.
//!   2. A statement containing several sub-queries passes if ANY of them
//!      filters after the first `WHERE`. `data_inventory::postgres_counts` is
//!      the real instance: twenty-eight sub-selects, all scoped, and the rule
//!      only proves that at least one is.
//!   3. **It cannot see a JOIN with the predicate on one side.**
//!      `resolve_model_targets` was the fourth P1K defect and this guard would
//!      have called it clean, because `WHERE models.workspace_id = $1` is a
//!      predicate on `workspace_id`. That hole is closed by a runtime test
//!      (`resolve_model_targets_keeps_the_tenancy_predicate_on_both_joined_tables`)
//!      and not by this file. Do not read a green run here as "every join is
//!      scoped".
//!
//! A false positive costs a reviewer one allowlist line with a reason, which is
//! a prompt for a decision rather than a wrong answer. A false negative is a
//! gap, which is why this supplements the runtime suite rather than replacing
//! it.

use regex::Regex;
use sqlx::PgPool;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// One SQL statement, in a function that was handed a workspace, that does not
/// filter on one.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Unfiltered {
    file: String,
    line: usize,
    function: String,
    table: String,
    sql: String,
}

/// Every unfiltered statement that is KNOWN and accepted, with the reason.
/// `count` is exact so adding a second one to the same function fails even
/// though the first already appears here.
///
/// The list is checked in BOTH directions, like `scripts/ci/fmt-gate.sh` and
/// `rls_call_site_guard.rs`: an unlisted hit fails, and a listed entry that no
/// longer describes anything ALSO fails. It can shrink and cannot rot into a
/// permanent excuse column.
///
/// Every reason here must be something that was EXECUTED. Fourteen comments
/// asserting guarantees have proved false on this branch, three of them
/// allowlist reason strings, all optimistic in the same direction.
const ALLOWED: &[(&str, &str, usize, &str)] = &[
    // FIXED and therefore GONE (P1K), recorded in prose because the entries do
    // not survive to say it:
    //
    //   provider_repo.rs / list_models                    — no callers, but
    //     `SELECT ... FROM models WHERE excluded = FALSE` returned BOTH
    //     workspaces' models under the compose superuser.
    //   provider_repo.rs / list_models_for_provider       — the REACHABLE one.
    //     `GET /v1/providers/{id}/models` takes the provider id from the URL
    //     path and performs no ownership check, unlike `sync_provider_models`
    //     and `test_connection_stored`, which both resolve it through
    //     `list_providers(ctx.workspace_id)` first.
    //   provider_repo.rs / list_excluded_model_names_for_provider — same shape;
    //     its single caller was already safe by a check two files away.
    //   twofactor.rs / self_actor                         — `SELECT role FROM
    //     users WHERE id = $1`. `users` is at `relforcerowsecurity = false`, so
    //     no policy was supplying this predicate on ANY role. Its sibling
    //     `AdminActor::resolve` had always filtered on both columns.
    //
    // All four are pinned by `tests/rls_missing_predicate.rs`, and each fix was
    // mutation-checked: the predicate removed again, the matching test re-run
    // in the same shell, four for four RED.
    (
        "secureprompt-api/src/db/provider_repo.rs",
        "create_model",
        1,
        "SAFE BY CONSTRUCTION, and the construction was executed rather than \
         read. `UPDATE models SET excluded = FALSE WHERE id = $1` is the revive \
         branch. `id` is not caller input: it is read in the SAME transaction, \
         three statements earlier, by a SELECT filtered on `workspace_id = $1 \
         AND provider_id = $2 AND name = $3` — and the method returns NotFound \
         before either statement unless the provider itself passed `SELECT 1 \
         FROM providers WHERE id = $1 AND workspace_id = $2`. \
         `create_model_cannot_revive_a_foreign_workspaces_excluded_model` in \
         tests/rls_missing_predicate.rs drives both refusals under the \
         superuser and checks the foreign row is still excluded on disk \
         afterwards, beside a positive control that the revive works for its \
         own workspace.",
    ),
    (
        "secureprompt-api/src/db/api_key_repo.rs",
        "rotate",
        1,
        "SAFE BY CONSTRUCTION, executed rather than read. `UPDATE api_keys SET \
         status = 'rotating', ... WHERE id = $3` is the second write of a \
         rotation. `key_id` is validated AND LOCKED by the statement that opens \
         the same transaction — `SELECT ... WHERE id = $1 AND workspace_id = $2 \
         AND status IN ('active', 'rotating') FOR UPDATE` — and the method \
         returns NotFound when it matches nothing, so the UPDATE is \
         unreachable with a foreign id. The predicate is not added because the \
         FOR UPDATE gate is what the idempotency design depends on, and a \
         duplicate would imply that gate is not trusted. \
         `rotate_refuses_a_foreign_workspaces_api_key` in \
         tests/rls_missing_predicate.rs drives the refusal under the superuser \
         and re-reads B's key status from B's own armed scope afterwards \
         ('active', not 'rotating'), beside a positive control that A's own \
         key does reach 'rotating'. \
         NOTE the sibling statement three lines above it — `INSERT INTO \
         api_keys ... SELECT $1, workspace_id, ... FROM api_keys WHERE id = $3` \
         — is NOT flagged, because the INSERT rule counts its column list as \
         scoping. Its inner SELECT is unfiltered and rests on the same FOR \
         UPDATE gate. The same test covers it: a refused rotation inserts no \
         successor row.",
    ),
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("secureprompt-api must have a parent directory")
        .to_path_buf()
}

/// Every table in `public` carrying a `workspace_id` column, right now.
///
/// The column and not the policy: a table can carry tenant data with no policy
/// covering it, and those are the tables where a missing predicate has nothing
/// behind it. Six of them are at `relforcerowsecurity = false` after migration
/// 033.
async fn tenant_tables(pool: &PgPool) -> BTreeSet<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT table_name
         FROM information_schema.columns
         WHERE table_schema = 'public' AND column_name = 'workspace_id'",
    )
    .fetch_all(pool)
    .await
    .expect("tenant-table probe")
    .into_iter()
    .map(|t| t.to_lowercase())
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

/// Whether one statement filters on tenancy in a PREDICATE position.
///
/// Split out and `pub`-in-module so `the_detector_actually_detects` can drive
/// the exact function the guard runs, rather than a paraphrase of it.
fn filters_on_tenancy(sql: &str) -> bool {
    let lower = sql.to_lowercase();
    let trimmed = lower.trim_start();
    if trimmed.starts_with("insert") {
        // The column list IS the scoping for an INSERT — there is no WHERE to
        // put it after.
        return lower.contains("workspace_id");
    }
    match lower.find(" where ") {
        Some(at) => lower[at..].contains("workspace_id"),
        None => false,
    }
}

/// Byte span of the `{ ... }` body that follows `from`, brace-matched.
fn body_span(source: &str, from: usize) -> Option<(usize, usize)> {
    let open = source[from..].find('{')? + from;
    let mut depth = 0usize;
    for (offset, ch) in source[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some((open, open + offset + 1));
                }
            }
            _ => {}
        }
    }
    None
}

/// Byte offset just past the closing paren of a signature's parameter list.
fn params_end(source: &str, open_paren: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, ch) in source[open_paren..].char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(open_paren + offset + 1);
                }
            }
            _ => {}
        }
    }
    None
}

/// Find every unfiltered statement on a tenant table inside a function that was
/// handed a workspace.
///
/// Shared by the real scan and by the positive control, so the control
/// exercises the code the guard runs.
fn scan(source: &str, file: &str, tenant: &BTreeSet<String>) -> Vec<Unfiltered> {
    let func =
        Regex::new(r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(\w+)\s*(?:<[^>]*>)?\s*\(")
            .expect("fn regex");
    // A parameter named for a tenant and typed as one.
    let tenancy = Regex::new(
        r"\b(?:workspace_id|ws_id|ws|workspace|org_id)\s*:\s*(?:&\s*)?(?:WorkspaceId|Uuid|uuid::Uuid|OrgId)\b",
    )
    .expect("tenancy-param regex");
    let literal = Regex::new(r#"(?s)"([^"\\]*(?:\\.[^"\\]*)*)""#).expect("string literal regex");
    let verb = Regex::new(r"(?is)\b(?:SELECT|INSERT|UPDATE|DELETE)\b").expect("verb regex");
    let table = Regex::new(r"(?i)(?:FROM|INTO|UPDATE|JOIN)\s+([A-Za-z_][A-Za-z_0-9]*)")
        .expect("table regex");

    // Unit tests live behind `#[cfg(test)]` and are not application paths.
    let body_source = match source.find("\n#[cfg(test)]") {
        Some(cut) => &source[..cut],
        None => source,
    };

    let mut found = Vec::new();
    for caps in func.captures_iter(body_source) {
        let whole = caps.get(0).expect("match 0");
        let name = caps[1].to_owned();
        let Some(after_params) = params_end(body_source, whole.end() - 1) else {
            continue;
        };
        let signature = &body_source[whole.start()..after_params];
        if !tenancy.is_match(signature) {
            continue;
        }
        let Some((open, close)) = body_span(body_source, after_params) else {
            continue;
        };
        let body = &body_source[open..close];

        for lit in literal.captures_iter(body) {
            let raw = lit.get(1).expect("literal group").as_str();
            if !verb.is_match(raw) {
                continue;
            }
            let sql = raw.split_whitespace().collect::<Vec<_>>().join(" ");
            let mut tables: BTreeSet<String> = BTreeSet::new();
            for m in table.captures_iter(&sql) {
                let t = m[1].to_lowercase();
                if tenant.contains(&t) {
                    tables.insert(t);
                }
            }
            if tables.is_empty() || filters_on_tenancy(&sql) {
                continue;
            }
            let at = open + lit.get(0).expect("literal").start();
            let line = body_source[..at].matches('\n').count() + 1;
            for t in tables {
                found.push(Unfiltered {
                    file: file.to_owned(),
                    line,
                    function: name.clone(),
                    table: t,
                    sql: sql.chars().take(140).collect(),
                });
            }
        }
    }
    found
}

// ===========================================================================
// The gate
// ===========================================================================

/// THE GATE. Every SQL statement on a tenant table, inside a function that was
/// given a workspace, must filter on that workspace — or be on the allowlist
/// with a reason someone executed.
#[sqlx::test]
async fn no_unreviewed_statement_takes_a_workspace_and_ignores_it(pool: PgPool) {
    let tenant = tenant_tables(&pool).await;

    // PREMISE. An empty or truncated probe — wrong database, migrations not
    // applied, a future Postgres renaming the view — would match no tables and
    // make this test pass while checking NOTHING.
    for required in ["models", "providers", "users", "api_keys", "policy_rules"] {
        assert!(
            tenant.contains(required),
            "premise: `{required}` carries a workspace_id column and is absent \
             from the probe's {} tables ({tenant:?}). The probe is broken, so \
             this guard is vacuous.",
            tenant.len()
        );
    }
    assert!(
        tenant.len() >= 18,
        "premise: 18 tables carry workspace_id as of migration 033; the probe \
         found {} ({tenant:?}). Fewer means the test database is not fully \
         migrated.",
        tenant.len()
    );

    // PREMISE, and the reason this guard keys on the COLUMN rather than on
    // `relforcerowsecurity`: `users` carries tenant data with no policy over
    // it, so a missing predicate there has nothing behind it on any role. That
    // was `self_actor`. If a future migration arms `users`, this assertion
    // fails and the header's argument needs re-reading, not deleting.
    let users_armed: bool = sqlx::query_scalar(
        "SELECT relforcerowsecurity FROM pg_class WHERE oid = 'users'::regclass",
    )
    .fetch_one(&pool)
    .await
    .expect("users must exist to be probed");
    assert!(
        !users_armed,
        "premise: `users` is now under FORCE ROW LEVEL SECURITY. That is good \
         news, and it means this guard's stated reason for keying on the \
         workspace_id COLUMN rather than on the armed-table list has changed."
    );

    let root = repo_root();
    let mut found: Vec<Unfiltered> = Vec::new();
    let mut files_scanned = 0usize;
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
            // Test modules are not application paths. Their fixtures write
            // deliberately unscoped SQL to set up the very conditions the
            // suites measure.
            if rel.contains("/tests/") || rel.ends_with("_tests.rs") || rel.ends_with("/tests.rs") {
                continue;
            }
            files_scanned += 1;
            let source = std::fs::read_to_string(&path).expect("readable source file");
            found.extend(scan(&source, &rel, &tenant));
        }
    }

    // PREMISE: the walker found source to scan. A moved crate or a broken
    // `rs_files` would otherwise read as "no violations".
    assert!(
        files_scanned >= 50,
        "premise: only {files_scanned} source files were scanned across three \
         crates. The walker is broken, not the code."
    );

    let mut unlisted: Vec<String> = Vec::new();
    let mut wrong_count: Vec<String> = Vec::new();

    for (file, function, expected, _reason) in ALLOWED {
        let actual = found
            .iter()
            .filter(|u| u.file == *file && u.function == *function)
            .count();
        if actual != *expected {
            wrong_count.push(format!(
                "  {file} / {function}: allowlist says {expected}, found {actual}"
            ));
        }
    }

    for hit in &found {
        let listed = ALLOWED
            .iter()
            .any(|(file, function, _, _)| *file == hit.file && *function == hit.function);
        if !listed {
            unlisted.push(format!(
                "  {}:{} fn `{}` on tenant table `{}`\n      {}",
                hit.file, hit.line, hit.function, hit.table, hit.sql
            ));
        }
    }

    assert!(
        unlisted.is_empty(),
        "A function was handed a workspace and issued a statement on a tenant \
         table without filtering on it:\n{}\n\nOn `secureprompt_runner` the \
         `workspace_isolation` policy supplies the predicate and the query \
         looks correct. The compose role is a SUPERUSER and bypasses every \
         policy, so on the deployed configuration the statement returns EVERY \
         tenant's rows — and on `users`, `token_vault_entries` or any other \
         table at `relforcerowsecurity = false` it does so under every role. \
         Add `WHERE workspace_id = $n`. If the statement genuinely cannot name \
         one, add it to ALLOWED with a reason you EXECUTED.",
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

/// POSITIVE CONTROL for the scanner. Without it, a regex that matched nothing
/// would make the gate above green and silent — the exact failure mode the gate
/// exists to prevent, one level up.
///
/// The cases must DIFFER from one another, and the fourth is the one that
/// matters most: `workspace_id` in the SELECT COLUMN LIST and not in the WHERE
/// is precisely the shape of two of the four defects P1K found, and a
/// "statement mentions workspace_id" rule calls it clean.
#[test]
fn the_detector_actually_detects() {
    let tenant: BTreeSet<String> = ["models".to_owned(), "users".to_owned()]
        .into_iter()
        .collect();

    let unfiltered = r#"
        pub async fn list_models(&self, workspace_id: WorkspaceId) -> Result<Vec<ModelRow>> {
            let mut tx = begin_scoped(&self.pool, workspace_id.0).await?;
            let rows = sqlx::query("SELECT id, name FROM models WHERE excluded = FALSE")
                .fetch_all(&mut *tx)
                .await?;
        }
    "#;
    let hits = scan(unfiltered, "synthetic.rs", &tenant);
    assert_eq!(
        hits.len(),
        1,
        "the scanner must flag an armed-but-unfiltered read of a tenant table, got {hits:?}"
    );
    assert_eq!(hits[0].table, "models");
    assert_eq!(hits[0].function, "list_models");

    // NEGATIVE CONTROL — the same statement, filtered. Must NOT be flagged, or
    // the guard demands an allowlist entry for every correct query in the
    // workspace and is useless.
    let filtered = r#"
        pub async fn list_models(&self, workspace_id: WorkspaceId) -> Result<Vec<ModelRow>> {
            let rows = sqlx::query("SELECT id, name FROM models WHERE workspace_id = $1")
                .bind(workspace_id.0)
                .fetch_all(&mut *tx)
                .await?;
        }
    "#;
    assert!(
        scan(filtered, "synthetic.rs", &tenant).is_empty(),
        "a statement filtered on workspace_id must not be flagged"
    );

    // NEGATIVE CONTROL, second axis: an INSERT scopes through its COLUMN LIST.
    // There is no WHERE to put the predicate after, and every write in the
    // repositories has this shape — flagging them would bury the real hits.
    let insert = r#"
        pub async fn create(&self, workspace_id: WorkspaceId) -> Result<()> {
            sqlx::query("INSERT INTO models (id, workspace_id, name) VALUES ($1, $2, $3)")
                .execute(&mut *tx)
                .await?;
        }
    "#;
    assert!(
        scan(insert, "synthetic.rs", &tenant).is_empty(),
        "an INSERT naming workspace_id in its column list must not be flagged"
    );

    // THE ONE THAT MATTERS. `workspace_id` appears in the statement — in the
    // SELECT list — and nowhere in the predicate. This is the literal shape of
    // `list_models_for_provider` and `list_models` before P1K, and the reason
    // `filters_on_tenancy` looks after the first WHERE instead of anywhere.
    let column_list_only = r#"
        pub async fn list_models_for_provider(&self, workspace_id: WorkspaceId, provider_id: Uuid) -> Result<()> {
            sqlx::query("SELECT id, workspace_id, provider_id, name FROM models WHERE provider_id = $1")
                .bind(provider_id)
                .fetch_all(&mut *tx)
                .await?;
        }
    "#;
    let hits = scan(column_list_only, "synthetic.rs", &tenant);
    assert_eq!(
        hits.len(),
        1,
        "workspace_id in the SELECT column list is NOT a tenancy predicate; \
         the scanner must still flag this, got {hits:?}"
    );

    // NEGATIVE CONTROL, third axis: no tenancy parameter, no claim to check.
    // `fetch_user_by_id` in dashboard::auth is the real instance — it is the
    // lookup that DISCOVERS which workspace a user belongs to, so requiring it
    // to filter on one would be circular.
    let no_tenancy_param = r#"
        async fn fetch_user_by_id(pool: &PgPool, user_id: Uuid) -> Result<Option<UserIdentity>> {
            sqlx::query("SELECT id, workspace_id, email FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_optional(pool)
                .await?;
        }
    "#;
    assert!(
        scan(no_tenancy_param, "synthetic.rs", &tenant).is_empty(),
        "a function with no tenancy parameter promises no scoping and must not \
         be flagged"
    );

    // NEGATIVE CONTROL, fourth axis: a table with no workspace_id column is
    // not this guard's business. This is what keeps the guard tracking the
    // DATABASE instead of a static list.
    let untenanted = r#"
        pub async fn purge(&self, workspace_id: WorkspaceId) -> Result<()> {
            sqlx::query("DELETE FROM user_backup_codes WHERE user_id = $1")
                .execute(&mut *tx)
                .await?;
        }
    "#;
    assert!(
        scan(untenanted, "synthetic.rs", &tenant).is_empty(),
        "a table that carries no workspace_id column must not be reported"
    );
}

/// `filters_on_tenancy` on its own, at the boundary the whole rule turns on.
///
/// The gate above can only fail on statements that EXIST in the tree. These
/// cases pin the predicate rule against shapes the repository does not happen
/// to contain today, so a future simplification of the function is caught here
/// rather than by its silence.
#[test]
fn the_predicate_rule_looks_after_the_where_and_not_before_it() {
    assert!(filters_on_tenancy(
        "SELECT name FROM models WHERE workspace_id = $1"
    ));
    assert!(filters_on_tenancy(
        "SELECT name FROM models WHERE provider_id = $1 AND workspace_id = $2"
    ));
    assert!(
        !filters_on_tenancy("SELECT workspace_id FROM models WHERE provider_id = $1"),
        "the projection is not a predicate"
    );
    assert!(
        !filters_on_tenancy("SELECT workspace_id, name FROM models"),
        "no WHERE at all is not scoped"
    );
    assert!(
        !filters_on_tenancy("UPDATE models SET workspace_id = $1 WHERE id = $2"),
        "a SET is not a predicate either — assigning the column does not \
         restrict which rows are assigned"
    );
    assert!(filters_on_tenancy(
        "INSERT INTO models (id, workspace_id, name) VALUES ($1, $2, $3)"
    ));
    assert!(
        !filters_on_tenancy("INSERT INTO models (id, name) VALUES ($1, $2)"),
        "an INSERT that does not name the column is not scoped by it"
    );
    // Case-insensitivity is load-bearing: this repository writes SQL in upper
    // case and `pg_class` names in lower.
    assert!(filters_on_tenancy(
        "select name from models where WORKSPACE_ID = $1"
    ));
}
