//! Migrations 017, 018, 021, 022 and 023 executed by a NON-SUPERUSER,
//! NOBYPASSRLS Postgres role.
//!
//! WHY THIS SUITE EXISTS
//!
//! `#[sqlx::test]` provisions its database and connects as the role in
//! `DATABASE_URL`, which the `postgres:16` image creates as a SUPERUSER.
//! Superusers bypass row-level security unconditionally, so NO lib-level
//! migration test in this repository can observe an RLS defect. That is not a
//! theoretical concern: `017_uzbek_identifier_policy_classes.sql` shipped a
//! `UPDATE policy_rules ... WHERE name = 'Redact common PII'` with no
//! workspace scoping, which under a non-bypassing role matches zero rows and
//! still reports success. It was caught by hand, not by a test.
//!
//! `tests/migration_020_rls.rs` and `policy::failclosed_tests::
//! migration_024_rls_tests` cover 020 and 024. This file covers the five
//! migrations that had no non-superuser coverage at all: 017, 018, 021, 022
//! and 023. The role, the premise assertions and the "fixtures through the
//! privileged pool, migration through the low-privilege connection" split are
//! deliberately the SAME pattern as those two — a second pattern would be a
//! second thing to keep true.
//!
//! WHAT WAS MEASURED (every claim below was executed against a database with
//! migrations 001-016 applied and two seeded workspaces, before these tests
//! were written):
//!
//!   * 017 as `secureprompt_runner`: `UPDATE 0`, exit 0, both class arrays
//!     still nine entries. Re-run as superuser: fifteen entries. The defect
//!     is real and this harness sees it.
//!   * 018 / 021 / 023 as `secureprompt_runner`: exit 0. They are pure DDL
//!     and have no RLS-sensitive statement to no-op.
//!   * 022 as `secureprompt_runner` WITHOUT table ownership:
//!     `ERROR: must be owner of table token_vault_entries`. WITH ownership:
//!     exit 0, table empty, `mapping_ciphertext` NOT NULL present.
//!   * 022 against a `token_vault_entries` that HAS RLS: `DELETE 0` then
//!     `ERROR: column "mapping_ciphertext" ... contains null values`, and the
//!     plaintext row survives. 022's correctness is load-bearing on that
//!     table having no RLS, which is why a test asserts it.
//!
//! WHAT 018/021/023 TURNED OUT TO BE. "Pure DDL with no RLS-sensitive
//! statement to no-op" was true of the migrations and false of the tables they
//! created. `workspace_sidecar_policy`, `workspace_raw_capture`,
//! `raw_capture_audit` and `retention_purge_audit` shipped with NO row-level
//! security at all, and this suite's first three versions of the tests below
//! PINNED that as expected behaviour — measured, from an armed foreign scope:
//! another tenant's rows were readable and writable. `raw_capture_audit` is a
//! source of the signed compliance export, so the only thing keeping one
//! tenant's audit rows out of another tenant's attestation was an
//! application-level `WHERE workspace_id = $1`.
//!
//! Migration 030 arms all four. The tests below now assert the boundary
//! instead of the breach.
//!
//! SCOPE. Running the FULL suite as `secureprompt_runner` produces ~85
//! failures of the form `new row violates row-level security policy for table
//! "policy_rules"`, originating in `workspace_repo`'s default-rule seeding:
//! the application depends on connecting as a BYPASSRLS role today. That is
//! the DB role-split backlog item and is out of scope here. These tests
//! therefore do all FIXTURE setup through the ordinary superuser pool and run
//! only the MIGRATION on the low-privilege connection.

use sqlx::postgres::PgConnectOptions;
use sqlx::{Connection, PgConnection, PgPool, Row};
use std::collections::BTreeSet;
use uuid::Uuid;

const MIGRATION_017: &str = include_str!("../migrations/017_uzbek_identifier_policy_classes.sql");
const MIGRATION_018: &str = include_str!("../migrations/018_sidecar_failure_policy.sql");
const MIGRATION_020: &str = include_str!("../migrations/020_reconcile_default_policy_classes.sql");
const MIGRATION_021: &str = include_str!("../migrations/021_raw_content_capture.sql");
const MIGRATION_022: &str = include_str!("../migrations/022_token_vault_encryption.sql");
const MIGRATION_023: &str = include_str!("../migrations/023_retention_purge_audit.sql");

/// The role every migration below is executed as.
/// `scripts/ci/create-nonsuperuser-role.sh` creates it in CI with exactly
/// these attributes; [`ensure_low_privilege_role`] creates it on demand
/// locally so this suite can never silently degrade into "ran as superuser
/// after all".
const RLS_ROLE: &str = "secureprompt_runner";
const RLS_PASSWORD: &str = "secureprompt";

/// The nine classes every workspace seeded before the fix wave carries, and
/// the exact shape 017's guard tests for. `GCP_KEY` / `AZURE_KEY` are dead
/// names that match nothing any detector emits; they are part of the legacy
/// shape, which is why the guard is keyed on them.
const LEGACY_NINE: &str = r#"["PERSON","EMAIL_ADDRESS","PHONE_NUMBER","CREDIT_CARD","US_SSN","IBAN_CODE","AWS_ACCESS_KEY","GCP_KEY","AZURE_KEY"]"#;

/// The six classes 017 exists to add. Restated from the migration body
/// because SQL cannot export a list to Rust.
const UZBEK_SIX: [&str; 6] = ["PINFL", "STIR", "MFO", "PASSPORT_NUMBER", "UZCARD", "HUMO"];

// ---------------------------------------------------------------------------
// Fixtures — all through the (superuser) `#[sqlx::test]` pool.
// ---------------------------------------------------------------------------

async fn seed_workspace(pool: &PgPool, name: &str) -> Uuid {
    let workspace_id = Uuid::new_v4();
    sqlx::query("INSERT INTO workspaces (id, name) VALUES ($1, $2)")
        .bind(workspace_id)
        .bind(name)
        .execute(pool)
        .await
        .expect("workspace insert");
    workspace_id
}

/// Insert a policy rule directly rather than through
/// `WorkspaceRepository::create_with_owner`: the low-privilege role cannot
/// insert into `policy_rules` at all, and this suite is about the migrations,
/// not the seeding path.
async fn seed_rule(pool: &PgPool, workspace_id: Uuid, rule_name: &str, classes: &str) -> Uuid {
    let rule_id = Uuid::new_v4();
    let conditions: serde_json::Value = serde_json::from_str(&format!(
        r#"[{{"field":"detection_class","op":"in","value":{classes}}}]"#
    ))
    .expect("fixture class list is valid JSON");

    sqlx::query(
        "INSERT INTO policy_rules
            (id, workspace_id, name, priority, conditions, action, action_params,
             enabled, dry_run, created_at, updated_at)
         VALUES ($1, $2, $3, 100, $4, 'redact', '{}'::jsonb, true, false, NOW(), NOW())",
    )
    .bind(rule_id)
    .bind(workspace_id)
    .bind(rule_name)
    .bind(&conditions)
    .execute(pool)
    .await
    .expect("policy rule insert");

    rule_id
}

async fn classes_of(pool: &PgPool, rule_id: Uuid) -> Vec<String> {
    let row = sqlx::query("SELECT conditions FROM policy_rules WHERE id = $1")
        .bind(rule_id)
        .fetch_one(pool)
        .await
        .expect("rule must still exist");
    let conditions: serde_json::Value = row.get("conditions");
    conditions[0]["value"]
        .as_array()
        .expect("conditions[0].value must be an array")
        .iter()
        .filter_map(|value| value.as_str().map(ToOwned::to_owned))
        .collect()
}

/// `updated_at` as text. 017 sets it alongside `conditions`, so reading it
/// back is how "the statement matched zero rows" is told apart from "the
/// statement matched and only bumped the timestamp" — a shape already caught
/// once on this branch.
async fn updated_at_of(pool: &PgPool, rule_id: Uuid) -> String {
    sqlx::query_scalar("SELECT updated_at::text FROM policy_rules WHERE id = $1")
        .bind(rule_id)
        .fetch_one(pool)
        .await
        .expect("rule must still exist")
}

/// Every policy on a table as `(policyname, qual)`, ordered by name.
///
/// `qual` is Postgres's own rendering of the USING expression, so a test that
/// compares it is reading the catalog rather than restating the migration.
async fn policies_of(pool: &PgPool, table: &str) -> Vec<(String, String)> {
    sqlx::query(
        "SELECT policyname::text AS name, qual::text AS qual
         FROM pg_policies
         WHERE schemaname = 'public' AND tablename = $1
         ORDER BY policyname",
    )
    .bind(table)
    .fetch_all(pool)
    .await
    .unwrap_or_else(|e| panic!("policy probe for {table}: {e}"))
    .into_iter()
    .map(|r| (r.get("name"), r.get("qual")))
    .collect()
}

/// `(rowsecurity, forcerowsecurity)` straight out of the catalog.
async fn rls_flags(pool: &PgPool, table: &str) -> (bool, bool) {
    let row = sqlx::query(
        "SELECT relrowsecurity, relforcerowsecurity
         FROM pg_class
         WHERE oid = to_regclass($1)",
    )
    .bind(format!("public.{table}"))
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("{table} must exist to be probed: {e}"));
    (row.get("relrowsecurity"), row.get("relforcerowsecurity"))
}

// ---------------------------------------------------------------------------
// The low-privilege connection. This is the entire point of the suite.
// ---------------------------------------------------------------------------

/// Create `secureprompt_runner` if absent, then hand this test database's
/// tables to it. Idempotent and concurrency-safe: roles are cluster-global
/// while `#[sqlx::test]` databases are per-test, so several tests race here.
///
/// `CREATE ON SCHEMA public` is the one addition over
/// `tests/migration_020_rls.rs`: 018, 021 and 023 are DDL migrations, and
/// without it they fail with `permission denied for schema public` before
/// reaching anything this suite is about.
async fn ensure_low_privilege_role(pool: &PgPool) {
    sqlx::raw_sql(&format!(
        "DO $$
         BEGIN
             CREATE ROLE {RLS_ROLE}
                 LOGIN PASSWORD '{RLS_PASSWORD}'
                 NOSUPERUSER CREATEDB CREATEROLE NOBYPASSRLS;
         EXCEPTION
             WHEN duplicate_object THEN NULL;
             WHEN unique_violation THEN NULL;
         END $$;"
    ))
    .execute(pool)
    .await
    .unwrap_or_else(|e| {
        panic!(
            "could not create the {RLS_ROLE} role ({e}). In CI this role is \
             created by scripts/ci/create-nonsuperuser-role.sh; locally the \
             connecting role needs CREATEROLE. This suite refuses to fall \
             back to the superuser connection, because a migration test that \
             runs as superuser cannot observe an RLS defect at all."
        )
    });

    sqlx::raw_sql(&format!(
        "GRANT USAGE, CREATE ON SCHEMA public TO {RLS_ROLE};
         GRANT ALL ON ALL TABLES IN SCHEMA public TO {RLS_ROLE};
         GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO {RLS_ROLE};"
    ))
    .execute(pool)
    .await
    .expect("grants on the test database");
}

/// Open a connection to the SAME `#[sqlx::test]` database as `RLS_ROLE`, and
/// assert ON THE WIRE that it really is powerless.
///
/// PREMISE ASSERTIONS. Without these the suite is worthless: if a future base
/// image, a stray `ALTER ROLE` or a typo handed this role SUPERUSER or
/// BYPASSRLS, every test below would keep passing while exercising no RLS at
/// all — the exact failure mode this workstream exists to prevent.
async fn low_privilege_connection(pool: &PgPool) -> PgConnection {
    ensure_low_privilege_role(pool).await;

    let options: PgConnectOptions = (*pool.connect_options())
        .clone()
        .username(RLS_ROLE)
        .password(RLS_PASSWORD);

    let mut conn = PgConnection::connect_with(&options)
        .await
        .expect("low-privilege connection to the test database");

    let row = sqlx::query(
        "SELECT current_user::text AS who, rolsuper, rolbypassrls
         FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&mut conn)
    .await
    .expect("identity probe");

    let who: String = row.get("who");
    let superuser: bool = row.get("rolsuper");
    let bypassrls: bool = row.get("rolbypassrls");

    assert_eq!(who, RLS_ROLE, "premise: connected as the wrong role");
    assert!(
        !superuser,
        "premise: {who} is a SUPERUSER, so it bypasses RLS and this test \
         proves nothing"
    );
    assert!(
        !bypassrls,
        "premise: {who} has BYPASSRLS, so it bypasses RLS and this test \
         proves nothing"
    );

    conn
}

/// Point the connection's RLS predicate at one workspace, for the rest of the
/// session. `is_local = false` because these tests issue statements outside a
/// transaction on a connection they own outright; a pooled caller must use
/// `db::scope::begin_scoped` instead, which sets it transaction-locally AND
/// reads it back.
async fn arm_scope(conn: &mut PgConnection, workspace_id: Uuid) {
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, false)")
        .bind(workspace_id.to_string())
        .execute(&mut *conn)
        .await
        .expect("arming app.current_workspace_id");

    let armed: Option<String> =
        sqlx::query_scalar("SELECT current_setting('app.current_workspace_id', true)")
            .fetch_one(&mut *conn)
            .await
            .expect("reading the GUC back");
    assert_eq!(
        armed.as_deref(),
        Some(workspace_id.to_string().as_str()),
        "premise: the scope did not arm, so every visibility assertion that \
         follows would be measuring an unset GUC instead of a tenancy boundary"
    );
}

// ===========================================================================
// 017 — BROKEN. A bare UPDATE against an RLS-protected table.
// ===========================================================================

/// THE TEST THAT WOULD HAVE CAUGHT 017.
///
/// Run verbatim by a role that cannot bypass RLS, 017 SUCCEEDS and changes
/// NOTHING. Both halves matter: an error would have been caught on the first
/// deployment; silence is what let it ship.
///
/// Three things stop this being vacuous:
///   * the premise assertions inside `low_privilege_connection`;
///   * `updated_at` is compared as well as `conditions`, so "matched a row
///     and only bumped the timestamp" cannot masquerade as "matched nothing";
///   * the POSITIVE CONTROL at the end runs the IDENTICAL file over the
///     superuser pool and requires the classes to appear. Without it, an
///     unchanged array could equally mean the fixture never matched 017's
///     guard, and the test would be measuring a typo instead of RLS.
#[sqlx::test]
async fn migration_017_is_a_silent_no_op_under_rls(pool: PgPool) {
    let workspace_a = seed_workspace(&pool, "Silent No-Op Co A").await;
    let workspace_b = seed_workspace(&pool, "Silent No-Op Co B").await;
    let rule_a = seed_rule(&pool, workspace_a, "Redact common PII", LEGACY_NINE).await;
    let rule_b = seed_rule(&pool, workspace_b, "Redact common PII", LEGACY_NINE).await;

    // PREMISE: the rows exist, are visible to the privileged pool, and are
    // MISSING the six classes 017 exists to add.
    let before_a = classes_of(&pool, rule_a).await;
    let before_b = classes_of(&pool, rule_b).await;
    let stamp_a = updated_at_of(&pool, rule_a).await;
    let stamp_b = updated_at_of(&pool, rule_b).await;
    for class in UZBEK_SIX {
        assert!(
            !before_a.contains(&class.to_owned()),
            "premise: {class} must be absent before 017 runs: {before_a:?}"
        );
    }
    assert_eq!(before_a.len(), 9, "premise: {before_a:?}");

    let mut conn = low_privilege_connection(&pool).await;
    sqlx::raw_sql(MIGRATION_017)
        .execute(&mut conn)
        .await
        .expect(
            "017 must SUCCEED under a NOBYPASSRLS role — the silence is the \
             whole defect. An error here would mean the migration fails loudly \
             instead, which is a different (and better) bug.",
        );

    assert_eq!(
        classes_of(&pool, rule_a).await,
        before_a,
        "017 ran as {RLS_ROLE} (NOSUPERUSER, NOBYPASSRLS) and reported \
         success. `policy_rules` has FORCE ROW LEVEL SECURITY keyed on \
         `app.current_workspace_id`, which the migration never sets, so its \
         bare UPDATE matched ZERO rows. If this assertion ever fails, 017 has \
         been made RLS-safe and this characterisation test should become a \
         positive one."
    );
    assert_eq!(classes_of(&pool, rule_b).await, before_b, "workspace B too");
    assert_eq!(
        updated_at_of(&pool, rule_a).await,
        stamp_a,
        "not even `updated_at` moved — the statement matched no row at all, \
         rather than matching one and writing only the timestamp"
    );
    assert_eq!(
        updated_at_of(&pool, rule_b).await,
        stamp_b,
        "workspace B too"
    );

    // POSITIVE CONTROL — the SAME file, the SAME rows, over the superuser
    // pool. It must land. This is what makes the assertions above about RLS
    // rather than about a guard the fixture failed to satisfy.
    sqlx::raw_sql(MIGRATION_017)
        .execute(&pool)
        .await
        .expect("017 must apply when RLS is bypassed");

    let after_a: BTreeSet<String> = classes_of(&pool, rule_a).await.into_iter().collect();
    for class in UZBEK_SIX {
        assert!(
            after_a.contains(class),
            "positive control: {class} must appear when 017 runs as a \
             BYPASSRLS role. It did not, so the fixture — not RLS — is what \
             made the low-privilege run a no-op: {after_a:?}"
        );
    }
    assert_eq!(after_a.len(), 15, "{after_a:?}");
}

/// 017's damage is ALREADY REPAIRED by 020, so there is nothing new to fix.
/// This is the test that decides whether this workstream needs to ship a new
/// migration, so it asserts the repair rather than assuming it: 017 runs
/// (no-op), then 020 runs on the SAME low-privilege connection and the six
/// classes must be there.
#[sqlx::test]
async fn migration_020_repairs_017_on_the_same_low_privilege_connection(pool: PgPool) {
    let workspace = seed_workspace(&pool, "Repaired By 020 Co").await;
    let rule_id = seed_rule(&pool, workspace, "Redact common PII", LEGACY_NINE).await;

    let mut conn = low_privilege_connection(&pool).await;
    sqlx::raw_sql(MIGRATION_017)
        .execute(&mut conn)
        .await
        .expect("017 applies (as a no-op)");

    // PREMISE: 017 really did nothing, so what 020 achieves below is 020's.
    let after_017: BTreeSet<String> = classes_of(&pool, rule_id).await.into_iter().collect();
    for class in UZBEK_SIX {
        assert!(
            !after_017.contains(class),
            "premise: 017 must have no-opped, otherwise this test does not \
             show that 020 is the thing repairing it: {after_017:?}"
        );
    }

    sqlx::raw_sql(MIGRATION_020)
        .execute(&mut conn)
        .await
        .expect("020 must apply cleanly as a NOSUPERUSER/NOBYPASSRLS role");

    let after_020: BTreeSet<String> = classes_of(&pool, rule_id).await.into_iter().collect();
    for class in UZBEK_SIX {
        assert!(
            after_020.contains(class),
            "020 did not repair what 017 no-opped, which would mean this \
             branch owes a new back-fill migration: {after_020:?}"
        );
    }
}

/// TENANCY for the table 017 targets. From workspace A's armed scope,
/// workspace B's `policy_rules` row is invisible, un-updatable and
/// un-insertable.
///
/// The positive control is A's own row: the same connection, the same scope,
/// must see and write THAT. Without it, "B is invisible" would also be
/// satisfied by a connection that can see nothing at all.
#[sqlx::test]
async fn policy_rules_are_isolated_from_another_workspaces_scope(pool: PgPool) {
    let workspace_a = seed_workspace(&pool, "Tenant A").await;
    let workspace_b = seed_workspace(&pool, "Tenant B").await;
    let rule_a = seed_rule(&pool, workspace_a, "Rule A", LEGACY_NINE).await;
    let rule_b = seed_rule(&pool, workspace_b, "Rule B", LEGACY_NINE).await;

    let mut conn = low_privilege_connection(&pool).await;
    arm_scope(&mut conn, workspace_a).await;

    let visible: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM policy_rules ORDER BY name")
        .fetch_all(&mut conn)
        .await
        .expect("select under scope A");
    assert_eq!(
        visible,
        vec![rule_a],
        "scope A must see exactly its own rule. Seeing B's row is a \
         cross-tenant read; seeing none means the positive control below \
         cannot distinguish isolation from a broken connection."
    );

    let cross_update = sqlx::query("UPDATE policy_rules SET priority = 999 WHERE id = $1")
        .bind(rule_b)
        .execute(&mut conn)
        .await
        .expect("an UPDATE that matches nothing is not an error — that is the trap");
    assert_eq!(
        cross_update.rows_affected(),
        0,
        "scope A updated workspace B's rule"
    );

    let cross_insert = sqlx::query(
        "INSERT INTO policy_rules
            (id, workspace_id, name, priority, conditions, action, action_params,
             enabled, dry_run, created_at, updated_at)
         VALUES ($1, $2, 'Planted', 50, '[]'::jsonb, 'redact', '{}'::jsonb,
                 true, false, NOW(), NOW())",
    )
    .bind(Uuid::new_v4())
    .bind(workspace_b)
    .execute(&mut conn)
    .await;
    assert!(
        cross_insert.is_err(),
        "scope A inserted a rule into workspace B. Writes are the LOUD half \
         of RLS: this one must be rejected, not silently dropped."
    );

    // POSITIVE CONTROL — the same connection, the same scope, its OWN row.
    let own_update = sqlx::query("UPDATE policy_rules SET priority = 42 WHERE id = $1")
        .bind(rule_a)
        .execute(&mut conn)
        .await
        .expect("scope A must be able to update its own rule");
    assert_eq!(
        own_update.rows_affected(),
        1,
        "positive control: scope A cannot write its OWN row either, so the \
         zero above says nothing about tenancy"
    );
}

// ===========================================================================
// 018 — CORRECT. Pure DDL; the new table carries no RLS, by design.
// ===========================================================================

/// Drop what `#[sqlx::test]` already applied so the migration can be replayed
/// as the low-privilege role. `CASCADE` because 021 and later reference
/// nothing here, but a dependent view added later must not make this silently
/// skip.
async fn drop_for_replay(pool: &PgPool, tables: &[&str]) {
    for table in tables {
        sqlx::raw_sql(&format!("DROP TABLE IF EXISTS {table} CASCADE"))
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("dropping {table} for replay: {e}"));
    }
}

/// 018 applies as a NOSUPERUSER/NOBYPASSRLS role, and the table it creates
/// behaves as specified: default `block`, CHECK rejects anything else.
///
/// MUTATION-VERIFIED: replacing 018's `DEFAULT 'block'` with
/// `DEFAULT 'degrade_with_alert'` in the migration file turns this test red on
/// the default assertion, so it is reading the migration and not a constant.
#[sqlx::test]
async fn migration_018_applies_under_a_non_superuser_role(pool: PgPool) {
    drop_for_replay(&pool, &["workspace_sidecar_policy"]).await;
    let workspace = seed_workspace(&pool, "Sidecar Policy Co").await;

    // PREMISE: the table is really gone, so "it exists afterwards" is 018's
    // doing and not a leftover from the harness's own migration run.
    let exists: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('public.workspace_sidecar_policy')::text")
            .fetch_one(&pool)
            .await
            .expect("regclass probe");
    assert_eq!(exists, None, "premise: the table must be dropped first");

    let mut conn = low_privilege_connection(&pool).await;
    sqlx::raw_sql(MIGRATION_018)
        .execute(&mut conn)
        .await
        .expect("018 must apply cleanly as a NOSUPERUSER/NOBYPASSRLS role");

    sqlx::query("INSERT INTO workspace_sidecar_policy (workspace_id) VALUES ($1)")
        .bind(workspace)
        .execute(&pool)
        .await
        .expect("insert with defaults");
    let mode: String = sqlx::query_scalar(
        "SELECT sidecar_unavailable FROM workspace_sidecar_policy WHERE workspace_id = $1",
    )
    .bind(workspace)
    .fetch_one(&pool)
    .await
    .expect("read back");
    assert_eq!(
        mode, "block",
        "018's default is the fail-closed choice; a different default silently \
         changes what an outage does to every workspace that never chose"
    );

    let bad = sqlx::query(
        "UPDATE workspace_sidecar_policy SET sidecar_unavailable = 'fail_open' WHERE workspace_id = $1",
    )
    .bind(workspace)
    .execute(&pool)
    .await;
    assert!(
        bad.is_err(),
        "the CHECK constraint must reject unknown modes"
    );
}

/// TENANCY for `workspace_sidecar_policy` (018), armed by migration 030.
///
/// 018 shipped this table with no row-level security at all — its header calls
/// that deliberate — so until 030 another tenant's scope could read AND write
/// its rows. This test asserts the boundary on both halves.
///
/// Three things stop it being vacuous:
///   * the premise assertions inside `low_privilege_connection`;
///   * `policy_rules` on the SAME connection in the SAME scope is the POSITIVE
///     CONTROL for the read, and workspace A's OWN row is the positive control
///     for the write — without them, "B is invisible / unwritable" would also
///     be satisfied by a connection that can see and write nothing at all;
///   * B's row is re-read through the privileged pool afterwards, so a blocked
///     UPDATE is told apart from an UPDATE that ran and changed nothing.
#[sqlx::test]
async fn workspace_sidecar_policy_is_isolated_from_another_workspaces_scope(pool: PgPool) {
    let workspace_a = seed_workspace(&pool, "Sidecar Tenant A").await;
    let workspace_b = seed_workspace(&pool, "Sidecar Tenant B").await;
    let rule_a = seed_rule(&pool, workspace_a, "Rule A", LEGACY_NINE).await;
    seed_rule(&pool, workspace_b, "Rule B", LEGACY_NINE).await;

    for (workspace, mode) in [(workspace_a, "block"), (workspace_b, "degrade_with_alert")] {
        sqlx::query(
            "INSERT INTO workspace_sidecar_policy (workspace_id, sidecar_unavailable)
             VALUES ($1, $2)",
        )
        .bind(workspace)
        .bind(mode)
        .execute(&pool)
        .await
        .expect("a workspace chooses its sidecar policy");
    }

    // PREMISE: both rows really are on disk. Otherwise "A cannot see B's row"
    // would be satisfied by there being no row to see.
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM workspace_sidecar_policy")
        .fetch_one(&pool)
        .await
        .expect("row count through the privileged pool");
    assert_eq!(stored, 2, "premise: two rows must exist before scoping");

    let mut conn = low_privilege_connection(&pool).await;
    arm_scope(&mut conn, workspace_a).await;

    // POSITIVE CONTROL first: on this very connection, in this very scope, an
    // already-RLS-protected table IS isolated.
    let rules: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM policy_rules")
        .fetch_all(&mut conn)
        .await
        .expect("policy_rules under scope A");
    assert_eq!(
        rules,
        vec![rule_a],
        "premise: policy_rules must be isolated on this connection, otherwise \
         the assertions below prove nothing about the table"
    );

    let visible: Vec<Uuid> = sqlx::query_scalar(
        "SELECT workspace_id FROM workspace_sidecar_policy ORDER BY workspace_id",
    )
    .fetch_all(&mut conn)
    .await
    .expect("sidecar policy under scope A");
    assert_eq!(
        visible,
        vec![workspace_a],
        "workspace A's scope must see its OWN row and ONLY its own row. Seeing \
         both is the pre-030 defect; seeing neither would mean the scope did \
         not arm."
    );

    // WRITE half, cross-tenant: rejected.
    let cross = sqlx::query(
        "UPDATE workspace_sidecar_policy SET sidecar_unavailable = 'block' WHERE workspace_id = $1",
    )
    .bind(workspace_b)
    .execute(&mut conn)
    .await
    .expect("an UPDATE filtered out by RLS is not an error, it matches nothing");
    assert_eq!(
        cross.rows_affected(),
        0,
        "workspace A's scope must not be able to overwrite workspace B's \
         fail-open/fail-closed choice"
    );

    // WRITE half, own-tenant: the positive control. Without it, `0` above is
    // equally satisfied by a connection that cannot write at all.
    let own = sqlx::query(
        "UPDATE workspace_sidecar_policy SET sidecar_unavailable = 'degrade_with_alert'
         WHERE workspace_id = $1",
    )
    .bind(workspace_a)
    .execute(&mut conn)
    .await
    .expect("own-scope update");
    assert_eq!(
        own.rows_affected(),
        1,
        "premise: the armed scope must still be able to write its OWN row"
    );

    // And B's row is untouched ON DISK — a blocked UPDATE, not one that ran.
    let b_mode: String = sqlx::query_scalar(
        "SELECT sidecar_unavailable FROM workspace_sidecar_policy WHERE workspace_id = $1",
    )
    .bind(workspace_b)
    .fetch_one(&pool)
    .await
    .expect("B's row read through the privileged pool");
    assert_eq!(
        b_mode, "degrade_with_alert",
        "B's stored choice must survive verbatim"
    );

    // INSERTing a row FOR B from A's scope is the loud half of the same rule:
    // a policy stated with USING only supplies WITH CHECK as well.
    let forged = sqlx::query(
        "INSERT INTO workspace_sidecar_policy (workspace_id, sidecar_unavailable)
         VALUES ($1, 'degrade_with_alert')
         ON CONFLICT (workspace_id) DO UPDATE SET sidecar_unavailable = 'degrade_with_alert'",
    )
    .bind(seed_workspace(&pool, "Sidecar Tenant C").await)
    .execute(&mut conn)
    .await;
    let error = forged.expect_err("inserting a row for another workspace must be refused");
    assert!(
        error.to_string().contains("row-level security"),
        "the refusal must be the RLS one, not a constraint violation standing \
         in for it. Got: {error}"
    );

    // Last, the mechanism. Stated after the behaviour so that a regression
    // fails on what a tenant can actually reach, not on a catalog flag.
    assert_eq!(
        rls_flags(&pool, "workspace_sidecar_policy").await,
        (true, true),
        "migration 030 must ENABLE and FORCE row-level security here. ENABLE \
         alone exempts the table OWNER, which under the DB role-split is the \
         migration role, so FORCE is not decoration."
    );
}

/// THE SILENT-FAILURE SHAPE FOR A DDL MIGRATION.
///
/// 018, 021 and 023 each end with
/// `GRANT ... ON ALL TABLES IN SCHEMA public TO secureprompt_app`. Executed
/// by a role that does not own most of those tables, that statement emits a
/// `WARNING: no privileges were granted for "..."` per table and REPORTS
/// SUCCESS — the GRANT analogue of 017's `UPDATE 0`. It still does its real
/// job (the table the migration just created), which is why 018 is correct;
/// but under the DB role-split those repeated GRANT lines stop covering
/// anything else, silently.
///
/// Measured here rather than asserted in prose: a scratch table owned by the
/// superuser, with `secureprompt_app`'s privileges revoked, must STILL be
/// un-granted after the migration runs, while the new table IS granted.
#[sqlx::test]
async fn migration_018_grant_silently_skips_tables_the_running_role_does_not_own(pool: PgPool) {
    drop_for_replay(&pool, &["workspace_sidecar_policy"]).await;

    sqlx::raw_sql(
        "CREATE TABLE grant_probe (id UUID PRIMARY KEY);
         REVOKE ALL ON grant_probe FROM secureprompt_app;",
    )
    .execute(&pool)
    .await
    .expect("scratch table owned by the privileged role");

    // PREMISE: the probe really is un-granted before the migration runs.
    let before: bool =
        sqlx::query_scalar("SELECT has_table_privilege('secureprompt_app','grant_probe','SELECT')")
            .fetch_one(&pool)
            .await
            .expect("privilege probe");
    assert!(!before, "premise: the scratch table must start un-granted");

    let mut conn = low_privilege_connection(&pool).await;
    sqlx::raw_sql(MIGRATION_018)
        .execute(&mut conn)
        .await
        .expect("018 must SUCCEED despite being unable to grant on most tables");

    let probe_after: bool =
        sqlx::query_scalar("SELECT has_table_privilege('secureprompt_app','grant_probe','SELECT')")
            .fetch_one(&pool)
            .await
            .expect("privilege probe");
    assert!(
        !probe_after,
        "the GRANT was expected to skip a table the running role does not own. \
         It did not, so this test is no longer documenting the shape it claims."
    );

    let new_table_after: bool = sqlx::query_scalar(
        "SELECT has_table_privilege('secureprompt_app','workspace_sidecar_policy','INSERT')",
    )
    .fetch_one(&pool)
    .await
    .expect("privilege probe");
    assert!(
        new_table_after,
        "018's GRANT must still cover the table 018 itself created — that is \
         the part the migration exists to do, and the part a role-split must \
         not break"
    );
}

// ===========================================================================
// 021 — CORRECT. Pure DDL; neither new table carries RLS.
// ===========================================================================

/// 021 applies as a NOSUPERUSER/NOBYPASSRLS role and its safety-critical
/// defaults survive: capture OFF, 30-day retention, bounds enforced.
///
/// MUTATION-VERIFIED: changing `enabled BOOL NOT NULL DEFAULT false` to
/// `DEFAULT true` in the migration file turns this test red on the `enabled`
/// assertion.
#[sqlx::test]
async fn migration_021_applies_under_a_non_superuser_role(pool: PgPool) {
    drop_for_replay(&pool, &["raw_capture_audit", "workspace_raw_capture"]).await;
    let workspace = seed_workspace(&pool, "Raw Capture Co").await;

    for table in ["workspace_raw_capture", "raw_capture_audit"] {
        let probe = format!("SELECT to_regclass('public.{table}')::text");
        let exists: Option<String> = sqlx::query_scalar(&probe)
            .fetch_one(&pool)
            .await
            .expect("regclass probe");
        assert_eq!(exists, None, "premise: {table} must be dropped first");
    }

    let mut conn = low_privilege_connection(&pool).await;
    sqlx::raw_sql(MIGRATION_021)
        .execute(&mut conn)
        .await
        .expect("021 must apply cleanly as a NOSUPERUSER/NOBYPASSRLS role");

    sqlx::query("INSERT INTO workspace_raw_capture (workspace_id) VALUES ($1)")
        .bind(workspace)
        .execute(&pool)
        .await
        .expect("insert with defaults");
    let row = sqlx::query(
        "SELECT enabled, retention_days FROM workspace_raw_capture WHERE workspace_id = $1",
    )
    .bind(workspace)
    .fetch_one(&pool)
    .await
    .expect("read back");
    assert!(
        !row.get::<bool, _>("enabled"),
        "021 exists to make plaintext capture opt-in; a true default reverses it"
    );
    assert_eq!(row.get::<i32, _>("retention_days"), 30);

    let out_of_range = sqlx::query(
        "UPDATE workspace_raw_capture SET retention_days = 4000 WHERE workspace_id = $1",
    )
    .bind(workspace)
    .execute(&pool)
    .await;
    assert!(
        out_of_range.is_err(),
        "the CHECK on retention_days (1..=3650) must be enforced"
    );
}

/// TENANCY for 021's two tables, armed by migration 030.
///
/// `raw_capture_audit` is the one that matters most. It is a SOURCE of the
/// signed compliance export: `secureprompt-worker/src/tasks/audit_export.rs::
/// fetch_control_rows` reads it inside `begin_scoped`, and until 030 its
/// doc-comment's claim that "the RLS-armed table is readable" was false — the
/// table had no RLS, and the only thing keeping one tenant's audit rows out of
/// another tenant's signed attestation was the query's own
/// `WHERE workspace_id = $1`. This test makes the database enforce it too, so
/// that removing that predicate stops being a one-line tenancy breach.
///
/// The positive controls are `policy_rules` (read) and workspace A's own rows
/// (read and write): without them, "B is invisible" would also be satisfied by
/// a connection that can see nothing at all.
#[sqlx::test]
async fn migration_021_tables_are_isolated_from_another_workspaces_scope(pool: PgPool) {
    let workspace_a = seed_workspace(&pool, "Capture Tenant A").await;
    let workspace_b = seed_workspace(&pool, "Capture Tenant B").await;
    let rule_a = seed_rule(&pool, workspace_a, "Rule A", LEGACY_NINE).await;

    for (workspace, email) in [
        (workspace_a, "admin@tenant-a.example"),
        (workspace_b, "admin@tenant-b.example"),
    ] {
        sqlx::query("INSERT INTO workspace_raw_capture (workspace_id, enabled) VALUES ($1, true)")
            .bind(workspace)
            .execute(&pool)
            .await
            .expect("a workspace turns capture on");

        sqlx::query(
            "INSERT INTO raw_capture_audit
                (id, workspace_id, actor_user_id, actor_email, enabled_before, enabled_after,
                 retention_days_before, retention_days_after)
             VALUES ($1, $2, NULL, $3, false, true, 30, 90)",
        )
        .bind(Uuid::new_v4())
        .bind(workspace)
        .bind(email)
        .execute(&pool)
        .await
        .expect("and the change is audited");
    }

    // PREMISE: both tenants' rows really are on disk.
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM raw_capture_audit")
        .fetch_one(&pool)
        .await
        .expect("audit row count through the privileged pool");
    assert_eq!(
        stored, 2,
        "premise: two audit rows must exist before scoping"
    );

    let mut conn = low_privilege_connection(&pool).await;
    arm_scope(&mut conn, workspace_a).await;

    // POSITIVE CONTROL: RLS does bite on this connection.
    let rules: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM policy_rules")
        .fetch_all(&mut conn)
        .await
        .expect("policy_rules under scope A");
    assert_eq!(
        rules,
        vec![rule_a],
        "premise: policy_rules must be isolated"
    );

    let visible: Vec<String> = sqlx::query_scalar("SELECT actor_email FROM raw_capture_audit")
        .fetch_all(&mut conn)
        .await
        .expect("raw_capture_audit under scope A");
    assert_eq!(
        visible,
        vec!["admin@tenant-a.example".to_owned()],
        "workspace A's scope must read its OWN audit row and no other. Reading \
         B's — including the actor's email address — is what fed the wrong \
         tenant's signed compliance export before 030."
    );

    let settings: Vec<Uuid> =
        sqlx::query_scalar("SELECT workspace_id FROM workspace_raw_capture ORDER BY workspace_id")
            .fetch_all(&mut conn)
            .await
            .expect("workspace_raw_capture under scope A");
    assert_eq!(
        settings,
        vec![workspace_a],
        "the settings table must be isolated on the same terms as its audit trail"
    );

    // WRITE half: appending an audit row that CLAIMS to be workspace B's is
    // the forgery this table exists to make impossible.
    let forged = sqlx::query(
        "INSERT INTO raw_capture_audit
            (id, workspace_id, actor_user_id, actor_email, enabled_before, enabled_after,
             retention_days_before, retention_days_after)
         VALUES ($1, $2, NULL, 'attacker@tenant-a.example', true, false, 90, 30)",
    )
    .bind(Uuid::new_v4())
    .bind(workspace_b)
    .execute(&mut conn)
    .await;
    let error = forged.expect_err("appending to another workspace's audit trail must be refused");
    assert!(
        error.to_string().contains("row-level security"),
        "the refusal must be the RLS one, not a constraint violation standing \
         in for it. Got: {error}"
    );

    // POSITIVE CONTROL for the write half: A's own append still works.
    sqlx::query(
        "INSERT INTO raw_capture_audit
            (id, workspace_id, actor_user_id, actor_email, enabled_before, enabled_after,
             retention_days_before, retention_days_after)
         VALUES ($1, $2, NULL, 'admin@tenant-a.example', true, false, 90, 30)",
    )
    .bind(Uuid::new_v4())
    .bind(workspace_a)
    .execute(&mut conn)
    .await
    .expect("premise: the armed scope must still be able to append its OWN audit row");

    // B's trail is intact ON DISK — one row, its own.
    let b_rows: Vec<String> =
        sqlx::query_scalar("SELECT actor_email FROM raw_capture_audit WHERE workspace_id = $1")
            .bind(workspace_b)
            .fetch_all(&pool)
            .await
            .expect("B's trail read through the privileged pool");
    assert_eq!(
        b_rows,
        vec!["admin@tenant-b.example".to_owned()],
        "B's audit trail must be exactly what B wrote"
    );

    // Last, the mechanism.
    for table in ["workspace_raw_capture", "raw_capture_audit"] {
        assert_eq!(
            rls_flags(&pool, table).await,
            (true, true),
            "migration 030 must ENABLE and FORCE row-level security on {table}"
        );
    }
}

// ===========================================================================
// 022 — CORRECT, and load-bearing on `token_vault_entries` having no RLS.
// ===========================================================================

/// Put `token_vault_entries` back into its pre-022 shape so the migration can
/// be replayed, and hand it to the low-privilege role.
///
/// The OWNER change is required, not cosmetic: 022 issues `ALTER TABLE`, and
/// Postgres refuses that to a non-owner — measured, `ERROR: must be owner of
/// table token_vault_entries`. Ownership is the one privilege a role-split
/// migration role must have and is unrelated to RLS: every RLS-protected
/// table in this schema uses FORCE ROW LEVEL SECURITY, which subjects the
/// owner too. `rls_still_bites_for_the_owner` below proves that rather than
/// asserting it.
async fn restore_pre_022_token_vault(pool: &PgPool) {
    ensure_low_privilege_role(pool).await;
    sqlx::raw_sql(
        "ALTER TABLE token_vault_entries DROP COLUMN mapping_ciphertext;
         ALTER TABLE token_vault_entries ADD COLUMN mapping JSONB NOT NULL DEFAULT '{}'::jsonb;
         ALTER TABLE token_vault_entries ALTER COLUMN mapping DROP DEFAULT;
         ALTER TABLE token_vault_entries OWNER TO secureprompt_runner;",
    )
    .execute(pool)
    .await
    .expect("restoring the pre-022 token vault shape");
}

async fn seed_vault_row(pool: &PgPool, workspace_id: Uuid, original: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO token_vault_entries (id, workspace_id, mapping)
         VALUES ($1, $2, jsonb_build_object('{{Person_1}}', $3::text))",
    )
    .bind(id)
    .bind(workspace_id)
    .bind(original)
    .execute(pool)
    .await
    .expect("vault row insert");
    id
}

/// THE PROPERTY 022 CLAIMS: the plaintext originals are GONE, and the column
/// that could hold them no longer exists — under a role that cannot bypass
/// RLS.
///
/// `rows_affected` is deliberately not the assertion. What is asserted is
/// that the bytes are unreachable: zero rows, no `mapping` column, and a
/// full-table scan for the literal name finds nothing.
#[sqlx::test]
async fn migration_022_removes_the_plaintext_originals_under_a_non_superuser_role(pool: PgPool) {
    let workspace_a = seed_workspace(&pool, "Vault Tenant A").await;
    let workspace_b = seed_workspace(&pool, "Vault Tenant B").await;
    restore_pre_022_token_vault(&pool).await;
    seed_vault_row(&pool, workspace_a, "Anvar Karimov").await;
    seed_vault_row(&pool, workspace_b, "Bektemir Yusupov").await;

    // PREMISE: the plaintext really is on disk and readable right now. This
    // is the state migration 008 shipped and 022 exists to end.
    let plaintext: Vec<String> =
        sqlx::query_scalar("SELECT mapping::text FROM token_vault_entries")
            .fetch_all(&pool)
            .await
            .expect("pre-022 plaintext read");
    assert_eq!(plaintext.len(), 2, "premise: {plaintext:?}");
    assert!(
        plaintext.iter().any(|m| m.contains("Anvar Karimov")),
        "premise: the un-redacted original must be readable before 022: {plaintext:?}"
    );

    let mut conn = low_privilege_connection(&pool).await;
    sqlx::raw_sql(MIGRATION_022)
        .execute(&mut conn)
        .await
        .expect("022 must apply cleanly as a NOSUPERUSER/NOBYPASSRLS role");

    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM token_vault_entries")
        .fetch_one(&pool)
        .await
        .expect("count after");
    assert_eq!(
        remaining, 0,
        "022's DELETE must actually delete. Under RLS a bare DELETE matches \
         zero rows and succeeds; this counts the survivors instead of trusting \
         the row count the statement reported."
    );

    let mapping_column: Option<String> = sqlx::query_scalar::<_, String>(
        "SELECT column_name::text FROM information_schema.columns
         WHERE table_name = 'token_vault_entries' AND column_name = 'mapping'",
    )
    .fetch_optional(&pool)
    .await
    .expect("column probe");
    assert_eq!(
        mapping_column, None,
        "the plaintext `mapping` column must be gone, not merely emptied"
    );

    let ciphertext_nullable: String = sqlx::query_scalar(
        "SELECT is_nullable::text FROM information_schema.columns
         WHERE table_name = 'token_vault_entries' AND column_name = 'mapping_ciphertext'",
    )
    .fetch_one(&pool)
    .await
    .expect("mapping_ciphertext must exist after 022");
    assert_eq!(
        ciphertext_nullable, "NO",
        "a nullable ciphertext column would let a future insert bug write a \
         row with no payload and no error — 022's own header says so"
    );
}

/// 022 IS ONLY SAFE BECAUSE `token_vault_entries` HAS NO RLS. This test
/// executes the counterfactual so the dependency is not left as a comment.
///
/// MEASURED: with `ENABLE`/`FORCE ROW LEVEL SECURITY` and the standard
/// `workspace_isolation` policy on the table, 022 run by its own OWNER gives
/// `DELETE 0` followed by
/// `ERROR: column "mapping_ciphertext" of relation "token_vault_entries"
/// contains null values` — the migration aborts and the plaintext survives.
///
/// It also proves ownership does NOT re-open RLS: the role owns this table
/// and is still blocked, because the policy is FORCEd.
#[sqlx::test]
async fn migration_022_would_abort_if_token_vault_entries_gained_rls(pool: PgPool) {
    let workspace = seed_workspace(&pool, "Counterfactual Co").await;
    restore_pre_022_token_vault(&pool).await;
    seed_vault_row(&pool, workspace, "Anvar Karimov").await;

    // PREMISE for the whole test: as SHIPPED, the table has no RLS. If this
    // ever changes, 022 becomes a migration that aborts on replay and this
    // test is the warning.
    assert_eq!(
        rls_flags(&pool, "token_vault_entries").await,
        (false, false),
        "`token_vault_entries` has gained row-level security. Migration 022 \
         DELETEs the table and then adds a NOT NULL column, so an RLS-blocked \
         DELETE turns it into a hard failure on any replay. See this test's \
         counterfactual below for the exact error."
    );

    sqlx::raw_sql(
        "ALTER TABLE token_vault_entries ENABLE ROW LEVEL SECURITY;
         ALTER TABLE token_vault_entries FORCE ROW LEVEL SECURITY;
         CREATE POLICY workspace_isolation ON token_vault_entries
             USING (workspace_id = current_setting('app.current_workspace_id', true)::uuid);",
    )
    .execute(&pool)
    .await
    .expect("applying the counterfactual policy");

    let mut conn = low_privilege_connection(&pool).await;

    let owner: String = sqlx::query_scalar(
        "SELECT pg_get_userbyid(relowner)::text FROM pg_class
         WHERE oid = to_regclass('public.token_vault_entries')",
    )
    .fetch_one(&mut conn)
    .await
    .expect("owner probe");
    assert_eq!(
        owner, RLS_ROLE,
        "premise: the low-privilege role must OWN the table here, so that the \
         block below is attributable to FORCE ROW LEVEL SECURITY and not to a \
         missing privilege"
    );

    let outcome = sqlx::raw_sql(MIGRATION_022).execute(&mut conn).await;
    let error = outcome.expect_err(
        "022 was expected to ABORT once the table is RLS-protected: its DELETE \
         matches zero rows, so `ADD COLUMN mapping_ciphertext TEXT NOT NULL` \
         hits a non-empty table",
    );
    let message = error.to_string();
    assert!(
        message.contains("contains null values"),
        "the abort must be the NOT NULL one, which is what proves the DELETE \
         silently matched nothing. Got: {message}"
    );

    let survivors: Vec<String> =
        sqlx::query_scalar("SELECT mapping::text FROM token_vault_entries")
            .fetch_all(&pool)
            .await
            .expect("post-abort read");
    assert!(
        survivors.iter().any(|m| m.contains("Anvar Karimov")),
        "the whole migration rolls back, so the plaintext the migration exists \
         to destroy is still there: {survivors:?}"
    );
}

// ===========================================================================
// 023 — Pure DDL. Armed by 030, but NOT with the standard policy.
// ===========================================================================

/// 023 applies as a NOSUPERUSER/NOBYPASSRLS role and its three indexes exist.
///
/// MUTATION-VERIFIED: deleting the `idx_retention_purge_audit_workspace`
/// statement from the migration file turns this test red on the index count.
#[sqlx::test]
async fn migration_023_applies_under_a_non_superuser_role(pool: PgPool) {
    drop_for_replay(&pool, &["retention_purge_audit"]).await;

    let exists: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('public.retention_purge_audit')::text")
            .fetch_one(&pool)
            .await
            .expect("regclass probe");
    assert_eq!(exists, None, "premise: the table must be dropped first");

    let mut conn = low_privilege_connection(&pool).await;
    sqlx::raw_sql(MIGRATION_023)
        .execute(&mut conn)
        .await
        .expect("023 must apply cleanly as a NOSUPERUSER/NOBYPASSRLS role");

    let indexes: Vec<String> = sqlx::query_scalar(
        "SELECT indexname::text FROM pg_indexes
         WHERE tablename = 'retention_purge_audit' AND indexname LIKE 'idx_%'
         ORDER BY indexname",
    )
    .fetch_all(&pool)
    .await
    .expect("index probe");
    assert_eq!(
        indexes,
        vec![
            "idx_retention_purge_audit_run".to_owned(),
            "idx_retention_purge_audit_scope_time".to_owned(),
            "idx_retention_purge_audit_workspace".to_owned(),
        ],
        "023's indexes are what make `what did the 04:00 run do` one query"
    );

    // The run-with-nothing-to-delete row 023's header insists on.
    sqlx::query(
        "INSERT INTO retention_purge_audit
            (id, run_id, scope, workspace_id, cutoff, rows_deleted,
             rows_remaining_past_cutoff, status, started_at)
         VALUES ($1, $2, 'token_vault_entries', NULL, NOW(), 0, 0, 'ok', NOW())",
    )
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .execute(&pool)
    .await
    .expect("a zero-row purge must still be recordable");
}

/// The `retention_purge_audit` INSERT the purge job issues, for one scope.
///
/// A closure factory rather than a helper function because both tests below
/// need it bound to a different `workspace_id` several times on the same
/// connection.
fn purge_row(
    workspace_id: Option<Uuid>,
) -> sqlx::query::Query<'static, sqlx::Postgres, sqlx::postgres::PgArguments> {
    sqlx::query(
        "INSERT INTO retention_purge_audit
            (id, run_id, scope, workspace_id, cutoff, rows_deleted,
             rows_remaining_past_cutoff, status, started_at)
         VALUES ($1, $2, 'token_vault_entries', $3, NOW(), 7, 0, 'ok', NOW())",
    )
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .bind(workspace_id)
}

/// TENANCY for `retention_purge_audit`, armed by migration 030 with a policy
/// that is DELIBERATELY NOT the standard one.
///
/// `workspace_id` is NULLABLE here by design: the token vault and the session
/// device-context scrub are purged globally, so those rows carry NULL. The
/// schema's standard predicate —
/// `workspace_id = current_setting('app.current_workspace_id', true)::uuid` —
/// is NULL, never true, for exactly those rows, so arming this table with it
/// would silently drop the purge audit trail's global half (and, on the read
/// side, would zero the excluded-row COUNT that
/// `audit_export.rs::fetch_control_rows` puts in the signed manifest). 030
/// therefore adds `workspace_id IS NULL OR ...`.
///
/// This test measures all four consequences on ONE armed connection: another
/// tenant's row is invisible and un-writable, the caller's own row is both,
/// and the global rows stay readable and writable.
#[sqlx::test]
async fn retention_purge_audit_isolates_tenants_and_still_admits_global_scopes(pool: PgPool) {
    let workspace_a = seed_workspace(&pool, "Purge Tenant A").await;
    let workspace_b = seed_workspace(&pool, "Purge Tenant B").await;
    let rule_a = seed_rule(&pool, workspace_a, "Rule A", LEGACY_NINE).await;

    for scope in [Some(workspace_a), Some(workspace_b), None] {
        purge_row(scope)
            .execute(&pool)
            .await
            .expect("the purge job records one row per scope");
    }

    // PREMISE: all three rows really are on disk.
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM retention_purge_audit")
        .fetch_one(&pool)
        .await
        .expect("row count through the privileged pool");
    assert_eq!(stored, 3, "premise: two scoped rows and one global row");

    let mut conn = low_privilege_connection(&pool).await;
    arm_scope(&mut conn, workspace_a).await;

    // POSITIVE CONTROL: RLS bites on this connection.
    let rules: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM policy_rules")
        .fetch_all(&mut conn)
        .await
        .expect("policy_rules under scope A");
    assert_eq!(
        rules,
        vec![rule_a],
        "premise: policy_rules must be isolated"
    );

    let visible: Vec<Option<Uuid>> = sqlx::query_scalar(
        "SELECT workspace_id FROM retention_purge_audit ORDER BY workspace_id NULLS FIRST",
    )
    .fetch_all(&mut conn)
    .await
    .expect("retention_purge_audit under scope A");
    assert_eq!(
        visible,
        vec![None, Some(workspace_a)],
        "the armed scope must see the GLOBAL row and its OWN row, and not \
         workspace B's. Seeing B's is the pre-030 defect; losing the global \
         row is the mistake 030's non-standard policy exists to avoid."
    );

    // The number `fetch_control_rows` puts in the signed manifest as
    // `excluded_rows`. Under the standard policy this would be a silent 0.
    let excluded: i64 =
        sqlx::query_scalar("SELECT count(*) FROM retention_purge_audit WHERE workspace_id IS NULL")
            .fetch_one(&mut conn)
            .await
            .expect("the export's own exclusion count, on the armed connection");
    assert_eq!(
        excluded, 1,
        "the export reports how many global purge rows it EXCLUDED. A policy \
         that hides them turns that disclosure into a false zero."
    );

    // WRITES. The purge job writes global rows with no scope armed at all, so
    // that must stay possible; a scoped row for the armed workspace must too;
    // a scoped row for ANOTHER workspace must not.
    purge_row(None)
        .execute(&mut conn)
        .await
        .expect("the purge job's GLOBAL scope row must remain writable");
    purge_row(Some(workspace_a))
        .execute(&mut conn)
        .await
        .expect("premise: a row for the armed scope must be writable");

    let forged = purge_row(Some(workspace_b)).execute(&mut conn).await;
    let error =
        forged.expect_err("writing a purge record attributed to another workspace must be refused");
    assert!(
        error.to_string().contains("row-level security"),
        "the refusal must be the RLS one, not a constraint violation standing \
         in for it. Got: {error}"
    );

    // B's trail is intact ON DISK: still exactly the one row B's run wrote.
    let b_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM retention_purge_audit WHERE workspace_id = $1")
            .bind(workspace_b)
            .fetch_one(&pool)
            .await
            .expect("B's rows read through the privileged pool");
    assert_eq!(
        b_rows, 1,
        "B's proof-of-purge trail must be exactly its own"
    );

    // Last, the mechanism.
    assert_eq!(
        rls_flags(&pool, "retention_purge_audit").await,
        (true, true),
        "migration 030 must ENABLE and FORCE row-level security here"
    );
}

/// WHY 030 DOES NOT GIVE `retention_purge_audit` THE STANDARD POLICY,
/// executed rather than argued.
///
/// The tripwire for anyone who "tidies" 030 by making all four tables use the
/// same `workspace_isolation` predicate: it shows the purge job's global row
/// being REJECTED, and the per-workspace insert succeeding in the same breath,
/// so the failure cannot be mistaken for the table being unwritable in
/// general. A rejected global INSERT is the LOUD half; the silent half — the
/// global rows vanishing from the export's excluded-row count — is covered by
/// the test above.
#[sqlx::test]
async fn retention_purge_audit_cannot_adopt_the_standard_workspace_policy(pool: PgPool) {
    let workspace = seed_workspace(&pool, "Purge Tenant").await;

    // PREMISE: as SHIPPED, the table is armed with the OR-global policy. If
    // that name or predicate changes, this counterfactual is swapping out
    // something other than what it thinks it is.
    assert_eq!(
        policies_of(&pool, "retention_purge_audit").await.len(),
        1,
        "premise: 030 ships exactly one policy on this table"
    );
    let (shipped_name, shipped_qual) = policies_of(&pool, "retention_purge_audit").await[0].clone();
    assert_eq!(shipped_name, "workspace_isolation_or_global");
    assert!(
        shipped_qual.contains("IS NULL"),
        "premise: the shipped predicate must be the one that admits global \
         rows. Got: {shipped_qual}"
    );

    ensure_low_privilege_role(&pool).await;
    sqlx::raw_sql(
        "ALTER TABLE retention_purge_audit OWNER TO secureprompt_runner;
         DROP POLICY workspace_isolation_or_global ON retention_purge_audit;
         CREATE POLICY workspace_isolation ON retention_purge_audit
             USING (workspace_id = current_setting('app.current_workspace_id', true)::uuid);",
    )
    .execute(&pool)
    .await
    .expect("applying the counterfactual policy");

    let mut conn = low_privilege_connection(&pool).await;
    arm_scope(&mut conn, workspace).await;

    // POSITIVE CONTROL: a per-workspace row for the armed scope goes in.
    purge_row(Some(workspace))
        .execute(&mut conn)
        .await
        .expect("a scoped purge record must still be writable under the policy");

    let global = purge_row(None).execute(&mut conn).await;
    let error = global.expect_err(
        "the purge job's GLOBAL scope row (workspace_id IS NULL) must be \
         rejected by the standard workspace_isolation policy — that is why \
         030 does not give this table that policy",
    );
    assert!(
        error.to_string().contains("row-level security"),
        "the rejection must be the RLS one, not a constraint violation \
         standing in for it. Got: {error}"
    );
}

// ===========================================================================
// 030 — the arming migration itself.
// ===========================================================================

/// Migration 030's whole surface, read out of the catalog.
///
/// The three behavioural tests above each cover one table. This one exists so
/// that DROPPING a table from 030's list is red even if someone also deletes
/// the test that covered it, and so the exact predicate is pinned rather than
/// inferred from behaviour.
#[sqlx::test]
async fn migration_030_arms_four_tables_with_two_deliberately_different_policies(pool: PgPool) {
    const STANDARD: &str =
        "(workspace_id = (current_setting('app.current_workspace_id'::text, true))::uuid)";
    const OR_GLOBAL: &str = "((workspace_id IS NULL) OR (workspace_id = \
                             (current_setting('app.current_workspace_id'::text, true))::uuid))";

    for (table, policy, qual) in [
        ("workspace_sidecar_policy", "workspace_isolation", STANDARD),
        ("workspace_raw_capture", "workspace_isolation", STANDARD),
        ("raw_capture_audit", "workspace_isolation", STANDARD),
        (
            "retention_purge_audit",
            "workspace_isolation_or_global",
            OR_GLOBAL,
        ),
    ] {
        assert_eq!(
            rls_flags(&pool, table).await,
            (true, true),
            "{table} must carry ENABLE and FORCE row level security after 030"
        );
        assert_eq!(
            policies_of(&pool, table).await,
            vec![(policy.to_owned(), qual.to_owned())],
            "{table}'s policy is what decides which rows a tenant reaches"
        );
    }
}
