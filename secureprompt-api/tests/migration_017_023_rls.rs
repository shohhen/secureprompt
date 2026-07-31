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

/// 018's `workspace_sidecar_policy` has NO row-level security. The migration
/// header says so deliberately; this test makes the CONSEQUENCE measurable
/// rather than a claim, because a table that carries `workspace_id` and no
/// RLS is exactly the shape a reader assumes is protected.
///
/// The positive control is `policy_rules` on the SAME connection in the SAME
/// scope: it IS isolated. So the cross-tenant read below is a property of the
/// table, not of the connection.
#[sqlx::test]
async fn migration_018_table_has_no_rls_so_another_scope_can_read_and_write_it(pool: PgPool) {
    let workspace_a = seed_workspace(&pool, "Sidecar Tenant A").await;
    let workspace_b = seed_workspace(&pool, "Sidecar Tenant B").await;
    let rule_a = seed_rule(&pool, workspace_a, "Rule A", LEGACY_NINE).await;
    seed_rule(&pool, workspace_b, "Rule B", LEGACY_NINE).await;
    sqlx::query(
        "INSERT INTO workspace_sidecar_policy (workspace_id, sidecar_unavailable)
         VALUES ($1, 'degrade_with_alert')",
    )
    .bind(workspace_b)
    .execute(&pool)
    .await
    .expect("workspace B chooses degrade");

    assert_eq!(
        rls_flags(&pool, "workspace_sidecar_policy").await,
        (false, false),
        "018 states `NO ROW-LEVEL SECURITY` in its header. If that has changed, \
         the reasoning in the header and in src/db/sidecar_policy_repo.rs is \
         stale and the rest of this test is asserting the wrong thing."
    );

    let mut conn = low_privilege_connection(&pool).await;
    arm_scope(&mut conn, workspace_a).await;

    // POSITIVE CONTROL first: on this very connection, in this very scope, an
    // RLS-protected table IS isolated.
    let rules: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM policy_rules")
        .fetch_all(&mut conn)
        .await
        .expect("policy_rules under scope A");
    assert_eq!(
        rules,
        vec![rule_a],
        "premise: policy_rules must be isolated on this connection, otherwise \
         the cross-tenant read below proves nothing about the table"
    );

    let leaked: Vec<Uuid> = sqlx::query_scalar("SELECT workspace_id FROM workspace_sidecar_policy")
        .fetch_all(&mut conn)
        .await
        .expect("sidecar policy under scope A");
    assert_eq!(
        leaked,
        vec![workspace_b],
        "MEASURED, not a defect claim: `workspace_sidecar_policy` has no RLS, \
         so workspace A's scope reads workspace B's row. Today the only guard \
         is that every query in src/db/sidecar_policy_repo.rs binds the \
         authenticated workspace_id — verified by reading it. This assertion \
         exists so that stops being an unwritten assumption."
    );

    let overwritten = sqlx::query(
        "UPDATE workspace_sidecar_policy SET sidecar_unavailable = 'block' WHERE workspace_id = $1",
    )
    .bind(workspace_b)
    .execute(&mut conn)
    .await
    .expect("update under scope A");
    assert_eq!(
        overwritten.rows_affected(),
        1,
        "and it is writable across tenants too — the same absence, on the \
         loud half"
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

/// 021's two tables carry `workspace_id` and NO row-level security. The
/// header calls that deliberate and points at `src/db/raw_capture_repo.rs`,
/// which does bind the workspace on every statement — verified by reading it.
///
/// This test pins the CONSEQUENCE, because one consumer reasons otherwise:
/// `secureprompt-worker/src/tasks/audit_export.rs::fetch_control_rows` reads
/// `raw_capture_audit` inside `begin_scoped` and its doc-comment says it
/// "runs inside a transaction opened by begin_scoped, so the RLS-armed table
/// is readable". `raw_capture_audit` is not RLS-armed; that export is
/// tenant-safe only because the query also binds `WHERE workspace_id = $1`.
/// If anyone ever removes that predicate trusting the scope, this test says
/// what actually protects the row.
#[sqlx::test]
async fn migration_021_audit_table_has_no_rls_so_another_scope_can_read_it(pool: PgPool) {
    let workspace_a = seed_workspace(&pool, "Capture Tenant A").await;
    let workspace_b = seed_workspace(&pool, "Capture Tenant B").await;
    let rule_a = seed_rule(&pool, workspace_a, "Rule A", LEGACY_NINE).await;

    let audit_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO raw_capture_audit
            (id, workspace_id, actor_user_id, actor_email, enabled_before, enabled_after,
             retention_days_before, retention_days_after)
         VALUES ($1, $2, NULL, 'admin@tenant-b.example', false, true, 30, 90)",
    )
    .bind(audit_id)
    .bind(workspace_b)
    .execute(&pool)
    .await
    .expect("workspace B turns capture on");

    for table in ["workspace_raw_capture", "raw_capture_audit"] {
        assert_eq!(
            rls_flags(&pool, table).await,
            (false, false),
            "{table} was expected to carry no RLS, per 021's header"
        );
    }

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

    let leaked: Vec<String> = sqlx::query_scalar("SELECT actor_email FROM raw_capture_audit")
        .fetch_all(&mut conn)
        .await
        .expect("raw_capture_audit under scope A");
    assert_eq!(
        leaked,
        vec!["admin@tenant-b.example".to_owned()],
        "workspace A's scope read workspace B's audit row, including the \
         actor's email address. Only the explicit `WHERE workspace_id = $1` in \
         raw_capture_repo.rs and audit_export.rs keeps that out of the wrong \
         tenant's compliance export."
    );
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
// 023 — CORRECT. Pure DDL; the table cannot adopt `workspace_isolation`.
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

/// WHY 023 HAS NO ROW-LEVEL SECURITY, executed rather than argued.
///
/// `retention_purge_audit.workspace_id` is NULLABLE by design — the token
/// vault is purged globally, so those rows carry NULL, and
/// `audit_export.rs::fetch_control_rows` counts them separately as
/// deliberately-excluded. The schema's standard policy is
/// `workspace_id = current_setting('app.current_workspace_id', true)::uuid`,
/// which is NULL — never true — for exactly those rows. Applying it would
/// make the purge job unable to record its own global scopes.
///
/// This test is the tripwire for anyone who "fixes" 023 by adding the usual
/// policy: it shows the global insert being REJECTED, and the per-workspace
/// insert succeeding in the same breath, so the failure cannot be mistaken
/// for the table being unwritable in general.
#[sqlx::test]
async fn retention_purge_audit_cannot_adopt_the_standard_workspace_policy(pool: PgPool) {
    let workspace = seed_workspace(&pool, "Purge Tenant").await;

    assert_eq!(
        rls_flags(&pool, "retention_purge_audit").await,
        (false, false),
        "023 ships this table without RLS. If that changed, the purge job's \
         global scopes need re-checking against the new policy."
    );

    ensure_low_privilege_role(&pool).await;
    sqlx::raw_sql(
        "ALTER TABLE retention_purge_audit OWNER TO secureprompt_runner;
         ALTER TABLE retention_purge_audit ENABLE ROW LEVEL SECURITY;
         ALTER TABLE retention_purge_audit FORCE ROW LEVEL SECURITY;
         CREATE POLICY workspace_isolation ON retention_purge_audit
             USING (workspace_id = current_setting('app.current_workspace_id', true)::uuid);",
    )
    .execute(&pool)
    .await
    .expect("applying the counterfactual policy");

    let mut conn = low_privilege_connection(&pool).await;
    arm_scope(&mut conn, workspace).await;

    let insert = |workspace_id: Option<Uuid>| {
        sqlx::query(
            "INSERT INTO retention_purge_audit
                (id, run_id, scope, workspace_id, cutoff, rows_deleted,
                 rows_remaining_past_cutoff, status, started_at)
             VALUES ($1, $2, 'token_vault_entries', $3, NOW(), 7, 0, 'ok', NOW())",
        )
        .bind(Uuid::new_v4())
        .bind(Uuid::new_v4())
        .bind(workspace_id)
    };

    // POSITIVE CONTROL: a per-workspace row for the armed scope goes in.
    insert(Some(workspace))
        .execute(&mut conn)
        .await
        .expect("a scoped purge record must still be writable under the policy");

    let global = insert(None).execute(&mut conn).await;
    let error = global.expect_err(
        "the purge job's GLOBAL scope row (workspace_id IS NULL) must be \
         rejected by the standard workspace_isolation policy — that is why \
         023 does not carry it",
    );
    assert!(
        error.to_string().contains("row-level security"),
        "the rejection must be the RLS one, not a constraint violation \
         standing in for it. Got: {error}"
    );
}
