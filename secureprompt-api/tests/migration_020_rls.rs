//! Migration 020 executed by a NON-SUPERUSER, NOBYPASSRLS Postgres role.
//!
//! WHY THIS SUITE EXISTS — the defect it was written to catch
//! `policy_rules` has FORCE ROW LEVEL SECURITY with
//! `USING (workspace_id = current_setting('app.current_workspace_id', true)::uuid)`
//! (`001_init.sql:78-95`). `current_setting(..., true)` yields NULL when the
//! GUC is unset, so a bare `UPDATE policy_rules ...` inside a migration
//! matches ZERO rows — and an `UPDATE` that matches zero rows is NOT an error.
//! The migration "succeeds", sqlx records it as applied, and the back-fill
//! silently ships as a no-op.
//!
//! `017_uzbek_identifier_policy_classes.sql` is that bare UPDATE. Measured on
//! a real database with all migrations applied and two seeded workspaces:
//!
//!     $ psql -U sp_probe rls_probe < 017_uzbek_identifier_policy_classes.sql
//!     UPDATE 0
//!     exit=0
//!
//! It looks correct today only because the compose `secureprompt` role is a
//! SUPERUSER (`rolsuper = t`, `rolbypassrls = t`), and superusers bypass RLS
//! unconditionally. Every existing migration test in this repo — including
//! `policy::tests::migration_backfill_tests` for 017 itself — connects as
//! that role, so NONE of them can observe this bug. That is precisely why the
//! tests below open their own low-privilege connection instead of using the
//! `#[sqlx::test]` pool: a suite that only ever runs as superuser proves
//! nothing about RLS.
//!
//! SCOPE — this suite now runs correctly under EITHER role, and is listed in
//! the `test:rls-nonsuperuser` CI job as well as the ordinary `test` job.
//!
//! It did not always. MEASURED before the conversion: pointing `DATABASE_URL`
//! at `secureprompt_runner` failed 7/7 before reaching a single assertion —
//!   `error 42501: new row violates row-level security policy for table
//!    "policy_rules"` at `seed_rule`'s INSERT.
//! The fixtures assumed the `#[sqlx::test]` pool could bypass RLS. They now
//! seed AND verify through `db::scope::begin_scoped`, the same armed
//! transaction the repositories open — which is not elevation, so a read
//! through it means what the assertion says it means under both roles.
//!
//! The one thing that could NOT become scoped is the POSITIVE CONTROL in
//! `bare_update_silently_matches_zero_rows_under_rls`. It used to be "the
//! same statement over the superuser pool must match 1 row", which stops
//! being a control the moment the pool is not a superuser. It is now "the
//! same statement, from an ARMED scope, must match 1 row" — one dimension
//! changed (the GUC), same guarantee, and true under both roles.

use secureprompt_api::db::scope::begin_scoped;
use secureprompt_api::db::workspace_repo::DEFAULT_POLICY_CLASSES;
use sqlx::postgres::PgConnectOptions;
use sqlx::{Connection, PgConnection, PgPool, Row};
use std::collections::BTreeSet;
use uuid::Uuid;

const MIGRATION_020: &str = include_str!("../migrations/020_reconcile_default_policy_classes.sql");

/// The role the migration is executed as. `scripts/ci/create-nonsuperuser-role.sh`
/// creates it in CI with exactly these attributes; `ensure_low_privilege_role`
/// below creates it on demand for local runs so that this suite can never
/// silently degrade into "ran as superuser after all".
const RLS_ROLE: &str = "secureprompt_runner";
const RLS_PASSWORD: &str = "secureprompt";

/// The class array every workspace seeded before the fix wave carries.
/// `GCP_KEY` / `AZURE_KEY` are the two DEAD NAMES that match nothing any
/// detector emits; they are part of the shape, which is why the migration's
/// "is this still the untouched seed?" guard is keyed on them.
const LEGACY_NINE: &str = r#"["PERSON","EMAIL_ADDRESS","PHONE_NUMBER","CREDIT_CARD","US_SSN","IBAN_CODE","AWS_ACCESS_KEY","GCP_KEY","AZURE_KEY"]"#;

/// What a database looks like when 017 no-opped under RLS but 019 (which was
/// written RLS-safely) applied: the legacy nine plus every credential class,
/// and NOT ONE of the six Uzbek identifiers. This is the exact state measured
/// on the probe database, and the state 020 has to repair.
const POST_019_WITHOUT_017: &str = r#"["PERSON","EMAIL_ADDRESS","PHONE_NUMBER","CREDIT_CARD","US_SSN","IBAN_CODE","AWS_ACCESS_KEY","GCP_KEY","AZURE_KEY","SSN","IBAN","GOOGLE_API_KEY","GCP_SERVICE_ACCOUNT_EMAIL","AZURE_STORAGE_CONNECTION_STRING","OPENAI_API_KEY","ANTHROPIC_API_KEY","STRIPE_SECRET_KEY","STRIPE_PUBLISHABLE_KEY","GITHUB_PAT","GITHUB_FINE_GRAINED_PAT","GITHUB_OAUTH_TOKEN","GITHUB_REFRESH_TOKEN","SLACK_BOT_TOKEN","SLACK_USER_TOKEN","SLACK_APP_TOKEN","PRIVATE_KEY_PEM","RSA_PRIVATE_KEY","OPENSSH_PRIVATE_KEY","POSTGRESQL_URI","MONGODB_URI","WEBHOOK_URL","BEARER_TOKEN","BASIC_AUTH_HEADER","PASSWORD_ASSIGNMENT","OAUTH_CLIENT_SECRET","API_TOKEN_GENERIC","JWT"]"#;

// ---------------------------------------------------------------------------
// Fixture helpers. Every statement that touches `policy_rules` — seed and
// verify alike — runs inside `begin_scoped`, so this file behaves identically
// whether `DATABASE_URL` names the compose superuser or `secureprompt_runner`.
// ---------------------------------------------------------------------------

/// The two ids a fixture hands back. The WORKSPACE is part of the handle
/// because every read of the rule has to name the tenant it belongs to —
/// `policy_rules` is FORCE ROW LEVEL SECURITY, so there is no such thing as
/// reading it without saying whose it is.
#[derive(Clone, Copy)]
struct SeededRule {
    workspace_id: Uuid,
    rule_id: Uuid,
}

/// Insert a workspace and a policy rule directly, bypassing
/// `WorkspaceRepository::create_with_owner`. Raw inserts keep the fixture
/// independent of the seeding path these tests are not about, and avoid
/// dragging `users` / `api_keys` into a migration test.
///
/// The `policy_rules` INSERT runs inside `begin_scoped` — the application's
/// own armed transaction. `workspaces` is not RLS-armed, so that one insert
/// stays on the pool.
async fn seed_rule(pool: &PgPool, workspace: &str, rule_name: &str, classes: &str) -> SeededRule {
    let workspace_id = Uuid::new_v4();
    sqlx::query("INSERT INTO workspaces (id, name) VALUES ($1, $2)")
        .bind(workspace_id)
        .bind(workspace)
        .execute(pool)
        .await
        .expect("workspace insert");

    let rule_id = Uuid::new_v4();
    let conditions: serde_json::Value = serde_json::from_str(&format!(
        r#"[{{"field":"detection_class","op":"in","value":{classes}}}]"#
    ))
    .expect("fixture class list is valid JSON");

    let mut scope = begin_scoped(pool, workspace_id)
        .await
        .expect("armed scope for the workspace being seeded");
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
    .execute(&mut *scope)
    .await
    .expect("policy rule insert");
    scope.commit().await.expect("commit the seeded rule");

    SeededRule {
        workspace_id,
        rule_id,
    }
}

/// Read the rule's class list back FROM INSIDE ITS OWN WORKSPACE'S SCOPE.
///
/// `fetch_one` is load-bearing and must stay: it is what stops a scope that
/// cannot see the row from being mistaken for a rule whose class list is
/// empty. Several assertions below are of the form "X is absent from the
/// result"; with `fetch_optional` and a default they would all pass on a
/// reader that sees nothing.
async fn classes_of(pool: &PgPool, rule: SeededRule) -> Vec<String> {
    let mut scope = begin_scoped(pool, rule.workspace_id)
        .await
        .expect("armed scope for the workspace being read");
    let row = sqlx::query("SELECT conditions FROM policy_rules WHERE id = $1")
        .bind(rule.rule_id)
        .fetch_one(&mut *scope)
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

// ---------------------------------------------------------------------------
// The low-privilege connection. This is the entire point of the suite.
// ---------------------------------------------------------------------------

/// Create `secureprompt_runner` if it is absent, then hand the test database's
/// tables to it. Idempotent and concurrency-safe: roles are cluster-global
/// while `#[sqlx::test]` databases are per-test, so several tests race here.
async fn ensure_low_privilege_role(pool: &PgPool) {
    sqlx::raw_sql(&format!(
        "DO $$
         BEGIN
             CREATE ROLE {RLS_ROLE}
                 LOGIN PASSWORD '{RLS_PASSWORD}'
                 NOSUPERUSER CREATEDB CREATEROLE NOBYPASSRLS;
         EXCEPTION
             WHEN duplicate_object THEN NULL;
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
        "GRANT USAGE ON SCHEMA public TO {RLS_ROLE};
         GRANT ALL ON ALL TABLES IN SCHEMA public TO {RLS_ROLE};
         GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO {RLS_ROLE};"
    ))
    .execute(pool)
    .await
    .expect("grants on the test database");
}

/// Open a connection to the SAME `#[sqlx::test]` database as `RLS_ROLE`, and
/// assert on the wire that it really is powerless.
///
/// PREMISE ASSERTIONS. Without these the suite is worthless: if a future base
/// image, a stray `ALTER ROLE`, or a typo handed this role SUPERUSER or
/// BYPASSRLS, every test below would keep passing while exercising no RLS at
/// all — the exact failure mode the whole workstream exists to prevent.
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
        "SELECT current_user::text AS who,
                rolsuper,
                rolbypassrls
         FROM pg_roles
         WHERE rolname = current_user",
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// CHARACTERISATION + PREMISE for everything below: prove the harness can
/// actually see the defect. A bare `UPDATE policy_rules ...` — the shape 017
/// ships — reports ZERO rows affected and does NOT error, even though the row
/// is right there and an ARMED reader can see it.
///
/// If this test ever passes trivially (0 rows because there is no row), the
/// `before` assertion below catches it.
#[sqlx::test]
async fn bare_update_silently_matches_zero_rows_under_rls(pool: PgPool) {
    let rule = seed_rule(&pool, "Bare Update Co", "Redact common PII", LEGACY_NINE).await;

    // PREMISE: the row exists and is visible from its own workspace's scope.
    let before = classes_of(&pool, rule).await;
    assert!(
        before.contains(&"PERSON".to_owned()),
        "premise: the fixture rule must exist before the probe: {before:?}"
    );

    let mut conn = low_privilege_connection(&pool).await;

    let result = sqlx::query(
        "UPDATE policy_rules
         SET conditions = jsonb_set(conditions, '{0,value}', '[\"MUTATED\"]'::jsonb)
         WHERE name = 'Redact common PII'",
    )
    .execute(&mut conn)
    .await
    .expect("the bare UPDATE must SUCCEED — silence is the whole defect");

    assert_eq!(
        result.rows_affected(),
        0,
        "premise: under FORCE ROW LEVEL SECURITY with app.current_workspace_id \
         unset, a bare UPDATE must match zero rows. It matched {} — the \
         connection is not actually RLS-constrained and every other test in \
         this file is vacuous.",
        result.rows_affected()
    );

    // ...and the row really was untouched.
    let after = classes_of(&pool, rule).await;
    assert_eq!(
        before, after,
        "the no-op UPDATE must not have changed the row"
    );

    // POSITIVE CONTROL — the SAME statement, on the SAME row, from an ARMED
    // scope, must affect ONE row. Without this the zero above could just as
    // well mean "the WHERE clause never matched anything" and the test would
    // be measuring a typo instead of RLS.
    //
    // This used to run over `&pool` and be described as "when RLS is
    // bypassed". That only held while the pool was a superuser: point
    // `DATABASE_URL` at `secureprompt_runner` and the control matched 0 too,
    // so the test lost the very thing that made its zero mean something.
    // Arming the scope changes exactly ONE dimension — the GUC — between the
    // two runs, which is a stricter control than changing the role, and it is
    // true under both roles.
    let mut armed = begin_scoped(&pool, rule.workspace_id)
        .await
        .expect("armed scope for the control update");
    let privileged = sqlx::query(
        "UPDATE policy_rules
         SET conditions = jsonb_set(conditions, '{0,value}', '[\"MUTATED\"]'::jsonb)
         WHERE name = 'Redact common PII'",
    )
    .execute(&mut *armed)
    .await
    .expect("the armed UPDATE must succeed");

    assert_eq!(
        privileged.rows_affected(),
        1,
        "positive control: the identical statement must match the row once \
         app.current_workspace_id is armed. It matched {} — the fixture, not \
         RLS, is what made the unarmed run report zero.",
        privileged.rows_affected()
    );
    armed.commit().await.expect("commit the control update");
    assert_eq!(
        classes_of(&pool, rule).await,
        vec!["MUTATED".to_owned()],
        "positive control: the armed UPDATE must actually have written"
    );
}

/// THE HEADLINE. Migration 020, run by a role that cannot bypass RLS, must
/// reconcile a legacy seeded rule against the FULL current default list.
///
/// DELETION CHECK: replace the `FOR ws IN SELECT id FROM workspaces` /
/// `PERFORM set_config('app.current_workspace_id', ws::text, true)` loop in
/// `020_reconcile_default_policy_classes.sql` with a bare
/// `UPDATE policy_rules ... WHERE name = 'Redact common PII'` and this test
/// fails with every class reported missing.
#[sqlx::test]
async fn migration_020_backfills_under_a_non_superuser_role(pool: PgPool) {
    let rule = seed_rule(&pool, "Legacy Nine Co", "Redact common PII", LEGACY_NINE).await;

    // PREMISE — assert the ABSENCE we are about to fix. A migration that did
    // nothing would still pass a "the classes are present" assertion if the
    // fixture had already contained them.
    let before: BTreeSet<String> = classes_of(&pool, rule).await.into_iter().collect();
    let missing_before: Vec<&&str> = DEFAULT_POLICY_CLASSES
        .iter()
        .filter(|class| !before.contains(**class))
        .collect();
    assert!(
        missing_before.len() > 30,
        "premise: the fixture must start out MISSING most of the defaults, \
         otherwise a no-op migration passes this test. Missing only: \
         {missing_before:?}"
    );
    assert!(!before.contains("PINFL"), "premise: {before:?}");
    assert!(!before.contains("BEARER_TOKEN"), "premise: {before:?}");

    let mut conn = low_privilege_connection(&pool).await;
    sqlx::raw_sql(MIGRATION_020)
        .execute(&mut conn)
        .await
        .expect("migration 020 must execute cleanly");

    let after: BTreeSet<String> = classes_of(&pool, rule).await.into_iter().collect();
    let still_missing: Vec<&&str> = DEFAULT_POLICY_CLASSES
        .iter()
        .filter(|class| !after.contains(**class))
        .collect();

    assert!(
        still_missing.is_empty(),
        "migration 020 ran as {RLS_ROLE} (NOSUPERUSER, NOBYPASSRLS) and these \
         DEFAULT_POLICY_CLASSES are still absent: {still_missing:?}. A bare \
         UPDATE matches zero rows under RLS and succeeds silently — drive the \
         update from a loop over `workspaces` with app.current_workspace_id \
         set per workspace, as 019 does."
    );

    // Nothing may be dropped, including the two dead names the guard is keyed on.
    assert!(after.contains("GCP_KEY"), "{after:?}");
    assert!(after.contains("AZURE_KEY"), "{after:?}");
}

/// The specific regression 017 was supposed to deliver and did not: a database
/// where 017 no-opped under RLS and 019 applied is left carrying every
/// credential class and NOT ONE Uzbek identifier. 020 must close exactly that
/// gap without disturbing what 019 achieved.
#[sqlx::test]
async fn migration_020_repairs_a_database_where_017_no_opped(pool: PgPool) {
    let rule = seed_rule(
        &pool,
        "Post 019 Co",
        "Redact common PII",
        POST_019_WITHOUT_017,
    )
    .await;

    // PREMISE: this fixture is the post-019 shape — credentials present, the
    // six Uzbek classes absent. Asserting BOTH halves is what makes the test
    // about 017's gap rather than about 019.
    let before: BTreeSet<String> = classes_of(&pool, rule).await.into_iter().collect();
    assert!(before.contains("BEARER_TOKEN"), "premise: {before:?}");
    assert!(before.contains("JWT"), "premise: {before:?}");
    for uzbek in ["PINFL", "STIR", "MFO", "PASSPORT_NUMBER", "UZCARD", "HUMO"] {
        assert!(
            !before.contains(uzbek),
            "premise: {uzbek} must be absent before the back-fill: {before:?}"
        );
    }

    let mut conn = low_privilege_connection(&pool).await;
    sqlx::raw_sql(MIGRATION_020)
        .execute(&mut conn)
        .await
        .expect("migration 020 must execute cleanly");

    let after: BTreeSet<String> = classes_of(&pool, rule).await.into_iter().collect();
    for uzbek in ["PINFL", "STIR", "MFO", "PASSPORT_NUMBER", "UZCARD", "HUMO"] {
        assert!(
            after.contains(uzbek),
            "{uzbek} missing after 020 — the deterministic Uzbek detection \
             floor fires and the policy layer then discards it: {after:?}"
        );
    }
    // 019's work survives.
    assert!(after.contains("BEARER_TOKEN"), "{after:?}");
    assert!(after.contains("JWT"), "{after:?}");
}

/// POSITIVE CONTROL for the two tests above. Same migration, same
/// low-privilege connection, same fixture helper — DIFFERENT result. An admin
/// who deliberately NARROWED the seeded rule keeps their rule untouched.
///
/// This is what separates "020 back-fills the right rows" from "020 updates
/// every row it can reach": if the guards were dropped, the two tests above
/// would still pass and this one would fail.
#[sqlx::test]
async fn migration_020_leaves_a_narrowed_rule_alone(pool: PgPool) {
    let narrowed = r#"["PERSON","EMAIL_ADDRESS"]"#;
    let rule = seed_rule(&pool, "Narrowed Co", "Redact common PII", narrowed).await;

    let mut conn = low_privilege_connection(&pool).await;
    sqlx::raw_sql(MIGRATION_020)
        .execute(&mut conn)
        .await
        .expect("migration 020 must execute cleanly");

    assert_eq!(
        classes_of(&pool, rule).await,
        vec!["PERSON".to_owned(), "EMAIL_ADDRESS".to_owned()],
        "a rule an admin narrowed must be left exactly as the admin left it"
    );
}

/// POSITIVE CONTROL, second axis: only the seeded rule NAME is back-filled.
#[sqlx::test]
async fn migration_020_leaves_an_unrelated_rule_alone(pool: PgPool) {
    let rule = seed_rule(&pool, "Unrelated Co", "Block secrets", LEGACY_NINE).await;

    let mut conn = low_privilege_connection(&pool).await;
    sqlx::raw_sql(MIGRATION_020)
        .execute(&mut conn)
        .await
        .expect("migration 020 must execute cleanly");

    let after = classes_of(&pool, rule).await;
    assert!(
        !after.contains(&"PINFL".to_owned()),
        "only the seeded 'Redact common PII' rule may be back-filled: {after:?}"
    );
}

/// Idempotent, and specifically: no duplicate entries. Re-running a migration
/// is normal (`sqlx migrate run` on a restored backup, a re-applied
/// deployment), and a duplicated class array is a UI defect at best.
///
/// PREMISE: the FIRST run must have back-filled. Without it this test is a
/// constant compared against itself — the exact shape this file exists to
/// catch, one level up. Replace 020's whole `DO $$ … END $$` body with
/// `SELECT 1;` and `once == twice == LEGACY_NINE`, whose nine entries are
/// distinct, so both the equality and the no-duplicates assertion pass for a
/// migration that did nothing. A silent no-op under RLS is the headline
/// defect of this suite, and this was the one test that survived it.
#[sqlx::test]
async fn migration_020_is_idempotent_under_a_non_superuser_role(pool: PgPool) {
    let rule = seed_rule(&pool, "Idempotent Co", "Redact common PII", LEGACY_NINE).await;

    let mut conn = low_privilege_connection(&pool).await;
    sqlx::raw_sql(MIGRATION_020)
        .execute(&mut conn)
        .await
        .expect("first run");
    let once = classes_of(&pool, rule).await;
    assert!(
        once.contains(&"PINFL".to_owned()),
        "premise: the first run must actually have back-filled, or `once` is \
         just the seeded array and everything below compares it with itself. \
         020 reached no row: {once:?}"
    );
    assert!(
        once.len() > 9,
        "premise: the seed carries nine classes and the back-fill adds to \
         them, so a first run that changed anything leaves more than nine: \
         {once:?}"
    );
    sqlx::raw_sql(MIGRATION_020)
        .execute(&mut conn)
        .await
        .expect("second run");
    let twice = classes_of(&pool, rule).await;

    assert_eq!(once, twice, "re-running 020 must not change anything");

    let unique: BTreeSet<&String> = once.iter().collect();
    assert_eq!(
        unique.len(),
        once.len(),
        "020 produced duplicate class entries: {once:?}"
    );
}

/// Multi-tenant: the loop must visit EVERY workspace, not just the first.
/// A `set_config` outside the loop, or a loop that breaks early, still passes
/// every single-workspace test above.
#[sqlx::test]
async fn migration_020_backfills_every_workspace(pool: PgPool) {
    let mut rules = Vec::new();
    for index in 0..3 {
        rules.push(
            seed_rule(
                &pool,
                &format!("Multi Tenant Co {index}"),
                "Redact common PII",
                LEGACY_NINE,
            )
            .await,
        );
    }

    // PREMISE, per workspace. `classes_of` reads through THAT workspace's own
    // scope and `fetch_one`s, so a workspace the reader cannot see fails here
    // loudly instead of contributing a silently empty "before".
    for rule in &rules {
        let before = classes_of(&pool, *rule).await;
        assert!(!before.contains(&"PINFL".to_owned()), "premise: {before:?}");
    }

    let mut conn = low_privilege_connection(&pool).await;
    sqlx::raw_sql(MIGRATION_020)
        .execute(&mut conn)
        .await
        .expect("migration 020 must execute cleanly");

    for (index, rule) in rules.iter().enumerate() {
        let after = classes_of(&pool, *rule).await;
        assert!(
            after.contains(&"PINFL".to_owned()),
            "workspace {index} was not visited by the loop: {after:?}"
        );
    }
}
