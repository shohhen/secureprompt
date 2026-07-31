//! WS1-P1D — the two tables that carry a `workspace_id` and still have no
//! row-level security after migration 030: `users` and
//! `workspace_secure_mode`.
//!
//! # The finding
//!
//! `001_init.sql` arms RLS with a loop over an explicit list:
//!
//! ```text
//! ARRAY['api_keys', 'providers', 'models', 'policy_rules', 'audit_events_meta']
//! ```
//!
//! `users` is not in it, and appears in no arming list in any of the thirty
//! migrations that follow. It is the table that holds `email` and
//! `password_hash`. `workspace_secure_mode` (007) is likewise unarmed, and its
//! written justification is CIRCULAR: 018 and 021 each say "NO ROW-LEVEL
//! SECURITY, matching `workspace_secure_mode` (007)", while 007 itself gives
//! no reason at all. Migration 030 has since armed both of the tables that
//! were pointing at 007, leaving 007 as the last table in the schema whose
//! only argument for having no policy is that two now-armed tables once cited
//! it.
//!
//! # Why these assertions are not vacuous
//!
//! `#[sqlx::test]` connects as a BYPASSRLS superuser and CANNOT observe an RLS
//! defect — every assertion below would pass against a completely unarmed
//! schema. So each test opens its OWN connection as a NOSUPERUSER,
//! NOBYPASSRLS role, asserts that role's powerlessness on the wire
//! (`low_privilege_connection`), arms it to workspace A with a read-back
//! (`arm_scope`), and then runs a POSITIVE CONTROL — `policy_rules`, armed
//! since 001 — over the SAME connection. The control must show isolation. If
//! it does not, the connection is not RLS-subject and the tenancy assertions
//! that follow are measuring nothing.

use sqlx::postgres::{PgConnectOptions, PgConnection};
use sqlx::{Connection, PgPool, Row};
use uuid::Uuid;

/// Same role, password and creation attributes as
/// `tests/migration_017_023_rls.rs`, `tests/rls_repo_scope.rs` and
/// `scripts/ci/create-nonsuperuser-role.sh`. A second set would be a second
/// thing to keep true.
const RLS_ROLE: &str = "secureprompt_runner";
const RLS_PASSWORD: &str = "secureprompt";

// ===========================================================================
// Fixtures — all through the (superuser) `#[sqlx::test]` pool.
// ===========================================================================

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

/// A user with a recognisable `password_hash`, so a cross-tenant read is
/// distinguishable from an empty result by VALUE and not only by row count.
async fn seed_user(pool: &PgPool, workspace_id: Uuid, email: &str, hash: &str) -> Uuid {
    let user_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, workspace_id, email, password_hash, role)
         VALUES ($1, $2, $3, $4, 'owner')",
    )
    .bind(user_id)
    .bind(workspace_id)
    .bind(email)
    .bind(hash)
    .execute(pool)
    .await
    .expect("user insert");
    user_id
}

async fn seed_secure_mode(pool: &PgPool, workspace_id: Uuid, level: &str) {
    sqlx::query(
        "INSERT INTO workspace_secure_mode (workspace_id, enabled, level)
         VALUES ($1, true, $2)",
    )
    .bind(workspace_id)
    .bind(level)
    .execute(pool)
    .await
    .expect("workspace_secure_mode insert");
}

/// The POSITIVE CONTROL fixture: `policy_rules` has been armed since 001.
async fn seed_rule(pool: &PgPool, workspace_id: Uuid, name: &str) {
    sqlx::query("INSERT INTO policy_rules (workspace_id, name, action) VALUES ($1, $2, 'redact')")
        .bind(workspace_id)
        .bind(name)
        .execute(pool)
        .await
        .expect("policy rule insert");
}

/// `(rowsecurity, forcerowsecurity)` straight out of the catalog, so a failure
/// message can say what the table's arming actually is instead of leaving the
/// reader to guess.
async fn rls_flags(pool: &PgPool, table: &str) -> (bool, bool) {
    let row = sqlx::query(
        "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = to_regclass($1)",
    )
    .bind(format!("public.{table}"))
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("{table} must exist to be probed: {e}"));
    (row.get("relrowsecurity"), row.get("relforcerowsecurity"))
}

// ===========================================================================
// The low-privilege connection
// ===========================================================================

/// Create `secureprompt_runner` if absent and grant it this test database.
/// Idempotent and concurrency-safe: roles are cluster-global while
/// `#[sqlx::test]` databases are per-test, so several tests race here.
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
             connecting role needs CREATEROLE. This suite refuses to fall back \
             to the superuser pool, because a superuser bypasses RLS and would \
             make every assertion below vacuous."
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
/// assert ON THE WIRE that it really is powerless.
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
    assert_eq!(who, RLS_ROLE, "premise: connected as the wrong role");
    assert!(
        !row.get::<bool, _>("rolsuper"),
        "premise: {who} is a SUPERUSER, so it bypasses RLS and this test proves nothing"
    );
    assert!(
        !row.get::<bool, _>("rolbypassrls"),
        "premise: {who} has BYPASSRLS, so it bypasses RLS and this test proves nothing"
    );

    conn
}

/// Point the connection's RLS predicate at one workspace, and read it back.
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

/// The POSITIVE CONTROL, run over the caller's own connection.
///
/// `policy_rules` is armed by 001. Armed to workspace A, this connection must
/// see A's rule and NOT B's. Every test below calls this before asserting
/// anything about an unarmed table, so that "the foreign row was invisible"
/// cannot be confused with "this connection sees nothing at all", and
/// "the foreign row was visible" cannot be confused with "RLS is off
/// everywhere in this database".
async fn assert_positive_control(conn: &mut PgConnection, own: &str, foreign: &str) {
    let visible: Vec<String> = sqlx::query_scalar("SELECT name FROM policy_rules ORDER BY name")
        .fetch_all(&mut *conn)
        .await
        .expect("policy_rules read under the armed scope");

    assert!(
        visible.iter().any(|n| n == own),
        "positive control FAILED: the armed scope cannot see its OWN \
         policy_rules row ({own}). Visible: {visible:?}. Nothing below is \
         measuring a tenancy boundary."
    );
    assert!(
        !visible.iter().any(|n| n == foreign),
        "positive control FAILED: `policy_rules` has been armed since \
         migration 001, yet the foreign row ({foreign}) is visible. RLS is \
         not in force on this connection, so every assertion below would pass \
         against a completely unarmed schema. Visible: {visible:?}"
    );
}

// ===========================================================================
// `users` — email and password_hash
// ===========================================================================

/// THE FINDING. Workspace B's `email` and `password_hash` read from
/// workspace A's armed scope.
///
/// `users` carries a NOT NULL `workspace_id` and is the system of record for
/// dashboard credentials. It is in no arming list in the schema, so the only
/// tenancy control on it is whatever `WHERE workspace_id = $n` each individual
/// query happens to carry — and eleven production query sites carry none.
#[sqlx::test]
async fn users_credentials_are_isolated_from_a_foreign_armed_scope(pool: PgPool) {
    let workspace_a = seed_workspace(&pool, "Users RLS A").await;
    let workspace_b = seed_workspace(&pool, "Users RLS B").await;

    seed_user(&pool, workspace_a, "owner@a.example", "$argon2id$AAAA").await;
    seed_user(&pool, workspace_b, "owner@b.example", "$argon2id$BBBB").await;

    seed_rule(&pool, workspace_a, "control-a").await;
    seed_rule(&pool, workspace_b, "control-b").await;

    let mut conn = low_privilege_connection(&pool).await;
    arm_scope(&mut conn, workspace_a).await;
    assert_positive_control(&mut conn, "control-a", "control-b").await;

    // The read an attacker with the application role would run.
    let leaked: Vec<(String, String)> =
        sqlx::query_as("SELECT email, password_hash FROM users WHERE workspace_id = $1")
            .bind(workspace_b)
            .fetch_all(&mut conn)
            .await
            .expect("cross-tenant users read");

    let flags = rls_flags(&pool, "users").await;
    assert!(
        leaked.is_empty(),
        "CROSS-TENANT CREDENTIAL LEAK: a scope armed to workspace A read {} \
         row(s) of workspace B's users, including the password hash: \
         {leaked:?}. `users` has (rowsecurity, forcerowsecurity) = {flags:?} \
         — it is in no RLS arming list in any migration. The positive control \
         above passed, so this is a property of the `users` table and not of \
         this connection.",
        leaked.len()
    );
}

// ===========================================================================
// `workspace_secure_mode` — the redaction control
// ===========================================================================

/// `workspace_secure_mode` decides whether redaction runs at all, and at what
/// level. Armed to workspace A, this scope must not see workspace B's row.
///
/// The negative half matters as much as the positive: `SecureModeRepository::get`
/// resolves "no row" to `SecureModeRow::default()`, which is `enabled: false`
/// — secure mode OFF. So on this table a silent zero does not merely hide
/// data, it turns the product's central control off for a workspace that
/// switched it on.
#[sqlx::test]
async fn workspace_secure_mode_is_isolated_from_a_foreign_armed_scope(pool: PgPool) {
    let workspace_a = seed_workspace(&pool, "Secure Mode RLS A").await;
    let workspace_b = seed_workspace(&pool, "Secure Mode RLS B").await;

    seed_secure_mode(&pool, workspace_a, "standard").await;
    seed_secure_mode(&pool, workspace_b, "strict").await;

    seed_rule(&pool, workspace_a, "control-a").await;
    seed_rule(&pool, workspace_b, "control-b").await;

    let mut conn = low_privilege_connection(&pool).await;
    arm_scope(&mut conn, workspace_a).await;
    assert_positive_control(&mut conn, "control-a", "control-b").await;

    let foreign: Vec<String> =
        sqlx::query_scalar("SELECT level FROM workspace_secure_mode WHERE workspace_id = $1")
            .bind(workspace_b)
            .fetch_all(&mut conn)
            .await
            .expect("cross-tenant workspace_secure_mode read");

    let flags = rls_flags(&pool, "workspace_secure_mode").await;
    assert!(
        foreign.is_empty(),
        "CROSS-TENANT READ: a scope armed to workspace A read workspace B's \
         secure-mode configuration {foreign:?}. \
         `workspace_secure_mode` has (rowsecurity, forcerowsecurity) = \
         {flags:?}. The positive control above passed, so this is a property \
         of the table and not of this connection."
    );

    // The armed scope must still see its OWN row. Isolation that also hides
    // the caller's own configuration would switch redaction off for everyone,
    // which is a worse outcome than the leak.
    let own: Vec<String> =
        sqlx::query_scalar("SELECT level FROM workspace_secure_mode WHERE workspace_id = $1")
            .bind(workspace_a)
            .fetch_all(&mut conn)
            .await
            .expect("own-workspace workspace_secure_mode read");
    assert_eq!(
        own,
        vec!["standard".to_owned()],
        "the armed scope must still read its OWN secure-mode row; reading \
         nothing here is the silent zero that resolves to `enabled: false`"
    );
}
