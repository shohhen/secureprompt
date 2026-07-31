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

use secureprompt_api::db::secure_mode_repo::SecureModeRepository;
use secureprompt_common::types::WorkspaceId;
use sqlx::postgres::{PgConnectOptions, PgConnection, PgPoolOptions};
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

/// A POOL onto the same `#[sqlx::test]` database as `RLS_ROLE`, for driving a
/// repository rather than raw SQL. Same premise assertions, same reason.
///
/// `max_connections(4)` / `min_connections(2)`: more than one, so a repository
/// that armed the scope outside its transaction has a real chance of reading
/// on a different connection and failing here.
async fn low_privilege_pool(pool: &PgPool) -> PgPool {
    ensure_low_privilege_role(pool).await;

    let options: PgConnectOptions = (*pool.connect_options())
        .clone()
        .username(RLS_ROLE)
        .password(RLS_PASSWORD);

    let low = PgPoolOptions::new()
        .max_connections(4)
        .min_connections(2)
        .connect_with(options)
        .await
        .expect("low-privilege pool onto the test database");

    let row = sqlx::query(
        "SELECT current_user::text AS who, rolsuper, rolbypassrls
         FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&low)
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

    low
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

/// THE OPEN DEFECT, recorded as a measurement rather than a claim.
///
/// **This test asserts that a leak IS PRESENT. It is not an approval of it.**
/// Migration 031 deliberately does not arm `users`, and this test is the
/// tripwire that fires the moment somebody does, because arming the table is
/// only the first of roughly twenty-two changes and the other twenty-one break
/// authentication if they are skipped. The reasoning is in the header of
/// `migrations/031_arm_rls_on_workspace_secure_mode.sql`, Part 2.
///
/// What is measured here, from a scope armed to workspace A with the
/// `policy_rules` positive control isolated on the same connection: workspace
/// B's `users` row comes back in full, `email` and `password_hash` together.
///
/// When `users` is finally armed, this test fails on its FIRST assertion —
/// which is the intended signal, and the failure message names the work.
#[sqlx::test]
async fn users_is_not_armed_and_this_is_the_open_defect(pool: PgPool) {
    let workspace_a = seed_workspace(&pool, "Users RLS A").await;
    let workspace_b = seed_workspace(&pool, "Users RLS B").await;

    seed_user(&pool, workspace_a, "owner@a.example", "$argon2id$AAAA").await;
    seed_user(&pool, workspace_b, "owner@b.example", "$argon2id$BBBB").await;

    seed_rule(&pool, workspace_a, "control-a").await;
    seed_rule(&pool, workspace_b, "control-b").await;

    // THE TRIPWIRE. Deliberately the first assertion, so that arming `users`
    // is reported as "you have work to do" and not as a confusing cross-tenant
    // failure further down.
    let flags = rls_flags(&pool, "users").await;
    assert_eq!(
        flags,
        (false, false),
        "`users` has gained row-level security. That is the right destination, \
         but arming the table is one of ~22 changes and the rest are not \
         optional:\n\
         \x20 * `UserRepository::find_by_email_with_role` is the PRE-AUTH \
         login lookup — by email, before any workspace is known. Under a \
         workspace policy it returns zero rows and EVERY LOGIN in the \
         deployment silently fails. It needs a SECURITY DEFINER function \
         (see `security_definer_escapes_force_rls_only_if_its_owner_bypasses` \
         below for the ownership constraint).\n\
         \x20 * `UserRepository::count_total_users` and \
         `internal.rs::build_signed_attestation` count users DEPLOYMENT-WIDE \
         for license seats; a per-workspace count evades the seat cap and \
         publishes a signed 0.\n\
         \x20 * ~18 sites (`/v1/users`, `/v1/me/profile`, session revocation, \
         admin-audit actor attribution, the 2FA state machine, the openai \
         `device_mac` write) already say `WHERE workspace_id = $n` but run on \
         the BARE POOL with no GUC. RLS filters independently of the WHERE \
         clause, so each becomes a silent zero.\n\
         Read migrations/031_arm_rls_on_workspace_secure_mode.sql Part 2, then \
         delete this test."
    );

    let mut conn = low_privilege_connection(&pool).await;
    arm_scope(&mut conn, workspace_a).await;
    assert_positive_control(&mut conn, "control-a", "control-b").await;

    // The read an attacker holding the application role would run.
    let leaked: Vec<(String, String)> =
        sqlx::query_as("SELECT email, password_hash FROM users WHERE workspace_id = $1")
            .bind(workspace_b)
            .fetch_all(&mut conn)
            .await
            .expect("cross-tenant users read");

    assert_eq!(
        leaked,
        vec![("owner@b.example".to_owned(), "$argon2id$BBBB".to_owned())],
        "the cross-tenant credential read is the measurement this test exists \
         to keep visible. The positive control above passed, so a change here \
         is a change in `users`, not in the connection."
    );
}

// ===========================================================================
// The REPOSITORY path onto `workspace_secure_mode`
// ===========================================================================

/// Arming the table is only half of the change; the other half is that the
/// read sets `app.current_workspace_id`. This is the half no `#[sqlx::test]`
/// can see, because the compose role is a SUPERUSER and bypasses RLS
/// unconditionally — so `SecureModeRepository::get` reading on the bare pool
/// is fine TODAY and becomes a silent zero the moment the DB role-split lands.
///
/// A silent zero here is not a hidden row. `get` resolves "no row" to
/// `SecureModeRow::default()`, whose `enabled` is `false`, and
/// `pipeline::service` treats that as "secure mode off" and proceeds with
/// policy-only behaviour. A workspace that switched redaction ON would have it
/// silently switched OFF, with nothing logged.
///
/// A POOL rather than a single connection, deliberately: `set_config(..., true)`
/// is transaction-local and a pool hands successive statements to different
/// connections, so a repository that armed the scope outside its transaction
/// would pass a single-connection test and fail here.
///
/// The NEGATIVE CONTROL is the second workspace, which really has no row and
/// must resolve to the default. Without it, "A reads back enabled/strict"
/// would also be satisfied by a repository that ignored `workspace_id`.
#[sqlx::test]
async fn secure_mode_repo_get_survives_a_non_bypassing_role(pool: PgPool) {
    let workspace_a = seed_workspace(&pool, "Secure Mode Repo A").await;
    let workspace_b = seed_workspace(&pool, "Secure Mode Repo B").await;

    seed_secure_mode(&pool, workspace_a, "strict").await;

    // PREMISE: the row is on disk and migration 031 armed the table, so the
    // read below really passes through a policy.
    assert_eq!(
        rls_flags(&pool, "workspace_secure_mode").await,
        (true, true),
        "premise: migration 031 must have armed this table, or the \
         low-privilege pool reads everything and this test measures nothing"
    );

    let low = low_privilege_pool(&pool).await;
    let repo = SecureModeRepository::new(low);

    let row = repo
        .get(WorkspaceId(workspace_a))
        .await
        .expect("reading a workspace's own secure-mode config must not error");
    assert!(
        row.enabled && row.level == "strict",
        "workspace A's stored secure-mode config must survive the read, got \
         enabled={} level={:?}. Reading back the default here is the silent \
         zero: redaction would be off for a workspace that turned it on, and \
         `pipeline::service` would log nothing.",
        row.enabled,
        row.level
    );

    // NEGATIVE CONTROL: a workspace with no row really does resolve to the
    // default, so the assertion above is about the stored row and not about
    // the repository returning a constant.
    let absent = repo
        .get(WorkspaceId(workspace_b))
        .await
        .expect("a workspace with no row must resolve, not error");
    assert!(
        !absent.enabled && absent.level == "standard",
        "a workspace that never chose must still read as the default, got \
         enabled={} level={:?}",
        absent.enabled,
        absent.level
    );
}

// ===========================================================================
// The constraint that decides HOW `users` can eventually be armed
// ===========================================================================

/// `SECURITY DEFINER` is the standard PostgreSQL answer for the pre-auth login
/// lookup, and it does NOT work by itself under `FORCE ROW LEVEL SECURITY`.
///
/// This is measured rather than asserted because migration 031's header states
/// it as the open question that defers arming `users`, and a header claiming a
/// database behaviour nobody ran is how the circular justification on
/// `workspace_secure_mode` came about in the first place.
///
/// Both directions are measured on the same scratch table, so neither result
/// can be an artefact of the fixture:
///   * owner WITHOUT `BYPASSRLS` — the definer function is still filtered by
///     the policy, and a login lookup through it would return nothing;
///   * owner WITH `BYPASSRLS` — the same function body now sees every row.
///
/// The consequence for the `users` design: which role owns that function, and
/// whether it carries `BYPASSRLS`, is a DB role-split decision. Today's
/// compose role is a SUPERUSER, so a definer function written now would appear
/// to work and would break when the role-split lands.
#[sqlx::test]
async fn security_definer_escapes_force_rls_only_if_its_owner_bypasses(pool: PgPool) {
    let workspace_a = seed_workspace(&pool, "Definer A").await;
    let workspace_b = seed_workspace(&pool, "Definer B").await;

    // A scratch table armed exactly like every `workspace_isolation` table in
    // this schema, so the result transfers to `users`.
    sqlx::raw_sql(
        "CREATE TABLE p1d_definer_probe (
             workspace_id UUID NOT NULL,
             secret       TEXT NOT NULL
         );
         ALTER TABLE p1d_definer_probe ENABLE ROW LEVEL SECURITY;
         ALTER TABLE p1d_definer_probe FORCE ROW LEVEL SECURITY;
         CREATE POLICY workspace_isolation ON p1d_definer_probe
             USING (workspace_id = current_setting('app.current_workspace_id', true)::uuid);",
    )
    .execute(&pool)
    .await
    .expect("scratch table armed like the real ones");

    for (workspace, secret) in [(workspace_a, "secret-a"), (workspace_b, "secret-b")] {
        sqlx::query("INSERT INTO p1d_definer_probe (workspace_id, secret) VALUES ($1, $2)")
            .bind(workspace)
            .bind(secret)
            .execute(&pool)
            .await
            .expect("probe row insert");
    }

    // The shape a login lookup would have: no workspace predicate, because the
    // caller does not know one yet.
    sqlx::raw_sql(
        "CREATE FUNCTION p1d_lookup_all() RETURNS SETOF TEXT
             LANGUAGE sql
             SECURITY DEFINER
             SET search_path = pg_catalog, public
         AS $$ SELECT secret FROM public.p1d_definer_probe ORDER BY secret $$;",
    )
    .execute(&pool)
    .await
    .expect("SECURITY DEFINER lookup function");

    ensure_low_privilege_role(&pool).await;

    // A NOLOGIN role that exists only to own the function in the second half.
    // Roles are cluster-global while `#[sqlx::test]` databases are per-test,
    // so this races with sibling tests and must tolerate losing the race.
    sqlx::raw_sql(
        "DO $$
         BEGIN
             CREATE ROLE p1d_definer_owner NOLOGIN BYPASSRLS;
         EXCEPTION
             WHEN duplicate_object THEN NULL;
             WHEN unique_violation THEN NULL;
         END $$;
         GRANT SELECT ON p1d_definer_probe TO p1d_definer_owner;",
    )
    .execute(&pool)
    .await
    .expect("bypassing owner role");

    // PREMISE: the two candidate owners really differ in the one attribute
    // this test is about. Without this the two halves could differ for some
    // other reason and the test would be measuring nothing.
    let bypass: Vec<(String, bool)> = sqlx::query_as(
        "SELECT rolname::text, rolbypassrls FROM pg_roles
         WHERE rolname IN ('secureprompt_runner', 'p1d_definer_owner')
         ORDER BY rolname",
    )
    .fetch_all(&pool)
    .await
    .expect("owner attribute probe");
    assert_eq!(
        bypass,
        vec![
            ("p1d_definer_owner".to_owned(), true),
            ("secureprompt_runner".to_owned(), false),
        ],
        "premise: the two function owners must differ in BYPASSRLS and nothing else"
    );

    // ── Half 1: owner does NOT bypass RLS ────────────────────────────────
    sqlx::raw_sql("ALTER FUNCTION p1d_lookup_all() OWNER TO secureprompt_runner")
        .execute(&pool)
        .await
        .expect("hand the function to the non-bypassing role");

    let mut conn = low_privilege_connection(&pool).await;
    arm_scope(&mut conn, workspace_a).await;

    let filtered: Vec<String> = sqlx::query_scalar("SELECT * FROM p1d_lookup_all()")
        .fetch_all(&mut conn)
        .await
        .expect("definer call under a non-bypassing owner");
    assert_eq!(
        filtered,
        vec!["secret-a".to_owned()],
        "SECURITY DEFINER did NOT escape the policy: FORCE ROW LEVEL SECURITY \
         applies to the function's owner too. A login lookup written this way \
         would see only the workspace the session happens to be armed to — and \
         the pre-auth path is armed to none, so it would see nothing."
    );

    // ── Half 2: same function body, owner WITH BYPASSRLS ─────────────────
    sqlx::raw_sql("ALTER FUNCTION p1d_lookup_all() OWNER TO p1d_definer_owner")
        .execute(&pool)
        .await
        .expect("hand the function to the bypassing role");

    let unfiltered: Vec<String> = sqlx::query_scalar("SELECT * FROM p1d_lookup_all()")
        .fetch_all(&mut conn)
        .await
        .expect("definer call under a bypassing owner");
    assert_eq!(
        unfiltered,
        vec!["secret-a".to_owned(), "secret-b".to_owned()],
        "with a BYPASSRLS owner the identical function body sees every row. \
         This is the mechanism a `users` login lookup would rely on, and it is \
         why the function's OWNERSHIP is a role-split decision rather than \
         something migration 031 could settle."
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
