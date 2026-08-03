//! An unscoped read of an RLS-ARMED table must be INVISIBLE, not an ERROR.
//!
//! # The platform fact this suite is built on
//!
//! `set_config('app.current_workspace_id', …, true)` is TRANSACTION-LOCAL. When
//! that transaction ends the setting does NOT go back to unset — it reverts to
//! the EMPTY STRING, and stays that way for the life of the connection.
//! `current_setting(…, true)` therefore returns `Some("")`, not `None`, and
//! `''::uuid` is not a cast that yields NULL: it raises
//! `22P02 invalid input syntax for type uuid: ""`.
//!
//! `a_released_scope_reverts_to_the_empty_string_not_null` measures exactly
//! that, and every other test in this file depends on it.
//!
//! # Why it matters more than a wrong error message
//!
//! Connections are POOLED. Whether a given unscoped statement gets the empty
//! set or the exception is decided by which connection the pool hands out:
//!
//!   * a connection that has never served a scoped transaction → `NULL::uuid`
//!     → predicate NULL → zero rows, no error;
//!   * a connection that has → `''::uuid` → 22P02.
//!
//! One defect with two failure modes, neither of which is what
//! `001_init.sql`'s `workspace_isolation` was written to do. Migration 032
//! fixed it for `refresh_tokens` with `NULLIF` and said in as many words that
//! "the same landmine is in every other `workspace_isolation` policy in this
//! schema". Migration 033 is that sweep, and this file is what it has to make
//! true.
//!
//! # What "correct" is here, stated before it is asserted
//!
//! INVISIBLE. An unscoped read returns the empty set and raises nothing; a
//! correctly scoped read returns exactly what it returned before. This is
//! deliberately the MORE PERMISSIVE direction in the "no error" sense — a
//! query that used to shout now returns nothing quietly. That is the
//! `workspace_isolation` semantics 001 intended, and the compensating control
//! is `db::scope::begin_scoped`, which sets the GUC and READS IT BACK so that
//! an unarmed application path fails at the application layer instead of
//! answering nothing. The WRITE direction stays loud either way, and
//! `an_unscoped_insert_is_still_rejected_loudly` is what pins that.
//!
//! # How this suite avoids the two vacuity traps on this branch
//!
//! ROLE. Every claim below is made on a connection that is asserted ON THE
//! WIRE to be `rolsuper = false, rolbypassrls = false`. `#[sqlx::test]`'s own
//! pool is a BYPASSRLS superuser when `DATABASE_URL` names the compose role, so
//! a claim made through it would be true of nothing. The probe connection is
//! built from the test database's connect options with the username replaced,
//! so it is the same non-bypassing role under BOTH `DATABASE_URL`s and every
//! assertion here holds under both.
//!
//! ABSENCE. "Nothing is visible" is asserted only next to a POSITIVE CONTROL on
//! the same connection and the same rows — a scoped read that DOES see them.
//! Without the pair, `assert_eq!(count, 0)` is satisfied by an empty table, a
//! failed fixture or a filtered reader indifferently.
//!
//! FIXTURES. Seeds and premise reads go through scope-armed transactions, never
//! a bare pool, because under the `secureprompt_runner` `DATABASE_URL` the
//! `#[sqlx::test]` pool is itself subject to RLS and a bare-pool seed into an
//! armed table is rejected with 42501.

use sqlx::postgres::PgConnectOptions;
use sqlx::{Connection, PgConnection, PgPool, Postgres, Row, Transaction};
use std::collections::BTreeSet;
use uuid::Uuid;

/// Same role, password and creation attributes as `tests/rls_repo_scope.rs`,
/// `tests/rls_refresh_token_scope.rs` and
/// `scripts/ci/create-nonsuperuser-role.sh`. A second set would be a second
/// thing to keep true.
const RLS_ROLE: &str = "secureprompt_runner";
const RLS_PASSWORD: &str = "secureprompt";

/// The number of tables under `FORCE ROW LEVEL SECURITY` as of migration 031,
/// which is the last migration that arms one. Asserted as a premise so that a
/// probe returning a short list — wrong database, migrations not applied, a
/// future Postgres renaming the column — fails instead of shrinking the sweep
/// to nothing.
const ARMED_TABLE_COUNT: usize = 16;

// ===========================================================================
// Fixtures
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

/// A single CONNECTION — not a pool — onto the same `#[sqlx::test]` database,
/// with the role's powerlessness asserted on the wire.
///
/// A connection and not a pool because the defect under test is a property of
/// ONE connection's session state: arm a transaction-local scope, let the
/// transaction end, then read on THAT SAME connection. A pool may hand the
/// second statement to a different, never-scoped connection and the released
/// state would never be observed.
async fn low_privilege_connection(pool: &PgPool) -> PgConnection {
    ensure_low_privilege_role(pool).await;

    let options: PgConnectOptions = (*pool.connect_options())
        .clone()
        .username(RLS_ROLE)
        .password(RLS_PASSWORD);
    let mut conn = PgConnection::connect_with(&options)
        .await
        .expect("low-privilege connection onto the test database");

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
        "premise: {who} is a SUPERUSER, so it bypasses RLS unconditionally and \
         every assertion in this file would be true of nothing"
    );
    assert!(
        !row.get::<bool, _>("rolbypassrls"),
        "premise: {who} has BYPASSRLS, so it bypasses RLS and every assertion \
         in this file would be true of nothing"
    );

    conn
}

/// Open a transaction with `app.current_workspace_id` armed.
///
/// The same shape as `db::scope::begin_scoped`, restated here rather than
/// imported because these are FIXTURES: a fixture that breaks when the code
/// under test breaks cannot show which of the two moved.
async fn scoped_tx(pool: &PgPool, workspace_id: Uuid) -> Transaction<'static, Postgres> {
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
        .bind(workspace_id.to_string())
        .execute(&mut *tx)
        .await
        .expect("arm the fixture scope");
    tx
}

/// Arm a workspace scope on `conn` inside a transaction and then COMMIT it, so
/// the connection is left in the RELEASED state — the state a pooled connection
/// is in for every statement after the first scoped one it ever served.
async fn arm_then_release(conn: &mut PgConnection, workspace_id: Uuid) {
    let mut tx = conn.begin().await.expect("probe transaction");
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
        .bind(workspace_id.to_string())
        .execute(&mut *tx)
        .await
        .expect("arm the probe scope");
    tx.commit().await.expect("release the probe scope");
}

/// The tables Postgres is ACTUALLY forcing row-level security on, right now.
///
/// Read from the catalog and never from a list in this file, for the same
/// reason `tests/rls_call_site_guard.rs` does it: a future migration that arms
/// a seventeenth table is then covered by the sweep below without anyone
/// remembering to add it here.
///
/// `relforcerowsecurity` and not `relrowsecurity`: ENABLE alone exempts the
/// table owner, and under `#[sqlx::test]` the connecting role owns every table,
/// so FORCE is the flag that decides whether a policy binds at all.
async fn armed_tables(pool: &PgPool) -> BTreeSet<String> {
    let armed: BTreeSet<String> = sqlx::query_scalar::<_, String>(
        "SELECT c.relname
         FROM pg_class c
         JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public' AND c.relforcerowsecurity",
    )
    .fetch_all(pool)
    .await
    .expect("armed-table probe")
    .into_iter()
    .collect();

    // PREMISE. A probe that came back empty or short would shrink every sweep
    // below to nothing and report success.
    assert!(
        armed.contains("policy_rules"),
        "premise: policy_rules has been under FORCE ROW LEVEL SECURITY since \
         001_init.sql:78-95. It is absent from {armed:?}, so the armed-table \
         probe is broken and this suite is vacuous."
    );
    assert!(
        armed.len() >= ARMED_TABLE_COUNT,
        "premise: {ARMED_TABLE_COUNT} tables are armed as of migration 031; the \
         probe found {} ({armed:?}). Fewer means the test database is not fully \
         migrated.",
        armed.len()
    );

    armed
}

async fn seed_workspace(pool: &PgPool, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO workspaces (id, name) VALUES ($1, $2)")
        .bind(id)
        .bind(name)
        .execute(pool)
        .await
        .expect("workspace insert");
    id
}

/// One `admin_audit` row for `workspace_id`, written through a SCOPED
/// transaction.
///
/// Not through the bare pool: under the `secureprompt_runner` `DATABASE_URL`
/// the `#[sqlx::test]` pool is itself filtered, and a bare-pool insert here is
/// rejected with `42501 new row violates row-level security policy`.
async fn seed_admin_audit(pool: &PgPool, workspace_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let mut tx = scoped_tx(pool, workspace_id).await;
    sqlx::query(
        "INSERT INTO admin_audit (id, workspace_id, action, target_type)
         VALUES ($1, $2, 'user.created', 'user')",
    )
    .bind(id)
    .bind(workspace_id)
    .execute(&mut *tx)
    .await
    .expect("admin_audit seed");
    tx.commit().await.expect("commit admin_audit seed");
    id
}

/// `SELECT count(*)` with the SQLSTATE kept instead of unwrapped, so a test can
/// assert on which of the two failure modes it got.
async fn count_or_sqlstate(conn: &mut PgConnection, table: &str) -> Result<i64, String> {
    sqlx::query_scalar::<_, i64>(&format!("SELECT count(*) FROM public.\"{table}\""))
        .fetch_one(conn)
        .await
        .map_err(|e| describe(&e))
}

/// `SQLSTATE: message` for a database error, or the debug form for anything
/// else. Tests match on the five-character code, never on the prose.
fn describe(e: &sqlx::Error) -> String {
    match e.as_database_error().and_then(|d| d.code()) {
        Some(code) => format!("{code}: {e}"),
        None => format!("{e:?}"),
    }
}

// ===========================================================================
// The platform fact
// ===========================================================================

/// A TRANSACTION-LOCAL `set_config` reverts to the EMPTY STRING, not to NULL.
///
/// This is the whole premise of the file and of migration 033, so it is
/// measured rather than cited. If a future PostgreSQL made a released custom
/// GUC read back as NULL, `''::uuid` would never be evaluated, the sweep would
/// be unnecessary, and this test — not a comment — is what would say so.
#[sqlx::test]
async fn a_released_scope_reverts_to_the_empty_string_not_null(pool: PgPool) {
    let mut conn = low_privilege_connection(&pool).await;
    let workspace_id = Uuid::new_v4();

    // PREMISE: before anything is armed the setting really is absent, so the
    // change observed below is the RELEASE and not the initial state.
    let before: Option<String> =
        sqlx::query_scalar("SELECT current_setting('app.current_workspace_id', true)")
            .fetch_one(&mut conn)
            .await
            .expect("read the unset GUC");
    assert_eq!(
        before, None,
        "premise: a GUC that has never been assigned in this session must read \
         back as NULL. Got {before:?}, so this connection is not fresh and the \
         measurement below means nothing."
    );

    arm_then_release(&mut conn, workspace_id).await;

    let after: Option<String> =
        sqlx::query_scalar("SELECT current_setting('app.current_workspace_id', true)")
            .fetch_one(&mut conn)
            .await
            .expect("read the released GUC");

    assert_eq!(
        after,
        Some(String::new()),
        "a released transaction-local set_config must revert to the EMPTY \
         STRING. It read back as {after:?}. If this is now None, migration \
         033's NULLIF is redundant rather than wrong — but the policies it \
         rewrote are still correct, so delete the sweep deliberately rather \
         than because a test went green."
    );

    // The consequence, spelled out on the wire: the cast the policies perform
    // on that value RAISES.
    let cast: Result<Option<Uuid>, sqlx::Error> =
        sqlx::query_scalar("SELECT (current_setting('app.current_workspace_id', true))::uuid")
            .fetch_one(&mut conn)
            .await;
    let err = describe(&cast.expect_err(
        "premise: casting the released empty string to uuid must raise. If it \
         does not, the 22P02 this suite is about cannot occur and the sweep \
         needs re-deriving.",
    ));
    assert!(
        err.starts_with("22P02"),
        "expected 22P02 invalid input syntax for type uuid, got {err}"
    );

    // POSITIVE CONTROL on the same connection: NULLIF is what turns that raise
    // into the NULL the policy wants. Without this the assertion above would be
    // equally satisfied by a cast that raises for some unrelated reason.
    let nullif: Option<Uuid> = sqlx::query_scalar(
        "SELECT NULLIF(current_setting('app.current_workspace_id', true), '')::uuid",
    )
    .fetch_one(&mut conn)
    .await
    .expect("NULLIF must make the same cast succeed");
    assert_eq!(
        nullif, None,
        "NULLIF('' , '')::uuid must be NULL, and a NULL predicate shows no rows"
    );
}

// ===========================================================================
// The sweep
// ===========================================================================

/// EVERY armed table, read with no scope on a connection that has served one
/// before, must answer with rows — zero of them — and not with an exception.
///
/// The list comes from `pg_class.relforcerowsecurity`, so this is a claim about
/// the schema as it actually is and not about a list someone maintained.
#[sqlx::test]
async fn every_armed_table_answers_a_released_scope_with_invisibility_not_an_error(pool: PgPool) {
    let armed = armed_tables(&pool).await;
    let mut conn = low_privilege_connection(&pool).await;

    // NEGATIVE CONTROL, taken BEFORE the release: on a connection that has
    // never carried a scope every one of these reads already succeeds. So a
    // failure after the release is caused by the release and by nothing else —
    // not by a missing GRANT, a missing table or a broken connection.
    let mut broken_when_fresh = Vec::new();
    for table in &armed {
        if let Err(e) = count_or_sqlstate(&mut conn, table).await {
            broken_when_fresh.push(format!("  {table}: {e}"));
        }
    }
    assert!(
        broken_when_fresh.is_empty(),
        "premise: on a NEVER-SCOPED connection every armed table must read \
         cleanly (the GUC is NULL, the predicate is NULL, the answer is zero \
         rows). These did not, so the failures below would not be about the \
         released empty string:\n{}",
        broken_when_fresh.join("\n")
    );

    arm_then_release(&mut conn, Uuid::new_v4()).await;

    let mut raised = Vec::new();
    for table in &armed {
        match count_or_sqlstate(&mut conn, table).await {
            Ok(_) => {}
            Err(e) => raised.push(format!("  {table}: {e}")),
        }
    }

    assert!(
        raised.is_empty(),
        "{} of {} armed tables raise instead of returning the empty set when \
         read with no scope armed on a connection that previously carried \
         one:\n{}\n\nA released transaction-local set_config reverts to '' and \
         ''::uuid raises 22P02. Rewrite each policy's predicate as \
         `NULLIF(current_setting('app.current_workspace_id', true), '')::uuid`, \
         which migration 032 already did for refresh_tokens. Whether a given \
         request sees this error or the empty set is decided by pool checkout, \
         so it is one defect with two faces.",
        raised.len(),
        armed.len(),
        raised.join("\n")
    );
}

// ===========================================================================
// Invisible, and only invisible
// ===========================================================================

/// The pair that has to DIFFER: with no scope armed the rows are invisible;
/// with the right scope armed, on the SAME connection and the SAME rows, they
/// are all there.
///
/// The second half is what makes the first half mean something. A test that
/// only asserted `count == 0` would be satisfied by a failed fixture.
#[sqlx::test]
async fn an_unscoped_read_is_invisible_while_a_scoped_read_is_unchanged(pool: PgPool) {
    let a = seed_workspace(&pool, "Invisible A").await;
    let b = seed_workspace(&pool, "Invisible B").await;
    seed_admin_audit(&pool, a).await;
    seed_admin_audit(&pool, a).await;
    seed_admin_audit(&pool, b).await;

    // PREMISE: the three rows are on disk. Read back from a scope that WOULD
    // see them, with an explicit predicate, so this holds under both roles.
    let mut tx = scoped_tx(&pool, a).await;
    let on_disk: i64 =
        sqlx::query_scalar("SELECT count(*) FROM admin_audit WHERE workspace_id = $1")
            .bind(a)
            .fetch_one(&mut *tx)
            .await
            .expect("premise read");
    tx.commit().await.expect("commit premise read");
    assert_eq!(
        on_disk, 2,
        "premise: the fixture must have written two admin_audit rows for \
         workspace A. Without them 'the unscoped reader sees nothing' is true \
         of an empty table."
    );

    let mut conn = low_privilege_connection(&pool).await;

    // Put the connection in the RELEASED state, which is what a pooled
    // connection is in for every statement after the first scoped one.
    arm_then_release(&mut conn, a).await;

    let unscoped = count_or_sqlstate(&mut conn, "admin_audit")
        .await
        .unwrap_or_else(|e| {
            panic!(
                "an unscoped read of an armed table must be INVISIBLE, not an \
                 error. Got {e}. Migration 033 rewrites the predicate with \
                 NULLIF so the released empty string yields NULL rather than \
                 raising on the cast."
            )
        });
    assert_eq!(
        unscoped, 0,
        "with no scope armed the predicate is NULL for every row, so the \
         answer must be the empty set"
    );

    // POSITIVE CONTROL, same connection, same rows: arm A and all of A's rows
    // appear. This is the half that fails if 033 broke the predicate rather
    // than only its behaviour on ''.
    let mut tx = conn.begin().await.expect("control transaction");
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
        .bind(a.to_string())
        .execute(&mut *tx)
        .await
        .expect("arm A");
    let scoped: i64 = sqlx::query_scalar("SELECT count(*) FROM admin_audit")
        .fetch_one(&mut *tx)
        .await
        .expect("scoped read");
    tx.commit().await.expect("commit control");
    assert_eq!(
        scoped, 2,
        "a CORRECTLY SCOPED read must be unchanged by the rewrite: workspace A \
         has two admin_audit rows and B's row must not be among them"
    );

    // And the isolation itself is still isolation — B's scope sees exactly B's
    // row, not A's two. If NULLIF had been applied to the wrong side of the
    // comparison this is the assertion that catches it.
    let mut tx = conn.begin().await.expect("control transaction B");
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
        .bind(b.to_string())
        .execute(&mut *tx)
        .await
        .expect("arm B");
    let scoped_b: i64 = sqlx::query_scalar("SELECT count(*) FROM admin_audit")
        .fetch_one(&mut *tx)
        .await
        .expect("scoped read B");
    tx.commit().await.expect("commit control B");
    assert_eq!(
        scoped_b, 1,
        "workspace B must see its own row and only its own row"
    );
}

/// The WRITE direction stays LOUD. This is the compensating half of making the
/// read direction quiet.
///
/// `USING` supplies `WITH CHECK` for a policy created without one, so after the
/// rewrite an unscoped INSERT is checked against a NULL predicate and rejected
/// with `42501 new row violates row-level security policy` — a different
/// SQLSTATE from the 22P02 it raised before, and still an error the caller
/// cannot miss.
#[sqlx::test]
async fn an_unscoped_insert_is_still_rejected_loudly(pool: PgPool) {
    let workspace_id = seed_workspace(&pool, "Loud Insert").await;
    let mut conn = low_privilege_connection(&pool).await;
    arm_then_release(&mut conn, workspace_id).await;

    let err = sqlx::query(
        "INSERT INTO admin_audit (id, workspace_id, action, target_type)
         VALUES (gen_random_uuid(), $1, 'user.created', 'user')",
    )
    .bind(workspace_id)
    .execute(&mut conn)
    .await
    .expect_err(
        "an INSERT with no scope armed must be REJECTED. If it succeeded, the \
         rewrite loosened the write path and one workspace can plant rows in \
         another's audit trail.",
    );
    let code = describe(&err);
    assert!(
        code.starts_with("42501"),
        "the unscoped INSERT must fail with 42501 (row-level security policy \
         violation), which is what a NULL predicate produces on the WITH CHECK \
         side. Got {code}. A 22P02 here means the policy still casts the \
         released empty string and this table was missed by the sweep."
    );

    // POSITIVE CONTROL: the same INSERT, same connection, WITH the scope armed,
    // succeeds. Without it the assertion above is satisfied by any broken
    // insert — a bad column list, a missing grant, a check constraint.
    let mut tx = conn.begin().await.expect("control transaction");
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
        .bind(workspace_id.to_string())
        .execute(&mut *tx)
        .await
        .expect("arm the scope");
    sqlx::query(
        "INSERT INTO admin_audit (id, workspace_id, action, target_type)
         VALUES (gen_random_uuid(), $1, 'user.created', 'user')",
    )
    .bind(workspace_id)
    .execute(&mut *tx)
    .await
    .expect("the identical INSERT must succeed once the scope is armed");
    tx.commit().await.expect("commit control insert");
}

/// `retention_purge_audit` carries the ONE policy in the schema that is not
/// plain `workspace_isolation`: migration 030's `workspace_isolation_or_global`
/// admits `workspace_id IS NULL` as well.
///
/// `tests/rls_call_site_guard.rs` accepts the worker's bare-pool write there as
/// a FALSE POSITIVE on the grounds that "`workspace_id IS NULL` satisfies
/// migration 030's `workspace_isolation_or_global` policy on its own". That is
/// true of the INSERT and NOT of the SELECT: an INSERT evaluates the predicate
/// against one NULL-workspace row, the OR short-circuits and the cast is never
/// reached, but a SELECT evaluates it against WORKSPACE-OWNED rows too, where
/// the first operand is false and the cast IS reached. On a released connection
/// that read raised. After the sweep, both halves work.
#[sqlx::test]
async fn the_global_retention_purge_audit_row_is_readable_without_a_scope(pool: PgPool) {
    let workspace_id = seed_workspace(&pool, "Purge Audit").await;

    let mut tx = scoped_tx(&pool, workspace_id).await;
    for (scope, ws) in [("global", None), ("workspace", Some(workspace_id))] {
        sqlx::query(
            "INSERT INTO retention_purge_audit
                 (id, run_id, scope, workspace_id, cutoff, rows_deleted,
                  rows_remaining_past_cutoff, status, started_at)
             VALUES (gen_random_uuid(), gen_random_uuid(), $1, $2, NOW(), 0, 0,
                     'ok', NOW())",
        )
        .bind(scope)
        .bind(ws)
        .execute(&mut *tx)
        .await
        .expect("retention_purge_audit seed");
    }
    // PREMISE, from a scope that sees BOTH: one global row and one
    // workspace-owned row are on disk. Without this the "1" below could be an
    // empty table plus a coincidence.
    let seeded: i64 =
        sqlx::query_scalar("SELECT count(*) FROM retention_purge_audit WHERE workspace_id IS NULL")
            .fetch_one(&mut *tx)
            .await
            .expect("premise: global row");
    let seeded_ws: i64 =
        sqlx::query_scalar("SELECT count(*) FROM retention_purge_audit WHERE workspace_id = $1")
            .bind(workspace_id)
            .fetch_one(&mut *tx)
            .await
            .expect("premise: workspace row");
    tx.commit().await.expect("commit seed");
    assert_eq!(seeded, 1, "premise: exactly one global row was seeded");
    assert_eq!(
        seeded_ws, 1,
        "premise: exactly one workspace-owned row was seeded. It is what forces \
         the OR's second operand — and therefore the cast — to be evaluated."
    );

    let mut conn = low_privilege_connection(&pool).await;
    arm_then_release(&mut conn, workspace_id).await;

    let visible = count_or_sqlstate(&mut conn, "retention_purge_audit")
        .await
        .unwrap_or_else(|e| {
            panic!(
                "the worker writes GLOBAL retention_purge_audit records on a bare \
                 pool and an auditor reads them back the same way. On a released \
                 connection that read got {e}."
            )
        });
    assert_eq!(
        visible, 1,
        "with no scope armed exactly the GLOBAL row is visible: \
         `workspace_id IS NULL` is true of it and the second operand of the OR \
         is NULL for the workspace-owned one"
    );

    // POSITIVE CONTROL: with the workspace armed, BOTH rows are visible on the
    // same connection. `1` above is therefore filtering and not an empty table.
    let mut tx = conn.begin().await.expect("control transaction");
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
        .bind(workspace_id.to_string())
        .execute(&mut *tx)
        .await
        .expect("arm the scope");
    let both: i64 = sqlx::query_scalar("SELECT count(*) FROM retention_purge_audit")
        .fetch_one(&mut *tx)
        .await
        .expect("scoped read");
    tx.commit().await.expect("commit control");
    assert_eq!(
        both, 2,
        "armed to the owning workspace, both the global and the workspace-owned \
         row must be visible"
    );
}
