//! Migration 006's `api_keys` back-fill under a NON-SUPERUSER, NOBYPASSRLS
//! Postgres role — the residue of MR1 review finding C1.
//!
//! # What C1 said, and what is left of it
//!
//! C1 reported `017_uzbek_identifier_policy_classes.sql:40` as a bare
//! `UPDATE policy_rules` against a table under FORCE ROW LEVEL SECURITY:
//! `current_setting('app.current_workspace_id', true)` is NULL when the GUC is
//! unset, the policy predicate is NULL for every row, the statement matches
//! zero rows, reports `UPDATE 0` and exits 0, and `sqlx migrate run` records
//! the migration as applied.
//!
//! At the current tip that specific instance is REPAIRED:
//! `020_reconcile_default_policy_classes.sql` re-runs the back-fill inside a
//! `FOR ws IN SELECT id FROM workspaces LOOP PERFORM set_config(...)` loop,
//! and `tests/migration_017_023_rls.rs::
//! migration_020_repairs_017_on_the_same_low_privilege_connection` proves it.
//! 017 itself is deliberately unedited: it is applied on real databases and a
//! byte change breaks the sqlx checksum.
//!
//! The residue is `006_api_key_rotation.sql:16`:
//!
//! ```sql
//! UPDATE api_keys SET status = 'revoked'
//!  WHERE revoked_at IS NOT NULL AND status = 'active';
//! ```
//!
//! `api_keys` is armed by `001_init.sql:78` — five migrations BEFORE this one
//! — so 006 is the same trap, five migrations earlier, and nothing has ever
//! repaired it.
//!
//! # Why this one is worse than 017's
//!
//! 017's failure leaks: an Uzbek identifier is detected and forwarded.
//! 006's failure ADMITS. `status` is a column 006 adds with
//! `DEFAULT 'active'`, and the back-fill is the ONLY thing that carries a
//! Phase-5 `revoked_at IS NOT NULL` row across into the new lifecycle.
//! `ApiKeyRepository::authenticate_api_key` decides on `status` alone — its
//! own comment says so: *"Reject: status = 'revoked' (even if revoked_at IS
//! NULL from pre-migration data)"*. So where 006 no-opped, a key an
//! administrator revoked keeps `status = 'active'` and KEEPS AUTHENTICATING.
//! That is an authentication bypass with a revocation record in the same row
//! saying it should not be possible.
//!
//! # The two fixes this suite pins
//!
//!   * `035_repair_api_key_revocation_status.sql` — 006's back-fill re-run
//!     RLS-safely, exactly as 020 did for 017.
//!   * `authenticate_api_key` gains `AND revoked_at IS NULL`. Only
//!     `ApiKeyRepository::revoke` ever writes `revoked_at`, and it writes
//!     `status = 'revoked'` in the same statement; `rotate` never touches it.
//!     So `revoked_at IS NOT NULL` implies "must not authenticate"
//!     unconditionally, and the predicate holds on a database whose migration
//!     history nobody can reconstruct.
//!
//! # Vacuity rules, same as this crate's other RLS suites
//!
//!   * the low-privilege role's `rolsuper`/`rolbypassrls`/`row_security_active`
//!     are asserted ON THE WIRE before anything is measured;
//!   * every negative claim has a positive control on the same connection that
//!     must DIFFER;
//!   * the no-op measurement carries a superuser replay of the IDENTICAL file,
//!     so "nothing changed" cannot mean "the fixture never matched the guard".
//!
//! All fixture key material is synthetic.

use secureprompt_api::db::api_key_repo::{hash_api_key, ApiKeyRepository};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Connection, PgConnection, PgPool, Row};
use uuid::Uuid;

const RLS_ROLE: &str = "secureprompt_runner";
const RLS_PASSWORD: &str = "secureprompt";

const MIGRATION_006: &str = include_str!("../migrations/006_api_key_rotation.sql");

/// Read at RUNTIME, not `include_str!`. The repair migration is the thing
/// under test; a missing file must fail this suite with a message that names
/// it, not fail the crate to compile.
fn migration_035() -> String {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/migrations/035_repair_api_key_revocation_status.sql"
    );
    std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "{path} is missing ({e}). Migration 006's `UPDATE api_keys SET \
             status = 'revoked'` is a no-op under RLS, so every key revoked \
             before 006 ran still authenticates. The repair migration is what \
             closes that."
        )
    })
}

struct Key {
    id: Uuid,
    plaintext: String,
}

async fn new_workspace(pool: &PgPool, label: &str) -> Uuid {
    let workspace_id = Uuid::new_v4();
    sqlx::query("INSERT INTO workspaces (id, name) VALUES ($1, $2)")
        .bind(workspace_id)
        .bind(format!("Revocation Residue {label}"))
        .execute(pool)
        .await
        .expect("workspace insert");
    workspace_id
}

/// Seed the exact row shape a database left behind by a no-opped 006 carries:
/// an administrator revoked the key (`revoked_at` set) but the lifecycle
/// column never caught up, so it still reads `'active'`.
///
/// `api_keys` is under FORCE RLS, so this INSERT is armed. An unarmed INSERT
/// is refused with `42501` — loudly — so a fixture that forgot to arm could
/// not masquerade as a passing test.
async fn seed_key(
    pool: &PgPool,
    workspace_id: Uuid,
    label: &str,
    status: &str,
    revoked: bool,
) -> Key {
    let id = Uuid::new_v4();
    let plaintext = format!("sp_{}{}", label.to_lowercase(), Uuid::new_v4().simple());

    let mut tx = pool.begin().await.expect("fixture transaction");
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
        .bind(workspace_id.to_string())
        .execute(&mut *tx)
        .await
        .expect("arm the fixture scope");
    sqlx::query(
        "INSERT INTO api_keys
             (id, workspace_id, name, key_hash, created_at, status, revoked_at)
         VALUES ($1, $2, $3, $4, NOW(), $5,
                 CASE WHEN $6 THEN NOW() - INTERVAL '30 days' ELSE NULL END)",
    )
    .bind(id)
    .bind(workspace_id)
    .bind(format!("key-{label}"))
    .bind(hash_api_key(&plaintext))
    .bind(status)
    .bind(revoked)
    .execute(&mut *tx)
    .await
    .expect("api_keys insert must be armed, or the fixture itself is the bug");
    tx.commit().await.expect("fixture commit");

    Key { id, plaintext }
}

/// `status` for one key, read from a scope that WOULD see it. `None` is a
/// broken premise, never an answer.
async fn status_of(pool: &PgPool, workspace_id: Uuid, key_id: Uuid) -> Option<String> {
    let mut tx = pool.begin().await.expect("read-back transaction");
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
        .bind(workspace_id.to_string())
        .execute(&mut *tx)
        .await
        .expect("arm the read-back scope");
    let row = sqlx::query("SELECT status FROM api_keys WHERE id = $1")
        .bind(key_id)
        .fetch_optional(&mut *tx)
        .await
        .expect("read-back query");
    tx.commit().await.expect("read-back commit");
    row.map(|r| r.get("status"))
}

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
        "GRANT USAGE, CREATE ON SCHEMA public TO {RLS_ROLE};
         GRANT ALL ON ALL TABLES IN SCHEMA public TO {RLS_ROLE};
         GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO {RLS_ROLE};"
    ))
    .execute(pool)
    .await
    .expect("grants on the test database");
}

/// 006 contains `ALTER TABLE api_keys ADD COLUMN`, which Postgres allows only
/// to the table's owner, so replaying it needs ownership handed over first.
///
/// Ownership does NOT re-open row-level security: `001_init.sql` arms
/// api_keys with FORCE ROW LEVEL SECURITY, and FORCE subjects the owner too.
/// The `row_security_active('api_keys')` premise inside
/// [`low_privilege_connection`] is what proves that on the wire rather than
/// asserting it — if a future Postgres or a dropped FORCE ever exempted the
/// owner, that assertion fires instead of this suite quietly measuring
/// nothing.
async fn hand_api_keys_to_the_runner(pool: &PgPool) {
    ensure_low_privilege_role(pool).await;
    sqlx::raw_sql(&format!("ALTER TABLE api_keys OWNER TO {RLS_ROLE};"))
        .execute(pool)
        .await
        .expect("handing api_keys ownership to the low-privilege role");
}

/// A single CONNECTION as `RLS_ROLE` — how `sqlx migrate run` executes a
/// migration file. Powerlessness asserted on the wire.
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
        "SELECT current_user::text AS who, rolsuper, rolbypassrls, \
         row_security_active('api_keys') AS enforced \
         FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&mut conn)
    .await
    .expect("identity probe");

    let who: String = row.get("who");
    assert_eq!(who, RLS_ROLE, "premise: connected as the wrong role");
    assert!(
        !row.get::<bool, _>("rolsuper"),
        "premise: {who} is a SUPERUSER, so it bypasses RLS and this suite proves nothing"
    );
    assert!(
        !row.get::<bool, _>("rolbypassrls"),
        "premise: {who} has BYPASSRLS, so it bypasses RLS and this suite proves nothing"
    );
    assert!(
        row.get::<bool, _>("enforced"),
        "premise: row security is not active on api_keys for {who}, so the \
         migration below runs unfiltered and measures nothing"
    );

    conn
}

/// A POOL as `RLS_ROLE`, for driving the repository. A pool rather than a
/// connection because `set_config(..., true)` is transaction-local and a pool
/// hands successive statements to different checkouts.
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
        "SELECT rolsuper, rolbypassrls, row_security_active('api_keys') AS enforced \
         FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&low)
    .await
    .expect("identity probe");
    assert!(
        !row.get::<bool, _>("rolsuper") && !row.get::<bool, _>("rolbypassrls"),
        "premise: the repository pool bypasses RLS, so this suite proves nothing"
    );
    assert!(
        row.get::<bool, _>("enforced"),
        "premise: row security is not active on api_keys for the repository pool"
    );

    low
}

// ===========================================================================
// The measurement. 006 is FROZEN — this test documents why the row shape the
// next two tests are about exists in the wild, and it must stay green forever.
// ===========================================================================

/// Run verbatim by a role that cannot bypass RLS, 006's back-fill SUCCEEDS and
/// changes NOTHING. Both halves matter: an error would have been caught on the
/// first deployment; silence is what let it ship.
///
/// The POSITIVE CONTROL runs the IDENTICAL file over the superuser pool and
/// requires the status to flip. Without it, an unchanged `status` could
/// equally mean the fixture never matched 006's `WHERE`, and the test would be
/// measuring a typo instead of RLS.
#[sqlx::test]
async fn migration_006_backfill_is_a_silent_no_op_under_rls(pool: PgPool) {
    assert_eq!(
        rls_flags(&pool, "api_keys").await,
        (true, true),
        "premise: 001_init.sql arms api_keys. Unarmed, the low-privilege \
         connection writes everything and this test measures nothing."
    );

    let tenant = new_workspace(&pool, "No-Op").await;
    let stranded = seed_key(&pool, tenant, "Stranded", "active", true).await;

    assert_eq!(
        status_of(&pool, tenant, stranded.id).await.as_deref(),
        Some("active"),
        "premise: the fixture must start in the state 006 exists to correct"
    );

    // Replay 006 the way `sqlx migrate run` would: one connection, no GUC.
    hand_api_keys_to_the_runner(&pool).await;
    let mut conn = low_privilege_connection(&pool).await;
    sqlx::raw_sql(MIGRATION_006)
        .execute(&mut conn)
        .await
        .expect(
            "006 must SUCCEED under the non-bypassing role. An error would \
             have been caught on the first deployment; the defect is that it \
             succeeds.",
        );

    assert_eq!(
        status_of(&pool, tenant, stranded.id).await.as_deref(),
        Some("active"),
        "006's back-fill matched a row under RLS. If this ever fires the \
         defect is gone and this test — and migration 035 — can be retired."
    );

    // POSITIVE CONTROL: the identical file, superuser pool.
    sqlx::raw_sql(MIGRATION_006)
        .execute(&pool)
        .await
        .expect("006 replay on the privileged pool");
    assert_eq!(
        status_of(&pool, tenant, stranded.id).await.as_deref(),
        Some("revoked"),
        "the fixture never matched 006's WHERE at all, so the assertion above \
         was measuring a typo rather than row-level security"
    );
}

// ===========================================================================
// Fix 1 — the repair migration.
// ===========================================================================

/// 035 does under RLS what 006 could not: the SAME back-fill, driven from a
/// loop over `workspaces` with `set_config` per tenant.
///
/// Run on the SAME low-privilege connection that just proved 006 is inert, so
/// the difference between them is the migration and nothing else. Two tenants,
/// because a loop that only ever arms the first workspace passes a
/// single-tenant test.
#[sqlx::test]
async fn migration_035_repairs_006_on_the_same_low_privilege_connection(pool: PgPool) {
    let tenant_a = new_workspace(&pool, "Repair A").await;
    let tenant_b = new_workspace(&pool, "Repair B").await;
    let stranded_a = seed_key(&pool, tenant_a, "StrandedA", "active", true).await;
    let stranded_b = seed_key(&pool, tenant_b, "StrandedB", "active", true).await;
    // Must survive untouched: 035 only ever promotes 'active' -> 'revoked' for
    // rows that CARRY a revocation.
    let live = seed_key(&pool, tenant_a, "Live", "active", false).await;

    hand_api_keys_to_the_runner(&pool).await;
    let mut conn = low_privilege_connection(&pool).await;

    sqlx::raw_sql(MIGRATION_006)
        .execute(&mut conn)
        .await
        .expect("006 replay");
    assert_eq!(
        status_of(&pool, tenant_a, stranded_a.id).await.as_deref(),
        Some("active"),
        "premise: 006 must be inert here, or 035 has nothing to repair"
    );

    sqlx::raw_sql(&migration_035())
        .execute(&mut conn)
        .await
        .expect("035 must apply cleanly under the non-bypassing role");

    assert_eq!(
        status_of(&pool, tenant_a, stranded_a.id).await.as_deref(),
        Some("revoked"),
        "035 did not repair the first tenant's stranded revocation"
    );
    assert_eq!(
        status_of(&pool, tenant_b, stranded_b.id).await.as_deref(),
        Some("revoked"),
        "035 repaired only the FIRST workspace — the per-tenant loop is not \
         iterating, which is what a single-tenant fixture would have hidden"
    );
    assert_eq!(
        status_of(&pool, tenant_a, live.id).await.as_deref(),
        Some("active"),
        "035 revoked a key that was never revoked. It must only promote rows \
         that already carry `revoked_at`."
    );

    // IDEMPOTENCE: 035 re-runs without error and without further change.
    sqlx::raw_sql(&migration_035())
        .execute(&mut conn)
        .await
        .expect("035 must be idempotent");
    assert_eq!(
        status_of(&pool, tenant_a, live.id).await.as_deref(),
        Some("active"),
        "a second 035 run changed a live key"
    );
}

// ===========================================================================
// Fix 2 — the predicate that does not depend on migration history at all.
// ===========================================================================

/// THE SECURITY CLAIM. A key whose `revoked_at` is set must not authenticate,
/// whatever `status` says.
///
/// This is the shape 006 strands, and it is reachable on any database migrated
/// by a role without BYPASSRLS — which is every database once the DB role
/// split lands. The repository is driven on the LOW-PRIVILEGE pool so the
/// answer is the production one.
///
/// The positive control is mandatory here for a reason peculiar to this
/// method: `authenticate_api_key` has NO `workspace_id` predicate and leans on
/// the `workspace_isolation` policy, so an unarmed or over-restricted scope
/// returns the empty set for EVERY key, and "revoked key rejected" would be
/// indistinguishable from "the repository is broken and rejects everything".
#[sqlx::test]
async fn a_revoked_key_stranded_active_by_migration_006_does_not_authenticate(pool: PgPool) {
    let tenant = new_workspace(&pool, "Bypass").await;
    let stranded = seed_key(&pool, tenant, "Stranded", "active", true).await;
    let live = seed_key(&pool, tenant, "Live", "active", false).await;

    let repo = ApiKeyRepository::new(low_privilege_pool(&pool).await);

    let stranded_auth = repo
        .authenticate_api_key(&stranded.plaintext)
        .await
        .expect("authentication must not error");
    assert!(
        stranded_auth.is_none(),
        "a key an administrator REVOKED authenticated, because migration 006's \
         `UPDATE api_keys SET status = 'revoked'` no-opped under RLS and left \
         `status = 'active'` on a row whose `revoked_at` is set. That is an \
         authentication bypass carrying its own revocation record."
    );

    // POSITIVE CONTROL — must DIFFER, or the assertion above is just the empty
    // set an unarmed reader gets back.
    let live_auth = repo
        .authenticate_api_key(&live.plaintext)
        .await
        .expect("authentication must not error");
    assert_eq!(
        live_auth.map(|k| k.id),
        Some(live.id),
        "a live ACTIVE key was rejected under the non-bypassing role, so the \
         rejection above proves nothing about revocation"
    );
}
