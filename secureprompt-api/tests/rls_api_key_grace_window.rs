//! What the API-key rotation grace window ACTUALLY depends on, measured
//! through a NON-SUPERUSER, NOBYPASSRLS pool.
//!
//! # Why this file exists
//!
//! `tests/rls_call_site_guard.rs` used to allowlist a bare-pool statement on
//! `api_keys` in `secureprompt-worker/src/main.rs`. Its reason string called
//! that statement "the worker's startup key-cache warm", a READ that "fails
//! CLOSED". Both halves were false: there is no key-cache warm in the worker,
//! and the statement was the 03:00 rotation-cleanup
//! `UPDATE api_keys SET status = 'revoked'`.
//!
//! The obvious correction — "so rotated-out keys are never revoked and stay
//! valid past their grace window; it fails OPEN" — is ALSO false, and this
//! suite is what establishes that rather than arguing it.
//! [`ApiKeyRepository::authenticate_api_key`] re-derives the boundary in its
//! own WHERE:
//!
//! ```sql
//! status = 'rotating'
//!   AND rotated_at + (rotation_grace_secs || ' seconds')::INTERVAL > NOW()
//! ```
//!
//! which is the exact complement of the sweep's `<= NOW()`. The gate is that
//! predicate, not the sweep. A key whose window has closed stops
//! authenticating at the boundary whether the sweep ran, failed, or was never
//! deployed.
//!
//! What the un-run sweep actually costs is measured in the second test: the
//! row keeps `status = 'rotating'` forever, and
//! [`ApiKeyRepository::rotate`]'s idempotent `'rotating'` branch then answers
//! `200 OK` to an administrator re-rotating a dead credential — with
//! `grace_expires_at` already in the past, no new key issued, and NO
//! admin-audit row. Once the sweep works, the same call is a clean
//! `404 NotFound`.
//!
//! # The vacuity rules this suite obeys
//!
//! * The repository under test runs on the LOW-PRIVILEGE pool, and that pool
//!   asserts `rolsuper = false`, `rolbypassrls = false` and
//!   `row_security_active('api_keys')` ON THE WIRE before anything is measured.
//! * Every negative claim is paired with a positive control on the same
//!   connection that must DIFFER — "this key does not authenticate" is only
//!   meaningful next to a key that does.
//! * Every read-back arms the scope to the row's own workspace, so the suite
//!   behaves identically under the superuser and under `secureprompt_runner`,
//!   which the `test:rls-nonsuperuser` job requires.
//!
//! All fixture key material is synthetic.

use secureprompt_api::db::admin_audit_repo::AdminActor;
use secureprompt_api::db::api_key_repo::{hash_api_key, ApiKeyRepository};
use secureprompt_common::types::WorkspaceId;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Same role, password and creation attributes as
/// `scripts/ci/create-nonsuperuser-role.sh` and this crate's other RLS suites.
const RLS_ROLE: &str = "secureprompt_runner";
const RLS_PASSWORD: &str = "secureprompt";

/// A seeded key and the plaintext that hashes to its `key_hash`.
struct Key {
    id: Uuid,
    plaintext: String,
}

async fn new_workspace(pool: &PgPool, label: &str) -> Uuid {
    let workspace_id = Uuid::new_v4();
    sqlx::query("INSERT INTO workspaces (id, name) VALUES ($1, $2)")
        .bind(workspace_id)
        .bind(format!("Grace Window {label}"))
        .execute(pool)
        .await
        .expect("workspace insert");
    workspace_id
}

/// Seed one API key with an explicit lifecycle state.
///
/// `rotated_ago` is `None` for an `'active'` key. For a `'rotating'` one it is
/// a Postgres interval literal, and the key is past its window exactly when it
/// exceeds `grace_secs`.
///
/// `api_keys` is under FORCE ROW LEVEL SECURITY, so this INSERT is armed. An
/// unarmed INSERT is refused with `42501` — loudly, unlike the UPDATE this
/// whole workstream is about — so a fixture that forgot to arm could not
/// masquerade as a passing test.
async fn seed_key(
    pool: &PgPool,
    workspace_id: Uuid,
    label: &str,
    status: &str,
    rotated_ago: Option<&str>,
    grace_secs: i32,
) -> Key {
    let id = Uuid::new_v4();
    let plaintext = format!(
        "sp_{}{}",
        label.to_lowercase().replace(' ', ""),
        Uuid::new_v4().simple()
    );

    let mut tx = pool.begin().await.expect("fixture transaction");
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
        .bind(workspace_id.to_string())
        .execute(&mut *tx)
        .await
        .expect("arm the fixture scope");
    sqlx::query(
        "INSERT INTO api_keys
             (id, workspace_id, name, key_hash, created_at, status,
              rotated_at, rotation_grace_secs, successor_key_prefix)
         VALUES ($1, $2, $3, $4, NOW(), $5,
                 CASE WHEN $6::TEXT IS NULL THEN NULL ELSE NOW() - $6::INTERVAL END,
                 $7, CASE WHEN $6::TEXT IS NULL THEN NULL ELSE 'sp_successor' END)",
    )
    .bind(id)
    .bind(workspace_id)
    .bind(format!("key-{label}"))
    .bind(hash_api_key(&plaintext))
    .bind(status)
    .bind(rotated_ago)
    .bind(grace_secs)
    .execute(&mut *tx)
    .await
    .expect("api_keys insert must be armed, or the fixture itself is the bug");
    tx.commit().await.expect("fixture commit");

    Key { id, plaintext }
}

/// `(status, revoked_at IS NULL)` for one key, read from a scope that WOULD
/// see it. `None` is a broken premise, never an answer.
async fn key_state(pool: &PgPool, workspace_id: Uuid, key_id: Uuid) -> Option<(String, bool)> {
    let mut tx = pool.begin().await.expect("read-back transaction");
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
        .bind(workspace_id.to_string())
        .execute(&mut *tx)
        .await
        .expect("arm the read-back scope");
    let row = sqlx::query("SELECT status, revoked_at IS NULL AS never FROM api_keys WHERE id = $1")
        .bind(key_id)
        .fetch_optional(&mut *tx)
        .await
        .expect("read-back query");
    tx.commit().await.expect("read-back commit");
    row.map(|r| (r.get("status"), r.get("never")))
}

/// How many `api_key.rotated` rows this workspace's admin-audit trail holds,
/// read from an armed scope.
async fn rotated_audit_rows(pool: &PgPool, workspace_id: Uuid) -> i64 {
    let mut tx = pool.begin().await.expect("audit read transaction");
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
        .bind(workspace_id.to_string())
        .execute(&mut *tx)
        .await
        .expect("arm the audit read scope");
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM admin_audit
         WHERE workspace_id = $1 AND action = 'api_key.rotated'",
    )
    .bind(workspace_id)
    .fetch_one(&mut *tx)
    .await
    .expect("admin_audit count");
    tx.commit().await.expect("audit read commit");
    count
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

/// A POOL onto the same `#[sqlx::test]` database as `RLS_ROLE`, with the
/// role's powerlessness asserted ON THE WIRE.
///
/// A POOL rather than a connection: `set_config(..., true)` is
/// transaction-local and a pool hands successive statements to different
/// connections, so a repository that armed the scope on one checkout and read
/// on another fails here and would pass a single-connection test.
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
        "SELECT current_user::text AS who, rolsuper, rolbypassrls, \
         row_security_active('api_keys') AS enforced \
         FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&low)
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
        "premise: row security is not active on api_keys for {who}, so every \
         repository call below runs unfiltered and measures nothing"
    );

    low
}

// ===========================================================================
// What the grace window actually rests on
// ===========================================================================

/// THE CORRECTION. A `'rotating'` key whose grace window closed and which the
/// sweep NEVER revoked must not authenticate — so the un-run sweep is not an
/// authentication bypass, and the entry that graded it one would have been
/// wrong in the other direction.
///
/// Three keys in ONE workspace, so all three are decided by the same armed
/// scope and any difference between them is the PREDICATE, not the tenancy:
///
///   * stale  — `'rotating'`, 10 days past a 1-day window. Must be rejected.
///   * fresh  — `'rotating'`, 1 minute into a 1-day window. Must be accepted.
///   * active — `'active'`. Must be accepted.
///
/// The last two are the positive controls. Without them a repository that
/// rejected everything — the silent-empty-set failure this whole workstream is
/// about — would pass the first assertion.
#[sqlx::test]
async fn a_grace_expired_key_the_sweep_never_revoked_does_not_authenticate(pool: PgPool) {
    assert_eq!(
        rls_flags(&pool, "api_keys").await,
        (true, true),
        "premise: 001_init.sql arms api_keys. Unarmed, the low-privilege pool \
         reads everything and this test measures nothing."
    );

    let tenant = new_workspace(&pool, "Boundary").await;
    let stale = seed_key(&pool, tenant, "Stale", "rotating", Some("10 days"), 86_400).await;
    let fresh = seed_key(&pool, tenant, "Fresh", "rotating", Some("1 minute"), 86_400).await;
    let active = seed_key(&pool, tenant, "Active", "active", None, 86_400).await;

    // PREMISE: the sweep genuinely never touched the stale key. If the fixture
    // had seeded it revoked, the rejection below would prove nothing about the
    // grace predicate.
    assert_eq!(
        key_state(&pool, tenant, stale.id).await,
        Some(("rotating".to_owned(), true)),
        "premise: the stale key must still be `rotating` with revoked_at NULL — \
         that IS the state a never-run sweep leaves behind"
    );

    let low = low_privilege_pool(&pool).await;
    let repo = ApiKeyRepository::new(low);

    let stale_auth = repo
        .authenticate_api_key(&stale.plaintext)
        .await
        .expect("authentication must not error");
    assert!(
        stale_auth.is_none(),
        "a key 9 days past its grace window authenticated because the sweep \
         never revoked it. If this ever fires, the un-run sweep IS an \
         authentication bypass and its severity is the highest in the \
         allowlist, not the lowest."
    );

    // POSITIVE CONTROLS. These must DIFFER, or the assertion above is just the
    // empty set that RLS returns to an unarmed reader.
    let fresh_auth = repo
        .authenticate_api_key(&fresh.plaintext)
        .await
        .expect("authentication must not error");
    assert_eq!(
        fresh_auth.map(|k| k.id),
        Some(fresh.id),
        "a `rotating` key still INSIDE its grace window was rejected. Either \
         the low-privilege pool is reading the empty set — which makes the \
         rejection above meaningless — or rotation now breaks every caller it \
         was designed to protect."
    );
    let active_auth = repo
        .authenticate_api_key(&active.plaintext)
        .await
        .expect("authentication must not error");
    assert_eq!(
        active_auth.map(|k| k.id),
        Some(active.id),
        "an ACTIVE key was rejected under the non-bypassing role"
    );
}

/// WHAT THE UN-RUN SWEEP ACTUALLY COSTS. A key left `'rotating'` forever makes
/// re-rotation a silent no-op: `rotate` takes its idempotent branch, answers
/// success with a `grace_expires_at` already in the past, issues no new key,
/// and writes no admin-audit row. An administrator responding to a suspected
/// compromise watches that succeed.
///
/// The control is the same call once the sweep HAS done its work: `'revoked'`
/// falls outside `status IN ('active', 'rotating')`, so the administrator gets
/// a `404` naming the key instead of a fabricated success.
#[sqlx::test]
async fn re_rotating_a_key_the_sweep_left_rotating_reports_success_and_does_nothing(pool: PgPool) {
    let tenant = new_workspace(&pool, "Stuck").await;
    let stale = seed_key(&pool, tenant, "Stuck", "rotating", Some("10 days"), 86_400).await;
    let healthy = seed_key(&pool, tenant, "Healthy", "active", None, 86_400).await;

    assert_eq!(
        key_state(&pool, tenant, stale.id).await,
        Some(("rotating".to_owned(), true)),
        "premise: the stale key must start in the state a never-run sweep leaves"
    );
    assert_eq!(
        rotated_audit_rows(&pool, tenant).await,
        0,
        "premise: no rotation has been audited in this workspace yet"
    );

    let low = low_privilege_pool(&pool).await;
    let repo = ApiKeyRepository::new(low);
    let actor = AdminActor {
        workspace_id: tenant,
        user_id: None,
        email: None,
        role: Some("admin".to_owned()),
    };

    // POSITIVE CONTROL, and the premise for the audit count below: a REAL
    // rotation writes exactly one audit row and issues a usable key. Without
    // this, "no audit row was written" could be RLS hiding the table rather
    // than `rotate` declining to write.
    let (issued, _expires) = repo
        .rotate(WorkspaceId(tenant), healthy.id, &actor)
        .await
        .expect("rotating an active key must succeed");
    assert!(
        issued.starts_with("sp_") && issued.len() > 20,
        "a real rotation must return a usable plaintext key, got {issued:?}"
    );
    assert_eq!(
        rotated_audit_rows(&pool, tenant).await,
        1,
        "premise: a real rotation writes exactly one api_key.rotated row, and \
         this armed scope can SEE it. If this is 0, the count below proves \
         nothing about whether the stale rotation was recorded."
    );

    // THE DEFECT'S COST. Same call, on the key the sweep should have revoked.
    let (echoed, grace_expires_at) = repo
        .rotate(WorkspaceId(tenant), stale.id, &actor)
        .await
        .expect("today this returns Ok — that is the finding, not the goal");
    assert!(
        !echoed.starts_with("sp_") || echoed.ends_with("..."),
        "the idempotent branch must not look like a freshly issued key; got {echoed:?}"
    );
    assert!(
        grace_expires_at < chrono::Utc::now(),
        "the administrator was told the rotation's grace window expires at \
         {grace_expires_at}, which is in the FUTURE. The premise of this test \
         is that the key is already past its window."
    );
    assert_eq!(
        rotated_audit_rows(&pool, tenant).await,
        1,
        "the count moved, so the stale re-rotation DID write an audit row. \
         Re-derive this test: the claim it pins is that it does not."
    );
    assert_eq!(
        key_state(&pool, tenant, stale.id).await,
        Some(("rotating".to_owned(), true)),
        "the stale re-rotation changed the key's state, so it was not the \
         no-op this test claims"
    );
}
