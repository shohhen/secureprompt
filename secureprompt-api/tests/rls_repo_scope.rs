//! The REPOSITORY paths onto the four tables migration 030 arms, executed
//! through a NON-SUPERUSER, NOBYPASSRLS connection pool.
//!
//! # Why this suite exists, and why it is not a migration test
//!
//! `tests/migration_017_023_rls.rs` proves the DATABASE now refuses a foreign
//! tenant. That is only half of arming a table. The other half is that every
//! access path onto it sets `app.current_workspace_id` — because a query that
//! does not is fine TODAY (the compose role is a SUPERUSER and bypasses RLS
//! unconditionally) and becomes a SILENT ZERO the moment the DB role-split on
//! this project's backlog lands. That is migration 017's exact failure mode,
//! one layer up:
//!
//!   * `RawCaptureRepository::get_effective` resolves "no row" to
//!     [`RawCaptureSettings::default`]. An unset GUC makes the SELECT return
//!     no row, so a workspace that HAS opted into raw capture would read back
//!     as "capture off" — indistinguishable from never having chosen.
//!   * `SidecarPolicyRepository::get_effective` resolves "no row" to the
//!     deployment default. A workspace that chose `degrade_with_alert` would
//!     silently revert to `block`. That direction is fail-CLOSED, so it will
//!     not page anyone; it will just quietly stop honouring the choice the
//!     operator made, and 503 requests they expected to be served.
//!
//! Neither failure raises. Neither is visible from a `#[sqlx::test]` pool. So
//! this suite builds a SECOND pool against the same test database as
//! `secureprompt_runner` and drives the repositories through it, asserting the
//! role's powerlessness on the wire first.
//!
//! A POOL rather than a single connection, deliberately: `set_config(..., true)`
//! is transaction-local, and a pool hands successive statements to different
//! connections. A repository that armed the scope on one checkout and read on
//! another would pass a single-connection test and fail here.
//!
//! # What this suite does NOT cover
//!
//! Running the whole application as `secureprompt_runner` still fails ~85
//! tests in `workspace_repo`'s default-rule seeding — the DB role-split is a
//! separate backlog item. Fixtures here therefore go through the ordinary
//! superuser pool; only the repository call under test uses the low-privilege
//! pool.

use secureprompt_api::db::admin_audit_repo::AdminActor;
use secureprompt_api::db::raw_capture_repo::{RawCaptureRepository, RawCaptureSettings};
use secureprompt_api::db::sidecar_policy_repo::{
    SidecarPolicyRepository, SidecarUnavailablePolicy,
};
use secureprompt_common::types::WorkspaceId;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Same role, password and creation attributes as
/// `tests/migration_017_023_rls.rs` and `scripts/ci/create-nonsuperuser-role.sh`.
/// A second set would be a second thing to keep true.
const RLS_ROLE: &str = "secureprompt_runner";
const RLS_PASSWORD: &str = "secureprompt";

async fn seed_workspace(pool: &PgPool, name: &str) -> WorkspaceId {
    let workspace_id = Uuid::new_v4();
    sqlx::query("INSERT INTO workspaces (id, name) VALUES ($1, $2)")
        .bind(workspace_id)
        .bind(name)
        .execute(pool)
        .await
        .expect("workspace insert");
    WorkspaceId(workspace_id)
}

/// `(rowsecurity, forcerowsecurity)` straight out of the catalog.
///
/// Asserted as a PREMISE in every test below: if 030 were reverted, the
/// low-privilege pool would read everything and each test would pass while
/// measuring nothing.
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
/// Without these premise assertions the suite is worthless: a future base
/// image, a stray `ALTER ROLE` or a typo handing this role SUPERUSER or
/// BYPASSRLS would keep every test below green while exercising no RLS at all.
async fn low_privilege_pool(pool: &PgPool) -> PgPool {
    ensure_low_privilege_role(pool).await;

    let options: PgConnectOptions = (*pool.connect_options())
        .clone()
        .username(RLS_ROLE)
        .password(RLS_PASSWORD);

    // `max_connections(4)` and `min_connections(2)`: more than one, so that a
    // repository which armed the scope outside its transaction has a real
    // chance of reading on a different connection and failing here.
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
        "premise: {who} is a SUPERUSER, so it bypasses RLS and this suite proves nothing"
    );
    assert!(
        !row.get::<bool, _>("rolbypassrls"),
        "premise: {who} has BYPASSRLS, so it bypasses RLS and this suite proves nothing"
    );

    low
}

// ===========================================================================
// raw_capture_repo — `workspace_raw_capture` + `raw_capture_audit`
// ===========================================================================

/// THE SILENT ZERO, on the setting that decides whether plaintext prompts are
/// kept.
///
/// A workspace that opted IN must read back as opted in. With the scope
/// unarmed the SELECT returns no row and `get_effective` resolves that to
/// `RawCaptureSettings::default()` — capture off, 30 days — which is
/// indistinguishable from never having chosen and raises nothing.
///
/// The NEGATIVE CONTROL is the second workspace: it really has no row, and
/// must resolve to the default. Without it, "A reads 90 days" would also be
/// satisfied by a repository that ignored `workspace_id` entirely.
#[sqlx::test]
async fn raw_capture_get_effective_survives_a_non_bypassing_role(pool: PgPool) {
    let workspace_a = seed_workspace(&pool, "Capture Repo A").await;
    let workspace_b = seed_workspace(&pool, "Capture Repo B").await;

    sqlx::query(
        "INSERT INTO workspace_raw_capture (workspace_id, enabled, retention_days)
         VALUES ($1, true, 90)",
    )
    .bind(workspace_a.0)
    .execute(&pool)
    .await
    .expect("workspace A opts into raw capture for 90 days");

    // PREMISE: the row is on disk, and RLS is armed so the read below is
    // really passing through a policy.
    assert_eq!(
        rls_flags(&pool, "workspace_raw_capture").await,
        (true, true),
        "premise: migration 030 must have armed this table, or the \
         low-privilege pool reads everything and this test measures nothing"
    );

    let low = low_privilege_pool(&pool).await;
    let repo = RawCaptureRepository::new(low);

    let settings = repo
        .get_effective(workspace_a)
        .await
        .expect("reading a workspace's own capture settings must not error");
    assert_eq!(
        settings,
        RawCaptureSettings {
            enabled: true,
            retention_days: 90,
        },
        "workspace A's stored choice must survive the read. Reading back the \
         default here is the silent zero: an opted-in workspace would look \
         like one that never chose, and nothing would raise."
    );

    // NEGATIVE CONTROL: a workspace with no row really does resolve to the
    // default, so the assertion above is about the stored row and not about
    // the repository returning a constant.
    assert_eq!(
        repo.get_effective(workspace_b)
            .await
            .expect("a workspace with no row must resolve, not error"),
        RawCaptureSettings::default(),
        "a workspace that never chose must still read as capture-off"
    );
}

/// The audit trail WS3-1 requires must remain readable under a non-bypassing
/// role, and must carry only the caller's own rows.
#[sqlx::test]
async fn raw_capture_audit_trail_survives_a_non_bypassing_role(pool: PgPool) {
    let workspace_a = seed_workspace(&pool, "Trail A").await;
    let workspace_b = seed_workspace(&pool, "Trail B").await;

    for (workspace, email) in [
        (workspace_a, "admin@a.example"),
        (workspace_b, "admin@b.example"),
    ] {
        sqlx::query(
            "INSERT INTO raw_capture_audit
                (id, workspace_id, actor_user_id, actor_email, enabled_before, enabled_after,
                 retention_days_before, retention_days_after)
             VALUES ($1, $2, NULL, $3, false, true, 30, 90)",
        )
        .bind(Uuid::new_v4())
        .bind(workspace.0)
        .bind(email)
        .execute(&pool)
        .await
        .expect("audit row insert");
    }

    assert_eq!(
        rls_flags(&pool, "raw_capture_audit").await,
        (true, true),
        "premise: migration 030 must have armed this table"
    );

    let low = low_privilege_pool(&pool).await;
    let repo = RawCaptureRepository::new(low);

    let trail = repo
        .audit_trail(workspace_a, 10)
        .await
        .expect("reading a workspace's own audit trail must not error");
    let emails: Vec<Option<String>> = trail.iter().map(|e| e.actor_email.clone()).collect();
    assert_eq!(
        emails,
        vec![Some("admin@a.example".to_owned())],
        "the trail must be exactly workspace A's. An empty vec here is the \
         silent zero — on WS3-1's acceptance criterion it reads as `nobody \
         ever enabled plaintext capture`."
    );
}

/// The WRITE path. `upsert_audited` commits the settings row and the
/// append-only audit row in ONE transaction; under a non-bypassing role both
/// halves need the scope armed, and an unarmed INSERT is REJECTED rather than
/// silently dropped — so this is the loud half of the same defect.
#[sqlx::test]
async fn raw_capture_upsert_audited_survives_a_non_bypassing_role(pool: PgPool) {
    let workspace = seed_workspace(&pool, "Upsert Co").await;

    let low = low_privilege_pool(&pool).await;
    let repo = RawCaptureRepository::new(low);

    let stored = repo
        .upsert_audited(
            workspace,
            RawCaptureSettings {
                enabled: true,
                retention_days: 45,
            },
            None,
            Some("admin@upsert.example"),
        )
        .await
        .expect("an admin turning capture on must not be blocked by RLS");
    assert_eq!(
        stored,
        RawCaptureSettings {
            enabled: true,
            retention_days: 45,
        }
    );

    // Read back through the PRIVILEGED pool: what landed on disk, not what
    // the method claims it wrote.
    let row = sqlx::query(
        "SELECT enabled, retention_days FROM workspace_raw_capture WHERE workspace_id = $1",
    )
    .bind(workspace.0)
    .fetch_one(&pool)
    .await
    .expect("the settings row must exist on disk");
    assert!(row.get::<bool, _>("enabled"));
    assert_eq!(row.get::<i32, _>("retention_days"), 45);

    let audit: Vec<String> =
        sqlx::query_scalar("SELECT actor_email FROM raw_capture_audit WHERE workspace_id = $1")
            .bind(workspace.0)
            .fetch_all(&pool)
            .await
            .expect("the audit row must exist on disk");
    assert_eq!(
        audit,
        vec!["admin@upsert.example".to_owned()],
        "WS3-1's criterion is that enabling capture is itself audited. A \
         settings row with no audit row means a workspace retaining plaintext \
         prompts with nobody on the hook for it."
    );
}

// ===========================================================================
// sidecar_policy_repo — `workspace_sidecar_policy`
// ===========================================================================

/// THE SILENT REVERT. A workspace that chose `degrade_with_alert` must not
/// read back as `block`.
///
/// This direction fails CLOSED, which is why it would not be noticed: nothing
/// leaks, nothing errors. The gateway simply starts 503-ing requests for a
/// workspace that explicitly asked it not to, and the only evidence is a
/// setting that reads correctly through the dashboard's own (superuser) path.
///
/// The NEGATIVE CONTROL is the workspace with no row, which must resolve to
/// the deployment default passed in.
#[sqlx::test]
async fn sidecar_policy_get_effective_survives_a_non_bypassing_role(pool: PgPool) {
    let workspace_a = seed_workspace(&pool, "Sidecar Repo A").await;
    let workspace_b = seed_workspace(&pool, "Sidecar Repo B").await;

    sqlx::query(
        "INSERT INTO workspace_sidecar_policy (workspace_id, sidecar_unavailable)
         VALUES ($1, 'degrade_with_alert')",
    )
    .bind(workspace_a.0)
    .execute(&pool)
    .await
    .expect("workspace A chooses to degrade rather than block");

    assert_eq!(
        rls_flags(&pool, "workspace_sidecar_policy").await,
        (true, true),
        "premise: migration 030 must have armed this table"
    );

    let low = low_privilege_pool(&pool).await;
    let repo = SidecarPolicyRepository::new(low);

    assert_eq!(
        repo.get_effective(workspace_a, SidecarUnavailablePolicy::Block)
            .await
            .expect("reading a workspace's own sidecar policy must not error"),
        SidecarUnavailablePolicy::DegradeWithAlert,
        "workspace A's stored choice must survive the read. Reading `Block` \
         here is the silent revert: the workspace keeps 503-ing on a sidecar \
         outage it explicitly asked to ride out."
    );

    // NEGATIVE CONTROL: no row really does fall through to the deployment
    // default, and to the one passed in rather than a hardcoded one.
    assert_eq!(
        repo.get_effective(workspace_b, SidecarUnavailablePolicy::DegradeWithAlert)
            .await
            .expect("a workspace with no row must resolve, not error"),
        SidecarUnavailablePolicy::DegradeWithAlert,
        "a workspace that never chose must take the deployment default"
    );
}

/// The sidecar policy WRITE path. Already scoped before this workstream — the
/// admin-audit change routed it through `begin_scoped` — so this is a
/// regression guard rather than a fix, and it doubles as the positive control
/// proving the low-privilege pool CAN write these tables when armed.
#[sqlx::test]
async fn sidecar_policy_upsert_survives_a_non_bypassing_role(pool: PgPool) {
    let workspace = seed_workspace(&pool, "Sidecar Upsert Co").await;

    let low = low_privilege_pool(&pool).await;
    let repo = SidecarPolicyRepository::new(low);

    let actor = AdminActor {
        workspace_id: workspace.0,
        user_id: None,
        email: Some("admin@sidecar.example".to_owned()),
        role: Some("admin".to_owned()),
    };
    assert_eq!(
        repo.upsert(
            workspace,
            SidecarUnavailablePolicy::DegradeWithAlert,
            SidecarUnavailablePolicy::Block,
            &actor,
        )
        .await
        .expect("an admin changing the sidecar policy must not be blocked by RLS"),
        SidecarUnavailablePolicy::DegradeWithAlert
    );

    // The P1A audit row lands in the SAME transaction, and `admin_audit` has
    // been under FORCE RLS since migration 028 — so its presence is also the
    // proof that the scope really armed, rather than the write having slipped
    // past an unarmed policy.
    let audited: Vec<String> =
        sqlx::query_scalar("SELECT action::text FROM admin_audit WHERE workspace_id = $1")
            .bind(workspace.0)
            .fetch_all(&pool)
            .await
            .expect("admin_audit read");
    assert_eq!(
        audited,
        vec!["sidecar_policy.updated".to_owned()],
        "the move must leave exactly one administrative record"
    );

    let stored: String = sqlx::query_scalar(
        "SELECT sidecar_unavailable FROM workspace_sidecar_policy WHERE workspace_id = $1",
    )
    .bind(workspace.0)
    .fetch_one(&pool)
    .await
    .expect("the row must exist on disk");
    assert_eq!(stored, "degrade_with_alert");
}
