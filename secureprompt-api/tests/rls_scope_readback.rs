//! What the read-back seam buys, measured on the four repositories P1I
//! converted, through a NON-SUPERUSER, NOBYPASSRLS pool.
//!
//! # The claim this file exists to make checkable
//!
//! `tests/rls_scope_arming_guard.rs` proves that no application path arms
//! `app.current_workspace_id` without verifying it took. That is a claim about
//! SOURCE TEXT. It is worth nothing unless the verification it insists on
//! actually changes an outcome, and unless the twenty-nine converted call sites
//! still read the right tenant's rows afterwards. Those are claims about
//! RUNNING CODE, and they are here.
//!
//! Three things are established, in order:
//!
//!   1. An unarmed read of an armed table is a SILENT ZERO — `Ok(0)`, no
//!      exception — while the same read from an armed transaction on the same
//!      pool returns the row. That pair is what makes zero indistinguishable
//!      from a legitimate answer.
//!   2. `db::scope::scope_is_armed` is what turns that silence into an error,
//!      and it requires the setting to MATCH, not merely to be present.
//!   3. Every converted repository still reads its own workspace and not
//!      another's when the role does not bypass RLS.
//!
//! # Why a non-bypassing role is not optional here
//!
//! `#[sqlx::test]` connects as whatever `DATABASE_URL` names, and on this
//! project's compose stack that is a SUPERUSER. Superusers bypass row-level
//! security unconditionally — `FORCE ROW LEVEL SECURITY` does not stop one — so
//! every assertion below would be true of nothing if it were made through the
//! `#[sqlx::test]` pool. [`low_privilege_pool`] builds a second pool onto the
//! SAME test database with the username replaced, and asserts `rolsuper = false`
//! and `rolbypassrls = false` ON THE WIRE before any test uses it.
//!
//! Building it from the test pool's own connect options, rather than from a
//! literal URL, is what lets this file pass under BOTH `DATABASE_URL`s: as the
//! superuser it is a second, weaker pool, and as `secureprompt_runner` it is the
//! same role twice. Nothing here changes meaning between the two runs.
//!
//! # Two vacuity traps this file is built around
//!
//! ABSENCE. "The foreign workspace sees nothing" is never asserted alone. Every
//! such claim sits next to a POSITIVE CONTROL on the same pool and the same
//! rows — the owning workspace's read, which must see them. Without the pair,
//! `assert!(rows.is_empty())` is satisfied by an empty table, a failed fixture
//! and a broken reader indifferently.
//!
//! FIXTURES. Seeds into armed tables go through a scope-armed transaction, not
//! the bare pool: under the `secureprompt_runner` `DATABASE_URL` the
//! `#[sqlx::test]` pool is itself filtered and a bare-pool insert into
//! `providers` is rejected with `42501`. `workspaces` is not armed
//! (`relforcerowsecurity = false`, measured), so it is seeded directly.

use secureprompt_api::db::api_key_repo::{hash_api_key, ApiKeyRepository};
use secureprompt_api::db::budget_repo::{BudgetBehavior, BudgetRepository};
use secureprompt_api::db::policy_repo::PolicyRepository;
use secureprompt_api::db::provider_repo::ProviderRepository;
use secureprompt_api::db::scope::{scope_is_armed, SCOPE_NOT_ARMED};
use secureprompt_common::errors::ApiError;
use secureprompt_common::types::WorkspaceId;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

/// Same role, password and creation attributes as `tests/rls_repo_scope.rs`,
/// `tests/rls_unscoped_read_is_invisible.rs` and
/// `scripts/ci/create-nonsuperuser-role.sh`. A second set would be a second
/// thing to keep true.
const RLS_ROLE: &str = "secureprompt_runner";
const RLS_PASSWORD: &str = "secureprompt";

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

/// A POOL onto the same `#[sqlx::test]` database as [`RLS_ROLE`], with the
/// role's powerlessness asserted ON THE WIRE.
///
/// A pool and not a connection, for the reason `tests/rls_repo_scope.rs` gives:
/// `set_config(..., true)` is transaction-local and a pool hands successive
/// statements to different connections, so a repository that armed its scope
/// outside its transaction would pass a single-connection test and fail here.
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
        "premise: {who} is a SUPERUSER, so it bypasses RLS and this suite proves nothing"
    );
    assert!(
        !row.get::<bool, _>("rolbypassrls"),
        "premise: {who} has BYPASSRLS, so it bypasses RLS and this suite proves nothing"
    );

    low
}

/// `relforcerowsecurity` for one table, straight out of the catalog.
///
/// Asserted as a PREMISE wherever a table's policy is what a test measures: if
/// the arming were reverted, the low-privilege pool would read everything and
/// each assertion below would pass while measuring nothing.
async fn is_armed(pool: &PgPool, table: &str) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT relforcerowsecurity FROM pg_class WHERE oid = to_regclass($1)",
    )
    .bind(format!("public.{table}"))
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("{table} must exist to be probed: {e}"))
}

/// A transaction with `app.current_workspace_id` armed, hand-rolled.
///
/// Deliberately NOT `db::scope::begin_scoped`: these are FIXTURES, and a
/// fixture that breaks when the code under test breaks cannot show which of the
/// two moved. Same reasoning, and the same shape, as `scoped_tx` in
/// `tests/rls_unscoped_read_is_invisible.rs`.
async fn scoped_tx(pool: &PgPool, workspace_id: Uuid) -> Transaction<'static, Postgres> {
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
        .bind(workspace_id.to_string())
        .execute(&mut *tx)
        .await
        .expect("arm the fixture scope");
    tx
}

/// `workspaces` is not under FORCE ROW LEVEL SECURITY, so this is the one seed
/// that may go through the bare pool under either `DATABASE_URL`.
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

/// One provider, one model, one policy rule, one API key and one budget for
/// `workspace_id` — the five armed tables the converted repositories read.
///
/// Returns `(provider_id, api_key_plaintext)`.
async fn seed_tenant(pool: &PgPool, workspace_id: Uuid, tag: &str) -> (Uuid, String) {
    let provider_id = Uuid::new_v4();
    let plaintext = format!("sp_{tag}_{}", Uuid::new_v4().simple());

    let mut tx = scoped_tx(pool, workspace_id).await;

    sqlx::query(
        "INSERT INTO providers (id, workspace_id, name, provider_type, config)
         VALUES ($1, $2, $3, 'openai', '{}'::jsonb)",
    )
    .bind(provider_id)
    .bind(workspace_id)
    .bind(format!("provider-{tag}"))
    .execute(&mut *tx)
    .await
    .expect("provider seed");

    sqlx::query(
        "INSERT INTO models (id, workspace_id, provider_id, name)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(Uuid::new_v4())
    .bind(workspace_id)
    .bind(provider_id)
    .bind(format!("model-{tag}"))
    .execute(&mut *tx)
    .await
    .expect("model seed");

    sqlx::query(
        "INSERT INTO policy_rules
             (id, workspace_id, name, priority, conditions, action, action_params, enabled)
         VALUES ($1, $2, $3, 10, '[]'::jsonb, 'redact', '{}'::jsonb, true)",
    )
    .bind(Uuid::new_v4())
    .bind(workspace_id)
    .bind(format!("rule-{tag}"))
    .execute(&mut *tx)
    .await
    .expect("policy_rules seed");

    sqlx::query(
        "INSERT INTO api_keys (id, workspace_id, name, key_hash, status)
         VALUES ($1, $2, $3, $4, 'active')",
    )
    .bind(Uuid::new_v4())
    .bind(workspace_id)
    .bind(format!("key-{tag}"))
    .bind(hash_api_key(&plaintext))
    .execute(&mut *tx)
    .await
    .expect("api_keys seed");

    sqlx::query(
        "INSERT INTO workspace_budgets
             (workspace_id, daily_token_limit, monthly_token_limit, behavior)
         VALUES ($1, 1000, 30000, 'block')",
    )
    .bind(workspace_id)
    .execute(&mut *tx)
    .await
    .expect("workspace_budgets seed");

    tx.commit().await.expect("commit tenant seed");
    (provider_id, plaintext)
}

// ===========================================================================
// 1 + 2 — the silent zero, and what records it
// ===========================================================================

/// THE FAILURE THE SEAM EXISTS FOR, and the seam's answer to it, in one test so
/// the two are read together.
///
/// The pair is the point. `assert_eq!(unarmed, 0)` on its own is satisfied by
/// an empty table and by a failed fixture; the ARMED read on the SAME pool
/// against the SAME row is what proves the zero is the policy filtering and not
/// the absence of data.
///
/// The `Ok` matters as much as the `0`. Since migration 033's `NULLIF` sweep an
/// unscoped read RAISES NOTHING on every armed table, including a connection
/// that previously served a scoped transaction — which before 033 would have
/// answered `22P02`. Nothing in the database will ever complain again, so the
/// only thing that can is `scope_is_armed`.
#[sqlx::test]
async fn an_unarmed_read_is_a_silent_zero_and_only_the_seam_records_it(pool: PgPool) {
    let workspace = seed_workspace(&pool, "P1I readback owner").await;
    seed_tenant(&pool, workspace, "own").await;

    // PREMISE: the policy is actually in force. If 001/033 were reverted the
    // low-privilege pool would read everything and every claim below would be
    // measuring an unarmed table.
    assert!(
        is_armed(&pool, "policy_rules").await,
        "premise: policy_rules must be under FORCE ROW LEVEL SECURITY \
         (001_init.sql:78-95) or this test measures nothing"
    );

    let low = low_privilege_pool(&pool).await;

    // POSITIVE CONTROL — the armed read. Must see the seeded rule, or the
    // zero below says nothing about scoping.
    let mut armed = scoped_tx(&low, workspace).await;
    let armed_count: i64 = sqlx::query_scalar("SELECT count(*) FROM policy_rules")
        .fetch_one(&mut *armed)
        .await
        .expect("armed read must not fail");
    assert_eq!(
        armed_count, 1,
        "positive control: an armed transaction on the low-privilege pool must \
         see this workspace's one seeded rule. It saw {armed_count}, so the \
         fixture or the grants are broken and the zero below proves nothing."
    );

    // THE CLAIM — the same read, same pool, scope never armed. Zero rows, and
    // `Ok` rather than an error: this is the shape 29 call sites were exposed
    // to, and it is indistinguishable from "this workspace has no rules".
    let mut unarmed = low.begin().await.expect("begin unarmed");
    let unarmed_count: Result<i64, sqlx::Error> =
        sqlx::query_scalar("SELECT count(*) FROM policy_rules")
            .fetch_one(&mut *unarmed)
            .await;
    let unarmed_count = unarmed_count.expect(
        "an unscoped read of an armed table must SUCCEED and return nothing. \
         If this raised, migration 033's NULLIF sweep has regressed and \
         tests/rls_unscoped_read_is_invisible.rs is the suite that owns it.",
    );
    assert_eq!(
        unarmed_count, 0,
        "an unarmed read must return the empty set; it returned {unarmed_count}"
    );

    // 2 — the seam is what turns that silence into a recorded failure.
    let refused = scope_is_armed(&mut unarmed, workspace).await;
    let Err(ApiError::Internal(message)) = refused else {
        panic!(
            "scope_is_armed on an unarmed transaction must return \
             ApiError::Internal(SCOPE_NOT_ARMED); it returned {refused:?}. \
             Without this the silent zero above has nothing to report it."
        );
    };
    assert_eq!(
        message, SCOPE_NOT_ARMED,
        "the refusal must carry the shared constant, so a caller can match on \
         it without restating the prose"
    );

    // POSITIVE CONTROL for the seam itself: on the armed transaction it must
    // return Ok. A `scope_is_armed` that refused everything would satisfy the
    // assertion above and break every call site.
    scope_is_armed(&mut armed, workspace)
        .await
        .expect("positive control: scope_is_armed must accept a correctly armed transaction");
}

/// The seam requires the setting to MATCH, not merely to be PRESENT.
///
/// A transaction armed to workspace B and then used to read workspace A's rows
/// is the cross-tenant version of the same defect, and `current_setting`
/// returning "something" is not enough to catch it. Under RLS the read itself
/// is silent again — B's scope shows B's rule and none of A's — so the caller
/// gets a plausible answer for the wrong tenant.
#[sqlx::test]
async fn a_scope_armed_to_another_workspace_is_refused_not_accepted(pool: PgPool) {
    let workspace_a = seed_workspace(&pool, "P1I mismatch A").await;
    let workspace_b = seed_workspace(&pool, "P1I mismatch B").await;
    seed_tenant(&pool, workspace_a, "a").await;
    seed_tenant(&pool, workspace_b, "b").await;

    assert!(
        is_armed(&pool, "policy_rules").await,
        "premise: policy_rules must be under FORCE ROW LEVEL SECURITY"
    );

    let low = low_privilege_pool(&pool).await;
    let mut tx = scoped_tx(&low, workspace_b).await;

    // The read is SILENT about the mismatch: it answers with B's row, which is
    // a perfectly well-formed answer to the wrong question.
    let names: Vec<String> = sqlx::query_scalar("SELECT name FROM policy_rules")
        .fetch_all(&mut *tx)
        .await
        .expect("B's scoped read");
    assert_eq!(
        names,
        vec!["rule-b".to_owned()],
        "premise: a transaction armed to B must see exactly B's rule. It saw \
         {names:?}, so the fixture is wrong and the refusal below proves nothing."
    );

    // THE CLAIM: asked whether it is armed for A, the seam says no.
    let refused = scope_is_armed(&mut tx, workspace_a).await;
    assert!(
        matches!(&refused, Err(ApiError::Internal(m)) if m == SCOPE_NOT_ARMED),
        "a transaction armed to another workspace must be refused for this \
         one; got {refused:?}"
    );

    // POSITIVE CONTROL, same transaction: asked about B, it says yes. Without
    // this the assertion above is satisfied by a `scope_is_armed` that refuses
    // unconditionally.
    scope_is_armed(&mut tx, workspace_b)
        .await
        .expect("positive control: the same transaction IS armed for B");
}

// ===========================================================================
// 3 — the converted repositories, under the non-bypassing role
// ===========================================================================

/// Every repository P1I converted, driven through the low-privilege pool.
///
/// This is the regression half of the change: `begin_scoped` binds the GUC from
/// `workspace_id` where the hand-rolled code bound `workspace_id.to_string()`,
/// and if those ever disagreed every read below would come back empty. They do
/// not disagree — `WorkspaceId`'s `Display` delegates to `Uuid`'s — and this is
/// what checks it rather than the reasoning.
///
/// The FOREIGN workspace is the negative control throughout. `list_providers`
/// naming A's provider would also be satisfied by a repository that ignored
/// `workspace_id` entirely, if B's were not asserted absent from the same call.
#[sqlx::test]
async fn the_converted_repositories_read_their_own_workspace_and_not_another(pool: PgPool) {
    let workspace_a = seed_workspace(&pool, "P1I repo A").await;
    let workspace_b = seed_workspace(&pool, "P1I repo B").await;
    let (provider_a, _) = seed_tenant(&pool, workspace_a, "a").await;
    let (_provider_b, _) = seed_tenant(&pool, workspace_b, "b").await;

    for table in [
        "providers",
        "models",
        "policy_rules",
        "api_keys",
        "workspace_budgets",
    ] {
        assert!(
            is_armed(&pool, table).await,
            "premise: {table} must be under FORCE ROW LEVEL SECURITY, or this \
             test is exercising an unfiltered read"
        );
    }

    let low = low_privilege_pool(&pool).await;
    let ws_a = WorkspaceId(workspace_a);

    // ── provider_repo ────────────────────────────────────────────────────
    let providers = ProviderRepository::new(low.clone());
    let listed = providers
        .list_providers(ws_a)
        .await
        .expect("list_providers under a non-bypassing role");
    let names: Vec<&str> = listed.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["provider-a"],
        "list_providers must return exactly this workspace's provider — B's \
         must be absent, or the scoping is not what is doing the work"
    );

    let models = providers
        .list_models_for_provider(ws_a, provider_a)
        .await
        .expect("list_models_for_provider under a non-bypassing role");
    let model_names: Vec<&str> = models.iter().map(|m| m.name.as_str()).collect();
    assert_eq!(model_names, vec!["model-a"]);

    let targets = providers
        .resolve_model_targets(ws_a, "model-b")
        .await
        .expect("resolve_model_targets under a non-bypassing role");
    assert!(
        targets.is_empty(),
        "negative control: workspace A must not resolve workspace B's model \
         name; got {} target(s)",
        targets.len()
    );
    let own = providers
        .resolve_model_targets(ws_a, "model-a")
        .await
        .expect("resolve_model_targets for its own model");
    assert_eq!(
        own.len(),
        1,
        "positive control: A must resolve its OWN model, or the empty result \
         above is just a broken query"
    );

    // ── policy_repo ──────────────────────────────────────────────────────
    // The highest-consequence read in the set: `list_enabled_rules` wraps this
    // and feeds `policy::engine::evaluate`, where an empty list is not an error
    // — it is a workspace with no rules, and nothing gets redacted.
    let policies = PolicyRepository::new(low.clone());
    let rules = policies
        .list_rules(ws_a)
        .await
        .expect("list_rules under a non-bypassing role");
    let rule_names: Vec<&str> = rules.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(rule_names, vec!["rule-a"]);
    assert_eq!(
        policies
            .list_enabled_rules(ws_a)
            .await
            .expect("list_enabled_rules")
            .len(),
        1,
        "the redaction engine's entry point must see the rule too"
    );
    assert!(
        policies
            .priority_in_use(ws_a, 10, None)
            .await
            .expect("priority_in_use"),
        "priority 10 is taken in A by the seeded rule"
    );

    // ── api_key_repo ─────────────────────────────────────────────────────
    let keys = ApiKeyRepository::new(low.clone());
    let listed_keys = keys
        .list_api_keys(ws_a)
        .await
        .expect("list_api_keys under a non-bypassing role");
    let key_names: Vec<&str> = listed_keys.iter().map(|k| k.name.as_str()).collect();
    assert_eq!(key_names, vec!["key-a"]);

    // ── budget_repo ──────────────────────────────────────────────────────
    // "No row" here means NO SPEND LIMIT, so a silent zero switches enforcement
    // OFF. A must read its `block`; a workspace with no budget must read None,
    // which is the negative control that keeps `Some(block)` from being
    // satisfied by a repository that returns the first row it finds.
    let budgets = BudgetRepository::new(low.clone());
    let budget = budgets
        .get(workspace_a)
        .await
        .expect("budget get under a non-bypassing role")
        .expect("workspace A configured a budget");
    assert_eq!(budget.workspace_id, workspace_a);
    assert_eq!(budget.behavior, BudgetBehavior::Block);
    assert_eq!(budget.daily_token_limit, Some(1000));

    let unbudgeted = seed_workspace(&pool, "P1I repo C, no budget").await;
    assert!(
        budgets
            .get(unbudgeted)
            .await
            .expect("budget get for an unbudgeted workspace")
            .is_none(),
        "negative control: a workspace with no budget row must read as None"
    );
}

/// `authenticate_api_key` is the one converted read whose ONLY tenancy filter
/// is the policy: its `WHERE` names `key_hash` and nothing else, which is why
/// the method walks the workspaces and lets RLS decide.
///
/// So this is the site where an unarmed scope does not degrade an answer, it
/// inverts one — a valid key is rejected with 401 and nothing is logged. Under
/// the non-bypassing role the loop must still resolve each key to ITS OWN
/// workspace, and a hash nobody holds to `None`.
#[sqlx::test]
async fn authenticate_api_key_resolves_the_right_tenant_with_no_workspace_predicate(pool: PgPool) {
    let workspace_a = seed_workspace(&pool, "P1I auth A").await;
    let workspace_b = seed_workspace(&pool, "P1I auth B").await;
    let (_, key_a) = seed_tenant(&pool, workspace_a, "a").await;
    let (_, key_b) = seed_tenant(&pool, workspace_b, "b").await;

    assert!(
        is_armed(&pool, "api_keys").await,
        "premise: api_keys must be under FORCE ROW LEVEL SECURITY — this \
         method has no workspace predicate of its own, so an unarmed table \
         would make the test pass for the wrong reason"
    );

    let low = low_privilege_pool(&pool).await;
    let keys = ApiKeyRepository::new(low);

    let resolved_a = keys
        .authenticate_api_key(&key_a)
        .await
        .expect("authenticate under a non-bypassing role")
        .expect("A's key must authenticate");
    assert_eq!(
        resolved_a.workspace_id.0, workspace_a,
        "A's key must resolve to A"
    );
    assert_eq!(resolved_a.name, "key-a");

    // The second half is what makes the first non-vacuous: a loop that always
    // returned the first workspace would satisfy A and fail here.
    let resolved_b = keys
        .authenticate_api_key(&key_b)
        .await
        .expect("authenticate under a non-bypassing role")
        .expect("B's key must authenticate");
    assert_eq!(
        resolved_b.workspace_id.0, workspace_b,
        "B's key must resolve to B, not to whichever workspace the loop reached first"
    );
    assert_eq!(resolved_b.name, "key-b");

    // NEGATIVE CONTROL: a well-formed key nobody holds resolves to nothing,
    // rather than to whatever the last iteration left behind.
    assert!(
        keys.authenticate_api_key("sp_this_key_was_never_issued")
            .await
            .expect("authenticate an unknown key")
            .is_none(),
        "an unissued key must not authenticate"
    );
}
