//! The class neither existing guard can see: a query that is perfectly ARMED
//! and simply forgot to FILTER.
//!
//! # What the two existing guards each answer, and what neither does
//!
//! `tests/rls_call_site_guard.rs` asks "is this statement on an armed
//! transaction?". `tests/rls_scope_readback.rs` asks "did anyone verify the
//! arming took?". Both are satisfied by
//!
//! ```ignore
//! let mut tx = begin_scoped(&self.pool, workspace_id.0).await?;   // armed
//! sqlx::query("SELECT ... FROM models WHERE provider_id = $1")    // unfiltered
//! ```
//!
//! — a function that ACCEPTS a `workspace_id`, arms the scope with it, and then
//! never mentions it in the SQL it issues. That is a missing predicate, not a
//! missing arming, and it is invisible to both.
//!
//! # Why the bug hides behind the fix
//!
//! Once the scope is armed, the `workspace_isolation` policy SUPPLIES the
//! missing predicate. So on a role that does not bypass RLS these functions
//! read correctly — the defect is masked by exactly the work that armed them.
//! It reappears the moment the same query runs where RLS does not reach:
//!
//!   * a SUPERUSER connection — **which is how this product runs today**. The
//!     compose role `secureprompt` is created SUPERUSER by the postgres image
//!     and bypasses every policy unconditionally;
//!   * a table no policy covers — `users`, `workspaces`, `token_vault_entries`,
//!     `user_backup_codes`, `license_activation` and `license_freshness` are
//!     all `relforcerowsecurity = false` after migration 033 (measured);
//!   * a JOIN whose predicate lands on only one of the joined tables.
//!
//! # Why every test here BRANCHES on the connected role
//!
//! `#[sqlx::test]` connects as whatever `DATABASE_URL` names, and this repo is
//! run under two: the compose SUPERUSER in the `test:` CI job, and
//! `secureprompt_runner` (NOSUPERUSER, NOBYPASSRLS) in `test:rls-nonsuperuser`.
//! The SAME call has two different correct answers in those two worlds, and
//! both are facts worth pinning:
//!
//!   * bypassing role — the missing predicate is VISIBLE. The foreign rows come
//!     back. This is the arm that was RED before the fix.
//!   * non-bypassing role — the missing predicate is MASKED. The foreign rows
//!     do not come back, and that is the finding's second half stated as a
//!     test rather than as prose.
//!
//! [`world`] probes `pg_roles` ON THE WIRE and every test prints which arm it
//! took, so a reader of the log knows which world the run described. Neither
//! arm is an absence-assertion on its own: each sits beside a POSITIVE CONTROL
//! on the same pool and the same rows — the OWNING workspace's read, which must
//! see them — because `assert!(rows.is_empty())` is satisfied by an empty
//! table, a failed fixture and a broken reader indifferently.

use secureprompt_api::db::admin_audit_repo::AdminActor;
use secureprompt_api::db::api_key_repo::{hash_api_key, ApiKeyRepository};
use secureprompt_api::db::provider_repo::ProviderRepository;
use secureprompt_common::types::WorkspaceId;
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

// ===========================================================================
// Which world is this run in?
// ===========================================================================

/// Whether the connected role can see past a `workspace_isolation` policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum World {
    /// SUPERUSER or BYPASSRLS. No policy binds this connection, so a missing
    /// `WHERE workspace_id = $n` is the ONLY thing standing between a caller
    /// and another tenant's rows. This is the compose default and therefore
    /// the deployed reality.
    RlsDoesNotBind,
    /// Neither. `models`/`providers` policies filter every statement, so a
    /// missing predicate is silently supplied by Postgres.
    RlsBinds,
}

/// Probe the connected role's actual privileges, from `pg_roles`, on the wire.
///
/// Not inferred from `DATABASE_URL` and not passed in: the whole point of this
/// file is that the answer changes with the role, so the role is measured.
async fn world(pool: &PgPool) -> World {
    let row = sqlx::query(
        "SELECT current_user::text AS who, rolsuper, rolbypassrls
         FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(pool)
    .await
    .expect("identity probe: the connected role must be readable from pg_roles");

    let who: String = row.get("who");
    let rolsuper: bool = row.get("rolsuper");
    let rolbypassrls: bool = row.get("rolbypassrls");

    let world = if rolsuper || rolbypassrls {
        World::RlsDoesNotBind
    } else {
        World::RlsBinds
    };
    println!(
        "  [world] connected as {who}: rolsuper={rolsuper} rolbypassrls={rolbypassrls} -> {world:?}"
    );
    world
}

/// `relforcerowsecurity` for one table, straight out of the catalog.
///
/// Asserted as a PREMISE wherever a test's meaning depends on whether a policy
/// covers the table: if `models` were disarmed, the `RlsBinds` arm below would
/// be measuring nothing.
async fn is_armed(pool: &PgPool, table: &str) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT relforcerowsecurity FROM pg_class WHERE oid = to_regclass($1)",
    )
    .bind(format!("public.{table}"))
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("{table} must exist to be probed: {e}"))
}

// ===========================================================================
// Fixtures
// ===========================================================================

/// A transaction with `app.current_workspace_id` armed, hand-rolled.
///
/// Deliberately NOT `db::scope::begin_scoped`: these are FIXTURES, and a
/// fixture that breaks when the code under test breaks cannot show which of
/// the two moved. Same shape and the same reason as `scoped_tx` in
/// `tests/rls_scope_readback.rs`.
async fn scoped_tx(pool: &PgPool, workspace_id: Uuid) -> Transaction<'static, Postgres> {
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
        .bind(workspace_id.to_string())
        .execute(&mut *tx)
        .await
        .expect("arm the fixture scope");
    tx
}

/// `workspaces` is not under FORCE ROW LEVEL SECURITY (measured — see the
/// header), so this is the one seed that may go through the bare pool under
/// either `DATABASE_URL`.
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

/// One provider carrying a MARKER credential, plus one model on it.
///
/// The marker is what makes the join test's leak legible: a credential is the
/// thing whose disclosure actually costs money, so the assertion names the
/// string rather than a row count. Returns the provider's id.
async fn seed_provider_with_model(
    pool: &PgPool,
    workspace_id: Uuid,
    tag: &str,
    model_name: &str,
) -> Uuid {
    let provider_id = Uuid::new_v4();
    let mut tx = scoped_tx(pool, workspace_id).await;

    sqlx::query(
        "INSERT INTO providers (id, workspace_id, name, provider_type, encrypted_credential, config)
         VALUES ($1, $2, $3, 'openai', $4, '{}'::jsonb)",
    )
    .bind(provider_id)
    .bind(workspace_id)
    .bind(format!("provider-{tag}"))
    .bind(format!("CREDENTIAL-OF-{tag}"))
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
    .bind(model_name)
    .execute(&mut *tx)
    .await
    .expect("model seed");

    tx.commit().await.expect("fixture commit");
    provider_id
}

/// Mark one model excluded, through the owning workspace's own armed scope.
async fn exclude_model(pool: &PgPool, workspace_id: Uuid, name: &str) {
    let mut tx = scoped_tx(pool, workspace_id).await;
    let affected =
        sqlx::query("UPDATE models SET excluded = TRUE WHERE workspace_id = $1 AND name = $2")
            .bind(workspace_id)
            .bind(name)
            .execute(&mut *tx)
            .await
            .expect("exclusion seed")
            .rows_affected();
    tx.commit().await.expect("exclusion commit");
    assert_eq!(
        affected, 1,
        "premise: the exclusion fixture must have marked exactly one row, or \
         the test below reads an empty exclusion list and proves nothing"
    );
}

// ===========================================================================
// 1 — `list_models` takes a workspace and never mentions it
// ===========================================================================

/// `ProviderRepository::list_models(workspace_id)` issues
/// `SELECT ... FROM models WHERE excluded = FALSE` — no tenancy predicate at
/// all. The parameter is spent entirely on `begin_scoped`.
///
/// It has NO CALLERS anywhere in the repository (`grep -rn '.list_models('`
/// over every `.rs` outside `target/` returned nothing), so nothing is broken
/// by it today. It is listed and fixed because the next caller inherits a
/// signature that promises a scope the query does not apply.
#[sqlx::test]
async fn list_models_applies_the_workspace_it_was_given(pool: PgPool) {
    let world = world(&pool).await;
    assert!(
        is_armed(&pool, "models").await,
        "premise: `models` must be under FORCE ROW LEVEL SECURITY, or the \
         RlsBinds arm below measures nothing"
    );

    let workspace_a = seed_workspace(&pool, "missing-predicate A").await;
    let workspace_b = seed_workspace(&pool, "missing-predicate B").await;
    seed_provider_with_model(&pool, workspace_a, "a", "model-a").await;
    seed_provider_with_model(&pool, workspace_b, "b", "model-b").await;

    let repo = ProviderRepository::new(pool.clone());
    let listed = repo
        .list_models(WorkspaceId(workspace_a))
        .await
        .expect("list_models");
    let names: Vec<&str> = listed.iter().map(|m| m.name.as_str()).collect();

    // POSITIVE CONTROL, asserted FIRST and in both worlds: A's own model must
    // be there. Without it, the absence claim below is satisfied by a query
    // that returns nothing at all.
    assert!(
        names.contains(&"model-a"),
        "positive control: workspace A must see its OWN model; got {names:?}"
    );

    match world {
        World::RlsDoesNotBind => assert!(
            !names.contains(&"model-b"),
            "list_models(A) returned workspace B's model on a role that does \
             not bypass RLS filtering. The SQL is `WHERE excluded = FALSE` — \
             the `workspace_id` argument is never applied — so the only reason \
             this ever looks right is a policy the compose role bypasses. \
             Got {names:?}"
        ),
        World::RlsBinds => assert!(
            !names.contains(&"model-b"),
            "even with the `workspace_isolation` policy binding this \
             connection, B's model came back. That is a broken policy, not a \
             missing predicate. Got {names:?}"
        ),
    }
    assert_eq!(
        names,
        vec!["model-a"],
        "list_models(A) must be exactly A's models"
    );
}

// ===========================================================================
// 2 — `list_models_for_provider` filters on `provider_id` alone
// ===========================================================================

/// The REACHABLE one. `GET /v1/providers/{id}/models`
/// (`dashboard::providers::list_provider_models`) takes `provider_id` straight
/// out of the URL path and hands it to this function with the caller's own
/// `ctx.workspace_id`. Unlike its siblings `sync_provider_models` and
/// `test_connection_stored` — which both look the provider up via
/// `list_providers(ctx.workspace_id)` and 404 when it is not there — that
/// handler performs NO ownership check, so the only tenancy boundary on the
/// path is the one this query is missing.
#[sqlx::test]
async fn list_models_for_provider_will_not_serve_a_foreign_providers_models(pool: PgPool) {
    let world = world(&pool).await;
    assert!(is_armed(&pool, "models").await, "premise: `models` armed");

    let workspace_a = seed_workspace(&pool, "foreign-provider A").await;
    let workspace_b = seed_workspace(&pool, "foreign-provider B").await;
    let provider_a = seed_provider_with_model(&pool, workspace_a, "a", "model-a").await;
    let provider_b = seed_provider_with_model(&pool, workspace_b, "b", "model-b").await;

    let repo = ProviderRepository::new(pool.clone());

    // POSITIVE CONTROL first: A asking about its OWN provider must see its own
    // model, in BOTH worlds. This is what makes the emptiness below mean
    // "filtered" rather than "the reader is broken".
    let own = repo
        .list_models_for_provider(WorkspaceId(workspace_a), provider_a)
        .await
        .expect("list_models_for_provider, own provider");
    let own_names: Vec<&str> = own.iter().map(|m| m.name.as_str()).collect();
    assert_eq!(
        own_names,
        vec!["model-a"],
        "positive control: A must see its own provider's model"
    );

    // The route's actual attack shape: A's JWT, B's provider id from the URL.
    let foreign = repo
        .list_models_for_provider(WorkspaceId(workspace_a), provider_b)
        .await
        .expect("list_models_for_provider, foreign provider");
    let foreign_names: Vec<&str> = foreign.iter().map(|m| m.name.as_str()).collect();

    match world {
        World::RlsDoesNotBind => assert!(
            foreign_names.is_empty(),
            "workspace A, holding only its own JWT, read workspace B's model \
             list by naming B's provider id in the URL of \
             `GET /v1/providers/{{id}}/models`. The SQL filters on \
             `provider_id` alone. Got {foreign_names:?}"
        ),
        World::RlsBinds => assert!(
            foreign_names.is_empty(),
            "the `workspace_isolation` policy is binding and B's model still \
             came back: {foreign_names:?}"
        ),
    }
}

// ===========================================================================
// 3 — `list_excluded_model_names_for_provider`, same shape
// ===========================================================================

/// The third sibling. Its ONLY caller, `providers::persist_synced_models`, is
/// reached from `sync_provider_models`, which DOES validate the provider
/// against `list_providers(ctx.workspace_id)` before calling — so tenancy is
/// enforced elsewhere on today's single path, and that elsewhere is named here
/// rather than assumed. The predicate is added anyway: the function is `pub`,
/// takes a `workspace_id`, and the next caller will not know that its safety
/// lives in a handler two files away.
#[sqlx::test]
async fn list_excluded_models_will_not_serve_a_foreign_providers_exclusions(pool: PgPool) {
    let world = world(&pool).await;
    assert!(is_armed(&pool, "models").await, "premise: `models` armed");

    let workspace_a = seed_workspace(&pool, "excluded A").await;
    let workspace_b = seed_workspace(&pool, "excluded B").await;
    let provider_a = seed_provider_with_model(&pool, workspace_a, "a", "model-a").await;
    let provider_b = seed_provider_with_model(&pool, workspace_b, "b", "model-b").await;
    exclude_model(&pool, workspace_a, "model-a").await;
    exclude_model(&pool, workspace_b, "model-b").await;

    let repo = ProviderRepository::new(pool.clone());

    let own = repo
        .list_excluded_model_names_for_provider(WorkspaceId(workspace_a), provider_a)
        .await
        .expect("own exclusions");
    assert_eq!(
        own,
        vec!["model-a".to_owned()],
        "positive control: A must see its own exclusion list, or the emptiness \
         asserted below is just a query that returns nothing"
    );

    let foreign = repo
        .list_excluded_model_names_for_provider(WorkspaceId(workspace_a), provider_b)
        .await
        .expect("foreign exclusions");

    match world {
        World::RlsDoesNotBind => assert!(
            foreign.is_empty(),
            "workspace A read workspace B's curated model-exclusion list — \
             which names the models B's administrator deliberately removed, \
             and is therefore a statement about B's configuration. The SQL \
             filters on `provider_id` alone. Got {foreign:?}"
        ),
        World::RlsBinds => assert!(
            foreign.is_empty(),
            "policy binding and B's exclusions still returned: {foreign:?}"
        ),
    }
}

// ===========================================================================
// 4 — the JOIN half: a predicate on one table only
// ===========================================================================

/// `resolve_model_targets` DOES filter — `WHERE models.workspace_id = $1` — and
/// is therefore invisible to any check that looks for a tenancy predicate in
/// the statement. The predicate lands on ONE of the two joined tables:
///
/// ```sql
/// FROM models INNER JOIN providers ON providers.id = models.provider_id
/// WHERE models.workspace_id = $1 AND models.name = $2
/// ```
///
/// so `providers.encrypted_credential` — the row this function exists to
/// fetch, and the one whose disclosure costs real money — is returned for
/// WHATEVER provider the model points at, in whatever workspace.
///
/// The invariant that keeps that from happening today is enforced in
/// application code only: `create_model` checks
/// `SELECT 1 FROM providers WHERE id = $1 AND workspace_id = $2` first, and
/// `persist_synced_models` reaches the database through it. There is NO
/// database constraint behind that check — `001_init.sql:41` declares
/// `provider_id UUID NOT NULL REFERENCES providers(id)`, a single-column FK
/// that says nothing about workspaces. The house pattern is
/// `audit_export::get_export_page`, whose join carries the predicate on BOTH
/// tables with the comment "the join keeps the tenancy predicate on BOTH
/// tables rather than trusting the FK".
///
/// This test writes the cross-pointing row directly, which is exactly what the
/// missing constraint permits.
#[sqlx::test]
async fn resolve_model_targets_keeps_the_tenancy_predicate_on_both_joined_tables(pool: PgPool) {
    let world = world(&pool).await;
    assert!(is_armed(&pool, "models").await, "premise: `models` armed");
    assert!(
        is_armed(&pool, "providers").await,
        "premise: `providers` armed"
    );

    let workspace_a = seed_workspace(&pool, "join A").await;
    let workspace_b = seed_workspace(&pool, "join B").await;
    let provider_a = seed_provider_with_model(&pool, workspace_a, "a", "own-model").await;
    let provider_b = seed_provider_with_model(&pool, workspace_b, "b", "model-b").await;

    // PREMISE: nothing in the schema forbids the row this test is about to
    // write. If a future migration adds the composite FK, this insert starts
    // failing and the test must be re-read rather than deleted.
    let composite_fk: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_constraint
         WHERE conrelid = 'models'::regclass AND contype = 'f'
           AND array_length(conkey, 1) > 1",
    )
    .fetch_one(&pool)
    .await
    .expect("constraint probe");
    assert_eq!(
        composite_fk, 0,
        "premise: `models` has a multi-column foreign key now, so the \
         cross-workspace row below may be impossible and this test's shape is \
         stale"
    );

    // A model row OWNED by A that points at B's provider. `create_model`
    // refuses to make this; the database does not.
    let mut tx = scoped_tx(&pool, workspace_a).await;
    sqlx::query(
        "INSERT INTO models (id, workspace_id, provider_id, name)
         VALUES ($1, $2, $3, 'crossed')",
    )
    .bind(Uuid::new_v4())
    .bind(workspace_a)
    .bind(provider_b)
    .execute(&mut *tx)
    .await
    .expect("cross-pointing model seed");
    tx.commit().await.expect("cross seed commit");

    let repo = ProviderRepository::new(pool.clone());

    // POSITIVE CONTROL, both worlds: the ordinary path still resolves.
    let own = repo
        .resolve_model_targets(WorkspaceId(workspace_a), "own-model")
        .await
        .expect("resolve own model");
    assert_eq!(
        own.len(),
        1,
        "positive control: A must still resolve its own model, or the fix has \
         broken the routing path this function exists to serve"
    );
    assert_eq!(own[0].provider_id.0, provider_a);
    assert_eq!(
        own[0].encrypted_credential.as_deref(),
        Some("CREDENTIAL-OF-a"),
        "positive control: the resolved target must still carry its OWN \
         provider's credential"
    );

    let crossed = repo
        .resolve_model_targets(WorkspaceId(workspace_a), "crossed")
        .await
        .expect("resolve crossed model");
    let leaked: Vec<&str> = crossed
        .iter()
        .filter_map(|t| t.encrypted_credential.as_deref())
        .collect();

    match world {
        World::RlsDoesNotBind => assert!(
            !leaked.contains(&"CREDENTIAL-OF-b"),
            "the join handed workspace A workspace B's stored provider \
             credential. `WHERE models.workspace_id = $1` filters the LEFT \
             table only; nothing constrains `providers.workspace_id`. Got \
             {leaked:?}"
        ),
        World::RlsBinds => assert!(
            !leaked.contains(&"CREDENTIAL-OF-b"),
            "the `providers` policy is binding and B's credential still came \
             through the join: {leaked:?}"
        ),
    }
}

// ===========================================================================
// 5 — the one statement left unfixed, and the reason, EXECUTED
// ===========================================================================

/// `create_model`'s revive branch issues `UPDATE models SET excluded = FALSE
/// WHERE id = $1` — no tenancy predicate, and the one entry on
/// `tests/tenancy_predicate_guard.rs`'s allowlist.
///
/// The reason given there is that `id` cannot name a foreign row: it comes
/// from a SELECT in the SAME transaction that is itself filtered on
/// `workspace_id`, and the method refuses before reaching either statement
/// unless the provider belongs to the caller's workspace. That is a claim
/// about running code, so it is made here rather than in the allowlist's
/// prose. Fourteen comments asserting guarantees have proved false on this
/// branch; an allowlist reason nobody executed is how the fifteenth happens.
///
/// Two separate refusals are checked, because they fail differently: naming a
/// foreign PROVIDER, and naming a foreign provider's excluded MODEL by name.
#[sqlx::test]
async fn create_model_cannot_revive_a_foreign_workspaces_excluded_model(pool: PgPool) {
    let world = world(&pool).await;

    let workspace_a = seed_workspace(&pool, "revive A").await;
    let workspace_b = seed_workspace(&pool, "revive B").await;
    let provider_a = seed_provider_with_model(&pool, workspace_a, "a", "model-a").await;
    let provider_b = seed_provider_with_model(&pool, workspace_b, "b", "model-b").await;
    exclude_model(&pool, workspace_b, "model-b").await;

    let repo = ProviderRepository::new(pool.clone());

    // POSITIVE CONTROL: the revive branch WORKS for the owning workspace, or
    // the refusals below are satisfied by a method that refuses everything.
    exclude_model(&pool, workspace_a, "model-a").await;
    repo.create_model(WorkspaceId(workspace_a), provider_a, "model-a")
        .await
        .expect("positive control: A must be able to revive its OWN excluded model");
    let revived = repo
        .list_models_for_provider(WorkspaceId(workspace_a), provider_a)
        .await
        .expect("A's models after revive");
    assert_eq!(
        revived.iter().map(|m| m.name.as_str()).collect::<Vec<_>>(),
        vec!["model-a"],
        "positive control: the revive must actually clear `excluded`"
    );

    // The refusal: A names B's provider. `create_model` validates the provider
    // against `WHERE id = $1 AND workspace_id = $2` before anything else.
    let refused = repo
        .create_model(WorkspaceId(workspace_a), provider_b, "model-b")
        .await;
    assert!(
        refused.is_err(),
        "create_model accepted a provider id belonging to another workspace; \
         the `UPDATE ... WHERE id = $1` below it would then be reachable with \
         a foreign row's id, and the guard's allowlist entry is false. World: \
         {world:?}"
    );

    // And B's row is untouched — the refusal is not merely a returned error.
    let still_excluded: bool = sqlx::query_scalar(
        "SELECT excluded FROM models WHERE workspace_id = $1 AND name = 'model-b'",
    )
    .bind(workspace_b)
    .fetch_one(&pool)
    .await
    .expect("B's row must still be readable to be checked");
    assert!(
        still_excluded,
        "workspace B's excluded model was revived by a call made from \
         workspace A"
    );
}

/// `ApiKeyRepository::rotate`'s second write is
/// `UPDATE api_keys SET status = 'rotating', ... WHERE id = $3` — no tenancy
/// predicate, and the second entry on `tests/tenancy_predicate_guard.rs`'s
/// allowlist.
///
/// The reason given there is that `key_id` cannot name a foreign row by the
/// time that statement runs: the method opens with
/// `SELECT ... WHERE id = $1 AND workspace_id = $2 AND status IN ('active',
/// 'rotating') FOR UPDATE` and returns `NotFound` when it matches nothing, so
/// the row is both validated and LOCKED in the same transaction. That is a
/// claim about running code, so it is made here.
///
/// Rotation is the highest-consequence write on this table — it issues a
/// credential and puts the old one on a grace clock — so the check is that A
/// cannot start one on B's key, and that B's key is untouched afterwards.
#[sqlx::test]
async fn rotate_refuses_a_foreign_workspaces_api_key(pool: PgPool) {
    let world = world(&pool).await;
    assert!(
        is_armed(&pool, "api_keys").await,
        "premise: `api_keys` armed"
    );

    let workspace_a = seed_workspace(&pool, "rotate A").await;
    let workspace_b = seed_workspace(&pool, "rotate B").await;
    let key_a = seed_api_key(&pool, workspace_a, "key-a").await;
    let key_b = seed_api_key(&pool, workspace_b, "key-b").await;

    let repo = ApiKeyRepository::new(pool.clone());
    let actor = AdminActor {
        workspace_id: workspace_a,
        user_id: None,
        email: None,
        role: Some("admin".to_owned()),
    };

    // POSITIVE CONTROL: rotation WORKS for A's own key, or the refusal below
    // is satisfied by a method that refuses everything. A real rotation also
    // INSERTS a successor row, which is what makes the row count in B a
    // meaningful check rather than a count that never moves.
    assert_eq!(
        keys_in(&pool, workspace_a).await,
        1,
        "premise: A starts at 1 key"
    );
    repo.rotate(WorkspaceId(workspace_a), key_a, &actor)
        .await
        .expect("positive control: A must be able to rotate its OWN key");
    assert_eq!(
        key_status(&pool, workspace_a, key_a).await,
        "rotating",
        "positive control: A's own key must actually reach 'rotating'"
    );
    assert_eq!(
        keys_in(&pool, workspace_a).await,
        2,
        "positive control: a real rotation inserts the successor row, so the \
         count in B below can distinguish 'no insert happened' from 'inserts \
         never happen'"
    );

    let refused = repo.rotate(WorkspaceId(workspace_a), key_b, &actor).await;
    assert!(
        refused.is_err(),
        "rotate accepted an api-key id belonging to another workspace. The \
         `UPDATE ... WHERE id = $3` beneath the FOR UPDATE gate would then be \
         reachable with a foreign row's id, and the guard's allowlist entry is \
         false. World: {world:?}"
    );

    // And B's key is untouched — the refusal is not merely a returned error.
    assert_eq!(
        key_status(&pool, workspace_b, key_b).await,
        "active",
        "workspace B's api key was put on a rotation clock by a call made \
         from workspace A"
    );

    // The sibling statement the guard's INSERT rule does NOT flag:
    // `INSERT INTO api_keys ... SELECT $1, workspace_id, ... FROM api_keys
    // WHERE id = $3`. Its inner SELECT is unfiltered and rests on the same FOR
    // UPDATE gate, so the allowlist entry claims a refused rotation mints no
    // successor. This is that claim, executed.
    assert_eq!(
        keys_in(&pool, workspace_b).await,
        1,
        "the refused rotation still minted a successor credential in workspace \
         B — the INSERT's `SELECT ... FROM api_keys WHERE id = $3` copied a \
         foreign row"
    );
}

/// One `active` api key, seeded through the owning workspace's armed scope.
async fn seed_api_key(pool: &PgPool, workspace_id: Uuid, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    let mut tx = scoped_tx(pool, workspace_id).await;
    sqlx::query(
        "INSERT INTO api_keys (id, workspace_id, name, key_hash, created_at, status)
         VALUES ($1, $2, $3, $4, NOW(), 'active')",
    )
    .bind(id)
    .bind(workspace_id)
    .bind(name)
    .bind(hash_api_key(&format!("sp_{}", Uuid::new_v4().simple())))
    .execute(&mut *tx)
    .await
    .expect("api key seed");
    tx.commit().await.expect("api key seed commit");
    id
}

/// One key's `status`, read through the OWNING workspace's armed scope so the
/// read works under either `DATABASE_URL`.
async fn key_status(pool: &PgPool, workspace_id: Uuid, key_id: Uuid) -> String {
    let mut tx = scoped_tx(pool, workspace_id).await;
    let status: String =
        sqlx::query_scalar("SELECT status FROM api_keys WHERE id = $1 AND workspace_id = $2")
            .bind(key_id)
            .bind(workspace_id)
            .fetch_one(&mut *tx)
            .await
            .expect("the key must be readable from its own workspace to be checked");
    tx.commit().await.expect("status read commit");
    status
}

/// How many api-key rows one workspace holds, read through its OWN armed
/// scope so the count works under either `DATABASE_URL`.
async fn keys_in(pool: &PgPool, workspace_id: Uuid) -> i64 {
    let mut tx = scoped_tx(pool, workspace_id).await;
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM api_keys WHERE workspace_id = $1")
        .bind(workspace_id)
        .fetch_one(&mut *tx)
        .await
        .expect("key count");
    tx.commit().await.expect("count commit");
    n
}
