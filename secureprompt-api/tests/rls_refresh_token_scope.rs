//! `RefreshTokenRepository` executed through a NON-SUPERUSER, NOBYPASSRLS
//! connection pool — the three session-lifecycle paths that touch
//! `refresh_tokens`, which has been under FORCE ROW LEVEL SECURITY since
//! migration 002.
//!
//! # Why these three and not the whole repository
//!
//! `tests/rls_call_site_guard.rs` lists two statements in
//! `src/db/refresh_token_repo.rs` that run on a BARE POOL with no
//! `app.current_workspace_id` armed: `rotate`'s pre-lookup and
//! `find_active_by_hash`. Both are cross-tenant BY NECESSITY — a refresh token
//! is an opaque random string and does not name its workspace, so neither
//! caller can know which scope to arm until it has already found the row.
//!
//! Today the deployment connects as a SUPERUSER, superusers bypass RLS
//! unconditionally, and both read correctly. Under the role-split on this
//! project's backlog they return the EMPTY SET without erroring.
//!
//! `revoke_all_for_user` is the third path here and is NOT on that list. It is
//! included because it is what `POST /v1/auth/logout` actually calls, and the
//! guard's reason string attributes the logout revoke to `find_active_by_hash`
//! instead. That attribution is wrong and the difference is the whole severity
//! of the entry, so it is measured rather than argued.
//!
//! # The absence-assertion rule this suite obeys
//!
//! Every claim about what did or did not land on disk is read back through the
//! PRIVILEGED `#[sqlx::test]` pool, never through the low-privilege one. A
//! `SELECT` issued by the low-privilege role with no scope armed returns zero
//! rows whether the write happened or not, so "I saw nothing" from that pool
//! cannot distinguish "nothing happened" from "I cannot see it".
//!
//! Fixtures go through the privileged pool for the same reason
//! `tests/rls_repo_scope.rs` does: running the whole application as
//! `secureprompt_runner` still fails in `workspace_repo`'s default-rule
//! seeding, and that is a separate backlog item. Only the repository call
//! under test uses the low-privilege pool.

use chrono::{Duration, Utc};
use secureprompt_api::db::refresh_token_repo::{
    hash_refresh_token, RefreshTokenRepository, RotationOutcome,
};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Connection, PgConnection, PgPool, Row};
use uuid::Uuid;

/// Same role, password and creation attributes as `tests/rls_repo_scope.rs`,
/// `tests/migration_017_023_rls.rs` and
/// `scripts/ci/create-nonsuperuser-role.sh`. A second set would be a second
/// thing to keep true.
const RLS_ROLE: &str = "secureprompt_runner";
const RLS_PASSWORD: &str = "secureprompt";

/// One workspace, one user in it, and one ACTIVE refresh row.
struct Session {
    workspace_id: Uuid,
    user_id: Uuid,
    token_id: Uuid,
    raw: String,
}

async fn seed_session(pool: &PgPool, label: &str) -> Session {
    let workspace_id = Uuid::new_v4();
    sqlx::query("INSERT INTO workspaces (id, name) VALUES ($1, $2)")
        .bind(workspace_id)
        .bind(format!("Refresh Scope {label}"))
        .execute(pool)
        .await
        .expect("workspace insert");

    let user_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, workspace_id, email, password_hash, role)
         VALUES ($1, $2, $3, 'x', 'admin')",
    )
    .bind(user_id)
    .bind(workspace_id)
    .bind(format!("{}@refresh-scope.example", label.to_lowercase()))
    .execute(pool)
    .await
    .expect("user insert");

    let token_id = Uuid::new_v4();
    let raw = format!("rt-{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO refresh_tokens
             (id, user_id, workspace_id, token_hash, expires_at, created_at, session_id)
         VALUES ($1, $2, $3, $4, NOW() + INTERVAL '1 hour', NOW(), gen_random_uuid())",
    )
    .bind(token_id)
    .bind(user_id)
    .bind(workspace_id)
    .bind(hash_refresh_token(&raw))
    .execute(pool)
    .await
    .expect("refresh row insert");

    Session {
        workspace_id,
        user_id,
        token_id,
        raw,
    }
}

/// `revoked_at IS NOT NULL` for one row, read through the PRIVILEGED pool.
///
/// The privileged pool is the scope that WOULD see the row. Asking the
/// low-privilege pool whether a row is revoked would answer "no row" in both
/// the revoked and the unrevoked case.
async fn is_revoked(pool: &PgPool, token_id: Uuid) -> bool {
    sqlx::query_scalar::<_, bool>("SELECT revoked_at IS NOT NULL FROM refresh_tokens WHERE id = $1")
        .bind(token_id)
        .fetch_one(pool)
        .await
        .expect("the seeded refresh row must still exist to be probed")
}

/// `(rowsecurity, forcerowsecurity)` straight out of the catalog. Asserted as
/// a PREMISE: if migration 002's arming were reverted, the low-privilege pool
/// would read everything and every test below would pass while measuring
/// nothing.
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
/// A POOL rather than a connection, deliberately: `set_config(..., true)` is
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
// The logout path
// ===========================================================================

/// LOGOUT MUST REVOKE. `POST /v1/auth/logout` blacklists the access-token jti
/// in Redis and then calls `revoke_all_for_user`; the refresh row is the only
/// Redis-independent half, so if it survives, the session outlives the
/// sign-out the user watched succeed.
///
/// The read-back is through the PRIVILEGED pool. Asking the low-privilege pool
/// would return no row in BOTH the revoked and the unrevoked case, which is
/// the vacuity this whole suite exists to avoid.
#[sqlx::test]
async fn logout_revokes_the_refresh_token_under_a_non_bypassing_role(pool: PgPool) {
    let victim = seed_session(&pool, "Logout").await;

    // PREMISE 1: the table really is armed, so the call below is passing
    // through a policy rather than an unenforced table.
    assert_eq!(
        rls_flags(&pool, "refresh_tokens").await,
        (true, true),
        "premise: migration 002 arms refresh_tokens. Unarmed, the low-privilege \
         pool reads everything and this test measures nothing."
    );
    // PREMISE 2: the row is ACTIVE before the logout. Without this, a
    // `revoked_at IS NOT NULL` afterwards could be the fixture's doing.
    assert!(
        !is_revoked(&pool, victim.token_id).await,
        "premise: the seeded refresh row must be active before the logout"
    );

    let low = low_privilege_pool(&pool).await;
    let repo = RefreshTokenRepository::new(low);

    repo.revoke_all_for_user(victim.user_id)
        .await
        .expect("logout's revoke must not error");

    assert!(
        is_revoked(&pool, victim.token_id).await,
        "the refresh row survived the logout. The user watched the sign-out \
         succeed and their session is still refreshable."
    );
}

/// NEGATIVE CONTROL for the test above: `revoke_all_for_user` must revoke the
/// named user's rows and NOBODY ELSE'S. Without this, a `revoke_all_for_user`
/// that ignored `user_id` entirely — or a policy change that let it see every
/// tenant — would satisfy the assertion above.
#[sqlx::test]
async fn logout_revokes_only_the_user_who_logged_out(pool: PgPool) {
    let leaver = seed_session(&pool, "Leaver").await;
    let bystander = seed_session(&pool, "Bystander").await;

    let low = low_privilege_pool(&pool).await;
    let repo = RefreshTokenRepository::new(low);

    repo.revoke_all_for_user(leaver.user_id)
        .await
        .expect("logout's revoke must not error");

    assert!(
        is_revoked(&pool, leaver.token_id).await,
        "the leaver's row must be revoked"
    );
    assert!(
        !is_revoked(&pool, bystander.token_id).await,
        "another workspace's session was revoked by this workspace's logout"
    );
}

// ===========================================================================
// The refresh path — `rotate`'s cross-tenant pre-lookup
// ===========================================================================

/// THE SILENT ZERO ON `/v1/auth/refresh`. `rotate` must find the presented
/// token, revoke it, and mint the successor.
///
/// With the pre-lookup on a bare pool and a non-bypassing role, the SELECT
/// returns no row, `rotate` answers `NotFound`, and the handler 401s — every
/// session refresh in the deployment, for every tenant, indefinitely.
#[sqlx::test]
async fn refresh_rotation_survives_a_non_bypassing_role(pool: PgPool) {
    let session = seed_session(&pool, "Rotate").await;

    assert_eq!(
        rls_flags(&pool, "refresh_tokens").await,
        (true, true),
        "premise: migration 002 arms refresh_tokens"
    );

    let low = low_privilege_pool(&pool).await;
    let repo = RefreshTokenRepository::new(low);

    let successor_raw = format!("rt-{}", Uuid::new_v4().simple());
    let outcome = repo
        .rotate(
            &session.raw,
            &successor_raw,
            "jti-rotate",
            Utc::now() + Duration::hours(1),
        )
        .await
        .expect("rotation must not error");

    let RotationOutcome::Rotated {
        old_id,
        new_id,
        user_id,
        workspace_id,
    } = outcome
    else {
        panic!(
            "presenting a live refresh token answered {outcome:?}. `NotFound` \
             here is the silent zero: the pre-lookup saw no row, so every \
             `/v1/auth/refresh` in the deployment 401s and every signed-in \
             session dies at the first rotation."
        );
    };
    assert_eq!(old_id, session.token_id);
    assert_eq!(user_id, session.user_id);
    assert_eq!(workspace_id, session.workspace_id);

    // What landed on disk, read through the privileged pool — not what the
    // method claims it did.
    let replaced_by: Option<Uuid> =
        sqlx::query_scalar("SELECT replaced_by FROM refresh_tokens WHERE id = $1")
            .bind(session.token_id)
            .fetch_one(&pool)
            .await
            .expect("the rotated row must still exist");
    assert_eq!(
        replaced_by,
        Some(new_id),
        "the rotated row must name its successor, or replay detection has \
         nothing to key on"
    );
    assert!(
        is_revoked(&pool, session.token_id).await,
        "the presented token must be revoked by its own rotation, or it is \
         reusable forever"
    );

    let successor_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM refresh_tokens WHERE id = $1 AND token_hash = $2)",
    )
    .bind(new_id)
    .bind(hash_refresh_token(&successor_raw))
    .fetch_one(&pool)
    .await
    .expect("successor probe");
    assert!(
        successor_exists,
        "the successor row must be on disk under the hash the caller was handed"
    );
}

/// NEGATIVE CONTROL for the test above, and the one that keeps a fix from
/// being "make the lookup see everything": a token that does not exist must
/// still answer `NotFound`.
#[sqlx::test]
async fn rotation_of_an_unknown_token_is_still_not_found(pool: PgPool) {
    let _ = seed_session(&pool, "Unknown").await;

    let low = low_privilege_pool(&pool).await;
    let repo = RefreshTokenRepository::new(low);

    let outcome = repo
        .rotate(
            "rt-this-token-was-never-issued",
            "rt-successor",
            "jti-unknown",
            Utc::now() + Duration::hours(1),
        )
        .await
        .expect("rotation of an unknown token must not error");

    assert!(
        matches!(outcome, RotationOutcome::NotFound),
        "an unissued token must answer NotFound, got {outcome:?}"
    );
}

// ===========================================================================
// The by-hash lookup
// ===========================================================================

/// `find_active_by_hash` is the by-hash session lookup primitive. Under a
/// non-bypassing role with the statement on a bare pool it answers `None` for
/// a token that is live on disk — "this token is not active" is a plausible
/// answer to every question its callers ask, and it raises nothing.
#[sqlx::test]
async fn find_active_by_hash_survives_a_non_bypassing_role(pool: PgPool) {
    let session = seed_session(&pool, "Find").await;

    assert_eq!(
        rls_flags(&pool, "refresh_tokens").await,
        (true, true),
        "premise: migration 002 arms refresh_tokens"
    );

    let low = low_privilege_pool(&pool).await;
    let repo = RefreshTokenRepository::new(low);

    let found = repo
        .find_active_by_hash(&hash_refresh_token(&session.raw))
        .await
        .expect("the lookup must not error")
        .expect(
            "a live refresh token was not found. `None` here is the silent \
             zero: the row is on disk and active, and the lookup says the \
             session does not exist.",
        );
    assert_eq!(found.id, session.token_id);
    assert_eq!(found.user_id, session.user_id);
    assert_eq!(found.workspace_id, session.workspace_id);

    // NEGATIVE CONTROL, first axis: a REVOKED row must not be returned, so the
    // assertion above is about an active token and not about the lookup
    // returning whatever it finds.
    sqlx::query("UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = $1")
        .bind(session.token_id)
        .execute(&pool)
        .await
        .expect("revoke the row through the privileged pool");
    assert!(
        repo.find_active_by_hash(&hash_refresh_token(&session.raw))
            .await
            .expect("the lookup must not error")
            .is_none(),
        "a revoked row must not read as an active session"
    );
}

/// NEGATIVE CONTROL, second axis, and the one that bounds what any fix is
/// allowed to admit: a hash NOBODY holds must find nothing. A fix that made
/// the lookup see the whole table would pass every positive assertion above
/// and fail here only if the wrong hash is asked for — so this is the test
/// that says the capability is "the row whose hash you name", not "the table".
#[sqlx::test]
async fn find_active_by_hash_finds_nothing_for_an_unissued_hash(pool: PgPool) {
    let session = seed_session(&pool, "Unissued").await;

    let low = low_privilege_pool(&pool).await;
    let repo = RefreshTokenRepository::new(low);

    // PREMISE: the lookup CAN find something in this database, so the `None`
    // below is about the hash and not about the lookup being broken outright.
    assert!(
        repo.find_active_by_hash(&hash_refresh_token(&session.raw))
            .await
            .expect("the lookup must not error")
            .is_some(),
        "premise: the seeded token must be findable, or the negative below is \
         satisfied by a lookup that finds nothing at all"
    );

    assert!(
        repo.find_active_by_hash(&hash_refresh_token("rt-never-issued"))
            .await
            .expect("the lookup must not error")
            .is_none(),
        "an unissued hash must find nothing"
    );
}

// ===========================================================================
// What migration 032 admits — asserted directly on the policy, not through a
// repository
// ===========================================================================

/// A single low-privilege CONNECTION, not a pool.
///
/// The two tests below are about state that persists on a connection ACROSS
/// transactions — the value a released `set_config(…, true)` reverts to. A
/// pool would hand each statement to an arbitrary checkout and the premise
/// would be untestable.
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
    assert_eq!(
        row.get::<String, _>("who"),
        RLS_ROLE,
        "premise: connected as the wrong role"
    );
    assert!(
        !row.get::<bool, _>("rolsuper") && !row.get::<bool, _>("rolbypassrls"),
        "premise: this role bypasses RLS, so the assertions below prove nothing"
    );

    conn
}

/// THE BOUNDARY. `refresh_token_possession` is `FOR SELECT`, so a transaction
/// holding a foreign workspace's token hash may READ that row and must not be
/// able to change anything.
///
/// Every write below is measured by `rows_affected`, and then the table is
/// re-read through the PRIVILEGED pool AFTER the probe transaction COMMITS —
/// because "the UPDATE reported 0" and "the row is unchanged on disk" are
/// different claims, and only the second is the security property.
#[sqlx::test]
async fn the_probe_grants_a_read_and_nothing_else(pool: PgPool) {
    let mine = seed_session(&pool, "Prober").await;
    let theirs = seed_session(&pool, "Target").await;
    let their_hash = hash_refresh_token(&theirs.raw);

    let mut conn = low_privilege_connection(&pool).await;

    sqlx::query("BEGIN")
        .execute(&mut conn)
        .await
        .expect("begin the probe transaction");
    sqlx::query("SELECT set_config('app.refresh_token_probe', $1, true)")
        .bind(&their_hash)
        .execute(&mut conn)
        .await
        .expect("arm the probe");

    // READ: exactly one row, and it is the one whose hash was named.
    let visible: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM refresh_tokens")
        .fetch_all(&mut conn)
        .await
        .expect("the probe read must not error");
    assert_eq!(
        visible,
        vec![theirs.token_id],
        "the probe must admit EXACTLY the row whose hash it named. More than \
         one row means the policy is not an equality; zero means the probe \
         does not work at all."
    );

    // ENUMERATION: the policy decides visibility, not the query. A wildcard in
    // the WHERE clause must not widen what comes back.
    let wildcard: i64 =
        sqlx::query_scalar("SELECT count(*) FROM refresh_tokens WHERE token_hash LIKE '%'")
            .fetch_one(&mut conn)
            .await
            .expect("wildcard probe");
    assert_eq!(
        wildcard, 1,
        "a wildcard in the query must not enumerate the table"
    );

    // WRITES: all three must be no-ops.
    for (label, sql) in [
        (
            "targeted revoke",
            "UPDATE refresh_tokens SET revoked_at = NOW() WHERE token_hash = $1",
        ),
        (
            "targeted delete",
            "DELETE FROM refresh_tokens WHERE token_hash = $1",
        ),
    ] {
        let affected = sqlx::query(sql)
            .bind(&their_hash)
            .execute(&mut conn)
            .await
            .unwrap_or_else(|e| panic!("{label} must not error, it must be a no-op: {e}"))
            .rows_affected();
        assert_eq!(
            affected, 0,
            "{label} through the possession probe affected {affected} rows. \
             The probe is FOR SELECT; a write reaching a foreign row means one \
             tenant can end another tenant's session."
        );
    }
    let blind = sqlx::query("UPDATE refresh_tokens SET revoked_at = NOW()")
        .execute(&mut conn)
        .await
        .expect("a blind table-wide update must not error, it must be a no-op")
        .rows_affected();
    assert_eq!(blind, 0, "a blind table-wide UPDATE affected {blind} rows");

    sqlx::query("COMMIT")
        .execute(&mut conn)
        .await
        .expect("commit the probe transaction");

    // ON DISK, through the privileged pool, after the COMMIT. `rows_affected`
    // is what the statement claims; this is what happened.
    assert!(
        !is_revoked(&pool, theirs.token_id).await,
        "the probed foreign session was revoked. A read-only capability wrote."
    );
    assert!(
        !is_revoked(&pool, mine.token_id).await,
        "an unprobed session was revoked by the blind UPDATE"
    );
    let survivors: i64 = sqlx::query_scalar("SELECT count(*) FROM refresh_tokens")
        .fetch_one(&pool)
        .await
        .expect("row count through the privileged pool");
    assert_eq!(
        survivors, 2,
        "both refresh rows must survive the probe; the DELETE removed one"
    );
}

/// MIGRATION 032 PART 1. On a connection that has served a scoped transaction
/// and released it, `app.current_workspace_id` reverts to the EMPTY STRING,
/// not to NULL — and `''::uuid` RAISES. Before this migration that made a bare
/// read of `refresh_tokens` fail with `invalid input syntax for type uuid: ""`
/// on a recycled pool checkout and return the empty set on a fresh one, decided
/// by which connection the pool happened to hand over.
///
/// The premise assertion is the whole test: without it a fresh connection would
/// satisfy the "0 rows, no error" claim trivially, having never been armed.
#[sqlx::test]
async fn a_released_scope_leaves_the_setting_empty_and_the_read_harmless(pool: PgPool) {
    let session = seed_session(&pool, "Recycled").await;

    let mut conn = low_privilege_connection(&pool).await;

    // Serve a scoped transaction and release it, exactly as a pooled
    // connection does between two repository calls.
    for stmt in [
        "BEGIN",
        &format!(
            "SELECT set_config('app.current_workspace_id', '{}', true)",
            session.workspace_id
        ),
        "COMMIT",
    ] {
        sqlx::query(stmt)
            .execute(&mut conn)
            .await
            .expect("the scoped transaction must run");
    }

    // PREMISE: the setting is now '' and NOT NULL. This is the state that used
    // to raise; on a never-armed connection it would be NULL and the read below
    // would be uninteresting.
    let (is_null, value): (bool, Option<String>) = sqlx::query_as(
        "SELECT current_setting('app.current_workspace_id', true) IS NULL,
                current_setting('app.current_workspace_id', true)",
    )
    .fetch_one(&mut conn)
    .await
    .expect("setting probe");
    assert!(
        !is_null,
        "premise: after a released transaction-local set_config the setting \
         must read back as '' rather than NULL. It is NULL, so this connection \
         is not in the recycled state and the assertion below proves nothing."
    );
    assert_eq!(
        value.as_deref(),
        Some(""),
        "premise: the setting must be ''"
    );

    // The read must be HARMLESS: empty, and not an error.
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM refresh_tokens")
        .fetch_one(&mut conn)
        .await
        .expect(
            "an unarmed read on a recycled connection must return the empty \
             set, not raise. `invalid input syntax for type uuid: \"\"` here \
             means migration 032 Part 1's NULLIF is missing.",
        );
    assert_eq!(
        rows, 0,
        "an unarmed read must see nothing. Seeing rows means the policy stopped \
         filtering."
    );
}

/// MIGRATION 032 PART 1, the direction that must stay LOUD. Part 1 turns an
/// ERROR into invisibility on the read side; it must not do the same on the
/// write side. An INSERT with no scope armed is rejected — before and after.
#[sqlx::test]
async fn an_unarmed_insert_is_still_rejected_not_silently_dropped(pool: PgPool) {
    let session = seed_session(&pool, "Reject").await;

    let mut conn = low_privilege_connection(&pool).await;

    let err = sqlx::query(
        "INSERT INTO refresh_tokens
             (id, user_id, workspace_id, token_hash, expires_at, created_at, session_id)
         VALUES (gen_random_uuid(), $1, $2, 'unarmed-insert', NOW() + INTERVAL '1 hour',
                 NOW(), gen_random_uuid())",
    )
    .bind(session.user_id)
    .bind(session.workspace_id)
    .execute(&mut conn)
    .await
    .expect_err(
        "an INSERT with no workspace scope armed must be REJECTED. Succeeding \
         here means one tenant can mint a refresh token in another's workspace.",
    )
    .to_string();
    assert!(
        err.contains("row-level security"),
        "the rejection must come from the policy, not from something else: {err}"
    );

    // The absence-claim, read from the scope that WOULD see the row.
    let planted: i64 =
        sqlx::query_scalar("SELECT count(*) FROM refresh_tokens WHERE token_hash = $1")
            .bind("unarmed-insert")
            .fetch_one(&pool)
            .await
            .expect("privileged count");
    assert_eq!(planted, 0, "the rejected row must not be on disk");
}

/// The probe must not outlive its own transaction. A session-local `false`
/// would leave one caller's token hash armed on a pooled connection for
/// whatever statement is handed it next.
#[sqlx::test]
async fn the_probe_does_not_outlive_its_transaction(pool: PgPool) {
    let session = seed_session(&pool, "Local").await;
    let hash = hash_refresh_token(&session.raw);

    let mut conn = low_privilege_connection(&pool).await;

    sqlx::query("BEGIN")
        .execute(&mut conn)
        .await
        .expect("begin");
    sqlx::query("SELECT set_config('app.refresh_token_probe', $1, true)")
        .bind(&hash)
        .execute(&mut conn)
        .await
        .expect("arm the probe");
    // PREMISE: the probe really is admitting the row inside its transaction,
    // so the 0 below is about the transaction ending and not about the probe
    // never having worked.
    let inside: i64 = sqlx::query_scalar("SELECT count(*) FROM refresh_tokens")
        .fetch_one(&mut conn)
        .await
        .expect("read inside the probe transaction");
    assert_eq!(
        inside, 1,
        "premise: the probe must admit its row while armed"
    );
    sqlx::query("COMMIT")
        .execute(&mut conn)
        .await
        .expect("commit");

    let outside: i64 = sqlx::query_scalar("SELECT count(*) FROM refresh_tokens")
        .fetch_one(&mut conn)
        .await
        .expect("read after the probe transaction");
    assert_eq!(
        outside, 0,
        "the probe survived its transaction. On a pooled connection that hands \
         one caller's token row to the next statement served."
    );
}
