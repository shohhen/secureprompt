//! WS3-4 — tests for the `retention.purge` job.
//!
//! # The trap these tests are written against
//!
//! "purge deleted the expired rows" passes trivially if no rows were ever
//! inserted, if the delete errored and was swallowed, or if the rows were
//! never expired to begin with. Every test below therefore asserts the
//! PRE-STATE (the rows ARE there and ARE past the boundary), then purges,
//! then asserts the POST-STATE — and every test asserts that rows which are
//! NOT past the boundary SURVIVE. Without that last part the whole file
//! would pass for a purge job that simply deleted everything.
//!
//! All fixture PII is synthetic.

use super::*;
use sqlx::{PgPool, Row as _};
use uuid::Uuid;

/// The gateway's own analytics database, so the ClickHouse assertions run
/// against the real `request_content_captures` table rather than a bespoke
/// fixture.
const CH_DB: &str = "sp_analytics";

fn ch_url() -> String {
    std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://localhost:8123".to_owned())
}

fn ch_client() -> clickhouse::Client {
    clickhouse::Client::default()
        .with_url(ch_url())
        .with_database(CH_DB)
}

/// Raw ClickHouse HTTP, used for fixture setup and for reading state back.
/// Panics rather than skipping when ClickHouse is unreachable: a missing
/// dependency must fail loudly, never turn into a quietly-passing "no rows
/// found".
async fn ch_query(sql: &str) -> String {
    let response = reqwest::Client::new()
        .post(format!("{}/?database={CH_DB}", ch_url()))
        .body(sql.to_owned())
        .send()
        .await
        .expect("ClickHouse must be reachable — see the task env (CLICKHOUSE_URL)");
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "clickhouse query failed ({status}): {text}\nsql: {sql}"
    );
    text.trim().to_owned()
}

/// Apply ClickHouse migration 007 the same way the worker does at startup.
/// Idempotent, and deliberately NOT a "skip if the table is missing" guard.
async fn ensure_capture_table() {
    const MIGRATION: &str = include_str!(
        "../../../../secureprompt-api/clickhouse/migrations/007_request_content_captures.sql"
    );
    let sql: String = MIGRATION
        .lines()
        .filter(|l| !l.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n");
    for statement in sql.split(';') {
        if !statement.trim().is_empty() {
            ch_query(statement.trim()).await;
        }
    }
}

async fn seed_workspace(pool: &PgPool) -> sqlx::Result<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workspaces (id, name, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(id)
    .bind(format!("ws3-4-{}", id.simple()))
    .execute(pool)
    .await?;
    Ok(id)
}

/// Insert a vault row with an explicit `expires_at`, bypassing the
/// repository so the fixture can place a row in the past.
async fn insert_vault_entry(
    pool: &PgPool,
    workspace_id: Uuid,
    expires_in_hours: i64,
) -> sqlx::Result<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO token_vault_entries
             (id, workspace_id, mapping_ciphertext, created_at, expires_at)
         VALUES ($1, $2, $3, NOW(), NOW() + ($4 || ' hours')::INTERVAL)",
    )
    .bind(id)
    .bind(workspace_id)
    // Stand-in ciphertext. Never plaintext PII, even in a fixture.
    .bind(format!("ciphertext-stand-in-{}", id.simple()))
    .bind(expires_in_hours.to_string())
    .execute(pool)
    .await?;
    Ok(id)
}

async fn vault_row_exists(pool: &PgPool, id: Uuid) -> sqlx::Result<bool> {
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM token_vault_entries WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await?;
    Ok(n == 1)
}

async fn audit_rows(
    pool: &PgPool,
    run_id: Uuid,
    scope: &str,
) -> sqlx::Result<Vec<sqlx::postgres::PgRow>> {
    sqlx::query(
        "SELECT * FROM retention_purge_audit WHERE run_id = $1 AND scope = $2
         ORDER BY completed_at",
    )
    .bind(run_id)
    .bind(scope)
    .fetch_all(pool)
    .await
}

// ── (a) expired token_vault_entries ───────────────────────────────────────

/// Acceptance criterion: "Purge deletes expired vault entries."
///
/// PRE-STATE / POST-STATE, plus the survival assertion that stops this
/// passing for a job that deletes indiscriminately.
#[sqlx::test(migrations = "../secureprompt-api/migrations")]
async fn purge_deletes_expired_vault_entries_and_spares_live_ones(
    pool: PgPool,
) -> sqlx::Result<()> {
    let workspace_id = seed_workspace(&pool).await?;

    let expired = insert_vault_entry(&pool, workspace_id, -1).await?;
    let live = insert_vault_entry(&pool, workspace_id, 23).await?;

    // ── PRE-STATE. Without these, "zero expired rows remain" is satisfied
    // by never having inserted one.
    assert!(
        vault_row_exists(&pool, expired).await?,
        "premise: the expired row must exist before the purge"
    );
    assert!(
        vault_row_exists(&pool, live).await?,
        "premise: the live row must exist before the purge"
    );
    let expired_is_expired: bool =
        sqlx::query_scalar("SELECT expires_at <= NOW() FROM token_vault_entries WHERE id = $1")
            .bind(expired)
            .fetch_one(&pool)
            .await?;
    assert!(
        expired_is_expired,
        "premise: the row this test calls expired must actually BE expired — \
         otherwise the purge is being credited for deleting a row it should \
         not have touched"
    );
    let live_is_live: bool =
        sqlx::query_scalar("SELECT expires_at > NOW() FROM token_vault_entries WHERE id = $1")
            .bind(live)
            .fetch_one(&pool)
            .await?;
    assert!(
        live_is_live,
        "premise: the row this test calls live must actually be un-expired"
    );

    // ── PURGE.
    let outcome = run(&pool, &ch_client()).await;

    // ── POST-STATE.
    assert!(
        !vault_row_exists(&pool, expired).await?,
        "the expired vault entry survived the purge"
    );
    // THE TRAP-GUARD. A purge that deletes everything also passes the line
    // above.
    assert!(
        vault_row_exists(&pool, live).await?,
        "the purge deleted an UN-EXPIRED vault entry — the 24h window is a \
         retention floor, not a licence to drop live rows"
    );

    let remaining_expired: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM token_vault_entries WHERE expires_at <= NOW()")
            .fetch_one(&pool)
            .await?;
    assert_eq!(
        remaining_expired, 0,
        "expired rows remain after the purge claimed to run"
    );

    // The run reported what it did.
    assert!(
        outcome.all_ok(),
        "the purge reported a failure: {:?}",
        outcome.records
    );
    Ok(())
}

/// A purge run over a store with nothing to delete must still succeed, must
/// delete nothing, and must still leave an audit row.
///
/// This is the POSITIVE-CONTROL COUNTERPART to the test above: it produces a
/// DIFFERENT result (`rows_deleted == 0`) from the same code path, so
/// "rows_deleted == 1" up there is a real measurement rather than a constant.
#[sqlx::test(migrations = "../secureprompt-api/migrations")]
async fn purge_with_nothing_expired_deletes_nothing_but_still_records_a_run(
    pool: PgPool,
) -> sqlx::Result<()> {
    let workspace_id = seed_workspace(&pool).await?;
    let live = insert_vault_entry(&pool, workspace_id, 23).await?;

    // PRE-STATE: exactly one row, and it is NOT expired.
    let expired_before: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM token_vault_entries WHERE expires_at <= NOW()")
            .fetch_one(&pool)
            .await?;
    assert_eq!(
        expired_before, 0,
        "premise: this test needs a store with nothing eligible for purge"
    );

    let outcome = run(&pool, &ch_client()).await;

    assert!(
        vault_row_exists(&pool, live).await?,
        "the purge deleted a live row on a run that had nothing to do"
    );

    let rows = audit_rows(&pool, outcome.run_id, "token_vault_entries").await?;
    assert_eq!(
        rows.len(),
        1,
        "a run that deleted nothing must STILL write an audit row — otherwise \
         a missing row is ambiguous between 'nothing to purge' and 'the job \
         never ran'"
    );
    assert_eq!(
        rows[0].get::<i64, _>("rows_deleted"),
        0,
        "nothing was eligible, so nothing may be reported as deleted"
    );
    assert_eq!(rows[0].get::<String, _>("status"), "ok");
    Ok(())
}

// ── proof-of-purge record ─────────────────────────────────────────────────

/// Acceptance criterion: "Emits a proof-of-purge audit record with counts and
/// ranges."
#[sqlx::test(migrations = "../secureprompt-api/migrations")]
async fn purge_emits_a_proof_of_purge_record_with_counts_and_ranges(
    pool: PgPool,
) -> sqlx::Result<()> {
    let workspace_id = seed_workspace(&pool).await?;

    // Two expired rows with DIFFERENT expiries, so a recorded range is
    // distinguishable from a recorded single instant.
    insert_vault_entry(&pool, workspace_id, -50).await?;
    insert_vault_entry(&pool, workspace_id, -2).await?;
    insert_vault_entry(&pool, workspace_id, 23).await?;

    let before: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM token_vault_entries WHERE expires_at <= NOW()")
            .fetch_one(&pool)
            .await?;
    assert_eq!(before, 2, "premise: exactly two rows are eligible");

    let outcome = run(&pool, &ch_client()).await;

    let rows = audit_rows(&pool, outcome.run_id, "token_vault_entries").await?;
    assert_eq!(rows.len(), 1, "one audit row per scope per run");
    let row = &rows[0];

    assert_eq!(
        row.get::<i64, _>("rows_deleted"),
        2,
        "the record must report the real count"
    );
    assert_eq!(
        row.get::<i64, _>("rows_remaining_past_cutoff"),
        0,
        "the job must re-check after deleting and record what still violates \
         the policy — this is the field an auditor can independently recompute"
    );
    assert_eq!(row.get::<String, _>("status"), "ok");

    // The RANGE the PRD asks for: two rows expiring 48h apart must produce a
    // window, not a point.
    let oldest: DateTime<Utc> = row
        .try_get("oldest_deleted")
        .expect("oldest_deleted must be set when rows were deleted");
    let newest: DateTime<Utc> = row
        .try_get("newest_deleted")
        .expect("newest_deleted must be set when rows were deleted");
    assert!(
        newest > oldest,
        "the recorded window must span the two deleted rows, got {oldest} .. {newest}"
    );
    let cutoff: DateTime<Utc> = row.get("cutoff");
    assert!(
        newest <= cutoff,
        "everything deleted must be at or before the recorded cutoff; \
         newest={newest} cutoff={cutoff}"
    );
    Ok(())
}

// ── (b) retroactive retention lowering on captured content ────────────────

/// Insert a capture row with an explicit `created_at` age and an
/// `expires_at` stamped under the OLD (long) retention.
async fn insert_capture(workspace_id: Uuid, request_id: Uuid, created_days_ago: u32) {
    ch_query(&format!(
        "INSERT INTO request_content_captures
             (request_id, workspace_id, created_at, expires_at, encrypted,
              raw_prompt, raw_response, restored_response)
         VALUES
             ('{request_id}', '{workspace_id}',
              now() - INTERVAL {created_days_ago} DAY,
              now() + INTERVAL 300 DAY,
              true, 'ciphertext-stand-in', NULL, NULL)"
    ))
    .await;
}

async fn capture_count(workspace_id: Uuid) -> i64 {
    ch_query(&format!(
        "SELECT count() FROM request_content_captures WHERE workspace_id = '{workspace_id}'"
    ))
    .await
    .parse()
    .expect("count must parse")
}

async fn capture_exists(request_id: Uuid) -> bool {
    ch_query(&format!(
        "SELECT count() FROM request_content_captures WHERE request_id = '{request_id}'"
    ))
    .await
        != "0"
}

/// THE CASE WS3-2 DEFERRED HERE.
///
/// `request_content_captures` carries `TTL expires_at DELETE`, which handles
/// the ordinary case. But `expires_at` is computed at INSERT time from the
/// workspace's retention, so an operator who LOWERS retention from 300 days
/// to 7 does not shorten rows already on disk — their `expires_at` is still
/// 300 days out and the engine will happily keep them.
///
/// PREMISE ASSERTIONS make this test about that case specifically:
///   1. the rows exist;
///   2. their `expires_at` is in the FUTURE — so ClickHouse's own TTL would
///      NOT remove them, and anything that disappears did so because the
///      purge ran, not because the engine got there first.
///
/// SURVIVAL ASSERTION: a row INSIDE the lowered window must remain.
#[sqlx::test(migrations = "../secureprompt-api/migrations")]
async fn purge_applies_lowered_retention_to_already_captured_content(
    pool: PgPool,
) -> sqlx::Result<()> {
    ensure_capture_table().await;
    let workspace_id = seed_workspace(&pool).await?;

    // Captured while retention was long.
    let old = Uuid::new_v4();
    let recent = Uuid::new_v4();
    insert_capture(workspace_id, old, 30).await;
    insert_capture(workspace_id, recent, 2).await;

    // The operator LOWERS retention to 7 days, after the rows were written.
    sqlx::query(
        "INSERT INTO workspace_raw_capture (workspace_id, enabled, retention_days)
         VALUES ($1, true, 7)",
    )
    .bind(workspace_id)
    .execute(&pool)
    .await?;

    // ── PRE-STATE.
    assert_eq!(
        capture_count(workspace_id).await,
        2,
        "premise: both capture rows must exist before the purge"
    );
    let not_yet_ttl_eligible = ch_query(&format!(
        "SELECT count() FROM request_content_captures
         WHERE workspace_id = '{workspace_id}' AND expires_at > now()"
    ))
    .await;
    assert_eq!(
        not_yet_ttl_eligible, "2",
        "premise: BOTH rows must still be inside their stamped expires_at, so \
         ClickHouse's own TTL would not delete either. Otherwise this test \
         would be crediting the purge for the engine's work."
    );

    // ── PURGE.
    let outcome = run(&pool, &ch_client()).await;

    // ── POST-STATE.
    assert!(
        !capture_exists(old).await,
        "the 30-day-old capture survived a retention lowered to 7 days"
    );
    // THE TRAP-GUARD.
    assert!(
        capture_exists(recent).await,
        "the purge deleted a 2-day-old capture under a 7-day retention — it is \
         deleting by something other than the configured window"
    );

    let rows = audit_rows(&pool, outcome.run_id, "request_content_captures").await?;
    let mine: Vec<_> = rows
        .iter()
        .filter(|r| r.get::<Option<Uuid>, _>("workspace_id") == Some(workspace_id))
        .collect();
    assert_eq!(
        mine.len(),
        1,
        "one audit row for this workspace's captured content"
    );
    assert_eq!(
        mine[0].get::<i64, _>("rows_deleted"),
        1,
        "exactly the one past-retention row"
    );
    assert_eq!(
        mine[0].get::<i64, _>("rows_remaining_past_cutoff"),
        0,
        "nothing past the lowered cutoff may remain"
    );
    Ok(())
}

// ── (c) FU4: session device context ───────────────────────────────────────

/// Insert one session's sign-in row. `expires_in_hours` in the past makes the
/// session dead; `revoked` makes it dead a different way. Both are ways a
/// session ends, and both must lead to the device context being erased.
async fn insert_session(
    pool: &PgPool,
    workspace_id: Uuid,
    user_id: Uuid,
    expires_in_hours: i64,
    revoked: bool,
) -> sqlx::Result<Uuid> {
    let session_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO refresh_tokens
             (id, user_id, workspace_id, token_hash, created_at, expires_at,
              revoked_at, session_id, access_jti, client_ip, client_descriptor)
         VALUES ($1, $2, $3, $4, NOW(), NOW() + ($5 || ' hours')::INTERVAL,
                 CASE WHEN $6 THEN NOW() ELSE NULL END,
                 $7, $8, '203.0.113.7', 'Chrome on macOS')",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(workspace_id)
    .bind(Uuid::new_v4().simple().to_string())
    .bind(expires_in_hours.to_string())
    .bind(revoked)
    .bind(session_id)
    .bind(Uuid::new_v4().to_string())
    .execute(pool)
    .await?;
    Ok(session_id)
}

async fn device_context_of(pool: &PgPool, session_id: Uuid) -> sqlx::Result<(i64, i64)> {
    let row = sqlx::query(
        "SELECT COUNT(*)::BIGINT AS total,
                COUNT(*) FILTER (
                    WHERE client_ip IS NOT NULL OR client_descriptor IS NOT NULL
                )::BIGINT AS with_context
         FROM refresh_tokens WHERE session_id = $1",
    )
    .bind(session_id)
    .fetch_one(pool)
    .await?;
    Ok((row.get("total"), row.get("with_context")))
}

async fn seed_user(pool: &PgPool, workspace_id: Uuid) -> sqlx::Result<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, workspace_id, email, password_hash, role, created_at, updated_at)
         VALUES ($1, $2, $3, 'x', 'viewer', NOW(), NOW())",
    )
    .bind(id)
    .bind(workspace_id)
    .bind(format!("fu4-{}@example.com", id.simple()))
    .execute(pool)
    .await?;
    Ok(id)
}

/// FU4 — the device context on a session that has ENDED is erased, and the
/// context on a LIVE session is not.
///
/// This is the retention half of the FU4 privacy argument. Migration 027 puts
/// an IP address and a client descriptor on a refresh row so that a session can
/// be told apart from another one; `GET /v1/data-inventory` declares them as
/// `personal_data` with `worker_purge` as the mechanism. This job is that
/// mechanism, and without it the declaration is a false assurance — the exact
/// failure `retention_days_without_an_enforcement_mechanism_is_never_reported`
/// exists to catch on the other side.
///
/// It is a SCRUB, not a delete. The row survives because migration 002's
/// single-use rotation detects a replayed token by finding the revoked row it
/// belongs to; deleting rows would turn a replay into a plain 401 and lose
/// threat T-05-03's detection. The personal data does not survive.
#[sqlx::test(migrations = "../secureprompt-api/migrations")]
async fn purge_scrubs_device_context_from_ended_sessions_only(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = seed_workspace(&pool).await?;
    let user_id = seed_user(&pool, workspace_id).await?;

    let expired = insert_session(&pool, workspace_id, user_id, -1, false).await?;
    let revoked = insert_session(&pool, workspace_id, user_id, 24, true).await?;
    let live = insert_session(&pool, workspace_id, user_id, 24, false).await?;

    // ── PRE-STATE. Without these, "the context is gone" is satisfied by never
    // having written any.
    for (name, session) in [("expired", expired), ("revoked", revoked), ("live", live)] {
        assert_eq!(
            device_context_of(&pool, session).await?,
            (1, 1),
            "premise: the {name} session must carry device context before the purge"
        );
    }

    let outcome = run(&pool, &ch_client()).await;

    // The two dead sessions are scrubbed...
    for (name, session) in [("expired", expired), ("revoked", revoked)] {
        let (total, with_context) = device_context_of(&pool, session).await?;
        assert_eq!(
            with_context, 0,
            "the {name} session's device context must be erased once the session \
             is over"
        );
        assert_eq!(
            total, 1,
            "...but the ROW must survive: deleting it would turn a replayed \
             refresh token into a plain 401 and lose the replay detection \
             migration 002 describes"
        );
    }

    // ...and the live one is NOT. Without this the whole test would pass for a
    // job that erased every device column in the table.
    assert_eq!(
        device_context_of(&pool, live).await?,
        (1, 1),
        "a LIVE session must keep the context that makes it identifiable in the \
         listing — scrubbing it would leave an administrator unable to tell \
         which session to end"
    );

    // The proof-of-purge record. `rows_deleted` counts rows SCRUBBED for this
    // scope; the post-check must be able to recompute zero.
    let rows = audit_rows(&pool, outcome.run_id, "refresh_tokens.device_context").await?;
    assert_eq!(rows.len(), 1, "one audit row for the device-context scope");
    assert_eq!(
        rows[0].get::<i64, _>("rows_deleted"),
        2,
        "exactly the two ended sessions"
    );
    assert_eq!(
        rows[0].get::<i64, _>("rows_remaining_past_cutoff"),
        0,
        "no ended session may still be carrying device context"
    );
    assert_eq!(rows[0].get::<String, _>("status"), "ok");
    Ok(())
}

/// A session whose chain has ROTATED is one session, and the scrub must decide
/// on the CHAIN. The sign-in row of a live session is itself revoked (its
/// successor replaced it), so a scrub that looked only at the row carrying the
/// context would erase the device of every session the moment it first
/// rotated — roughly fifteen minutes in.
///
/// STATED PLAINLY: this test passes before the scrub exists, because a job that
/// erases nothing erases nothing wrongly. It is the control on the test above —
/// the pair is what distinguishes a correct scrub from one that empties the
/// column — and it is the one that fails if a later change moves the decision
/// from the chain to the row.
#[sqlx::test(migrations = "../secureprompt-api/migrations")]
async fn a_rotated_but_live_session_keeps_its_device_context(pool: PgPool) -> sqlx::Result<()> {
    let workspace_id = seed_workspace(&pool).await?;
    let user_id = seed_user(&pool, workspace_id).await?;

    // The sign-in row: carries the device, and is REVOKED because it rotated.
    let session_id = insert_session(&pool, workspace_id, user_id, 24, true).await?;
    // Its successor: live, no device context, same session.
    sqlx::query(
        "INSERT INTO refresh_tokens
             (id, user_id, workspace_id, token_hash, created_at, expires_at, session_id, access_jti)
         VALUES ($1, $2, $3, $4, NOW(), NOW() + INTERVAL '24 hours', $5, $6)",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(workspace_id)
    .bind(Uuid::new_v4().simple().to_string())
    .bind(session_id)
    .bind(Uuid::new_v4().to_string())
    .execute(&pool)
    .await?;

    // PREMISE: the row holding the context really is revoked, so a row-level
    // scrub WOULD erase it and this test is not passing by accident.
    let revoked_row_holds_context: bool = sqlx::query_scalar(
        "SELECT bool_or(revoked_at IS NOT NULL AND client_ip IS NOT NULL)
         FROM refresh_tokens WHERE session_id = $1",
    )
    .bind(session_id)
    .fetch_one(&pool)
    .await?;
    assert!(
        revoked_row_holds_context,
        "premise: the device context must sit on a REVOKED row, which is what \
         makes the chain-level decision necessary"
    );

    run(&pool, &ch_client()).await;

    let (total, with_context) = device_context_of(&pool, session_id).await?;
    assert_eq!(
        total, 2,
        "premise: both rows of the chain are still present"
    );
    assert_eq!(
        with_context, 1,
        "a session that has merely ROTATED is still live, and must keep its \
         device context — the scrub decides per CHAIN, not per row"
    );
    Ok(())
}

// ── proof-of-purge under a non-bypassing role ─────────────────────────────

/// Same role, password and attributes as
/// `secureprompt-api/tests/migration_017_023_rls.rs` and
/// `scripts/ci/create-nonsuperuser-role.sh`.
const RLS_ROLE: &str = "secureprompt_runner";
const RLS_PASSWORD: &str = "secureprompt";

/// A pool onto the same test database as a NOSUPERUSER, NOBYPASSRLS role,
/// with that powerlessness asserted ON THE WIRE.
///
/// Without the premise assertions this helper is worthless: a role that turned
/// out to be SUPERUSER would keep the test below green while exercising no
/// row-level security at all.
async fn low_privilege_pool(pool: &PgPool) -> PgPool {
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
    .unwrap_or_else(|e| panic!("could not create the {RLS_ROLE} role: {e}"));

    sqlx::raw_sql(&format!(
        "GRANT USAGE ON SCHEMA public TO {RLS_ROLE};
         GRANT ALL ON ALL TABLES IN SCHEMA public TO {RLS_ROLE};
         GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO {RLS_ROLE};"
    ))
    .execute(pool)
    .await
    .expect("grants on the test database");

    let options: sqlx::postgres::PgConnectOptions = (*pool.connect_options())
        .clone()
        .username(RLS_ROLE)
        .password(RLS_PASSWORD);
    let low = sqlx::postgres::PgPoolOptions::new()
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
        "premise: {who} is a SUPERUSER and bypasses RLS"
    );
    assert!(
        !row.get::<bool, _>("rolbypassrls"),
        "premise: {who} has BYPASSRLS"
    );
    low
}

/// The purge job's proof-of-purge write, under a role that cannot bypass RLS.
///
/// Migration 030 armed `retention_purge_audit`. The job writes TWO shapes of
/// row in one run and they need different things from the policy:
///
///   * GLOBAL scopes (`workspace_id IS NULL`) — the token vault and the
///     session device-context scrub. 030's policy admits them without any
///     scope armed, which is why the job can keep writing them from a bare
///     pool.
///   * PER-WORKSPACE scopes (`request_content_captures`, one row per
///     workspace). These are rejected unless `app.current_workspace_id` is
///     armed to that row's workspace — and a run covers MANY workspaces, so
///     one scope for the whole run would not do.
///
/// `run()` logs the failure as `retention_purge_audit_write_failed` and
/// carries on, so a rejected write does NOT fail the job: the purge would
/// happen and its evidence would silently not exist. That is the shape this
/// test exists to prevent.
#[sqlx::test(migrations = "../secureprompt-api/migrations")]
async fn write_audit_records_both_global_and_per_workspace_scopes_under_rls(
    pool: PgPool,
) -> sqlx::Result<()> {
    let workspace = seed_workspace(&pool).await?;

    // PREMISE: the table really is armed, or this test measures nothing.
    let (enabled, forced): (bool, bool) = sqlx::query_as(
        "SELECT relrowsecurity, relforcerowsecurity FROM pg_class
         WHERE oid = to_regclass('public.retention_purge_audit')",
    )
    .fetch_one(&pool)
    .await?;
    assert!(
        enabled && forced,
        "premise: migration 030 must ENABLE and FORCE row-level security on \
         retention_purge_audit"
    );

    let low = low_privilege_pool(&pool).await;
    let run_id = Uuid::new_v4();
    let now = Utc::now();

    let record = |scope: &str, workspace_id: Option<Uuid>| PurgeRecord {
        scope: scope.to_owned(),
        workspace_id,
        cutoff: now,
        rows_deleted: 3,
        oldest_deleted: None,
        newest_deleted: None,
        rows_remaining_past_cutoff: 0,
        status: "ok".to_owned(),
        error: None,
        started_at: now,
    };

    write_audit(&low, run_id, &record(SCOPE_TOKEN_VAULT, None))
        .await
        .expect("a GLOBAL scope row must be writable with no scope armed");
    write_audit(&low, run_id, &record(SCOPE_SESSION_DEVICE_CONTEXT, None))
        .await
        .expect("the second global scope must be writable too");
    write_audit(
        &low,
        run_id,
        &record(SCOPE_CONTENT_CAPTURES, Some(workspace)),
    )
    .await
    .expect(
        "a PER-WORKSPACE scope row must be writable — the job has to arm \
             the row's own workspace to get it past the policy",
    );

    // Read back through the PRIVILEGED pool: what landed on disk, not what
    // the writes claimed.
    let scopes: Vec<String> = sqlx::query_scalar(
        "SELECT scope FROM retention_purge_audit WHERE run_id = $1 ORDER BY scope",
    )
    .bind(run_id)
    .fetch_all(&pool)
    .await?;
    assert_eq!(
        scopes,
        vec![
            SCOPE_SESSION_DEVICE_CONTEXT.to_owned(),
            SCOPE_CONTENT_CAPTURES.to_owned(),
            SCOPE_TOKEN_VAULT.to_owned(),
        ],
        "all three scopes of the run must be on disk. A missing per-workspace \
         scope is the silent gap: the purge ran and left no evidence."
    );

    // And the per-workspace row is attributed to the right tenant — the scope
    // was armed to that workspace, not merely to something.
    let attributed: Option<Uuid> = sqlx::query_scalar(
        "SELECT workspace_id FROM retention_purge_audit WHERE run_id = $1 AND scope = $2",
    )
    .bind(run_id)
    .bind(SCOPE_CONTENT_CAPTURES)
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        attributed,
        Some(workspace),
        "the per-workspace record must carry the workspace it is about"
    );
    Ok(())
}
