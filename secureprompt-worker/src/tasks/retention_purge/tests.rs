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
use sqlx::PgPool;
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
    // `workspace_raw_capture` is armed (migration 030), so the write goes
    // through the same scoped helper the P1H tests below use — a bare-pool
    // INSERT here is refused with `42501` under `secureprompt_runner`.
    set_capture_retention(&pool, workspace_id, 7).await?;

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

    // Read from THIS workspace's armed scope. `retention_purge_audit` is armed
    // (migration 030) and this row is per-workspace, so a bare read answers
    // nothing under `secureprompt_runner` — the assertion below would then be
    // measuring the reader rather than the purge.
    let mine =
        audit_rows_for_workspace(&pool, outcome.run_id, SCOPE_CONTENT_CAPTURES, workspace_id)
            .await?;
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

/// Arm one transaction to a workspace, the way every fixture and every read in
/// this file that touches an ARMED table has to.
///
/// `refresh_tokens` has been under FORCE ROW LEVEL SECURITY since migration
/// 002, so a bare-pool INSERT into it is refused with `42501` when
/// `DATABASE_URL` names `secureprompt_runner`, and a bare-pool SELECT of it
/// answers zero rows since migration 033. MEASURED: before this helper existed,
/// `purge_scrubs_device_context_from_ended_sessions_only` and
/// `a_rotated_but_live_session_keeps_its_device_context` both failed under the
/// runner with `new row violates row-level security policy for table
/// "refresh_tokens"`, and the suite could only ever run as a superuser — which
/// is the one role that cannot observe any of what it tests.
async fn arm(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    workspace_id: Uuid,
) -> sqlx::Result<()> {
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
        .bind(workspace_id.to_string())
        .execute(&mut **tx)
        .await
        .map(|_| ())
}

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
    let mut tx = pool.begin().await?;
    arm(&mut tx, workspace_id).await?;
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
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(session_id)
}

/// The device context on one session, read FROM A SCOPE THAT WOULD SEE IT.
///
/// The workspace is a PARAMETER rather than something this helper looks up,
/// because looking it up would mean reading `refresh_tokens` unarmed — the very
/// read whose silent zero every assertion here is written against. Under
/// `secureprompt_runner` a bare-pool version of this query answers `(0, 0)`,
/// which is byte-identical to "the row was deleted" and to "the context was
/// scrubbed". Every caller pairs its absence claim with a control row this same
/// helper DOES return.
async fn device_context_of(
    pool: &PgPool,
    workspace_id: Uuid,
    session_id: Uuid,
) -> sqlx::Result<(i64, i64)> {
    let mut tx = pool.begin().await?;
    arm(&mut tx, workspace_id).await?;
    let row = sqlx::query(
        "SELECT COUNT(*)::BIGINT AS total,
                COUNT(*) FILTER (
                    WHERE client_ip IS NOT NULL OR client_descriptor IS NOT NULL
                )::BIGINT AS with_context
         FROM refresh_tokens WHERE session_id = $1",
    )
    .bind(session_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
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
            device_context_of(&pool, workspace_id, session).await?,
            (1, 1),
            "premise: the {name} session must carry device context before the purge"
        );
    }

    let outcome = run(&pool, &ch_client()).await;

    // The two dead sessions are scrubbed...
    for (name, session) in [("expired", expired), ("revoked", revoked)] {
        let (total, with_context) = device_context_of(&pool, workspace_id, session).await?;
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
        device_context_of(&pool, workspace_id, live).await?,
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
    let mut tx = pool.begin().await?;
    arm(&mut tx, workspace_id).await?;
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
    .execute(&mut *tx)
    .await?;

    // PREMISE: the row holding the context really is revoked, so a row-level
    // scrub WOULD erase it and this test is not passing by accident. Read on
    // the SAME armed transaction as the insert above — `bool_or` over an empty
    // set is NULL, so a blind read would fail decoding into `bool` rather than
    // answering `false`, but an armed read that is proving a premise should not
    // be relying on that.
    let revoked_row_holds_context: bool = sqlx::query_scalar(
        "SELECT bool_or(revoked_at IS NOT NULL AND client_ip IS NOT NULL)
         FROM refresh_tokens WHERE session_id = $1",
    )
    .bind(session_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    assert!(
        revoked_row_holds_context,
        "premise: the device context must sit on a REVOKED row, which is what \
         makes the chain-level decision necessary"
    );

    run(&pool, &ch_client()).await;

    let (total, with_context) = device_context_of(&pool, workspace_id, session_id).await?;
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

    // Read back what landed on disk, not what the writes claimed — and read
    // each shape through a lens that WOULD see it. `pool` is only a privileged
    // connection when `DATABASE_URL` names a superuser; under the runner it is
    // as filtered as `low`, so a bare read of the per-workspace row answers
    // nothing whether or not the row exists. That ambiguity is the disease this
    // whole file is about, so the two shapes are read separately.
    let global_scopes: Vec<String> = sqlx::query_scalar(
        "SELECT scope FROM retention_purge_audit
         WHERE run_id = $1 AND workspace_id IS NULL ORDER BY scope",
    )
    .bind(run_id)
    .fetch_all(&pool)
    .await?;
    assert_eq!(
        global_scopes,
        vec![
            SCOPE_SESSION_DEVICE_CONTEXT.to_owned(),
            SCOPE_TOKEN_VAULT.to_owned(),
        ],
        "both GLOBAL scopes must be on disk: `workspace_id IS NULL` satisfies \
         030's policy with nothing armed, so these are the rows that survive a \
         run in which arming a scope is what failed."
    );

    // The per-workspace row, read from ITS OWN armed scope — which is also the
    // control proving the read above is not simply blind, since the same
    // connection returns this row only once the scope is armed.
    let per_workspace =
        audit_rows_for_workspace(&pool, run_id, SCOPE_CONTENT_CAPTURES, workspace).await?;
    assert_eq!(
        per_workspace.len(),
        1,
        "a PER-WORKSPACE scope row must be on disk. Zero is the silent gap: the \
         purge ran and left no evidence."
    );
    assert_eq!(
        per_workspace[0].get::<Option<Uuid>, _>("workspace_id"),
        Some(workspace),
        "the per-workspace record must carry the workspace it is about — the \
         scope was armed to that workspace, not merely to something"
    );
    Ok(())
}

// ===========================================================================
// P1H — the capture sweep under a non-bypassing role
// ===========================================================================
//
// # The failure being measured
//
// `workspace_raw_capture` has been under FORCE ROW LEVEL SECURITY since
// migration 030. Migration 033 rewrote its `workspace_isolation` policy with
// `NULLIF`, which was the intended semantics and which removed the one face of
// the defect that shouted: an unscoped read no longer raises `22P02`, it
// returns the EMPTY SET.
//
// `purge_content_captures` reads that table ON A BARE POOL to learn each
// workspace's CURRENT retention. Under a NOSUPERUSER/NOBYPASSRLS role the read
// therefore answers `Ok(vec![])` — not an error — and the function builds one
// record PER SETTINGS ROW, so the result is an EMPTY vector.
// `PurgeOutcome::all_ok` is `records.iter().all(...)`, which is VACUOUSLY TRUE
// over the empty set. The job logs `retention.purge complete`, records
// `record_job(..., ok = true)`, and the captured PLAINTEXT PROMPTS — the most
// sensitive rows this product stores — are never purged and the audit trail
// does not even mention the scope.
//
// The three tests below are, in order: the plaintext survives while the job
// says `ok`; "nothing to do" is recorded and is distinguishable; "I could not
// see" is recorded and is NOT success.
//
// All fixture content is a synthetic ciphertext stand-in, never plaintext PII.

/// `workspace_raw_capture` is ARMED, so this INSERT is armed too. A bare-pool
/// fixture write would be refused with `42501` under the runner role, and the
/// suite could not run at all.
async fn set_capture_retention(
    pool: &PgPool,
    workspace_id: Uuid,
    retention_days: i32,
) -> sqlx::Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
        .bind(workspace_id.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO workspace_raw_capture (workspace_id, enabled, retention_days)
         VALUES ($1, true, $2)",
    )
    .bind(workspace_id)
    .bind(retention_days)
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

/// One workspace's configured retention, read FROM A SCOPE THAT WOULD SEE IT.
///
/// `None` means the row is genuinely absent, never "RLS hid it" — the caller
/// gets that guarantee only because this read arms the scope first. Every
/// absence premise below goes through here and is paired with a control
/// workspace whose row this same helper DOES return.
async fn armed_capture_retention(pool: &PgPool, workspace_id: Uuid) -> sqlx::Result<Option<i32>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
        .bind(workspace_id.to_string())
        .execute(&mut *tx)
        .await?;
    let days: Option<i32> = sqlx::query_scalar(
        "SELECT retention_days FROM workspace_raw_capture WHERE workspace_id = $1",
    )
    .bind(workspace_id)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(days)
}

/// Proof-of-purge rows for one scope, read from a scope that WOULD see them.
///
/// The bare-pool [`audit_rows`] above is fine for the two GLOBAL scopes, whose
/// `workspace_id IS NULL` satisfies 030's policy unarmed. It is NOT fine for a
/// per-workspace row: under the runner role a bare read returns nothing whether
/// the row exists or not, which is the exact ambiguity these tests are about.
async fn audit_rows_for_workspace(
    pool: &PgPool,
    run_id: Uuid,
    scope: &str,
    workspace_id: Uuid,
) -> sqlx::Result<Vec<sqlx::postgres::PgRow>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('app.current_workspace_id', $1, true)")
        .bind(workspace_id.to_string())
        .execute(&mut *tx)
        .await?;
    let rows = sqlx::query(
        "SELECT * FROM retention_purge_audit
         WHERE run_id = $1 AND scope = $2 AND workspace_id = $3
         ORDER BY completed_at",
    )
    .bind(run_id)
    .bind(scope)
    .bind(workspace_id)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(rows)
}

/// The run's ONE global record for the capture scope — the census that says the
/// sweep happened at all. `workspace_id IS NULL`, so a bare read sees it under
/// either role.
async fn capture_sweep_census(
    pool: &PgPool,
    run_id: Uuid,
) -> sqlx::Result<Vec<sqlx::postgres::PgRow>> {
    sqlx::query(
        "SELECT * FROM retention_purge_audit
         WHERE run_id = $1 AND scope = $2 AND workspace_id IS NULL",
    )
    .bind(run_id)
    .bind(SCOPE_CONTENT_CAPTURES)
    .fetch_all(pool)
    .await
}

/// Postgres answering whether a policy will actually bind THIS connection on
/// THIS table — not a role attribute, and not a catalog flag.
async fn row_security_active(pool: &PgPool, table: &str) -> sqlx::Result<bool> {
    sqlx::query_scalar("SELECT row_security_active($1)")
        .bind(format!("public.{table}"))
        .fetch_one(pool)
        .await
}

/// Premise asserted by every test here: the low-privilege pool really is
/// filtered on the table the sweep reads. Without it a role that turned out to
/// bypass RLS would keep all three green while measuring nothing.
async fn assert_capture_settings_are_policed(low: &PgPool) {
    assert!(
        row_security_active(low, "workspace_raw_capture")
            .await
            .expect("row_security_active probe"),
        "premise: row security is not active on workspace_raw_capture for this \
         connection, so the sweep below runs unfiltered and measures nothing"
    );
}

/// THE DEFECT. Captured plaintext past the workspace's CURRENT retention must
/// be gone after a run under a role that cannot bypass RLS.
///
/// `all_ok()` is asserted BEFORE the deletion, deliberately: under migration
/// 033 this job's failure mode is SILENCE, not an error, so the RED failure
/// this test was written against reads "the job reported success and the
/// plaintext is still there" rather than "the job errored".
///
/// The 2-day-old capture is the POSITIVE CONTROL that must DIFFER: without it
/// the test would pass for a sweep that deleted the whole table.
#[sqlx::test(migrations = "../secureprompt-api/migrations")]
async fn captured_plaintext_is_purged_under_a_non_bypassing_role(pool: PgPool) -> sqlx::Result<()> {
    ensure_capture_table().await;
    let workspace_id = seed_workspace(&pool).await?;

    // Captured while retention was long; the operator has since lowered it.
    let old = Uuid::new_v4();
    let recent = Uuid::new_v4();
    insert_capture(workspace_id, old, 30).await;
    insert_capture(workspace_id, recent, 2).await;
    set_capture_retention(&pool, workspace_id, 7).await?;

    // ── PRE-STATE.
    assert_eq!(
        armed_capture_retention(&pool, workspace_id).await?,
        Some(7),
        "premise: the workspace must have a retention setting the sweep could \
         act on. If this is None the test is measuring a missing fixture, not RLS."
    );
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
         ClickHouse's own TTL would not delete either and anything that \
         disappears did so because this job ran"
    );

    let low = low_privilege_pool(&pool).await;
    assert_capture_settings_are_policed(&low).await;

    let outcome = run(&low, &ch_client()).await;

    // The silent-success half of the defect. This assertion PASSED before the
    // fix, and that is the point: the job never signalled anything.
    assert!(
        outcome.all_ok(),
        "the purge reported a failure: {:?}. Under migration 033 the failure \
         mode of this job is silence, so an error here is a different bug.",
        outcome.records
    );

    // ── POST-STATE. This is the assertion that was RED.
    assert!(
        !capture_exists(old).await,
        "captured PLAINTEXT past the workspace's retention survived a run that \
         reported `ok`. Under a non-bypassing role the bare-pool read of \
         workspace_raw_capture returns the empty set, so the sweep visited no \
         workspace, produced no record, and `all_ok()` was vacuously true over \
         the empty set."
    );
    // POSITIVE CONTROL. Must DIFFER from the row above.
    assert!(
        capture_exists(recent).await,
        "the sweep deleted a 2-day-old capture under a 7-day retention — it is \
         deleting by something other than the configured window"
    );

    // The proof-of-purge trail names the tenant it acted on.
    let mine =
        audit_rows_for_workspace(&pool, outcome.run_id, SCOPE_CONTENT_CAPTURES, workspace_id)
            .await?;
    assert_eq!(
        mine.len(),
        1,
        "exactly one proof-of-purge record for this workspace's captured \
         content. Zero is the silent gap: the purge either did not happen or \
         left no evidence that it did."
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
    assert_eq!(mine[0].get::<String, _>("status"), "ok");
    Ok(())
}

/// "NOTHING TO DO", recorded as such.
///
/// Workspace A has capture switched off entirely — no `workspace_raw_capture`
/// row — and workspace B has one with nothing past its window. A run must:
/// report success, write the census record that says the scope RAN, write B's
/// per-workspace record with `rows_deleted = 0`, and write NO record for A.
///
/// The ABSENCE of A's settings row is asserted from a scope that WOULD see it,
/// with B's row — read by the SAME helper, in the SAME run, under the SAME
/// role — as the control proving that scope is not simply blind. Without that
/// pair, "A has no settings" and "RLS hid A's settings" are the same
/// observation, which is the disease this whole change is about.
#[sqlx::test(migrations = "../secureprompt-api/migrations")]
async fn a_capture_sweep_with_nothing_to_do_still_records_the_scope(
    pool: PgPool,
) -> sqlx::Result<()> {
    ensure_capture_table().await;
    let unconfigured = seed_workspace(&pool).await?;
    let configured = seed_workspace(&pool).await?;
    set_capture_retention(&pool, configured, 7).await?;

    // Inside the window: nothing for the sweep to delete anywhere.
    let inside = Uuid::new_v4();
    insert_capture(configured, inside, 2).await;

    // ── PREMISE PAIR. The control first, so the absence below means absence.
    assert_eq!(
        armed_capture_retention(&pool, configured).await?,
        Some(7),
        "premise/control: the configured workspace's settings row must be \
         VISIBLE from its own armed scope, or the None below proves nothing"
    );
    assert_eq!(
        armed_capture_retention(&pool, unconfigured).await?,
        None,
        "premise: the unconfigured workspace must genuinely have no settings row"
    );
    assert_ne!(
        unconfigured, configured,
        "premise: the two fixtures must be different workspaces"
    );

    let low = low_privilege_pool(&pool).await;
    assert_capture_settings_are_policed(&low).await;

    let outcome = run(&low, &ch_client()).await;

    assert!(
        outcome.all_ok(),
        "a run with nothing eligible must still succeed: {:?}",
        outcome.records
    );
    assert!(
        capture_exists(inside).await,
        "the sweep deleted a capture inside its retention window on a run that \
         had nothing to do"
    );

    // THE CENSUS. This is what makes "nothing to do" distinguishable from "I
    // could not see anything": the scope is named in the trail on every run,
    // whether or not any workspace had work.
    let census = capture_sweep_census(&pool, outcome.run_id).await?;
    assert_eq!(
        census.len(),
        1,
        "the run must write exactly one global census record for the capture \
         scope. Zero means the trail simply OMITS the scope, and an absence is \
         harder to notice than a row that says nothing happened."
    );
    assert_eq!(
        census[0].get::<String, _>("status"),
        "ok",
        "the sweep could read every workspace's settings, so its census must \
         say so"
    );
    assert_eq!(
        census[0].get::<i64, _>("rows_deleted"),
        0,
        "the census deletes nothing itself; the per-workspace records carry the \
         counts and total_deleted() must not double-count them"
    );

    let for_configured =
        audit_rows_for_workspace(&pool, outcome.run_id, SCOPE_CONTENT_CAPTURES, configured).await?;
    assert_eq!(
        for_configured.len(),
        1,
        "the configured workspace was swept and must have its own record"
    );
    assert_eq!(
        for_configured[0].get::<i64, _>("rows_deleted"),
        0,
        "nothing was past the window, so nothing may be reported as deleted"
    );
    assert_eq!(for_configured[0].get::<String, _>("status"), "ok");

    // And no record for the workspace that has capture switched off — read
    // from ITS armed scope, so this absence is an absence.
    let for_unconfigured =
        audit_rows_for_workspace(&pool, outcome.run_id, SCOPE_CONTENT_CAPTURES, unconfigured)
            .await?;
    assert!(
        for_unconfigured.is_empty(),
        "a workspace with no capture settings has nothing to purge and must not \
         get a proof-of-purge record, got {} of them",
        for_unconfigured.len()
    );
    Ok(())
}

/// "I COULD NOT SEE ANYTHING" is NOT success.
///
/// The sweep enumerates `workspaces` on a bare pool, which is sound only
/// because that table is not policed. This test arms it — the future migration
/// the enumeration's comment warns about — and requires the run to FAIL rather
/// than sweep zero workspaces and report `ok`.
///
/// It is the exact counterpart of the test above: same code path, same role,
/// and the outcome record must DIFFER. Without this pair the census record
/// would be a constant that says `ok` no matter what the job could see.
///
/// PREMISES: the workspace IS enumerable before arming and is NOT after (the
/// before/after pair is what makes the second reading mean "hidden"), and there
/// really was work to do — a past-retention capture row and a settings row
/// saying so — so `ok` would be a lie rather than a technicality.
#[sqlx::test(migrations = "../secureprompt-api/migrations")]
async fn a_capture_sweep_that_cannot_enumerate_workspaces_fails_loudly(
    pool: PgPool,
) -> sqlx::Result<()> {
    ensure_capture_table().await;
    let workspace_id = seed_workspace(&pool).await?;
    set_capture_retention(&pool, workspace_id, 7).await?;

    let doomed = Uuid::new_v4();
    insert_capture(workspace_id, doomed, 30).await;

    let low = low_privilege_pool(&pool).await;
    assert_capture_settings_are_policed(&low).await;

    // ── PREMISE: there is real work. Both halves, or `ok` could be honest.
    assert_eq!(
        armed_capture_retention(&pool, workspace_id).await?,
        Some(7),
        "premise: the workspace must have a retention setting"
    );
    assert!(
        capture_exists(doomed).await,
        "premise: a 30-day-old capture must exist to be past a 7-day retention"
    );

    // ── PREMISE/CONTROL: the enumeration WORKS before the table is armed.
    let visible_before: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM workspaces")
        .fetch_all(&low)
        .await?;
    assert!(
        visible_before.contains(&workspace_id),
        "premise: the low-privilege pool must be able to enumerate workspaces \
         BEFORE the table is armed, or the empty reading afterwards is not \
         caused by what this test thinks"
    );

    // The future migration. No policy at all, so ENABLE alone is default-deny
    // for a non-owner; FORCE covers the case where the connecting role owns the
    // table, which it does when DATABASE_URL is already the runner.
    sqlx::raw_sql(
        "ALTER TABLE workspaces ENABLE ROW LEVEL SECURITY;
         ALTER TABLE workspaces FORCE ROW LEVEL SECURITY;",
    )
    .execute(&pool)
    .await?;

    assert!(
        row_security_active(&low, "workspaces").await?,
        "premise: arming workspaces did not make row security active for the \
         low-privilege pool, so the enumeration below is not actually filtered"
    );
    let visible_after: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM workspaces")
        .fetch_all(&low)
        .await?;
    assert!(
        visible_after.is_empty(),
        "premise: the armed table must hide every workspace from this pool, \
         got {visible_after:?}"
    );

    let outcome = run(&low, &ch_client()).await;

    // THE POINT. Sweeping zero workspaces because it cannot read them is not
    // success.
    assert!(
        !outcome.all_ok(),
        "the purge reported SUCCESS while it could not see a single workspace. \
         There was a settings row and a past-retention capture, so this run \
         did nothing and said it was fine: {:?}",
        outcome.records
    );

    // FAIL CLOSED: an unreadable settings table must never be read as
    // `retention is zero, delete everything`.
    assert!(
        capture_exists(doomed).await,
        "the sweep deleted captured content while it could not read the \
         retention that governs it"
    );

    let census = capture_sweep_census(&pool, outcome.run_id).await?;
    assert_eq!(
        census.len(),
        1,
        "the failure must still be recorded — a run that could not see is the \
         one an auditor most needs in the trail"
    );
    assert_eq!(
        census[0].get::<String, _>("status"),
        "error",
        "the census must DIFFER from the succeeding run's; a constant `ok` \
         would make the record worthless"
    );
    assert!(
        census[0]
            .get::<Option<String>, _>("error")
            .is_some_and(|e| e.contains("workspaces")),
        "the recorded error must name what could not be read, got {:?}",
        census[0].get::<Option<String>, _>("error")
    );
    Ok(())
}
