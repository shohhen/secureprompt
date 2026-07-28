//! WS2-3 — the ClickHouse startup schema probe and the analytics writer's
//! behaviour around it.
//!
//! These live in an INTEGRATION binary, not the lib, on purpose. They require
//! a live ClickHouse, and lib tests run on every `cargo test --lib` where an
//! integration binary can be scheduled deliberately. There is no skip path:
//! a skip that hides a missing dependency is how a broken probe would ship
//! looking green. If ClickHouse is not reachable these FAIL, loudly, naming
//! `CLICKHOUSE_URL`.

use secureprompt_api::analytics::clickhouse_writer::{
    build_clickhouse_client, verify_request_events_schema, AnalyticsHandle, REQUEST_EVENTS_COLUMNS,
};
use secureprompt_api::analytics::events::RequestEvent;
use secureprompt_api::observability::metrics::MetricsRegistry;
use secureprompt_common::types::{RequestId, TokenUsage, WorkspaceId};
use std::sync::Arc;

fn ch_url() -> String {
    std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://localhost:8123".to_owned())
}

/// Raw HTTP so fixture setup does not depend on the very client under test.
async fn exec(sql: &str) {
    exec_in("default", sql).await;
}

/// As `exec`, but with a target database (ClickHouse rejects `USE x; …` —
/// multi-statements are not allowed over HTTP).
async fn exec_in(database: &str, sql: &str) {
    let response = reqwest::Client::new()
        .post(format!("{}/?database={database}", ch_url()))
        .body(sql.to_owned())
        .send()
        .await
        .expect("ClickHouse must be reachable — set CLICKHOUSE_URL (see the task env)");
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "clickhouse ddl failed ({status}): {body}\nsql: {sql}"
    );
}

/// Scratch database that drops itself even if the test panics.
///
/// Without this, a panic between CREATE and DROP leaks `sp_probe_*` databases
/// on a shared ClickHouse instance forever.
struct ScratchDb {
    name: String,
}

impl ScratchDb {
    async fn create(prefix: &str) -> Self {
        let name = format!("{prefix}_{}", uuid::Uuid::new_v4().simple());
        exec(&format!("CREATE DATABASE IF NOT EXISTS {name}")).await;
        Self { name }
    }

    /// Clone the REAL production table, so RowBinary inserts actually
    /// succeed. A hand-rolled all-`String` table cannot accept the typed
    /// values `RequestEventRow` serialises (UUID, u32, DateTime), so a commit
    /// against one always fails and could never demonstrate the gauge
    /// clearing.
    async fn create_request_events_like_production(&self) {
        // Apply ClickHouse migration 006 first: the source table needs
        // `floor_only` or the clone inherits a stale schema. Idempotent, and
        // read from the migration file so it cannot drift.
        const MIGRATION: &str = include_str!("../clickhouse/migrations/006_floor_only.sql");
        let sql: String = MIGRATION
            .lines()
            .filter(|l| !l.trim_start().starts_with("--"))
            .collect::<Vec<_>>()
            .join("\n");
        for statement in sql.split(';') {
            if !statement.trim().is_empty() {
                exec_in("sp_analytics", statement.trim()).await;
            }
        }
        exec(&format!(
            "CREATE TABLE IF NOT EXISTS {}.request_events AS sp_analytics.request_events",
            self.name
        ))
        .await;
    }

    /// Production shape, minus one column. Everything else keeps its real
    /// type, so `ALTER TABLE ... ADD COLUMN` genuinely repairs the layout —
    /// unlike the all-`String` fixture, where adding `floor_only` leaves every
    /// other column still mistyped and `to_row` still failing.
    async fn create_request_events_missing(&self, column: &str) {
        self.create_request_events_like_production().await;
        exec_in(
            &self.name,
            &format!("ALTER TABLE request_events DROP COLUMN IF EXISTS {column}"),
        )
        .await;
    }

    async fn create_request_events(&self, columns: &[&str]) {
        let cols = columns
            .iter()
            .map(|c| format!("{c} String"))
            .collect::<Vec<_>>()
            .join(", ");
        exec(&format!(
            "CREATE TABLE IF NOT EXISTS {}.request_events ({cols}) \
             ENGINE = MergeTree ORDER BY tuple()",
            self.name
        ))
        .await;
    }
}

impl Drop for ScratchDb {
    fn drop(&mut self) {
        // `Drop` cannot await, and this must run on the panic path too, so the
        // cleanup gets its own thread with its own current-thread runtime.
        // Without it, a panic between CREATE and DROP leaks the database on a
        // shared ClickHouse forever.
        let name = self.name.clone();
        let url = ch_url();
        let _ = std::thread::spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            runtime.block_on(async move {
                let _ = reqwest::Client::new()
                    .post(format!("{url}/"))
                    .body(format!("DROP DATABASE IF EXISTS {name}"))
                    .send()
                    .await;
            });
        })
        .join();
    }
}

/// The probe must flag a table missing a column the writer serialises — the
/// state in which every analytics event is dropped wholesale because the
/// worker has not run its migrations.
///
/// POSITIVE CONTROL is the second half: the same probe against a complete
/// table must leave the gauge at 0. Without it, "the gauge is 1" would be
/// satisfied by a probe that flags unconditionally.
#[tokio::test]
async fn probe_flags_a_stale_schema_and_passes_a_complete_one() {
    let stale = ScratchDb::create("sp_probe_stale").await;
    let complete = ScratchDb::create("sp_probe_good").await;

    let without_floor_only: Vec<&str> = REQUEST_EVENTS_COLUMNS
        .iter()
        .filter(|c| **c != "floor_only")
        .copied()
        .collect();
    stale.create_request_events(&without_floor_only).await;
    complete.create_request_events(REQUEST_EVENTS_COLUMNS).await;

    let stale_metrics = Arc::new(MetricsRegistry::default());
    assert_eq!(
        stale_metrics.clickhouse_schema_mismatch_count(),
        0,
        "premise: a fresh registry starts clean"
    );
    verify_request_events_schema(
        &build_clickhouse_client(&ch_url(), &stale.name),
        &stale_metrics,
    )
    .await;
    assert_eq!(
        stale_metrics.clickhouse_schema_mismatch_count(),
        1,
        "a request_events missing floor_only must raise the gauge"
    );

    let good_metrics = Arc::new(MetricsRegistry::default());
    verify_request_events_schema(
        &build_clickhouse_client(&ch_url(), &complete.name),
        &good_metrics,
    )
    .await;
    assert_eq!(
        good_metrics.clickhouse_schema_mismatch_count(),
        0,
        "a table with every required column must NOT be flagged"
    );
}

/// "Migrations never ran at all".
#[tokio::test]
async fn probe_flags_a_missing_table() {
    let empty = ScratchDb::create("sp_probe_empty").await;

    let metrics = Arc::new(MetricsRegistry::default());
    verify_request_events_schema(&build_clickhouse_client(&ch_url(), &empty.name), &metrics).await;
    assert_eq!(
        metrics.clickhouse_schema_mismatch_count(),
        1,
        "no request_events table at all must raise the gauge"
    );
}

fn sample_event() -> RequestEvent {
    RequestEvent::new(
        RequestId::new(),
        WorkspaceId(uuid::Uuid::new_v4()),
        "anthropic".to_owned(),
        "claude-3-haiku".to_owned(),
        "allow".to_owned(),
        &TokenUsage::default(),
        false,
        0.0,
        Vec::new(),
    )
}

/// Fix round 3, BLOCKER 3 — the probe must not sit between the writer task
/// starting and its `recv()` loop.
///
/// The previous test for this wrapped the probe in its OWN 2s timeout and
/// asserted the fixture hangs; deleting the production wrapper left it green.
///
/// This one drives the REAL `AnalyticsHandle` against a ClickHouse that
/// accepts connections and never answers, and asserts the receive loop
/// actually consumed something. Awaited inline, the loop cannot reach
/// `recv()` for the whole 10s probe timeout, so `consumed` stays 0.
///
/// `analytics_dropped_count` is deliberately NOT the observable here: with a
/// 256-slot channel the consumer is network-bound on its first event either
/// way, so drop counts come out identical (measured: 143 both ways) and
/// cannot falsify anything.
#[tokio::test]
async fn writer_starts_consuming_while_clickhouse_hangs() {
    // Accepts, then never replies and never closes.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept() {
            held.push(stream);
        }
    });

    let metrics = Arc::new(MetricsRegistry::default());
    let handle = AnalyticsHandle::new(metrics.clone(), &format!("http://{addr}"), "default");

    assert_eq!(
        metrics.analytics_consumed_count(),
        0,
        "premise: nothing consumed before anything is enqueued"
    );

    for _ in 0..8 {
        handle.enqueue(sample_event(), metrics.as_ref()).await;
    }
    // Let the writer task be polled. Generous relative to the work involved,
    // tiny relative to the 10s probe timeout it must not be waiting on.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    assert!(
        metrics.analytics_consumed_count() >= 1,
        "the receive loop must be running even though ClickHouse hangs; a \
         probe awaited ahead of recv() blocks it for the whole probe timeout"
    );
}

/// POSITIVE CONTROL for the test above: the same assertion against a
/// REACHABLE ClickHouse. Proves `analytics_consumed_count` moves at all, so
/// "it is >= 1" is a property of the loop running rather than of the counter
/// being trivially satisfiable.
#[tokio::test]
async fn writer_consumes_against_a_healthy_clickhouse() {
    let db = ScratchDb::create("sp_probe_healthy").await;
    db.create_request_events_like_production().await;

    let metrics = Arc::new(MetricsRegistry::default());
    let handle = AnalyticsHandle::new(metrics.clone(), &ch_url(), &db.name);

    for _ in 0..8 {
        handle.enqueue(sample_event(), metrics.as_ref()).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    assert!(
        metrics.analytics_consumed_count() >= 1,
        "the writer must consume from a healthy ClickHouse too"
    );
}

/// A gauge raised by the startup probe must be lowered once writes actually
/// succeed — that is how the system self-heals without an API restart.
///
/// This replaces a round-3 test that asserted the opposite ("a buffered write
/// proves nothing about the schema; the gauge must stay raised"). That
/// assertion encoded the wrong model of the client: with validation enabled —
/// which is our configuration — a successful `write` has already round-tripped
/// a DESCRIBE and validated the row layout, so it proves precisely what the
/// old test denied.
///
/// Deletion check: removing the `clear_clickhouse_schema_mismatch()` on the
/// write-success arm turns this red.
#[tokio::test]
async fn a_successful_write_lowers_a_probe_raised_gauge() {
    let db = ScratchDb::create("sp_probe_gauge").await;
    db.create_request_events_like_production().await;

    let metrics = Arc::new(MetricsRegistry::default());
    // Simulate the startup probe having flagged a stale schema.
    metrics.record_clickhouse_schema_mismatch();
    assert_eq!(
        metrics.clickhouse_schema_mismatch_count(),
        1,
        "premise: the gauge starts raised"
    );

    let handle = AnalyticsHandle::new(metrics.clone(), &ch_url(), &db.name);
    for _ in 0..4 {
        handle.enqueue(sample_event(), metrics.as_ref()).await;
    }

    let mut cleared = false;
    for _ in 0..40 {
        if metrics.clickhouse_schema_mismatch_count() == 0 {
            cleared = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(
        cleared,
        "a write the server validated and accepted must lower the gauge"
    );
}

// ── Fix round 4: where a stale schema actually surfaces ───────────────────
//
// Round 3 put the gauge logic on the commit path on the strength of reading
// `Inserter::write` in the crate source and concluding it was buffer-only.
// That reading ignored OUR configuration: `build_clickhouse_client` never
// calls `.with_validation(false)` and clickhouse 0.15 defaults validation to
// true, so `write` -> `init_insert` -> `insert_unescaped` -> a DESCRIBE
// round-trip -> `to_row::<T>()` -> `Error::SchemaMismatch`. The stale schema
// errors at WRITE, and the `continue` on the retry path skips the commit
// block entirely, so the gauge was never touched.

/// A stale table must raise the gauge, from the write path.
///
/// Deletion check: removing the `SchemaMismatch` arm turns this red.
#[tokio::test]
async fn stale_schema_raises_the_gauge_from_the_write_path() {
    // All the right column NAMES, all the wrong TYPES. The startup probe only
    // compares names, so it passes; `to_row::<RequestEventRow>()` still fails
    // because UUID/u32/DateTime cannot be written into String columns.
    //
    // This isolation matters: with a missing-column table BOTH the probe and
    // the write path raise the gauge, so the test would pass even with the
    // write path doing nothing — which is precisely how the first draft of
    // this test passed against the unfixed code.
    let db = ScratchDb::create("sp_probe_writepath").await;
    db.create_request_events(REQUEST_EVENTS_COLUMNS).await;

    let metrics = Arc::new(MetricsRegistry::default());

    // Premise: the PROBE is satisfied by this table, so anything the gauge
    // reports afterwards came from the write path.
    verify_request_events_schema(&build_clickhouse_client(&ch_url(), &db.name), &metrics).await;
    assert_eq!(
        metrics.clickhouse_schema_mismatch_count(),
        0,
        "premise: the name-based probe must NOT flag this table, so the write \
         path is the only thing that can raise the gauge"
    );

    let handle = AnalyticsHandle::new(metrics.clone(), &ch_url(), &db.name);
    for _ in 0..4 {
        handle.enqueue(sample_event(), metrics.as_ref()).await;
    }

    let mut raised = false;
    for _ in 0..40 {
        if metrics.clickhouse_schema_mismatch_count() == 1 {
            raised = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(
        raised,
        "a row layout the server rejects must raise the schema gauge; \
         insert_failures={}",
        metrics.clickhouse_insert_failure_count()
    );
}

/// POSITIVE CONTROL that must differ: the same traffic against a
/// production-shaped table must leave the gauge at 0. Without this, "the gauge
/// is 1" would be satisfied by code that raises it on any write at all.
#[tokio::test]
async fn healthy_schema_leaves_the_gauge_clear() {
    let db = ScratchDb::create("sp_probe_writepath_ok").await;
    db.create_request_events_like_production().await;

    let metrics = Arc::new(MetricsRegistry::default());
    let handle = AnalyticsHandle::new(metrics.clone(), &ch_url(), &db.name);
    for _ in 0..4 {
        handle.enqueue(sample_event(), metrics.as_ref()).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;

    assert_eq!(
        metrics.clickhouse_schema_mismatch_count(),
        0,
        "a compatible schema must never raise the gauge"
    );
}

/// A TRANSPORT failure is not a schema failure. Round 3 raised the gauge on
/// any commit error, which would page an operator with a CRITICAL "run your
/// migrations" alert for a 5s insert timeout or a connection reset.
///
/// Deletion check: removing the `SchemaMismatch` discrimination (raising on
/// every write error) turns this red.
#[tokio::test]
async fn transport_failure_does_not_raise_the_schema_gauge() {
    // Nothing listening.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);

    let metrics = Arc::new(MetricsRegistry::default());
    let handle = AnalyticsHandle::new(metrics.clone(), &format!("http://{addr}"), "default");
    for _ in 0..4 {
        handle.enqueue(sample_event(), metrics.as_ref()).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;

    assert!(
        metrics.clickhouse_insert_failure_count() > 0,
        "premise: the writes must actually be failing, or this proves nothing"
    );
    assert_eq!(
        metrics.clickhouse_schema_mismatch_count(),
        0,
        "an unreachable ClickHouse is a transport problem, not a stale schema; \
         raising a CRITICAL migrations alert here is a false page"
    );
}

/// The writer must recover once the worker runs the migration, without an API
/// restart. `InsertMetadata` is cached per table, so without an explicit
/// `clear_cached_metadata()` the client keeps validating against the schema it
/// fetched at startup and can never notice the new column.
///
/// Deletion check: removing the `clear_cached_metadata().await` call turns
/// this red.
#[tokio::test]
async fn writer_recovers_after_the_schema_is_migrated() {
    let db = ScratchDb::create("sp_probe_recover").await;
    db.create_request_events_missing("floor_only").await;

    let metrics = Arc::new(MetricsRegistry::default());
    let handle = AnalyticsHandle::new(metrics.clone(), &ch_url(), &db.name);

    for _ in 0..4 {
        handle.enqueue(sample_event(), metrics.as_ref()).await;
    }
    let mut raised = false;
    for _ in 0..40 {
        if metrics.clickhouse_schema_mismatch_count() == 1 {
            raised = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(
        raised,
        "premise: the gauge must be raised before recovery is meaningful"
    );

    // The worker runs its migration.
    exec_in(
        &db.name,
        "ALTER TABLE request_events ADD COLUMN IF NOT EXISTS floor_only Bool DEFAULT false",
    )
    .await;

    for _ in 0..8 {
        handle.enqueue(sample_event(), metrics.as_ref()).await;
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }

    let mut cleared = false;
    for _ in 0..60 {
        if metrics.clickhouse_schema_mismatch_count() == 0 {
            cleared = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(
        cleared,
        "the writer must notice the migrated schema without an API restart; \
         cached InsertMetadata has to be invalidated"
    );
}
