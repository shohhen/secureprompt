//! Tests for secureprompt-worker periodic jobs and ClickHouse schema migration.
//! Requirements covered: CH-05 (MV aggregation), schema migration idempotency

#[cfg(test)]
mod tests {
    // CH-05: mv_hourly_cost aggregates correctly
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires live ClickHouse — run with --include-ignored"]
    async fn test_mv_hourly_cost_aggregation() {
        // TODO(04-03): insert request_events, wait for MV to populate, query mv_hourly_cost_agg
        todo!("implement after worker is wired in 04-03")
    }

    // Schema migration idempotency: running apply_migrations twice must not error
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires live ClickHouse — run with --include-ignored"]
    async fn test_migration_idempotency() {
        // TODO(04-03): call apply_migrations twice against test ClickHouse; assert no error on second call
        todo!("implement after apply_migrations is implemented in 04-03")
    }
}
