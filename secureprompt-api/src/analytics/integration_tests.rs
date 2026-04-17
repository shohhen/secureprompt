//! Integration tests for the ClickHouse analytics write path.
//! These tests require a live ClickHouse instance (see docker-compose.yml).
//! Run with: cargo test -p secureprompt-api analytics --lib
//!
//! Requirements covered: CH-01 (tables created + insert round-trip), CH-03 (batch sizing)

#[cfg(test)]
mod tests {
    // CH-01: request_events insert round-trip
    // Filled in by 04-02-PLAN.md (requires AnalyticsHandle with real Client)
    #[tokio::test]
    #[ignore = "requires live ClickHouse — run with --include-ignored"]
    async fn test_request_event_insert_round_trip() {
        // TODO(04-02): use build_clickhouse_client, insert one RequestEvent, verify row count
        todo!("implement after AnalyticsHandle is wired in 04-02")
    }

    // CH-03: Inserter respects max_rows=100 batch threshold
    #[tokio::test]
    #[ignore = "requires live ClickHouse — run with --include-ignored"]
    async fn test_inserter_batch_size_threshold() {
        // TODO(04-02): insert 101 events, assert Inserter committed after 100 rows
        todo!("implement after AnalyticsHandle is wired in 04-02")
    }

    // POL-04: policy_events rows de-normalized from Vec<PolicyEvent>
    #[tokio::test]
    #[ignore = "requires live ClickHouse — run with --include-ignored"]
    async fn test_policy_events_denormalization() {
        // TODO(04-02): RequestEvent with 2 PolicyEvents → 2 policy_events rows
        todo!("implement after AnalyticsHandle is wired in 04-02")
    }
}
