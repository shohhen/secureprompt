pub mod capture;
pub mod clickhouse_writer;
pub mod dashboard_reader;
// WS3-6 — the class allowlist that keeps `detection_class_counts` content-free.
pub mod detection_counts;
// WS2-4 — which detection engines produced coverage for a request.
pub mod engines;
pub mod events;
pub mod serde_helpers;

pub use clickhouse_writer::AnalyticsHandle;
pub use dashboard_reader::DashboardReader;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod integration_tests;
