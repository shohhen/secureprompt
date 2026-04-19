//! Phase 6 / Plan 06-04 — Redis task queue types (RDS-03, D-20, D-21).
//!
//! Defines the canonical task envelope pushed onto Redis lists by
//! `secureprompt-api` and consumed by `secureprompt-worker`.
//!
//! ## Design
//! - Queue names: `queue:analytics`, `queue:audit_export`, `queue:retention`
//! - Protocol: RPUSH (producer) / BLPOP (consumer)
//! - Envelope is a JSON-serialized `TaskEnvelope` — one envelope per Redis list element.
//! - Worker deserializes and dispatches on `task_type` string.
//!
//! ## Module imports
//! This module must remain dep-light: only serde, uuid, chrono, serde_json.
//! Do NOT import secureprompt-api types here — common crate cannot depend on api crate.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

// ── Queue name constants (D-20) ────────────────────────────────────────────────

/// Redis list key for analytics flush tasks.
pub const QUEUE_ANALYTICS: &str = "queue:analytics";

/// Redis list key for audit export tasks.
pub const QUEUE_AUDIT_EXPORT: &str = "queue:audit_export";

/// Redis list key for data retention purge tasks.
pub const QUEUE_RETENTION: &str = "queue:retention";

/// All queue names as a slice — used by worker BLPOP call.
pub const ALL_QUEUES: [&str; 3] = [QUEUE_ANALYTICS, QUEUE_AUDIT_EXPORT, QUEUE_RETENTION];

// ── Task envelope (D-21) ───────────────────────────────────────────────────────

/// JSON envelope pushed onto Redis queue lists.
///
/// The worker deserializes this struct from each BLPOP result and dispatches
/// on `task_type` using the constants in `task_types`.
///
/// Field invariants:
/// - `task_type` MUST be one of the constants in the `task_types` sub-module.
/// - `retry_count` is incremented by the worker on transient failures (max 3).
/// - `created_at` is UTC timestamp at enqueue time (not processing time).
/// - `payload` is task-specific; see `task_types` docs for shape per task type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskEnvelope {
    pub task_type: String,
    pub payload: Value,
    pub workspace_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub retry_count: u8,
}

impl TaskEnvelope {
    /// Construct a new envelope with `retry_count = 0` and `created_at = now()`.
    #[must_use]
    pub fn new(task_type: impl Into<String>, payload: Value, workspace_id: Uuid) -> Self {
        Self {
            task_type: task_type.into(),
            payload,
            workspace_id,
            created_at: Utc::now(),
            retry_count: 0,
        }
    }

    /// Increment `retry_count` for requeue on transient failure.
    #[must_use]
    pub fn with_retry(mut self) -> Self {
        self.retry_count = self.retry_count.saturating_add(1);
        self
    }
}

// ── Well-known task type string constants ─────────────────────────────────────

/// String constants for `TaskEnvelope::task_type`.
/// Use these instead of raw strings to prevent typos.
pub mod task_types {
    /// Push buffered analytics rows to ClickHouse.
    pub const ANALYTICS_FLUSH: &str = "analytics.flush";

    /// Export audit events to long-term storage.
    pub const AUDIT_EXPORT: &str = "audit.export";

    /// Purge records past the configured retention window.
    pub const RETENTION_PURGE: &str = "retention.purge";

    /// Move expired-grace-window API keys from 'rotating' to 'revoked'.
    /// (Worker can also handle this inline, but the task type is defined
    /// here for symmetry with the cron approach in Plan 06-01 Task 3.)
    pub const API_KEY_ROTATION_CLEANUP: &str = "api_key.rotation_cleanup";
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use uuid::Uuid;

    #[test]
    fn envelope_roundtrips_through_json() {
        let ws = Uuid::new_v4();
        let original = TaskEnvelope::new(
            task_types::ANALYTICS_FLUSH,
            json!({"rows": 42}),
            ws,
        );
        let serialized = serde_json::to_string(&original).expect("serialize");
        let deserialized: TaskEnvelope = serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(deserialized.task_type, task_types::ANALYTICS_FLUSH);
        assert_eq!(deserialized.workspace_id, ws);
        assert_eq!(deserialized.retry_count, 0);
    }

    #[test]
    fn with_retry_increments_count() {
        let ws = Uuid::new_v4();
        let env = TaskEnvelope::new("test", json!({}), ws);
        let retried = env.with_retry();
        assert_eq!(retried.retry_count, 1);
    }

    #[test]
    fn all_queues_covers_three_queues() {
        assert_eq!(ALL_QUEUES.len(), 3);
        assert!(ALL_QUEUES.contains(&QUEUE_ANALYTICS));
        assert!(ALL_QUEUES.contains(&QUEUE_AUDIT_EXPORT));
        assert!(ALL_QUEUES.contains(&QUEUE_RETENTION));
    }
}
