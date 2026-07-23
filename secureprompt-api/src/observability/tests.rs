/// Tests for observability: metrics registry and structured tracing functions.
///
/// Covers:
///   - MetricsRegistry::record_request increments correct counters
///   - MetricsRegistry::record_analytics_drop increments drop counter
///   - MetricsRegistry::record_analytics_failure increments failure counter
///   - render_prometheus output contains required metric names and workspace_id-ready format
///   - Tracing functions emit structured logs with request_id, workspace_id, rule_id context
///   - Counters are independent (recording one does not affect others)

#[cfg(test)]
mod observability_tests {
    use super::super::{
        metrics::MetricsRegistry,
        tracing::{log_policy_event, log_request_finish, log_request_start},
    };
    use secureprompt_common::types::{RequestId, WorkspaceId};
    use uuid::Uuid;

    // ── MetricsRegistry counters ──────────────────────────────────────────────

    #[test]
    fn record_request_success_increments_total_only() {
        let registry = MetricsRegistry::default();
        registry.record_request(true);
        let output = registry.render_prometheus();
        assert!(
            output.contains("secureprompt_requests_total 1"),
            "requests_total should be 1 after one success"
        );
        assert!(
            output.contains("secureprompt_request_failures_total 0"),
            "failures should still be 0 after success"
        );
    }

    #[test]
    fn record_request_failure_increments_both_counters() {
        let registry = MetricsRegistry::default();
        registry.record_request(false);
        let output = registry.render_prometheus();
        assert!(
            output.contains("secureprompt_requests_total 1"),
            "requests_total should be 1"
        );
        assert!(
            output.contains("secureprompt_request_failures_total 1"),
            "failures_total should be 1 after failure"
        );
    }

    #[test]
    fn record_analytics_drop_increments_drop_counter() {
        let registry = MetricsRegistry::default();
        registry.record_analytics_drop();
        registry.record_analytics_drop();
        let output = registry.render_prometheus();
        assert!(
            output.contains("secureprompt_analytics_dropped_total 2"),
            "dropped counter should be 2"
        );
    }

    #[test]
    fn record_analytics_failure_increments_failure_counter() {
        let registry = MetricsRegistry::default();
        registry.record_analytics_failure();
        let output = registry.render_prometheus();
        assert!(
            output.contains("secureprompt_analytics_failures_total 1"),
            "analytics failure counter should be 1"
        );
    }

    #[test]
    fn counters_are_independent_of_each_other() {
        let registry = MetricsRegistry::default();
        // Record only a drop — request and failure counters must stay 0
        registry.record_analytics_drop();
        let output = registry.render_prometheus();
        assert!(output.contains("secureprompt_requests_total 0"));
        assert!(output.contains("secureprompt_request_failures_total 0"));
        assert!(output.contains("secureprompt_analytics_failures_total 0"));
        assert!(output.contains("secureprompt_analytics_dropped_total 1"));
    }

    #[test]
    fn counter_accumulates_across_multiple_calls() {
        let registry = MetricsRegistry::default();
        for _ in 0..5 {
            registry.record_request(true);
        }
        let output = registry.render_prometheus();
        assert!(
            output.contains("secureprompt_requests_total 5"),
            "counter should accumulate: {output}"
        );
    }

    // ── render_prometheus format ──────────────────────────────────────────────

    #[test]
    fn render_prometheus_includes_type_annotations() {
        let registry = MetricsRegistry::default();
        let output = registry.render_prometheus();
        assert!(output.contains("# TYPE secureprompt_requests_total counter"));
        assert!(output.contains("# TYPE secureprompt_request_failures_total counter"));
        assert!(output.contains("# TYPE secureprompt_analytics_dropped_total counter"));
        assert!(output.contains("# TYPE secureprompt_analytics_failures_total counter"));
    }

    #[test]
    fn render_prometheus_contains_all_four_metric_names() {
        let registry = MetricsRegistry::default();
        let output = registry.render_prometheus();
        assert!(output.contains("secureprompt_requests_total"));
        assert!(output.contains("secureprompt_request_failures_total"));
        assert!(output.contains("secureprompt_analytics_dropped_total"));
        assert!(output.contains("secureprompt_analytics_failures_total"));
    }

    #[test]
    fn render_prometheus_fresh_registry_all_counters_zero() {
        let registry = MetricsRegistry::default();
        let output = registry.render_prometheus();
        assert!(output.contains("secureprompt_requests_total 0"));
        assert!(output.contains("secureprompt_request_failures_total 0"));
        assert!(output.contains("secureprompt_analytics_dropped_total 0"));
        assert!(output.contains("secureprompt_analytics_failures_total 0"));
    }

    // ── KPI-2 monitoring, Task 2 — request-duration histogram ─────────────────

    #[test]
    fn observe_request_duration_renders_bucket_sum_and_count() {
        let registry = MetricsRegistry::default();
        registry.observe_request_duration("gpt-4o", std::time::Duration::from_millis(20));
        let output = registry.render_prometheus();
        assert!(
            output.contains("# TYPE secureprompt_request_duration_seconds histogram"),
            "missing TYPE line; got:\n{output}"
        );
        assert!(
            output.contains(
                "secureprompt_request_duration_seconds_bucket{model=\"gpt-4o\",le=\"+Inf\"} 1"
            ),
            "expected a +Inf bucket line for model=gpt-4o after one observe; got:\n{output}"
        );
        assert!(
            output.contains("secureprompt_request_duration_seconds_count{model=\"gpt-4o\"} 1"),
            "expected count=1 for model=gpt-4o; got:\n{output}"
        );
        assert_eq!(registry.request_duration_count("gpt-4o"), 1);
    }

    #[test]
    fn observe_request_duration_keeps_models_as_separate_series() {
        let registry = MetricsRegistry::default();
        registry.observe_request_duration("gpt-4o", std::time::Duration::from_millis(5));
        registry.observe_request_duration("unknown", std::time::Duration::from_millis(5));
        assert_eq!(registry.request_duration_count("gpt-4o"), 1);
        assert_eq!(registry.request_duration_count("unknown"), 1);
        assert_eq!(registry.request_duration_count("claude-3-5-haiku"), 0);
    }

    #[test]
    fn request_duration_absent_when_never_observed() {
        let registry = MetricsRegistry::default();
        let output = registry.render_prometheus();
        assert!(
            !output.contains("secureprompt_request_duration_seconds"),
            "a fresh registry must not emit the histogram family before any observe; got:\n{output}"
        );
    }

    // ── KPI-2 monitoring, Task 2 — policy-violation counter ────────────────────

    #[test]
    fn record_policy_violation_increments_labelled_counter() {
        let registry = MetricsRegistry::default();
        registry.record_policy_violation("block");
        let output = registry.render_prometheus();
        assert!(
            output.contains("# TYPE secureprompt_policy_violations_total counter"),
            "missing TYPE line; got:\n{output}"
        );
        assert!(
            output.contains("secureprompt_policy_violations_total{action=\"block\"} 1"),
            "expected action=block to be 1 after one record; got:\n{output}"
        );
        assert_eq!(registry.policy_violation_count("block"), 1);
    }

    #[test]
    fn record_policy_violation_keeps_actions_independent() {
        let registry = MetricsRegistry::default();
        registry.record_policy_violation("redact");
        registry.record_policy_violation("redact");
        registry.record_policy_violation("flag");
        let output = registry.render_prometheus();
        assert!(output.contains("secureprompt_policy_violations_total{action=\"redact\"} 2"));
        assert!(output.contains("secureprompt_policy_violations_total{action=\"flag\"} 1"));
        assert_eq!(registry.policy_violation_count("warn"), 0);
    }

    #[test]
    fn policy_violations_absent_when_never_recorded() {
        let registry = MetricsRegistry::default();
        let output = registry.render_prometheus();
        assert!(
            !output.contains("secureprompt_policy_violations_total"),
            "a fresh registry must not emit the counter family before any record; got:\n{output}"
        );
    }

    // ── Structured tracing context (smoke tests) ──────────────────────────────
    // These tests verify the tracing functions can be called with structured
    // request_id / workspace_id / rule_id fields without panicking.
    // Actual log output is not captured in unit tests but the field names are
    // checked at compile time by the `tracing::info!` macro.

    #[test]
    fn log_request_start_does_not_panic() {
        let request_id = RequestId::new();
        let workspace_id = WorkspaceId::new();
        // Should not panic; structured fields: request_id, workspace_id, model
        log_request_start(request_id, workspace_id, "gpt-4o-mini");
    }

    #[test]
    fn log_request_finish_success_does_not_panic() {
        let request_id = RequestId::new();
        let workspace_id = WorkspaceId::new();
        log_request_finish(request_id, workspace_id, "allow", true);
    }

    #[test]
    fn log_request_finish_failure_does_not_panic() {
        let request_id = RequestId::new();
        let workspace_id = WorkspaceId::new();
        log_request_finish(request_id, workspace_id, "deny", false);
    }

    #[test]
    fn log_policy_event_includes_rule_id_context() {
        let request_id = RequestId::new();
        let workspace_id = WorkspaceId::new();
        let rule_id = Uuid::new_v4();
        // Structured fields: request_id, workspace_id, rule_id, action, dry_run
        log_policy_event(request_id, workspace_id, rule_id, "redact", false);
    }

    #[test]
    fn log_policy_event_dry_run_does_not_panic() {
        let request_id = RequestId::new();
        let workspace_id = WorkspaceId::new();
        let rule_id = Uuid::new_v4();
        log_policy_event(request_id, workspace_id, rule_id, "flag", true);
    }
}
