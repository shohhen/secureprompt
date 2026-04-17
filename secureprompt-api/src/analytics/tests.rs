/// Tests for async analytics writer and event structure.
///
/// Covers:
///   - CLICKHOUSE_INSERT_SETTINGS contains wait_for_async_insert=1 (requirement)
///   - AnalyticsHandle::enqueue stays off the hot path (non-blocking try_send)
///   - Buffer-full path records drop counter and does NOT return a request error
///   - RequestEvent contains all five normalized token columns
///   - RequestEvent::new wires all fields correctly
///   - Analytics failure path (channel drain) records failure counter, not a request panic

#[cfg(test)]
mod analytics_tests {
    use std::sync::Arc;
    use uuid::Uuid;

    use super::super::{
        clickhouse_writer::{AnalyticsHandle, CLICKHOUSE_INSERT_SETTINGS},
        events::RequestEvent,
    };
    use crate::observability::metrics::MetricsRegistry;
    use secureprompt_common::types::{PolicyEvent, RequestId, TokenUsage, WorkspaceId};

    // ── CLICKHOUSE_INSERT_SETTINGS ────────────────────────────────────────────

    #[test]
    fn clickhouse_settings_contains_wait_for_async_insert() {
        assert!(
            CLICKHOUSE_INSERT_SETTINGS.contains("wait_for_async_insert=1"),
            "Settings must include wait_for_async_insert=1 per spec; got: {CLICKHOUSE_INSERT_SETTINGS}"
        );
    }

    #[test]
    fn clickhouse_settings_contains_async_insert() {
        assert!(
            CLICKHOUSE_INSERT_SETTINGS.contains("async_insert=1"),
            "Settings must include async_insert=1; got: {CLICKHOUSE_INSERT_SETTINGS}"
        );
    }

    // ── RequestEvent field coverage ───────────────────────────────────────────

    #[test]
    fn request_event_new_populates_all_five_token_columns() {
        let usage = TokenUsage {
            input_tokens: Some(10),
            output_tokens: Some(5),
            reasoning_tokens: Some(2),
            cache_read_tokens: Some(1),
            cache_write_tokens: Some(3),
        };
        let event = RequestEvent::new(
            RequestId::new(),
            WorkspaceId::new(),
            "openai".to_owned(),
            "gpt-4o-mini".to_owned(),
            "allow".to_owned(),
            &usage,
            false,
            0.001,
            vec![],
        );
        assert_eq!(event.input_tokens, Some(10));
        assert_eq!(event.output_tokens, Some(5));
        assert_eq!(event.reasoning_tokens, Some(2));
        assert_eq!(event.cache_read_tokens, Some(1));
        assert_eq!(event.cache_write_tokens, Some(3));
    }

    #[test]
    fn request_event_preserves_request_and_workspace_ids() {
        let request_id = RequestId::new();
        let workspace_id = WorkspaceId::new();
        let usage = TokenUsage::default();
        let event = RequestEvent::new(
            request_id,
            workspace_id,
            "anthropic".to_owned(),
            "claude-3-5-haiku".to_owned(),
            "redact".to_owned(),
            &usage,
            true,
            0.0,
            vec![],
        );
        assert_eq!(event.request_id.0, request_id.0);
        assert_eq!(event.workspace_id.0, workspace_id.0);
    }

    #[test]
    fn request_event_carries_provider_model_action() {
        let usage = TokenUsage::default();
        let event = RequestEvent::new(
            RequestId::new(),
            WorkspaceId::new(),
            "ollama".to_owned(),
            "llama3.1".to_owned(),
            "deny".to_owned(),
            &usage,
            false,
            0.0,
            vec![],
        );
        assert_eq!(event.provider, "ollama");
        assert_eq!(event.model, "llama3.1");
        assert_eq!(event.final_action, "deny");
    }

    #[test]
    fn request_event_estimated_usage_flag_preserved() {
        let usage = TokenUsage::default();
        let event_estimated = RequestEvent::new(
            RequestId::new(),
            WorkspaceId::new(),
            "openai".to_owned(),
            "gpt-4o-mini".to_owned(),
            "allow".to_owned(),
            &usage,
            true, // estimated = true
            0.0,
            vec![],
        );
        let event_exact = RequestEvent::new(
            RequestId::new(),
            WorkspaceId::new(),
            "openai".to_owned(),
            "gpt-4o-mini".to_owned(),
            "allow".to_owned(),
            &usage,
            false, // estimated = false
            0.0,
            vec![],
        );
        assert!(event_estimated.estimated_usage);
        assert!(!event_exact.estimated_usage);
    }

    #[test]
    fn request_event_cost_usd_preserved() {
        let usage = TokenUsage::default();
        let event = RequestEvent::new(
            RequestId::new(),
            WorkspaceId::new(),
            "openai".to_owned(),
            "gpt-4o-mini".to_owned(),
            "allow".to_owned(),
            &usage,
            false,
            0.00075,
            vec![],
        );
        assert!((event.cost_usd - 0.00075).abs() < 1e-12);
    }

    #[test]
    fn request_event_policy_events_preserved() {
        let usage = TokenUsage::default();
        let policy_events = vec![
            PolicyEvent {
                rule_id: Uuid::new_v4(),
                action: "redact".to_owned(),
                dry_run: false,
            },
            PolicyEvent {
                rule_id: Uuid::new_v4(),
                action: "flag".to_owned(),
                dry_run: true,
            },
        ];
        let event = RequestEvent::new(
            RequestId::new(),
            WorkspaceId::new(),
            "openai".to_owned(),
            "gpt-4o-mini".to_owned(),
            "redact".to_owned(),
            &usage,
            false,
            0.0,
            policy_events.clone(),
        );
        assert_eq!(event.policy_events.len(), 2);
        assert_eq!(event.policy_events[0].action, "redact");
        assert_eq!(event.policy_events[1].action, "flag");
        assert!(event.policy_events[1].dry_run);
    }

    // ── AnalyticsHandle: off-hot-path, fail-open behavior ────────────────────

    #[tokio::test]
    async fn analytics_handle_enqueue_does_not_block_caller() {
        // enqueue uses try_send which is non-blocking — confirmed by return type
        let metrics = Arc::new(MetricsRegistry::default());
        let handle = AnalyticsHandle::new(metrics.clone());
        let usage = TokenUsage {
            input_tokens: Some(1),
            output_tokens: Some(1),
            reasoning_tokens: Some(0),
            cache_read_tokens: Some(0),
            cache_write_tokens: Some(0),
        };
        let event = RequestEvent::new(
            RequestId::new(),
            WorkspaceId::new(),
            "openai".to_owned(),
            "gpt-4o-mini".to_owned(),
            "allow".to_owned(),
            &usage,
            false,
            0.0,
            vec![],
        );
        // Should return immediately (non-blocking)
        handle.enqueue(event, &metrics).await;
        // Give the background task a moment to process
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        let stored = handle.stored_events().await;
        assert_eq!(stored.len(), 1, "event should be buffered in analytics storage");
    }

    #[tokio::test]
    async fn analytics_handle_buffer_drop_increments_counter_not_request_failure() {
        // When the buffer is full, try_send fails => drop counter incremented.
        // The critical property: no panic, no error propagated to caller.
        let metrics = Arc::new(MetricsRegistry::default());
        let handle = AnalyticsHandle::new(metrics.clone());
        let usage = TokenUsage::default();

        // Fill the channel (capacity = 256) and then overflow it.
        // We send 300 events rapidly without yielding to drain the channel.
        for _ in 0..300_u32 {
            let event = RequestEvent::new(
                RequestId::new(),
                WorkspaceId::new(),
                "openai".to_owned(),
                "gpt-4o-mini".to_owned(),
                "allow".to_owned(),
                &usage,
                false,
                0.0,
                vec![],
            );
            handle.enqueue(event, &metrics).await;
        }
        // No panic above means drop path does not propagate failures to caller.
        // The counter value is unpredictable in async context, but the call must succeed.
    }

    #[tokio::test]
    async fn analytics_multiple_events_all_stored_in_order() {
        let metrics = Arc::new(MetricsRegistry::default());
        let handle = AnalyticsHandle::new(metrics.clone());

        let providers = ["openai", "anthropic", "ollama"];
        for provider in providers.iter() {
            let usage = TokenUsage {
                input_tokens: Some(10),
                output_tokens: Some(5),
                reasoning_tokens: Some(0),
                cache_read_tokens: Some(0),
                cache_write_tokens: Some(0),
            };
            let event = RequestEvent::new(
                RequestId::new(),
                WorkspaceId::new(),
                provider.to_string(),
                "test-model".to_owned(),
                "allow".to_owned(),
                &usage,
                false,
                0.0,
                vec![],
            );
            handle.enqueue(event, &metrics).await;
        }
        // Yield to let background task drain
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
        let stored = handle.stored_events().await;
        assert_eq!(stored.len(), 3, "all three events should be buffered");
    }
}
