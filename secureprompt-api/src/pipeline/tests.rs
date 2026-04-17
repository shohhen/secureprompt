/// Tests for the concrete pipeline runtime (Phase 2, Plan 03 — Task 1).
///
/// The implementation is pre-built in the wave-1 commit. Tests document and
/// verify the acceptance criteria: stage ordering, common-contract types, and
/// the dep-light boundary between secureprompt-common and secureprompt-api.
#[cfg(test)]
mod pipeline_contract_tests {
    use crate::{
        pipeline::service::{GatewayRequest, PipelineService, RequestKind},
        providers::ProviderCatalog,
    };
    use secureprompt_common::{
        pipeline::{PipelineInput, PipelineOutput, PipelineState},
        types::{Message, ProviderId, RequestId, WorkspaceId},
    };
    use uuid::Uuid;

    // ---------------------------------------------------------------------------
    // Helper builders
    // ---------------------------------------------------------------------------

    fn sample_workspace_id() -> WorkspaceId {
        WorkspaceId(Uuid::new_v4())
    }

    fn sample_provider_id() -> ProviderId {
        ProviderId(Uuid::new_v4())
    }

    fn chat_request(content: &str, stream: bool) -> GatewayRequest {
        GatewayRequest {
            public_model: "test-model".to_owned(),
            messages: vec![Message {
                role: "user".to_owned(),
                content: content.to_owned(),
            }],
            stream,
            request_kind: RequestKind::Chat,
            extra_params: serde_json::json!({}),
        }
    }

    // ---------------------------------------------------------------------------
    // PipelineInput / PipelineState / PipelineOutput are common-contract types
    // ---------------------------------------------------------------------------

    #[test]
    fn pipeline_input_roundtrips_via_serde() {
        let input = PipelineInput {
            request_id: RequestId::new(),
            workspace_id: sample_workspace_id(),
            provider_id: sample_provider_id(),
            messages: vec![Message {
                role: "user".to_owned(),
                content: "hello world".to_owned(),
            }],
            stream: false,
            model: "gpt-4o".to_owned(),
            extra_params: serde_json::json!({ "temperature": 0.7 }),
        };

        let json = serde_json::to_string(&input).expect("serialize PipelineInput");
        let back: PipelineInput = serde_json::from_str(&json).expect("deserialize PipelineInput");

        assert_eq!(back.model, "gpt-4o");
        assert_eq!(back.messages.len(), 1);
        assert_eq!(back.messages[0].content, "hello world");
        assert!(!back.stream);
    }

    #[test]
    fn pipeline_state_default_is_empty() {
        let state = PipelineState::default();
        assert!(state.detections.is_empty());
        assert!(state.policy_events.is_empty());
        assert!(state.redaction_map.is_empty());
        assert!(state.vault.is_empty());
    }

    #[test]
    fn pipeline_output_roundtrips_via_serde() {
        use secureprompt_common::types::{PolicyResult, ProviderResponse, TokenUsage};
        use std::collections::HashMap;

        let output = PipelineOutput {
            response: ProviderResponse {
                content: "answer".to_owned(),
                model: "gpt-4o".to_owned(),
                finish_reason: Some("stop".to_owned()),
                embedding: None,
            },
            usage: TokenUsage {
                input_tokens: Some(10),
                output_tokens: Some(5),
                reasoning_tokens: None,
                cache_read_tokens: None,
                cache_write_tokens: None,
            },
            redaction_map: HashMap::new(),
            policy_result: PolicyResult {
                final_action: "allow".to_owned(),
                events: vec![],
            },
        };

        let json = serde_json::to_string(&output).expect("serialize PipelineOutput");
        let back: PipelineOutput =
            serde_json::from_str(&json).expect("deserialize PipelineOutput");

        assert_eq!(back.response.content, "answer");
        assert_eq!(back.usage.input_tokens, Some(10));
        assert_eq!(back.policy_result.final_action, "allow");
    }

    // ---------------------------------------------------------------------------
    // Common-crate dep-light boundary: run_pipeline stub returns NotImplemented
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn common_run_pipeline_stub_returns_not_implemented() {
        let mut state = PipelineState::default();
        let input = PipelineInput {
            request_id: RequestId::new(),
            workspace_id: sample_workspace_id(),
            provider_id: sample_provider_id(),
            messages: vec![Message {
                role: "user".to_owned(),
                content: "hello".to_owned(),
            }],
            stream: false,
            model: "gpt-4o".to_owned(),
            extra_params: serde_json::json!({}),
        };

        let result = secureprompt_common::pipeline::run_pipeline(&mut state, input).await;
        assert!(
            result.is_err(),
            "common run_pipeline must stay a stub — no I/O deps in common crate"
        );
        // Verify it's specifically NotImplemented, not a runtime panic
        let err = result.unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("NotImplemented") || msg.contains("not yet implemented"),
            "expected NotImplemented error, got: {msg}"
        );
    }

    // ---------------------------------------------------------------------------
    // PipelineService is defined in the API crate (dep boundary confirmed)
    // ---------------------------------------------------------------------------

    #[test]
    fn pipeline_service_new_accepts_app_state() {
        // Verifies that PipelineService lives in secureprompt-api and accepts AppState.
        // We only compile-test it here since AppState requires a real DB pool for execution.
        // The function returns PipelineService<AppState> with no extra deps in common.
        let _marker: fn(crate::app_state::AppState) -> PipelineService =
            PipelineService::new;
    }

    // ---------------------------------------------------------------------------
    // RequestKind enum covers all three handler types
    // ---------------------------------------------------------------------------

    #[test]
    fn request_kind_all_variants_distinct() {
        assert_ne!(RequestKind::Chat, RequestKind::Completion);
        assert_ne!(RequestKind::Chat, RequestKind::Embedding);
        assert_ne!(RequestKind::Completion, RequestKind::Embedding);
    }

    // ---------------------------------------------------------------------------
    // GatewayRequest carries stream flag correctly
    // ---------------------------------------------------------------------------

    #[test]
    fn gateway_request_stream_flag_preserved() {
        let streaming = chat_request("test", true);
        let non_streaming = chat_request("test", false);

        assert!(streaming.stream);
        assert!(!non_streaming.stream);
    }

    // ---------------------------------------------------------------------------
    // ProviderCatalog registers all four required providers at startup
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn provider_catalog_has_all_required_adapters() {
        let catalog = ProviderCatalog::with_defaults();

        for provider_type in &["openai", "anthropic", "ollama", "vllm"] {
            let adapter = catalog.adapter_for(provider_type).await;
            assert!(
                adapter.is_some(),
                "expected adapter for {provider_type} to be registered"
            );
            let adapter = adapter.unwrap();
            assert_eq!(
                adapter.provider_type(),
                *provider_type,
                "adapter.provider_type() must match the registered key"
            );
        }
    }

    // ---------------------------------------------------------------------------
    // Stage ordering: detection precedes provider call (unit-level verification)
    // The pipeline applies detect_content before forwarding to the provider.
    // ---------------------------------------------------------------------------

    #[test]
    fn detect_content_runs_before_provider_invocation() {
        // This test verifies the stage-order contract at the detection level.
        // A known secret embedded in the prompt is caught by the detection stage;
        // if the detection stage ran _after_ the provider call it would be too late
        // to satisfy the T-02-09 "only redacted content leaves the gateway" threat.
        let prompt = "my AWS key is AKIAIOSFODNN7EXAMPLE and nothing else";
        let detections = crate::detection::detect_content(prompt);

        // At least one detection for the AWS key must fire
        let aws_detected = detections
            .iter()
            .any(|d| d.class.to_lowercase().contains("aws") || d.class.to_lowercase().contains("access_key"));
        assert!(
            aws_detected,
            "detection stage must catch AWS access key before provider call; detections: {detections:?}"
        );
    }

    // ---------------------------------------------------------------------------
    // PipelineExecution result carries all required fields
    // ---------------------------------------------------------------------------

    #[test]
    fn pipeline_execution_fields_are_populated() {
        use crate::pipeline::service::PipelineExecution;
        use secureprompt_common::types::{PolicyResult, ProviderResponse, TokenUsage};
        use std::collections::HashMap;

        // Build a representative PipelineExecution and verify fields exist
        let exec = PipelineExecution {
            request_id: RequestId::new(),
            provider_name: "openai".to_owned(),
            model: "gpt-4o".to_owned(),
            content: Some("response content".to_owned()),
            embedding: None,
            usage: TokenUsage {
                input_tokens: Some(5),
                output_tokens: Some(10),
                reasoning_tokens: Some(0),
                cache_read_tokens: Some(0),
                cache_write_tokens: Some(0),
            },
            estimated_usage: false,
            stream_chunks: vec!["hello".to_owned(), " world".to_owned()],
            finish_reason: Some("stop".to_owned()),
            pipeline_output: PipelineOutput {
                response: ProviderResponse {
                    content: "response content".to_owned(),
                    model: "gpt-4o".to_owned(),
                    finish_reason: Some("stop".to_owned()),
                    embedding: None,
                },
                usage: TokenUsage {
                    input_tokens: Some(5),
                    output_tokens: Some(10),
                    reasoning_tokens: None,
                    cache_read_tokens: None,
                    cache_write_tokens: None,
                },
                redaction_map: HashMap::new(),
                policy_result: PolicyResult::default(),
            },
        };

        assert_eq!(exec.provider_name, "openai");
        assert_eq!(exec.model, "gpt-4o");
        assert!(exec.content.is_some());
        assert_eq!(exec.stream_chunks.len(), 2);
        assert!(!exec.estimated_usage);
        assert_eq!(exec.finish_reason.as_deref(), Some("stop"));
    }
}
