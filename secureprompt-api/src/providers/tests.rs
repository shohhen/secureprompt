/// Tests for provider adapters and the streaming bridge (Phase 2, Plan 03 — Task 2).
///
/// Covers:
///   - All four provider adapters (OpenAI, Anthropic, Ollama, vLLM) behind the shared interface
///   - `force_include_usage` / `include_usage` enforcement
///   - `placeholder_safe_chunks` rolling-buffer logic
///   - `fallback_allowed` boundary: allowed only before first emitted byte/chunk
///   - No code path attempts mid-stream provider stitching

#[cfg(test)]
mod provider_adapter_tests {
    use crate::{
        http::model_router::ModelTarget,
        providers::{
            anthropic::AnthropicAdapter,
            ollama::OllamaAdapter,
            openai::OpenAiAdapter,
            vllm::VllmAdapter,
            InvocationKind, ProviderAdapter, ProviderCatalog, ProviderInvocation,
        },
    };
    use secureprompt_common::types::{ProviderId, RequestId, WorkspaceId};
    use uuid::Uuid;

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    fn test_target(provider_type: &str, model: &str) -> ModelTarget {
        ModelTarget {
            model_id: Uuid::new_v4(),
            workspace_id: WorkspaceId(Uuid::new_v4()),
            provider_id: ProviderId(Uuid::new_v4()),
            provider_name: format!("{provider_type}-primary"),
            provider_type: provider_type.to_owned(),
            model_name: model.to_owned(),
            encrypted_credential: None,
        }
    }

    fn chat_invocation(prompt: &str, stream: bool) -> ProviderInvocation {
        ProviderInvocation {
            request_id: RequestId::new(),
            model: "test-model".to_owned(),
            prompt: prompt.to_owned(),
            messages: vec![secureprompt_common::types::Message {
                role: "user".to_owned(),
                content: prompt.to_owned(),
            }],
            extra_params: serde_json::json!({}),
            stream,
            kind: InvocationKind::Chat,
            decrypted_credential: None,
        }
    }

    fn embedding_invocation(prompt: &str) -> ProviderInvocation {
        ProviderInvocation {
            request_id: RequestId::new(),
            model: "text-embedding".to_owned(),
            prompt: prompt.to_owned(),
            messages: vec![],
            extra_params: serde_json::json!({}),
            stream: false,
            kind: InvocationKind::Embedding,
            decrypted_credential: None,
        }
    }

    // ---------------------------------------------------------------------------
    // OpenAI adapter
    // ---------------------------------------------------------------------------

    #[test]
    fn openai_adapter_provider_type() {
        assert_eq!(OpenAiAdapter.provider_type(), "openai");
    }

    #[tokio::test]
    async fn openai_adapter_complete_returns_content() {
        let target = test_target("openai", "gpt-4o");
        let inv = chat_invocation("hello", false);
        let output = OpenAiAdapter.complete(&target, &inv).await.unwrap();
        assert!(
            output.content.contains("openai"),
            "openai complete should echo provider label; got: {}",
            output.content
        );
        assert!(output.stream_chunks.is_empty(), "non-streaming must produce no chunks");
        assert_eq!(output.model, "gpt-4o");
    }

    #[tokio::test]
    async fn openai_adapter_stream_returns_chunks() {
        let target = test_target("openai", "gpt-4o");
        let inv = chat_invocation("streaming test", true);
        let output = OpenAiAdapter.stream(&target, &inv).await.unwrap();
        assert!(!output.stream_chunks.is_empty(), "streaming must produce chunks");
        // All chunks reassembled should equal the full content
        let joined: String = output.stream_chunks.join("");
        assert_eq!(joined, output.content);
    }

    #[tokio::test]
    async fn openai_adapter_complete_includes_usage_by_default() {
        let target = test_target("openai", "gpt-4o");
        let inv = chat_invocation("hello", false);
        let output = OpenAiAdapter.complete(&target, &inv).await.unwrap();
        assert!(output.usage.is_some(), "usage must be present by default");
        let usage = output.usage.unwrap();
        assert!(usage.input_tokens.is_some());
        assert!(usage.output_tokens.is_some());
    }

    #[tokio::test]
    async fn openai_adapter_omit_usage_param_suppresses_usage() {
        let target = test_target("openai", "gpt-4o");
        let mut inv = chat_invocation("hello", false);
        inv.extra_params = serde_json::json!({ "omit_usage": true });
        let output = OpenAiAdapter.complete(&target, &inv).await.unwrap();
        assert!(output.usage.is_none(), "omit_usage=true must suppress usage");
    }

    #[tokio::test]
    async fn openai_adapter_force_retryable_failure() {
        let mut target = test_target("openai", "gpt-4o");
        target.encrypted_credential = Some("force_retryable".to_owned());
        let inv = chat_invocation("hello", false);
        let err = OpenAiAdapter.complete(&target, &inv).await.unwrap_err();
        assert!(err.retryable, "force_retryable must produce retryable=true failure");
    }

    #[tokio::test]
    async fn openai_adapter_force_fatal_failure() {
        let mut target = test_target("openai", "gpt-4o");
        target.encrypted_credential = Some("force_fatal".to_owned());
        let inv = chat_invocation("hello", false);
        let err = OpenAiAdapter.complete(&target, &inv).await.unwrap_err();
        assert!(!err.retryable, "force_fatal must produce retryable=false failure");
    }

    // ---------------------------------------------------------------------------
    // Anthropic adapter
    // ---------------------------------------------------------------------------

    #[test]
    fn anthropic_adapter_provider_type() {
        assert_eq!(AnthropicAdapter.provider_type(), "anthropic");
    }

    #[tokio::test]
    async fn anthropic_adapter_complete_returns_content() {
        let target = test_target("anthropic", "claude-3-5-haiku");
        let inv = chat_invocation("hello", false);
        let output = AnthropicAdapter.complete(&target, &inv).await.unwrap();
        assert!(
            output.content.contains("anthropic"),
            "anthropic complete should echo provider label; got: {}",
            output.content
        );
        assert!(output.stream_chunks.is_empty());
    }

    #[tokio::test]
    async fn anthropic_adapter_stream_returns_chunks() {
        let target = test_target("anthropic", "claude-3-5-haiku");
        let inv = chat_invocation("streaming test", true);
        let output = AnthropicAdapter.stream(&target, &inv).await.unwrap();
        assert!(!output.stream_chunks.is_empty());
        let joined: String = output.stream_chunks.join("");
        assert_eq!(joined, output.content);
    }

    #[tokio::test]
    async fn anthropic_adapter_force_retryable_failure() {
        let mut target = test_target("anthropic", "claude-3-5-haiku");
        target.encrypted_credential = Some("force_retryable".to_owned());
        let inv = chat_invocation("hello", false);
        let err = AnthropicAdapter.complete(&target, &inv).await.unwrap_err();
        assert!(err.retryable);
    }

    // ---------------------------------------------------------------------------
    // Ollama adapter
    // ---------------------------------------------------------------------------

    #[test]
    fn ollama_adapter_provider_type() {
        assert_eq!(OllamaAdapter.provider_type(), "ollama");
    }

    #[tokio::test]
    async fn ollama_adapter_complete_returns_content() {
        let target = test_target("ollama", "llama3.2");
        let inv = chat_invocation("hello", false);
        let output = OllamaAdapter.complete(&target, &inv).await.unwrap();
        assert!(
            output.content.contains("ollama"),
            "ollama complete should echo provider label; got: {}",
            output.content
        );
    }

    #[tokio::test]
    async fn ollama_adapter_stream_returns_chunks() {
        let target = test_target("ollama", "llama3.2");
        let inv = chat_invocation("streaming test", true);
        let output = OllamaAdapter.stream(&target, &inv).await.unwrap();
        assert!(!output.stream_chunks.is_empty());
    }

    // ---------------------------------------------------------------------------
    // vLLM adapter
    // ---------------------------------------------------------------------------

    #[test]
    fn vllm_adapter_provider_type() {
        assert_eq!(VllmAdapter.provider_type(), "vllm");
    }

    #[tokio::test]
    async fn vllm_adapter_complete_returns_content() {
        let target = test_target("vllm", "meta-llama/Meta-Llama-3.1-8B");
        let inv = chat_invocation("hello", false);
        let output = VllmAdapter.complete(&target, &inv).await.unwrap();
        assert!(
            output.content.contains("vllm"),
            "vllm complete should echo provider label; got: {}",
            output.content
        );
    }

    #[tokio::test]
    async fn vllm_adapter_stream_returns_chunks() {
        let target = test_target("vllm", "meta-llama/Meta-Llama-3.1-8B");
        let inv = chat_invocation("streaming test", true);
        let output = VllmAdapter.stream(&target, &inv).await.unwrap();
        assert!(!output.stream_chunks.is_empty());
    }

    // ---------------------------------------------------------------------------
    // Shared interface: embeddings path produces embedding vector, no content
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn all_adapters_produce_embeddings() {
        let adapters: &[(&dyn ProviderAdapter, &str)] = &[
            (&OpenAiAdapter as &dyn ProviderAdapter, "openai"),
            (&AnthropicAdapter, "anthropic"),
            (&OllamaAdapter, "ollama"),
            (&VllmAdapter, "vllm"),
        ];
        for (adapter, name) in adapters {
            let target = test_target(name, "text-embedding");
            let inv = embedding_invocation("embed this text");
            let output = adapter.complete(&target, &inv).await.unwrap();
            assert!(
                output.embedding.is_some(),
                "{name} embedding must produce embedding vector"
            );
            let emb = output.embedding.clone().unwrap();
            assert!(!emb.is_empty(), "{name} embedding vector must be non-empty");
            assert!(
                output.stream_chunks.is_empty(),
                "{name} embedding must not produce stream chunks"
            );
        }
    }

    // ---------------------------------------------------------------------------
    // Dynamic registration: catalog.register() works at runtime
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn provider_catalog_register_overrides_existing() {
        use crate::providers::ProviderOutput;
        use async_trait::async_trait;
        use crate::providers::ProviderFailure;

        struct CustomAdapter;

        #[async_trait]
        impl ProviderAdapter for CustomAdapter {
            fn provider_type(&self) -> &'static str {
                "openai"
            }

            async fn complete(
                &self,
                _target: &ModelTarget,
                _inv: &ProviderInvocation,
            ) -> Result<ProviderOutput, ProviderFailure> {
                Ok(ProviderOutput {
                    content: "custom-adapter-response".to_owned(),
                    ..Default::default()
                })
            }

            async fn stream(
                &self,
                _target: &ModelTarget,
                _inv: &ProviderInvocation,
            ) -> Result<ProviderOutput, ProviderFailure> {
                Ok(ProviderOutput {
                    content: "custom-stream".to_owned(),
                    stream_chunks: vec!["custom".to_owned(), "-stream".to_owned()],
                    ..Default::default()
                })
            }
        }

        let catalog = ProviderCatalog::with_defaults();
        catalog
            .register("openai", std::sync::Arc::new(CustomAdapter))
            .await;

        let adapter = catalog.adapter_for("openai").await.unwrap();
        let target = test_target("openai", "gpt-4o");
        let inv = chat_invocation("test", false);
        let output = adapter.complete(&target, &inv).await.unwrap();
        assert_eq!(output.content, "custom-adapter-response");
    }
}

#[cfg(test)]
mod streaming_bridge_tests {
    use crate::http::streaming::{fallback_allowed, force_include_usage, placeholder_safe_chunks};
    use secureprompt_common::types::TokenVault;

    // ---------------------------------------------------------------------------
    // force_include_usage: sets stream_options.include_usage = true
    // ---------------------------------------------------------------------------

    #[test]
    fn force_include_usage_on_empty_object() {
        let mut params = serde_json::json!({});
        force_include_usage(&mut params);
        assert_eq!(
            params["stream_options"]["include_usage"],
            serde_json::Value::Bool(true)
        );
    }

    #[test]
    fn force_include_usage_on_existing_stream_options() {
        let mut params = serde_json::json!({ "stream_options": { "include_usage": false } });
        force_include_usage(&mut params);
        assert_eq!(
            params["stream_options"]["include_usage"],
            serde_json::Value::Bool(true),
            "force_include_usage must override false -> true"
        );
    }

    #[test]
    fn force_include_usage_on_non_object_params_creates_object() {
        let mut params = serde_json::Value::Null;
        force_include_usage(&mut params);
        assert_eq!(
            params["stream_options"]["include_usage"],
            serde_json::Value::Bool(true)
        );
    }

    #[test]
    fn force_include_usage_preserves_other_params() {
        let mut params = serde_json::json!({ "temperature": 0.5, "max_tokens": 100 });
        force_include_usage(&mut params);
        assert_eq!(params["temperature"], serde_json::json!(0.5));
        assert_eq!(params["max_tokens"], serde_json::json!(100));
    }

    // ---------------------------------------------------------------------------
    // fallback_allowed: allowed only before first chunk emitted
    // ---------------------------------------------------------------------------

    #[test]
    fn fallback_allowed_before_first_chunk() {
        assert!(
            fallback_allowed(0),
            "fallback must be allowed when no chunks have been emitted"
        );
    }

    #[test]
    fn fallback_forbidden_after_first_chunk() {
        assert!(
            !fallback_allowed(1),
            "fallback must be forbidden after the first chunk is emitted"
        );
    }

    #[test]
    fn fallback_forbidden_after_many_chunks() {
        assert!(
            !fallback_allowed(42),
            "fallback must remain forbidden regardless of chunk count > 0"
        );
    }

    // ---------------------------------------------------------------------------
    // placeholder_safe_chunks: rolling buffer prevents split placeholders
    // ---------------------------------------------------------------------------

    fn empty_vault() -> TokenVault {
        TokenVault::default()
    }

    #[test]
    fn plain_content_passes_through_unchanged() {
        let chunks = vec!["hello".to_owned(), " world".to_owned()];
        let vault = empty_vault();
        let safe = placeholder_safe_chunks(&chunks, &vault);
        let joined: String = safe.join("");
        assert_eq!(joined, "hello world");
    }

    #[test]
    fn complete_placeholder_in_single_chunk_passes_through() {
        let placeholder = "<Aws_Access_Key_1>";
        let chunks = vec![placeholder.to_owned()];
        let vault = empty_vault();
        let safe = placeholder_safe_chunks(&chunks, &vault);
        let joined: String = safe.join("");
        assert_eq!(joined, placeholder);
    }

    #[test]
    fn placeholder_split_across_two_chunks_is_reassembled() {
        // Split the placeholder between two chunks — rolling buffer must hold the
        // partial prefix until the closing ']' arrives.
        let placeholder = "<Email_Address_1>";
        let mid = placeholder.len() / 2;
        let chunk1 = placeholder[..mid].to_owned();
        let chunk2 = placeholder[mid..].to_owned();

        let vault = empty_vault();
        let safe = placeholder_safe_chunks(&[chunk1, chunk2], &vault);
        let joined: String = safe.join("");
        // The placeholder must not be fragmented; it must appear whole in output
        assert!(
            joined.contains(placeholder),
            "rolling buffer must reassemble split placeholder; got: {joined:?}"
        );
    }

    #[test]
    fn placeholder_split_into_many_chunks_is_reassembled() {
        // Simulate very small chunk size splitting the placeholder into many pieces
        let placeholder = "<Api_Key_1>";
        let chunks: Vec<String> = placeholder.chars().map(|c| c.to_string()).collect();

        let vault = empty_vault();
        let safe = placeholder_safe_chunks(&chunks, &vault);
        let joined: String = safe.join("");
        assert!(
            joined.contains(placeholder),
            "placeholder split into single-char chunks must be reassembled; got: {joined:?}"
        );
    }

    #[test]
    fn vault_with_entry_restores_placeholder_in_stream() {
        let mut vault = TokenVault::default();
        let placeholder = "<Email_Address_1>";
        vault.insert(placeholder.to_owned(), "user@example.com".to_owned());

        // Content arrives as a complete placeholder in one chunk
        let chunks = vec![
            "Dear ".to_owned(),
            placeholder.to_owned(),
            ", thank you".to_owned(),
        ];
        let safe = placeholder_safe_chunks(&chunks, &vault);
        let joined: String = safe.join("");
        assert!(
            joined.contains("user@example.com"),
            "vault restoration must replace placeholder in streamed output; got: {joined:?}"
        );
        assert!(
            !joined.contains(placeholder),
            "placeholder must not appear in restored output; got: {joined:?}"
        );
    }

    #[test]
    fn content_before_and_after_placeholder_is_preserved() {
        let placeholder = "<Us_Ssn_1>";
        let chunks = vec![format!("prefix {placeholder} suffix")];
        let vault = empty_vault();
        let safe = placeholder_safe_chunks(&chunks, &vault);
        let joined: String = safe.join("");
        assert!(joined.contains("prefix"));
        assert!(joined.contains("suffix"));
        assert!(joined.contains(placeholder));
    }

    #[test]
    fn multiple_placeholders_in_stream_all_preserved() {
        let ph1 = "<Email_Address_3>";
        let ph2 = "<Aws_Key_1>";
        let content = format!("{ph1} and {ph2} done");
        let chunks = vec![content];
        let vault = empty_vault();
        let safe = placeholder_safe_chunks(&chunks, &vault);
        let joined: String = safe.join("");
        assert!(joined.contains(ph1));
        assert!(joined.contains(ph2));
    }

    #[test]
    fn empty_chunk_list_produces_empty_output() {
        let vault = empty_vault();
        let safe = placeholder_safe_chunks(&[], &vault);
        assert!(safe.is_empty() || safe.iter().all(|s| s.is_empty()));
    }

    #[test]
    fn trailing_partial_prefix_held_until_next_chunk() {
        // New `<Class_N>` placeholder split across chunk boundary — the
        // reassembler must hold `<Perso` until the closer `>` arrives.
        let ch1 = "text <Perso".to_owned();
        let ch2 = "n_1> end".to_owned();
        let vault = empty_vault();
        let safe = placeholder_safe_chunks(&[ch1, ch2], &vault);
        let joined: String = safe.join("");
        assert!(
            joined.contains("<Person_1>"),
            "partial prefix held across chunk boundary; got: {joined:?}"
        );
        assert!(joined.contains("text "));
        assert!(joined.contains(" end"));
    }

    // ---------------------------------------------------------------------------
    // Fallback boundary: no mid-stream stitching (structural test)
    // We can't easily simulate mid-stream stitching in unit tests, but we can
    // confirm that fallback_allowed transitions sharply at count==0 boundary.
    // ---------------------------------------------------------------------------

    #[test]
    fn fallback_boundary_is_strictly_at_zero_chunks() {
        // Only count==0 allows fallback; any positive count must forbid it
        for count in 0usize..=10 {
            let allowed = fallback_allowed(count);
            if count == 0 {
                assert!(allowed, "fallback must be allowed at count=0");
            } else {
                assert!(!allowed, "fallback must be forbidden at count={count}");
            }
        }
    }
}
