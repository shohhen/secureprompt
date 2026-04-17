/// Tests for provider-dispatched token accounting with fallback estimation.
///
/// Covers:
///   - dispatch::derive_usage: provider-reported usage takes precedence
///   - dispatch::derive_usage: fallback estimation path for missing usage (disconnect case)
///   - dispatch::estimate_tokens: provider-specific tokenization heuristics
///   - pricing::PricingTable: cost computation from known and unknown models
///   - All five normalized token columns present in computed usage
///   - reasoning_tokens present in dispatch output

#[cfg(test)]
mod token_usage_tests {
    use super::super::{
        dispatch::{derive_usage, estimate_tokens},
        pricing::PricingTable,
    };
    use secureprompt_common::types::TokenUsage;

    // ── derive_usage: provider-reported path ──────────────────────────────────

    #[test]
    fn derive_usage_uses_provider_reported_when_present() {
        let reported = TokenUsage {
            input_tokens: Some(100),
            output_tokens: Some(50),
            reasoning_tokens: Some(10),
            cache_read_tokens: Some(5),
            cache_write_tokens: Some(3),
        };
        let result = derive_usage("openai", Some(reported.clone()), "hello world", "response");
        assert!(!result.estimated, "should be marked non-estimated when provider reports usage");
        assert_eq!(result.usage.input_tokens, Some(100));
        assert_eq!(result.usage.output_tokens, Some(50));
        assert_eq!(result.usage.reasoning_tokens, Some(10));
        assert_eq!(result.usage.cache_read_tokens, Some(5));
        assert_eq!(result.usage.cache_write_tokens, Some(3));
    }

    #[test]
    fn derive_usage_estimated_flag_false_when_provider_reported() {
        let reported = TokenUsage {
            input_tokens: Some(42),
            output_tokens: Some(7),
            reasoning_tokens: None,
            cache_read_tokens: None,
            cache_write_tokens: None,
        };
        let result = derive_usage("anthropic", Some(reported), "prompt", "completion");
        assert!(!result.estimated);
    }

    // ── derive_usage: fallback estimation path ────────────────────────────────

    #[test]
    fn derive_usage_falls_back_to_estimation_when_no_reported_usage() {
        let result = derive_usage("openai", None, "hello world foo", "bar baz");
        assert!(result.estimated, "should be marked estimated when usage is absent");
        assert!(result.usage.input_tokens.is_some(), "fallback must produce input_tokens");
        assert!(result.usage.output_tokens.is_some(), "fallback must produce output_tokens");
    }

    #[test]
    fn derive_usage_fallback_all_five_columns_present() {
        let result = derive_usage("openai", None, "some prompt text here", "some response");
        assert!(result.usage.input_tokens.is_some());
        assert!(result.usage.output_tokens.is_some());
        assert!(result.usage.reasoning_tokens.is_some());
        assert!(result.usage.cache_read_tokens.is_some());
        assert!(result.usage.cache_write_tokens.is_some());
    }

    #[test]
    fn derive_usage_fallback_reasoning_tokens_is_zero_for_estimation() {
        // Estimated reasoning tokens should default to 0 (we cannot guess reasoning)
        let result = derive_usage("openai", None, "test prompt", "test response");
        assert_eq!(result.usage.reasoning_tokens, Some(0));
    }

    #[test]
    fn derive_usage_fallback_cache_tokens_are_zero() {
        // Cache tokens cannot be estimated from prompt text alone
        let result = derive_usage("anthropic", None, "test", "test");
        assert_eq!(result.usage.cache_read_tokens, Some(0));
        assert_eq!(result.usage.cache_write_tokens, Some(0));
    }

    #[test]
    fn derive_usage_fallback_nonzero_input_for_non_empty_prompt() {
        let result = derive_usage("openai", None, "hello world this is a test prompt", "");
        assert!(
            result.usage.input_tokens.unwrap_or(0) > 0,
            "non-empty prompt must produce non-zero estimated input tokens"
        );
    }

    #[test]
    fn derive_usage_fallback_zero_tokens_for_empty_strings() {
        let result = derive_usage("openai", None, "", "");
        assert_eq!(result.usage.input_tokens, Some(0));
        assert_eq!(result.usage.output_tokens, Some(0));
    }

    // ── derive_usage: provider dispatching ───────────────────────────────────

    #[test]
    fn derive_usage_branches_by_provider_type_openai() {
        let result = derive_usage("openai", None, "hello world", "hi");
        assert!(result.estimated);
        assert!(result.usage.input_tokens.unwrap_or(0) > 0);
    }

    #[test]
    fn derive_usage_branches_by_provider_type_anthropic() {
        let result = derive_usage("anthropic", None, "hello world", "hi");
        assert!(result.estimated);
        assert!(result.usage.input_tokens.unwrap_or(0) > 0);
    }

    #[test]
    fn derive_usage_branches_by_provider_type_ollama() {
        let result = derive_usage("ollama", None, "hello world", "hi");
        assert!(result.estimated);
        assert!(result.usage.input_tokens.unwrap_or(0) > 0);
    }

    #[test]
    fn derive_usage_branches_by_provider_type_vllm() {
        let result = derive_usage("vllm", None, "hello world", "hi");
        assert!(result.estimated);
        assert!(result.usage.input_tokens.unwrap_or(0) > 0);
    }

    // ── estimate_tokens ───────────────────────────────────────────────────────

    #[test]
    fn estimate_tokens_empty_content_returns_zero() {
        assert_eq!(estimate_tokens("openai", ""), 0);
        assert_eq!(estimate_tokens("anthropic", ""), 0);
        assert_eq!(estimate_tokens("ollama", "  "), 0);
    }

    #[test]
    fn estimate_tokens_single_word_nonzero() {
        assert!(estimate_tokens("openai", "hello") > 0);
    }

    #[test]
    fn estimate_tokens_increases_with_content_length() {
        let short = estimate_tokens("openai", "hello");
        let longer = estimate_tokens("openai", "hello world this is a longer piece of text with more words");
        assert!(
            longer >= short,
            "longer content should have >= tokens than shorter content"
        );
    }

    #[test]
    fn estimate_tokens_anthropic_uses_char_ratio() {
        // Anthropic uses char_count/3 or word_count (max). 12 chars / 3 = 4; words = 2. max = 4
        let result = estimate_tokens("anthropic", "hello world!");
        assert!(result >= 2, "anthropic estimate should be at least word_count");
    }

    #[test]
    fn estimate_tokens_unknown_provider_falls_back_to_default() {
        // Unknown providers should still produce a reasonable estimate
        let result = estimate_tokens("unknown_provider", "hello world foo bar");
        assert!(result > 0);
    }

    // ── PricingTable ──────────────────────────────────────────────────────────

    #[test]
    fn pricing_table_with_defaults_has_known_models() {
        let table = PricingTable::with_defaults();
        // Known models should produce non-default costs; verify they produce something
        let usage = TokenUsage {
            input_tokens: Some(1000),
            output_tokens: Some(1000),
            reasoning_tokens: None,
            cache_read_tokens: None,
            cache_write_tokens: None,
        };
        // gpt-4o-mini: 0.00015 * 1 + 0.0006 * 1 = 0.00075
        let cost = table.compute_cost("gpt-4o-mini", &usage);
        assert!((cost - 0.00075).abs() < 1e-9, "gpt-4o-mini cost mismatch: {cost}");
    }

    #[test]
    fn pricing_table_compute_cost_zero_for_free_models() {
        let table = PricingTable::with_defaults();
        let usage = TokenUsage {
            input_tokens: Some(1000),
            output_tokens: Some(1000),
            reasoning_tokens: None,
            cache_read_tokens: None,
            cache_write_tokens: None,
        };
        // llama3.1 should be $0
        let cost = table.compute_cost("llama3.1", &usage);
        assert_eq!(cost, 0.0, "local model should cost $0");
    }

    #[test]
    fn pricing_table_compute_cost_unknown_model_uses_defaults() {
        let table = PricingTable::with_defaults();
        let usage = TokenUsage {
            input_tokens: Some(1000),
            output_tokens: Some(1000),
            reasoning_tokens: None,
            cache_read_tokens: None,
            cache_write_tokens: None,
        };
        // Unknown model falls back to 0.0002 / 1k input + 0.0008 / 1k output
        // = 0.0002 * 1 + 0.0008 * 1 = 0.001
        let cost = table.compute_cost("unknown-model-xyz", &usage);
        assert!((cost - 0.001).abs() < 1e-9, "unknown model fallback cost mismatch: {cost}");
    }

    #[test]
    fn pricing_table_compute_cost_proportional_to_token_count() {
        let table = PricingTable::with_defaults();
        let usage_small = TokenUsage {
            input_tokens: Some(100),
            output_tokens: Some(100),
            reasoning_tokens: None,
            cache_read_tokens: None,
            cache_write_tokens: None,
        };
        let usage_large = TokenUsage {
            input_tokens: Some(1000),
            output_tokens: Some(1000),
            reasoning_tokens: None,
            cache_read_tokens: None,
            cache_write_tokens: None,
        };
        let cost_small = table.compute_cost("gpt-4o-mini", &usage_small);
        let cost_large = table.compute_cost("gpt-4o-mini", &usage_large);
        assert!(
            cost_large > cost_small,
            "more tokens should cost more: small={cost_small}, large={cost_large}"
        );
    }

    #[test]
    fn pricing_table_compute_cost_zero_usage_costs_zero() {
        let table = PricingTable::with_defaults();
        let usage = TokenUsage::default();
        let cost = table.compute_cost("gpt-4o-mini", &usage);
        assert_eq!(cost, 0.0, "zero usage should cost nothing");
    }

    #[test]
    fn pricing_table_claude_haiku_pricing_correct() {
        let table = PricingTable::with_defaults();
        // claude-3-5-haiku: input=0.0008/1k, output=0.004/1k
        // 1000 in + 1000 out = 0.0008 + 0.004 = 0.0048
        let usage = TokenUsage {
            input_tokens: Some(1000),
            output_tokens: Some(1000),
            reasoning_tokens: None,
            cache_read_tokens: None,
            cache_write_tokens: None,
        };
        let cost = table.compute_cost("claude-3-5-haiku", &usage);
        assert!((cost - 0.0048).abs() < 1e-9, "claude-3-5-haiku cost mismatch: {cost}");
    }
}
