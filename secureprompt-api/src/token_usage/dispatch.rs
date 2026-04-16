use secureprompt_common::types::TokenUsage;

#[derive(Debug, Clone)]
pub struct UsageComputation {
    pub usage: TokenUsage,
    pub estimated: bool,
}

#[must_use]
pub fn derive_usage(
    provider_type: &str,
    reported: Option<TokenUsage>,
    prompt: &str,
    response: &str,
) -> UsageComputation {
    if let Some(usage) = reported {
        return UsageComputation {
            usage,
            estimated: false,
        };
    }

    UsageComputation {
        usage: TokenUsage {
            input_tokens: Some(estimate_tokens(provider_type, prompt)),
            output_tokens: Some(estimate_tokens(provider_type, response)),
            reasoning_tokens: Some(0),
            cache_read_tokens: Some(0),
            cache_write_tokens: Some(0),
        },
        estimated: true,
    }
}

#[must_use]
pub fn estimate_tokens(provider_type: &str, content: &str) -> u32 {
    let trimmed = content.trim();

    if trimmed.is_empty() {
        return 0;
    }

    let word_count = trimmed.split_whitespace().count() as u32;
    let char_count = trimmed.chars().count() as u32;

    match provider_type {
        "anthropic" => (char_count / 3).max(word_count),
        "ollama" | "vllm" => word_count.max(char_count / 5),
        _ => (char_count / 4).max(word_count),
    }
}
