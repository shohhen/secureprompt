use secureprompt_common::types::TokenUsage;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy)]
pub struct ModelPricing {
    pub input_per_1k_usd: f64,
    pub output_per_1k_usd: f64,
}

#[derive(Debug, Default)]
pub struct PricingTable {
    entries: HashMap<String, ModelPricing>,
}

impl PricingTable {
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut entries = HashMap::new();
        entries.insert(
            "gpt-4o-mini".to_owned(),
            ModelPricing {
                input_per_1k_usd: 0.00015,
                output_per_1k_usd: 0.0006,
            },
        );
        entries.insert(
            "claude-3-5-haiku".to_owned(),
            ModelPricing {
                input_per_1k_usd: 0.0008,
                output_per_1k_usd: 0.004,
            },
        );
        entries.insert(
            "llama3.1".to_owned(),
            ModelPricing {
                input_per_1k_usd: 0.0,
                output_per_1k_usd: 0.0,
            },
        );

        Self { entries }
    }

    #[must_use]
    pub fn compute_cost(&self, model: &str, usage: &TokenUsage) -> f64 {
        let pricing = self.entries.get(model).copied().unwrap_or(ModelPricing {
            input_per_1k_usd: 0.0002,
            output_per_1k_usd: 0.0008,
        });

        let input = f64::from(usage.input_tokens.unwrap_or_default()) / 1000.0;
        let output = f64::from(usage.output_tokens.unwrap_or_default()) / 1000.0;

        (input * pricing.input_per_1k_usd) + (output * pricing.output_per_1k_usd)
    }
}
