use crate::{
    http::model_router::ModelTarget,
    providers::{
        maybe_fail, render_output, ProviderAdapter, ProviderFailure, ProviderInvocation,
        ProviderOutput,
    },
};
use async_trait::async_trait;

pub struct OpenAiAdapter;

#[async_trait]
impl ProviderAdapter for OpenAiAdapter {
    fn provider_type(&self) -> &'static str {
        "openai"
    }

    async fn complete(
        &self,
        target: &ModelTarget,
        invocation: &ProviderInvocation,
    ) -> Result<ProviderOutput, ProviderFailure> {
        if let Some(failure) = maybe_fail(self.provider_type(), target, invocation) {
            return Err(failure);
        }
        Ok(render_output("openai", target, invocation, false))
    }

    async fn stream(
        &self,
        target: &ModelTarget,
        invocation: &ProviderInvocation,
    ) -> Result<ProviderOutput, ProviderFailure> {
        if let Some(failure) = maybe_fail(self.provider_type(), target, invocation) {
            return Err(failure);
        }
        Ok(render_output("openai", target, invocation, true))
    }
}
