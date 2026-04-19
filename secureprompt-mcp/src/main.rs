//! Phase 6 / Plan 06-03 — SecurePrompt MCP server.
//!
//! Exposes 8 MCP tools over stdio transport using rmcp 1.5.0.
//! All tools are thin HTTP adapters over the running secureprompt-api.
//!
//! Environment variables:
//!   SECUREPROMPT_MCP_SERVICE_KEY — API key for authenticating to secureprompt-api (required)
//!   SECUREPROMPT_API_URL         — Base URL of running API (default: http://localhost:8080)
//!
//! Transport: stdio only (D-02). Streamable HTTP deferred to Phase 7.
//!
//! CRITICAL — Pitfall 2: ALL logging MUST go to stderr. stdout is the MCP
//! JSON-RPC transport pipe. Any println! or subscriber writing to stdout will
//! corrupt the protocol. tracing-subscriber is configured with .with_writer(std::io::stderr).

use anyhow::Result;
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, Content, ServerCapabilities, ServerInfo},
    schemars, tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler, ServiceExt,
    transport::stdio,
};
use serde::Deserialize;
use tracing_subscriber::EnvFilter;

// ── Tool parameter structs ──────────────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct RedactParams {
    #[schemars(description = "Text to scan for PII, secrets, and sensitive data")]
    pub text: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct EstimateTokensParams {
    #[schemars(description = "Text to estimate token count for")]
    pub text: String,
    #[schemars(description = "Provider name, e.g. 'openai', 'anthropic'")]
    pub provider: Option<String>,
    #[schemars(description = "Model name, e.g. 'gpt-4o', 'claude-3-5-sonnet-20241022'")]
    pub model: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct AuditQueryParams {
    #[schemars(description = "Maximum number of recent request events to return (max 100)")]
    pub limit: Option<u32>,
    #[schemars(description = "ISO8601 start time for the query window")]
    pub since: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct PolicyCheckParams {
    #[schemars(description = "Prompt text to dry-run against active policy rules")]
    pub prompt: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ListProvidersParams {
    // No params — tool lists all configured providers and models.
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ChatParams {
    #[schemars(description = "Model identifier, e.g. 'gpt-4o'")]
    pub model: String,
    #[schemars(description = "Array of message objects with 'role' and 'content' fields")]
    pub messages: serde_json::Value,
    #[schemars(description = "Maximum tokens to generate")]
    pub max_tokens: Option<u32>,
    #[schemars(description = "Temperature (0.0–2.0)")]
    pub temperature: Option<f32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct EmbeddingsParams {
    #[schemars(description = "Text or array of texts to embed")]
    pub input: serde_json::Value,
    #[schemars(description = "Model identifier, e.g. 'text-embedding-3-small'")]
    pub model: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct RedactWrapperParams {
    #[schemars(description = "Prompt text to redact before passing to the model")]
    pub prompt: String,
    #[schemars(description = "Model identifier")]
    pub model: String,
    #[schemars(description = "Additional messages for multi-turn context")]
    pub messages: Option<serde_json::Value>,
}

// ── Server struct ─────────────────────────────────────────────────────────────

#[derive(Clone)]
struct SecurePromptMcp {
    tool_router: ToolRouter<Self>,
    http_client: reqwest::Client,
    api_base_url: String,
    service_key: String,
}

impl SecurePromptMcp {
    fn new(api_base_url: String, service_key: String) -> Self {
        Self {
            tool_router: Self::tool_router(),
            http_client: reqwest::Client::new(),
            api_base_url,
            service_key,
        }
    }

    /// Convenience: POST to the API with the service key and return the JSON body as a String.
    async fn api_post(&self, path: &str, body: &serde_json::Value) -> Result<String, McpError> {
        let url = format!("{}{}", self.api_base_url.trim_end_matches('/'), path);
        let response = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.service_key))
            .header("Content-Type", "application/json")
            .json(body)
            .send()
            .await
            .map_err(|e| McpError::internal_error(format!("API request failed: {e}"), None))?;

        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|e| {
                McpError::internal_error(format!("API response read failed: {e}"), None)
            })?;

        if !status.is_success() {
            return Err(McpError::internal_error(
                format!("API returned {status}: {text}"),
                None,
            ));
        }
        Ok(text)
    }

    /// Convenience: GET to the API with the service key.
    async fn api_get(&self, path: &str) -> Result<String, McpError> {
        let url = format!("{}{}", self.api_base_url.trim_end_matches('/'), path);
        let response = self
            .http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.service_key))
            .send()
            .await
            .map_err(|e| McpError::internal_error(format!("API request failed: {e}"), None))?;

        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|e| {
                McpError::internal_error(format!("API response read failed: {e}"), None)
            })?;

        if !status.is_success() {
            return Err(McpError::internal_error(
                format!("API returned {status}: {text}"),
                None,
            ));
        }
        Ok(text)
    }
}

// ── Tool implementations ───────────────────────────────────────────────────────

#[tool_router]
impl SecurePromptMcp {
    /// Redact PII and secrets from text.
    /// Maps to: POST /v1/redact
    #[tool(description = "Scan text for PII, credentials, and sensitive data, and return a redacted version with detection metadata.")]
    async fn redact(
        &self,
        Parameters(p): Parameters<RedactParams>,
    ) -> Result<CallToolResult, McpError> {
        let body = serde_json::json!({ "text": p.text });
        let result = self.api_post("/v1/redact", &body).await?;
        tracing::debug!(chars = result.len(), "redact completed");
        Ok(CallToolResult::success(vec![Content::text(result)]))
    }

    /// Estimate token count for text, optionally for a specific provider+model.
    /// Maps to: POST /v1/tokens/estimate
    #[tool(description = "Estimate the number of tokens in text for a given provider and model.")]
    async fn estimate_tokens(
        &self,
        Parameters(p): Parameters<EstimateTokensParams>,
    ) -> Result<CallToolResult, McpError> {
        let mut body = serde_json::json!({ "text": p.text });
        if let Some(provider) = p.provider {
            body["provider"] = serde_json::Value::String(provider);
        }
        if let Some(model) = p.model {
            body["model"] = serde_json::Value::String(model);
        }
        let result = self.api_post("/v1/tokens/estimate", &body).await?;
        Ok(CallToolResult::success(vec![Content::text(result)]))
    }

    /// Query recent audit events (read-only).
    /// Maps to: GET /v1/requests
    #[tool(description = "Query recent request audit events. Returns a list of recent requests with metadata.")]
    async fn audit_query(
        &self,
        Parameters(p): Parameters<AuditQueryParams>,
    ) -> Result<CallToolResult, McpError> {
        let limit = p.limit.unwrap_or(20).min(100);
        let path = if let Some(since) = p.since {
            format!("/v1/requests?limit={limit}&since={since}")
        } else {
            format!("/v1/requests?limit={limit}")
        };
        let result = self.api_get(&path).await?;
        Ok(CallToolResult::success(vec![Content::text(result)]))
    }

    /// Dry-run a prompt against active policy rules.
    /// Maps to: POST /v1/policy/check
    #[tool(description = "Dry-run a prompt against all active policy rules. Returns which rules would match and what action would be taken.")]
    async fn policy_check(
        &self,
        Parameters(p): Parameters<PolicyCheckParams>,
    ) -> Result<CallToolResult, McpError> {
        let body = serde_json::json!({ "prompt": p.prompt, "dry_run": true });
        let result = self.api_post("/v1/policy/check", &body).await?;
        Ok(CallToolResult::success(vec![Content::text(result)]))
    }

    /// List configured providers and available models.
    /// Maps to: GET /v1/providers
    #[tool(description = "List all configured LLM providers and their available models.")]
    async fn list_providers(
        &self,
        Parameters(_p): Parameters<ListProvidersParams>,
    ) -> Result<CallToolResult, McpError> {
        let result = self.api_get("/v1/providers").await?;
        Ok(CallToolResult::success(vec![Content::text(result)]))
    }

    /// Call the gateway chat completions pipeline.
    /// Maps to: POST /v1/chat/completions (non-streaming)
    #[tool(description = "Send a chat completion request through the SecurePrompt gateway pipeline. Applies redaction, policy checks, and audit logging.")]
    async fn chat(
        &self,
        Parameters(p): Parameters<ChatParams>,
    ) -> Result<CallToolResult, McpError> {
        let mut body = serde_json::json!({
            "model": p.model,
            "messages": p.messages,
            "stream": false,
        });
        if let Some(max_tokens) = p.max_tokens {
            body["max_tokens"] = serde_json::Value::Number(max_tokens.into());
        }
        if let Some(temperature) = p.temperature {
            body["temperature"] = serde_json::json!(temperature);
        }
        let result = self.api_post("/v1/chat/completions", &body).await?;
        Ok(CallToolResult::success(vec![Content::text(result)]))
    }

    /// Call the gateway embeddings pipeline.
    /// Maps to: POST /v1/embeddings
    #[tool(description = "Generate embeddings for text through the SecurePrompt gateway pipeline.")]
    async fn embeddings(
        &self,
        Parameters(p): Parameters<EmbeddingsParams>,
    ) -> Result<CallToolResult, McpError> {
        let mut body = serde_json::json!({ "input": p.input });
        if let Some(model) = p.model {
            body["model"] = serde_json::Value::String(model);
        }
        let result = self.api_post("/v1/embeddings", &body).await?;
        Ok(CallToolResult::success(vec![Content::text(result)]))
    }

    /// Redact a prompt, then call the chat pipeline with the redacted version.
    /// This is the recommended tool for agents: redact first, then chat.
    /// Maps to: POST /v1/redact + POST /v1/chat/completions
    #[tool(description = "Redact sensitive data from a prompt and then send it through the chat pipeline. Combines redact and chat into a single safe step.")]
    async fn redact_wrapper(
        &self,
        Parameters(p): Parameters<RedactWrapperParams>,
    ) -> Result<CallToolResult, McpError> {
        // Step 1: Redact
        let redact_body = serde_json::json!({ "text": p.prompt });
        let redact_result_raw = self.api_post("/v1/redact", &redact_body).await?;
        let redact_result: serde_json::Value = serde_json::from_str(&redact_result_raw)
            .map_err(|e| McpError::internal_error(format!("redact parse failed: {e}"), None))?;
        let redacted_text = redact_result["redacted_text"]
            .as_str()
            .unwrap_or(&p.prompt)
            .to_owned();

        // Step 2: Build messages with redacted prompt
        let mut messages = p.messages.unwrap_or_else(|| serde_json::json!([]));
        if let Some(arr) = messages.as_array_mut() {
            arr.push(serde_json::json!({
                "role": "user",
                "content": redacted_text
            }));
        }

        // Step 3: Chat
        let chat_body = serde_json::json!({
            "model": p.model,
            "messages": messages,
            "stream": false,
        });
        let chat_result = self.api_post("/v1/chat/completions", &chat_body).await?;
        Ok(CallToolResult::success(vec![Content::text(chat_result)]))
    }
}

// ── ServerHandler impl ─────────────────────────────────────────────────────────

#[tool_handler]
impl ServerHandler for SecurePromptMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
    }
}

// ── Entry point ────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    // CRITICAL — Pitfall 2: tracing MUST write to stderr.
    // stdout is the MCP JSON-RPC transport — any bytes written to stdout corrupt the protocol.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr) // MUST be stderr, never stdout
        .with_ansi(false) // Disable ANSI codes for log aggregation compatibility
        .init();

    let service_key = std::env::var("SECUREPROMPT_MCP_SERVICE_KEY")
        .expect("SECUREPROMPT_MCP_SERVICE_KEY must be set (D-03)");
    let api_base_url = std::env::var("SECUREPROMPT_API_URL")
        .unwrap_or_else(|_| "http://localhost:8080".to_string());

    tracing::info!(api_base_url = %api_base_url, "SecurePrompt MCP server starting");

    let server = SecurePromptMcp::new(api_base_url, service_key);

    // rmcp 1.5.0 serve pattern: handler.serve(transport).await
    // NOT ServerBuilder::new().stdio() — that pattern does not exist in rmcp 1.x (Pitfall 1).
    let service = server.serve(stdio()).await?;

    // Wait until the MCP host closes the stdio connection.
    service.waiting().await?;

    tracing::info!("SecurePrompt MCP server shut down cleanly");
    Ok(())
}
