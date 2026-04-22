---
slug: /
sidebar_position: 1
---

# Introduction

**SecurePrompt** is an LLM security gateway that sits between your applications and AI providers — redacting secrets and PII, enforcing policy, tracking tokens and costs, and providing governance analytics.

## What SecurePrompt does

- **PII & secret redaction** — Strip names, emails, API keys, and credentials before they reach any LLM provider.
- **Policy enforcement** — Block or transform requests that violate your org's rules, with semantic RAG-based matching.
- **Prompt injection detection** — ML-based detection of adversarial prompt injection attempts.
- **Token & cost tracking** — Real-time ClickHouse-backed analytics per model, workspace, and time window.
- **OpenAI-compatible gateway** — Drop-in replacement for `api.openai.com`; no client-side SDK changes needed.
- **MCP integration** — Native Model Context Protocol server for Claude Desktop and other MCP clients.

## Architecture

```
Client App  →  SecurePrompt Gateway  →  LLM Provider (OpenAI, Anthropic, …)
                     │
              ┌──────┴──────┐
         ML Sidecar     ClickHouse
         (PII/NER/RAG)  (Analytics)
```

## Quick links

- [Quickstart](./getting-started/quickstart) — up and running in 5 minutes
- [MCP Quickstart](./getting-started/mcp-quickstart) — connect Claude Desktop
- [API Reference](./api-reference/overview) — full endpoint documentation
- [Self-hosting](./guides/self-hosting) — deploy on-prem with Docker Compose
