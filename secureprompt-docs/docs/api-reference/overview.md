---
sidebar_position: 1
---

# API Reference Overview

SecurePrompt exposes a REST API at `http://localhost:8080`.

## Base URL

```
http://localhost:8080   (self-hosted)
https://api.secureprompt.tech   (cloud)
```

## Authentication

Two token types are used:

| Type | Header | Routes |
|------|--------|--------|
| **JWT** (dashboard users) | `Authorization: Bearer eyJ...` | `/v1/auth/*`, `/v1/analytics/*`, `/v1/keys`, `/v1/providers`, `/v1/policy-rules`, `/v1/requests` |
| **API Key** (gateway clients) | `Authorization: Bearer sp-...` | `/v1/chat/completions`, `/v1/completions`, `/v1/embeddings`, `/v1/redact`, `/v1/tokens/estimate`, `/v1/policy/check` |

## Endpoints

### Auth
<span className="api-method api-method-post">POST</span> `/v1/auth/token` — Login, get JWT  
<span className="api-method api-method-post">POST</span> `/v1/auth/refresh` — Refresh access token  
<span className="api-method api-method-post">POST</span> `/v1/auth/logout` — Revoke refresh token  

### Gateway (OpenAI-compatible)
<span className="api-method api-method-post">POST</span> `/v1/chat/completions`  
<span className="api-method api-method-post">POST</span> `/v1/completions`  
<span className="api-method api-method-post">POST</span> `/v1/embeddings`  

### MCP Utilities
<span className="api-method api-method-post">POST</span> `/v1/redact`  
<span className="api-method api-method-post">POST</span> `/v1/tokens/estimate`  
<span className="api-method api-method-post">POST</span> `/v1/policy/check`  

### Analytics
<span className="api-method api-method-get">GET</span> `/v1/analytics/usage-daily`  
<span className="api-method api-method-get">GET</span> `/v1/analytics/cost-by-model`  
<span className="api-method api-method-get">GET</span> `/v1/analytics/latency-pctiles`  
<span className="api-method api-method-get">GET</span> `/v1/analytics/policy-violations`  

### Management
<span className="api-method api-method-get">GET</span> `/v1/keys` — List API keys  
<span className="api-method api-method-post">POST</span> `/v1/keys` — Create API key  
<span className="api-method api-method-get">GET</span> `/v1/providers` — List providers  
<span className="api-method api-method-post">POST</span> `/v1/providers` — Create provider  
<span className="api-method api-method-get">GET</span> `/v1/policy-rules` — List policy rules  
<span className="api-method api-method-post">POST</span> `/v1/policy-rules` — Create policy rule  
<span className="api-method api-method-get">GET</span> `/v1/requests` — List gateway requests  

### Observability
<span className="api-method api-method-get">GET</span> `/metrics` — Prometheus metrics  
