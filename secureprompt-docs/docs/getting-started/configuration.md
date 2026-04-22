---
sidebar_position: 3
---

# Configuration

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | — | PostgreSQL connection string |
| `REDIS_URL` | — | Redis/Valkey connection string |
| `CLICKHOUSE_URL` | — | ClickHouse HTTP URL |
| `SECUREPROMPT_JWT_SECRET` | — | JWT signing secret (min 32 chars) |
| `KMS_FILE_KEY` | — | Base64-encoded 32-byte AES key for credential encryption |
| `ML_SIDECAR_URL` | `http://secureprompt-ml:8080` | ML sidecar URL |
| `QDRANT_URL` | `http://qdrant:6333` | Qdrant vector store URL |
| `LOG_LEVEL` | `info` | `trace`, `debug`, `info`, `warn`, `error` |

## Generating secrets

```bash
# JWT secret
openssl rand -base64 32

# KMS file key (must decode to exactly 32 bytes)
openssl rand 32 | base64
```

## Adding LLM providers

Providers are configured via the dashboard or API. Each provider stores its credential encrypted at rest using the KMS key.

```bash
curl -X POST http://localhost:8080/v1/providers \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "openai-prod",
    "provider_type": "openai",
    "credential": "sk-..."
  }'
```
