---
sidebar_position: 1
---

# Quickstart

Get SecurePrompt running locally in under 5 minutes.

## Prerequisites

- Docker and Docker Compose v2
- An OpenAI (or compatible) API key

## 1. Clone and start

```bash
git clone https://github.com/secureprompt/secureprompt.git
cd secureprompt
cp .env.example .env
docker compose up -d
```

## 2. Create your first API key

```bash
# Get a JWT by logging in
TOKEN=$(curl -s -X POST http://localhost:8080/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"changeme"}' \
  | jq -r .access_token)

# Create a gateway key
curl -X POST http://localhost:8080/v1/keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"my-first-key"}'
```

## 3. Send your first request

Point your OpenAI client at `http://localhost:8080` and use your SecurePrompt key:

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer sp-your-key-here" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

## 4. View the dashboard

Open **http://localhost:3000** — you'll see your request logged with token counts, latency, and any detected violations.

## Next steps

- [Configure providers](./configuration) — add your LLM API credentials
- [Set up policies](../concepts/policies) — define what gets blocked or redacted
- [Enable Secure Mode](../concepts/secure-mode) — turn on ML-based protections
