# SecurePrompt

## Deploying

**The Docker Compose single-VM appliance is the primary supported install path**
— see [docs/deployment/](docs/deployment/README.md). Helm on Kubernetes is
secondary. `docker-compose.simple.yml` is for local evaluation only: it ships no
ML sidecar, so there is no NER coverage at all.

```bash
./scripts/init-env.sh     # generates every secret locally; .env.example is CHANGEME on purpose
docker compose up -d
```

Air-gapped installs: `scripts/bundle-images.sh` then
`docker compose -f docker-compose.yml -f docker-compose.onprem.yml up -d`.

---

SecurePrompt is an OpenAI-compatible LLM security gateway. The current Phase 2 slice exposes `/v1/chat/completions`, `/v1/completions`, and `/v1/embeddings`, runs API-key auth and rate limiting, applies detection and policy evaluation before provider invocation, restores placeholders on the response path, and emits async analytics off the hot path.

## Local Run

Start Postgres, then run the gateway:

```bash
docker compose up -d postgres
DATABASE_URL=postgres://secureprompt:secureprompt@127.0.0.1:5432/postgres cargo run -p secureprompt-api
```

The gateway exposes:

- `POST /v1/chat/completions`
- `POST /v1/completions`
- `POST /v1/embeddings`
- `GET /metrics`

## Phase 2 Test Path

Run the focused gateway checks:

```bash
cargo test --test openai_compat --test streaming_redaction --test token_usage_fallback --test provider_fallback --test fuzz_placeholder_boundaries -- --nocapture
```

Run the standing RLS gate:

```bash
cargo test --test cross_tenant -- --nocapture
```

## Streaming Notes

Streaming uses SSE and forces `stream_options.include_usage=true` on the gateway path. Reverse proxies must not buffer or gzip SSE traffic. See [docs/proxying/sse.md](docs/proxying/sse.md).
