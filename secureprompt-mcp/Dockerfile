# Phase 6 / Plan 06-03 — secureprompt-mcp Docker image.
# Multi-stage build: cargo build in builder, distroless/debian-slim in final.
# CRITICAL: this binary communicates over stdio — it is NOT a long-running HTTP server.
# Docker is used only for deployment packaging; the MCP host (Claude Desktop, Cursor, etc.)
# launches the binary directly.

FROM rust:1.89-slim-bookworm AS builder

WORKDIR /workspace
COPY . .

RUN cargo build --release --bin secureprompt-mcp

FROM debian:bookworm-slim AS final

# Install CA certs for outbound HTTPS to secureprompt-api.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /workspace/target/release/secureprompt-mcp /usr/local/bin/secureprompt-mcp

# MCP servers run interactively via stdio — no EXPOSE, no health check.
# Env vars required at runtime:
#   SECUREPROMPT_MCP_SERVICE_KEY — API key
#   SECUREPROMPT_API_URL         — Base URL (default: http://localhost:8080)
ENV SECUREPROMPT_API_URL=http://secureprompt-api:8080

ENTRYPOINT ["/usr/local/bin/secureprompt-mcp"]
