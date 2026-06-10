# Phase 6 / Plan 06-03 — secureprompt-mcp Docker image.
# Multi-stage build: cargo build in builder, distroless/debian-slim in final.
# CRITICAL: this binary communicates over stdio — it is NOT a long-running HTTP server.
# Docker is used only for deployment packaging; the MCP host (Claude Desktop, Cursor, etc.)
# launches the binary directly.

FROM rust:1.89-slim-bookworm AS builder

# sp-license is a private git+ssh dependency resolved across the workspace.
# Install the git CLI + ssh client, trust gitlab.com's host key, and let cargo
# use the git CLI so it honours the forwarded ssh agent (--mount=type=ssh).
RUN apt-get update && apt-get install -y --no-install-recommends \
    git openssh-client ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -p -m 0700 ~/.ssh && ssh-keyscan gitlab.com >> ~/.ssh/known_hosts
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true

WORKDIR /workspace
COPY . .

RUN --mount=type=ssh cargo build --release --bin secureprompt-mcp

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
