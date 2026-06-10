FROM rust:1.89-slim-bookworm AS builder
WORKDIR /workspace

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates git openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Cargo resolves the whole workspace, so this build fetches the private
# git+ssh sp-license dependency (used by secureprompt-api) even though the
# worker doesn't link it. Trust gitlab.com's host key and use the git CLI so
# cargo honours the forwarded ssh agent (--mount=type=ssh).
RUN mkdir -p -m 0700 ~/.ssh && ssh-keyscan gitlab.com >> ~/.ssh/known_hosts
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true

COPY Cargo.toml Cargo.lock ./
COPY secureprompt-common/Cargo.toml secureprompt-common/
COPY secureprompt-api/Cargo.toml secureprompt-api/
COPY secureprompt-worker/Cargo.toml secureprompt-worker/
COPY secureprompt-mcp/Cargo.toml secureprompt-mcp/
COPY sp-agent/Cargo.toml sp-agent/

RUN mkdir -p secureprompt-common/src && echo "pub fn _stub() {}" > secureprompt-common/src/lib.rs \
 && mkdir -p secureprompt-api/src && echo "fn main() {}" > secureprompt-api/src/main.rs \
 && mkdir -p secureprompt-worker/src && echo "fn main() {}" > secureprompt-worker/src/main.rs \
 && mkdir -p secureprompt-mcp/src && echo "fn main() {}" > secureprompt-mcp/src/main.rs \
 && mkdir -p sp-agent/src && echo "fn main() {}" > sp-agent/src/main.rs

RUN --mount=type=ssh cargo build --release -p secureprompt-worker

COPY . .
RUN --mount=type=ssh touch secureprompt-common/src/lib.rs secureprompt-worker/src/main.rs \
 && cargo build --release -p secureprompt-worker

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /workspace/target/release/secureprompt-worker /usr/local/bin/secureprompt-worker
COPY --from=builder /workspace/secureprompt-api/clickhouse/migrations /clickhouse/migrations
ENV CLICKHOUSE_MIGRATIONS_DIR=/clickhouse/migrations
ENTRYPOINT ["/usr/local/bin/secureprompt-worker"]
