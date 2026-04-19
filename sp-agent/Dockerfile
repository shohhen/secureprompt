FROM rust:1.89-slim-bookworm AS builder
WORKDIR /workspace

RUN rustup target add x86_64-unknown-linux-musl && \
    apt-get update && apt-get install -y --no-install-recommends musl-tools ca-certificates \
    && rm -rf /var/lib/apt/lists/*

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

RUN cargo build --release --target x86_64-unknown-linux-musl -p sp-agent

COPY . .
RUN touch sp-agent/src/main.rs && cargo build --release --target x86_64-unknown-linux-musl -p sp-agent

FROM scratch
COPY --from=builder /workspace/target/x86_64-unknown-linux-musl/release/sp-agent /sp-agent
ENTRYPOINT ["/sp-agent"]
