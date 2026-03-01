# ZeroPoint v2 — zp-server
# Multi-stage build for minimal production image
#
# Build:  docker build -t zp-server .
# Run:    docker run -p 8080:8080 zp-server

# --- Stage 1: Build ---
FROM rust:1.77-slim-bookworm AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace manifests first (cache dependency layer)
COPY Cargo.toml Cargo.lock ./
COPY crates/zp-core/Cargo.toml crates/zp-core/Cargo.toml
COPY crates/zp-audit/Cargo.toml crates/zp-audit/Cargo.toml
COPY crates/zp-policy/Cargo.toml crates/zp-policy/Cargo.toml
COPY crates/zp-trust/Cargo.toml crates/zp-trust/Cargo.toml
COPY crates/zp-pipeline/Cargo.toml crates/zp-pipeline/Cargo.toml
COPY crates/zp-llm/Cargo.toml crates/zp-llm/Cargo.toml
COPY crates/zp-skills/Cargo.toml crates/zp-skills/Cargo.toml
COPY crates/zp-learning/Cargo.toml crates/zp-learning/Cargo.toml
COPY crates/zp-mesh/Cargo.toml crates/zp-mesh/Cargo.toml
COPY crates/zp-server/Cargo.toml crates/zp-server/Cargo.toml
COPY crates/zp-cli/Cargo.toml crates/zp-cli/Cargo.toml
COPY policies/default-gate/Cargo.toml policies/default-gate/Cargo.toml

# Create stub lib.rs files so cargo can resolve the workspace
RUN for crate in zp-core zp-audit zp-policy zp-trust zp-pipeline zp-llm zp-skills zp-learning zp-mesh zp-server zp-cli; do \
      mkdir -p crates/$crate/src && echo "" > crates/$crate/src/lib.rs; \
    done && \
    mkdir -p crates/zp-server/src && echo "fn main() {}" > crates/zp-server/src/main.rs && \
    mkdir -p crates/zp-cli/src && echo "fn main() {}" > crates/zp-cli/src/main.rs && \
    mkdir -p policies/default-gate/src && echo "" > policies/default-gate/src/lib.rs

# Build dependencies only (cached unless Cargo.toml changes)
RUN cargo build --release -p zp-server 2>/dev/null || true

# Copy actual source
COPY crates/ crates/
COPY policies/ policies/

# Build the real binary
RUN cargo build --release -p zp-server

# --- Stage 2: Runtime ---
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd --create-home --shell /bin/bash zeropoint

WORKDIR /home/zeropoint

# Copy binary from builder
COPY --from=builder /build/target/release/zp-server .

# Own the working directory
RUN chown -R zeropoint:zeropoint /home/zeropoint

USER zeropoint

EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD curl -f http://localhost:8080/health || exit 1

ENV RUST_LOG=info

CMD ["./zp-server"]
