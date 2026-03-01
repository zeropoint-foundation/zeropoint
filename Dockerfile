# ZeroPoint Build Environment
# Multi-stage Dockerfile based on Debian Bookworm for lean, auditable builds
#
# Usage:
#   docker build -t zeropoint-builder .
#   docker run -v $(pwd):/workspace zeropoint-builder cargo build --release
#
# Cross-compile for aarch64:
#   docker run -v $(pwd):/workspace zeropoint-builder \
#     cargo build --release --target aarch64-unknown-linux-gnu

# =============================================================================
# Stage 1: Builder base with Rust toolchain on Debian Bookworm
# =============================================================================
FROM rust:bookworm AS builder-base

# Avoid prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Enable multiarch for aarch64 cross-compilation
RUN dpkg --add-architecture arm64

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build essentials
    build-essential \
    pkg-config \
    libssl-dev \
    libsqlite3-dev \
    cmake \
    git \
    # For llama.cpp / bindgen (libclang required)
    llvm \
    clang \
    libclang-dev \
    # For cross-compilation to aarch64
    gcc-aarch64-linux-gnu \
    g++-aarch64-linux-gnu \
    libc6-dev-arm64-cross \
    libssl-dev:arm64 \
    && rm -rf /var/lib/apt/lists/*

# Find libclang and write the path to a file that persists across RUN commands
RUN LIBCLANG_DIR=$(find /usr -name "libclang.so*" -o -name "libclang-*.so*" 2>/dev/null | head -1 | xargs -r dirname) && \
    if [ -n "$LIBCLANG_DIR" ]; then \
        echo "Found libclang at: $LIBCLANG_DIR"; \
        echo "$LIBCLANG_DIR" > /tmp/libclang_path; \
    else \
        echo "ERROR: libclang not found!"; \
        find /usr -name "*clang*" -type f 2>/dev/null | head -20; \
        exit 1; \
    fi

# Set LLVM environment variables
ENV LLVM_CONFIG_PATH=/usr/bin/llvm-config
ENV BINDGEN_EXTRA_CLANG_ARGS="-I/usr/include"

# Create wrapper script that sets LIBCLANG_PATH dynamically
RUN echo '#!/bin/bash\n\
export LIBCLANG_PATH=$(find /usr -name "libclang.so*" -o -name "libclang-*.so*" 2>/dev/null | head -1 | xargs -r dirname)\n\
exec "$@"' > /usr/local/bin/with-libclang && chmod +x /usr/local/bin/with-libclang

# Install additional Rust targets for cross-compilation
RUN rustup target add aarch64-unknown-linux-gnu \
    && rustup target add x86_64-apple-darwin \
    && rustup target add aarch64-apple-darwin \
    && rustup component add rustfmt clippy

# Set up cargo config for cross-compilation linkers
RUN mkdir -p /usr/local/cargo && echo '\
[target.aarch64-unknown-linux-gnu]\n\
linker = "aarch64-linux-gnu-gcc"\n\
\n\
[target.aarch64-unknown-linux-gnu.openssl-sys]\n\
# Point openssl-sys to the arm64 cross-compilation libraries\n\
# This is set via environment variables in the compose/CI config\n\
' > /usr/local/cargo/config.toml

# Create a cargo wrapper that sets LIBCLANG_PATH for every cargo invocation
RUN LIBCLANG_DIR=$(cat /tmp/libclang_path) && \
    mv /usr/local/cargo/bin/cargo /usr/local/cargo/bin/cargo.real && \
    printf '#!/bin/bash\nexport LIBCLANG_PATH=%s\nexec /usr/local/cargo/bin/cargo.real "$@"\n' "$LIBCLANG_DIR" > /usr/local/cargo/bin/cargo && \
    chmod +x /usr/local/cargo/bin/cargo && \
    echo "Created cargo wrapper with LIBCLANG_PATH=$LIBCLANG_DIR"

WORKDIR /workspace

# =============================================================================
# Stage 2: Development environment (build tools + dev conveniences)
# =============================================================================
FROM builder-base AS dev

# Install dev tools and cargo extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    ripgrep \
    fd-find \
    jq \
    less \
    vim \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install cargo tools for development
RUN cargo install cargo-watch cargo-audit cargo-outdated cargo-deny

# Default command for dev container
CMD ["bash"]

# =============================================================================
# Stage 3: Build stage (optimized for CI/release builds)
# =============================================================================
FROM builder-base AS build

# Copy source code
COPY . .

# Build release binaries
RUN cargo build --release

# =============================================================================
# Stage 4: Runtime image (minimal Debian for deployment)
# =============================================================================
FROM debian:bookworm-slim AS runtime

ENV DEBIAN_FRONTEND=noninteractive

# Install only runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    libsqlite3-0 \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 zeropoint

# Copy binaries from build stage
COPY --from=build /workspace/target/release/zeropoint-server /usr/local/bin/
COPY --from=build /workspace/target/release/zp /usr/local/bin/

# Copy config files
COPY --from=build /workspace/config /etc/zeropoint/config

# Set ownership
RUN chown -R zeropoint:zeropoint /etc/zeropoint

USER zeropoint
WORKDIR /home/zeropoint

# Default port
EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -fsk https://localhost:3001/health || exit 1

# Default command
CMD ["zeropoint-server", "--server", "--port", "3001"]
