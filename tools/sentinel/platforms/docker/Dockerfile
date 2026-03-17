# ZeroPoint Network Sentinel — Docker image
# Multi-arch: linux/amd64, linux/arm64, linux/arm/v7
#
# Build:
#   docker build -t zp-sentinel -f platforms/docker/Dockerfile .
#
# Run:
#   docker run -d --name zp-sentinel \
#     -v /path/to/zp-sentinel.toml:/etc/zp-sentinel/zp-sentinel.toml:ro \
#     -v sentinel-data:/data \
#     -v /var/log/dnsmasq.log:/var/log/dnsmasq.log:ro \
#     zp-sentinel
#
# Run without DNS monitoring (mesh peer only):
#   docker run -d --name zp-sentinel \
#     -v /path/to/zp-sentinel.toml:/etc/zp-sentinel/zp-sentinel.toml:ro \
#     -v sentinel-data:/data \
#     zp-sentinel

FROM python:3.11-slim AS base

# Labels
LABEL org.opencontainers.image.title="ZeroPoint Sentinel"
LABEL org.opencontainers.image.description="Governance-based network monitoring for the ZeroPoint trust mesh"
LABEL org.opencontainers.image.url="https://zeropoint.global/sentinel"
LABEL org.opencontainers.image.source="https://github.com/zeropoint-foundation/zeropoint"

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Python deps
RUN pip install --no-cache-dir pynacl blake3 tomli

# Create directories
RUN mkdir -p /app /etc/zp-sentinel /data /var/log/zp-sentinel /var/cache/zp-sentinel

# Copy sentinel module
COPY zp_sentinel/ /app/zp_sentinel/

# Wrapper script
RUN printf '#!/bin/sh\nexec python3 -B -m zp_sentinel.main "$@"\n' > /usr/local/bin/zp-sentinel \
    && chmod +x /usr/local/bin/zp-sentinel

# Default config (overridden by mount)
COPY platforms/docker/zp-sentinel.docker.toml /etc/zp-sentinel/zp-sentinel.toml

ENV PYTHONPATH=/app
WORKDIR /app

VOLUME ["/data", "/etc/zp-sentinel"]

ENTRYPOINT ["zp-sentinel"]
CMD ["-c", "/etc/zp-sentinel/zp-sentinel.toml", "monitor"]
