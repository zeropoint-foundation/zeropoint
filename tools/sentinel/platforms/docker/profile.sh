#!/bin/sh
# ZP Sentinel — Docker container platform profile
#
# Compatible with:
#   - Any Docker host (Linux, macOS, Windows)
#   - Docker Compose, Kubernetes, Podman
#   - Cloud container services (ECS, Cloud Run, etc.)
#
# Use case: Running Sentinel as a containerized mesh peer.
# DNS monitoring requires mounting the host's dnsmasq log.
#
# Requirements:
#   - Docker 20+ or Podman
#   - Optional: host dnsmasq log mounted at /var/log/dnsmasq.log

PLATFORM_NAME="Docker"
PLATFORM_ID="docker"

# Inside container, everything is pre-installed
PKG_MANAGER="none"
PKG_INSTALL="echo 'Dependencies baked into image'"
PIP_CMD="pip3"
PYTHON_CMD="python3"
PYTHON_PKG=""

# Paths — container-internal
INSTALL_DIR="/app"
CONFIG_FILE="/etc/zp-sentinel/zp-sentinel.toml"
LOG_DIR="/var/log/zp-sentinel"
RUN_DIR="/run/zp-sentinel"
DATA_DIR="/data"
CACHE_DIR="/var/cache/zp-sentinel"
WRAPPER="/usr/local/bin/zp-sentinel"

# Init system — none, container runs directly
INIT_SYSTEM="none"
INIT_SCRIPT=""

# DNS server
DNS_SERVER="dnsmasq"
DNS_LOG_PATH="/var/log/dnsmasq.log"
DHCP_LEASE_FILE="/var/lib/misc/dnsmasq.leases"

# Platform checks
check_platform() {
    if [ -f "/.dockerenv" ] || grep -q docker /proc/1/cgroup 2>/dev/null; then
        info "Running inside Docker container"
    else
        info "Docker profile selected (may be used for image build)"
    fi
    ARCH=$(uname -m)
    info "Architecture: $ARCH"
}

# Install Python — already in image
install_python() {
    info "Python pre-installed in container ($($PYTHON_CMD --version 2>&1))"
}

# No init script for containers
install_init() {
    info "Container mode — no init script needed (use docker run or compose)"
}

# Service control — container lifecycle
service_start()   { echo "Use: docker start zp-sentinel"; }
service_stop()    { echo "Use: docker stop zp-sentinel"; }
service_restart() { echo "Use: docker restart zp-sentinel"; }
service_enable()  { echo "Use: docker run --restart=unless-stopped"; }
