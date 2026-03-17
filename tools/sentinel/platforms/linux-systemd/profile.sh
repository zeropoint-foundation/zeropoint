#!/bin/sh
# ZP Sentinel — Standard Linux (systemd) platform profile
#
# Compatible with:
#   - Ubuntu 22.04+, Debian 12+
#   - Fedora 38+, CentOS Stream 9+
#   - Raspberry Pi OS (Bookworm+)
#   - Any Linux with systemd and Python 3.11+
#
# Use case: Running Sentinel on a dedicated box (Raspberry Pi,
# NUC, Mac Mini, server) that monitors dnsmasq or acts as a
# standalone mesh peer.
#
# Requirements:
#   - Python 3.11+
#   - systemd
#   - dnsmasq (optional — Sentinel runs without it, just no DNS monitoring)

PLATFORM_NAME="Linux (systemd)"
PLATFORM_ID="linux-systemd"

# Package manager detection
if command -v apt-get >/dev/null 2>&1; then
    PKG_MANAGER="apt"
    PKG_INSTALL="apt-get install -y"
    PYTHON_PKG="python3 python3-pip python3-venv"
elif command -v dnf >/dev/null 2>&1; then
    PKG_MANAGER="dnf"
    PKG_INSTALL="dnf install -y"
    PYTHON_PKG="python3 python3-pip"
elif command -v pacman >/dev/null 2>&1; then
    PKG_MANAGER="pacman"
    PKG_INSTALL="pacman -S --noconfirm"
    PYTHON_PKG="python python-pip"
else
    PKG_MANAGER="unknown"
    PKG_INSTALL="echo 'Install manually:'"
    PYTHON_PKG="python3 python3-pip"
fi

PIP_CMD="pip3"
PYTHON_CMD="python3"

# Paths — FHS standard
INSTALL_DIR="/opt/zp-sentinel"
CONFIG_FILE="/etc/zp-sentinel/zp-sentinel.toml"
LOG_DIR="/var/log/zp-sentinel"
RUN_DIR="/run/zp-sentinel"
DATA_DIR="/var/lib/zp-sentinel"
CACHE_DIR="/var/cache/zp-sentinel"
WRAPPER="/usr/local/bin/zp-sentinel"

# Init system
INIT_SYSTEM="systemd"
INIT_SCRIPT="/etc/systemd/system/zp-sentinel.service"

# DNS server — optional on standard Linux
DNS_SERVER="dnsmasq"
DNS_LOG_PATH="/var/log/dnsmasq.log"
DHCP_LEASE_FILE="/var/lib/misc/dnsmasq.leases"

# Platform checks
check_platform() {
    if ! command -v systemctl >/dev/null 2>&1; then
        warn "systemd not found — service management will be manual"
    else
        info "systemd detected"
    fi

    if command -v dnsmasq >/dev/null 2>&1; then
        info "dnsmasq found — DNS monitoring available"
    else
        warn "dnsmasq not found — DNS monitoring will be disabled"
        warn "  Sentinel will still work for mesh, anomaly detection, and audit"
    fi

    ARCH=$(uname -m)
    info "Architecture: $ARCH"

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        info "OS: ${PRETTY_NAME:-Linux}"
    fi
}

# Install Python
install_python() {
    if $PYTHON_CMD --version >/dev/null 2>&1; then
        PY_VER=$($PYTHON_CMD --version 2>&1)
        info "Python 3 already installed ($PY_VER)"
    else
        printf "  Installing python3 via $PKG_MANAGER..."
        $PKG_INSTALL $PYTHON_PKG >/dev/null 2>&1 || fail "Failed to install Python 3"
        info "Python 3 installed"
    fi
}

# Install init script (systemd unit)
install_init() {
    cat > "$INIT_SCRIPT" << SYSTEMD_EOF
[Unit]
Description=ZeroPoint Network Sentinel
Documentation=https://zeropoint.global/sentinel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$WRAPPER -c $CONFIG_FILE monitor
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR $LOG_DIR $CACHE_DIR
PrivateTmp=true

[Install]
WantedBy=multi-user.target
SYSTEMD_EOF
    systemctl daemon-reload 2>/dev/null || true
    info "systemd unit installed at $INIT_SCRIPT"
}

# Service control
service_start()   { systemctl start zp-sentinel; }
service_stop()    { systemctl stop zp-sentinel; }
service_restart() { systemctl restart zp-sentinel; }
service_enable()  { systemctl enable zp-sentinel; }
