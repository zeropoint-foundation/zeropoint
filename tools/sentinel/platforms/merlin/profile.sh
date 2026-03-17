#!/bin/sh
# ZP Sentinel — ASUS Merlin + Entware platform profile
#
# Compatible with:
#   - ASUS RT-AX58U, RT-AX86U, RT-AX88U, GT-AX11000, etc.
#   - Any ASUS router running Asuswrt-Merlin firmware
#   - GNUton's Merlin fork for non-ASUS routers
#
# Requirements:
#   - Asuswrt-Merlin firmware (384.x+)
#   - Entware installed to USB drive
#   - Python 3.11+ via Entware

PLATFORM_NAME="ASUS Merlin (Entware)"
PLATFORM_ID="merlin"

# Package manager
PKG_MANAGER="opkg"
PKG_INSTALL="opkg install"
PIP_CMD="/opt/bin/pip3"
PYTHON_CMD="/opt/bin/python3"
PYTHON_PKG="python3 python3-pip"

# Paths
INSTALL_DIR="/opt/etc/zp-sentinel"
CONFIG_FILE="/opt/etc/zp-sentinel.toml"
LOG_DIR="/opt/var/log"
RUN_DIR="/opt/var/run"
DATA_DIR="/opt/var/zp-sentinel"
CACHE_DIR="/opt/var/cache/zp-sentinel"
INIT_SCRIPT="/opt/etc/init.d/S99zp-sentinel"
WRAPPER="/opt/bin/zp-sentinel"

# Init system
INIT_SYSTEM="entware"  # SysV-style init.d under /opt/etc/init.d

# DNS server (for log format detection)
DNS_SERVER="dnsmasq"
DNS_LOG_PATH="/var/log/dnsmasq.log"
DHCP_LEASE_FILE="/tmp/dnsmasq.leases"

# Platform checks
check_platform() {
    if [ ! -d "/opt/bin" ]; then
        fail "Entware not found. Install Entware first: https://github.com/Entware/Entware/wiki"
    fi
    info "Entware found at /opt"

    if [ -f "/usr/sbin/nvram" ]; then
        FW=$(nvram get firmver 2>/dev/null || echo "unknown")
        info "Firmware: $FW"
    fi

    ARCH=$(uname -m)
    info "Architecture: $ARCH"
}

# Install Python
install_python() {
    if $PYTHON_CMD --version >/dev/null 2>&1; then
        info "Python 3 already installed ($($PYTHON_CMD --version 2>&1))"
    else
        printf "  Installing python3 via opkg..."
        $PKG_INSTALL $PYTHON_PKG >/dev/null 2>&1 || fail "Failed to install Python 3"
        info "Python 3 installed"
    fi
}

# Install init script
install_init() {
    cp "$1" "$INIT_SCRIPT"
    chmod +x "$INIT_SCRIPT"
    info "Entware init script installed at $INIT_SCRIPT"
}

# Service control
service_start()   { "$INIT_SCRIPT" start; }
service_stop()    { "$INIT_SCRIPT" stop; }
service_restart() { "$INIT_SCRIPT" restart; }
service_enable()  { info "Entware auto-starts S99 scripts on boot"; }
