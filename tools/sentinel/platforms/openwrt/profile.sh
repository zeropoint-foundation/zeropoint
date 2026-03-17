#!/bin/sh
# ZP Sentinel — OpenWrt platform profile
#
# Compatible with:
#   - OpenWrt 21.02+ (any architecture)
#   - GL.iNet routers (GL-MT3000, GL-AXT1800, etc.)
#   - Turris Omnia / Turris MOX
#   - Any router running OpenWrt with opkg
#
# Requirements:
#   - OpenWrt 21.02+ with opkg
#   - Python 3.11+ (opkg or Entware)
#   - dnsmasq (default on OpenWrt)

PLATFORM_NAME="OpenWrt"
PLATFORM_ID="openwrt"

# Package manager
PKG_MANAGER="opkg"
PKG_INSTALL="opkg install"

# OpenWrt may have Python in /usr or /opt (Entware)
if [ -x "/usr/bin/python3" ]; then
    PIP_CMD="/usr/bin/pip3"
    PYTHON_CMD="/usr/bin/python3"
    PYTHON_PKG="python3 python3-pip"
    _PREFIX="/usr"
elif [ -x "/opt/bin/python3" ]; then
    PIP_CMD="/opt/bin/pip3"
    PYTHON_CMD="/opt/bin/python3"
    PYTHON_PKG="python3 python3-pip"
    _PREFIX="/opt"
else
    PIP_CMD="pip3"
    PYTHON_CMD="python3"
    PYTHON_PKG="python3 python3-pip"
    _PREFIX="/usr"
fi

# Paths — prefer /opt if Entware present, else /etc
if [ -d "/opt/etc" ]; then
    INSTALL_DIR="/opt/etc/zp-sentinel"
    CONFIG_FILE="/opt/etc/zp-sentinel.toml"
    LOG_DIR="/opt/var/log"
    RUN_DIR="/opt/var/run"
    DATA_DIR="/opt/var/zp-sentinel"
    CACHE_DIR="/opt/var/cache/zp-sentinel"
    WRAPPER="/opt/bin/zp-sentinel"
else
    INSTALL_DIR="/etc/zp-sentinel"
    CONFIG_FILE="/etc/zp-sentinel.toml"
    LOG_DIR="/var/log"
    RUN_DIR="/var/run"
    DATA_DIR="/var/zp-sentinel"
    CACHE_DIR="/var/cache/zp-sentinel"
    WRAPPER="/usr/bin/zp-sentinel"
fi

# Init system — OpenWrt uses procd
INIT_SYSTEM="procd"
INIT_SCRIPT="/etc/init.d/zp-sentinel"

# DNS server
DNS_SERVER="dnsmasq"
DNS_LOG_PATH="/tmp/dnsmasq.log"
DHCP_LEASE_FILE="/tmp/dhcp.leases"

# Platform checks
check_platform() {
    if ! command -v opkg >/dev/null 2>&1; then
        fail "opkg not found — is this OpenWrt?"
    fi
    info "OpenWrt detected"

    if [ -f "/etc/openwrt_release" ]; then
        . /etc/openwrt_release
        info "Distribution: ${DISTRIB_DESCRIPTION:-OpenWrt}"
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
        opkg update >/dev/null 2>&1
        $PKG_INSTALL $PYTHON_PKG >/dev/null 2>&1 || fail "Failed to install Python 3"
        info "Python 3 installed"
    fi
}

# Install init script (procd-style)
install_init() {
    # Convert SysV init to procd if needed, or use procd template
    cat > "$INIT_SCRIPT" << 'PROCD_EOF'
#!/bin/sh /etc/rc.common
# ZeroPoint Network Sentinel — procd init script

START=99
STOP=10
USE_PROCD=1

PROG=/usr/bin/zp-sentinel
CONF=/etc/zp-sentinel.toml

start_service() {
    procd_open_instance
    procd_set_param command $PROG -c $CONF monitor
    procd_set_param respawn
    procd_set_param stderr 1
    procd_set_param stdout 1
    procd_close_instance
}
PROCD_EOF
    # Fix paths if using /opt
    if [ "$INSTALL_DIR" = "/opt/etc/zp-sentinel" ]; then
        sed -i "s|PROG=/usr/bin|PROG=/opt/bin|" "$INIT_SCRIPT"
        sed -i "s|CONF=/etc/|CONF=/opt/etc/|" "$INIT_SCRIPT"
    fi
    chmod +x "$INIT_SCRIPT"
    info "procd init script installed at $INIT_SCRIPT"
}

# Service control
service_start()   { "$INIT_SCRIPT" start; }
service_stop()    { "$INIT_SCRIPT" stop; }
service_restart() { "$INIT_SCRIPT" restart; }
service_enable()  { "$INIT_SCRIPT" enable; }
