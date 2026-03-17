#!/bin/sh
#
# ZeroPoint Network Sentinel — Installer for ASUS Merlin + Entware
# https://github.com/zeropoint-foundation/zeropoint
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/zeropoint-foundation/zeropoint/main/tools/merlin-sentinel/install.sh | sh
#
# Or clone and run locally:
#   git clone https://github.com/zeropoint-foundation/zeropoint.git
#   cd zeropoint/tools/merlin-sentinel
#   sh install.sh
#

set -e

# --- Configuration ---
INSTALL_DIR="/opt/etc/zp-sentinel"
CONFIG_FILE="/opt/etc/zp-sentinel.toml"
INIT_SCRIPT="/opt/etc/init.d/S99zp-sentinel"
WRAPPER="/opt/bin/zp-sentinel"
LOG_DIR="/opt/var/log"
RUN_DIR="/opt/var/run"
DATA_DIR="/opt/var/zp-sentinel"
CACHE_DIR="/opt/var/cache/zp-sentinel"
REPO_URL="https://raw.githubusercontent.com/zeropoint-foundation/zeropoint/main/tools/merlin-sentinel"

# --- Colors (if terminal supports them) ---
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' CYAN='' BOLD='' NC=''
fi

info()  { printf "${GREEN}✓${NC} %s\n" "$1"; }
warn()  { printf "${YELLOW}⚠${NC} %s\n" "$1"; }
fail()  { printf "${RED}✗${NC} %s\n" "$1"; exit 1; }
step()  { printf "\n${BOLD}%s${NC}\n" "$1"; }

# --- Header ---
printf "\n${CYAN}╔══════════════════════════════════════════════╗${NC}\n"
printf "${CYAN}║${NC}  ${BOLD}ZeroPoint Network Sentinel${NC}                   ${CYAN}║${NC}\n"
printf "${CYAN}║${NC}  Governance-based network monitoring          ${CYAN}║${NC}\n"
printf "${CYAN}║${NC}  for ASUS Merlin routers                      ${CYAN}║${NC}\n"
printf "${CYAN}╚══════════════════════════════════════════════╝${NC}\n\n"

# --- Preflight Checks ---
step "Preflight checks"

# Check Entware
if [ ! -d "/opt/bin" ]; then
    fail "Entware not found. Install Entware first: https://github.com/Entware/Entware/wiki"
fi
info "Entware found"

# Check architecture
ARCH=$(uname -m)
info "Architecture: $ARCH"

# --- Install Dependencies ---
step "Installing dependencies"

# Python 3
if /opt/bin/python3 --version >/dev/null 2>&1; then
    info "Python 3 already installed ($(/opt/bin/python3 --version 2>&1))"
else
    printf "  Installing python3..."
    opkg install python3 python3-pip >/dev/null 2>&1 || fail "Failed to install Python 3"
    info "Python 3 installed"
fi

# pip
if /opt/bin/pip3 --version >/dev/null 2>&1; then
    info "pip3 available"
else
    printf "  Installing pip3..."
    opkg install python3-pip >/dev/null 2>&1 || fail "Failed to install pip3"
    info "pip3 installed"
fi

# tomli (TOML parser — needed for Python < 3.11)
printf "  Installing tomli..."
if /opt/bin/pip3 install tomli >/dev/null 2>&1; then
    info "tomli installed"
else
    warn "tomli install failed (may already be available as tomllib)"
fi

# PyNaCl (Ed25519 signing for mesh identity — optional but recommended)
printf "  Installing PyNaCl (Ed25519 mesh identity)..."
if /opt/bin/pip3 install pynacl >/dev/null 2>&1; then
    info "PyNaCl installed (Ed25519 signing)"
else
    warn "PyNaCl not available — mesh will use HMAC-SHA256 fallback"
    warn "  Ed25519 is preferred. To retry: pip3 install pynacl"
fi

# openssh-sftp-server (for future SCP operations)
if [ ! -f "/opt/libexec/sftp-server" ]; then
    printf "  Installing openssh-sftp-server..."
    opkg install openssh-sftp-server >/dev/null 2>&1 || true
    info "sftp-server installed"
fi

# --- Create Directories ---
step "Creating directories"
for dir in "$INSTALL_DIR" "$LOG_DIR" "$RUN_DIR" "$DATA_DIR" "$CACHE_DIR"; do
    mkdir -p "$dir"
done
info "Directories created"

# --- Detect Source ---
# Check if running from cloned repo or curl-pipe-sh
SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd)" || SCRIPT_DIR=""

if [ -d "$SCRIPT_DIR/zp_sentinel" ]; then
    SOURCE="local"
    info "Installing from local files: $SCRIPT_DIR"
else
    SOURCE="remote"
    info "Installing from GitHub"
fi

# --- Copy Sentinel Module ---
step "Installing sentinel"

if [ "$SOURCE" = "local" ]; then
    cp -r "$SCRIPT_DIR/zp_sentinel" "$INSTALL_DIR/"
    info "Python modules copied"
else
    # Download from GitHub
    mkdir -p "$INSTALL_DIR/zp_sentinel"
    for mod in __init__.py main.py config.py gate.py audit.py dns_monitor.py device_monitor.py anomaly.py notifier.py mesh.py; do
        curl -fsSL "$REPO_URL/zp_sentinel/$mod" -o "$INSTALL_DIR/zp_sentinel/$mod" || fail "Failed to download $mod"
    done
    info "Python modules downloaded"
fi

# --- Install Config ---
if [ -f "$CONFIG_FILE" ]; then
    warn "Config already exists at $CONFIG_FILE — not overwriting"
    warn "New default config saved to ${CONFIG_FILE}.new for reference"
    if [ "$SOURCE" = "local" ]; then
        cp "$SCRIPT_DIR/zp-sentinel.toml" "${CONFIG_FILE}.new"
    else
        curl -fsSL "$REPO_URL/zp-sentinel.toml" -o "${CONFIG_FILE}.new"
    fi
else
    if [ "$SOURCE" = "local" ]; then
        cp "$SCRIPT_DIR/zp-sentinel.toml" "$CONFIG_FILE"
    else
        curl -fsSL "$REPO_URL/zp-sentinel.toml" -o "$CONFIG_FILE"
    fi
    info "Config installed at $CONFIG_FILE"
fi

# --- Install Init Script ---
if [ "$SOURCE" = "local" ]; then
    cp "$SCRIPT_DIR/S99zp-sentinel" "$INIT_SCRIPT"
else
    curl -fsSL "$REPO_URL/S99zp-sentinel" -o "$INIT_SCRIPT"
fi
chmod +x "$INIT_SCRIPT"
info "Init script installed"

# --- Create Wrapper Script ---
cat > "$WRAPPER" << 'WRAPPER_EOF'
#!/bin/sh
# ZeroPoint Network Sentinel CLI
PYTHON=/opt/bin/python3
SCRIPT_DIR=/opt/etc/zp-sentinel
export PYTHONPATH="$SCRIPT_DIR"
exec "$PYTHON" -B -m zp_sentinel.main "$@"
WRAPPER_EOF
chmod +x "$WRAPPER"
info "CLI wrapper installed at $WRAPPER"

# --- Verify ---
step "Verifying installation"

if "$WRAPPER" -c "$CONFIG_FILE" status >/dev/null 2>&1; then
    info "Sentinel CLI is functional"
else
    # May fail on first run if dnsmasq log doesn't exist yet — that's okay
    warn "CLI returned non-zero (this is normal on fresh installs)"
fi

# --- Done ---
printf "\n${GREEN}${BOLD}Installation complete!${NC}\n\n"

printf "${BOLD}Files:${NC}\n"
printf "  Config:   $CONFIG_FILE\n"
printf "  Modules:  $INSTALL_DIR/zp_sentinel/\n"
printf "  Data:     $DATA_DIR/\n"
printf "  Logs:     $LOG_DIR/zp-sentinel.log\n"
printf "  Alerts:   $DATA_DIR/alerts.log\n"
printf "  Init:     $INIT_SCRIPT\n"
printf "  CLI:      $WRAPPER\n"

printf "\n${BOLD}Commands:${NC}\n"
printf "  zp-sentinel status          Show sentinel health\n"
printf "  zp-sentinel monitor         Start monitoring (foreground)\n"
printf "  zp-sentinel alerts          View recent alerts\n"
printf "  zp-sentinel audit           View audit trail\n"
printf "  zp-sentinel verify          Verify audit chain integrity\n"
printf "  zp-sentinel devices         List known devices\n"
printf "  zp-sentinel block <MAC>     Block a MAC address\n"
printf "  zp-sentinel unblock <MAC>   Unblock a MAC address\n"
printf "  zp-sentinel ack <pattern>   Acknowledge critical alerts\n"

printf "\n${BOLD}Next steps:${NC}\n"
printf "  1. Edit config:        vi $CONFIG_FILE\n"
printf "  2. Add MAC blocklist:  [device] → mac_blocklist\n"
printf "  3. Set up alerts:      [notifications] → webhook_url\n"
printf "  4. Connect to mesh:    [mesh] → core_url (optional)\n"
printf "  5. Start service:      $INIT_SCRIPT start\n"
printf "  6. Verify chain:       zp-sentinel verify\n"

printf "\n${BOLD}Mesh registration:${NC}\n"
printf "  To join the ZeroPoint trust mesh, set core_url in [mesh].\n"
printf "  The Sentinel will announce itself to Core on startup and\n"
printf "  appear in the Bridge topology view. Identity key is auto-\n"
printf "  generated at /opt/var/zp-sentinel/identity.key.\n"

printf "\n${BOLD}Push notifications:${NC}\n"
printf "  Install Ntfy on your phone, subscribe to a unique topic,\n"
printf "  then set webhook_url and webhook_topic in the config.\n"
printf "  The sentinel will push to your phone when something happens.\n"

printf "\n${CYAN}Governed by ZeroPoint · https://zeropoint.global${NC}\n\n"

exit 0
