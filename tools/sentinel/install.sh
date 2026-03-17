#!/bin/sh
#
# ZeroPoint Network Sentinel — Universal Installer
# https://github.com/zeropoint-foundation/zeropoint
#
# Auto-detects platform or accepts --platform flag:
#
#   curl -fsSL https://zeropoint.global/sentinel/install.sh | sh
#   curl -fsSL https://zeropoint.global/sentinel/install.sh | sh -s -- --platform merlin
#   curl -fsSL https://zeropoint.global/sentinel/install.sh | sh -s -- --platform openwrt
#   curl -fsSL https://zeropoint.global/sentinel/install.sh | sh -s -- --platform linux
#
# Or clone and run locally:
#   git clone https://github.com/zeropoint-foundation/zeropoint.git
#   cd zeropoint/tools/sentinel
#   sh install.sh
#

set -e

REPO_URL="https://raw.githubusercontent.com/zeropoint-foundation/zeropoint/main/tools/sentinel"
VERSION="0.3.0"

# --- Colors ---
if [ -t 1 ]; then
    RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[1;33m'
    CYAN='\033[0;36m' BOLD='\033[1m' DIM='\033[2m' NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' CYAN='' BOLD='' DIM='' NC=''
fi

info()  { printf "${GREEN}✓${NC} %s\n" "$1"; }
warn()  { printf "${YELLOW}⚠${NC} %s\n" "$1"; }
fail()  { printf "${RED}✗${NC} %s\n" "$1"; exit 1; }
step()  { printf "\n${BOLD}%s${NC}\n" "$1"; }

# --- Header ---
printf "\n${CYAN}╔══════════════════════════════════════════════╗${NC}\n"
printf "${CYAN}║${NC}  ${BOLD}ZeroPoint Network Sentinel${NC} v${VERSION}          ${CYAN}║${NC}\n"
printf "${CYAN}║${NC}  Governance-based network monitoring          ${CYAN}║${NC}\n"
printf "${CYAN}║${NC}  ${DIM}https://zeropoint.global/sentinel${NC}             ${CYAN}║${NC}\n"
printf "${CYAN}╚══════════════════════════════════════════════╝${NC}\n\n"

# --- Parse Arguments ---
PLATFORM_OVERRIDE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --platform|-p) PLATFORM_OVERRIDE="$2"; shift 2 ;;
        --help|-h)
            printf "Usage: install.sh [--platform <platform>]\n\n"
            printf "Platforms:\n"
            printf "  merlin        ASUS Merlin routers (Entware)\n"
            printf "  openwrt       OpenWrt / GL.iNet / Turris\n"
            printf "  linux         Standard Linux (systemd)\n"
            printf "  docker        Docker container build\n"
            printf "\nIf --platform is omitted, auto-detection is used.\n"
            exit 0 ;;
        *) shift ;;
    esac
done

# --- Auto-detect Platform ---
detect_platform() {
    # Check for ASUS Merlin
    if [ -f "/usr/sbin/nvram" ] && [ -d "/opt/bin" ]; then
        echo "merlin"
        return
    fi

    # Check for OpenWrt
    if [ -f "/etc/openwrt_release" ]; then
        echo "openwrt"
        return
    fi

    # Check for Entware without Merlin (could be OpenWrt+Entware)
    if [ -d "/opt/bin" ] && command -v opkg >/dev/null 2>&1; then
        echo "openwrt"
        return
    fi

    # Check for Docker
    if [ -f "/.dockerenv" ] || grep -q docker /proc/1/cgroup 2>/dev/null; then
        echo "docker"
        return
    fi

    # Check for systemd Linux
    if command -v systemctl >/dev/null 2>&1; then
        echo "linux-systemd"
        return
    fi

    echo "unknown"
}

step "Detecting platform"

if [ -n "$PLATFORM_OVERRIDE" ]; then
    # Normalize platform name
    case "$PLATFORM_OVERRIDE" in
        merlin|asus|asus-merlin) PLATFORM="merlin" ;;
        openwrt|glinet|turris)   PLATFORM="openwrt" ;;
        linux|linux-systemd|systemd|debian|ubuntu|fedora|raspi|raspberry) PLATFORM="linux-systemd" ;;
        docker|container)        PLATFORM="docker" ;;
        *) fail "Unknown platform: $PLATFORM_OVERRIDE (use: merlin, openwrt, linux, docker)" ;;
    esac
    info "Platform override: $PLATFORM"
else
    PLATFORM=$(detect_platform)
    if [ "$PLATFORM" = "unknown" ]; then
        printf "\n${YELLOW}Could not auto-detect platform.${NC}\n"
        printf "Please specify: ${BOLD}--platform merlin|openwrt|linux|docker${NC}\n\n"
        exit 1
    fi
    info "Auto-detected: $PLATFORM"
fi

# --- Load Platform Profile ---
SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd)" || SCRIPT_DIR=""

if [ -f "$SCRIPT_DIR/platforms/$PLATFORM/profile.sh" ]; then
    . "$SCRIPT_DIR/platforms/$PLATFORM/profile.sh"
    info "Platform profile loaded (local): $PLATFORM_NAME"
else
    # Download profile
    PROFILE_TMP=$(mktemp)
    curl -fsSL "$REPO_URL/platforms/$PLATFORM/profile.sh" -o "$PROFILE_TMP" \
        || fail "Failed to download platform profile for $PLATFORM"
    . "$PROFILE_TMP"
    rm -f "$PROFILE_TMP"
    info "Platform profile loaded (remote): $PLATFORM_NAME"
fi

# --- Preflight ---
step "Preflight checks"
check_platform

# --- Install Dependencies ---
step "Installing dependencies"
install_python

# pip dependencies
printf "  Installing tomli..."
if $PIP_CMD install tomli >/dev/null 2>&1; then
    info "tomli installed"
else
    warn "tomli install failed (may already be available as tomllib)"
fi

printf "  Installing PyNaCl (Ed25519 mesh identity)..."
if $PIP_CMD install pynacl >/dev/null 2>&1; then
    info "PyNaCl installed (Ed25519 signing)"
else
    warn "PyNaCl not available — mesh will use HMAC-SHA256 fallback"
fi

printf "  Installing blake3 (audit chain hashing)..."
if $PIP_CMD install blake3 >/dev/null 2>&1; then
    info "blake3 installed"
else
    warn "blake3 not available — audit will use SHA-256 fallback"
fi

# --- Create Directories ---
step "Creating directories"
for dir in "$INSTALL_DIR" "$LOG_DIR" "$RUN_DIR" "$DATA_DIR" "$CACHE_DIR"; do
    mkdir -p "$dir"
done
# Config directory (may differ from INSTALL_DIR)
mkdir -p "$(dirname "$CONFIG_FILE")"
info "Directories created"

# --- Detect Source ---
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
    mkdir -p "$INSTALL_DIR/zp_sentinel"
    for mod in __init__.py main.py config.py gate.py audit.py dns_monitor.py device_monitor.py anomaly.py notifier.py mesh.py; do
        curl -fsSL "$REPO_URL/zp_sentinel/$mod" -o "$INSTALL_DIR/zp_sentinel/$mod" \
            || fail "Failed to download $mod"
    done
    info "Python modules downloaded"
fi

# --- Install Config ---
if [ -f "$CONFIG_FILE" ]; then
    warn "Config exists at $CONFIG_FILE — not overwriting"
    warn "New defaults saved to ${CONFIG_FILE}.new"
    if [ "$SOURCE" = "local" ]; then
        cp "$SCRIPT_DIR/platforms/$PLATFORM/zp-sentinel.${PLATFORM}.toml" "${CONFIG_FILE}.new" 2>/dev/null \
            || cp "$SCRIPT_DIR/zp-sentinel.toml" "${CONFIG_FILE}.new" 2>/dev/null \
            || curl -fsSL "$REPO_URL/platforms/$PLATFORM/zp-sentinel.${PLATFORM_ID}.toml" -o "${CONFIG_FILE}.new" 2>/dev/null \
            || true
    fi
else
    # Try platform-specific config first, fall back to default
    if [ "$SOURCE" = "local" ] && [ -f "$SCRIPT_DIR/platforms/$PLATFORM/zp-sentinel.${PLATFORM_ID}.toml" ]; then
        cp "$SCRIPT_DIR/platforms/$PLATFORM/zp-sentinel.${PLATFORM_ID}.toml" "$CONFIG_FILE"
    elif [ "$SOURCE" = "local" ]; then
        cp "$SCRIPT_DIR/zp-sentinel.toml" "$CONFIG_FILE"
    else
        curl -fsSL "$REPO_URL/zp-sentinel.toml" -o "$CONFIG_FILE"
    fi

    # Patch paths to match platform
    if command -v sed >/dev/null 2>&1; then
        sed -i "s|/opt/var/zp-sentinel|$DATA_DIR|g" "$CONFIG_FILE" 2>/dev/null || true
        sed -i "s|/opt/var/log|$LOG_DIR|g" "$CONFIG_FILE" 2>/dev/null || true
        sed -i "s|/opt/var/run|$RUN_DIR|g" "$CONFIG_FILE" 2>/dev/null || true
        sed -i "s|/opt/var/cache/zp-sentinel|$CACHE_DIR|g" "$CONFIG_FILE" 2>/dev/null || true
    fi
    info "Config installed at $CONFIG_FILE"
fi

# --- Install Init Script ---
step "Installing service"
if [ "$INIT_SYSTEM" != "none" ]; then
    if [ "$SOURCE" = "local" ] && [ -f "$SCRIPT_DIR/platforms/$PLATFORM/S99zp-sentinel" ]; then
        install_init "$SCRIPT_DIR/platforms/$PLATFORM/S99zp-sentinel"
    else
        install_init ""
    fi
fi

# --- Create Wrapper Script ---
cat > "$WRAPPER" << WRAPPER_EOF
#!/bin/sh
# ZeroPoint Network Sentinel CLI
PYTHON=$PYTHON_CMD
SCRIPT_DIR=$INSTALL_DIR
export PYTHONPATH="\$SCRIPT_DIR"
exec "\$PYTHON" -B -m zp_sentinel.main "\$@"
WRAPPER_EOF
chmod +x "$WRAPPER"
info "CLI wrapper installed at $WRAPPER"

# --- Verify ---
step "Verifying installation"

if "$WRAPPER" -c "$CONFIG_FILE" status >/dev/null 2>&1; then
    info "Sentinel CLI is functional"
else
    warn "CLI returned non-zero (normal on fresh install without dnsmasq)"
fi

# --- Done ---
printf "\n${GREEN}${BOLD}Installation complete!${NC}\n"
printf "${DIM}Platform: $PLATFORM_NAME${NC}\n\n"

printf "${BOLD}Files:${NC}\n"
printf "  Config:   $CONFIG_FILE\n"
printf "  Modules:  $INSTALL_DIR/zp_sentinel/\n"
printf "  Data:     $DATA_DIR/\n"
printf "  Logs:     $LOG_DIR/\n"
printf "  CLI:      $WRAPPER\n"

printf "\n${BOLD}Commands:${NC}\n"
printf "  zp-sentinel status          Show sentinel health\n"
printf "  zp-sentinel monitor         Start monitoring (foreground)\n"
printf "  zp-sentinel alerts          View recent alerts\n"
printf "  zp-sentinel audit           View audit trail\n"
printf "  zp-sentinel verify          Verify audit chain integrity\n"
printf "  zp-sentinel devices         List known devices\n"
printf "  zp-sentinel block <MAC>     Block a MAC address\n"

printf "\n${BOLD}Next steps:${NC}\n"
printf "  1. Edit config:        vi $CONFIG_FILE\n"
printf "  2. Connect to mesh:    [mesh] → core_url (optional)\n"

if [ "$INIT_SYSTEM" = "systemd" ]; then
    printf "  3. Enable service:     systemctl enable --now zp-sentinel\n"
elif [ "$INIT_SYSTEM" = "entware" ]; then
    printf "  3. Start service:      $INIT_SCRIPT start\n"
elif [ "$INIT_SYSTEM" = "procd" ]; then
    printf "  3. Enable service:     /etc/init.d/zp-sentinel enable && /etc/init.d/zp-sentinel start\n"
fi

printf "\n${BOLD}Mesh registration:${NC}\n"
printf "  Set core_url in [mesh] to join the ZeroPoint trust mesh.\n"
printf "  Identity key auto-generated at $DATA_DIR/identity.key\n"

printf "\n${CYAN}Governed by ZeroPoint · https://zeropoint.global/sentinel${NC}\n\n"

exit 0
