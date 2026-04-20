#!/usr/bin/env bash
# ============================================================================
# ZeroPoint v2 — Uninstall
# ============================================================================
#
# Reverses everything install.sh and `zp secure` created.
# Safe by design: shows what it will do, asks before acting.
#
# Usage:
#   bash deploy/uninstall.sh           # Interactive (default)
#   bash deploy/uninstall.sh --force   # Skip confirmations
#   bash deploy/uninstall.sh --keep-source  # Remove runtime, keep source code
#
# ============================================================================

set -euo pipefail

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
DIM='\033[2m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "  ${CYAN}▸${NC} $1"; }
ok()    { echo -e "  ${GREEN}✓${NC} $1"; }
warn()  { echo -e "  ${YELLOW}⚠${NC} $1"; }
dim()   { echo -e "  ${DIM}$1${NC}"; }

# --- Config ---
ZP_HOME="$HOME/ZeroPoint"
ZP_BIN="$ZP_HOME/bin"
INSTALL_DIR="${ZP_INSTALL_DIR:-$HOME/zeropoint}"
FORCE=false
KEEP_SOURCE=false

for arg in "$@"; do
    case "$arg" in
        --force) FORCE=true ;;
        --keep-source) KEEP_SOURCE=true ;;
        --help|-h)
            echo "Usage: bash deploy/uninstall.sh [--force] [--keep-source]"
            echo ""
            echo "  --force        Skip all confirmations"
            echo "  --keep-source  Remove runtime files but keep source repository"
            exit 0
            ;;
    esac
done

confirm() {
    if $FORCE; then return 0; fi
    echo ""
    echo -ne "  ${BOLD}$1${NC} [y/N] "
    read -r response
    [[ "$response" =~ ^[Yy] ]]
}

echo ""
echo -e "  ${BOLD}╔═══════════════════════════════════════════════════╗${NC}"
echo -e "  ${BOLD}║      ZEROPOINT UNINSTALL                          ║${NC}"
echo -e "  ${BOLD}╚═══════════════════════════════════════════════════╝${NC}"
echo ""

# ============================================================================
# Phase 1: Inventory — show what exists
# ============================================================================

echo -e "  ${BOLD}Scanning for ZeroPoint artifacts...${NC}"
echo ""

FOUND_ANYTHING=false

# Shell rc modifications
RC_FILES_MODIFIED=()
for rc in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.config/fish/config.fish"; do
    if [ -f "$rc" ] && grep -q "ZeroPoint" "$rc" 2>/dev/null; then
        RC_FILES_MODIFIED+=("$rc")
        FOUND_ANYTHING=true
    fi
done

# Shell hooks (from zp secure)
HOOK_FILES=()
for hook in "$ZP_HOME/hooks/preexec.zsh" "$ZP_HOME/hooks/preexec.bash"; do
    if [ -f "$hook" ]; then
        HOOK_FILES+=("$hook")
        FOUND_ANYTHING=true
    fi
done

# PATH shims (from zp secure)
SHIM_FILES=()
if [ -d "$ZP_BIN" ]; then
    for shim in "$ZP_BIN"/*; do
        [ -f "$shim" ] || continue
        name=$(basename "$shim")
        # Shims are everything except the core binaries
        if [[ "$name" != "zp" && "$name" != "zp-server" ]]; then
            SHIM_FILES+=("$shim")
            FOUND_ANYTHING=true
        fi
    done
fi

# Config files (from zp secure)
CONFIG_FILES=()
for cfg in "$ZP_HOME/config.toml" "$ZP_HOME/watchers.toml"; do
    if [ -f "$cfg" ]; then
        CONFIG_FILES+=("$cfg")
        FOUND_ANYTHING=true
    fi
done

# Core binaries (from install.sh)
BINARIES=()
for bin in "$ZP_BIN/zp" "$ZP_BIN/zp-server"; do
    if [ -f "$bin" ]; then
        BINARIES+=("$bin")
        FOUND_ANYTHING=true
    fi
done

# Data directory (from install.sh Genesis)
HAS_DATA=false
if [ -d "$ZP_HOME/data" ]; then
    HAS_DATA=true
    FOUND_ANYTHING=true
fi

# Guard receipts
HAS_RECEIPTS=false
RECEIPT_COUNT=0
if [ -d "$ZP_HOME/guard-receipts" ]; then
    RECEIPT_COUNT=$(ls -1 "$ZP_HOME/guard-receipts" 2>/dev/null | wc -l | tr -d ' ')
    if [ "$RECEIPT_COUNT" -gt 0 ]; then
        HAS_RECEIPTS=true
        FOUND_ANYTHING=true
    fi
fi

# Source repository
HAS_SOURCE=false
if [ -d "$INSTALL_DIR" ] && [ -f "$INSTALL_DIR/Cargo.toml" ]; then
    HAS_SOURCE=true
    FOUND_ANYTHING=true
fi

# ZP_HOME directory itself
HAS_ZP_HOME=false
if [ -d "$ZP_HOME" ]; then
    HAS_ZP_HOME=true
    FOUND_ANYTHING=true
fi

if ! $FOUND_ANYTHING; then
    echo -e "  ${GREEN}No ZeroPoint artifacts found. Nothing to uninstall.${NC}"
    echo ""
    exit 0
fi

# ============================================================================
# Phase 2: Report — show everything we found
# ============================================================================

echo -e "  ${BOLD}Found:${NC}"
echo ""

if [ ${#RC_FILES_MODIFIED[@]} -gt 0 ]; then
    for rc in "${RC_FILES_MODIFIED[@]}"; do
        info "Shell config modified: $rc"
    done
fi

if [ ${#HOOK_FILES[@]} -gt 0 ]; then
    for hook in "${HOOK_FILES[@]}"; do
        info "Shell hook: $hook"
    done
fi

if [ ${#SHIM_FILES[@]} -gt 0 ]; then
    for shim in "${SHIM_FILES[@]}"; do
        info "PATH shim: $shim"
    done
fi

if [ ${#CONFIG_FILES[@]} -gt 0 ]; then
    for cfg in "${CONFIG_FILES[@]}"; do
        info "Config: $cfg"
    done
fi

if [ ${#BINARIES[@]} -gt 0 ]; then
    for bin in "${BINARIES[@]}"; do
        info "Binary: $bin"
    done
fi

if $HAS_DATA; then
    info "Data directory: $ZP_HOME/data"
fi

if $HAS_RECEIPTS; then
    info "Guard receipts: $RECEIPT_COUNT records in $ZP_HOME/guard-receipts"
fi

if $HAS_SOURCE && ! $KEEP_SOURCE; then
    info "Source repository: $INSTALL_DIR"
fi

if $HAS_ZP_HOME; then
    info "Runtime directory: $ZP_HOME"
fi

# ============================================================================
# Phase 3: Confirm and execute
# ============================================================================

if ! confirm "Remove all ZeroPoint artifacts?"; then
    echo ""
    dim "Uninstall cancelled."
    echo ""
    exit 0
fi

echo ""

# --- Step 1: Clean shell rc files ---
if [ ${#RC_FILES_MODIFIED[@]} -gt 0 ]; then
    echo -e "  ${BOLD}Cleaning shell configurations...${NC}"
    for rc in "${RC_FILES_MODIFIED[@]}"; do
        # Create backup
        cp "$rc" "${rc}.zp-backup"

        # Remove ZeroPoint PATH line
        if [[ "$OSTYPE" == "darwin"* ]]; then
            sed -i '' '/# ZeroPoint/d' "$rc"
            sed -i '' '/ZeroPoint\/bin/d' "$rc"
            sed -i '' '/ZeroPoint Shell Governance/d' "$rc"
            sed -i '' '/ZeroPoint\/hooks\/preexec/d' "$rc"
        else
            sed -i '/# ZeroPoint/d' "$rc"
            sed -i '/ZeroPoint\/bin/d' "$rc"
            sed -i '/ZeroPoint Shell Governance/d' "$rc"
            sed -i '/ZeroPoint\/hooks\/preexec/d' "$rc"
        fi

        # Clean up any trailing blank lines we left behind
        if [[ "$OSTYPE" == "darwin"* ]]; then
            sed -i '' -e :a -e '/^\n*$/{$d;N;ba' -e '}' "$rc" 2>/dev/null || true
        else
            sed -i -e :a -e '/^\n*$/{$d;N;ba' -e '}' "$rc" 2>/dev/null || true
        fi

        ok "Cleaned $rc (backup: ${rc}.zp-backup)"
    done
fi

# --- Step 2: Remove ZP_HOME (hooks, shims, config, binaries, data, receipts) ---
if $HAS_ZP_HOME; then
    echo -e "  ${BOLD}Removing runtime directory...${NC}"
    rm -rf "$ZP_HOME"
    ok "Removed $ZP_HOME"
fi

# --- Step 3: Remove source repository ---
if $HAS_SOURCE && ! $KEEP_SOURCE; then
    echo -e "  ${BOLD}Removing source repository...${NC}"
    rm -rf "$INSTALL_DIR"
    ok "Removed $INSTALL_DIR"
elif $HAS_SOURCE && $KEEP_SOURCE; then
    dim "Keeping source repository at $INSTALL_DIR"
fi

# ============================================================================
# Summary
# ============================================================================

echo ""
echo -e "  ${GREEN}══════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}  UNINSTALL COMPLETE${NC}"
echo -e "  ${GREEN}══════════════════════════════════════════════════${NC}"
echo ""

if [ ${#RC_FILES_MODIFIED[@]} -gt 0 ]; then
    ok "Shell configs cleaned (backups saved as .zp-backup)"
fi
ok "Runtime directory removed ($ZP_HOME)"
if $HAS_SOURCE && ! $KEEP_SOURCE; then
    ok "Source repository removed ($INSTALL_DIR)"
fi

echo ""
dim "Open a new terminal to clear any cached PATH entries."
if [ ${#RC_FILES_MODIFIED[@]} -gt 0 ]; then
    dim "To remove backups: rm ${RC_FILES_MODIFIED[0]}.zp-backup"
fi
echo ""
