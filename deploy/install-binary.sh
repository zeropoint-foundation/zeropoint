#!/usr/bin/env bash
# ============================================================================
# ZeroPoint — Binary Installer
# ============================================================================
#
# Usage:
#   curl -fsSL https://install.zeropoint.global | sh
#
# Downloads pre-built binaries from GitHub Releases, installs to
# ~/.zeropoint/bin/, and runs genesis. No Rust toolchain needed.
#
# Requirements: curl or wget, tar, uname
# ============================================================================

set -euo pipefail

# ─── Constants ────────────────────────────────────────────────

REPO="zeropoint-foundation/zeropoint"
ZP_HOME="$HOME/.zeropoint"
ZP_BIN="$ZP_HOME/bin"
RELEASE_BASE="https://github.com/$REPO/releases"

# ─── Colors ───────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "  ${CYAN}▸${NC} $1"; }
ok()    { echo -e "  ${GREEN}✓${NC} $1"; }
warn()  { echo -e "  ${YELLOW}⚠${NC} $1"; }
err()   { echo -e "  ${RED}✗${NC} $1"; exit 1; }

# ─── Platform detection ──────────────────────────────────────

detect_platform() {
    local os arch

    os="$(uname -s)"
    arch="$(uname -m)"

    case "$os" in
        Linux)   os="unknown-linux-gnu" ;;
        Darwin)  os="apple-darwin" ;;
        MINGW*|MSYS*|CYGWIN*) err "Windows is not yet supported via this installer. Download from $RELEASE_BASE/latest" ;;
        *)       err "Unsupported OS: $os" ;;
    esac

    case "$arch" in
        x86_64)           arch="x86_64" ;;
        aarch64|arm64)    arch="aarch64" ;;
        *)                err "Unsupported architecture: $arch" ;;
    esac

    echo "${arch}-${os}"
}

# ─── Download helpers ─────────────────────────────────────────

fetch() {
    local url="$1" dest="$2"
    if command -v curl &>/dev/null; then
        curl -fsSL "$url" -o "$dest"
    elif command -v wget &>/dev/null; then
        wget -qO "$dest" "$url"
    else
        err "Neither curl nor wget found. Install one and retry."
    fi
}

get_latest_tag() {
    # Use GitHub API to get the latest release tag
    local tag
    if command -v curl &>/dev/null; then
        tag=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": "\(.*\)".*/\1/')
    elif command -v wget &>/dev/null; then
        tag=$(wget -qO- "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": "\(.*\)".*/\1/')
    fi

    if [ -z "$tag" ]; then
        err "Could not determine latest release. Check your network connection."
    fi
    echo "$tag"
}

# ─── Main ─────────────────────────────────────────────────────

echo ""
echo -e "  ${BOLD}ZeroPoint Binary Installer${NC}"
echo -e "  Trust is infrastructure."
echo ""

# Step 1: Detect platform
TARGET=$(detect_platform)
info "Platform: $TARGET"

# Step 2: Get latest release tag
TAG=$(get_latest_tag)
info "Latest release: $TAG"

# Step 3: Download
ARCHIVE="zeropoint-${TARGET}.tar.gz"
URL="$RELEASE_BASE/download/$TAG/$ARCHIVE"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

info "Downloading $ARCHIVE..."
if ! fetch "$URL" "$TMP_DIR/$ARCHIVE"; then
    err "Download failed. URL: $URL"
fi
ok "Downloaded ($(du -sh "$TMP_DIR/$ARCHIVE" | cut -f1))"

# Step 4: Verify checksum (if available)
CHECKSUM_URL="$RELEASE_BASE/download/$TAG/$ARCHIVE.sha256"
if fetch "$CHECKSUM_URL" "$TMP_DIR/$ARCHIVE.sha256" 2>/dev/null; then
    cd "$TMP_DIR"
    if command -v sha256sum &>/dev/null; then
        if sha256sum -c "$ARCHIVE.sha256" &>/dev/null; then
            ok "Checksum verified (SHA-256)"
        else
            warn "Checksum mismatch — proceeding anyway"
        fi
    elif command -v shasum &>/dev/null; then
        EXPECTED=$(cat "$ARCHIVE.sha256" | awk '{print $1}')
        ACTUAL=$(shasum -a 256 "$ARCHIVE" | awk '{print $1}')
        if [ "$EXPECTED" = "$ACTUAL" ]; then
            ok "Checksum verified (SHA-256)"
        else
            warn "Checksum mismatch — proceeding anyway"
        fi
    fi
    cd - >/dev/null
else
    info "No checksum file available — skipping verification"
fi

# Step 5: Extract and install
info "Installing to $ZP_BIN..."
mkdir -p "$ZP_BIN"
tar xzf "$TMP_DIR/$ARCHIVE" -C "$TMP_DIR"

# Copy binaries (release archives may have them at root or in dist/)
for bin in zp zp-server zp-cli zp-preflight; do
    for candidate in "$TMP_DIR/$bin" "$TMP_DIR/dist/$bin"; do
        if [ -f "$candidate" ]; then
            cp "$candidate" "$ZP_BIN/$bin"
            chmod 755 "$ZP_BIN/$bin"
            break
        fi
    done
done

# zp-cli may be named 'zp' in the archive
if [ ! -f "$ZP_BIN/zp" ] && [ -f "$ZP_BIN/zp-cli" ]; then
    cp "$ZP_BIN/zp-cli" "$ZP_BIN/zp"
fi

# Verify at least zp exists
if [ ! -f "$ZP_BIN/zp" ]; then
    err "Installation failed — zp binary not found in archive"
fi

ok "Binaries installed"

# Step 6: Add to PATH
if ! echo "$PATH" | grep -q "$ZP_BIN"; then
    SHELL_NAME=$(basename "${SHELL:-bash}")
    RC_FILE=""
    case "$SHELL_NAME" in
        zsh)  RC_FILE="$HOME/.zshrc" ;;
        bash) RC_FILE="$HOME/.bashrc"
              [ -f "$HOME/.bash_profile" ] && RC_FILE="$HOME/.bash_profile" ;;
        fish) RC_FILE="$HOME/.config/fish/config.fish" ;;
    esac

    if [ -n "$RC_FILE" ] && ! grep -q ".zeropoint/bin" "$RC_FILE" 2>/dev/null; then
        {
            echo ""
            echo "# ZeroPoint"
            echo 'export PATH="$HOME/.zeropoint/bin:$PATH"'
        } >> "$RC_FILE"
        ok "Added to PATH in $RC_FILE"
    fi
    export PATH="$ZP_BIN:$PATH"
fi

# Step 7: Run quick genesis (Tier A)
echo ""
info "Running genesis (Tier A — Quick Start)..."
"$ZP_BIN/zp" init 2>&1 || true

# Step 8: Verify
echo ""
if "$ZP_BIN/zp" --version &>/dev/null; then
    VER=$("$ZP_BIN/zp" --version 2>&1 | head -1)
    ok "Installed: $VER"
else
    warn "Binary installed but --version check failed"
fi

# ─── Summary ──────────────────────────────────────────────────

echo ""
echo -e "  ${GREEN}══════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}  ZEROPOINT INSTALLED${NC}"
echo -e "  ${GREEN}══════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Binaries: $ZP_BIN/zp"
echo -e "  Config:   $ZP_HOME/config.toml"
echo ""
echo -e "  ${BOLD}Get started:${NC}"
echo ""
echo -e "    ${CYAN}source ~/.zshrc${NC}     (or restart your terminal)"
echo -e "    ${CYAN}zp serve${NC}            Launch the dashboard"
echo -e "    ${CYAN}zp guard \"cmd\"${NC}      Evaluate a command"
echo -e "    ${CYAN}zp doctor${NC}           Run diagnostics"
echo ""
echo -e "  ${BOLD}Your keys. Your chain. Your trust.${NC}"
echo ""
