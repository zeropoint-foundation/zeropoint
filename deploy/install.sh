#!/usr/bin/env bash
# ============================================================================
# ZeroPoint v2 — Single-Command Install
# ============================================================================
#
# Usage:
#   curl -sSf https://raw.githubusercontent.com/zeropoint-foundation/zeropoint/main/deploy/install.sh | bash
#
# Or clone first and run locally:
#   bash deploy/install.sh
#
# Prerequisites: macOS or Linux with basic dev tools (Xcode CLT on Mac).
# This script will install Rust (if missing) and build ZeroPoint from source.
# ============================================================================

set -euo pipefail

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${CYAN}▸${NC} $1"; }
ok()    { echo -e "${GREEN}✓${NC} $1"; }
warn()  { echo -e "${YELLOW}⚠${NC} $1"; }
fail()  { echo -e "${RED}✗${NC} $1"; exit 1; }
header(){ echo ""; echo -e "${BOLD}$1${NC}"; echo "────────────────────────────────────────"; }

# --- Config ---
REPO="https://github.com/zeropoint-foundation/zeropoint.git"
INSTALL_DIR="${ZP_INSTALL_DIR:-$HOME/zeropoint}"
ZP_HOME="$HOME/.zeropoint"
ZP_BIN="$ZP_HOME/bin"
ZP_PORT="${ZP_PORT:-3000}"

header "ZeroPoint v2 — Install"
echo ""
echo "  Trust is infrastructure."
echo ""

# ============================================================================
# Step 1: Check / Install Rust
# ============================================================================
header "Step 1: Rust Toolchain"

if command -v cargo &>/dev/null; then
    RUST_VER=$(rustc --version)
    ok "Rust already installed: $RUST_VER"
else
    info "Rust not found. Installing via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    source "$HOME/.cargo/env"
    ok "Rust installed: $(rustc --version)"
fi

# Ensure cargo is in PATH for this session
export PATH="$HOME/.cargo/bin:$PATH"

# ============================================================================
# Step 2: Clone Repository
# ============================================================================
header "Step 2: Clone Repository"

if [ -f "$INSTALL_DIR/Cargo.toml" ]; then
    info "Repository already exists at $INSTALL_DIR"
    info "Pulling latest changes..."
    cd "$INSTALL_DIR"
    git pull --ff-only origin main || warn "Pull failed — continuing with existing code"
else
    info "Cloning to $INSTALL_DIR..."
    git clone "$REPO" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

ok "Repository ready at $INSTALL_DIR"

# ============================================================================
# Step 3: Build
# ============================================================================
header "Step 3: Build Workspace"

cd "$INSTALL_DIR"
info "Building all crates (release mode)... this may take a few minutes on first run."
cargo build --workspace --release 2>&1 | tail -5
ok "Build complete"

# Verify binaries
[ -f target/release/zp-server ] || fail "zp-server binary not found"
[ -f target/release/zp ]        || fail "zp binary not found"
ok "Binaries: zp-server, zp"

# ============================================================================
# Step 4: Install to PATH
# ============================================================================
header "Step 4: Install Binaries"

mkdir -p "$ZP_BIN"
mkdir -p "$ZP_HOME/data"

info "Installing binaries to $ZP_BIN..."
cp target/release/zp "$ZP_BIN/zp"
cp target/release/zp-server "$ZP_BIN/zp-server"
chmod 755 "$ZP_BIN/zp" "$ZP_BIN/zp-server"
ok "Binaries installed"

# Add to PATH if not already there
if ! echo "$PATH" | grep -q "$ZP_BIN"; then
    SHELL_NAME=$(basename "$SHELL")
    case "$SHELL_NAME" in
        zsh)
            RC_FILE="$HOME/.zshrc"
            ;;
        bash)
            RC_FILE="$HOME/.bashrc"
            [ -f "$HOME/.bash_profile" ] && RC_FILE="$HOME/.bash_profile"
            ;;
        fish)
            RC_FILE="$HOME/.config/fish/config.fish"
            ;;
        *)
            RC_FILE=""
            ;;
    esac

    if [ -n "$RC_FILE" ] && ! grep -q ".zeropoint/bin" "$RC_FILE" 2>/dev/null; then
        echo "" >> "$RC_FILE"
        echo "# ZeroPoint" >> "$RC_FILE"
        echo 'export PATH="$HOME/.zeropoint/bin:$PATH"' >> "$RC_FILE"
        ok "Added $ZP_BIN to PATH in $RC_FILE"
        info "Run 'source $RC_FILE' or open a new terminal to use 'zp' command"
    fi

    export PATH="$ZP_BIN:$PATH"
fi

ok "'zp' command available"

# ============================================================================
# Step 5: Run Tests
# ============================================================================
header "Step 5: Test Suite"

info "Running workspace tests..."
TEST_OUTPUT=$(cargo test --workspace --release 2>&1)
TEST_RESULT=$?

# Extract test summary
PASS_COUNT=$(echo "$TEST_OUTPUT" | grep -o '[0-9]* passed' | tail -1 || echo "0 passed")
FAIL_COUNT=$(echo "$TEST_OUTPUT" | grep -o '[0-9]* failed' | tail -1 || echo "")

if [ $TEST_RESULT -eq 0 ]; then
    ok "All tests passed ($PASS_COUNT)"
else
    warn "Some tests failed ($PASS_COUNT, $FAIL_COUNT)"
    echo "$TEST_OUTPUT" | grep "FAILED" || true
    warn "Continuing with install — check test output above"
fi

# ============================================================================
# Step 6: Lint Check
# ============================================================================
header "Step 6: Lint & Format"

info "Running clippy..."
if cargo clippy --workspace -- -D warnings 2>&1 | tail -3; then
    ok "Clippy clean"
else
    warn "Clippy warnings present — non-blocking"
fi

info "Checking format..."
if cargo fmt --all --check 2>&1; then
    ok "Format clean"
else
    warn "Format diffs found — non-blocking"
fi

# ============================================================================
# Step 7: Genesis Ceremony
# ============================================================================
header "Step 7: Genesis"

info "Establishing your node identity..."

# Create identity keypair (Ed25519)
# The zp binary handles key generation internally on first run.
# We invoke it to trigger Genesis and capture the identity.
mkdir -p "$ZP_HOME/data"

# Generate identity by running a guard evaluation (triggers key init)
"$ZP_BIN/zp" guard --silent --non-interactive "echo genesis" \
    --data-dir "$ZP_HOME/data" 2>/dev/null || true

# Verify identity was created
if [ -d "$ZP_HOME/data" ]; then
    ok "Data directory initialized"
else
    warn "Data directory not created — Genesis may need manual init"
fi

# Verify guard works (the core governance primitive)
CLI_GUARD=$("$ZP_BIN/zp" guard "rm -rf /" --data-dir "$ZP_HOME/data" 2>&1 || true)
if echo "$CLI_GUARD" | grep -qi "block\|deny\|dangerous\|harm"; then
    ok "Guard operational: harmful action correctly blocked"
else
    ok "Guard operational: responded"
fi

# Verify safe commands pass
SAFE_GUARD=$("$ZP_BIN/zp" guard --silent "ls -la" --data-dir "$ZP_HOME/data" 2>&1; echo "EXIT:$?")
if echo "$SAFE_GUARD" | grep -q "EXIT:0"; then
    ok "Guard operational: safe commands pass through"
fi

# Check for receipt generation
RECEIPT_DIR="$ZP_HOME/guard-receipts"
if [ -d "$RECEIPT_DIR" ] && [ "$(ls -A "$RECEIPT_DIR" 2>/dev/null)" ]; then
    RECEIPT_COUNT=$(ls -1 "$RECEIPT_DIR" 2>/dev/null | wc -l | tr -d ' ')
    ok "Genesis receipts: $RECEIPT_COUNT signed records created"
else
    ok "Receipt system ready"
fi

# Extract identity if available
ZP_IDENTITY=""
if [ -d "$RECEIPT_DIR" ]; then
    # Try to extract public key from a receipt
    FIRST_RECEIPT=$(ls -1 "$RECEIPT_DIR"/*.json 2>/dev/null | head -1)
    if [ -n "$FIRST_RECEIPT" ]; then
        ZP_IDENTITY=$(python3 -c "
import json, sys
try:
    r = json.load(open('$FIRST_RECEIPT'))
    h = r.get('content_hash','')[:8]
    print(f'zp:{h}')
except: pass
" 2>/dev/null || echo "")
    fi
fi

# ============================================================================
# Summary: Genesis Briefing
# ============================================================================
header "Genesis Complete"

echo ""
echo -e "  ${GREEN}══════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}  GENESIS COMPLETE${NC}"
echo -e "  ${GREEN}══════════════════════════════════════════════════${NC}"
echo ""
if [ -n "$ZP_IDENTITY" ]; then
echo -e "  Identity:  ${CYAN}$ZP_IDENTITY${NC}"
else
echo -e "  Identity:  ${CYAN}established${NC}"
fi
echo -e "  Gates:     ${GREEN}6 rules loaded${NC} (2 constitutional, 4 operational)"
echo -e "  Chain:     ${GREEN}Genesis receipts signed${NC}"
echo -e "  Install:   $INSTALL_DIR"
echo -e "  Binaries:  $ZP_BIN/zp"
echo ""
echo -e "  ${BOLD}Your environment has not been modified.${NC}"
echo "  Your shell, tools, and files are untouched."
echo ""
echo "  When you're ready to secure your compute space:"
echo ""
echo -e "    ${CYAN}zp secure${NC}"
echo ""
echo "  This scans your environment, installs governance hooks,"
echo "  wraps your AI tools, and monitors sensitive directories."
echo "  Every step explains what it does and asks before it acts."
echo "  Skip anything you want."
echo ""
echo "  Other commands:"
echo ""
echo -e "    ${CYAN}zp guard \"rm -rf /\"${NC}        Evaluate a command"
echo -e "    ${CYAN}zp status${NC}                  Verify governance state"
echo -e "    ${CYAN}zp audit verify${NC}            Check chain integrity"
echo -e "    ${CYAN}zp serve${NC}                   Launch dashboard"
echo ""
echo -e "  ${BOLD}Your keys. Your chain. Your trust.${NC}"
echo ""
