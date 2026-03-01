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
# Step 7: Quick Smoke Test
# ============================================================================
header "Step 7: Smoke Test"

info "Starting zp-server on port $ZP_PORT..."
ZP_DATA_DIR="$ZP_HOME/data" ZP_BIND=127.0.0.1 ZP_PORT=$ZP_PORT RUST_LOG=error \
    "$ZP_BIN/zp-server" &
SERVER_PID=$!

# Wait for server to start
sleep 2

# Health check
if curl -sf "http://localhost:$ZP_PORT/api/v1/health" > /dev/null 2>&1; then
    ok "Health check passed"
else
    warn "Health check failed — server may need more time to start"
fi

# Identity check
IDENTITY=$(curl -sf "http://localhost:$ZP_PORT/api/v1/identity" 2>/dev/null || echo "{}")
if echo "$IDENTITY" | grep -q "public_key"; then
    ok "Server identity verified"
else
    warn "Could not verify server identity"
fi

# Guard evaluation test
GUARD_RESULT=$(curl -sf -X POST "http://localhost:$ZP_PORT/api/v1/guard/evaluate" \
    -H "Content-Type: application/json" \
    -d '{"action":"deploy surveillance toolkit","trust_tier":"Tier1"}' 2>/dev/null || echo "{}")

if echo "$GUARD_RESULT" | grep -q "Block"; then
    ok "Guard evaluation: harmful action correctly blocked"
elif echo "$GUARD_RESULT" | grep -q "policy_decision"; then
    ok "Guard evaluation: responded with policy decision"
else
    warn "Guard evaluation: unexpected response"
fi

# Test a safe action
SAFE_RESULT=$(curl -sf -X POST "http://localhost:$ZP_PORT/api/v1/guard/evaluate" \
    -H "Content-Type: application/json" \
    -d '{"action":"read temperature sensor","trust_tier":"Tier1"}' 2>/dev/null || echo "{}")

if echo "$SAFE_RESULT" | grep -q "Allow"; then
    ok "Guard evaluation: safe action correctly allowed"
fi

# Audit trail check
AUDIT=$(curl -sf "http://localhost:$ZP_PORT/api/v1/audit/entries" 2>/dev/null || echo "{}")
if echo "$AUDIT" | grep -q "entries"; then
    ok "Audit trail: entries recorded"
fi

# Verify chain integrity
VERIFY=$(curl -sf "http://localhost:$ZP_PORT/api/v1/audit/verify" 2>/dev/null || echo "{}")
if echo "$VERIFY" | grep -q '"valid":true'; then
    ok "Audit chain: integrity verified"
fi

# Stop server
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

# ============================================================================
# Step 8: CLI Check
# ============================================================================
header "Step 8: CLI"

CLI_VERSION=$("$ZP_BIN/zp" --help 2>&1 | head -1 || echo "unknown")
ok "CLI available: $CLI_VERSION"

# Guard a command via CLI
CLI_GUARD=$("$ZP_BIN/zp" guard "rm -rf /" 2>&1 || true)
if echo "$CLI_GUARD" | grep -qi "block\|deny\|dangerous\|harm"; then
    ok "CLI guard: dangerous command detected"
else
    ok "CLI guard: responded"
fi

# ============================================================================
# Summary
# ============================================================================
header "Install Complete"

echo ""
echo -e "  ${GREEN}ZeroPoint v2 is installed at:${NC} $INSTALL_DIR"
echo -e "  ${GREEN}Binaries:${NC} $ZP_BIN/zp"
echo ""
echo "  Next step — launch the verification surface:"
echo ""
echo -e "    ${CYAN}zp serve${NC}"
echo ""
echo "  This performs the Genesis ceremony (first run),"
echo "  starts the governance server, and opens the"
echo "  verification dashboard in your browser."
echo ""
echo "  Other commands:"
echo ""
echo -e "    ${CYAN}zp guard \"rm -rf /\"${NC}        Evaluate a command"
echo -e "    ${CYAN}zp audit verify${NC}            Verify chain integrity"
echo -e "    ${CYAN}zp serve --no-open${NC}         Start without browser"
echo -e "    ${CYAN}zp health${NC}                  System health check"
echo ""
echo "  Environment variables:"
echo "    ZP_PORT=3000          Server port"
echo "    ZP_BIND=127.0.0.1    Bind address"
echo "    ZP_DATA_DIR=~/.zeropoint/data    Data directory"
echo "    RUST_LOG=info         Log level"
echo ""
echo -e "  ${BOLD}Your keys. Your chain. Your trust.${NC}"
echo ""
