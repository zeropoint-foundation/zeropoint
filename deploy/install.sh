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

if [ -d "$INSTALL_DIR/v2/Cargo.toml" ] || [ -f "$INSTALL_DIR/v2/Cargo.toml" ]; then
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

cd "$INSTALL_DIR/v2"
info "Building all crates (release mode)... this may take a few minutes on first run."
cargo build --workspace --release 2>&1 | tail -5
ok "Build complete"

# Verify binaries
[ -f target/release/zp-server ] || fail "zp-server binary not found"
[ -f target/release/zp-cli ]    || fail "zp-cli binary not found"
ok "Binaries: zp-server, zp-cli"

# ============================================================================
# Step 4: Run Tests
# ============================================================================
header "Step 4: Test Suite"

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
# Step 5: Lint Check
# ============================================================================
header "Step 5: Lint & Format"

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
# Step 6: Quick Smoke Test
# ============================================================================
header "Step 6: Smoke Test"

info "Starting zp-server on port $ZP_PORT..."
ZP_DATA_DIR="$INSTALL_DIR/data" RUST_LOG=error \
    target/release/zp-server &
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
    ENTRY_COUNT=$(echo "$AUDIT" | grep -o '"entry_count":[0-9]*' | grep -o '[0-9]*' || echo "0")
    ok "Audit trail: $ENTRY_COUNT entries recorded"
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
# Step 7: CLI Check
# ============================================================================
header "Step 7: CLI"

CLI_VERSION=$(target/release/zp-cli --help 2>&1 | head -1 || echo "unknown")
ok "CLI available: $CLI_VERSION"

# Guard a command via CLI
CLI_GUARD=$(target/release/zp-cli guard "rm -rf /" 2>&1 || true)
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
echo ""
echo "  Quick start:"
echo ""
echo -e "    ${CYAN}# Start the server${NC}"
echo "    cd $INSTALL_DIR/v2"
echo "    cargo run --release --bin zp-server"
echo ""
echo -e "    ${CYAN}# Or run the binary directly${NC}"
echo "    $INSTALL_DIR/v2/target/release/zp-server"
echo ""
echo -e "    ${CYAN}# Guard a command via CLI${NC}"
echo "    $INSTALL_DIR/v2/target/release/zp-cli guard \"rm -rf /\""
echo ""
echo -e "    ${CYAN}# Interactive chat (requires LLM config)${NC}"
echo "    ZP_LLM_ENABLED=true cargo run --release --bin zp-cli -- chat"
echo ""
echo -e "    ${CYAN}# Open the playground${NC}"
echo "    open http://localhost:$ZP_PORT"
echo "    # Or visit https://zeropoint.global/playground"
echo ""
echo "  Environment variables:"
echo "    ZP_PORT=3000          Server port"
echo "    ZP_DATA_DIR=./data    Persistent data directory"
echo "    RUST_LOG=info         Log level"
echo ""
echo -e "  ${BOLD}Your keys. Your chain. Your trust.${NC}"
echo ""
