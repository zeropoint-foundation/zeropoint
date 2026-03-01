#!/usr/bin/env bash
#
# HDLC Wire-Format Interop Test Runner
# ======================================
#
# Proves that ZeroPoint's Rust HDLC codec is byte-for-byte compatible
# with Reticulum's Python HDLC codec by exchanging framed test vectors
# over raw TCP.
#
# Usage:
#   cd v2
#   bash tests/reticulum/run_hdlc_interop.sh
#
# Requirements:
#   - Python 3.x (no pip packages needed — uses only stdlib)
#   - Rust toolchain (cargo)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
PORT=7331
PYTHON_PID=""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

cleanup() {
    if [ -n "$PYTHON_PID" ] && kill -0 "$PYTHON_PID" 2>/dev/null; then
        kill "$PYTHON_PID" 2>/dev/null || true
        wait "$PYTHON_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo ""
echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║       HDLC Wire-Format Cross-Stack Interop Test            ║${NC}"
echo -e "${YELLOW}║                                                            ║${NC}"
echo -e "${YELLOW}║  Python (Reticulum HDLC)  ←──TCP──→  Rust (ZeroPoint HDLC)║${NC}"
echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Step 1: Start Python HDLC server ────────────────────────────────
echo -e "${YELLOW}[1/3]${NC} Starting Python HDLC interop server on port ${PORT}..."
python3 "$SCRIPT_DIR/hdlc_interop_server.py" --port "$PORT" &
PYTHON_PID=$!

# Wait for the server to be ready
sleep 1
if ! kill -0 "$PYTHON_PID" 2>/dev/null; then
    echo -e "${RED}✗ Python server failed to start${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Python server running (PID: $PYTHON_PID)${NC}"
echo ""

# ── Step 2: Run Rust interop test ───────────────────────────────────
echo -e "${YELLOW}[2/3]${NC} Running Rust HDLC interop test..."
echo ""

cd "$PROJECT_DIR"
HDLC_INTEROP_PORT=$PORT cargo test \
    --package zp-mesh \
    --test hdlc_interop \
    -- --ignored --nocapture \
    2>&1
RUST_EXIT=$?

# ── Step 3: Collect results ─────────────────────────────────────────
echo ""
wait "$PYTHON_PID" 2>/dev/null
PYTHON_EXIT=$?
PYTHON_PID=""

echo -e "${YELLOW}[3/3]${NC} Results:"
echo ""

if [ $RUST_EXIT -eq 0 ] && [ $PYTHON_EXIT -eq 0 ]; then
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  ✓ HDLC INTEROP TEST: PASSED                               ║${NC}"
    echo -e "${GREEN}║                                                            ║${NC}"
    echo -e "${GREEN}║  Reticulum Python HDLC  ←→  ZeroPoint Rust HDLC           ║${NC}"
    echo -e "${GREEN}║  Wire format: BYTE-FOR-BYTE COMPATIBLE                     ║${NC}"
    echo -e "${GREEN}║                                                            ║${NC}"
    echo -e "${GREEN}║  ZeroPoint is a citizen of the Reticulum.                  ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    exit 0
else
    echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  ✗ HDLC INTEROP TEST: FAILED                               ║${NC}"
    echo -e "${RED}║                                                            ║${NC}"
    echo -e "${RED}║  Rust exit:   ${RUST_EXIT}                                          ║${NC}"
    echo -e "${RED}║  Python exit: ${PYTHON_EXIT}                                          ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
    exit 1
fi
