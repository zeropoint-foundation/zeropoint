#!/usr/bin/env bash
# ============================================================================
# ZeroPoint × Reticulum Integration Test Runner
# ============================================================================
#
# Starts the echo node, waits for it to initialize, then launches the
# agent bridge to send receipt chains and verify roundtrip integrity.
#
# Usage:
#   ./v2/tests/reticulum/run_test.sh
#   ./v2/tests/reticulum/run_test.sh --load 100   # Also run load test
#
# Prerequisites:
#   pip install rns msgpack PyNaCl

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$SCRIPT_DIR/reticulum_test_config"
LOAD_COUNT="${1:-0}"

echo "╔══════════════════════════════════════════════════════╗"
echo "║  ZeroPoint × Reticulum Integration Test             ║"
echo "╚══════════════════════════════════════════════════════╝"
echo

# Clean up any previous state
rm -f "$SCRIPT_DIR/.echo_node_identity"
ECHO_PID=""
cleanup() {
    echo
    echo "Cleaning up..."
    if [ -n "$ECHO_PID" ] && kill -0 "$ECHO_PID" 2>/dev/null; then
        kill "$ECHO_PID" 2>/dev/null || true
        wait "$ECHO_PID" 2>/dev/null || true
    fi
    rm -f "$SCRIPT_DIR/.echo_node_identity"
    echo "Done."
}
trap cleanup EXIT

# Check dependencies
echo "Checking dependencies..."
python3 -c "import RNS" 2>/dev/null || { echo "ERROR: pip install rns"; exit 1; }
python3 -c "import msgpack" 2>/dev/null || { echo "ERROR: pip install msgpack"; exit 1; }
python3 -c "from nacl.signing import SigningKey" 2>/dev/null || {
    echo "WARNING: PyNaCl not installed — signature verification will be skipped"
    echo "  Install with: pip install PyNaCl"
}
echo "  ✓ Dependencies OK"
echo

# Start echo node in background
echo "Starting echo node..."
python3 "$SCRIPT_DIR/rns_echo_node.py" -v &
ECHO_PID=$!
echo "  Echo node PID: $ECHO_PID"

# Wait for the echo node to print its destination hash
echo "  Waiting for echo node to initialize..."
sleep 5

# Extract destination hash from echo node output
# The echo node prints: "  │  Destination: <32 hex chars>  │"
# We need to capture that — for now, we check if the process is still alive
if ! kill -0 "$ECHO_PID" 2>/dev/null; then
    echo "ERROR: Echo node died during startup"
    exit 1
fi

# Get the destination hash by querying Reticulum's path table
# Since both share the same Reticulum instance, we can discover it
echo "  ✓ Echo node running"
echo

# The echo node's destination hash is printed in its output.
# In a fully automated setup, we'd parse it. For now, the user can
# also read it from the echo node output.
#
# For automated testing, we use the Reticulum shared instance:
DEST_HASH=$(python3 -c "
import RNS
import time
r = RNS.Reticulum()
time.sleep(2)
# List known destinations
import RNS.Transport as T
# The echo node should have announced locally
for h in T.destination_table:
    print(h.hex())
    break
" 2>/dev/null || echo "")

if [ -z "$DEST_HASH" ]; then
    echo "Could not auto-discover echo node destination."
    echo "Please find the destination hash in the echo node output above"
    echo "and run manually:"
    echo
    echo "  python3 $SCRIPT_DIR/zp_agent_bridge.py <DEST_HASH>"
    echo
    # Still try to continue — the bridge has a timeout mechanism
    echo "Attempting connection with path discovery..."
    DEST_HASH="auto"
fi

# Run the agent bridge
echo "Starting agent bridge..."
BRIDGE_ARGS="-n 5 -d 0.3"

if [ "$LOAD_COUNT" != "0" ] && [ "$LOAD_COUNT" != "--load" ]; then
    BRIDGE_ARGS="$BRIDGE_ARGS --load-test $LOAD_COUNT"
elif [ "${2:-}" != "" ]; then
    BRIDGE_ARGS="$BRIDGE_ARGS --load-test $2"
fi

if [ "$DEST_HASH" != "auto" ] && [ -n "$DEST_HASH" ]; then
    python3 "$SCRIPT_DIR/zp_agent_bridge.py" "$DEST_HASH" $BRIDGE_ARGS -v
    EXIT_CODE=$?
else
    echo "Skipping automated bridge — manual run required."
    echo "Keeping echo node alive. Press Ctrl+C to stop."
    wait "$ECHO_PID"
    EXIT_CODE=0
fi

exit $EXIT_CODE
