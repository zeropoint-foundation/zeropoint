#!/bin/bash
# ZeroPoint Dev
#
#   ./zp-dev.sh            Build (debug) + start server
#   ./zp-dev.sh release    Build (release) + start server
#   ./zp-dev.sh kill       Stop the server
#   ./zp-dev.sh log        Tail server log
#
# The server runs DIRECTLY from target/. No copy. No ~/.local/bin.
# `cargo build` is all you need.
set -e

REPO="$(cd "$(dirname "$0")" && pwd)"
CLI_NAME="zp"
TARGET_DIR=$(sed -n 's/^target-dir *= *"\(.*\)"/\1/p' "$REPO/.cargo/config.toml" 2>/dev/null)
TARGET_DIR="${TARGET_DIR:-$REPO/target}"
PORT=3000
LOG="/tmp/zp-serve.log"

# ── STALE BINARY GUARD ──────────────────────────────────────────────
# If a copy exists outside target/, it WILL cause confusion. Kill it.
STALE_LOCATIONS=(
    "$HOME/.local/bin/$CLI_NAME"
    "$HOME/.cargo/bin/$CLI_NAME"
)
for stale in "${STALE_LOCATIONS[@]}"; do
    if [ -f "$stale" ] && [ ! -L "$stale" ]; then
        echo "⚠ Removing stale binary: $stale"
        echo "  (dev mode runs from target/ — copies cause silent version skew)"
        rm -f "$stale"
    fi
done

kill_server() {
    local pids
    pids=$(lsof -ti :$PORT -sTCP:LISTEN 2>/dev/null || true)
    [ -n "$pids" ] && echo "$pids" | xargs kill 2>/dev/null || true
    pkill -f "$CLI_NAME serve" 2>/dev/null || true
    sleep 0.3
}

start_server() {
    local bin="$1"
    kill_server

    # Verify no stale process survived
    local lingering
    lingering=$(lsof -ti :$PORT -sTCP:LISTEN 2>/dev/null || true)
    if [ -n "$lingering" ]; then
        echo "⚠ Port $PORT still occupied (PID $lingering) — force killing"
        echo "$lingering" | xargs kill -9 2>/dev/null || true
        sleep 0.5
    fi

    local commit
    commit=$(cd "$REPO" && git rev-parse --short HEAD 2>/dev/null || echo 'unknown')
    echo "→ Starting server from $bin"
    echo "  commit: $commit"

    ZP_ASSETS_DIR="$REPO/crates/zp-server/assets" \
    RUST_LOG=info nohup "$bin" serve > "$LOG" 2>&1 &
    local server_pid=$!

    local tries=0
    while [ $tries -lt 15 ]; do
        if lsof -i :$PORT -sTCP:LISTEN > /dev/null 2>&1; then
            echo "✓ localhost:$PORT (PID $server_pid, build $commit)"
            return 0
        fi
        sleep 0.4
        tries=$((tries + 1))
    done
    echo "✗ Failed to start — check: ./zp-dev.sh log"
    tail -10 "$LOG"
    return 1
}

# ── Verify the running server matches source ────────────────────────
verify_running() {
    local running_build
    running_build=$(curl -s http://localhost:$PORT/api/v1/version 2>/dev/null | grep -o '"commit":"[^"]*"' | cut -d'"' -f4)
    local source_commit
    source_commit=$(cd "$REPO" && git rev-parse --short HEAD 2>/dev/null)

    if [ -z "$running_build" ]; then
        echo "⚠ Cannot reach running server (is it up?)"
        return 1
    fi

    if [ "$running_build" = "$source_commit" ]; then
        echo "✓ Running server matches source ($running_build)"
        return 0
    else
        echo "✗ VERSION SKEW: running=$running_build, source=$source_commit"
        echo "  Run: ./zp-dev.sh    to rebuild and restart"
        return 1
    fi
}

case "${1:-dev}" in
  dev|d|"")
    cd "$REPO"
    echo "→ cargo build -p zp-server -p zp-cli --features full..."
    cargo build -p zp-server -p zp-cli --features full 2>&1 | tail -5
    BIN="$TARGET_DIR/debug/$CLI_NAME"
    [ -f "$BIN" ] || { echo "✗ Binary not found: $BIN"; exit 1; }
    echo "✓ Built: $BIN (debug)"
    start_server "$BIN"
    ;;
  release|rel|r)
    cd "$REPO"
    echo "→ cargo build --release -p zp-server -p zp-cli --features full..."
    cargo build --release -p zp-server -p zp-cli --features full 2>&1 | tail -5
    BIN="$TARGET_DIR/release/$CLI_NAME"
    [ -f "$BIN" ] || { echo "✗ Binary not found: $BIN"; exit 1; }
    echo "✓ Built: $BIN (release)"
    start_server "$BIN"
    ;;
  kill|stop|k)
    kill_server
    echo "✓ Stopped"
    ;;
  log|l)
    [ -f "$LOG" ] && tail -50 -f "$LOG" || echo "No log yet"
    ;;
  verify|v|check)
    verify_running
    ;;
  *)
    echo "Usage: ./zp-dev.sh [dev|release|kill|log|verify]"
    exit 1
    ;;
esac
