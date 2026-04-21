#!/bin/bash
# ZeroPoint Dev
#
#   ./zp-dev.sh            Build (debug) + start server
#   ./zp-dev.sh release    Build (release) + start server
#   ./zp-dev.sh kill       Stop the server
#   ./zp-dev.sh log        Tail server log
#
# Assets are compiled into the binary. There is no asset pipeline.
# Edit files in crates/zp-server/assets/, rebuild, done.
set -e

REPO="$(cd "$(dirname "$0")" && pwd)"
CLI_NAME="zp"
LOCAL_BIN="$HOME/.local/bin/$CLI_NAME"
CARGO_BIN="$HOME/.cargo/bin/$CLI_NAME"
TARGET_DIR=$(sed -n 's/^target-dir *= *"\(.*\)"/\1/p' "$REPO/.cargo/config.toml" 2>/dev/null)
TARGET_DIR="${TARGET_DIR:-$REPO/target}"
DEBUG_BIN="$TARGET_DIR/debug/$CLI_NAME"
PORT=3000
LOG="/tmp/zp-serve.log"

kill_server() {
    # PID on port
    local pids
    pids=$(lsof -ti :$PORT -sTCP:LISTEN 2>/dev/null || true)
    [ -n "$pids" ] && echo "$pids" | xargs kill 2>/dev/null || true
    pkill -f "$CLI_NAME serve" 2>/dev/null || true
    sleep 0.3
}

start_server() {
    kill_server
    echo "→ Starting server..."
    # Serve assets from source tree in dev — includes narration MP3s
    ZP_ASSETS_DIR="$REPO/crates/zp-server/assets" \
    RUST_LOG=info nohup "$LOCAL_BIN" serve > "$LOG" 2>&1 &
    local tries=0
    while [ $tries -lt 15 ]; do
        if lsof -i :$PORT -sTCP:LISTEN > /dev/null 2>&1; then
            echo "✓ localhost:$PORT"
            return 0
        fi
        sleep 0.4
        tries=$((tries + 1))
    done
    echo "✗ Failed to start — check: ./zp-dev.sh log"
    tail -10 "$LOG"
    return 1
}

case "${1:-dev}" in
  dev|d|"")
    cd "$REPO"
    echo "→ cargo build -p zp-server -p zp-cli --features full..."
    cargo build -p zp-server -p zp-cli --features full 2>&1 | tail -5
    mkdir -p "$(dirname "$LOCAL_BIN")"
    cp "$DEBUG_BIN" "$LOCAL_BIN"
    codesign -s - -f "$LOCAL_BIN" 2>/dev/null || true
    echo "✓ $LOCAL_BIN (debug)"
    start_server
    ;;
  release|rel|r)
    cd "$REPO"
    echo "→ cargo install (release)..."
    cargo install --path crates/zp-server 2>&1 | tail -3
    cargo install --path crates/zp-cli 2>&1 | tail -3
    mkdir -p "$(dirname "$LOCAL_BIN")"
    cp "$CARGO_BIN" "$LOCAL_BIN"
    codesign -s - -f "$LOCAL_BIN" 2>/dev/null || true
    echo "✓ $LOCAL_BIN (release)"
    start_server
    ;;
  kill|stop|k)
    kill_server
    echo "✓ Stopped"
    ;;
  log|l)
    [ -f "$LOG" ] && tail -50 -f "$LOG" || echo "No log yet"
    ;;
  *)
    echo "Usage: ./zp-dev.sh [dev|release|kill|log]"
    exit 1
    ;;
esac
