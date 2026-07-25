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
PORT=17010
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

# ── SYSTEM SYMLINK ───────────────────────────────────────────────────
# /usr/local/bin/zp must be a SYMLINK into target/, not a copy.
# Copies trigger Gatekeeper (zsh: killed). Symlinks inherit the
# original binary's trust — Gatekeeper sees target/debug/zp, not /usr/local/bin/zp.
SYSTEM_BIN="/usr/local/bin/$CLI_NAME"

install_symlink() {
    local target="$1"
    # Already correct symlink — nothing to do.
    if [ -L "$SYSTEM_BIN" ] && [ "$(readlink "$SYSTEM_BIN")" = "$target" ]; then
        return 0
    fi
    # Remove whatever is there (stale copy or wrong symlink).
    if [ -e "$SYSTEM_BIN" ] || [ -L "$SYSTEM_BIN" ]; then
        rm -f "$SYSTEM_BIN" 2>/dev/null || sudo rm -f "$SYSTEM_BIN" 2>/dev/null || true
    fi
    if ln -sf "$target" "$SYSTEM_BIN" 2>/dev/null || sudo ln -sf "$target" "$SYSTEM_BIN" 2>/dev/null; then
        echo "✓ Symlinked: $SYSTEM_BIN → $target"
    else
        echo "⚠ Could not symlink $SYSTEM_BIN — run: sudo ln -sf $target $SYSTEM_BIN"
    fi
}

kill_server() {
    # Graceful shutdown: SIGTERM first, then poll for up to
    # $GRACE_SECS for the server to actually flush chain state, close
    # SQLite WAL, emit final officer/regent shutdown receipts, and
    # release the listening port. Only escalate to SIGKILL if the
    # grace window expires. Per BUILD-PROCESS-DESIGN-2026-07.md
    # "graceful shutdown" phase.
    local GRACE_SECS=8
    local pids
    pids=$(lsof -ti :$PORT -sTCP:LISTEN 2>/dev/null || true)
    if [ -z "$pids" ]; then
        pkill -TERM -f "$CLI_NAME serve" 2>/dev/null || true
        return
    fi

    echo "$pids" | xargs kill -TERM 2>/dev/null || true
    pkill -TERM -f "$CLI_NAME serve" 2>/dev/null || true

    # Poll every 0.25s waiting for the port to be released. Exit
    # early the moment lsof shows nothing listening — no need to
    # burn the full grace window when shutdown is fast.
    local waited=0
    while [ "$waited" -lt "$((GRACE_SECS * 4))" ]; do
        sleep 0.25
        local still
        still=$(lsof -ti :$PORT -sTCP:LISTEN 2>/dev/null || true)
        [ -z "$still" ] && return
        waited=$((waited + 1))
    done

    echo "⚠ SIGTERM did not release port $PORT within ${GRACE_SECS}s — escalating to SIGKILL"
    lsof -ti :$PORT -sTCP:LISTEN 2>/dev/null | xargs kill -9 2>/dev/null || true
    pkill -KILL -f "$CLI_NAME serve" 2>/dev/null || true
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
    RUST_LOG=info nohup "$bin" serve --foreground --port "$PORT" > "$LOG" 2>&1 &
    local server_pid=$!

    # Boot latency baselines:
    #   - OS Keychain Genesis:  ~9s (vault key resolution + startup)
    #   - Hardware Genesis (Trezor/YubiKey/Ledger/OnlyKey): operator confirmation
    #     latency is unbounded — physical touch on device, typically 10–120s.
    # Poll window sized for hardware-Genesis case; override via ZP_BOOT_WAIT_SECS.
    local wait_secs="${ZP_BOOT_WAIT_SECS:-180}"
    local max_tries=$((wait_secs * 2))
    local tries=0
    while [ $tries -lt $max_tries ]; do
        if lsof -i :$PORT -sTCP:LISTEN > /dev/null 2>&1; then
            echo "✓ localhost:$PORT (PID $server_pid, build $commit)"
            return 0
        fi
        sleep 0.5
        tries=$((tries + 1))
    done
    echo "✗ Failed to start after ${wait_secs}s — check: ./zp-dev.sh log"
    echo "  (override wait with ZP_BOOT_WAIT_SECS=<seconds>)"
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
    if ! cargo build -p zp-server -p zp-cli --features full; then
        echo "✗ BUILD FAILED — not starting server with stale binary"
        exit 1
    fi
    BIN="$TARGET_DIR/debug/$CLI_NAME"
    [ -f "$BIN" ] || { echo "✗ Binary not found: $BIN"; exit 1; }
    echo "✓ Built: $BIN (debug)"
    install_symlink "$BIN"
    start_server "$BIN"
    ;;
  release|rel|r)
    cd "$REPO"
    echo "→ cargo build --release -p zp-server -p zp-cli --features full..."
    if ! cargo build --release -p zp-server -p zp-cli --features full; then
        echo "✗ BUILD FAILED — not starting server with stale binary"
        exit 1
    fi
    BIN="$TARGET_DIR/release/$CLI_NAME"
    [ -f "$BIN" ] || { echo "✗ Binary not found: $BIN"; exit 1; }
    echo "✓ Built: $BIN (release)"
    install_symlink "$BIN"
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
