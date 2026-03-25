#!/bin/bash
# ══════════════════════════════════════════════════
# ZeroPoint Dev — single command, zero ambiguity.
#
#   ./zp-dev.sh          Fast dev build (debug profile) + restart
#   ./zp-dev.sh release  Release build (cargo install) + restart
#   ./zp-dev.sh html     HTML-only hot reload (instant, no compile)
#   ./zp-dev.sh kill     Stop the server, kill zombies
#   ./zp-dev.sh log      Tail the server log
#   ./zp-dev.sh status   What's running, which assets are active
#   ./zp-dev.sh clean    Kill + remove overrides + clear log
#
# Asset architecture (two-tier):
#   1. Override dir: ~/.zeropoint/assets/ (or $ZP_ASSETS_DIR)
#      - Hot reload: `./zp-dev.sh html` copies source files here
#      - Persistent: narration MP3s, images live here permanently
#   2. Compiled-in: include_str!() in the Rust binary
#      - Always available, matches the last cargo build
#      - Dev/release builds delete overrides so compiled-in takes effect
# ══════════════════════════════════════════════════
set -e

REPO="$(cd "$(dirname "$0")" && pwd)"
BINARY_NAME="zp-server"
CLI_NAME="zp"
LOCAL_BIN="$HOME/.local/bin/$CLI_NAME"
CARGO_BIN="$HOME/.cargo/bin/$CLI_NAME"
# Read target-dir from .cargo/config.toml (e.g. /tmp/zp-target)
TARGET_DIR=$(sed -n 's/^target-dir *= *"\(.*\)"/\1/p' "$REPO/.cargo/config.toml" 2>/dev/null)
TARGET_DIR="${TARGET_DIR:-$REPO/target}"
DEBUG_BIN="$TARGET_DIR/debug/$CLI_NAME"
ZP_HOME="$HOME/.zeropoint"
ASSETS_DIR="${ZP_ASSETS_DIR:-$ZP_HOME/assets}"
ASSET_SRC="$REPO/crates/zp-server/assets"
PID_FILE="$ZP_HOME/server.pid"
SERVER_LOG="/tmp/zp-serve.log"
PORT=3000

# ── Asset files ──────────────────────────────────
# HTML files have compiled-in fallbacks (include_str!) so the binary
# can serve them without the override dir. After a dev/release build,
# HTML overrides are deleted — compiled-in takes over.
HTML_FILES=(
    onboard.html
    dashboard.html
    speak.html
)

# Static files (CSS, JS) have NO compiled-in fallback — they're served
# only through ServeDir. They must ALWAYS exist in the override dir.
# After a build, these are copied fresh from source (never deleted).
STATIC_FILES=(
    onboard.css
    onboard.js
    tts.js
)

# ── Helpers ──────────────────────────────────────

# Delete HTML overrides (compiled-in takes over after build)
remove_html_overrides() {
    for f in "${HTML_FILES[@]}"; do
        rm -f "$ASSETS_DIR/$f"
    done
}

# Ensure static files are always present in override dir
deploy_static() {
    mkdir -p "$ASSETS_DIR"
    for f in "${STATIC_FILES[@]}"; do
        if [ -f "$ASSET_SRC/$f" ]; then
            cp "$ASSET_SRC/$f" "$ASSETS_DIR/$f"
        fi
    done
}

# Copy everything (html mode: override dir is the live source)
copy_all_assets() {
    mkdir -p "$ASSETS_DIR"
    for f in "${HTML_FILES[@]}" "${STATIC_FILES[@]}"; do
        if [ -f "$ASSET_SRC/$f" ]; then
            cp "$ASSET_SRC/$f" "$ASSETS_DIR/$f"
            printf "✓ %-18s → override\n" "$f"
        fi
    done
}

kill_server() {
    # 1. Kill by PID file (cleanest)
    if [ -f "$PID_FILE" ]; then
        local saved_pid
        saved_pid=$(cat "$PID_FILE" 2>/dev/null)
        if [ -n "$saved_pid" ] && kill -0 "$saved_pid" 2>/dev/null; then
            kill "$saved_pid" 2>/dev/null || true
            sleep 0.3
        fi
        rm -f "$PID_FILE"
    fi

    # 2. Kill by port (catches anything the PID file missed)
    local pids
    pids=$(lsof -ti :$PORT -sTCP:LISTEN 2>/dev/null || true)
    if [ -n "$pids" ]; then
        echo "$pids" | xargs kill 2>/dev/null || true
        sleep 0.5
        # Force-kill survivors
        pids=$(lsof -ti :$PORT -sTCP:LISTEN 2>/dev/null || true)
        if [ -n "$pids" ]; then
            echo "$pids" | xargs kill -9 2>/dev/null || true
            sleep 0.3
        fi
    fi

    # 3. Catch any stray "zp serve" not yet on the port
    pkill -f "$CLI_NAME serve" 2>/dev/null || true
}

start_server() {
    local binary="$1"
    kill_server

    echo "→ Starting server ($(basename "$binary"))..."
    nohup "$binary" serve > "$SERVER_LOG" 2>&1 &
    local server_pid=$!

    # Write PID file
    mkdir -p "$ZP_HOME"
    echo "$server_pid" > "$PID_FILE"

    # Wait for port
    local tries=0
    while [ $tries -lt 15 ]; do
        if lsof -i :$PORT -sTCP:LISTEN > /dev/null 2>&1; then
            echo "✓ Server running — localhost:$PORT/onboard  (PID $server_pid)"
            return 0
        fi
        sleep 0.4
        tries=$((tries + 1))
    done
    echo "✗ Server failed to start — check: ./zp-dev.sh log"
    tail -10 "$SERVER_LOG"
    return 1
}

check_binary() {
    if [ ! -f "$LOCAL_BIN" ]; then
        echo "✗ No binary at $LOCAL_BIN"
        echo "  Run './zp-dev.sh' or './zp-dev.sh release' first"
        exit 1
    fi
}

elapsed() {
    local start=$1
    local end=$(date +%s)
    echo "$((end - start))s"
}

# ── Commands ─────────────────────────────────────

case "${1:-dev}" in

  dev|d|"")
    echo "══════════════════════════════════════"
    echo "  ZeroPoint — Dev Build (debug)"
    echo "══════════════════════════════════════"
    START=$(date +%s)
    cd "$REPO"

    # Dev build: debug profile, no LTO, no strip → ~5x faster
    echo "→ cargo build -p zp-server -p zp-cli..."
    cargo build -p zp-server -p zp-cli 2>&1 | tail -10

    # Deploy: copy debug binary to PATH
    mkdir -p "$(dirname "$LOCAL_BIN")"
    if [ -f "$DEBUG_BIN" ]; then
        cp "$DEBUG_BIN" "$LOCAL_BIN"
    elif [ -f "$CARGO_BIN" ]; then
        cp "$CARGO_BIN" "$LOCAL_BIN"
    else
        echo "✗ No binary found at $DEBUG_BIN or $CARGO_BIN"
        exit 1
    fi
    # Ad-hoc codesign so macOS Keychain "Always Allow" persists across rebuilds.
    # Without this, every new binary has a different hash and Keychain forgets the ACL.
    codesign -s - -f "$LOCAL_BIN" 2>/dev/null && echo "✓ Binary: $LOCAL_BIN (debug, codesigned, $(elapsed $START))" \
        || echo "✓ Binary: $LOCAL_BIN (debug, $(elapsed $START))"

    # Remove HTML overrides (compiled-in takes over). Deploy static
    # files (CSS/JS have no compiled-in fallback, must always be present).
    remove_html_overrides
    deploy_static

    start_server "$LOCAL_BIN"
    echo "══════════════════════════════════════"
    ;;

  release|rel|r)
    echo "══════════════════════════════════════"
    echo "  ZeroPoint — Release Build"
    echo "══════════════════════════════════════"
    START=$(date +%s)
    cd "$REPO"

    # Release build: LTO + strip → slow but small + fast binary
    echo "→ cargo install --path crates/zp-server..."
    cargo install --path crates/zp-server 2>&1 | tail -5
    echo "→ cargo install --path crates/zp-cli..."
    cargo install --path crates/zp-cli 2>&1 | tail -5

    mkdir -p "$(dirname "$LOCAL_BIN")"
    cp "$CARGO_BIN" "$LOCAL_BIN"
    codesign -s - -f "$LOCAL_BIN" 2>/dev/null && echo "✓ Binary: $LOCAL_BIN (release, codesigned, $(elapsed $START))" \
        || echo "✓ Binary: $LOCAL_BIN (release, $(elapsed $START))"

    remove_html_overrides
    deploy_static

    start_server "$LOCAL_BIN"
    echo "══════════════════════════════════════"
    ;;

  html|hot|h)
    echo "══════════════════════════════════════"
    echo "  ZeroPoint — HTML Hot Reload"
    echo "══════════════════════════════════════"
    check_binary

    # Copy all source assets → override dir (HTML + static)
    # resolve_html_asset() and ServeDir both read from here.
    copy_all_assets

    start_server "$LOCAL_BIN"
    echo ""
    echo "  Edit source → run './zp-dev.sh html' → reload browser"
    echo "══════════════════════════════════════"
    ;;

  kill|stop|k)
    echo "→ Stopping server..."
    kill_server
    echo "✓ Done"
    ;;

  log|l)
    if [ -f "$SERVER_LOG" ]; then
        tail -50 -f "$SERVER_LOG"
    else
        echo "No log at $SERVER_LOG — server hasn't run yet"
    fi
    ;;

  status|s)
    echo "── ZeroPoint Status ──────────────────"

    # Binary
    if [ -f "$LOCAL_BIN" ]; then
        local_size=$(stat -f%z "$LOCAL_BIN" 2>/dev/null || stat -c%s "$LOCAL_BIN" 2>/dev/null)
        echo "Binary:   $LOCAL_BIN ($((local_size / 1048576))MB)"
    else
        echo "Binary:   NOT FOUND"
    fi

    # Asset tier
    echo "Assets:   $ASSETS_DIR"
    html_override=0
    for f in "${HTML_FILES[@]}"; do
        [ -f "$ASSETS_DIR/$f" ] && html_override=$((html_override + 1))
    done
    if [ "$html_override" -gt 0 ]; then
        echo "  HTML:   $html_override override(s) active (hot-reload mode)"
        for f in "${HTML_FILES[@]}"; do
            [ -f "$ASSETS_DIR/$f" ] && echo "          ↳ $f (override)"
        done
    else
        echo "  HTML:   compiled-in (matches last build)"
    fi
    static_missing=0
    for f in "${STATIC_FILES[@]}"; do
        [ ! -f "$ASSETS_DIR/$f" ] && static_missing=$((static_missing + 1))
    done
    if [ "$static_missing" -gt 0 ]; then
        echo "  Static: ⚠ $static_missing file(s) MISSING — run './zp-dev.sh' to fix"
        for f in "${STATIC_FILES[@]}"; do
            [ ! -f "$ASSETS_DIR/$f" ] && echo "          ✗ $f"
        done
    else
        echo "  Static: ${#STATIC_FILES[@]} file(s) deployed"
    fi

    # Persistent assets (narration, etc.)
    narration_count=0
    if [ -d "$ASSETS_DIR/narration" ]; then
        narration_count=$(find "$ASSETS_DIR/narration" -name '*.mp3' 2>/dev/null | wc -l | tr -d ' ')
    fi
    echo "          $narration_count narration MP3(s) in assets/narration/"

    # Server
    if [ -f "$PID_FILE" ]; then
        local saved_pid
        saved_pid=$(cat "$PID_FILE" 2>/dev/null)
        if kill -0 "$saved_pid" 2>/dev/null; then
            echo "Server:   RUNNING (PID $saved_pid, port $PORT)"
        else
            echo "Server:   STALE PID ($saved_pid dead)"
        fi
    else
        echo "Server:   no PID file"
    fi

    if lsof -i :$PORT -sTCP:LISTEN > /dev/null 2>&1; then
        local live_pid
        live_pid=$(lsof -ti :$PORT -sTCP:LISTEN 2>/dev/null)
        echo "Port:     :$PORT LISTENING (PID $live_pid)"
    else
        echo "Port:     :$PORT FREE"
    fi

    # TTS sidecar
    if curl -s --max-time 1 http://localhost:8473/health > /dev/null 2>&1; then
        echo "TTS:      localhost:8473 UP (voice-tuner-server)"
    else
        echo "TTS:      localhost:8473 DOWN"
    fi

    # Zombie check
    local count
    count=$(pgrep -fc "$CLI_NAME serve" 2>/dev/null || echo 0)
    if [ "$count" -gt 1 ]; then
        echo "⚠ ZOMBIES: $count '$CLI_NAME serve' processes — run './zp-dev.sh kill'"
    fi

    echo "──────────────────────────────────────"
    ;;

  clean|c)
    echo "→ Full cleanup..."
    kill_server
    remove_html_overrides
    for f in "${STATIC_FILES[@]}"; do rm -f "$ASSETS_DIR/$f"; done
    rm -f "$SERVER_LOG"
    rm -f "$PID_FILE"
    echo "✓ Server stopped, overrides removed, log cleared"
    ;;

  *)
    cat <<'USAGE'
Usage: ./zp-dev.sh [command]

Commands:
  (default)  Dev build (debug profile, fast) + restart
  release    Release build (optimized, slow) + restart
  html       Copy source assets to override dir + restart (no compile)
  kill       Stop server, kill zombies
  log        Tail server log
  status     Show binary, asset tiers, server & TTS state
  clean      Stop + remove overrides + clear log

Asset tiers:
  1. Override:    ~/.zeropoint/assets/ (or $ZP_ASSETS_DIR)
  2. Compiled-in: baked into the binary at build time

Workflow:
  Rust changes:  ./zp-dev.sh           (~5-10s dev build)
  HTML/JS/CSS:   ./zp-dev.sh html      (instant)
  Ship it:       ./zp-dev.sh release   (~30-60s optimized build)
USAGE
    exit 1
    ;;

esac
