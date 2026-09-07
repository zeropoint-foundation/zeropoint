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
LOG_KEEP=5   # rotated server logs retained

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

# Surface bedrock-invariant violations on the terminal after a successful boot.
#
# Same problem as the touch prompt, same solution. `AppState::init` evaluates
# the invariants and writes its findings to the log; under `nohup … >> "$LOG"`
# nothing the binary prints reaches the operator, so a violation of a
# load-bearing premise scrolls into a file nobody opens. That is how a missing
# vault survived months of boots — its only signal was an Info-severity finding
# that was, at the time, discarded before even reaching the chain.
#
# Greps the structured tracing lines rather than the coloured block the binary
# also emits: the block carries ANSI escapes that make range-matching brittle,
# while `bedrock invariant violated` is a stable marker with the fields beside
# it. Only this boot's lines are considered — the log is appended across runs
# and rotated, not truncated, so matching the whole file would replay every
# violation the substrate has ever had.
report_bedrock() {
    [ -f "$LOG" ] || return 0

    # Everything after the last boot marker. `Starting server` is echoed by
    # this script, not the binary, so the boundary is unambiguous.
    local this_boot
    this_boot=$(awk '/Vault key resolved|Vault key not available/{buf=""} {buf=buf $0 ORS} END{printf "%s", buf}' "$LOG" 2>/dev/null)
    [ -n "$this_boot" ] || return 0

    printf '%s' "$this_boot" | grep -q "bedrock invariant violated\|bedrock invariant degraded" || return 0

    local red="\033[1;31m" yellow="\033[1;33m" reset="\033[0m"
    echo
    printf "${red}   ── BEDROCK ──────────────────────────────────────────${reset}\n"
    echo

    printf '%s' "$this_boot" \
      | grep -E "bedrock invariant (violated|degraded)" \
      | sed -E 's/.*invariant="?([a-z_]+)"?.*detail="?([^"]*)"?.*/  \1 — \2/' \
      | while IFS= read -r line; do
            printf "${red}   ✗ %s${reset}\n" "$line"
        done

    echo
    printf "${yellow}   Detail and remedies: %s${reset}\n" "$LOG"
    printf "${red}   ─────────────────────────────────────────────────────${reset}\n"
    echo
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

    # Rotate, do not truncate. `> "$LOG"` destroyed three days of diagnostic
    # history on 2026-07-31 — including the only record of the boot whose
    # behaviour was under investigation. Evidence that survives exactly until
    # the next attempt to reproduce is not evidence.
    if [ -s "$LOG" ]; then
        mv "$LOG" "$LOG.$(date +%Y%m%dT%H%M%S)" 2>/dev/null || true
        ls -1t "$LOG".2* 2>/dev/null | tail -n +$((LOG_KEEP + 1)) | while read -r old; do
            rm -f "$old"
        done
    fi

    ZP_ASSETS_DIR="$REPO/crates/zp-server/assets" \
    RUST_LOG="${RUST_LOG:-info}" nohup "$bin" serve --foreground --port "$PORT" >> "$LOG" 2>&1 &
    local server_pid=$!

    # Boot latency baselines:
    #   - OS Keychain Genesis:  ~9s (vault key resolution + startup)
    #   - Hardware Genesis (Trezor/YubiKey/Ledger/OnlyKey): operator confirmation
    #     latency is unbounded — physical touch on device, typically 10–120s.
    # The comment above says operator confirmation latency is *unbounded*,
    # and the poll window used to bound it at 180s anyway — so a boot
    # correctly waiting on a hardware touch reported "Failed to start"
    # while the server was alive and healthy (observed 2026-07-28). An
    # operator who believes that message kills a good boot and retries,
    # and after a few rounds raises ZP_BOOT_WAIT_SECS or turns hardware
    # Genesis off. That is the bypass pattern *delegable safety* names:
    # the rigid mechanism does not get fixed, it gets routed around.
    #
    # Three states, distinguished rather than collapsed:
    #   process exited        → real failure, reported immediately
    #   awaiting a touch      → unbounded, and SAID SO on the terminal
    #   neither               → bounded wait, reported as "not yet
    #                           listening" rather than as failure
    local wait_secs="${ZP_BOOT_WAIT_SECS:-180}"
    local max_tries=$((wait_secs * 2))
    local tries=0
    local prompted=0
    local last_nag=0
    local device="hardware key"
    while :; do
        if lsof -i :$PORT -sTCP:LISTEN > /dev/null 2>&1; then
            [ $prompted -eq 1 ] && echo "✓ confirmed"
            echo "✓ localhost:$PORT (PID $server_pid, build $commit)"
            report_bedrock
            return 0
        fi

        # A dead process is a real failure and should not wait out the
        # window. This previously burned the full 180s on an instant crash.
        if ! kill -0 "$server_pid" 2>/dev/null; then
            echo "✗ Server exited during boot (PID $server_pid)"
            echo "  log: $LOG"
            tail -20 "$LOG"
            return 1
        fi

        # The prompt existed — at INFO, in a logfile, where nobody was
        # looking. Put it where the person is, and make it impossible to
        # miss: this is a *physical* action, and the operator may have
        # walked away or scrolled past. Bell, banner, and a repeating
        # reminder, because a boot that silently waits on a human is
        # indistinguishable from a hang.
        if [ $prompted -eq 0 ] \
           && grep -qE "confirm on device|Waiting for user confirmation" "$LOG" 2>/dev/null; then
            # Identify the device from the line that actually triggered
            # the prompt, not from anywhere in the log.
            #
            # Grepping the whole file matched "trezor" on
            # `trezor_client: transport connect: Connection refused` — a
            # probe line that appears whether or not a Trezor is the
            # device in use — so a YubiKey boot would have been told to
            # touch a Trezor. The four greps were also sequential
            # overwrites, so the last one appearing anywhere won,
            # in arbitrary order.
            #
            # The tracing module path on the prompting line is
            # unambiguous: zp_keys::sovereignty::hardware::<provider>.
            local promptline
            promptline=$(grep -E "confirm on device|Waiting for user confirmation" \
                         "$LOG" 2>/dev/null | tail -1)
            case "$promptline" in
                *hardware::trezor*)  device="Trezor"  ;;
                *hardware::yubikey*) device="YubiKey" ;;
                *hardware::ledger*)  device="Ledger"  ;;
                *hardware::onlykey*) device="OnlyKey" ;;
                *)                   device="hardware key" ;;
            esac

            # Block letters rather than a boxed message. This is a
            # *physical* action — the operator may have walked away, or be
            # looking at the device rather than the terminal — and a
            # message that scrolls past at normal weight is the same
            # failure as the INFO line in the logfile, just closer.
            #
            # Hardcoded glyphs rather than figlet: five lines beats a
            # runtime dependency the script would have to detect, and
            # there is exactly one word to render.
            #
            # No box borders or width padding either. The em-dash is three
            # bytes and one column, so printf padding drifts, and a longer
            # device name would break any fixed frame.
            local Y='\033[1;33m' Rst='\033[0m'
            printf '\a'    # terminal bell — a human is needed
            echo ""
            printf "${Y}   ██████  ████  ██  ██  █████ ██  ██${Rst}\n"
            printf "${Y}     ██   ██  ██ ██  ██ ██     ██  ██${Rst}\n"
            printf "${Y}     ██   ██  ██ ██  ██ ██     ██████${Rst}\n"
            printf "${Y}     ██   ██  ██ ██  ██ ██     ██  ██${Rst}\n"
            printf "${Y}     ██    ████   ████   █████ ██  ██${Rst}\n"
            echo ""
            printf "${Y}        ▶  Y O U R   %s${Rst}\n" \
                "$(echo "$device" | tr '[:lower:]' '[:upper:]' | sed 's/./& /g')"
            echo ""
            echo "   Look at the device and do what it asks — that may be a button"
            echo "   press, or entering your PIN. The gesture is the device's to choose."
            echo ""
            echo "   ZeroPoint is unlocking the sovereign root — every signature this"
            echo "   session traces back to this one touch."
            echo ""
            echo "   Boot is paused until you confirm and will wait as long as it takes."
            echo "   The ceremony is bounded by you, not by a clock."
            echo ""
            prompted=1
            last_nag=$tries
        fi

        # Repeat every ~20s. Someone who stepped away comes back to a
        # live instruction rather than a wall of scrollback.
        if [ $prompted -eq 1 ] && [ $((tries - last_nag)) -ge 40 ]; then
            printf '\a'
            printf "     \033[1;33m… still waiting on your %s — check the device screen\033[0m\n" "$device"
            last_nag=$tries
        fi

        sleep 0.5
        tries=$((tries + 1))

        # Only the non-ceremony path is bounded, and even then the server
        # is left running — it is alive, just not listening yet.
        if [ $prompted -eq 0 ] && [ $tries -ge $max_tries ]; then
            echo "⚠ Not listening after ${wait_secs}s, but the process is alive (PID $server_pid)."
            echo "  This is not necessarily a failure — check what it is waiting on:"
            echo "    ./zp-dev.sh log"
            echo "  (extend with ZP_BOOT_WAIT_SECS=<seconds>)"
            tail -10 "$LOG"
            return 1
        fi
    done
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
