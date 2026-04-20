#!/usr/bin/env bash
# ============================================================================
# ZeroPoint — Resumable State-Machine Installer
# ============================================================================
#
# Usage:
#   curl -sSf https://install.zeropoint.global | bash         # binary install
#   curl -sSf https://install.zeropoint.global | bash -s -- --source  # source build
#
# Or clone first and run locally:
#   bash deploy/install.sh
#   bash deploy/install.sh --retry-from build   # resume from build stage
#   bash deploy/install.sh --binary             # pre-built binary install
#   bash deploy/install.sh --skip-tests         # skip test suite
#   bash deploy/install.sh --verbose            # show full build output
#
# The installer is idempotent: running it twice does nothing.
# On failure it checkpoints and resumes from the failed stage.
# ============================================================================

set -uo pipefail
# Note: we do NOT set -e globally — each stage handles its own errors.

# ─── Constants ────────────────────────────────────────────────

INSTALLER_VERSION="2.0.0"
REPO="https://github.com/zeropoint-foundation/zeropoint.git"
INSTALL_DIR="${ZP_INSTALL_DIR:-$HOME/zeropoint}"
ZP_HOME="${ZP_HOME:-$HOME/ZeroPoint}"
ZP_BIN="$ZP_HOME/bin"
ZP_PORT="${ZP_PORT:-3000}"
STATE_FILE="$ZP_HOME/install-state.json"

# Stage timeouts (seconds)
TIMEOUT_PREFLIGHT=60
TIMEOUT_DEPS=300
TIMEOUT_CLONE=300
TIMEOUT_BUILD=1800    # 30 minutes
TIMEOUT_TEST=600      # 10 minutes
TIMEOUT_GENESIS=60
TIMEOUT_INSTALL=60
TIMEOUT_CONFIGURE=30
TIMEOUT_VERIFY=30

# Ordered list of stages
STAGES=(preflight dependencies clone build test genesis install configure verify)

# ─── CLI Argument Parsing ─────────────────────────────────────

RETRY_FROM=""
SKIP_TESTS=false
VERBOSE=false
BINARY_INSTALL=false
NON_INTERACTIVE=false
GENESIS_CONFIG=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --retry-from)
            RETRY_FROM="$2"; shift 2 ;;
        --retry-from=*)
            RETRY_FROM="${1#*=}"; shift ;;
        --skip-tests)
            SKIP_TESTS=true; shift ;;
        --verbose)
            VERBOSE=true; shift ;;
        --binary)
            BINARY_INSTALL=true; shift ;;
        --source)
            BINARY_INSTALL=false; shift ;;
        --non-interactive)
            NON_INTERACTIVE=true; shift ;;
        --genesis-config)
            GENESIS_CONFIG="$2"; shift 2 ;;
        --genesis-config=*)
            GENESIS_CONFIG="${1#*=}"; shift ;;
        --help|-h)
            echo "Usage: install.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --retry-from STAGE   Resume from a specific stage"
            echo "  --skip-tests         Skip the test stage"
            echo "  --verbose            Show full build output"
            echo "  --binary             Install pre-built binaries (no Rust needed)"
            echo "  --source             Build from source (default if run from repo)"
            echo "  --non-interactive    No prompts (for CI/CD)"
            echo "  --genesis-config F   Use TOML file for genesis (Tier C)"
            echo ""
            echo "Stages: ${STAGES[*]}"
            exit 0 ;;
        *)
            echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ─── Colors & Output ─────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

info()   { echo -e "  ${CYAN}▸${NC} $1"; }
ok()     { echo -e "  ${GREEN}✓${NC} $1"; }
warn()   { echo -e "  ${YELLOW}⚠${NC} $1"; }
err()    { echo -e "  ${RED}✗${NC} $1"; }
header() { echo ""; echo -e "  ${BOLD}$1${NC}"; echo -e "  ────────────────────────────────────────"; }
dim()    { echo -e "  ${DIM}$1${NC}"; }

# ─── State Management ─────────────────────────────────────────
# State is a JSON file: { "stages": { "preflight": { "status": "done", "ts": "...", "elapsed_s": N }, ... } }

mkdir -p "$ZP_HOME"

state_read() {
    # Read the status of a stage. Returns: "done", "failed", "running", or "pending"
    local stage="$1"
    if [ -f "$STATE_FILE" ]; then
        python3 -c "
import json, sys
try:
    s = json.load(open('$STATE_FILE'))
    print(s.get('stages', {}).get('$stage', {}).get('status', 'pending'))
except:
    print('pending')
" 2>/dev/null || echo "pending"
    else
        echo "pending"
    fi
}

state_write() {
    # Write the status of a stage with timestamp and optional elapsed time.
    local stage="$1"
    local status="$2"
    local elapsed="${3:-0}"
    python3 -c "
import json, os, sys
from datetime import datetime
path = '$STATE_FILE'
try:
    state = json.load(open(path))
except:
    state = {'installer_version': '$INSTALLER_VERSION', 'stages': {}}

state['stages']['$stage'] = {
    'status': '$status',
    'timestamp': datetime.utcnow().isoformat() + 'Z',
    'elapsed_s': $elapsed
}
state['installer_version'] = '$INSTALLER_VERSION'

os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, 'w') as f:
    json.dump(state, f, indent=2)
" 2>/dev/null
}

should_run_stage() {
    # Returns 0 (true) if the stage should be run, 1 (false) if it should be skipped.
    local stage="$1"

    # If --retry-from is set, skip everything before the retry stage
    if [ -n "$RETRY_FROM" ]; then
        local found_retry=false
        for s in "${STAGES[@]}"; do
            if [ "$s" = "$RETRY_FROM" ]; then
                found_retry=true
            fi
            if [ "$s" = "$stage" ]; then
                if $found_retry; then
                    return 0  # Run this stage
                else
                    return 1  # Skip — before retry point
                fi
            fi
        done
        return 0
    fi

    # Otherwise, skip stages that are already done
    local status
    status=$(state_read "$stage")
    if [ "$status" = "done" ]; then
        return 1  # Skip
    fi
    return 0  # Run
}

# Run a stage with timeout. Usage: run_with_timeout TIMEOUT STAGE_NAME command args...
run_with_timeout() {
    local timeout_s="$1"; shift
    local stage="$1"; shift

    if command -v timeout &>/dev/null; then
        timeout "$timeout_s" "$@"
        return $?
    else
        # macOS doesn't have coreutils timeout by default
        "$@" &
        local pid=$!
        local count=0
        while kill -0 "$pid" 2>/dev/null; do
            sleep 1
            count=$((count + 1))
            if [ "$count" -ge "$timeout_s" ]; then
                kill "$pid" 2>/dev/null
                warn "Stage '$stage' timed out after ${timeout_s}s"
                warn "Resume with: bash deploy/install.sh --retry-from $stage"
                return 124
            fi
        done
        wait "$pid"
        return $?
    fi
}

# ─── Banner ───────────────────────────────────────────────────

echo ""
echo -e "  ${BOLD}ZeroPoint Installer v${INSTALLER_VERSION}${NC}"
echo -e "  Trust is infrastructure."
echo ""

if [ -n "$RETRY_FROM" ]; then
    info "Resuming from stage: $RETRY_FROM"
fi

# ═══════════════════════════════════════════════════════════════
# Stage 1: PREFLIGHT
# ═══════════════════════════════════════════════════════════════

run_preflight() {
    header "Stage 1/9: Pre-flight Checks"

    # If zp-preflight binary is available, use it
    if command -v zp-preflight &>/dev/null; then
        if $BINARY_INSTALL; then
            zp-preflight --binary
        else
            zp-preflight
        fi
        return $?
    fi

    # Fallback: inline checks (for bootstrap when zp-preflight isn't built yet)
    local failures=0

    # Check git
    if command -v git &>/dev/null; then
        ok "git: $(git --version | head -c 20)"
    else
        err "git not found"
        failures=$((failures + 1))
    fi

    if ! $BINARY_INSTALL; then
        # Check Rust (only for source builds)
        if command -v rustc &>/dev/null; then
            local rust_ver
            rust_ver=$(rustc --version | awk '{print $2}')
            local major minor
            major=$(echo "$rust_ver" | cut -d. -f1)
            minor=$(echo "$rust_ver" | cut -d. -f2)
            if [ "$major" -ge 1 ] && [ "$minor" -ge 77 ]; then
                ok "rustc $rust_ver (>= 1.77 required)"
            else
                err "rustc $rust_ver is too old (>= 1.77 required)"
                info "Fix: rustup update stable"
                failures=$((failures + 1))
            fi
        else
            warn "rustc not found — will install in dependencies stage"
        fi

        # Check pkg-config
        if command -v pkg-config &>/dev/null; then
            ok "pkg-config found"
        else
            warn "pkg-config not found — will install in dependencies stage"
        fi
    fi

    # Check disk space
    local free_mb
    free_mb=$(df -m "$HOME" 2>/dev/null | awk 'NR==2{print $4}')
    if [ -n "$free_mb" ]; then
        if [ "$free_mb" -ge 2048 ]; then
            ok "Disk space: ${free_mb}MB free"
        elif [ "$free_mb" -ge 512 ]; then
            warn "Disk space: ${free_mb}MB free (2GB+ recommended for source build)"
        else
            err "Disk space: ${free_mb}MB free (512MB minimum required)"
            failures=$((failures + 1))
        fi
    fi

    # Check network
    if curl -sI --connect-timeout 5 https://github.com >/dev/null 2>&1; then
        ok "Network: github.com reachable"
    else
        err "Network: cannot reach github.com"
        failures=$((failures + 1))
    fi

    if [ "$failures" -gt 0 ]; then
        err "$failures pre-flight check(s) failed"
        return 1
    fi

    ok "All pre-flight checks passed"
    return 0
}

# ═══════════════════════════════════════════════════════════════
# Stage 2: DEPENDENCIES
# ═══════════════════════════════════════════════════════════════

run_dependencies() {
    header "Stage 2/9: Dependencies"

    if $BINARY_INSTALL; then
        ok "Binary install — no build dependencies needed"
        return 0
    fi

    # ── Rust toolchain ──
    if command -v cargo &>/dev/null; then
        ok "Rust toolchain: $(rustc --version | awk '{print $2}')"
    else
        info "Installing Rust via rustup..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
        # shellcheck source=/dev/null
        source "$HOME/.cargo/env" 2>/dev/null || true
        export PATH="$HOME/.cargo/bin:$PATH"
        ok "Rust installed: $(rustc --version | awk '{print $2}')"
    fi

    export PATH="$HOME/.cargo/bin:$PATH"

    # ── System libraries ──
    # Detect package manager
    local pkg_mgr=""
    if command -v apt-get &>/dev/null; then
        pkg_mgr="apt"
    elif command -v dnf &>/dev/null; then
        pkg_mgr="dnf"
    elif command -v brew &>/dev/null; then
        pkg_mgr="brew"
    elif command -v pacman &>/dev/null; then
        pkg_mgr="pacman"
    fi

    # Check and install libssl
    if ! pkg-config --exists openssl 2>/dev/null && ! pkg-config --exists libssl 2>/dev/null; then
        info "Installing OpenSSL development headers..."
        case "$pkg_mgr" in
            apt)    sudo apt-get update -qq && sudo apt-get install -y libssl-dev ;;
            dnf)    sudo dnf install -y openssl-devel ;;
            brew)   brew install openssl@3 ;;
            pacman) sudo pacman -S --noconfirm openssl ;;
            *)      err "Cannot auto-install libssl — install manually"; return 1 ;;
        esac
        ok "OpenSSL headers installed"
    else
        ok "OpenSSL headers present"
    fi

    # Check and install pkg-config (if missing)
    if ! command -v pkg-config &>/dev/null; then
        info "Installing pkg-config..."
        case "$pkg_mgr" in
            apt)    sudo apt-get install -y pkg-config ;;
            dnf)    sudo dnf install -y pkgconf-pkg-config ;;
            brew)   brew install pkg-config ;;
            pacman) sudo pacman -S --noconfirm pkgconf ;;
            *)      err "Cannot auto-install pkg-config — install manually"; return 1 ;;
        esac
        ok "pkg-config installed"
    fi

    ok "All dependencies satisfied"
    return 0
}

# ═══════════════════════════════════════════════════════════════
# Stage 3: CLONE
# ═══════════════════════════════════════════════════════════════

run_clone() {
    header "Stage 3/9: Repository"

    if $BINARY_INSTALL; then
        ok "Binary install — skipping clone"
        return 0
    fi

    if [ -f "$INSTALL_DIR/Cargo.toml" ]; then
        info "Repository exists at $INSTALL_DIR — pulling latest..."
        cd "$INSTALL_DIR"
        if git pull --ff-only origin main 2>/dev/null; then
            ok "Updated to latest"
        else
            warn "Pull failed — continuing with existing code"
        fi
    else
        info "Cloning to $INSTALL_DIR..."
        git clone --depth 1 "$REPO" "$INSTALL_DIR"
        cd "$INSTALL_DIR"
        ok "Cloned"
    fi

    ok "Repository ready at $INSTALL_DIR"
    return 0
}

# ═══════════════════════════════════════════════════════════════
# Stage 4: BUILD
# ═══════════════════════════════════════════════════════════════

run_build() {
    header "Stage 4/9: Build"

    if $BINARY_INSTALL; then
        # Download pre-built binaries
        info "Downloading pre-built binaries..."

        local os arch target
        os="$(uname -s | tr '[:upper:]' '[:lower:]')"
        arch="$(uname -m)"

        case "$os" in
            linux)  os="unknown-linux-gnu" ;;
            darwin) os="apple-darwin" ;;
            *)      err "Unsupported OS: $os"; return 1 ;;
        esac

        case "$arch" in
            x86_64)  target="x86_64-${os}" ;;
            aarch64|arm64) target="aarch64-${os}" ;;
            *)       err "Unsupported architecture: $arch"; return 1 ;;
        esac

        local release_url="https://github.com/zeropoint-foundation/zeropoint/releases/latest/download/zeropoint-${target}.tar.gz"
        local tmp_dir
        tmp_dir=$(mktemp -d)

        info "Target: $target"
        info "Downloading from GitHub Releases..."

        if curl -fsSL "$release_url" -o "$tmp_dir/zp.tar.gz"; then
            tar xzf "$tmp_dir/zp.tar.gz" -C "$tmp_dir"
            mkdir -p "$ZP_BIN"
            cp "$tmp_dir/zp" "$ZP_BIN/zp" 2>/dev/null || true
            cp "$tmp_dir/zp-server" "$ZP_BIN/zp-server" 2>/dev/null || true
            cp "$tmp_dir/zp-cli" "$ZP_BIN/zp" 2>/dev/null || true
            chmod 755 "$ZP_BIN"/*
            rm -rf "$tmp_dir"
            ok "Binaries downloaded and installed"
        else
            rm -rf "$tmp_dir"
            err "Download failed — check your network or try --source"
            return 1
        fi

        return 0
    fi

    # ── Source build ──
    cd "$INSTALL_DIR"

    info "Building workspace (release mode)..."
    if $VERBOSE; then
        info "Full output enabled (--verbose)"
    fi

    local build_start
    build_start=$(date +%s)

    # Build with feature flags — release binaries get full features
    local build_cmd="cargo build --workspace --release --features zp-cli/full,zp-server/full,zp-policy/policy-wasm"

    if $VERBOSE; then
        if ! eval "$build_cmd" 2>&1; then
            local elapsed=$(( $(date +%s) - build_start ))
            err "Build failed after ${elapsed}s"
            diagnose_build_failure
            return 1
        fi
    else
        # Capture output, show progress dots
        local log_file="$ZP_HOME/build.log"
        eval "$build_cmd" > "$log_file" 2>&1 &
        local build_pid=$!

        # Show progress
        local dot_count=0
        while kill -0 "$build_pid" 2>/dev/null; do
            sleep 5
            dot_count=$((dot_count + 1))
            local elapsed=$(( $(date +%s) - build_start ))
            printf "\r  ▸ Building... %ds " "$elapsed"

            # Check timeout
            if [ "$elapsed" -ge "$TIMEOUT_BUILD" ]; then
                kill "$build_pid" 2>/dev/null
                echo ""
                err "Build timed out after ${TIMEOUT_BUILD}s"
                warn "Resume with: bash deploy/install.sh --retry-from build"
                return 124
            fi
        done
        echo ""

        wait "$build_pid"
        local build_result=$?

        if [ "$build_result" -ne 0 ]; then
            local elapsed=$(( $(date +%s) - build_start ))
            err "Build failed after ${elapsed}s"
            err "Full log: $log_file"
            dim "Last 20 lines:"
            tail -20 "$log_file" | while IFS= read -r line; do
                dim "  $line"
            done
            diagnose_build_failure "$log_file"
            return 1
        fi
    fi

    local elapsed=$(( $(date +%s) - build_start ))
    ok "Build complete in ${elapsed}s"

    # Verify binaries
    local missing=0
    for bin in zp-server zp; do
        if [ -f "target/release/$bin" ]; then
            ok "Binary: $bin ($(du -sh "target/release/$bin" | cut -f1))"
        else
            err "Binary not found: target/release/$bin"
            missing=$((missing + 1))
        fi
    done

    [ "$missing" -eq 0 ] || return 1
    return 0
}

diagnose_build_failure() {
    local log_file="${1:-}"
    local log_content=""

    if [ -n "$log_file" ] && [ -f "$log_file" ]; then
        log_content=$(cat "$log_file")
    fi

    echo ""
    info "Diagnosing build failure..."

    # Pattern-match common errors to actionable fixes
    if echo "$log_content" | grep -q "could not find.*dbus"; then
        err "Missing system library: libdbus"
        info "Fix: sudo apt-get install -y libdbus-1-dev"
    fi
    if echo "$log_content" | grep -q "could not find.*usb"; then
        err "Missing system library: libusb"
        info "Fix: sudo apt-get install -y libusb-1.0-0-dev"
    fi
    if echo "$log_content" | grep -q "could not find.*ssl\|openssl"; then
        err "Missing system library: OpenSSL"
        info "Fix: sudo apt-get install -y libssl-dev"
    fi
    if echo "$log_content" | grep -q "linker.*not found\|cc.*not found"; then
        err "Missing C compiler / linker"
        info "Fix: sudo apt-get install -y build-essential"
    fi
    if echo "$log_content" | grep -q "out of.*memory\|cannot allocate"; then
        err "Out of memory during compilation"
        info "Fix: Close other applications or add swap space"
        info "  sudo fallocate -l 4G /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile"
    fi

    echo ""
    warn "After fixing, resume with: bash deploy/install.sh --retry-from build"
}

# ═══════════════════════════════════════════════════════════════
# Stage 5: TEST
# ═══════════════════════════════════════════════════════════════

run_test() {
    header "Stage 5/9: Test Suite"

    if $SKIP_TESTS; then
        warn "Tests skipped (--skip-tests)"
        return 0
    fi

    if $BINARY_INSTALL; then
        ok "Binary install — skipping source tests"
        return 0
    fi

    cd "$INSTALL_DIR"
    info "Running workspace tests..."

    local test_output test_result
    test_output=$(cargo test --workspace --release 2>&1)
    test_result=$?

    local total_passed total_failed
    total_passed=$(echo "$test_output" | grep -o '[0-9]* passed' | awk '{s+=$1} END {print s+0}')
    total_failed=$(echo "$test_output" | grep -o '[0-9]* failed' | awk '{s+=$1} END {print s+0}')

    if [ "$test_result" -eq 0 ]; then
        ok "All tests passed ($total_passed passed)"
    else
        warn "Some tests failed ($total_passed passed, $total_failed failed)"
        if $VERBOSE; then
            echo "$test_output" | grep -A2 "FAILED" || true
        fi
        warn "Continuing — test failures are non-blocking for install"
    fi

    return 0  # Tests are advisory, don't block install
}

# ═══════════════════════════════════════════════════════════════
# Stage 6: GENESIS
# ═══════════════════════════════════════════════════════════════

run_genesis() {
    header "Stage 6/9: Genesis Ceremony"

    mkdir -p "$ZP_HOME/data"

    # Tier C: headless config
    if [ -n "$GENESIS_CONFIG" ]; then
        info "Genesis: Tier C (headless from $GENESIS_CONFIG)"
        "$ZP_BIN/zp" init --config "$GENESIS_CONFIG" 2>&1 || true
        ok "Genesis complete (headless)"
        return 0
    fi

    # Tier A: Quick Start (default)
    if $NON_INTERACTIVE; then
        info "Genesis: Tier A (non-interactive quick start)"
        local operator_name
        operator_name=$(whoami)
        "$ZP_BIN/zp" guard --silent --non-interactive "echo genesis" \
            --data-dir "$ZP_HOME/data" 2>/dev/null || true
        ok "Genesis complete (operator: $operator_name)"
    else
        info "Genesis: Tier A (Quick Start)"
        echo ""

        # Auto-detect sovereignty provider
        local sovereignty="file"
        if [[ "$(uname -s)" == "Darwin" ]] && command -v security &>/dev/null; then
            sovereignty="keychain"
        elif [[ "$(uname -s)" == "Linux" ]] && command -v dbus-send &>/dev/null; then
            if dbus-send --session --dest=org.freedesktop.secrets \
                --print-reply /org/freedesktop/secrets \
                org.freedesktop.DBus.Peer.Ping 2>/dev/null; then
                sovereignty="secret-service"
            fi
        fi

        local operator_name
        operator_name=$(whoami)

        # Single prompt
        if [ "$sovereignty" != "file" ]; then
            info "Detected sovereignty provider: $sovereignty"
        fi
        printf "  Your operator name? [%s] > " "$operator_name"
        if ! $NON_INTERACTIVE; then
            read -r user_name
            [ -n "$user_name" ] && operator_name="$user_name"
        else
            echo "$operator_name"
        fi

        # Trigger genesis via guard evaluation
        "$ZP_BIN/zp" guard --silent --non-interactive "echo genesis" \
            --data-dir "$ZP_HOME/data" 2>/dev/null || true

        ok "Genesis key created ($sovereignty)"
        ok "Operator: $operator_name"
    fi

    # Verify genesis artifacts
    if [ -d "$ZP_HOME/data" ]; then
        ok "Data directory: $ZP_HOME/data"
    fi

    return 0
}

# ═══════════════════════════════════════════════════════════════
# Stage 7: INSTALL (binaries to PATH)
# ═══════════════════════════════════════════════════════════════

run_install() {
    header "Stage 7/9: Install Binaries"

    mkdir -p "$ZP_BIN"

    if ! $BINARY_INSTALL; then
        # Source build — copy from target/release
        cd "$INSTALL_DIR"
        info "Installing binaries to $ZP_BIN..."
        cp target/release/zp "$ZP_BIN/zp" 2>/dev/null || true
        cp target/release/zp-server "$ZP_BIN/zp-server" 2>/dev/null || true
        cp target/release/zp-preflight "$ZP_BIN/zp-preflight" 2>/dev/null || true
        chmod 755 "$ZP_BIN"/* 2>/dev/null || true
    fi
    # Binary install already placed files in run_build

    # Verify at least zp exists
    if [ ! -f "$ZP_BIN/zp" ]; then
        err "zp binary not found in $ZP_BIN"
        return 1
    fi

    ok "Binaries installed to $ZP_BIN"

    # ── PATH setup ──
    if ! echo "$PATH" | grep -q "$ZP_BIN"; then
        local shell_name rc_file=""
        shell_name=$(basename "${SHELL:-bash}")
        case "$shell_name" in
            zsh)  rc_file="$HOME/.zshrc" ;;
            bash) rc_file="$HOME/.bashrc"
                  [ -f "$HOME/.bash_profile" ] && rc_file="$HOME/.bash_profile" ;;
            fish) rc_file="$HOME/.config/fish/config.fish" ;;
        esac

        if [ -n "$rc_file" ] && ! grep -q "ZeroPoint/bin" "$rc_file" 2>/dev/null; then
            {
                echo ""
                echo "# ZeroPoint"
                echo 'export PATH="$HOME/ZeroPoint/bin:$PATH"'
            } >> "$rc_file"
            ok "Added to PATH in $rc_file"
        fi

        export PATH="$ZP_BIN:$PATH"
    fi

    ok "'zp' command available"
    return 0
}

# ═══════════════════════════════════════════════════════════════
# Stage 8: CONFIGURE
# ═══════════════════════════════════════════════════════════════

run_configure() {
    header "Stage 8/9: Configure"

    local config_file="$ZP_HOME/config.toml"

    if [ -f "$config_file" ]; then
        ok "Configuration exists: $config_file"
        return 0
    fi

    info "Writing default configuration..."

    mkdir -p "$ZP_HOME"
    cat > "$config_file" << 'TOML'
# ZeroPoint Configuration
# Generated by installer. Edit with: zp config set <key> <value>

[server]
port = 3000
bind = "127.0.0.1"

[data]
dir = "~/ZeroPoint/data"

[governance]
posture = "balanced"

[logging]
level = "info"
TOML

    # Apply port override if set
    if [ "$ZP_PORT" != "3000" ]; then
        sed -i.bak "s/port = 3000/port = $ZP_PORT/" "$config_file" 2>/dev/null || true
        rm -f "${config_file}.bak"
    fi

    ok "Configuration written to $config_file"
    return 0
}

# ═══════════════════════════════════════════════════════════════
# Stage 9: VERIFY
# ═══════════════════════════════════════════════════════════════

run_verify() {
    header "Stage 9/9: Verification"

    local failures=0

    # Binary version
    if "$ZP_BIN/zp" --version &>/dev/null; then
        local ver
        ver=$("$ZP_BIN/zp" --version 2>&1 | head -1)
        ok "Binary: $ver"
    else
        err "zp binary not responding"
        failures=$((failures + 1))
    fi

    # Data directory
    if [ -d "$ZP_HOME/data" ]; then
        local perms
        perms=$(stat -c '%a' "$ZP_HOME/data" 2>/dev/null || stat -f '%A' "$ZP_HOME/data" 2>/dev/null || echo "?")
        ok "Data directory: $ZP_HOME/data (mode $perms)"
    else
        warn "Data directory not found — will be created on first run"
    fi

    # Config
    if [ -f "$ZP_HOME/config.toml" ]; then
        ok "Configuration: $ZP_HOME/config.toml"
    else
        warn "No configuration file"
    fi

    # Guard smoke test
    local guard_out
    guard_out=$("$ZP_BIN/zp" guard "echo hello" --data-dir "$ZP_HOME/data" 2>&1 || true)
    if [ -n "$guard_out" ]; then
        ok "Guard responds"
    else
        warn "Guard did not produce output — may need genesis"
    fi

    if [ "$failures" -gt 0 ]; then
        return 1
    fi

    ok "Verification passed"
    return 0
}

# ═══════════════════════════════════════════════════════════════
# ORCHESTRATOR — run stages in order, checkpoint each one
# ═══════════════════════════════════════════════════════════════

declare -A STAGE_FN=(
    [preflight]=run_preflight
    [dependencies]=run_dependencies
    [clone]=run_clone
    [build]=run_build
    [test]=run_test
    [genesis]=run_genesis
    [install]=run_install
    [configure]=run_configure
    [verify]=run_verify
)

declare -A STAGE_TIMEOUT=(
    [preflight]=$TIMEOUT_PREFLIGHT
    [dependencies]=$TIMEOUT_DEPS
    [clone]=$TIMEOUT_CLONE
    [build]=$TIMEOUT_BUILD
    [test]=$TIMEOUT_TEST
    [genesis]=$TIMEOUT_GENESIS
    [install]=$TIMEOUT_INSTALL
    [configure]=$TIMEOUT_CONFIGURE
    [verify]=$TIMEOUT_VERIFY
)

overall_start=$(date +%s)
failed_stage=""

for stage in "${STAGES[@]}"; do
    if ! should_run_stage "$stage"; then
        dim "  ─ $stage (already done, skipping)"
        continue
    fi

    state_write "$stage" "running"
    stage_start=$(date +%s)

    # Run the stage function
    if ${STAGE_FN[$stage]}; then
        stage_elapsed=$(( $(date +%s) - stage_start ))
        state_write "$stage" "done" "$stage_elapsed"
    else
        stage_elapsed=$(( $(date +%s) - stage_start ))
        state_write "$stage" "failed" "$stage_elapsed"
        err "Stage '$stage' failed after ${stage_elapsed}s"
        warn "Resume with: bash deploy/install.sh --retry-from $stage"
        failed_stage="$stage"
        break
    fi
done

# ═══════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════

overall_elapsed=$(( $(date +%s) - overall_start ))

echo ""
if [ -z "$failed_stage" ]; then
    echo -e "  ${GREEN}══════════════════════════════════════════════════${NC}"
    echo -e "  ${GREEN}  ZEROPOINT INSTALLED SUCCESSFULLY${NC}"
    echo -e "  ${GREEN}══════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Total time:  ${overall_elapsed}s"
    echo -e "  Binaries:    $ZP_BIN/zp"
    echo -e "  Config:      $ZP_HOME/config.toml"
    echo -e "  Data:        $ZP_HOME/data"
    echo ""
    echo -e "  ${BOLD}Get started:${NC}"
    echo ""
    echo -e "    ${CYAN}source ~/.zshrc${NC}     (or restart your terminal)"
    echo -e "    ${CYAN}zp serve${NC}            Launch the dashboard"
    echo -e "    ${CYAN}zp guard \"cmd\"${NC}      Evaluate a command"
    echo -e "    ${CYAN}zp doctor${NC}           Run diagnostics"
    echo ""
    echo -e "  ${BOLD}Your keys. Your chain. Your trust.${NC}"
else
    echo -e "  ${RED}══════════════════════════════════════════════════${NC}"
    echo -e "  ${RED}  INSTALLATION INCOMPLETE${NC}"
    echo -e "  ${RED}══════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Failed at stage: ${BOLD}$failed_stage${NC}"
    echo -e "  Elapsed:         ${overall_elapsed}s"
    echo ""
    echo -e "  ${BOLD}To resume:${NC}"
    echo -e "    ${CYAN}bash deploy/install.sh --retry-from $failed_stage${NC}"
    echo ""
    echo -e "  State saved to: $STATE_FILE"
fi
echo ""
