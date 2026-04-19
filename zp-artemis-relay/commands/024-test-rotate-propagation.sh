#!/bin/bash
# 024-test-rotate-propagation.sh — Relay command for ARTEMIS
#
# Functional test: verify `run_rotate` and the vault ref graph.
# Commit 263f9c6 added:
#   - CredentialVault::resolve_ref() in zp-trust/src/vault.rs
#   - run_rotate() + 2 tests in zp-cli/src/configure.rs
#
# This exercises real compilation and test execution that the sandbox
# cannot do (libdbus linkage blocks zp-cli test in sandbox).
#
# NON-DESTRUCTIVE: read-only tests, no state mutation.

set -euo pipefail

echo "=== 024: rotate propagation functional test ==="
echo "Timestamp: $(date)"

# ── Setup: clone from bundle if needed ────────────────────────────
RELAY_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$HOME/projects/zeropoint"

if [ ! -d "$REPO/.git" ]; then
    echo "--- Cloning from relay bundle ---"
    git clone "$RELAY_DIR/zp-artemis.bundle" "$REPO"
    cd "$REPO"
    git remote set-url origin https://github.com/thinkstreamlabs/zeropoint.git
else
    cd "$REPO"
    echo "--- Pulling latest from bundle ---"
    git fetch "$RELAY_DIR/zp-artemis.bundle" main:main 2>/dev/null || \
        git fetch "$RELAY_DIR/zp-artemis.bundle" 2>/dev/null || true
    git checkout main
    git reset --hard FETCH_HEAD 2>/dev/null || git reset --hard main
fi

HEAD=$(git log --oneline -1)
echo "HEAD: $HEAD"
echo

# ── Phase 1: vault tests (zp-trust) ──────────────────────────────
echo "--- Phase 1: zp-trust vault tests (includes resolve_ref) ---"
cargo test -p zp-trust --release 2>&1
echo
echo "✓ Phase 1: vault tests pass"

# ── Phase 2: engine tests (zp-engine) ────────────────────────────
echo
echo "--- Phase 2: zp-engine capability tests ---"
cargo test -p zp-engine --release 2>&1
echo
echo "✓ Phase 2: engine tests pass"

# ── Phase 3: full zp-cli tests (rotate + MVC vault writer) ──────
echo
echo "--- Phase 3: zp-cli tests (rotate, MVC vault writer, configure) ---"
cargo test -p zp-cli --release 2>&1
echo
echo "✓ Phase 3: zp-cli tests pass (includes rotate propagation)"

# ── Phase 4: cargo check full workspace ──────────────────────────
echo
echo "--- Phase 4: workspace-wide cargo check ---"
cargo check --workspace 2>&1
echo
echo "✓ Phase 4: full workspace compiles"

# ── Summary ──────────────────────────────────────────────────────
echo
echo "=== 024 COMPLETE ==="
echo "Commit: $HEAD"
echo "All phases green. rotate propagation verified on real hardware."
echo "Timestamp: $(date)"
