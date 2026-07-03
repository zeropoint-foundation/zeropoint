#!/usr/bin/env bash
# Vault-aware IronClaw launcher.
#
# Used by launchd plist (org.zeropoint.ironclaw.plist) and as the one
# canonical way to start IronClaw on APOLLO. Never call `ironclaw run`
# directly — vault injection happens here via `zp configure exec`.
#
# Removes a stale PID file if the recorded process is no longer alive,
# so launchd restarts after a crash don't fail with "already running".

set -euo pipefail

IRONCLAW_DIR="$HOME/projects/ironclaw"
IRONCLAW_BIN="$IRONCLAW_DIR/target/release/ironclaw"
IRONCLAW_PID="$HOME/.ironclaw/ironclaw.pid"
ZP_BIN="$HOME/.cargo/bin/zp"

# ── PID file hygiene ──────────────────────────────────────────────────────────
if [[ -f "$IRONCLAW_PID" ]]; then
  pid=$(cat "$IRONCLAW_PID")
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "start-ironclaw: removing stale PID file (pid $pid is gone)"
    rm -f "$IRONCLAW_PID"
  fi
fi

# ── Guard: binary must exist ──────────────────────────────────────────────────
if [[ ! -x "$IRONCLAW_BIN" ]]; then
  echo "start-ironclaw: binary not found at $IRONCLAW_BIN"
  echo "  Run: cd $IRONCLAW_DIR && cargo build --release"
  exit 1
fi

# ── Vault-injected launch (silent config, receipt on chain) ──────────────────
exec "$ZP_BIN" configure exec \
  --path "$IRONCLAW_DIR" \
  --name ironclaw \
  -- "$IRONCLAW_BIN" run
