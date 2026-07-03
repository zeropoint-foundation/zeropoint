#!/usr/bin/env bash
# Install the IronClaw launchd plist (org.zeropoint.ironclaw).
#
# Makes IronClaw start on login and restart on crash, using the
# vault-aware launcher (start-ironclaw.sh) — no direct `ironclaw run`,
# no env files, vault injection always present.
#
# Run once from APOLLO as kenrom. No sudo needed (LaunchAgent scope).
# Re-run after: homebrew upgrades that clobber the plist, or if the
# plist label/paths change.
#
# Prerequisites:
#   - cargo build --release run at least once in ~/projects/ironclaw
#   - zp vault has ironclaw credentials (zp configure tool --path ... --name ironclaw)

set -euo pipefail

PLIST="$HOME/Library/LaunchAgents/org.zeropoint.ironclaw.plist"
LAUNCHER="$HOME/projects/zeropoint/scripts/start-ironclaw.sh"
IRONCLAW_DIR="$HOME/projects/ironclaw"
IRONCLAW_BIN="$IRONCLAW_DIR/target/release/ironclaw"
LOG_DIR="$HOME/Library/Logs/ZeroPoint"

# ── Preflight checks ──────────────────────────────────────────────────────────
if [[ ! -f "$LAUNCHER" ]]; then
  echo "ERROR: launcher not found at $LAUNCHER"
  exit 1
fi

if [[ ! -x "$IRONCLAW_BIN" ]]; then
  echo "ERROR: IronClaw binary not found at $IRONCLAW_BIN"
  echo "  Run: cd $IRONCLAW_DIR && cargo build --release"
  exit 1
fi

chmod +x "$LAUNCHER"
mkdir -p "$LOG_DIR"

echo "==> Writing plist to $PLIST ..."
cat > "$PLIST" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>org.zeropoint.ironclaw</string>

    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>$LAUNCHER</string>
    </array>

    <!-- Working directory must be the ironclaw project root so
         relative paths inside the binary resolve correctly. -->
    <key>WorkingDirectory</key>
    <string>$IRONCLAW_DIR</string>

    <!-- PATH needs cargo bin so `zp` is resolvable inside the launcher. -->
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/Users/kenrom/.cargo/bin</string>
        <key>HOME</key>
        <string>/Users/kenrom</string>
    </dict>

    <!-- Start on login. -->
    <key>RunAtLoad</key>
    <true/>

    <!-- Restart on crash; don't restart if IronClaw exits cleanly (e.g. zp stop). -->
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>

    <!-- Throttle rapid restart loops (e.g. vault misconfiguration). -->
    <key>ThrottleInterval</key>
    <integer>10</integer>

    <key>StandardOutPath</key>
    <string>$LOG_DIR/ironclaw.log</string>
    <key>StandardErrorPath</key>
    <string>$LOG_DIR/ironclaw.log</string>
</dict>
</plist>
PLIST

echo "==> Unloading any existing org.zeropoint.ironclaw entry..."
launchctl unload "$PLIST" 2>/dev/null || true

echo "==> Killing any manually-started IronClaw processes..."
pkill -f "ironclaw run" 2>/dev/null || true
sleep 1

echo "==> Loading plist..."
launchctl load -w "$PLIST"

echo "==> Waiting for IronClaw to start (~5s)..."
sleep 5

echo ""
echo "── Verification ─────────────────────────────────────────────────────────"
echo ""
echo "pgrep:"
pgrep -fl ironclaw || echo "  (none — check $LOG_DIR/ironclaw.log)"

echo ""
echo "launchctl:"
launchctl list | grep ironclaw || echo "  (not in list)"

echo ""
echo "gateway reachable:"
curl -sI http://127.0.0.1:3000/ 2>/dev/null | head -1 || echo "  (not yet up)"

echo ""
echo "Done. IronClaw will now start on login and restart on crash."
echo "Logs: $LOG_DIR/ironclaw.log"
echo "Stop: launchctl unload $PLIST"
echo "Start: launchctl load -w $PLIST"
