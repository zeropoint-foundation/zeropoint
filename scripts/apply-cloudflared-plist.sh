#!/usr/bin/env bash
# Apply corrected cloudflared launchd plist (#21)
# Fixes tunnel so it survives reboots and session close.
# Run once from APOLLO as kenrom. No sudo needed (LaunchAgent scope).
# See: docs/handoffs/cloudflared-restart-routing-design-2026-05.md

set -euo pipefail

PLIST="$HOME/Library/LaunchAgents/homebrew.mxcl.cloudflared.plist"
CONFIG="$HOME/.cloudflared/config.yml"

# Verify config exists before proceeding
if [[ ! -f "$CONFIG" ]]; then
  echo "ERROR: $CONFIG not found — expected at ~/.cloudflared/config.yml"
  exit 1
fi

echo "==> Writing corrected plist..."
cat > "$PLIST" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>homebrew.mxcl.cloudflared</string>
    <key>ProgramArguments</key>
    <array>
        <string>/opt/homebrew/opt/cloudflared/bin/cloudflared</string>
        <string>tunnel</string>
        <string>--config</string>
        <string>/Users/kenrom/.cloudflared/config.yml</string>
        <string>run</string>
        <string>foundation-apollo</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>ThrottleInterval</key>
    <integer>5</integer>
    <key>LimitLoadToSessionType</key>
    <array>
        <string>Aqua</string>
        <string>Background</string>
        <string>LoginWindow</string>
        <string>StandardIO</string>
        <string>System</string>
    </array>
    <key>StandardOutPath</key>
    <string>/opt/homebrew/var/log/cloudflared.log</string>
    <key>StandardErrorPath</key>
    <string>/opt/homebrew/var/log/cloudflared.log</string>
</dict>
</plist>
PLIST

echo "==> Unloading any existing launchd entry..."
launchctl unload "$PLIST" 2>/dev/null || true

echo "==> Killing manual tunnel processes..."
pkill -f "cloudflared tunnel run foundation-apollo" 2>/dev/null || true
sleep 1

echo "==> Loading corrected plist..."
launchctl load -w "$PLIST"

echo "==> Waiting for tunnel to connect (~3s)..."
sleep 3

echo "==> Verification:"
echo ""
echo "--- pgrep ---"
pgrep -fl cloudflared || echo "(none)"

echo ""
echo "--- launchctl ---"
launchctl list | grep cloudflared || echo "(not in list)"

echo ""
echo "--- tunnel connectors ---"
cloudflared tunnel info foundation-apollo 2>/dev/null | grep -E "ID:|Connector|STATUS" || echo "(cloudflared not in PATH or no connectors yet)"

echo ""
echo "--- site reachable ---"
curl -sI https://app.zeropointfoundation.org | head -1

echo ""
echo "Done. If pgrep shows exactly one cloudflared process with tunnel args, the plist is live."
echo "NOTE: 'brew upgrade cloudflared' may clobber this plist. After any upgrade, re-run this script."
