#!/usr/bin/env bash
# Install IronClaw Foundation Agent as a macOS Login Item.
#
# Creates a minimal .app bundle in ~/Applications/ and registers it
# so the Foundation workspace agent starts automatically on login,
# with full keychain/vault access (GUI session context).
#
# Run once from APOLLO as kenrom. Safe to re-run.

set -euo pipefail

APP_NAME="IronClaw Foundation Agent"
SRC="$HOME/projects/zeropoint/scripts/${APP_NAME}.app"
DEST="$HOME/Applications/${APP_NAME}.app"
EXECUTABLE="$DEST/Contents/MacOS/${APP_NAME}"

# ── Copy app bundle to ~/Applications ────────────────────────────────────────
echo "==> Installing ${APP_NAME}.app to ~/Applications/ ..."
mkdir -p "$HOME/Applications"
cp -R "$SRC" "$DEST"
chmod +x "$EXECUTABLE"
echo "    ✓ $DEST"

# ── Register as Login Item ────────────────────────────────────────────────────
echo "==> Registering Login Item ..."
osascript << OSASCRIPT
tell application "System Events"
    -- Remove any existing entry to avoid duplicates
    set existing_items to every login item whose path is "$DEST"
    repeat with li in existing_items
        delete li
    end repeat
    -- Add fresh entry (hidden = runs silently, no UI flash)
    make login item at end with properties {path:"$DEST", hidden:true}
end tell
OSASCRIPT
echo "    ✓ Login Item registered"

echo ""
echo "Done. ${APP_NAME} will start automatically on next login."
echo ""
echo "To verify: System Settings → General → Login Items"
echo "To start now without rebooting, run:"
echo "  open '$DEST'"
echo ""
echo "To remove: System Settings → General → Login Items → remove '${APP_NAME}'"
echo "  or: osascript -e 'tell application \"System Events\" to delete (every login item whose name is \"${APP_NAME}\")'"
