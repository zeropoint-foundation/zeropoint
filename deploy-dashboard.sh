#!/bin/bash
# Deploy latest dashboard.html to override dir and rebuild ZP binary
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OVERRIDE_DIR="$HOME/.zeropoint/assets"
SRC="$SCRIPT_DIR/crates/zp-server/assets/dashboard.html"

echo "── Deploying dashboard override ──"
mkdir -p "$OVERRIDE_DIR"
cp "$SRC" "$OVERRIDE_DIR/dashboard.html"
echo "✓ Copied to $OVERRIDE_DIR/dashboard.html"

echo ""
echo "── Rebuilding ZP (release) ──"
cd "$SCRIPT_DIR"
./zp-dev.sh release

echo ""
echo "✓ Done. Restart ZP server to pick up changes."
echo "  Dashboard: build+start resolve steps for Ember"
echo "  Binary: pnpm build-before-start in detect_launch()"
