#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────
# deploy.sh — Deploy ZeroPoint NomadNet node to Hetzner
#
# Run from ~/projects/zeropoint/nomadnet-pages/
# Usage: ./deploy.sh
# ─────────────────────────────────────────────────────────
set -euo pipefail

# Configure these for your deployment target
REMOTE="${ZP_NOMADNET_HOST:-root@your-server-ip}"
SSH_KEY="${ZP_NOMADNET_KEY:-$HOME/.ssh/your-key}"
SSH="ssh -i $SSH_KEY $REMOTE"
SCP="scp -i $SSH_KEY"

echo "═══════════════════════════════════════════════"
echo "  ZeroPoint NomadNet Node — Hetzner Deploy"
echo "═══════════════════════════════════════════════"
echo ""

# ── Step 1: Install RNS + NomadNet ──────────────────────
echo "▸ [1/6] Installing Reticulum + NomadNet..."
$SSH "pip3 install --break-system-packages rns nomadnet 2>/dev/null || pip3 install rns nomadnet"
echo "  ✓ Packages installed"

# ── Step 2: Initialize (creates dirs + identity) ────────
echo "▸ [2/6] Initializing NomadNet (first run)..."
$SSH "timeout 5 nomadnet --daemon 2>/dev/null || true"
sleep 2
$SSH "mkdir -p ~/.nomadnetwork/storage/pages ~/.reticulum"
echo "  ✓ Directories ready"

# ── Step 3: Deploy configs ──────────────────────────────
echo "▸ [3/6] Deploying configurations..."
$SCP server-config/reticulum.conf $REMOTE:~/.reticulum/config
$SCP server-config/nomadnet.conf $REMOTE:~/.nomadnetwork/config
echo "  ✓ Configs deployed"

# ── Step 4: Deploy pages ────────────────────────────────
echo "▸ [4/6] Deploying ZeroPoint pages..."
$SCP pages/*.mu $REMOTE:~/.nomadnetwork/storage/pages/
echo "  ✓ Pages deployed"

# ── Step 5: Install systemd service ─────────────────────
echo "▸ [5/6] Installing systemd service..."
$SCP server-config/nomadnet.service $REMOTE:/etc/systemd/system/nomadnet.service
$SSH "systemctl daemon-reload && systemctl enable nomadnet && systemctl restart nomadnet"
echo "  ✓ Service installed and started"

# ── Step 6: Verify ──────────────────────────────────────
echo "▸ [6/6] Verifying..."
sleep 3
$SSH "systemctl is-active nomadnet && echo '  ✓ NomadNet is running' || echo '  ✗ NomadNet failed to start'"
$SSH "ls ~/.nomadnetwork/storage/pages/"
echo ""

# ── Show node identity ──────────────────────────────────
echo "═══════════════════════════════════════════════"
echo "  Node deployed. Getting identity..."
echo "═══════════════════════════════════════════════"
$SSH "rnstatus 2>/dev/null | head -20 || echo 'Run: ssh -i \$SSH_KEY \$REMOTE rnstatus'"
echo ""
echo "To check logs:  ssh -i \$SSH_KEY \$REMOTE journalctl -u nomadnet -f"
echo "To browse node: Open NomadNet locally and navigate to your destination hash"
echo ""
