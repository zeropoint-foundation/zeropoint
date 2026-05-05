# ZeroPoint fleet build & deploy automation
# Usage: just deploy        — build, install, restart (local node)
#        just deploy-fleet  — deploy to all fleet nodes
#        just build         — build release binary only
#        just restart       — restart the running server
#        just status        — show binary version + server state

set shell := ["bash", "-euo", "pipefail", "-c"]

# ── Configuration ──────────────────────────────────────────
# IMPORTANT: Copy Justfile.local.example → Justfile.local and fill in real values.
# These are placeholder defaults — override them in your local env or Justfile.local.
install_path := "/usr/local/bin/zp"
artemis_host := env_var_or_default("ZP_ARTEMIS_HOST", "user@artemis-host")
artemis_ssh := env_var_or_default("ZP_ARTEMIS_SSH", "ssh")
artemis_scp := env_var_or_default("ZP_ARTEMIS_SCP", "scp")
playground_host := env_var_or_default("ZP_PLAYGROUND_HOST", "user@playground-host")
playground_ssh := env_var_or_default("ZP_PLAYGROUND_SSH", "ssh")
playground_scp := env_var_or_default("ZP_PLAYGROUND_SCP", "scp")

# ── Local operations ──────────────────────────────────────

# Build release binary
build:
    cargo build --release
    @echo ""
    @echo "✓  Built target/release/zp ($(git rev-parse --short HEAD))"

# Install the built binary to system path (symlink to avoid macOS codesign issues)
install: build
    sudo rm -f {{install_path}}
    sudo ln -sf $(pwd)/target/release/zp {{install_path}}
    @echo "✓  Installed to {{install_path}} (symlink)"

# Build, install, and restart the server — the one command you need
deploy: install
    @echo ""
    zp restart 2>/dev/null || echo "⚠  No server was running — start with: zp serve"
    @echo ""
    @echo "✓  Deployed $(zp --version)"

# Restart the running server (uses the installed binary)
restart:
    zp restart

# Show binary version and server state
status:
    @echo "Binary: $(zp --version 2>/dev/null || echo 'not installed')"
    @echo "Repo:   $(git rev-parse --short HEAD)"
    @echo ""
    @lsof -i :17770 2>/dev/null | head -3 || echo "No server running on :17770"

# ── Fleet operations ──────────────────────────────────────

# Deploy to all fleet nodes (APOLLO → ARTEMIS → Playground)
deploy-fleet: deploy deploy-artemis deploy-playground
    @echo ""
    @echo "✓  Fleet deployment complete"

# Deploy to ARTEMIS (config, pull, build, install, restart)
deploy-artemis:
    @echo ""
    @echo "── Deploying to ARTEMIS ──"
    @echo "  → Pushing node config..."
    {{artemis_ssh}} {{artemis_host}} 'mkdir -p ~/ZeroPoint'
    {{artemis_scp}} fleet/artemis-config.toml {{artemis_host}}:~/ZeroPoint/config.toml
    @echo "  → Building and installing..."
    {{artemis_ssh}} {{artemis_host}} 'cd ~/projects/zeropoint && git pull && cargo build --release && sudo cp target/release/zp /usr/local/bin/zp && (zp restart 2>/dev/null || true)'
    @echo "✓  ARTEMIS deployed"

# Deploy to ZP Playground (config, pull, build, install, restart)
deploy-playground:
    @echo ""
    @echo "── Deploying to Playground ──"
    @echo "  → Pushing node config..."
    {{playground_ssh}} {{playground_host}} 'mkdir -p ~/ZeroPoint'
    {{playground_scp}} fleet/playground-config.toml {{playground_host}}:~/ZeroPoint/config.toml
    @echo "  → Building and installing..."
    {{playground_ssh}} {{playground_host}} 'source ~/.cargo/env && cd /root/zeropoint && git pull && cargo build --release && cp target/release/zp /usr/local/bin/zp && (zp restart 2>/dev/null || true)'
    @echo "✓  Playground deployed"

# ── Fleet verification ────────────────────────────────────

# Verify all fleet nodes
verify-fleet:
    @echo "── APOLLO ──"
    zp verify
    @echo ""
    @echo "── ARTEMIS ──"
    {{artemis_ssh}} {{artemis_host}} 'zp verify'
    @echo ""
    @echo "── Playground ──"
    {{playground_ssh}} {{playground_host}} 'zp verify'

# Health check all fleet nodes (T1–T4 wiring)
doctor-fleet:
    @echo "── APOLLO ──"
    zp doctor
    @echo ""
    @echo "── ARTEMIS ──"
    {{artemis_ssh}} {{artemis_host}} 'zp doctor'
    @echo ""
    @echo "── Playground ──"
    {{playground_ssh}} {{playground_host}} 'zp doctor'

# Check binary versions across fleet
versions:
    @echo "APOLLO:     $(zp --version 2>/dev/null || echo 'not installed')"
    @echo "ARTEMIS:    $({{artemis_ssh}} {{artemis_host}} 'zp --version 2>/dev/null || echo "not installed"')"
    @echo "Playground: $({{playground_ssh}} {{playground_host}} 'zp --version 2>/dev/null || echo "not installed"')"

# ── T6: Fleet architecture deployment ─────────────────────
# After deploying binaries (just deploy-fleet), run these to
# establish the T1–T4 architectural state on each node.
#
# Order matters:
#   1. deploy-fleet          — push code + configs to all nodes
#   2. t6-verify-genesis     — confirm APOLLO chain is healthy
#   3. t6-verify-delegates   — confirm delegates see upstream
#   4. doctor-fleet          — full health check across fleet

# Verify APOLLO genesis chain is intact after deploy
t6-verify-genesis:
    @echo "── T6: Verifying APOLLO genesis state ──"
    zp verify
    zp doctor
    @echo ""
    @echo "✓  APOLLO genesis state verified"

# Verify delegates can reach and verify against upstream
t6-verify-delegates:
    @echo "── T6: Verifying ARTEMIS delegate state ──"
    {{artemis_ssh}} {{artemis_host}} 'zp doctor'
    @echo ""
    @echo "── T6: Verifying Playground delegate state ──"
    {{playground_ssh}} {{playground_host}} 'zp doctor'
    @echo ""
    @echo "✓  Delegate state verified"

# Full T6 deployment: binaries + configs + verification
t6-deploy: deploy-fleet t6-verify-genesis t6-verify-delegates
    @echo ""
    @echo "════════════════════════════════════════"
    @echo "  T6: Fleet architecture deployment"
    @echo "  ✓  Binaries deployed to all nodes"
    @echo "  ✓  Genesis state verified"
    @echo "  ✓  Delegate state verified"
    @echo "  "
    @echo "  T1: Chain-derived roles      ✓"
    @echo "  T2: Role transition receipts  ✓"
    @echo "  T3: Upstream binding checks   ✓"
    @echo "  T4: Fleet membership status   ✓"
    @echo "  T7: External anchor check     ✓"
    @echo "════════════════════════════════════════"
