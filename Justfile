# ZeroPoint fleet build & deploy automation
# Usage: just deploy        — build, install, restart (local node)
#        just deploy-fleet  — deploy to all fleet nodes
#        just build         — build release binary only
#        just restart       — restart the running server
#        just status        — show binary version + server state

set shell := ["bash", "-euo", "pipefail", "-c"]

# ── Configuration ──────────────────────────────────────────
install_path := "/usr/local/bin/zp"
artemis_host := "zp-pentest@ARTEMIS"
playground_host := "root@89.167.86.60"

# ── Local operations ──────────────────────────────────────

# Build release binary
build:
    cargo build --release
    @echo ""
    @echo "✓  Built target/release/zp ($(git rev-parse --short HEAD))"

# Install the built binary to system path
install: build
    sudo cp target/release/zp {{install_path}}
    @echo "✓  Installed to {{install_path}}"

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

# Deploy to ARTEMIS (pull, build, install, restart)
deploy-artemis:
    @echo ""
    @echo "── Deploying to ARTEMIS ──"
    ssh {{artemis_host}} 'cd ~/projects/zeropoint && git pull && cargo build --release && sudo cp target/release/zp /usr/local/bin/zp && (zp restart 2>/dev/null || true)'
    @echo "✓  ARTEMIS deployed"

# Deploy to ZP Playground (pull, build, install, restart)
deploy-playground:
    @echo ""
    @echo "── Deploying to Playground ──"
    ssh {{playground_host}} 'cd /root/zeropoint && git pull && cargo build --release && cp target/release/zp /usr/local/bin/zp && (zp restart 2>/dev/null || true)'
    @echo "✓  Playground deployed"

# ── Fleet verification ────────────────────────────────────

# Verify all fleet nodes
verify-fleet:
    @echo "── APOLLO ──"
    zp verify
    @echo ""
    @echo "── ARTEMIS ──"
    ssh {{artemis_host}} 'zp verify'
    @echo ""
    @echo "── Playground ──"
    ssh {{playground_host}} 'zp verify'

# Check binary versions across fleet
versions:
    @echo "APOLLO:     $(zp --version 2>/dev/null || echo 'not installed')"
    @echo "ARTEMIS:    $(ssh {{artemis_host}} 'zp --version 2>/dev/null || echo "not installed"')"
    @echo "Playground: $(ssh {{playground_host}} 'zp --version 2>/dev/null || echo "not installed"')"
