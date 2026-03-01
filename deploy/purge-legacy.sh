#!/bin/bash
# ZeroPoint Legacy Purge Script
# Run from repo root:  cd /path/to/zeropoint && bash deploy/purge-legacy.sh
#
# Removes all pre-v2 artifacts, keeping only the public release:
#   v2/, zeropoint.global/, thinkstreamlabs.ai/, deploy/,
#   .github/, community files, README.md, .gitignore

set -e

echo "=== ZeroPoint Legacy Purge ==="
echo ""

# Clean up stale lock if present
if [ -f .git/index.lock ]; then
  echo "Removing stale .git/index.lock..."
  rm -f .git/index.lock
fi

# --- Remove legacy workflows ---
echo "Removing legacy CI workflows..."
git rm -rf .github/workflows/soak-test.yml       2>/dev/null || true
git rm -rf .github/workflows/sign-release.yml     2>/dev/null || true
git rm -rf .github/workflows/anchor-release.yml   2>/dev/null || true
git rm -rf .github/workflows/generate-sbom.yml    2>/dev/null || true
git rm -rf .github/workflows/reproducible-build.yml 2>/dev/null || true
git rm -rf .github/workflows/release.yml          2>/dev/null || true
git rm -f  .github/ISSUE_TEMPLATE/cli_ux_enhancement.md 2>/dev/null || true

# --- Remove legacy directories ---
echo "Removing legacy directories..."
for dir in \
  zeropoint-server \
  core \
  cli \
  server \
  services \
  sidecar \
  docker \
  sandbox \
  scripts \
  schemas \
  spec \
  packs \
  frameworks \
  governance \
  attestations \
  graphiti \
  webui-next \
  graph-viz-wasm \
  wasm-modules \
  reticulum-meshchat \
  miniCPM-o-4_5 \
  docs \
  assets \
  config \
  prompts \
  archive \
  "Trust Layer Foundation" \
  third_party \
  release_pkg \
  sbom \
  build-output \
  data \
  logs \
  models \
  INPUT \
  test-outputs \
  pytest-cache-files-ztsvhyuf \
  hcs-prototype.jsx
do
  if [ -e "$dir" ]; then
    echo "  Removing $dir..."
    git rm -rf "$dir" 2>/dev/null || true
  fi
done

# --- Remove legacy top-level files ---
echo "Removing legacy top-level files..."
for file in \
  Cargo.toml \
  Cargo.lock \
  docker-compose.yml \
  rustfmt.toml \
  .dockerignore \
  .env.example \
  Makefile \
  start-zeropoint.sh \
  rustup-init.sh \
  AGENTS.md \
  ARCHITECTURE-V2.md \
  CHANGELOG.md \
  COMPONENT_TOUR.md \
  DOCUMENTATION_UPDATE_SUMMARY.md \
  HANDOFF-COMPILATION-FIXES.md \
  HANDOFF-OFFICER-CADRE.md \
  IMPLEMENTATION_CHECKLIST.md \
  IMPLEMENTATION_SUMMARY.md \
  INSTALL.md \
  INSTALLATION_README.txt \
  INSTALLER_INDEX.md \
  INSTALLER_SUMMARY.md \
  MANIFESTO.md \
  QA_REPORT.md \
  GENESIS_CEREMONY_ARTIFACT.json \
  GENESIS_MANIFEST.json \
  RECOVERY_MANIFEST.json \
  CONSTITUTIONAL_HASH.txt \
  catalog-latest.json \
  m0_homepage_copy.md \
  1RUST_log-debug \
  DATABASE_ANALYSIS_INDEX.txt \
  DATABASE_ANALYSIS_REPORT.txt \
  DATABASE_QUICK_REFERENCE.txt \
  AboveFoldPreview.jsx \
  SurfaceCatalogPreview.jsx \
  agent-zero-security-scorecard.jsx \
  atlas-surface-map.jsx \
  command-center-preview.jsx \
  command-center-v2.jsx \
  command-center.jsx \
  hcs-prototype.jsx \
  topology-preview.jsx \
  zp-command-center.jsx \
  test-binary-transport.sh \
  test-voice-comms.sh \
  test_abacus_models.sh \
  test_receipt_gated_execution.sh
do
  if [ -e "$file" ]; then
    echo "  Removing $file..."
    git rm -f "$file" 2>/dev/null || true
  fi
done

# --- Remove legacy hidden directories ---
echo "Removing legacy hidden state..."
for dir in .claude .cargo .pids .pytest_cache .ui-serve .zeropoint .zp-bare-process; do
  if [ -e "$dir" ]; then
    echo "  Removing $dir..."
    git rm -rf "$dir" 2>/dev/null || true
  fi
done

# --- Stage the updated files ---
echo ""
echo "Staging updated files..."
git add .github/workflows/ci.yml
git add README.md
git add .gitignore

echo ""
echo "=== Staged changes ==="
git --no-pager diff --cached --stat
echo ""

# --- Commit ---
git commit -m "$(cat <<'EOF'
chore: purge legacy codebase, keep only v2 public release

Remove all pre-v2 artifacts including:
- zeropoint-server (genesis), core/, cli/, server/, services/
- Legacy CI workflows (soak-test, sign-release, etc.)
- Old docs, previews, sandbox, scripts
- Root Cargo.toml workspace manifest

What remains:
- v2/ — 11-crate Rust workspace (623 tests)
- zeropoint.global/ — project site + interactive demos
- thinkstreamlabs.ai/ — company site
- deploy/ — Dockerfile, Caddyfile, deployment guide
- .github/ — v2-only CI workflow + issue templates
- Community files (CONTRIBUTING, CODE_OF_CONDUCT, SECURITY)

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"

echo ""
echo "=== Commit created ==="
git log --oneline -1
echo ""

# --- Push ---
echo "Pushing to origin/main..."
git push origin main

echo ""
echo "=== Done ==="
echo "The soak test workflow has been removed. Only the v2 CI will run now."
echo "Visit: https://github.com/zeropoint-foundation/zeropoint"
