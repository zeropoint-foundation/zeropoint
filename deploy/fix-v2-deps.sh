#!/bin/bash
# ZeroPoint v2 Dependency Fix
# Run from repo root:  cd /path/to/zeropoint && bash deploy/fix-v2-deps.sh
#
# Migrates zp-receipt and execution-engine into the v2 workspace,
# fixes all Cargo.toml path references, and pushes.

set -e

echo "=== ZeroPoint v2 Dependency Fix ==="
echo ""

# Clean up stale lock if present
if [ -f .git/index.lock ]; then
  echo "Removing stale .git/index.lock..."
  rm -f .git/index.lock
fi

# --- Stage all v2 changes ---
echo "Staging v2 workspace changes..."

# New crates copied into v2
git add v2/crates/zp-receipt/
git add v2/crates/execution-engine/

# Updated Cargo.toml files (path fixes + workspace members)
git add v2/Cargo.toml
git add v2/crates/zp-core/Cargo.toml
git add v2/crates/zp-pipeline/Cargo.toml
git add v2/crates/zp-cli/Cargo.toml
git add v2/crates/zp-mesh/Cargo.toml

# Make sure restored core/ dir is removed from index
git rm -rf core/crates/execution-engine 2>/dev/null || true

echo ""
echo "=== Staged changes ==="
git --no-pager diff --cached --stat
echo ""

# --- Commit ---
git commit -m "$(cat <<'EOF'
fix: migrate zp-receipt and execution-engine into v2 workspace

The legacy purge (a0fcf48) removed core/crates/ which contained
zp-receipt and execution-engine — two crates still referenced by
v2 via path dependencies.

Changes:
- Copy zp-receipt into v2/crates/zp-receipt (standalone, own deps)
- Copy execution-engine into v2/crates/execution-engine (workspace deps)
- Fix all path refs: ../../../core/crates/* → ../*
- Add both to v2 workspace members
- Add tempfile to workspace dependencies

Affected crates: zp-core, zp-pipeline, zp-cli, zp-mesh

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
echo "v2 workspace should now build cleanly in CI."
echo "Visit: https://github.com/zeropoint-foundation/zeropoint/actions"
