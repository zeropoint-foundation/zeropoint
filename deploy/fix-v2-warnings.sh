#!/bin/bash
# ZeroPoint v2 — Fix compilation errors and warnings
# Run from repo root:  cd /path/to/zeropoint && bash deploy/fix-v2-warnings.sh

set -e

echo "=== ZeroPoint v2 Warning Fix ==="
echo ""

# Clean up stale lock if present
if [ -f .git/index.lock ]; then
  rm -f .git/index.lock
fi

# Stage fixed files
git add v2/crates/zp-server/src/main.rs
git add v2/crates/execution-engine/src/sandbox.rs
git add v2/crates/execution-engine/src/engine.rs

echo "=== Staged changes ==="
git --no-pager diff --cached --stat
echo ""

git commit -m "$(cat <<'EOF'
fix: resolve compilation errors and warnings in v2 workspace

zp-server/src/main.rs:
- Fix GrantedCapability::Execute field name (scope → languages)
- Replace nonexistent Admin variant with ApiCall/ConfigChange
- Add wildcard arm for remaining capability variants
- Remove unused imports: IntoResponse, ChainBuilder, AuditAction

execution-engine/src/sandbox.rs:
- Prefix unused sandbox_dir parameter with underscore

execution-engine/src/engine.rs:
- Remove unnecessary #[allow(dead_code)] on RuntimeInfo.version

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"

echo ""
echo "=== Commit created ==="
git log --oneline -1
echo ""

echo "Pushing to origin/main..."
git push origin main

echo ""
echo "=== Done ==="
echo "Visit: https://github.com/zeropoint-foundation/zeropoint/actions"
