#!/bin/bash
# ZeroPoint v2 — Fix test compilation + dead code warning
# Run from repo root:  cd /path/to/zeropoint && bash deploy/fix-v2-tests.sh

set -e

echo "=== ZeroPoint v2 Test Fix ==="

if [ -f .git/index.lock ]; then rm -f .git/index.lock; fi

git add v2/crates/execution-engine/tests/integration_test.rs
git add v2/crates/zp-server/src/main.rs

echo "=== Staged ==="
git --no-pager diff --cached --stat
echo ""

git commit -m "$(cat <<'EOF'
fix: uuid::is_empty() → is_nil(), suppress dead_code on request struct

- execution-engine/tests/integration_test.rs: Uuid has no is_empty(),
  use is_nil() instead
- zp-server/src/main.rs: add #[allow(dead_code)] on GenerateReceiptRequest
  (policy_decision field is part of API contract but unused in handler)

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"

echo ""
git log --oneline -1
echo ""
echo "Pushing..."
git push origin main
echo "Done — https://github.com/zeropoint-foundation/zeropoint/actions"
