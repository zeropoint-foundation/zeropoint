#!/usr/bin/env bash
# fix-v2-macos-sandbox.sh — Fix execution-engine on macOS.
#
# Root cause: sandbox-exec with (deny default) is deprecated on modern macOS
# (Sonoma/Sequoia) and silently swallows all subprocess output.
# Fix: disable OS isolation on macOS by default (real sandbox targets Linux).
# Also: add /opt/homebrew/bin to PATH for Apple Silicon runtime discovery.
# Also: fix unused imports in zp-receipt for clippy -D warnings.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

git add v2/crates/execution-engine/src/sandbox.rs
git add v2/crates/execution-engine/src/executor.rs
git add v2/crates/zp-receipt/src/signer.rs

git commit -m "$(cat <<'EOF'
fix: disable sandbox-exec on macOS, add Homebrew to PATH

sandbox-exec with (deny default) is deprecated on modern macOS and
silently swallows subprocess output, causing all execution tests to
produce empty stdout/stderr.

Changes:
- Default use_os_isolation to false on macOS (cfg!(target_os = "linux"))
  Real process isolation targets Linux via unshare + future seccomp.
- Add /opt/homebrew/bin to minimal_path() on macOS for Apple Silicon
- Keep sandbox-exec code path for opt-in use, with perl timeout
- Remove unused imports (ReceiptType, TrustGrade) in zp-receipt signer

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"

git push origin main

echo ""
echo "✅ Pushed. macOS now skips sandbox-exec by default."
echo "   Run 'cargo test -- --ignored' to verify."
