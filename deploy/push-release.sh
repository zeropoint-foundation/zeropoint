#!/bin/bash
# ZeroPoint Public Release MVP — Git Push Script
# Run this from the root of your zeropoint repo:
#   cd /path/to/zeropoint && bash deploy/push-release.sh
#
# This stages all public release artifacts and pushes to origin/main.

set -e

echo "=== ZeroPoint Public Release MVP ==="
echo ""

# Clean up stale lock if present
if [ -f .git/index.lock ]; then
  echo "Removing stale .git/index.lock..."
  rm -f .git/index.lock
fi

# --- Stage public release artifacts ---

echo "Staging v2 crates, server, docs..."
git add v2/

echo "Staging zeropoint.global site..."
git add zeropoint.global/

echo "Staging thinkstreamlabs.ai site..."
git add thinkstreamlabs.ai/

echo "Staging deployment configs..."
git add deploy/

echo "Staging community infrastructure..."
git add CONTRIBUTING.md
git add CODE_OF_CONDUCT.md
git add SECURITY.md
git add .github/ISSUE_TEMPLATE/bug_report.md
git add .github/ISSUE_TEMPLATE/feature_request.md
git add .github/workflows/ci.yml

echo ""
echo "=== Staged files ==="
git --no-pager diff --cached --stat
echo ""

# --- Commit ---

git commit -m "$(cat <<'EOF'
feat: ZeroPoint v2 public release MVP

Whitepaper narrative overhaul:
- New §0.5 "Why This Exists — The Portable Trust Thesis"
- Revised abstract, problem statement, and conclusion
- Portable trust framing throughout (MD + HTML synchronized)

Interactive demos (connect to live zp-server backend):
- Governance Playground (playground.html) — Guard + Policy evaluation
- Receipt Chain Visualizer (demo-chain.html) — hash chain + tamper detection

zp-server expansion (13 API endpoints):
- Guard evaluation, capability grants, delegation chains
- Audit trail with chain verification
- Receipt generation, server identity, policy rules

Site overhauls:
- zeropoint.global: new hero, demo nav, Getting Started section
- thinkstreamlabs.ai: portable trust framing + new About page

Community infrastructure:
- CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md
- GitHub issue templates (bug + feature)
- CI workflow (build, test, clippy, fmt)

Deployment:
- Dockerfile (multi-stage, cached deps, non-root)
- Caddyfile (both sites + API proxy, auto-HTTPS)
- Deployment guide (Cloudflare Pages + Hetzner VPS)

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
echo "Visit: https://github.com/zeropoint-foundation/zeropoint"
