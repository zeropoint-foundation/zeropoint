#!/bin/sh
#
# .githooks/install.sh
#
# One-time setup per checkout: point git at this directory's hooks.
# Run from anywhere inside the repo:
#
#   ./.githooks/install.sh
#
# After this runs:
#   `git commit` invokes `.githooks/pre-commit` — the discipline pins.
#   `git push`   invokes `.githooks/pre-push`   — HEAD builds cleanly in a
#                temp worktree (catches the class of bug that broke
#                origin/main in 93b2fe7).
#
# Under a local-first posture `pre-push` never fires, so `pre-commit` is the
# only automatic reader the pins have. See SEAM-010.
#
# The hooks are tracked in the repo, so updates land via git pull.
# Bypass any hook with `git push --no-verify` (use sparingly).

set -e

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

# Make hook scripts executable. Git on macOS / Linux respects the
# executable bit on the working-tree files; without this, the hook
# wouldn't run.
chmod +x .githooks/pre-commit
chmod +x .githooks/pre-push
chmod +x .githooks/install.sh

# Point git at the in-repo hooks directory.
git config core.hooksPath .githooks

echo "Hooks installed. Active hook directory: .githooks/"
echo ""
echo "Verify with:"
echo "  git config --get core.hooksPath  # should print: .githooks"
echo "  ls -l .githooks/                  # pre-commit and pre-push executable"
