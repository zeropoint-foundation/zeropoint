#!/bin/sh
#
# .githooks/install.sh
#
# One-time setup per checkout: point git at this directory's hooks.
# Run from anywhere inside the repo:
#
#   ./.githooks/install.sh
#
# After this runs, `git push` invokes `.githooks/pre-push` which
# verifies HEAD builds cleanly via a temp worktree (catches the
# class of bug that broke origin/main in 93b2fe7).
#
# The hooks are tracked in the repo, so updates land via git pull.
# Bypass any hook with `git push --no-verify` (use sparingly).

set -e

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

# Make hook scripts executable. Git on macOS / Linux respects the
# executable bit on the working-tree files; without this, the hook
# wouldn't run.
chmod +x .githooks/pre-push
chmod +x .githooks/install.sh

# Point git at the in-repo hooks directory.
git config core.hooksPath .githooks

echo "Hooks installed. Active hook directory: .githooks/"
echo ""
echo "Verify with:"
echo "  git config --get core.hooksPath  # should print: .githooks"
echo "  ls -l .githooks/                  # pre-push should be executable"
