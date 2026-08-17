#!/usr/bin/env bash
#
# land.sh — commit a set of changes in named, ordered steps, refusing to run
# if anything dirty is unaccounted for.
#
# Usage: bash scripts/land.sh <manifest-dir> [--dry-run]
#
# Replaces the dated one-off land-YYYY-MM-DD.sh scripts. Seven of those
# accumulated between 2026-08-14 and 2026-08-17, each a copy of the same
# logic with different lists baked in. The logic lives here now; the lists
# live in a manifest directory. See scripts/landings/README.md.
#
# # The guard, and why it is the inverse of the obvious one
#
# On 2026-08-16 a commit defined as "everything dirty minus this list" swept
# 357 lines of a scheduled task's output into a commit whose message claimed
# a mechanical formatting sweep. Nothing had lied; the definition was simply
# open at one end.
#
# So the rule is inverted: every dirty path must be claimed by name, either
# for a commit step or as deliberately deferred. An unrecognised path stops
# the run. That guard has since caught a regenerated derived artifact whose
# self-stamp would have been false, someone else's in-flight edit, and a
# landing script's failure to account for itself.
#
# # Why commit messages are files
#
# git commit -F reads them directly, so message prose never passes through
# the shell. The dated scripts captured heredocs into variables, and bash 3.2
# scans for the closing paren of a command substitution *through* the heredoc
# body while tracking quote state — so a single apostrophe in ordinary prose
# ("zp-server's") read as an unterminated string and the parse died at EOF.
# A message in a file cannot do that, whatever it contains.

set -euo pipefail

MANIFEST="${1:-}"
DRY_RUN=0
if [ "${2:-}" = "--dry-run" ] || [ "${1:-}" = "--dry-run" ]; then DRY_RUN=1; fi
if [ "${1:-}" = "--dry-run" ]; then MANIFEST="${2:-}"; fi

if [ -z "$MANIFEST" ]; then
  echo "usage: bash scripts/land.sh <manifest-dir> [--dry-run]"
  echo
  echo "available manifests:"
  for d in scripts/landings/*/; do
    [ -d "$d" ] && echo "    ${d%/}"
  done
  exit 2
fi

cd "$(git rev-parse --show-toplevel)"
MANIFEST="${MANIFEST%/}"

if [ ! -d "$MANIFEST" ]; then
  echo "no such manifest directory: $MANIFEST"
  exit 2
fi

# ── read the manifest ────────────────────────────────────────────────────────
#
# NN-name.files  one path per line, the paths this step commits
# NN-name.msg    the commit message, passed to git commit -F unmodified
# deferred       one path per line, dirty on purpose, committed by nobody

CLAIMED_FILE="$(mktemp)"
trap 'rm -f "$CLAIMED_FILE"' EXIT

STEPS=""
STEP_N=0
for f in "$MANIFEST"/[0-9][0-9]-*.files; do
  [ -e "$f" ] || continue
  msg="${f%.files}.msg"
  if [ ! -f "$msg" ]; then
    echo "manifest error: $f has no matching $(basename "$msg")"
    exit 2
  fi
  STEPS="$STEPS $f"
  STEP_N=$((STEP_N + 1))
  cat "$f" >> "$CLAIMED_FILE"
done

if [ "$STEP_N" -eq 0 ]; then
  echo "manifest error: $MANIFEST contains no NN-name.files steps"
  exit 2
fi

if [ -f "$MANIFEST/deferred" ]; then
  cat "$MANIFEST/deferred" >> "$CLAIMED_FILE"
fi

# Drop blanks and comments from the claimed set.
CLAIMED_CLEAN="$(mktemp)"
trap 'rm -f "$CLAIMED_FILE" "$CLAIMED_CLEAN"' EXIT
grep -v '^[[:space:]]*$' "$CLAIMED_FILE" | grep -v '^[[:space:]]*#' > "$CLAIMED_CLEAN" || true

# ── guard ────────────────────────────────────────────────────────────────────
#
# --untracked-files=all is load-bearing. The default collapses a new untracked
# directory into a single entry — `tools/attribution-probe/` rather than the
# two files inside it — so a manifest naming the files would not match, and a
# manifest naming the directory would stop matching the moment the directory
# gained a tracked file. Neither failure is loud. Expanding first makes the
# comparison exact.

UNCLAIMED_N=0
while IFS= read -r path; do
  [ -z "$path" ] && continue
  if ! grep -qxF "$path" "$CLAIMED_CLEAN"; then
    if [ "$UNCLAIMED_N" -eq 0 ]; then
      echo "REFUSING TO RUN — dirty path(s) claimed by no list:"
    fi
    echo "    $path"
    UNCLAIMED_N=$((UNCLAIMED_N + 1))
  fi
done < <(git status --porcelain --untracked-files=all | sed 's/^...//')

if [ "$UNCLAIMED_N" -ne 0 ]; then
  echo
  echo "Add each to a step's .files or to $MANIFEST/deferred, deliberately."
  echo "Claiming a path is a decision about what a commit means — not a"
  echo "formality to get this script to run."
  exit 1
fi

echo "guard: every dirty path is claimed."
echo

# ── commit ───────────────────────────────────────────────────────────────────

for f in $STEPS; do
  step="$(basename "${f%.files}")"
  msg="${f%.files}.msg"
  subject="$(head -n 1 "$msg")"

  echo "-- $step — $subject"
  while IFS= read -r p; do
    [ -z "$p" ] && continue
    case "$p" in \#*) continue ;; esac
    echo "    $p"
  done < "$f"
  echo

  if [ "$DRY_RUN" -eq 0 ]; then
    # One git add per line rather than --pathspec-from-file: that flag needs
    # git >= 2.25, and staging is not where this script should acquire a
    # version floor.
    while IFS= read -r p; do
      [ -z "$p" ] && continue
      case "$p" in \#*) continue ;; esac
      git add -- "$p"
    done < "$f"
    git commit -q -F "$msg"
    echo "    committed: $(git rev-parse --short HEAD)"
    echo
  fi
done

# ── after ────────────────────────────────────────────────────────────────────

if [ -f "$MANIFEST/deferred" ]; then
  echo "-- left uncommitted, on purpose --"
  while IFS= read -r p; do
    [ -z "$p" ] && continue
    case "$p" in \#*) echo "  ${p}" ; continue ;; esac
    echo "    $p"
  done < "$MANIFEST/deferred"
  echo
fi

if [ -f "$MANIFEST/after" ]; then
  echo "-- next, in this order --"
  sed 's/^/    /' "$MANIFEST/after"
  echo
fi

if [ "$DRY_RUN" -eq 1 ]; then
  echo "(dry run — nothing was staged or committed)"
else
  echo "-- remaining dirty --"
  git status --short
fi
