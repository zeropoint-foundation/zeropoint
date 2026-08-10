#!/usr/bin/env bash
#
# migrate-envs-to-vault.sh — move project .env secrets into the ZP vault.
#
# ── Why this exists ───────────────────────────────────────────────────────
#
# A vault migration ran in April 2026: each governed tool's `.env` was renamed
# to `.env.pre-vault` and its contents stored in the credential vault. The
# `.env.zp` files written afterwards carry only ZP's own injected bookkeeping
# (PORT, GATEWAY_AUTH_TOKEN, ZP_MANAGED).
#
# On 2026-08-06 `~/ZeroPoint/vault.json` was found not to exist. The vault had
# been lost, the `.pre-vault` backups were still on disk in plaintext, and the
# substrate's declared discipline — "secrets only via ZP vault, never bypassed"
# — was not in effect for roughly two dozen live credentials including a
# Hedera operator key and eight LLM provider keys.
#
# This restores them. It is idempotent: re-running overwrites the same keys
# with the same values.
#
# ── Discipline ────────────────────────────────────────────────────────────
#
# * Values are never printed, never logged, never passed as arguments. Each is
#   piped to `zp vault put` on stdin, so it stays out of shell history and the
#   process table.
# * Dry-run by default. `--apply` is required to write anything.
# * Nothing is deleted. The `.pre-vault` files remain until you remove them
#   yourself, after verifying the governed launch works. A vault copy alongside
#   a live original is worse than either alone — but deleting before verifying
#   is worse still.
#
# ── Usage ─────────────────────────────────────────────────────────────────
#
#   tools/migrate-envs-to-vault.sh              # show what would move
#   tools/migrate-envs-to-vault.sh --apply      # actually store
#   tools/migrate-envs-to-vault.sh --apply ember ironclaw   # subset
#
# Requires the ZP server running (the verbs proxy to it for the vault key).

set -euo pipefail

# Written for bash 3.2 — the version macOS ships as /bin/bash. No `mapfile`,
# no associative arrays, no `${var,,}`. A newer bash from Homebrew works too,
# but the script must not require one: the whole point is that an operator can
# run it on the machine holding the secrets without installing anything first.
PROJECTS_DIR="${ZP_PROJECTS_DIR:-$HOME/projects}"
APPLY=0
ONLY=""

for arg in "$@"; do
  case "$arg" in
    --apply) APPLY=1 ;;
    -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
    -*) echo "unknown flag: $arg" >&2; exit 2 ;;
    *) ONLY="$ONLY $arg" ;;
  esac
done

# Variables ZP injects itself. Storing them would let a stale vault copy
# override what the runtime computes — ports and gateway tokens are allocated
# per launch, not configured.
ZP_MANAGED_VARS="PORT|HTTP_PORT|GATEWAY_PORT|GATEWAY_AUTH_TOKEN|ZP_MANAGED"

wanted() {
  [ -z "$ONLY" ] && return 0
  case " $ONLY " in *" $1 "*) return 0 ;; esac
  return 1
}

total_keys=0
total_tools=0

for src in "$PROJECTS_DIR"/*/.env.pre-vault; do
  [ -f "$src" ] || continue
  tool="$(basename "$(dirname "$src")")"
  wanted "$tool" || continue

  # Key names only. Newline-separated string rather than an array, so this
  # runs under bash 3.2.
  keys="$(
    grep -oE '^[[:space:]]*(export[[:space:]]+)?[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=' "$src" \
      | sed -E 's/^[[:space:]]*(export[[:space:]]+)?//; s/[[:space:]]*=$//' \
      | grep -vE "^($ZP_MANAGED_VARS)$" \
      | sort -u
  )"
  [ -z "$keys" ] && continue

  total_tools=$((total_tools + 1))
  echo
  echo "── $tool  ($src)"

  # Piping into `while` would put the loop in a subshell and lose the
  # counters, so read from a here-string instead.
  while IFS= read -r key; do
    [ -n "$key" ] || continue
    # Last assignment wins, matching dotenv semantics. Strips surrounding
    # quotes and a trailing CR; leaves interior content untouched.
    value="$(
      grep -E "^[[:space:]]*(export[[:space:]]+)?${key}[[:space:]]*=" "$src" \
        | tail -n1 \
        | sed -E "s/^[[:space:]]*(export[[:space:]]+)?${key}[[:space:]]*=//" \
        | sed -E 's/\r$//; s/^"(.*)"$/\1/; s/^'"'"'(.*)'"'"'$/\1/'
    )"

    if [ -z "$value" ]; then
      printf '   %-34s %s\n' "$key" "(empty — skipped)"
      continue
    fi

    vault_path="tools/${tool}/${key}"
    total_keys=$((total_keys + 1))

    if [ "$APPLY" -eq 1 ]; then
      # Value goes only through this pipe. Never an argument, never echoed.
      if printf %s "$value" | zp vault put "$vault_path" >/dev/null 2>&1; then
        printf '   %-34s → %s\n' "$key" "$vault_path"
      else
        printf '   %-34s \033[31mFAILED\033[0m → %s\n' "$key" "$vault_path"
      fi
    else
      printf '   %-34s → %s  (%d bytes)\n' "$key" "$vault_path" "${#value}"
    fi
  done <<EOF
$keys
EOF
done

echo
if [ "$APPLY" -eq 1 ]; then
  echo "Stored $total_keys secrets across $total_tools tools."
  echo
  echo "Next:"
  echo "  zp vault list                     # confirm the key names"
  echo "  zp configure tool --name <tool> --path <dir>"
  echo "  zp configure exec --name <tool> -- <command>"
  echo
  echo "Only after a governed launch works for a tool should its"
  echo ".env.pre-vault be removed. Until then the vault holds a copy,"
  echo "not the original."
else
  echo "Dry run — $total_keys secrets across $total_tools tools would be stored."
  echo "Re-run with --apply to write them."
fi
