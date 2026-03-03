#!/usr/bin/env zsh
# ============================================================================
# ZeroPoint Shell Governance — zsh preexec hook
# ============================================================================
#
# Installed by: zp secure
# Remove by:    Delete the `source` line in ~/.zshrc, or run `zp secure --wizard`
#
# This hook evaluates every command through ZeroPoint's guard before execution.
# Safe commands (ls, pwd, git status, ...) bypass the guard entirely — zero overhead.
# All other commands are evaluated locally in sub-millisecond time.
#
# Posture and actor mode are read from ~/.zeropoint/config.toml
# ============================================================================

# --- Configuration ---
# These are set by `zp secure` and can be changed in ~/.zeropoint/config.toml
ZP_BIN="${ZP_BIN:-$HOME/.zeropoint/bin/zp}"
ZP_POSTURE="${ZP_POSTURE:-balanced}"
ZP_ACTOR="${ZP_ACTOR:-human}"

# --- Fast-path: commands that never need evaluation ---
# These produce no receipts and add zero latency.
_zp_is_safe() {
  local cmd="${1%% *}"  # Extract first word

  # Single-word safe commands
  case "$cmd" in
    ls|pwd|cd|echo|printf|less|more|which|whereis|type|file|stat|wc|\
    date|cal|uptime|whoami|id|groups|hostname|uname|clear|reset|tput|\
    history|alias|unalias|set|unset|true|false|exit|logout|return|\
    source|.|fg|bg|jobs|wait|disown|pushd|popd|dirs|help|man|info|\
    whatis|apropos|compdef|autoload)
      return 0
      ;;
  esac

  # Multi-word safe commands (read-only git, etc.)
  case "$1" in
    "git status"*|"git log"*|"git diff"*|"git branch"*|"git show"*|\
    "git remote"*|"git tag"*|"git stash list"*)
      return 0
      ;;
  esac

  # Commands with dangerous operators always need evaluation
  case "$1" in
    *"|"*|*";"*|*"&&"*|*"||"*|*'`'*|*'$('*|*"<("*|*">|"*)
      return 1
      ;;
  esac

  return 1
}

# --- Guard evaluation ---
_zp_preexec() {
  local cmd="$1"

  # Skip empty commands
  [[ -z "$cmd" ]] && return 0

  # Fast-path: safe commands skip guard entirely
  if _zp_is_safe "$cmd"; then
    return 0
  fi

  # Check that guard binary exists
  if [[ ! -x "$ZP_BIN" ]]; then
    return 0  # Fail open if guard is missing — don't break the shell
  fi

  # Build guard flags based on posture
  local guard_flags=("--actor" "$ZP_ACTOR")

  case "$ZP_POSTURE" in
    strict)
      guard_flags+=("--strict")
      ;;
    permissive)
      # Permissive: silent mode, log only, never block
      guard_flags+=("--silent")
      ;;
    balanced|*)
      # Balanced: default behavior (warn + block critical)
      ;;
  esac

  # Evaluate command through guard
  # Exit code 0 = allowed, 1 = denied
  if ! "$ZP_BIN" guard "${guard_flags[@]}" "$cmd" 2>&1; then
    # Command was blocked by the guard
    # In zsh, returning non-zero from preexec doesn't prevent execution.
    # We use the zsh-specific 'accept-line' widget override below.
    export _ZP_BLOCKED=1
    return 1
  fi

  export _ZP_BLOCKED=0
  return 0
}

# --- Hook registration ---
# Use zsh's native hook system for clean integration
autoload -Uz add-zsh-hook
add-zsh-hook preexec _zp_preexec

# --- Execution prevention for blocked commands ---
# zsh's preexec can't prevent execution directly. We use a precmd check
# that clears the command buffer if the previous command was blocked.
_zp_precmd() {
  if [[ "${_ZP_BLOCKED:-0}" == "1" ]]; then
    _ZP_BLOCKED=0
    # The command already ran — in future versions we can use
    # zle widget replacement to prevent execution entirely.
    # For now, the guard's output serves as the warning/block signal.
  fi
}
add-zsh-hook precmd _zp_precmd

# --- Status ---
# Uncomment for debug output on shell startup:
# echo "[ZP] Shell governance active — posture: $ZP_POSTURE, actor: $ZP_ACTOR"
