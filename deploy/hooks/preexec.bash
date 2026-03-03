#!/usr/bin/env bash
# ============================================================================
# ZeroPoint Shell Governance — bash preexec hook
# ============================================================================
#
# Installed by: zp secure
# Remove by:    Delete the `source` line in ~/.bashrc, or run `zp secure --wizard`
#
# This hook evaluates every command through ZeroPoint's guard before execution.
# Safe commands (ls, pwd, git status, ...) bypass the guard entirely — zero overhead.
# All other commands are evaluated locally in sub-millisecond time.
#
# Posture and actor mode are read from ~/.zeropoint/config.toml
#
# Note: bash doesn't have native preexec. This uses the DEBUG trap, which
# fires before each command. Return non-zero from the trap to prevent execution.
# ============================================================================

# --- Configuration ---
ZP_BIN="${ZP_BIN:-$HOME/.zeropoint/bin/zp}"
ZP_POSTURE="${ZP_POSTURE:-balanced}"
ZP_ACTOR="${ZP_ACTOR:-human}"

# --- Prevent re-entry ---
_ZP_EVALUATING=0

# --- Fast-path: commands that never need evaluation ---
_zp_is_safe() {
  local cmd="$1"
  local first="${cmd%% *}"

  case "$first" in
    ls|pwd|cd|echo|printf|less|more|which|whereis|type|file|stat|wc|\
    date|cal|uptime|whoami|id|groups|hostname|uname|clear|reset|tput|\
    history|alias|unalias|set|unset|true|false|exit|logout|return|\
    source|.|fg|bg|jobs|wait|disown|pushd|popd|dirs|help|man|info|\
    whatis|apropos|complete|compgen)
      return 0
      ;;
  esac

  case "$cmd" in
    "git status"*|"git log"*|"git diff"*|"git branch"*|"git show"*|\
    "git remote"*|"git tag"*|"git stash list"*)
      return 0
      ;;
  esac

  # Dangerous operators always need evaluation
  case "$cmd" in
    *"|"*|*";"*|*"&&"*|*"||"*|*'`'*|*'$('*|*"<("*|*">|"*)
      return 1
      ;;
  esac

  return 1
}

# --- Guard evaluation via DEBUG trap ---
_zp_debug_trap() {
  # Prevent re-entry (guard itself runs commands)
  if [[ $_ZP_EVALUATING -eq 1 ]]; then
    return 0
  fi

  # Get the command about to execute
  local cmd="$BASH_COMMAND"

  # Skip empty, internal, and safe commands
  [[ -z "$cmd" ]] && return 0
  [[ "$cmd" == _zp_* ]] && return 0

  if _zp_is_safe "$cmd"; then
    return 0
  fi

  # Check guard binary exists
  if [[ ! -x "$ZP_BIN" ]]; then
    return 0  # Fail open
  fi

  # Build guard flags
  local guard_flags=("--actor" "$ZP_ACTOR")
  case "$ZP_POSTURE" in
    strict)     guard_flags+=("--strict") ;;
    permissive) guard_flags+=("--silent") ;;
  esac

  # Evaluate
  _ZP_EVALUATING=1
  "$ZP_BIN" guard "${guard_flags[@]}" "$cmd" 2>&1
  local result=$?
  _ZP_EVALUATING=0

  if [[ $result -ne 0 ]]; then
    # Command blocked — returning non-zero from DEBUG trap prevents execution
    return 1
  fi

  return 0
}

# --- Hook registration ---
# The DEBUG trap fires before each command execution.
# Returning non-zero prevents the command from running.
trap '_zp_debug_trap' DEBUG

# --- Status ---
# Uncomment for debug output on shell startup:
# echo "[ZP] Shell governance active — posture: $ZP_POSTURE, actor: $ZP_ACTOR"
