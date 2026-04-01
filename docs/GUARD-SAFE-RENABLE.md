# ZP Guard — Safe Re-enablement Strategy

## Problem

The `zp_guard_preexec` shell hook in `~/.zshrc` was disabled after it catastrophically
broke terminal functionality. The hook intercepts every command via zsh's `preexec`
mechanism, and when it fails (crash, hang, or bad exit code), it blocks ALL terminal
input — with no easy recovery path since the terminal itself is the broken interface.

## Root Cause Analysis

The preexec hook pattern is inherently fragile because:

1. **Single point of failure**: If `zp guard` crashes or hangs, every subsequent command is blocked
2. **No timeout**: A slow evaluation (disk I/O, regex backtracking) freezes the shell
3. **No bypass**: Once the hook is broken, you can't type commands to fix it
4. **Startup dependency**: If `zp` binary is missing or corrupt, the shell becomes unusable

## Safe Re-enablement: Three-Layer Protection

### Layer 1: Timeout Wrapper (mandatory)

Never call `zp guard` directly. Wrap it with a timeout so a hung evaluation
auto-allows after 200ms:

```zsh
zp_guard_preexec() {
    # Skip if Guard is paused
    [[ -f ~/.zeropoint/.guard-paused ]] && return 0

    # 200ms timeout — if Guard hangs, command proceeds
    timeout 0.2 zp guard -s "$1" 2>/dev/null
    local rc=$?

    # timeout returns 124 on expiry — treat as allow
    if [[ $rc -eq 124 ]]; then
        return 0  # timed out, fail-open
    elif [[ $rc -ne 0 ]]; then
        echo "⚡ ZP Guard: blocked"
        return 1
    fi
}
```

### Layer 2: Kill Switch File (mandatory)

A simple file-based pause mechanism that doesn't require the terminal to work:

```zsh
# To pause Guard (from Finder, another terminal, or ssh):
touch ~/.zeropoint/.guard-paused

# To resume Guard:
rm ~/.zeropoint/.guard-paused
```

The hook checks for this file FIRST, before invoking `zp guard`. This means
even if `zp` is completely broken, you can disable Guard by creating the file
from any interface (Finder → New File, ssh, another app).

### Layer 3: Auto-disable on Repeated Failures (recommended)

Track consecutive failures and auto-pause if Guard is misbehaving:

```zsh
_ZP_GUARD_FAILS=0

zp_guard_preexec() {
    [[ -f ~/.zeropoint/.guard-paused ]] && return 0

    # Auto-pause after 3 consecutive failures
    if (( _ZP_GUARD_FAILS >= 3 )); then
        touch ~/.zeropoint/.guard-paused
        echo "⚡ ZP Guard auto-paused after repeated failures. Remove ~/.zeropoint/.guard-paused to resume."
        _ZP_GUARD_FAILS=0
        return 0
    fi

    timeout 0.2 zp guard -s "$1" 2>/dev/null
    local rc=$?

    if [[ $rc -eq 0 || $rc -eq 124 ]]; then
        _ZP_GUARD_FAILS=0  # reset on success
        return 0
    else
        (( _ZP_GUARD_FAILS++ ))
        echo "⚡ ZP Guard: blocked ($_ZP_GUARD_FAILS/3 before auto-pause)"
        return 1
    fi
}

# Only install if zp binary exists
if command -v zp &>/dev/null; then
    autoload -Uz add-zsh-hook
    add-zsh-hook preexec zp_guard_preexec
fi
```

## Recovery Procedures

If the terminal becomes unresponsive despite these protections:

1. **From Finder**: Navigate to `~/.zeropoint/`, create a file named `.guard-paused`
2. **From another terminal/ssh**: `touch ~/.zeropoint/.guard-paused`
3. **Nuclear option**: Edit `~/.zshrc` from a text editor and comment out the hook
4. **Emergency shell**: `env -i zsh --no-rcs` bypasses all shell config

## When to Re-enable

Re-enable Guard only when:
- [ ] The timeout wrapper is in place (Layer 1)
- [ ] The kill switch file mechanism is in place (Layer 2)
- [ ] `zp guard -s "ls"` completes in under 50ms consistently
- [ ] `zp guard -s "echo test" && echo ok` works reliably 10+ times
- [ ] The `.guard-paused` recovery path has been tested manually

## Status

**Current**: Disabled (commented out in `~/.zshrc` since 2026-03-23)
**Target**: Re-enable with all three protection layers after validation
