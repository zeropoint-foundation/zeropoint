#!/usr/bin/env bash
# Discipline pin: zp_internal_port_range
#
# ZP-internal binaries must only bind literal ports in the 17000–17999 range.
# Port 0 (OS-assigned) is always allowed. Variable-driven ports (e.g.
# `format!("{}:{}", host, cfg.port)`) are not caught by this scan and are
# governed by the configuration layer.
#
# The external tool range (9100–9199) lives in tool_ports.rs constants and is
# intentionally excluded — those are tool-managed ports, not ZP-internal ports.
#
# Usage: ./scripts/zp_internal_port_range.sh [--fix]
#   --fix is a no-op (violations require intentional changes, not automation).
set -euo pipefail

SCAN_DIRS=(
    "crates/zp-cli"
    "crates/zp-server"
    "crates/zp-audit"
    "crates/zp-receipt"
    "crates/zp-core"
)

# Pattern: quoted host:port literals like "127.0.0.1:12345" or "localhost:4567"
PATTERN='"([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]+"'

VIOLATIONS=0

for dir in "${SCAN_DIRS[@]}"; do
    if [[ ! -d "$dir" ]]; then
        continue
    fi
    while IFS= read -r match; do
        # Extract numeric port from the match
        port=$(echo "$match" | grep -oE ':[0-9]+' | tr -d ':' | head -1)
        if [[ -z "$port" ]]; then
            continue
        fi
        # Allow port 0 (OS-assigned) and ZP-internal range 17000-17999
        if [[ "$port" -eq 0 ]] || { [[ "$port" -ge 17000 ]] && [[ "$port" -le 17999 ]]; }; then
            continue
        fi
        # Allow the tool port range constants (9100, 9199) in tool_ports.rs
        if echo "$match" | grep -q "tool_ports.rs"; then
            continue
        fi
        echo "VIOLATION: $match"
        ((VIOLATIONS++)) || true
    done < <(grep -rn --include="*.rs" -E "$PATTERN" "${SCAN_DIRS[@]}" 2>/dev/null || true)
done

if [[ "$VIOLATIONS" -gt 0 ]]; then
    echo ""
    echo "zp_internal_port_range: $VIOLATIONS violation(s) found."
    echo "ZP-internal binaries must bind within 17000–17999."
    echo "Port 0 (OS-assigned) and variable-driven ports are allowed."
    exit 1
fi

echo "zp_internal_port_range: OK"
