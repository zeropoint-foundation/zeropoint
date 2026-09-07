#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# Tool Governance Lifecycle — Empirical Test
# ─────────────────────────────────────────────────────────────────────
#
# Phase 1: Forge evaluates and hardens a known governed tool
# Phase 2: ZP detects ungoverned process (python3 http.server)
#
# Prerequisites:
#   - ./zp-dev.sh release completed
#   - zp serve running
#   - the tool registered in tool-ports.json
#
# Usage: ./scripts/test-governance-lifecycle.sh [phase1|phase2|both]

set -euo pipefail

ZP="$HOME/projects/zeropoint/target/release/zp"
DATA_DIR="$HOME/ZeroPoint/data"
AUDIT_DB="$DATA_DIR/audit.db"

# Colors
G='\033[32m' Y='\033[33m' R='\033[31m' C='\033[36m' B='\033[1m' N='\033[0m'

header() { echo -e "\n${B}${C}── $1 ──${N}"; }
pass()   { echo -e "  ${G}✓${N} $1"; }
info()   { echo -e "  ${C}ℹ${N} $1"; }
warn()   { echo -e "  ${Y}⚠${N} $1"; }
fail()   { echo -e "  ${R}✗${N} $1"; }

phase1() {
    header "PHASE 1: Forge evaluates and hardens a governed tool"

    # Step 1: Check current posture
    header "Step 1: Current governance posture"
    $ZP doctor --json 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
for c in data.get('checks', []):
    if 'Governance' in c.get('label', ''):
        icon = '✓' if c['status'] == 'pass' else '⚠' if c['status'] == 'warn' else '✗'
        print(f'  {icon} {c[\"label\"]}: {c[\"detail\"]}')
        if c.get('fix'):
            print(f'    → {c[\"fix\"]}')
" || $ZP doctor 2>/dev/null

    # Step 2: Grant Forge delegation for governance:propose
    header "Step 2: Grant Forge delegation"
    info "Issuing: zp delegate --subject officer:forge --capabilities governance:propose --lease-duration 24h"
    $ZP delegate --subject officer:forge --capabilities "governance:propose" --lease-duration 24h --json 2>/dev/null && pass "Forge delegation granted" || warn "Delegation may already exist or require interactive auth"

    # Step 3: Wait for sweep or trigger
    header "Step 3: Waiting for officer sweep"
    info "The periodic sweep fires every [officers] sweep_interval_secs."
    info "Check the server log for 'Officer sweep complete' with governance_requests > 0."
    info "Or wait for the sweep interval to pass..."
    echo ""
    info "While waiting, check recent chain entries:"
    $ZP chain tail --count 10 2>/dev/null || info "(chain tail not available — check audit.db directly)"

    # Step 4: Check for GovernanceRequest receipts
    header "Step 4: Check for governance request receipts"
    if [ -f "$AUDIT_DB" ]; then
        local count
        count=$(sqlite3 "$AUDIT_DB" "SELECT COUNT(*) FROM entries WHERE json_extract(action, '$.SystemEvent.event') LIKE 'governance_request:%'" 2>/dev/null || echo "0")
        if [ "$count" -gt 0 ]; then
            pass "Found $count governance request receipt(s)"
            sqlite3 "$AUDIT_DB" "
                SELECT json_extract(action, '$.SystemEvent.event') as event,
                       json_extract(policy_decision, '$.Allow.conditions') as conditions
                FROM entries
                WHERE json_extract(action, '$.SystemEvent.event') LIKE 'governance_request:%'
                ORDER BY timestamp DESC
                LIMIT 5
            " 2>/dev/null | while IFS='|' read -r event conditions; do
                info "  $event"
                info "    $conditions"
            done
        else
            warn "No governance request receipts yet — sweep may not have fired"
        fi
    else
        warn "Audit DB not found at $AUDIT_DB"
    fi

    # Step 5: Re-check posture
    header "Step 5: Updated governance posture"
    $ZP doctor --json 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
for c in data.get('checks', []):
    if 'Governance' in c.get('label', ''):
        icon = '✓' if c['status'] == 'pass' else '⚠' if c['status'] == 'warn' else '✗'
        print(f'  {icon} {c[\"label\"]}: {c[\"detail\"]}')
" || $ZP doctor 2>/dev/null
}

phase2() {
    header "PHASE 2: ZP detects ungoverned process"

    # Step 1: Start a rogue process
    header "Step 1: Starting rogue HTTP server on port 18080"
    python3 -m http.server 18080 --bind 127.0.0.1 &>/dev/null &
    ROGUE_PID=$!
    pass "Rogue process started (pid $ROGUE_PID)"
    info "Process: python3 -m http.server 18080"

    # Step 2: Wait for discovery scan
    header "Step 2: Waiting for sensor discovery scan"
    info "The discovery scanner runs on a timer (default: 30s)."
    info "Watching for NewListenerDiscovered event..."
    sleep 5

    # Step 3: Check for findings
    header "Step 3: Check for findings about the rogue process"
    if [ -f "$AUDIT_DB" ]; then
        local count
        count=$(sqlite3 "$AUDIT_DB" "
            SELECT COUNT(*) FROM entries
            WHERE json_extract(action, '$.SystemEvent.event') LIKE '%unauthorized_listener%'
               OR json_extract(action, '$.SystemEvent.event') LIKE '%unregistered_listener%'
               OR json_extract(action, '$.SystemEvent.event') LIKE '%governance_request%pid:$ROGUE_PID%'
        " 2>/dev/null || echo "0")
        if [ "$count" -gt 0 ]; then
            pass "Found $count finding(s) about unauthorized/unregistered processes"
        else
            info "No findings yet — discovery scan may not have fired"
            info "Wait for the scan interval, then re-run this check"
        fi

        # Check for governance requests about the rogue PID
        count=$(sqlite3 "$AUDIT_DB" "
            SELECT COUNT(*) FROM entries
            WHERE json_extract(action, '$.SystemEvent.event') LIKE 'governance_request:%'
              AND json_extract(policy_decision, '$.Allow.conditions') LIKE '%python3%'
        " 2>/dev/null || echo "0")
        if [ "$count" -gt 0 ]; then
            pass "Governance request surfaced for rogue process"
            sqlite3 "$AUDIT_DB" "
                SELECT json_extract(action, '$.SystemEvent.event') as event,
                       json_extract(policy_decision, '$.Allow.conditions') as conditions
                FROM entries
                WHERE json_extract(action, '$.SystemEvent.event') LIKE 'governance_request:%'
                  AND json_extract(policy_decision, '$.Allow.conditions') LIKE '%python3%'
                ORDER BY timestamp DESC
                LIMIT 3
            " 2>/dev/null | while IFS='|' read -r event conditions; do
                info "  $event"
                info "    $conditions"
            done
        fi
    fi

    # Step 4: Cleanup
    header "Step 4: Cleanup"
    kill $ROGUE_PID 2>/dev/null && pass "Rogue process killed (pid $ROGUE_PID)" || info "Process already exited"

    # Step 5: Check posture after cleanup
    header "Step 5: Posture after cleanup"
    $ZP doctor --json 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
for c in data.get('checks', []):
    if 'Governance' in c.get('label', ''):
        icon = '✓' if c['status'] == 'pass' else '⚠' if c['status'] == 'warn' else '✗'
        print(f'  {icon} {c[\"label\"]}: {c[\"detail\"]}')
" || $ZP doctor 2>/dev/null
}

# ── Main ─────────────────────────────────────────────────────────────

case "${1:-both}" in
    phase1) phase1 ;;
    phase2) phase2 ;;
    both)   phase1; echo ""; phase2 ;;
    *)      echo "Usage: $0 [phase1|phase2|both]"; exit 1 ;;
esac

echo ""
header "Done"
