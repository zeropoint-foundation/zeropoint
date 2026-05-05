#!/usr/bin/env bash
# ZeroPoint orchestrator hook: before_run
# Called immediately before an agent begins execution on a task.
#
# Environment variables (set by orchestrator):
#   ISSUE_ID           — The issue/task identifier
#   AGENT_ID           — The agent instance identifier
#   ZP_GENESIS_RECEIPT — Receipt ID from workspace creation (parent reference)
#   RUN_NUMBER         — Sequential run number (optional)
#
# This hook emits a receipt recording authorization to run, creating a
# parent→child link from the workspace genesis receipt.

set -euo pipefail

LABEL="orchestrator:run:authorized"
ISSUE="${ISSUE_ID:?ISSUE_ID must be set}"
AGENT="${AGENT_ID:?AGENT_ID must be set}"

PARENT_ARGS=""
if [ -n "${ZP_GENESIS_RECEIPT:-}" ]; then
    PARENT_ARGS="--parent $ZP_GENESIS_RECEIPT"
fi

RECEIPT_ID=$(zp emit "$LABEL" \
    --issue "$ISSUE" \
    --agent "$AGENT" \
    $PARENT_ARGS \
    ${RUN_NUMBER:+--meta run_number="$RUN_NUMBER"})

echo "[zp] run:authorized receipt=$RECEIPT_ID issue=$ISSUE agent=$AGENT" >&2

# Export for the after_run hook
export ZP_RUN_RECEIPT="$RECEIPT_ID"
