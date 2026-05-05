#!/usr/bin/env bash
# ZeroPoint orchestrator hook: before_remove
# Called before an agent workspace is torn down.
#
# Environment variables (set by orchestrator):
#   ISSUE_ID           — The issue/task identifier
#   AGENT_ID           — The agent instance identifier
#   ZP_GENESIS_RECEIPT — Receipt ID from workspace creation (parent reference)
#   REMOVAL_REASON     — Why the workspace is being removed (optional)
#
# This hook emits a receipt recording workspace teardown, closing the
# per-issue chain for this agent's lifecycle.

set -euo pipefail

LABEL="orchestrator:workspace:removed"
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
    ${REMOVAL_REASON:+--meta reason="$REMOVAL_REASON"})

echo "[zp] workspace:removed receipt=$RECEIPT_ID issue=$ISSUE agent=$AGENT" >&2
