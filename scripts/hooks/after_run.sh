#!/usr/bin/env bash
# ZeroPoint orchestrator hook: after_run
# Called after an agent completes execution (success or failure).
#
# Environment variables (set by orchestrator):
#   ISSUE_ID       — The issue/task identifier
#   AGENT_ID       — The agent instance identifier
#   ZP_RUN_RECEIPT — Receipt ID from the before_run hook (parent reference)
#   EXIT_CODE      — Agent exit code (0 = success)
#   RUN_DURATION   — Execution duration in seconds (optional)
#
# This hook emits a receipt sealing the run, recording the outcome
# and linking back to the authorization receipt.

set -euo pipefail

LABEL="orchestrator:run:sealed"
ISSUE="${ISSUE_ID:?ISSUE_ID must be set}"
AGENT="${AGENT_ID:?AGENT_ID must be set}"
EXIT="${EXIT_CODE:-0}"

PARENT_ARGS=""
if [ -n "${ZP_RUN_RECEIPT:-}" ]; then
    PARENT_ARGS="--parent $ZP_RUN_RECEIPT"
fi

META_ARGS="--meta exit_code=$EXIT"
if [ -n "${RUN_DURATION:-}" ]; then
    META_ARGS="$META_ARGS --meta duration_s=$RUN_DURATION"
fi

RECEIPT_ID=$(zp emit "$LABEL" \
    --issue "$ISSUE" \
    --agent "$AGENT" \
    $PARENT_ARGS \
    $META_ARGS)

echo "[zp] run:sealed receipt=$RECEIPT_ID issue=$ISSUE exit=$EXIT" >&2
