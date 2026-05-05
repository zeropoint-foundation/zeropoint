#!/usr/bin/env bash
# ZeroPoint orchestrator hook: after_create
# Called when a new agent workspace is provisioned.
#
# Environment variables (set by orchestrator):
#   ISSUE_ID     — The issue/task identifier (e.g., PROJ-347)
#   AGENT_ID     — The agent instance identifier
#   WORKSPACE_ID — The workspace/sandbox identifier (optional)
#
# This hook emits an ObservationClaim receipt recording that a workspace
# was created for the given issue, establishing the per-issue chain.

set -euo pipefail

LABEL="orchestrator:workspace:created"
ISSUE="${ISSUE_ID:?ISSUE_ID must be set}"
AGENT="${AGENT_ID:?AGENT_ID must be set}"

# Emit the receipt — stdout is the receipt ID
RECEIPT_ID=$(zp emit "$LABEL" \
    --issue "$ISSUE" \
    --agent "$AGENT" \
    ${WORKSPACE_ID:+--meta workspace_id="$WORKSPACE_ID"})

echo "[zp] workspace:created receipt=$RECEIPT_ID issue=$ISSUE agent=$AGENT" >&2

# Optionally export for downstream hooks
export ZP_GENESIS_RECEIPT="$RECEIPT_ID"
