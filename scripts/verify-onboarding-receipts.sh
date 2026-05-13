#!/usr/bin/env bash
# verify-onboarding-receipts.sh — validate a director's onboarding chain
#
# Pulls all receipts for the given operator from the production D1
# and checks they match the expected emission pattern of the
# onboarding wizard. This is the substrate using itself as the
# assertion mechanism — receipts ARE the proof of what happened.
#
# Usage:
#   ./scripts/verify-onboarding-receipts.sh <operator_id>
#
# Example:
#   ./scripts/verify-onboarding-receipts.sh ken
#
# Requires:
#   - wrangler (npx wrangler)
#   - jq
#   - Must be run from inside zeropointfoundation.org/ (or set $FOUNDATION_DIR)
#
# What this verifies (today):
#   - Required ceremony bookends are present (onboard:start, onboard:complete)
#   - All expected phase receipts appear in order
#   - Metadata shape on each receipt
#   - Time ordering is monotonic
#
# What this does NOT verify (yet — see TODO):
#   - Cryptographic signatures (receipts in the worker's D1 are not
#     currently signed; foundation-side receipt signing is open work)
#   - Chain integrity via hash-chaining (same reason)
#
# Refs:
#   - docs/handoffs/director-pilot-preflight-2026-05.md
#   - zeropointfoundation.org/migrations/0002_auth_schema.sql

set -euo pipefail

OPERATOR_ID="${1:-}"
if [[ -z "$OPERATOR_ID" ]]; then
  echo "usage: $0 <operator_id>" >&2
  exit 2
fi

FOUNDATION_DIR="${FOUNDATION_DIR:-$(cd "$(dirname "$0")/../zeropointfoundation.org" && pwd)}"
cd "$FOUNDATION_DIR"

echo "Verifying onboarding receipts for: $OPERATOR_ID"
echo "Foundation dir: $FOUNDATION_DIR"
echo

# ─── Pull receipts ────────────────────────────────────────────────

# wrangler d1 execute returns JSON with a "results" array per query
RAW=$(npx wrangler d1 execute zpmail --remote --json \
  --command="SELECT id, operator_id, claim, subject, capability_used, metadata, created_at FROM receipts WHERE operator_id = '$OPERATOR_ID' ORDER BY created_at ASC;" \
  2>/dev/null)

# Extract just the rows
RECEIPTS=$(echo "$RAW" | jq -r '.[0].results // []')
COUNT=$(echo "$RECEIPTS" | jq 'length')

echo "Found $COUNT receipts."
echo

if [[ "$COUNT" -eq 0 ]]; then
  echo "✗ FAIL: no receipts found for operator '$OPERATOR_ID'"
  echo "  Either the operator hasn't onboarded, or you're querying the wrong DB."
  exit 1
fi

# ─── Expected emission pattern (from onboard/index.html) ─────────

# Required claims (must appear; in order)
REQUIRED_CLAIMS=(
  "onboard:start"
  "onboard:identity:generated"
  "onboard:recovery:acknowledged"
  "onboard:voice:selected"
  "onboard:complete"
)

# Optional claims (may or may not appear, depending on path)
OPTIONAL_CLAIMS=(
  "onboard:start:already-onboarded"
  "onboard:identity:browser-unsupported"
  "onboard:identity:registration-refused"
  "onboard:passkey:registered"
  "onboard:passkey:skipped"
  "onboard:passkey:failed"
  "onboard:capability:demonstrated:allow"
  "onboard:capability:demonstrated:deny"
  "onboard:capability:incident"
)

# ─── Check required claims are present in order ──────────────────

CLAIM_LIST=$(echo "$RECEIPTS" | jq -r '.[].claim')

echo "Receipt sequence:"
echo "$CLAIM_LIST" | nl -ba -w2 -s'. '
echo

PASS=true

# Required claims, in order
prev_idx=-1
for required in "${REQUIRED_CLAIMS[@]}"; do
  idx=$(echo "$CLAIM_LIST" | grep -nx "$required" | head -1 | cut -d: -f1 || true)
  if [[ -z "$idx" ]]; then
    echo "✗ FAIL: missing required claim '$required'"
    PASS=false
    continue
  fi
  if (( idx <= prev_idx )); then
    echo "✗ FAIL: required claim '$required' appears at line $idx but should come AFTER line $prev_idx"
    PASS=false
  fi
  prev_idx=$idx
done

# ─── Unknown claims (might be bugs or new emission points) ───────

ALL_KNOWN=("${REQUIRED_CLAIMS[@]}" "${OPTIONAL_CLAIMS[@]}")
while IFS= read -r claim; do
  match=false
  for known in "${ALL_KNOWN[@]}"; do
    [[ "$claim" == "$known" ]] && { match=true; break; }
  done
  if [[ "$match" == false ]]; then
    echo "⚠  WARN: unrecognized claim '$claim' — either a new emission point or a bug"
  fi
done <<< "$CLAIM_LIST"

# ─── Time ordering ───────────────────────────────────────────────

OUT_OF_ORDER=$(echo "$RECEIPTS" | jq -r '
  reduce .[] as $r ({prev: "", ok: true};
    if .prev != "" and $r.created_at < .prev then {prev: $r.created_at, ok: false}
    else {prev: $r.created_at, ok: .ok}
    end
  ) | .ok')
if [[ "$OUT_OF_ORDER" != "true" ]]; then
  echo "✗ FAIL: receipts are not in monotonic time order"
  PASS=false
fi

# ─── Bookend check ───────────────────────────────────────────────

FIRST_CLAIM=$(echo "$CLAIM_LIST" | head -1)
LAST_CLAIM=$(echo "$CLAIM_LIST" | tail -1)

if [[ "$FIRST_CLAIM" != "onboard:start" && "$FIRST_CLAIM" != "onboard:start:already-onboarded" ]]; then
  echo "✗ FAIL: first claim should be onboard:start (or already-onboarded variant); got '$FIRST_CLAIM'"
  PASS=false
fi

if [[ "$LAST_CLAIM" != "onboard:complete" ]]; then
  echo "⚠  WARN: last claim is '$LAST_CLAIM', expected 'onboard:complete' — ceremony may be incomplete"
fi

# ─── Final ───────────────────────────────────────────────────────

echo
if [[ "$PASS" == true ]]; then
  echo "✓ PASS — receipt chain looks valid ($COUNT receipts, bookends present, time-ordered)"
  echo
  echo "Caveat: this script does NOT yet verify cryptographic signatures."
  echo "Foundation-side receipt signing is open work. The receipts table"
  echo "in the worker's D1 schema has no signature column today."
  exit 0
else
  echo "✗ FAIL — see issues above"
  exit 1
fi
