#!/usr/bin/env bash
# smoke-test-auth.sh — protocol-level smoke test of the foundation auth chain
#
# Exercises every seam between the substrate worker, IronClaw, and the
# static assets that the director walks through. Designed to catch the
# class of bugs that "everything works on localhost" hides — route
# binding, cookie domain scope, asset deploy, cross-language HMAC
# compat, the lot.
#
# Run before any pilot. Run after any deploy. Run after any auth-path
# change. ~10 seconds end-to-end.
#
# Usage:
#   ./scripts/smoke-test-auth.sh [operator_id]
#   ./scripts/smoke-test-auth.sh ken
#
# Env:
#   FOUNDATION_HOST   default: zeropointfoundation.org
#   APP_HOST          default: app.zeropointfoundation.org
#   OPERATOR_ID       default: $1 or 'ken'
#
# Refs:
#   - docs/handoffs/director-pilot-preflight-2026-05.md
#   - CLAUDE.md → Workflow heuristics → "only production tests production"

set -uo pipefail

FOUNDATION_HOST="${FOUNDATION_HOST:-zeropointfoundation.org}"
APP_HOST="${APP_HOST:-app.zeropointfoundation.org}"
OPERATOR_ID="${1:-${OPERATOR_ID:-ken}}"

FAIL=0

assert_eq() {
  local label="$1"
  local actual="$2"
  local expected="$3"
  if [[ "$actual" == "$expected" ]]; then
    echo "  ✓ $label: $actual"
  else
    echo "  ✗ $label: got '$actual', expected '$expected'"
    FAIL=1
  fi
}

assert_contains() {
  local label="$1"
  local haystack="$2"
  local needle="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    echo "  ✓ $label contains '$needle'"
  else
    echo "  ✗ $label missing '$needle'"
    echo "    haystack: $haystack" | head -c 200
    FAIL=1
  fi
}

# ─── 1. Static asset reachability ─────────────────────────────────

echo "[1/6] Static assets on $FOUNDATION_HOST"

WIZARD_STATUS=$(curl -s -o /dev/null -w '%{http_code}' "https://$FOUNDATION_HOST/onboard/")
assert_eq "wizard HTML" "$WIZARD_STATUS" "200"

PALETTE_STATUS=$(curl -s -o /dev/null -w '%{http_code}' "https://$FOUNDATION_HOST/onboard/onboarding-voice-palette.json")
assert_eq "voice palette JSON" "$PALETTE_STATUS" "200"

PALETTE_JSON=$(curl -s "https://$FOUNDATION_HOST/onboard/onboarding-voice-palette.json")
PALETTE_FAVS=$(echo "$PALETTE_JSON" | jq -r '.favorites | length' 2>/dev/null || echo "0")
if [[ "$PALETTE_FAVS" -gt 0 ]]; then
  echo "  ✓ voice palette has $PALETTE_FAVS curated voices"
else
  echo "  ✗ voice palette is empty or malformed"
  FAIL=1
fi

# Spot-check first voice sample
FIRST_VOICE=$(echo "$PALETTE_JSON" | jq -r '.favorites[0].voice' 2>/dev/null)
if [[ -n "$FIRST_VOICE" && "$FIRST_VOICE" != "null" ]]; then
  SAMPLE_STATUS=$(curl -s -o /dev/null -w '%{http_code}' "https://$FOUNDATION_HOST/onboard/voices/${FIRST_VOICE}-sample.mp3")
  SAMPLE_TYPE=$(curl -s -I "https://$FOUNDATION_HOST/onboard/voices/${FIRST_VOICE}-sample.mp3" | grep -i '^content-type:' | tr -d '\r' | awk '{print $2}')
  assert_eq "first sample status ($FIRST_VOICE)" "$SAMPLE_STATUS" "200"
  assert_eq "first sample content-type" "$SAMPLE_TYPE" "audio/mpeg"
fi

echo

# ─── 2. Mint a session token ──────────────────────────────────────

echo "[2/6] POST /api/auth/session for operator '$OPERATOR_ID'"

COOKIE_JAR=$(mktemp)
trap "rm -f $COOKIE_JAR" EXIT

SESSION_RES=$(curl -s -c "$COOKIE_JAR" \
  -H "Content-Type: application/json" \
  -d "{\"operatorId\":\"$OPERATOR_ID\"}" \
  -w '\nHTTP_STATUS:%{http_code}' \
  "https://$FOUNDATION_HOST/api/auth/session")

SESSION_STATUS=$(echo "$SESSION_RES" | grep '^HTTP_STATUS:' | cut -d: -f2)
SESSION_BODY=$(echo "$SESSION_RES" | sed '/^HTTP_STATUS:/d')

assert_eq "session status" "$SESSION_STATUS" "200"

TOKEN=$(echo "$SESSION_BODY" | jq -r '.token // empty' 2>/dev/null)
if [[ -n "$TOKEN" ]]; then
  echo "  ✓ token returned in JSON body ($(echo -n "$TOKEN" | wc -c | tr -d ' ') bytes)"
else
  echo "  ✗ no token in JSON body"
  FAIL=1
fi

# Confirm Set-Cookie landed in the jar
if grep -q '^\.zeropointfoundation\.org.*zp_session' "$COOKIE_JAR" 2>/dev/null \
   || grep -q '^zeropointfoundation\.org.*zp_session' "$COOKIE_JAR" 2>/dev/null; then
  echo "  ✓ Set-Cookie: zp_session received (domain-scoped)"
else
  echo "  ✗ Set-Cookie: zp_session NOT received or wrong scope"
  echo "    cookie jar contents:"
  sed 's/^/      /' "$COOKIE_JAR"
  FAIL=1
fi

echo

# ─── 3. Bearer token works against same-origin API ────────────────

echo "[3/6] Bearer token against /api/me"

ME_RES=$(curl -s -H "Authorization: Bearer $TOKEN" \
  -w '\nHTTP_STATUS:%{http_code}' \
  "https://$FOUNDATION_HOST/api/me")
ME_STATUS=$(echo "$ME_RES" | grep '^HTTP_STATUS:' | cut -d: -f2)
ME_BODY=$(echo "$ME_RES" | sed '/^HTTP_STATUS:/d')

assert_eq "/api/me status" "$ME_STATUS" "200"
ME_SUB=$(echo "$ME_BODY" | jq -r '.operatorId // .sub // empty' 2>/dev/null)
if [[ "$ME_SUB" == "$OPERATOR_ID" ]]; then
  echo "  ✓ /api/me returned operator '$OPERATOR_ID'"
else
  echo "  ⚠  /api/me operator field: got '$ME_SUB', expected '$OPERATOR_ID' (could be a schema variant)"
fi

echo

# ─── 4. Replay cookie against IronClaw (the cross-language seam) ──

echo "[4/6] Cookie replay against $APP_HOST (substrate-session bridge)"

GATEWAY_RES=$(curl -s -b "$COOKIE_JAR" \
  -w '\nHTTP_STATUS:%{http_code}' \
  "https://$APP_HOST/api/gateway/status")
GATEWAY_STATUS=$(echo "$GATEWAY_RES" | grep '^HTTP_STATUS:' | cut -d: -f2)

if [[ "$GATEWAY_STATUS" == "200" ]]; then
  echo "  ✓ /api/gateway/status returned 200 — IronClaw accepted the substrate-session cookie"
elif [[ "$GATEWAY_STATUS" == "401" ]]; then
  echo "  ✗ /api/gateway/status returned 401 — IronClaw rejected the cookie"
  echo "    Likely causes:"
  echo "      - SESSION_SIGNING_KEY mismatch between worker and IronClaw .env"
  echo "      - IronClaw running an old binary without substrate-session code"
  echo "      - GATEWAY_SUBSTRATE_SESSION_ENABLED not true in ~/.ironclaw/.env"
  FAIL=1
else
  echo "  ✗ /api/gateway/status returned $GATEWAY_STATUS (unexpected)"
  FAIL=1
fi

echo

# ─── 5. Chain endpoint + narrative bundle (agent-rendered chain PoC) ─

echo "[5/6] Chain endpoint and narrative bundle"

# 5a. Narrative bundle served via static assets
NARR_URL="https://$FOUNDATION_HOST/narratives/foundation-director-onboarding.yaml"
NARR_STATUS=$(curl -s -o /dev/null -w '%{http_code}' "$NARR_URL")
assert_eq "narrative bundle status" "$NARR_STATUS" "200"

NARR_BODY=$(curl -s "$NARR_URL")
assert_contains "narrative bundle workflow_id" "$NARR_BODY" "foundation/director-onboarding"
assert_contains "narrative bundle voice" "$NARR_BODY" "voice: sage"

# 5b. /api/operator/me/chain with onboard:* filter
CHAIN_RES=$(curl -s -H "Authorization: Bearer $TOKEN" \
  -w '\nHTTP_STATUS:%{http_code}' \
  "https://$FOUNDATION_HOST/api/operator/me/chain?claim_pattern=onboard:*")
CHAIN_STATUS=$(echo "$CHAIN_RES" | grep '^HTTP_STATUS:' | cut -d: -f2)
CHAIN_BODY=$(echo "$CHAIN_RES" | sed '/^HTTP_STATUS:/d')

assert_eq "chain endpoint status" "$CHAIN_STATUS" "200"

CHAIN_OP=$(echo "$CHAIN_BODY" | jq -r '.operatorId // empty' 2>/dev/null)
assert_eq "chain scoped to caller" "$CHAIN_OP" "$OPERATOR_ID"

CHAIN_COUNT=$(echo "$CHAIN_BODY" | jq -r '.count // 0' 2>/dev/null)
if [[ "$CHAIN_COUNT" -ge 1 ]]; then
  echo "  ✓ chain has $CHAIN_COUNT receipt(s)"
else
  echo "  ✗ chain has 0 receipts for $OPERATOR_ID (expected ≥ 1)"
  FAIL=1
fi

# Every returned claim must start with 'onboard:' (filter is doing its job)
BAD_CLAIM=$(echo "$CHAIN_BODY" | jq -r '.receipts[]?.claim | select(startswith("onboard:") | not)' 2>/dev/null | head -1)
if [[ -z "$BAD_CLAIM" ]]; then
  echo "  ✓ claim_pattern filter excluded non-matching claims"
else
  echo "  ✗ claim_pattern filter leaked non-matching claim: $BAD_CLAIM"
  FAIL=1
fi

# Ordering: created_at ascending
FIRST_TS=$(echo "$CHAIN_BODY" | jq -r '.receipts[0]?.created_at // empty' 2>/dev/null)
LAST_TS=$(echo "$CHAIN_BODY" | jq -r '.receipts[-1]?.created_at // empty' 2>/dev/null)
if [[ -n "$FIRST_TS" && -n "$LAST_TS" && ( "$FIRST_TS" < "$LAST_TS" || "$FIRST_TS" == "$LAST_TS" ) ]]; then
  echo "  ✓ receipts ordered ASC ($FIRST_TS → $LAST_TS)"
else
  echo "  ✗ ordering looks wrong (first=$FIRST_TS, last=$LAST_TS)"
  FAIL=1
fi

# Claim names must be unprefixed (no leading 'claim:')
LEAKED_PREFIX=$(echo "$CHAIN_BODY" | jq -r '.receipts[]?.claim | select(startswith("claim:"))' 2>/dev/null | head -1)
if [[ -z "$LEAKED_PREFIX" ]]; then
  echo "  ✓ stored claim names are unprefixed"
else
  echo "  ✗ found 'claim:'-prefixed name in storage: $LEAKED_PREFIX"
  FAIL=1
fi

echo

# ─── 6. Summary ───────────────────────────────────────────────────

echo "[6/6] Result"
if [[ "$FAIL" -eq 0 ]]; then
  echo "  ✓ ALL CHECKS PASSED — auth path is live end-to-end"
  exit 0
else
  echo "  ✗ ONE OR MORE CHECKS FAILED — see details above"
  exit 1
fi
