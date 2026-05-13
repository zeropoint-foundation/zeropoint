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

echo "[1/5] Static assets on $FOUNDATION_HOST"

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

echo "[2/5] POST /api/auth/session for operator '$OPERATOR_ID'"

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

echo "[3/5] Bearer token against /api/me"

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

echo "[4/5] Cookie replay against $APP_HOST (substrate-session bridge)"

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

# ─── 5. Summary ───────────────────────────────────────────────────

echo "[5/5] Result"
if [[ "$FAIL" -eq 0 ]]; then
  echo "  ✓ ALL CHECKS PASSED — auth path is live end-to-end"
  exit 0
else
  echo "  ✗ ONE OR MORE CHECKS FAILED — see details above"
  exit 1
fi
