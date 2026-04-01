#!/usr/bin/env bash
#
# zp-speak.sh — Speak text through local Piper TTS
#
# Usage:
#   pbpaste | ./zp-speak.sh              # read clipboard (macOS)
#   echo "Hello world" | ./zp-speak.sh   # pipe text
#   ./zp-speak.sh "Hello world"          # argument
#   ./zp-speak.sh                        # reads clipboard automatically
#
# Requires: voice-tuner-server.py running on port 8473
#           brew install jq (optional, for error messages)

set -euo pipefail

TTS_SERVER="${ZP_TTS_SERVER:-http://localhost:8473}"
VOICE="${ZP_TTS_VOICE:-en_US-kusal-medium}"
LENGTH_SCALE="${ZP_TTS_SPEED:-0.7692}"
NOISE_SCALE="0.360"
NOISE_W="0.930"
SILENCE="0.30"

# ── Gather text ───────────────────────────────────────────────
if [ $# -gt 0 ]; then
  TEXT="$*"
elif [ ! -t 0 ]; then
  TEXT=$(cat)
else
  # No args, no stdin — try clipboard
  if command -v pbpaste &>/dev/null; then
    TEXT=$(pbpaste)
  elif command -v xclip &>/dev/null; then
    TEXT=$(xclip -selection clipboard -o)
  else
    echo "Usage: echo 'text' | zp-speak.sh  OR  zp-speak.sh 'text'" >&2
    exit 1
  fi
fi

if [ -z "$TEXT" ]; then
  echo "Nothing to speak." >&2
  exit 0
fi

# ── Strip markdown formatting for cleaner speech ──────────────
TEXT=$(echo "$TEXT" | \
  sed -E 's/```[^`]*```/ code block omitted /g' | \
  sed -E 's/`([^`]+)`/\1/g' | \
  sed -E 's/\*\*([^*]+)\*\*/\1/g' | \
  sed -E 's/\*([^*]+)\*/\1/g' | \
  sed -E 's/^#{1,6} +//gm' | \
  sed -E 's/^\s*[-*] +//gm' | \
  sed -E 's/^\s*[0-9]+\. +//gm' | \
  sed -E 's/\[([^]]+)\]\([^)]+\)/\1/g')

CHARS=${#TEXT}
echo "  TTS  Speaking ${CHARS} chars via ${VOICE}..."

# ── Synthesize ────────────────────────────────────────────────
TMPFILE=$(mktemp /tmp/zp-speak-XXXXXX.wav)
trap "rm -f '$TMPFILE'" EXIT

HTTP_CODE=$(curl -s -o "$TMPFILE" -w "%{http_code}" \
  -X POST "${TTS_SERVER}/synthesize" \
  -H "Content-Type: application/json" \
  -d "$(cat <<EOF
{
  "text": $(printf '%s' "$TEXT" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))'),
  "voice_file": "$VOICE",
  "length_scale": "$LENGTH_SCALE",
  "noise_scale": "$NOISE_SCALE",
  "noise_w": "$NOISE_W",
  "sentence_silence": "$SILENCE"
}
EOF
)")

if [ "$HTTP_CODE" != "200" ]; then
  echo "  TTS  Error: server returned HTTP $HTTP_CODE" >&2
  if command -v jq &>/dev/null && [ -f "$TMPFILE" ]; then
    jq -r '.error // empty' "$TMPFILE" 2>/dev/null | sed 's/^/  TTS  /' >&2
  fi
  exit 1
fi

# ── Play ──────────────────────────────────────────────────────
if command -v afplay &>/dev/null; then
  afplay "$TMPFILE"
elif command -v aplay &>/dev/null; then
  aplay -q "$TMPFILE"
elif command -v play &>/dev/null; then
  play -q "$TMPFILE"
else
  echo "  TTS  No audio player found (afplay/aplay/play). WAV saved to: $TMPFILE" >&2
  trap - EXIT  # don't delete the file
  exit 1
fi

echo "  TTS  Done."
