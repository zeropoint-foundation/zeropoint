#!/bin/bash
# Batch-synthesize ZeroPoint July 2026 design docs to MP3 via local Piper TTS.
# Voice: en_US-amy-medium.  Speed: 1.5x (length_scale 0.667).
# Output: ~/Desktop/MP3 OUTPUT/
#
# Usage: bash ~/projects/zeropoint/scripts/synthesize-mp3-batch.sh

set -uo pipefail

# Kill any lingering afplay from prior sample runs.
pkill afplay 2>/dev/null || true

PIPER="/Users/kenrom/anaconda3/bin/piper"
MODEL="/Users/kenrom/projects/zeropoint/models/piper/en_US-amy-medium.onnx"
DOCS_ROOT="/Users/kenrom/projects/zeropoint/docs"
OUT_DIR="$HOME/Desktop/MP3 OUTPUT"
LENGTH_SCALE=0.667

# Verify prerequisites.
if [ ! -x "$PIPER" ]; then
  echo "ERROR: piper binary not found at $PIPER"
  exit 1
fi
if [ ! -f "$MODEL" ]; then
  echo "ERROR: Amy voice model not found at $MODEL"
  exit 1
fi
if ! command -v ffmpeg >/dev/null 2>&1; then
  echo "ERROR: ffmpeg not on PATH — needed for MP3 encoding"
  exit 1
fi

mkdir -p "$OUT_DIR"

# 31 documents from the last 3 days of ZP design work.
DOCS=(
  "whitepaper-v9.md"
  "zeropoint-overview-draft-2026-07.md"
  "PERSONALITY-ADAPTATION-VALIDATION-PROTOCOL-2026-07.md"
  "ARCHITECTURE-2026-07.md"
  "COGNITIVE-DESIGN-PRINCIPLES-2026-07.md"
  "EXECUTION-AUTHORITY-MODEL-2026-07.md"
  "REGENT-PHASE-0-1-DESIGN-2026-07.md"
  "design/ONTOLOGY-AND-CARTOGRAPHER-2026-07.md"
  "design/TOOL-OPACITY-AND-CAPABILITY-CLASSES-2026-07.md"
  "design/REGENT-ORCHESTRATION-ARCHITECTURE-2026-07.md"
  "design/TOOL-GOVERNANCE-LIFECYCLE-2026-07.md"
  "design/GOVERNANCE-POSTURE-WIRE-CONTRACT-2026-07.md"
  "handoffs/zp-tool-remove-design-2026-07.md"
  "design/PEER-DISCOVERY-AS-OUTREACH-2026-07.md"
  "design/DISTRIBUTED-KNOWLEDGE-COMMONS-2026-07.md"
  "design/BACKUP-AND-RECOVERY-LANDSCAPE-2026-07.md"
  "design/ENCRYPTED-STORAGE-ARCHITECTURE-2026-07.md"
  "design/REGENT-COMPARTMENTALIZATION-2026-07.md"
  "design/PHONE-AND-IDENTITY-2026-07.md"
  "design/SOFTWARE-INTEGRITY-ATTESTATION-2026-07.md"
  "design/MEDIA-PROVENANCE-2026-07.md"
  "design/COMMUNITY-SURFACE-ARCHITECTURE-2026-07.md"
  "design/TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT-2026-07.md"
  "design/COMMUNITY-COORDINATION-ON-ZEROPOINT-2026-07.md"
  "design/SUPERSESSION-FRAMEWORK-2026-07.md"
  "design/MULTI-DEVICE-OPERATION-2026-07.md"
  "design/ONBOARDING-FLOW-2026-07.md"
  "design/LICENSING-AND-INTEGRITY-2026-07.md"
  "design/REGENT-SECURITY-CHANNEL-INVESTIGATION-2026-07.md"
  "design/SECURITY-SIGNAL-CHANNEL-2026-07.md"
  "design/REGENT-GOSSIP-VALIDATION-2026-07.md"
)

# Strip markdown to reading-friendly plain text.
preprocess() {
  # Drop fenced code blocks entirely, then strip inline markdown.
  awk 'BEGIN{fence=0} /^```/{fence=!fence; next} !fence' "$1" | \
    sed -E \
      -e 's/^#+[[:space:]]*//' \
      -e 's/\*\*([^*]+)\*\*/\1/g' \
      -e 's/\*([^*]+)\*/\1/g' \
      -e 's/`([^`]+)`/\1/g' \
      -e 's/\[([^]]+)\]\([^)]+\)/\1/g' \
      -e 's/^---+$//' \
      -e 's/^[[:space:]]*[-*][[:space:]]+/- /' \
      -e 's/\|/, /g' \
      -e 's/&mdash;/—/g' \
      -e 's/&nbsp;/ /g' \
      -e 's/&amp;/and/g' \
      -e '/^[[:space:]]*$/d'
}

TOTAL=${#DOCS[@]}
COUNT=0
SUCCESS=0
FAILED=()
START_TIME=$(date +%s)

echo "======================================================================"
echo "ZeroPoint July 2026 batch → MP3"
echo "Voice: en_US-amy-medium @ 1.5x  |  Output: $OUT_DIR"
echo "Documents: $TOTAL"
echo "======================================================================"
echo ""

for doc in "${DOCS[@]}"; do
  COUNT=$((COUNT + 1))
  path="$DOCS_ROOT/$doc"
  base=$(basename "$doc" .md)
  outfile="$OUT_DIR/$base.mp3"

  printf "[%2d/%d] %s\n" "$COUNT" "$TOTAL" "$base"

  if [ ! -f "$path" ]; then
    echo "        NOT FOUND — skipped"
    FAILED+=("$doc (not found)")
    continue
  fi

  tmp_txt="/tmp/piper-input-$$.txt"
  tmp_wav="/tmp/piper-out-$$.wav"
  tmp_err="/tmp/piper-err-$$.log"

  preprocess "$path" > "$tmp_txt"

  chars=$(wc -c < "$tmp_txt" | tr -d ' ')
  printf "        text: %s chars ... " "$chars"

  # Synthesize to WAV.
  if ! "$PIPER" --model "$MODEL" --length_scale "$LENGTH_SCALE" \
       --output_file "$tmp_wav" < "$tmp_txt" 2>"$tmp_err"; then
    echo "PIPER FAILED"
    echo "        --- piper stderr ---"
    sed 's/^/        /' "$tmp_err"
    FAILED+=("$doc (piper failed)")
    rm -f "$tmp_txt" "$tmp_wav" "$tmp_err"
    continue
  fi

  # Convert to MP3.
  if ! ffmpeg -y -loglevel error -i "$tmp_wav" \
       -codec:a libmp3lame -b:a 128k "$outfile" 2>"$tmp_err"; then
    echo "FFMPEG FAILED"
    echo "        --- ffmpeg stderr ---"
    sed 's/^/        /' "$tmp_err"
    FAILED+=("$doc (ffmpeg failed)")
    rm -f "$tmp_txt" "$tmp_wav" "$tmp_err"
    continue
  fi

  rm -f "$tmp_txt" "$tmp_wav" "$tmp_err"

  SUCCESS=$((SUCCESS + 1))
  size=$(du -h "$outfile" | cut -f1)
  duration=$(ffprobe -v error -show_entries format=duration \
             -of default=noprint_wrappers=1:nokey=1 "$outfile" 2>/dev/null \
             | awk '{printf "%dm%02ds", $1/60, $1%60}')
  printf "OK  (%s, %s)\n" "$size" "$duration"
done

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
ELAPSED_MIN=$((ELAPSED / 60))
ELAPSED_SEC=$((ELAPSED % 60))

echo ""
echo "======================================================================"
printf "Complete: %d/%d succeeded in %dm%02ds\n" "$SUCCESS" "$TOTAL" "$ELAPSED_MIN" "$ELAPSED_SEC"
if [ ${#FAILED[@]} -gt 0 ]; then
  echo ""
  echo "Failed:"
  for f in "${FAILED[@]}"; do
    echo "  - $f"
  done
fi
echo ""
echo "Files: $OUT_DIR"
echo "======================================================================"
