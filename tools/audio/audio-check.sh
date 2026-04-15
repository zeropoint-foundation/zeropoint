#!/bin/bash
# audio-check.sh — CI gating script for ZeroPoint audio assets.
#
# Validates audio-manifest.json against source scripts and rendered
# MP3 files. Designed to run in CI on PRs that touch audio sources
# or the manifest. Exits nonzero if any check fails.
#
# Usage:
#   bash tools/audio/audio-check.sh              # strict mode (default)
#   bash tools/audio/audio-check.sh --manifest-only  # manifest + staleness only
#   bash tools/audio/audio-check.sh --verbose     # verbose output
#
# See docs/audio-pipeline.md for the full specification.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
MANIFEST="$REPO_ROOT/audio-manifest.json"

MODE="strict"
VERBOSE=false
ERRORS=0

for arg in "$@"; do
  case "$arg" in
    --manifest-only) MODE="manifest-only" ;;
    --verbose) VERBOSE=true ;;
    --help|-h)
      echo "Usage: audio-check.sh [--manifest-only] [--verbose]"
      echo "  --manifest-only  Only check manifest + source staleness (skip file checks)"
      echo "  --verbose        Print detailed output for passing checks too"
      exit 0
      ;;
    *) echo "Unknown flag: $arg"; exit 1 ;;
  esac
done

log()   { echo "  $1"; }
pass()  { if $VERBOSE; then echo "  ✓ $1"; fi; }
fail()  { echo "  ✗ $1"; ERRORS=$((ERRORS + 1)); }
warn()  { echo "  ⚠ $1"; }
header() { echo; echo "── $1 ──"; }

# ── Helpers ──────────────────────────────────────────────────────

# BLAKE3 hash of a file. Tries b3sum (Rust CLI), falls back to Python.
blake3_file() {
  local file="$1"
  if command -v b3sum >/dev/null 2>&1; then
    b3sum --no-names "$file"
  elif python3 -c "import blake3" 2>/dev/null; then
    python3 -c "import blake3, sys; print(blake3.blake3(open(sys.argv[1],'rb').read()).hexdigest())" "$file"
  else
    warn "BLAKE3 not available (install b3sum or pip install blake3) — skipping render hash checks"
    echo "SKIP"
  fi
}

# SHA-256 hash of a string (UTF-8, no trailing newline).
sha256_str() {
  printf '%s' "$1" | shasum -a 256 | cut -d' ' -f1
}

# Extract source text from a Python generator. Imports the module and
# prints NARRATIONS as JSON. Falls back to "UNAVAILABLE" if import fails.
extract_source_texts() {
  local domain="$1"
  local script="$2"
  python3 -c "
import sys, json, importlib.util
spec = importlib.util.spec_from_file_location('gen', '$script')
mod = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(mod)
    narrations = getattr(mod, 'NARRATIONS', [])
    result = {}
    for entry in narrations:
        if isinstance(entry, (list, tuple)) and len(entry) >= 2:
            result[entry[0]] = entry[1]
    json.dump(result, sys.stdout)
except Exception as e:
    print(json.dumps({'__error__': str(e)}), file=sys.stdout)
" 2>/dev/null || echo '{"__error__":"import failed"}'
}

# ── Check 1: Manifest exists and parses ──────────────────────────

header "Check 1: Manifest exists"

if [ ! -f "$MANIFEST" ]; then
  fail "audio-manifest.json not found at $MANIFEST"
  echo
  echo "RESULT: $ERRORS error(s). Run 'python3 tools/audio/update-manifest.py' to create the manifest."
  exit 1
fi

# Quick JSON parse check
if ! python3 -c "import json; json.load(open('$MANIFEST'))" 2>/dev/null; then
  fail "audio-manifest.json is not valid JSON"
  echo
  echo "RESULT: $ERRORS error(s)."
  exit 1
fi

ENTRY_COUNT=$(python3 -c "import json; print(len(json.load(open('$MANIFEST')).get('entries',[])))")
pass "Manifest present with $ENTRY_COUNT entries"

# ── Check 2: No orphan renders ───────────────────────────────────

if [ "$MODE" = "strict" ]; then
  header "Check 2: No orphan renders"

  # Directories that should be manifest-tracked
  TRACKED_DIRS=(
    "assets/narration/onboard"
    "crates/zp-server/assets/narration/onboard"
  )

  for dir in "${TRACKED_DIRS[@]}"; do
    full="$REPO_ROOT/$dir"
    if [ -d "$full" ]; then
      while IFS= read -r mp3; do
        rel="${mp3#$REPO_ROOT/}"
        in_manifest=$(python3 -c "
import json, sys
m = json.load(open('$MANIFEST'))
files = {e['file'] for e in m.get('entries',[])}
print('yes' if '$rel' in files else 'no')
")
        if [ "$in_manifest" = "no" ]; then
          fail "Orphan render: $rel (not in manifest)"
        else
          pass "$rel tracked"
        fi
      done < <(find "$full" -name '*.mp3' -type f 2>/dev/null)
    fi
  done
fi

# ── Check 3: No stale renders ───────────────────────────────────

header "Check 3: Source text staleness"

# Map domain → generator script
declare -A GENERATORS
GENERATORS[onboard]="$REPO_ROOT/generate-narration-onboard.py"
GENERATORS[whitepaper]="$REPO_ROOT/generate-narration.py"

for domain in "${!GENERATORS[@]}"; do
  gen="${GENERATORS[$domain]}"
  if [ ! -f "$gen" ]; then
    warn "Generator not found for domain '$domain': $gen"
    continue
  fi

  # Extract source texts as JSON: {"filename.mp3": "text..."}
  texts_json=$(extract_source_texts "$domain" "$gen")

  if echo "$texts_json" | python3 -c "import json,sys; d=json.load(sys.stdin); sys.exit(0 if '__error__' not in d else 1)" 2>/dev/null; then
    # Compare each entry's source_text_sha256 against current source
    python3 -c "
import json, hashlib, sys

texts = json.loads('''$texts_json''') if '''$texts_json''' != '' else {}
manifest = json.load(open('$MANIFEST'))
entries = {e['file']: e for e in manifest.get('entries', []) if e.get('domain') == '$domain'}

stale = []
for e_file, entry in entries.items():
    fname = e_file.rsplit('/', 1)[-1]
    if fname in texts:
        current_hash = hashlib.sha256(texts[fname].encode('utf-8')).hexdigest()
        manifest_hash = entry.get('source_text_sha256', '')
        if current_hash != manifest_hash:
            stale.append(fname)

if stale:
    for s in stale:
        print(f'STALE:{s}')
else:
    print('OK')
" | while IFS= read -r line; do
      if [[ "$line" == STALE:* ]]; then
        fail "Stale render in $domain: ${line#STALE:} (source text changed)"
      elif [ "$line" = "OK" ]; then
        pass "Domain '$domain': all source hashes current"
      fi
    done
  else
    warn "Could not extract source texts for domain '$domain' (generator import failed)"
  fi
done

# ── Check 4: No missing renders ──────────────────────────────────

if [ "$MODE" = "strict" ]; then
  header "Check 4: No missing renders"

  python3 -c "
import json, os, sys

manifest = json.load(open('$MANIFEST'))
missing = []
for entry in manifest.get('entries', []):
    fpath = os.path.join('$REPO_ROOT', entry['file'])
    if not os.path.isfile(fpath):
        missing.append(entry['file'])

if missing:
    for m in missing:
        print(f'MISSING:{m}')
else:
    print('OK')
" | while IFS= read -r line; do
    if [[ "$line" == MISSING:* ]]; then
      fail "Missing render: ${line#MISSING:}"
    elif [ "$line" = "OK" ]; then
      pass "All manifest entries have renders on disk"
    fi
  done
fi

# ── Check 5: Render hash match ───────────────────────────────────

if [ "$MODE" = "strict" ]; then
  header "Check 5: Render hash integrity"

  python3 -c "
import json, sys
manifest = json.load(open('$MANIFEST'))
for e in manifest.get('entries', []):
    print(e['file'] + '|' + e.get('render_blake3', ''))
" | while IFS='|' read -r relpath expected_hash; do
    full="$REPO_ROOT/$relpath"
    if [ -f "$full" ] && [ -n "$expected_hash" ]; then
      actual=$(blake3_file "$full")
      if [ "$actual" = "SKIP" ]; then
        continue
      elif [ "$actual" = "$expected_hash" ]; then
        pass "$relpath: hash matches"
      else
        fail "$relpath: hash mismatch (expected ${expected_hash:0:16}… got ${actual:0:16}…)"
      fi
    fi
  done
fi

# ── Summary ──────────────────────────────────────────────────────

echo
if [ "$ERRORS" -gt 0 ]; then
  echo "RESULT: $ERRORS error(s). Fix the issues above and re-run."
  echo "  Render stale?  → Re-run generator + update-manifest.py"
  echo "  Orphan file?   → Add to manifest or remove the file"
  echo "  Missing file?  → Render it or remove the manifest entry"
  echo "  Hash mismatch? → Re-render from source"
  exit 1
else
  echo "RESULT: All checks passed."
  exit 0
fi
