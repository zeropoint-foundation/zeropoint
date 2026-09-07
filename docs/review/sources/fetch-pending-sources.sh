#!/usr/bin/env bash
#
# fetch-pending-sources.sh — pin the four outstanding review sources.
#
# Why this script exists: the Cowork session that verified these documents'
# licence terms cannot download them. web_fetch results are not reachable from
# its bash sandbox, and its standing content restriction forbids retrieving URLs
# with curl/wget/an HTTP library. Both constraints are structural. So the terms
# check happened there (see SOURCES.md) and the retrieval happens here.
#
# What it does:
#   - downloads the three documents whose terms permit committing a full copy
#   - fetches the fourth (arXiv) to a temp path, hashes it, and DELETES it —
#     the arXiv non-exclusive licence does not grant redistribution
#   - prints SHA-256 for all four and emits manifest rows ready to paste
#
# Run from the repo root:  ./docs/review/sources/fetch-pending-sources.sh
#
# Terms verified 2026-08-18. See docs/review/sources/SOURCES.md for the
# verbatim licence text and the per-document verdict.

set -euo pipefail

DEST="docs/review/sources"
RETRIEVED="$(date -u +%Y-%m-%d)"

if [[ ! -d "$DEST" ]]; then
  echo "error: run this from the repo root (expected $DEST/ to exist)" >&2
  exit 1
fi

command -v curl >/dev/null || { echo "error: curl not found" >&2; exit 1; }

# sha256sum on Linux, shasum -a 256 on macOS
if command -v sha256sum >/dev/null; then
  sha256() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null; then
  sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  echo "error: no sha256sum or shasum on PATH" >&2; exit 1
fi

fetch() { # url, output path
  echo "  fetching $(basename "$2") ..." >&2
  curl -fsSL --retry 3 --retry-delay 2 --max-time 120 -o "$2" "$1"
}

declare -a ROWS=()

echo "== committable (terms permit a full, unmodified copy) ==" >&2

# --- 1. NIST SP 800-239 ipd ---------------------------------------------------
# "not subject to copyright in the United States"; attribution appreciated.
NIST_URL="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-239.ipd.pdf"
NIST_OUT="$DEST/NIST.SP.800-239.ipd.pdf"
fetch "$NIST_URL" "$NIST_OUT"
NIST_SHA="$(sha256 "$NIST_OUT")"
ROWS+=("NIST.SP.800-239.ipd.pdf|$NIST_URL|$NIST_SHA|committed")

# --- 2. draft-niyikiza-oauth-attenuating-agent-tokens-01 ----------------------
# IETF TLP 5.0 section 3.c: copy/distribute in full and without modification.
NIY_URL="https://www.ietf.org/archive/id/draft-niyikiza-oauth-attenuating-agent-tokens-01.txt"
NIY_OUT="$DEST/draft-niyikiza-oauth-attenuating-agent-tokens-01.txt"
fetch "$NIY_URL" "$NIY_OUT"
NIY_SHA="$(sha256 "$NIY_OUT")"
ROWS+=("draft-niyikiza-oauth-attenuating-agent-tokens-01.txt|$NIY_URL|$NIY_SHA|committed")

# --- 3. draft-nelson-agent-delegation-receipts-10 -----------------------------
NEL_URL="https://www.ietf.org/archive/id/draft-nelson-agent-delegation-receipts-10.txt"
NEL_OUT="$DEST/draft-nelson-agent-delegation-receipts-10.txt"
fetch "$NEL_URL" "$NEL_OUT"
NEL_SHA="$(sha256 "$NEL_OUT")"
ROWS+=("draft-nelson-agent-delegation-receipts-10.txt|$NEL_URL|$NEL_SHA|committed")

echo >&2
echo "== hash only (arXiv non-exclusive licence — NOT redistributable) ==" >&2

# --- 4. arXiv 2603.14332 v2 ---------------------------------------------------
# "arXiv.org perpetual non-exclusive license" grants arXiv distribution rights,
# not third-party redistribution. Hash it, record it, do not keep it.
ARX_URL="https://arxiv.org/pdf/2603.14332v2"
ARX_TMP="$(mktemp -t arxiv-2603.14332.XXXXXX)"
trap 'rm -f "$ARX_TMP"' EXIT
fetch "$ARX_URL" "$ARX_TMP"
ARX_SHA="$(sha256 "$ARX_TMP")"
rm -f "$ARX_TMP"
trap - EXIT
echo "  hashed and deleted (not committed, by licence)" >&2
ROWS+=("arXiv 2603.14332v2 (not committed)|$ARX_URL|$ARX_SHA|hash only")

# --- output -------------------------------------------------------------------
echo
echo "SHA-256, retrieved $RETRIEVED"
echo
printf '%s\n' "${ROWS[@]}" | while IFS='|' read -r f u h s; do
  printf '  %-58s %s  [%s]\n' "$f" "$h" "$s"
done

echo
echo "--- manifest rows for SOURCES.md, paste under Pinning status ---"
echo
echo "| File to land | SHA-256 |"
echo "|---|---|"
printf '%s\n' "${ROWS[@]}" | while IFS='|' read -r f u h s; do
  if [[ "$s" == "hash only" ]]; then
    echo "| $f | \`$h\` |"
  else
    echo "| \`$f\` | \`$h\` |"
  fi
done
echo
echo "Retrieved: $RETRIEVED, by the operator, via fetch-pending-sources.sh"
echo "Verified against publisher copy: yes — fetched directly from the publisher"
echo
echo "Note: zeropoint.global files are gitignored; these are not, but check"
echo "      git status before committing in case a pattern catches them."
