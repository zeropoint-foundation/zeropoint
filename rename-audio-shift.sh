#!/usr/bin/env bash
#
# rename-audio-shift.sh
# Renames whitepaper narration audio files to account for new §8 (Presence Plane).
# Old s8→s9, s9→s10, s10→s11, s11→s12, s12→s13
# Run in REVERSE order to avoid filename collisions.
#
# Usage: cd ~/projects/zeropoint && bash rename-audio-shift.sh
#
# Dry-run mode: set DRY_RUN=1 to preview without renaming
#   DRY_RUN=1 bash rename-audio-shift.sh

AUDIO_DIR="zeropoint.global/assets/narration/wp"
DRY_RUN="${DRY_RUN:-0}"

if [ ! -d "$AUDIO_DIR" ]; then
  echo "ERROR: Directory $AUDIO_DIR not found. Run from repo root."
  exit 1
fi

moved=0

# Rename in reverse: s12→s13, s11→s12, s10→s11, s9→s10, s8→s9
for old_num in 12 11 10 9 8; do
  new_num=$((old_num + 1))
  for f in "$AUDIO_DIR"/wp-s${old_num}-p*.mp3; do
    [ -e "$f" ] || continue
    new_f="${f/wp-s${old_num}-/wp-s${new_num}-}"
    if [ "$DRY_RUN" = "1" ]; then
      echo "[DRY] mv $f -> $new_f"
    else
      mv "$f" "$new_f"
      echo "Renamed: $(basename "$f") -> $(basename "$new_f")"
    fi
    moved=$((moved + 1))
  done
done

if [ $moved -eq 0 ]; then
  echo "No audio files found to rename in $AUDIO_DIR"
  echo "(This is expected if audio hasn't been generated yet for those sections)"
else
  echo ""
  echo "Done. $moved files renamed."
  echo "The new s8 slot (The Presence Plane) is now empty and ready for new audio."
fi
