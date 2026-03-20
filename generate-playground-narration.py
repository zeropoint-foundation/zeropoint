#!/usr/bin/env python3
"""
generate-playground-narration.py — Generate MP3s for playground scenario narration.

Reads playground-scripts.md, extracts each script block, and runs it through
Piper TTS to produce MP3 files in assets/narration/playground/.

Usage: cd ~/projects/zeropoint && python3 generate-playground-narration.py

Requires:
  - Piper TTS installed (anaconda3/bin/piper)
  - en_US-amy-medium model in models/piper/
  - ffmpeg for WAV→MP3 conversion
"""

import os
import re
import subprocess
import tempfile
from pathlib import Path

# ─── Configuration ───────────────────────────────────────────────
SCRIPTS_FILE = "zeropoint.global/assets/narration/playground-scripts.md"
OUTPUT_DIR = "zeropoint.global/assets/narration/playground"

PIPER_BIN = "/Users/kenrom/anaconda3/bin/piper"
PIPER_MODEL = "models/piper/en_US-amy-medium.onnx"
PIPER_LENGTH_SCALE = 0.741  # 1/1.35 = 1.35x speed
PIPER_NOISE_SCALE = 0.550
PIPER_NOISE_W = 0.510
PIPER_SENTENCE_SILENCE = 0.30

# ─── Parse scripts ───────────────────────────────────────────────
def parse_scripts(filepath):
    """Parse playground-scripts.md into (filename, text) pairs."""
    scripts = []
    current_file = None
    current_text = []

    with open(filepath) as f:
        for line in f:
            # Match: ### srm-mia.mp3 — Mia's perspective
            match = re.match(r'^###\s+(\S+\.mp3)\s', line)
            if match:
                # Save previous
                if current_file and current_text:
                    scripts.append((current_file, '\n'.join(current_text).strip()))
                current_file = match.group(1).replace('.mp3', '')
                current_text = []
                continue

            # Skip section headers (##) and separators (---)
            if line.startswith('## ') or line.startswith('# ') or line.strip() == '---':
                continue

            # Skip the metadata line at top
            if line.startswith('33 narration') or line.startswith('Generate with'):
                continue

            # Accumulate text
            if current_file:
                current_text.append(line.rstrip())

    # Save last
    if current_file and current_text:
        scripts.append((current_file, '\n'.join(current_text).strip()))

    return scripts

# ─── Generate audio ──────────────────────────────────────────────
def generate_audio(filename, text, output_dir):
    """Generate MP3 from text via Piper TTS."""
    wav_path = os.path.join(output_dir, f"{filename}.wav")
    mp3_path = os.path.join(output_dir, f"{filename}.mp3")

    if os.path.exists(mp3_path):
        print(f"  Skip (exists): {filename}.mp3")
        return True

    print(f"  Generating: {filename}.mp3 ({len(text)} chars)")

    # Run Piper
    try:
        proc = subprocess.run(
            [
                PIPER_BIN,
                "--model", PIPER_MODEL,
                "--output_file", wav_path,
                "--length_scale", str(PIPER_LENGTH_SCALE),
                "--noise_scale", str(PIPER_NOISE_SCALE),
                "--noise_w", str(PIPER_NOISE_W),
                "--sentence_silence", str(PIPER_SENTENCE_SILENCE),
            ],
            input=text,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if proc.returncode != 0:
            print(f"  ERROR (piper): {proc.stderr[:200]}")
            return False
    except Exception as e:
        print(f"  ERROR: {e}")
        return False

    # Convert WAV → MP3
    try:
        subprocess.run(
            ["ffmpeg", "-y", "-i", wav_path, "-codec:a", "libmp3lame", "-qscale:a", "4", mp3_path],
            capture_output=True,
            timeout=60,
        )
        os.remove(wav_path)
    except Exception as e:
        print(f"  WARN (ffmpeg): {e} — keeping WAV")

    return os.path.exists(mp3_path) or os.path.exists(wav_path)

# ─── Main ────────────────────────────────────────────────────────
def main():
    if not os.path.exists(SCRIPTS_FILE):
        print(f"Error: {SCRIPTS_FILE} not found")
        return 1

    if not os.path.exists(PIPER_BIN):
        print(f"Error: Piper not found at {PIPER_BIN}")
        return 1

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    scripts = parse_scripts(SCRIPTS_FILE)
    print(f"Found {len(scripts)} narration scripts\n")

    success = 0
    for filename, text in scripts:
        if generate_audio(filename, text, OUTPUT_DIR):
            success += 1

    print(f"\nDone: {success}/{len(scripts)} generated in {OUTPUT_DIR}/")
    return 0

if __name__ == "__main__":
    exit(main())
