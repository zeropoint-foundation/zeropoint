#!/usr/bin/env python3
"""
generate-onboard-voice-samples.py — Sage voice palette sample generator

Produces five short MP3 samples — one per voice in the Sage palette —
played by the onboarding wizard's Phase 5.5 (Voice) so the director can
hear each option before choosing.

Output: assets/onboard/voices/{voice_id}-sample.mp3
Runtime: ~/ZeroPoint/assets/onboard/voices/{voice_id}-sample.mp3
URL:     /onboard/voices/{voice_id}-sample.mp3

Engine: kokoro-onnx (light ONNX runtime port; no spacy / no source builds).

Usage:
  cd ~/projects/zeropoint
  # One-time setup — download model + voices file (~330MB total):
  mkdir -p models/kokoro
  curl -L -o models/kokoro/kokoro-v1.0.onnx \\
    https://github.com/thewh1teagle/kokoro-onnx/releases/download/model-files-v1.0/kokoro-v1.0.onnx
  curl -L -o models/kokoro/voices-v1.0.bin \\
    https://github.com/thewh1teagle/kokoro-onnx/releases/download/model-files-v1.0/voices-v1.0.bin
  # Then generate:
  python3 generate-onboard-voice-samples.py

Requires:
  - kokoro-onnx (pip install kokoro-onnx soundfile)
  - ffmpeg on PATH (for WAV → MP3 conversion; brew install ffmpeg)

Refs:
  - docs/STEWARD-WIZARD-SCRIPT-2026-05.md (Phase 5.5 voice palette)
  - docs/AGENT-AS-UX-ARCHITECTURE-2026-05.md (Sage's Jarvis-shaped voice)
  - Task #134 (Kokoro integration)
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

# ─── Configuration ───────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parent
MODEL_PATH = REPO_ROOT / "models" / "kokoro" / "kokoro-v1.0.onnx"
VOICES_PATH = REPO_ROOT / "models" / "kokoro" / "voices-v1.0.bin"
OUTPUT_DIR = REPO_ROOT / "assets" / "onboard" / "voices"
OUTPUT_DIR_ALL = REPO_ROOT / "assets" / "onboard" / "voices" / "all"

# Sample line — Jarvis-shaped: brief, anticipatory, no fawning. Three
# sentences so the voice has time to show timbre, pacing, and cadence.
# Generic on purpose: the wizard plays this before a director has been
# named, so [Name] interpolation isn't possible here.
SAMPLE_LINE = (
    "Welcome aboard. I'm Sage. "
    "This is the voice I'd use with you. "
    "If it suits, we'll proceed. If not, we'll try another."
)

# Voice palette — must match docs/STEWARD-WIZARD-SCRIPT-2026-05.md §5.5
# and the onboard wizard's voice cards.
#
# Kokoro voice naming convention:
#   {region}{gender}_{name}
#     a = American, b = British
#     m = male, f = female
#
# lang code passed to kokoro-onnx:
#   "en-us" for American voices, "en-gb" for British voices.
VOICES = [
    # voice_id,      lang,    label
    ("bm_george",    "en-gb", "British male, warm (Jarvis reference, default)"),
    ("bm_fable",     "en-gb", "British male, drier timbre"),
    ("bf_isabella",  "en-gb", "British female, professional"),
    ("am_michael",   "en-us", "American male, neutral / modern"),
    ("af_nicole",    "en-us", "American female, warm"),
]

# Speed: 1.0 is Kokoro default. Lower = slower / more measured.
# Sage's voice should feel composed, not rushed — try 0.95 first.
SPEED = 0.95

# Full English voice catalog (Kokoro v1.0). Used by --all mode for
# auditioning the whole space before locking in the production palette.
# Voice IDs taken from kokoro-onnx / Kokoro-82M v1.0 release.
ALL_ENGLISH_VOICES = [
    # American Female
    ("af_alloy",    "en-us", "AF · alloy"),
    ("af_aoede",    "en-us", "AF · aoede"),
    ("af_bella",    "en-us", "AF · bella"),
    ("af_heart",    "en-us", "AF · heart"),
    ("af_jessica",  "en-us", "AF · jessica"),
    ("af_kore",     "en-us", "AF · kore"),
    ("af_nicole",   "en-us", "AF · nicole"),
    ("af_nova",     "en-us", "AF · nova"),
    ("af_river",    "en-us", "AF · river"),
    ("af_sarah",    "en-us", "AF · sarah"),
    ("af_sky",      "en-us", "AF · sky"),
    # American Male
    ("am_adam",     "en-us", "AM · adam"),
    ("am_echo",     "en-us", "AM · echo"),
    ("am_eric",     "en-us", "AM · eric"),
    ("am_fenrir",   "en-us", "AM · fenrir"),
    ("am_liam",     "en-us", "AM · liam"),
    ("am_michael",  "en-us", "AM · michael"),
    ("am_onyx",     "en-us", "AM · onyx"),
    ("am_puck",     "en-us", "AM · puck"),
    ("am_santa",    "en-us", "AM · santa"),
    # British Female
    ("bf_alice",    "en-gb", "BF · alice"),
    ("bf_emma",     "en-gb", "BF · emma"),
    ("bf_isabella", "en-gb", "BF · isabella"),
    ("bf_lily",     "en-gb", "BF · lily"),
    # British Male
    ("bm_daniel",   "en-gb", "BM · daniel"),
    ("bm_fable",    "en-gb", "BM · fable"),
    ("bm_george",   "en-gb", "BM · george"),
    ("bm_lewis",    "en-gb", "BM · lewis"),
]


# ─── Generation ──────────────────────────────────────────────────

def ensure_deps() -> None:
    """Fail fast with a clear message if anything is missing."""
    try:
        import kokoro_onnx  # noqa: F401
        import soundfile  # noqa: F401
    except ImportError as e:
        sys.stderr.write(
            f"missing python dep: {e.name}\n"
            f"  install with: pip install kokoro-onnx soundfile\n"
        )
        sys.exit(1)

    if subprocess.run(["which", "ffmpeg"], capture_output=True).returncode != 0:
        sys.stderr.write(
            "ffmpeg not found on PATH\n"
            "  install with: brew install ffmpeg  (macOS)\n"
        )
        sys.exit(1)

    if not MODEL_PATH.exists():
        sys.stderr.write(
            f"model file missing: {MODEL_PATH}\n"
            f"  download with:\n"
            f"    mkdir -p {MODEL_PATH.parent}\n"
            f"    curl -L -o {MODEL_PATH} \\\n"
            f"      https://github.com/thewh1teagle/kokoro-onnx/releases/download/model-files-v1.0/kokoro-v1.0.onnx\n"
        )
        sys.exit(1)

    if not VOICES_PATH.exists():
        sys.stderr.write(
            f"voices file missing: {VOICES_PATH}\n"
            f"  download with:\n"
            f"    curl -L -o {VOICES_PATH} \\\n"
            f"      https://github.com/thewh1teagle/kokoro-onnx/releases/download/model-files-v1.0/voices-v1.0.bin\n"
        )
        sys.exit(1)


def generate_sample(kokoro, voice_id: str, lang: str, out_mp3: Path) -> None:
    """Render one voice sample as MP3."""
    import soundfile as sf

    print(f"  rendering {voice_id} ({lang}) ...")
    samples, sample_rate = kokoro.create(
        SAMPLE_LINE,
        voice=voice_id,
        speed=SPEED,
        lang=lang,
    )

    wav_tmp = out_mp3.with_suffix(".wav")
    sf.write(str(wav_tmp), samples, sample_rate)

    subprocess.run(
        ["ffmpeg", "-y", "-loglevel", "error",
         "-i", str(wav_tmp),
         "-codec:a", "libmp3lame", "-b:a", "96k",
         str(out_mp3)],
        check=True,
    )
    wav_tmp.unlink()
    print(f"    → {out_mp3.relative_to(REPO_ROOT)}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument(
        "--all", action="store_true",
        help="Render every English voice in Kokoro's catalog (audition mode). "
             "Outputs to assets/onboard/voices/all/ so the production palette "
             "in assets/onboard/voices/ is left untouched.",
    )
    args = parser.parse_args()

    ensure_deps()

    voices = ALL_ENGLISH_VOICES if args.all else VOICES
    out_dir = OUTPUT_DIR_ALL if args.all else OUTPUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    from kokoro_onnx import Kokoro
    print(f"Loading model: {MODEL_PATH.name}")
    kokoro = Kokoro(str(MODEL_PATH), str(VOICES_PATH))

    mode_label = "FULL CATALOG audition" if args.all else "Sage palette (production)"
    print(f"Generating {len(voices)} samples — {mode_label}")
    print(f"Sample line: {SAMPLE_LINE!r}")
    print(f"Speed:       {SPEED}")
    print(f"Output dir:  {out_dir.relative_to(REPO_ROOT)}/")
    print()

    failed = []
    for voice_id, lang, label in voices:
        print(f"[{voice_id}] — {label}")
        out_mp3 = out_dir / f"{voice_id}-sample.mp3"
        try:
            generate_sample(kokoro, voice_id, lang, out_mp3)
        except Exception as e:
            print(f"    ✗ failed: {e}")
            failed.append(voice_id)

    print()
    print(f"Done. {len(voices) - len(failed)}/{len(voices)} rendered.")
    if failed:
        print(f"Failed: {', '.join(failed)}")
    print()

    if not args.all:
        print("To deploy to runtime asset dir:")
        print(f"  mkdir -p ~/ZeroPoint/assets/onboard/voices")
        print(f"  cp assets/onboard/voices/*-sample.mp3 ~/ZeroPoint/assets/onboard/voices/")
        print()
        print("Or rely on zp-dev.sh to deploy on next build.")
    else:
        print("Audition all samples in order:")
        print(f"  for f in {out_dir.relative_to(REPO_ROOT)}/*-sample.mp3; do")
        print(f"    echo \"═══ $(basename $f .mp3) ═══\"; afplay \"$f\"; done")


if __name__ == "__main__":
    main()
