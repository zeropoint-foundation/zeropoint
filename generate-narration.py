#!/usr/bin/env python3
"""
generate-narration.py  (v2 — full-content extraction)
Extracts all narration-worthy content blocks from whitepaper.html:
  <p>, <ul>, <ol>, <table>, <blockquote>, <pre>

Generates:
1. narration-script.txt  — clean text per paragraph with filenames
2. generate-audio.sh     — bash script to run Piper TTS on every paragraph
3. Updates SECTION_MAP expected counts based on actual extraction

Usage: cd ~/projects/zeropoint && python3 generate-narration.py
"""

import re
import os
import sys
from html.parser import HTMLParser
from pathlib import Path

# ─── Configuration ───────────────────────────────────────────────
HTML_FILE = "zeropoint.global/whitepaper.html"
OUTPUT_SCRIPT = "narration-script.txt"
OUTPUT_AUDIO_SH = "generate-audio.sh"
OUTPUT_SECTION_MAP = "section-map-update.js"
AUDIO_DIR = "zeropoint.global/assets/narration/wp"

PIPER_BIN = "/Users/kenrom/anaconda3/bin/piper"
PIPER_MODEL_DIR = "/Users/kenrom/projects/zeropoint/models/piper"
PIPER_VOICE = "amy"
PIPER_LENGTH_SCALE = 0.6993  # 1/1.43 = 1.43x speed (1.3 * 1.1)
PIPER_NOISE_SCALE = 0.550    # Expressive but clean — no noise artifacts
PIPER_NOISE_W = 0.510        # Tighter phoneme variation
PIPER_SENTENCE_SILENCE = 0.30

# Section definitions (id, prefix, title)
# Expected paragraph counts will be computed from actual extraction.
SECTIONS = [
    ("abstract", "wp-abstract", "Abstract"),
    ("s0",  "wp-s0",  "Why This Exists — The Portable Trust Thesis"),
    ("s1",  "wp-s1",  "Problem Statement"),
    ("s2",  "wp-s2",  "Design Goals"),
    ("s3",  "wp-s3",  "System Overview"),
    ("s4",  "wp-s4",  "Receipts and Chains"),
    ("s5",  "wp-s5",  "Governance Model"),
    ("s6",  "wp-s6",  "Threat Model"),
    ("s7",  "wp-s7",  "Transport Integrations"),
    ("s8",  "wp-s8",  "The Presence Plane"),
    ("s9",  "wp-s9",  "Implementation Status"),
    ("s10", "wp-s10", "Adoption Paths"),
    ("s11", "wp-s11", "Roadmap"),
    ("s12", "wp-s12", "Ethics, Non-Goals, and Misuse Resistance"),
    ("s13", "wp-s13", "Conclusion"),
]

# Tags that constitute a narration unit (top-level content blocks)
NARRATION_TAGS = {"p", "ul", "ol", "blockquote", "pre"}


# ─── HTML Parser ─────────────────────────────────────────────────
class WhitepaperParser(HTMLParser):
    """
    Extracts top-level content blocks from <article> organized by <h2> sections.
    A "narration unit" is any top-level <p>, <ul>, <ol>, <blockquote>, or <pre>
    that is a direct child of the section flow (not nested inside another
    narration tag). Tables are deliberately excluded — TTS reads them incoherently.
    """

    def __init__(self):
        super().__init__()
        self.sections = {}           # section_id -> [text_blocks]
        self.current_section = None
        self.in_article = False
        self.skip_depth = 0          # depth counter for skipped containers (toc, etc.)

        # Narration block tracking
        self.capture_tag = None      # which narration tag we're inside
        self.capture_depth = 0       # nesting depth for that tag
        self.capture_text = []       # accumulated text
        self.nesting_depth = 0       # depth of narration tags (to skip nested)

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)

        if tag == "article":
            self.in_article = True
            return

        if not self.in_article:
            return

        # Skip containers that should not be narrated (TOC, etc.)
        css_class = attrs_dict.get("class", "")
        if tag == "div" and "toc" in css_class.split():
            self.skip_depth += 1
            return
        if self.skip_depth > 0:
            if tag == "div":
                self.skip_depth += 1
            return

        # Track section boundaries via <h2>
        if tag == "h2":
            # Flush any open capture
            self._flush_capture()
            h2_id = attrs_dict.get("id", "")
            if h2_id.startswith("appendix"):
                self.in_article = False
                return
            section_ids = [s[0] for s in SECTIONS]
            if h2_id in section_ids:
                self.current_section = h2_id
                if h2_id not in self.sections:
                    self.sections[h2_id] = []

        # Skip <h3> sub-section headers — not narration units
        if tag == "h3":
            self._flush_capture()
            return

        # Start capturing a narration block
        if tag in NARRATION_TAGS and self.current_section:
            # Skip elements marked data-no-narrate
            if "data-no-narrate" in attrs_dict:
                return
            if self.capture_tag is None:
                # Top-level narration block
                self.capture_tag = tag
                self.capture_depth = 1
                self.capture_text = []
            elif self.capture_tag == tag:
                # Nested same tag (e.g., <ul> inside <ul>)
                self.capture_depth += 1

        # If we're inside a capture, just accumulate

    def handle_endtag(self, tag):
        if tag == "article":
            self._flush_capture()
            self.in_article = False
            return

        # Track end of skipped containers
        if self.skip_depth > 0 and tag == "div":
            self.skip_depth -= 1
            return

        if self.capture_tag == tag:
            self.capture_depth -= 1
            if self.capture_depth == 0:
                self._flush_capture()

    def handle_data(self, data):
        if self.skip_depth > 0:
            return
        if self.capture_tag is not None:
            self.capture_text.append(data)

    def handle_entityref(self, name):
        if self.capture_tag is not None:
            entities = {"mdash": "—", "ndash": "–", "amp": "&",
                        "lt": "<", "gt": ">", "nbsp": " ", "quot": '"'}
            self.capture_text.append(entities.get(name, f"&{name};"))

    def handle_charref(self, name):
        if self.capture_tag is not None:
            try:
                if name.startswith("x"):
                    c = chr(int(name[1:], 16))
                else:
                    c = chr(int(name))
                self.capture_text.append(c)
            except (ValueError, OverflowError):
                self.capture_text.append(f"&#{name};")

    def _flush_capture(self):
        """Finalize current narration block and add to section."""
        if self.capture_tag is not None and self.current_section:
            text = "".join(self.capture_text).strip()
            if text:
                self.sections[self.current_section].append(text)
        self.capture_tag = None
        self.capture_depth = 0
        self.capture_text = []


def clean_text(text):
    """Clean extracted text for TTS narration."""
    # Normalize whitespace (collapse runs of spaces/newlines)
    text = re.sub(r'\s+', ' ', text).strip()

    # ─── Pronunciation fixes for Piper TTS ───────────────────────
    # Add entries here as needed: { "written form": "phonetic form" }
    PRONUNCIATION_FIXES = {
        "provenance": "prov-eh-nance",
    }
    for word, phonetic in PRONUNCIATION_FIXES.items():
        text = re.sub(re.escape(word), phonetic, text, flags=re.IGNORECASE)

    # Clean residual entities
    text = text.replace("&amp;", "&")
    text = text.replace("&lt;", "<")
    text = text.replace("&gt;", ">")
    return text


def list_voices():
    """List available Piper models and exit."""
    model_dir = Path(PIPER_MODEL_DIR)
    if not model_dir.exists():
        print(f"Model directory not found: {PIPER_MODEL_DIR}")
        return
    models = sorted(model_dir.glob("*.onnx"))
    if not models:
        print(f"No .onnx models found in {PIPER_MODEL_DIR}")
        print("Download voices from: https://github.com/rhasspy/piper/blob/master/VOICES.md")
        return
    print(f"Available Piper voices in {PIPER_MODEL_DIR}:\n")
    for m in models:
        name = m.stem  # e.g. en_GB-alan-medium
        size_mb = m.stat().st_size / (1024 * 1024)
        print(f"  {name:40s}  ({size_mb:.1f} MB)")
    print(f"\nTo use a specific voice:")
    print(f"  VOICE=alan bash generate-audio.sh")
    print(f"\nOpenAI 'Echo' is a deep male voice. Closest Piper matches:")
    print(f"  en_US-ryan-medium    — clear American male")
    print(f"  en_GB-alan-medium    — British male (you have this)")
    print(f"  en_US-hfc_male-medium — American male, neutral")
    print(f"\nDownload: https://huggingface.co/rhasspy/piper-voices/tree/main/en/en_US")


def main():
    if "--voices" in sys.argv or "--list" in sys.argv:
        list_voices()
        return

    # Parse HTML
    html_path = Path(HTML_FILE)
    if not html_path.exists():
        print(f"ERROR: {HTML_FILE} not found. Run from repo root.")
        return

    with open(html_path, "r", encoding="utf-8") as f:
        html = f.read()

    parser = WhitepaperParser()
    parser.feed(html)

    # ─── Generate narration-script.txt ───────────────────────────
    lines = []
    lines.append("=" * 70)
    lines.append("ZEROPOINT WHITEPAPER v1.1 — NARRATION SCRIPT (full content)")
    lines.append("Generated for Piper TTS")
    lines.append("Includes: <p>, <ul>, <ol>, <table>, <blockquote>, <pre>")
    lines.append("=" * 70)
    lines.append("")

    total = 0
    summary = []
    section_counts = {}

    for section_id, prefix, title in SECTIONS:
        paragraphs = parser.sections.get(section_id, [])
        count = len(paragraphs)
        total += count
        section_counts[section_id] = count

        lines.append("")
        lines.append(f"=== SECTION: {title} ({prefix}) — {count} paragraphs ===")
        lines.append("")

        for i, text in enumerate(paragraphs, 1):
            filename = f"{prefix}-p{i:02d}.mp3"
            cleaned = clean_text(text)
            lines.append(f"--- {filename} ---")
            lines.append(cleaned)
            lines.append("")

        summary.append(f"  {prefix:16s} {title:50s} {count:3d}")

    lines.append("")
    lines.append("=" * 70)
    lines.append("SUMMARY")
    lines.append("=" * 70)
    for s in summary:
        lines.append(s)
    lines.append(f"\n  TOTAL: {total} paragraphs")

    with open(OUTPUT_SCRIPT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"Written: {OUTPUT_SCRIPT} ({total} paragraphs)")

    # ─── Generate section-map-update.js ──────────────────────────
    # This is a snippet you can paste into whitepaper.html
    map_lines = ["  // Updated section map — paste into whitepaper.html",
                 "  const sections = ["]
    for section_id, prefix, title in SECTIONS:
        count = section_counts.get(section_id, 0)
        escaped_title = title.replace("'", "\\'")
        map_lines.append(
            f"    {{ id: '{section_id}',{' ' * max(1, 10-len(section_id))}"
            f"prefix: '{prefix}',{' ' * max(1, 14-len(prefix))}"
            f"title: '{escaped_title}',{' ' * max(1, 55-len(escaped_title))}"
            f"paragraphs: {count:3d} }},"
        )
    map_lines.append("  ];")
    with open(OUTPUT_SECTION_MAP, "w", encoding="utf-8") as f:
        f.write("\n".join(map_lines))
    print(f"Written: {OUTPUT_SECTION_MAP}")

    # ─── Generate generate-audio.sh ──────────────────────────────
    sh_lines = []
    sh_lines.append("#!/usr/bin/env bash")
    sh_lines.append("#")
    sh_lines.append("# generate-audio.sh — Produce all whitepaper narration via Piper TTS")
    sh_lines.append(f"# Total: {total} paragraphs across {len(SECTIONS)} sections")
    sh_lines.append("# Usage: cd ~/projects/zeropoint && bash generate-audio.sh")
    sh_lines.append("#")
    sh_lines.append("# Options:")
    sh_lines.append("#   SKIP_EXISTING=1 bash generate-audio.sh  — skip existing files")
    sh_lines.append("#   SECTION=s8 bash generate-audio.sh        — only generate one section")
    sh_lines.append("#")
    sh_lines.append(f'PIPER="{PIPER_BIN}"')
    sh_lines.append(f'MODEL_DIR="{PIPER_MODEL_DIR}"')
    sh_lines.append(f'AUDIO_DIR="{AUDIO_DIR}"')
    sh_lines.append('SKIP_EXISTING="${SKIP_EXISTING:-0}"')
    sh_lines.append('SECTION="${SECTION:-}"')
    sh_lines.append("")
    sh_lines.append(f"# Preferred voice: {PIPER_VOICE}")
    sh_lines.append(f'VOICE="${{VOICE:-{PIPER_VOICE}}}"')
    sh_lines.append("")
    sh_lines.append("# Find model matching voice name, fall back to any .onnx")
    sh_lines.append('MODEL=$(ls "$MODEL_DIR"/*"$VOICE"*.onnx 2>/dev/null | head -1)')
    sh_lines.append('if [ -z "$MODEL" ]; then')
    sh_lines.append('  MODEL=$(ls "$MODEL_DIR"/*.onnx 2>/dev/null | head -1)')
    sh_lines.append('  if [ -z "$MODEL" ]; then')
    sh_lines.append('    echo "ERROR: No .onnx model found in $MODEL_DIR"')
    sh_lines.append('    exit 1')
    sh_lines.append('  fi')
    sh_lines.append('  echo "WARNING: No model matching \\"$VOICE\\" found, using: $MODEL"')
    sh_lines.append("fi")
    sh_lines.append('echo "Using model: $MODEL"')
    sh_lines.append("")
    sh_lines.append('mkdir -p "$AUDIO_DIR"')
    sh_lines.append("")
    sh_lines.append("generated=0")
    sh_lines.append("skipped=0")
    sh_lines.append("failed=0")
    sh_lines.append("")
    sh_lines.append('generate() {')
    sh_lines.append('  local filename="$1"')
    sh_lines.append('  local text="$2"')
    sh_lines.append('  local outpath="$AUDIO_DIR/$filename"')
    sh_lines.append('')
    sh_lines.append('  if [ "$SKIP_EXISTING" = "1" ] && [ -f "$outpath" ]; then')
    sh_lines.append('    skipped=$((skipped + 1))')
    sh_lines.append('    return')
    sh_lines.append('  fi')
    sh_lines.append('')
    sh_lines.append('  echo "Generating: $filename"')
    sh_lines.append(f'  echo "$text" | "$PIPER" --model "$MODEL" '
                     f'--length_scale {PIPER_LENGTH_SCALE} '
                     f'--noise_scale {PIPER_NOISE_SCALE} '
                     f'--noise_w {PIPER_NOISE_W} '
                     f'--sentence_silence {PIPER_SENTENCE_SILENCE} '
                     f'--output_file "$outpath" 2>/dev/null')
    sh_lines.append('  if [ $? -eq 0 ]; then')
    sh_lines.append('    generated=$((generated + 1))')
    sh_lines.append('  else')
    sh_lines.append('    echo "  FAILED: $filename"')
    sh_lines.append('    failed=$((failed + 1))')
    sh_lines.append('  fi')
    sh_lines.append('}')
    sh_lines.append("")

    for section_id, prefix, title in SECTIONS:
        paragraphs = parser.sections.get(section_id, [])
        if not paragraphs:
            sh_lines.append(f'# === {title} ({prefix}) — no narration content ===')
            sh_lines.append("")
            continue

        # Section filter support
        sh_lines.append(f'# === {title} ({prefix}) — {len(paragraphs)} paragraphs ===')
        sh_lines.append(f'if [ -z "$SECTION" ] || [ "$SECTION" = "{section_id}" ] || [ "$SECTION" = "{prefix}" ]; then')

        for i, text in enumerate(paragraphs, 1):
            filename = f"{prefix}-p{i:02d}.mp3"
            cleaned = clean_text(text)
            escaped = cleaned.replace("'", "'\\''")
            sh_lines.append(f"  generate '{filename}' '{escaped}'")

        sh_lines.append("fi")
        sh_lines.append("")

    sh_lines.append('echo ""')
    sh_lines.append('echo "Done. Generated: $generated, Skipped: $skipped, Failed: $failed"')

    with open(OUTPUT_AUDIO_SH, "w", encoding="utf-8") as f:
        f.write("\n".join(sh_lines))
    os.chmod(OUTPUT_AUDIO_SH, 0o755)
    print(f"Written: {OUTPUT_AUDIO_SH}")
    print(f"\nWorkflow:")
    print(f"  1. Review narration-script.txt for accuracy")
    print(f"  2. Paste section-map-update.js counts into whitepaper.html")
    print(f"  3. Run: bash generate-audio.sh")
    print(f"     Or:  SECTION=s8 bash generate-audio.sh  (just Presence Plane)")


if __name__ == "__main__":
    main()
