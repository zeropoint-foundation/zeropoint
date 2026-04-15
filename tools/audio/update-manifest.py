#!/usr/bin/env python3
"""
update-manifest.py — Build or refresh audio-manifest.json.

Imports the generator modules to extract source texts directly (no
regex parsing), hashes source text + rendered files, and writes the
manifest. Designed to be run after rendering and before committing.

Usage:
    python3 tools/audio/update-manifest.py              # all domains
    python3 tools/audio/update-manifest.py --domain onboard  # one domain
    python3 tools/audio/update-manifest.py --dry-run     # show what would change

See docs/audio-pipeline.md for the full specification.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
MANIFEST_PATH = REPO_ROOT / "audio-manifest.json"

# ── Domain registry ──────────────────────────────────────────────
#
# Each domain maps to:
#   generator:  path to the Python script with a NARRATIONS list
#   output_dir: where rendered MP3s live (relative to REPO_ROOT)
#   voice_map:  callable that returns the voice name for a filename,
#               or a static voice name string

DOMAINS = {}


def _onboard_voice(filename: str) -> str:
    """Onboard uses dual voices: Amy for even steps, Kusal for odd + recovery."""
    try:
        spec = importlib.util.spec_from_file_location(
            "gen_onboard", REPO_ROOT / "generate-narration-onboard.py"
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return getattr(mod, "STEP_VOICE", {}).get(filename, "amy")
    except Exception:
        return "amy"


def _onboard_params(voice: str) -> dict:
    """Return Piper params for a given voice in the onboard domain."""
    try:
        spec = importlib.util.spec_from_file_location(
            "gen_onboard", REPO_ROOT / "generate-narration-onboard.py"
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        voices = getattr(mod, "VOICES", {})
        v = voices.get(voice, {})
        return {
            "length_scale": v.get("length_scale", 0.7692),
            "noise_scale": v.get("noise_scale", 0.360),
            "noise_w": v.get("noise_w", 0.930),
            "sentence_silence": v.get("sentence_silence", 0.30),
        }
    except Exception:
        return {
            "length_scale": 0.7692,
            "noise_scale": 0.360,
            "noise_w": 0.930,
            "sentence_silence": 0.30,
        }


DOMAINS["onboard"] = {
    "generator": REPO_ROOT / "generate-narration-onboard.py",
    "output_dir": "assets/narration/onboard",
    "voice_fn": _onboard_voice,
    "params_fn": _onboard_params,
    "piper_model_fn": lambda v: "en_US-amy-medium" if v == "amy" else "kusal",
}

DOMAINS["whitepaper"] = {
    "generator": REPO_ROOT / "generate-narration.py",
    "output_dir": "zeropoint.global/assets/narration/wp",
    "voice_fn": lambda _: "amy",
    "params_fn": lambda _: {
        "length_scale": 0.6993,
        "noise_scale": 0.55,
        "noise_w": 0.51,
        "sentence_silence": 0.30,
    },
    "piper_model_fn": lambda _: "en_US-amy-medium",
}


# ── Helpers ──────────────────────────────────────────────────────

def sha256_str(text: str) -> str:
    """SHA-256 of a UTF-8 string (no trailing newline)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def blake3_file(path: Path) -> str | None:
    """BLAKE3 hash of a file. Returns None if unavailable."""
    try:
        import blake3 as _blake3

        return _blake3.blake3(path.read_bytes()).hexdigest()
    except ImportError:
        pass
    # Fall back to b3sum CLI
    try:
        result = subprocess.run(
            ["b3sum", "--no-names", str(path)],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except FileNotFoundError:
        pass
    return None


def file_size(path: Path) -> int | None:
    try:
        return path.stat().st_size
    except OSError:
        return None


def extract_narrations(generator_path: Path) -> list[tuple[str, str]]:
    """Import a generator module and return its NARRATIONS list."""
    spec = importlib.util.spec_from_file_location("gen", str(generator_path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    narrations = getattr(mod, "NARRATIONS", [])
    return [(n[0], n[1]) for n in narrations if isinstance(n, (list, tuple)) and len(n) >= 2]


# ── Main ─────────────────────────────────────────────────────────

def build_entries(domain_name: str, domain_cfg: dict) -> list[dict]:
    """Build manifest entries for a single domain."""
    gen_path = domain_cfg["generator"]
    if not gen_path.exists():
        print(f"  ⚠ Generator not found: {gen_path}", file=sys.stderr)
        return []

    narrations = extract_narrations(gen_path)
    output_dir = REPO_ROOT / domain_cfg["output_dir"]
    voice_fn = domain_cfg["voice_fn"]
    params_fn = domain_cfg["params_fn"]
    model_fn = domain_cfg["piper_model_fn"]

    entries = []
    for filename, text in narrations:
        voice = voice_fn(filename)
        params = params_fn(voice)
        rel_path = f"{domain_cfg['output_dir']}/{filename}"
        full_path = output_dir / filename

        entry = {
            "domain": domain_name,
            "file": rel_path,
            "source_text_sha256": sha256_str(text),
            "voice": voice,
            "params": params,
            "piper_model": model_fn(voice),
        }

        if full_path.exists():
            entry["render_blake3"] = blake3_file(full_path) or ""
            entry["size_bytes"] = file_size(full_path)
            entry["rendered_at"] = datetime.fromtimestamp(
                full_path.stat().st_mtime, tz=timezone.utc
            ).isoformat()
        else:
            entry["render_blake3"] = ""
            entry["size_bytes"] = None
            entry["rendered_at"] = None

        entries.append(entry)

    return entries


def main():
    parser = argparse.ArgumentParser(description="Update audio-manifest.json")
    parser.add_argument("--domain", help="Only update a specific domain")
    parser.add_argument("--dry-run", action="store_true", help="Print changes without writing")
    args = parser.parse_args()

    # Load existing manifest (if any) for merge
    existing = {}
    if MANIFEST_PATH.exists():
        try:
            data = json.loads(MANIFEST_PATH.read_text())
            for e in data.get("entries", []):
                existing[e["file"]] = e
        except (json.JSONDecodeError, KeyError):
            pass

    # Build new entries
    target_domains = {args.domain: DOMAINS[args.domain]} if args.domain else DOMAINS

    new_entries = {}
    for name, cfg in target_domains.items():
        print(f"Processing domain: {name}")
        domain_entries = build_entries(name, cfg)
        for e in domain_entries:
            new_entries[e["file"]] = e
        print(f"  {len(domain_entries)} entries")

    # Merge: new entries override existing for processed domains;
    # entries from unprocessed domains are preserved.
    processed_domains = set(target_domains.keys())
    merged = {}
    for key, entry in existing.items():
        if entry.get("domain") not in processed_domains:
            merged[key] = entry
    merged.update(new_entries)

    manifest = {
        "version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "entries": sorted(merged.values(), key=lambda e: (e["domain"], e["file"])),
    }

    if args.dry_run:
        added = set(new_entries) - set(existing)
        updated = set(new_entries) & set(existing)
        removed = {k for k, v in existing.items() if v.get("domain") in processed_domains} - set(
            new_entries
        )
        print(f"\nDry run: {len(added)} added, {len(updated)} updated, {len(removed)} removed")
        for a in sorted(added):
            print(f"  + {a}")
        for r in sorted(removed):
            print(f"  - {r}")
    else:
        MANIFEST_PATH.write_text(json.dumps(manifest, indent=2) + "\n")
        print(f"\nWrote {len(manifest['entries'])} entries to {MANIFEST_PATH}")


if __name__ == "__main__":
    main()
