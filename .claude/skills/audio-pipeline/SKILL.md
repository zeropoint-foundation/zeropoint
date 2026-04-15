---
name: audio-pipeline
description: "Generate, validate, and manage ZeroPoint audio narration assets. Use this skill whenever the user mentions: audio, narration, TTS, text-to-speech, Piper, voice, mp3, render audio, generate audio, audio manifest, stale renders, voice profiles, onboarding narration, whitepaper narration, or asks about the audio pipeline. Also use when running CI checks for audio assets or updating the audio manifest."
---

# Audio Pipeline Skill

Manage the ZeroPoint audio narration pipeline: generate renders from
source scripts via Piper TTS, track them in `audio-manifest.json`,
and validate integrity via CI-gating checks.

## Quick Reference

Read `docs/audio-pipeline.md` in the repo root for the full spec
(naming conventions, voice profiles, manifest schema, CI modes,
storage strategy). That doc is the source of truth; this skill
provides the operational workflow.

## Domains

| Domain     | Generator                       | Output                              |
|:-----------|:--------------------------------|:------------------------------------|
| onboard    | generate-narration-onboard.py   | assets/narration/onboard/           |
| whitepaper | generate-narration.py           | zeropoint.global/assets/narration/wp/|
| playground | generate-playground-audio.sh    | zeropoint.global/assets/narration/playground/ |
| domains    | (manual)                        | webui-next/public/assets/narration/ |

## Workflows

### 1. Generate renders for a domain

```bash
cd ~/projects/zeropoint

# Onboard example:
python3 generate-narration-onboard.py     # produces generate-audio-onboard.sh
bash generate-audio-onboard.sh            # renders MP3s via Piper

# Whitepaper example:
python3 generate-narration.py             # produces generate-audio.sh
bash generate-audio.sh                    # renders MP3s via Piper
```

Prerequisites: Piper TTS installed, voice models in `models/piper/`.
The generator scripts hard-code the Piper binary path and model
directory. Check `PIPER_BIN` and `PIPER_MODEL_DIR` at the top of each
generator if renders fail with "command not found."

### 2. Update the manifest

After rendering, always update the manifest before committing:

```bash
python3 tools/audio/update-manifest.py                # all domains
python3 tools/audio/update-manifest.py --domain onboard  # one domain
python3 tools/audio/update-manifest.py --dry-run       # preview changes
```

The script imports the generator modules directly to extract source
texts and voice parameters. It hashes source text (SHA-256) and
rendered files (BLAKE3), and writes `audio-manifest.json` at repo
root.

### 3. Validate (CI check)

```bash
bash tools/audio/audio-check.sh              # strict: all 5 checks
bash tools/audio/audio-check.sh --manifest-only  # staleness only
bash tools/audio/audio-check.sh --verbose     # show passing checks
```

Checks:
1. Manifest exists and parses
2. No orphan renders (MP3s without manifest entries)
3. No stale renders (source text SHA-256 mismatch)
4. No missing renders (manifest entries without files)
5. Render hash match (BLAKE3 of file vs manifest)

### 4. Add narration text to an existing domain

Edit the NARRATIONS list in the domain's generator script (e.g.
`generate-narration-onboard.py`). Then re-run the full pipeline:
generate → render → update-manifest → validate.

### 5. Add a new domain

1. Write a generator script following the pattern in
   `generate-narration-onboard.py`. It must expose a `NARRATIONS`
   list of `(filename, text)` tuples at module scope.
2. Add the domain to the `DOMAINS` dict in
   `tools/audio/update-manifest.py`.
3. Add the output directory to `TRACKED_DIRS` in
   `tools/audio/audio-check.sh` (if the directory should be checked
   for orphans in strict mode).
4. Update the domain table in `docs/audio-pipeline.md`.

## Voice Profiles

| Voice | length_scale | noise_scale | noise_w | sentence_silence | Notes              |
|:------|:-------------|:------------|:--------|:-----------------|:-------------------|
| Amy   | 0.7692       | 0.360       | 0.930   | 0.30             | Primary voice      |
| Kusal | 0.8097       | 0.360       | 0.650   | 0.30             | Onboard odd steps  |

Whitepaper uses Amy with different tuning: length_scale=0.6993,
noise_scale=0.55, noise_w=0.51 (faster, crisper for dense content).

## Common Issues

**Piper not found:** Check PIPER_BIN in the generator script. On Mac
with Anaconda: `/Users/kenrom/anaconda3/bin/piper`. On Linux:
wherever `which piper` points.

**Model not found:** Piper models are ONNX files in `models/piper/`.
The generator scripts glob for `*amy*medium*.onnx` etc. Verify with
`ls models/piper/*.onnx`.

**BLAKE3 not available for manifest:** Install via
`pip install blake3` or `cargo install b3sum`.

**Render sounds different after update:** Piper output is
deterministic for identical (text + params + model). If the audio
changed, one of those three changed. Compare `params` in the manifest
entry against the voice profile table above.

**"stale" in CI but text didn't change:** The manifest compares
SHA-256 of the exact text string. Whitespace changes, trailing
newlines, or Python string concatenation changes all alter the hash.
