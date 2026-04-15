# ZeroPoint Audio Asset Pipeline

Standardized methodology for generating, tracking, validating, and
gating audio assets across the ZeroPoint repo. Covers all narration
domains (onboarding, whitepaper, playground, domain narrations) and any
future audio assets.

---

## Architecture

```
 Source Text            Generator Script       Piper TTS Engine       Rendered MP3
 ────────────          ─────────────────      ────────────────       ─────────────
 NARRATIONS list   →   generate-narration-    →   piper --model X   →   assets/narration/
 in .py scripts        {domain}.py produces       --length_scale        {domain}/*.mp3
                       generate-audio-             --noise_scale
                       {domain}.sh                 ...
                                                                     ↓
                                                                 audio-manifest.json
                                                                 (source_hash + render_hash
                                                                  + voice params + timestamp)
                                                                     ↓
                                                                 CI: tools/audio/audio-check.sh
                                                                 (blocks PR if stale/missing)
```

## Domains

| Domain       | Source script                    | Output directory                 | Voices    |
|:-------------|:--------------------------------|:---------------------------------|:----------|
| onboard      | generate-narration-onboard.py   | assets/narration/onboard/        | Amy, Kusal|
| whitepaper   | generate-narration.py           | zeropoint.global/assets/narration/wp/ | Amy  |
| playground   | generate-playground-audio.sh    | zeropoint.global/assets/narration/playground/ | Amy |
| domains      | (manual)                        | webui-next/public/assets/narration/  | Amy    |

## Naming Conventions

Every rendered file follows a domain-specific pattern. These are
enforced by the manifest and CI check:

    onboard:     onboard-{step-name}.mp3       onboard-welcome.mp3
    whitepaper:  wp-{section}-p{nn}.mp3        wp-s3-p08.mp3
    playground:  {scenario}-{agent}.mp3        srm-mia.mp3
    domains:     {domain-name}.mp3             governance.mp3

No spaces, no uppercase, no underscores. Kebab-case for multi-word
step names. Paragraph numbers zero-padded to 2 digits.

## Voice Profiles

Canonical Piper TTS parameters. All generators MUST use these values
(or explicitly document deviations in the manifest entry).

| Voice | Model glob          | length_scale | noise_scale | noise_w | sentence_silence |
|:------|:--------------------|:-------------|:------------|:--------|:-----------------|
| Amy   | en_US-amy-medium    | 0.7692       | 0.360       | 0.930   | 0.30             |
| Kusal | (kusal model)       | 0.8097       | 0.360       | 0.650   | 0.30             |

Amy is the default voice for all domains. Kusal is used for
alternating steps in onboarding narration (odd-numbered steps +
recovery) and any future secondary-voice needs.

## The Manifest: audio-manifest.json

Lives at repo root. Tracked in git. Each entry is a rendered audio
file with enough metadata to verify it's current and correct.

```json
{
  "version": "1.0",
  "generated_at": "2026-04-15T12:00:00Z",
  "entries": [
    {
      "domain": "onboard",
      "file": "assets/narration/onboard/onboard-welcome.mp3",
      "source_text_sha256": "a1b2c3...",
      "render_blake3": "d4e5f6...",
      "voice": "amy",
      "params": {
        "length_scale": 0.7692,
        "noise_scale": 0.360,
        "noise_w": 0.930,
        "sentence_silence": 0.30
      },
      "piper_model": "en_US-amy-medium",
      "rendered_at": "2026-04-13T10:30:00Z",
      "size_bytes": 2834567,
      "duration_seconds": 42.3
    }
  ]
}
```

Field semantics:

- `source_text_sha256` — SHA-256 of the exact narration text string
  (UTF-8 encoded, no trailing newline). Computed by the generator. A
  mismatch means the source text changed and the render is stale.
- `render_blake3` — BLAKE3 of the rendered MP3 file bytes. Confirms
  the file on disk is the one the manifest describes.
- `voice` — which voice profile was used.
- `params` — the Piper parameters. Allows detecting parameter drift
  across generator script edits.
- `piper_model` — model identifier, for reproducibility.
- `rendered_at` — ISO 8601 UTC timestamp of the render.
- `size_bytes`, `duration_seconds` — sanity-check fields. Duration is
  approximate (from ffprobe or similar); absent if unavailable.

## Generation Workflow

### Full render (from scratch)

```bash
cd ~/projects/zeropoint

# 1. Generate the bash runner from the Python source
python3 generate-narration-onboard.py

# 2. Render all MP3s via Piper
bash generate-audio-onboard.sh

# 3. Update the manifest
python3 tools/audio/update-manifest.py --domain onboard

# 4. Verify
bash tools/audio/audio-check.sh
```

### Incremental render (source text changed)

```bash
# Same steps — generate-audio-onboard.sh supports SKIP_EXISTING=1
# to skip files whose source text hasn't changed.
SKIP_EXISTING=1 bash generate-audio-onboard.sh
python3 tools/audio/update-manifest.py --domain onboard
bash tools/audio/audio-check.sh
```

### Adding a new domain

1. Write a generator script following the pattern in
   `generate-narration-onboard.py`.
2. Add the domain to the `DOMAINS` dict in
   `tools/audio/update-manifest.py`.
3. Add the domain to the `DOMAINS` array in
   `tools/audio/audio-check.sh`.
4. Add a row to the table in this document.

## CI Gating: tools/audio/audio-check.sh

Runs in CI on every PR that touches audio source files or the
manifest. Blocks the PR if any check fails.

### Checks performed

1. **Manifest exists** — `audio-manifest.json` must be present and
   parseable.
2. **No orphan renders** — every MP3 in a tracked audio directory
   must have a manifest entry. Unmanifested files fail the check.
3. **No stale renders** — for every manifest entry, recompute
   `source_text_sha256` from the current generator script and compare.
   If the source text changed but the render hash didn't, the render
   is stale.
4. **No missing renders** — every manifest entry must have a
   corresponding file on disk (unless the file is in a gitignored
   directory and CI is in verify-manifest-only mode).
5. **Render hash match** — if the file is present, its BLAKE3 must
   match `render_blake3` in the manifest. A mismatch means the file
   was replaced outside the pipeline.

### CI modes

- `--strict` (default): all 5 checks run; any failure exits nonzero.
- `--manifest-only`: checks 1, 3 only (for repos where MP3s are
  gitignored and only the manifest is tracked).

### Trigger paths

CI should run audio-check when any of these change:

```
audio-manifest.json
generate-narration*.py
generate-audio*.sh
generate-playground-audio.sh
assets/narration/**
crates/zp-server/assets/narration/**
tools/audio/**
```

## Storage Strategy

MP3 files are binary blobs. Two supported strategies:

### Option A: Git LFS (recommended for deployable repos)

Add to `.gitattributes`:
```
assets/narration/**/*.mp3 filter=lfs diff=lfs merge=lfs -text
crates/zp-server/assets/narration/**/*.mp3 filter=lfs diff=lfs merge=lfs -text
```

CI runs `audio-check.sh --strict` (all checks including render hash).
Renders are tracked, deployment is self-contained, no Piper needed at
deploy time.

### Option B: Gitignored + manifest-only (current state for zeropoint.global/)

MP3s stay gitignored. Only `audio-manifest.json` and source scripts
are tracked. CI runs `audio-check.sh --manifest-only` (checks source
staleness only). Renders must be regenerated at deploy time or fetched
from an artifact store.

### Migration path

The manifest format is the same either way. Moving from Option B to
Option A is: `git lfs track "*.mp3"`, commit the renders, switch CI
mode to `--strict`.

## Manifest Update Script: tools/audio/update-manifest.py

Reads the generator scripts, extracts source text + voice params,
hashes the rendered files, and writes `audio-manifest.json`.

```
python3 tools/audio/update-manifest.py                # all domains
python3 tools/audio/update-manifest.py --domain onboard  # one domain
```

The script imports the generator modules to extract NARRATIONS lists
directly (no regex parsing of Python source). For domains whose text
comes from HTML parsing (whitepaper), it re-runs the parser.

## Troubleshooting

**"stale render" in CI but I didn't change the text.**
Voice parameters or Piper model may have changed. Re-render and
update the manifest.

**"orphan render" for a file I just added.**
Run `update-manifest.py` after rendering. The manifest must be
committed alongside the render.

**"render hash mismatch" but I just rendered.**
Piper output is deterministic for identical input + params + model.
If the hash differs, either the model version changed or the params
drifted. Check `piper_model` and `params` in the manifest entry.

**BLAKE3 not available in CI.**
Install via `pip install blake3` or `cargo install b3sum`. The CI
script tries `b3sum` first, falls back to `python3 -c "import blake3"`.
