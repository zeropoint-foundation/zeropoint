# zp-local-model-bench

Benchmarks clear-license local models on Apple Silicon (MLX) against the five measures
ZeroPoint's inference routing actually needs: **decode tok/s, prefill tok/s across context
lengths, structured-output/tool-call reliability, peak memory, and quant-degradation sanity.**

Model selection rationale, the license posture, and the named hardware targets live in
`docs/design/LOCAL-MODEL-SELECTION-2026-07.md`.

## Named targets

- **APOLLO** — the M4 Pro Mac Mini (64GB). This MLX harness runs here. `--target APOLLO` (default).
- **PI5** — the Raspberry Pi 5 (**8GB**, CPU-only). MLX doesn't run on it — PI5 is a **separate
  llama.cpp/GGUF track** (same five measures, different runtime), to be scaffolded later. Don't
  run this script expecting PI5 numbers. On 8GB the limit is CPU speed, not capacity: classifier
  = Qwen3-0.6B (clear) or LFM2.5-230M (elected); light edge work = Qwen3-1.7B.

Clear-license reference set: Apache-2.0 (Qwen) resident/fast tiers; GLM-5.2 (MIT) is a separate
streaming track. Liquid (LFM Open License) is operator-electable via `--include-license-gated`.

## Setup (on APOLLO)

```bash
python3 -m venv ~/.venvs/zpbench && source ~/.venvs/zpbench/bin/activate
pip install -U mlx-lm huggingface_hub
sudo sysctl iogpu.wired_limit_mb=57344     # let ~56GB of the 64GB go to weights+KV
```

## Pull the models (you run these)

Confirm the newest `mlx-community` 4-bit Instruct tag at pull time; these are the safe floor:

```bash
hf download mlx-community/Qwen3-Coder-30B-A3B-Instruct-4bit
hf download mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit      # or Qwen3.6-35B-A3B-Instruct-4bit if present
hf download mlx-community/Qwen3-4B-Instruct-2507-4bit
hf download mlx-community/Qwen3-1.7B-4bit
```

If a tag has moved, edit the `repo` fields in the `MODELS` list at the top of
`zp_local_model_bench.py` — the harness loads by repo id and uses the HF cache.

### Operator-electable (license-gated) — optional

The reference set above is clear-license only (Apache/MIT). Liquid's LFM2.5 models are
*technically* strong for the fast/edge tier but ship under the **LFM Open License v1.0**
(revenue-gated), so they are **operator-electable, not part of the reference stack** —
admitting one is an explicit sovereignty tradeoff (bounded operator sovereignty). To
benchmark them anyway:

```bash
hf download LiquidAI/LFM2.5-8B-A1B-MLX-4bit    # confirm the actual MLX tag
hf download LiquidAI/LFM2.5-230M-MLX-4bit
python zp_local_model_bench.py --include-license-gated
```

They live in the `LICENSE_GATED_MODELS` list in the script, clearly separated from the
clear-license `MODELS`.

## Run

```bash
python zp_local_model_bench.py                       # APOLLO, all models, corpus-scale contexts
python zp_local_model_bench.py --models qwen3-4b,qwen3-1.7b
python zp_local_model_bench.py --contexts 4096,16384,32768,65536,131072   # add 131072 to find the hard wall
python zp_local_model_bench.py --decode-tokens 256 --stamp run1
python zp_local_model_bench.py --include-license-gated              # also run Liquid (Tier B)
```

**This run doubles as the UC-1 / UC-3 feasibility test** (per `DEMONSTRATIVE-USE-CASES-2026-07.md`):
the prefill probe carries a real needle-synthesis task at each context length, and the quality
samples are UC-1 ontology extraction + UC-3 grounded private-doc QA — so the first benchmark also
answers "can APOLLO actually do the flagship jobs, and up to what corpus size?"

`--target` defaults to `APOLLO` and is stamped into the output filenames and report so runs
never get mixed up. Outputs land in `results/` (`<base>` = `<target>-<stamp>`):
- `bench-<base>.md` — the comparison tables (also echoed to stdout)
- `bench-<base>.json` — full structured results (includes target + contexts)
- `samples-<base>.txt` — captured generations for the quant-degradation eyeball

## Reading it

- **decode tok/s** — is this tier interactive (realtime) or background-only?
- **UC-1 feasibility curve** (the prefill table) — each cell is `prefill tok/s / peak GB / ✓|✗`,
  where ✓ means the model located the right corpus section and answered *at that context length*.
  The length where ✓ flips to ✗ (or OOMs) is APOLLO's whole-chain-reflection ceiling — how much
  corpus the flagship use case can actually reason over. **This is the number that matters most.**
- **structured (x/4)** — receipt JSON, tool-call JSON, route classifier, and `uc1_synthesis`.
  A model that can't hold this is not a Regent-emission candidate, regardless of speed.
- **peak GB** — headroom vs the ~48–56GB budget; watch KV cache grow with context.
- **samples file** — read `uc1_ontology_extract` and `uc3_grounded_qa` against each task's
  `EXPECT:` line. A wrong number or fabricated section on UC-3 is int4 grounded-retrieval
  degradation, showing up quietly.

## Notes

- The 128k prefill probe may OOM with a 30B model on 64GB. That's a *result* (your effective
  context ceiling), not a failure — it's recorded per-context and the run continues.
- Written without a Mac to test on before delivery, so it's defensive about mlx-lm API drift
  (lazy imports, getattr stats fallbacks, per-model isolation). If a stat reads as `—` or an
  API differs on your mlx-lm version, that's the expected place to need a one-line fix.
- GLM-5.2 mondo tier is benchmarked separately via its streaming engine (Colibri), not here —
  it needs ~370GB parked on the SSD and is latency-tolerant by nature.
