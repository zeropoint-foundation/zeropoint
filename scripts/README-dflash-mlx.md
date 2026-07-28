# DFlash on APOLLO-4 (MLX backend)

Runtime for speculative-decoding acceleration on Apple Silicon. Companion
to `docs/design/MODEL-DOSSIER-2026-07.md` — DFlash is the operational
serialization of a target model's dossier (drafter weights that
byte-identically accelerate the target).

## Install

```
./scripts/install-dflash-mlx.sh
```

Idempotent; creates a project-local venv at `.venvs/dflash-mlx`,
installs `dflash-mlx[bench]`, verifies. Refuses on non-Darwin / non-arm64.

## What ships

- `dflash-mlx` (PyPI, v0.1.7 as of 2026-05-17) — MLX-native port of
  the DFlash speculative-decoding runtime.
- OpenAI-compatible HTTP server on `127.0.0.1:8000/v1` with streaming.
- CLI: `dflash generate` (one-shot), `dflash serve` (server).
- Auto-resolves drafters for registered targets: Qwen3, Qwen3.5, Qwen3.6
  families and Gemma-4 variants.

## Launch a drafter-accelerated server

```
source .venvs/dflash-mlx/bin/activate
dflash serve --model Qwen/Qwen3-8B
```

The first launch pulls the target model weights (~16GB for Qwen3-8B in
bf16) and the drafter checkpoint (`z-lab/Qwen3-8B-DFlash-b16`, ~2GB)
from Hugging Face. Subsequent launches use cached weights.

For a specific target/drafter pairing:

```
dflash serve \
  --model mlx-community/Qwen3.6-27B-4bit \
  --draft z-lab/Qwen3.6-27B-DFlash
```

## Verify with curl

```
curl -s http://127.0.0.1:8000/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{
    "model":"Qwen/Qwen3-8B",
    "messages":[{"role":"user","content":"hi"}]
  }'
```

Streaming variant: add `"stream":true`.

## Point Regent at DFlash

DFlash exposes the OpenAI Chat Completions shape, which Regent's
inference layer already speaks (per `INFERENCE-ROUTING-DISCIPLINE-2026-07.md`).

Set Regent's inference base URL to `http://127.0.0.1:8000/v1` (or
whichever port DFlash is bound to). No adapter needed. The exact
config location depends on Regent's current inference-source config —
typically an env var or config field on the InferenceBackend.

## Drafter adoption ceremony

Before promoting DFlash to `active` in a dossier per MODEL-DOSSIER-2026-07
§"Bootstrap ceremony", run the byte-identical parity attestation
(SHADOW-EVALUATION-PRIMITIVE Context 1, `acceleration_ablation` scenario):

1. Run the same fixed-seed corpus (N ≥ 200 representative prompts,
   `temperature=0`) through the target-alone and target+DFlash paths.
2. Compare token-by-token. Every prompt should produce byte-identical
   output. Any divergence blocks promotion until root-caused.
3. Emit the `substrate:characterization:validated` receipt with the
   corpus hash, seed, and byte-identity result. That receipt becomes
   the dossier's `drafter.byte_identical_parity_receipt` field.
4. Operator ratification per SHADOW-MODEL-SWITCHING-2026-07 promotes
   the drafter's `state` field from `not_yet_trained` → `active` in
   `models/<family>/model_dossier.toml`.

A parity-check helper script is a natural next build step; not yet
included here.

## Observation-plane wiring

Per `OBSERVATION-PLANE-2026-07.md` §"Inference telemetry", DFlash's
per-token acceptance signal is the substrate's live dossier-drift
signal. Wiring DFlash's confidence-head output to
`observation:inference:drafter_acceptance` receipt emission is a
follow-on build (Layer A of the inference-source integration). The
signal is available in DFlash's runtime today; the emission path
needs the substrate hook.

## What's characterized in the dossiers today

| Family      | State                | Notes |
|-------------|----------------------|-------|
| qwen3       | `not_yet_trained`    | `z-lab/Qwen3-8B-DFlash-b16` identified, MLX-compatible |
| qwen3.6     | `not_yet_trained`    | `z-lab/Qwen3.6-*-DFlash` shipped for 27B and 35B-A3B |
| gemma4      | `not_yet_trained`    | `z-lab/gemma-4-26B-A4B-it-DFlash` — MLX fit unverified |
| glm5        | `coming_soon`        | DFlash roadmap flags GLM-5.x |
| llama4      | `no_drafter_shipped` | DFlash covers Llama-3.1 only |
| phi4        | `no_drafter_shipped` | Not on DFlash's roadmap |

See `models/<family>/model_dossier.toml` `[drafter]` section.

## Non-goals for this install

- **Not a chain-integrity claim.** Install lands the runtime; adoption
  is a separate ceremony per MODEL-DOSSIER's bootstrap flow.
- **Not automatic drafter promotion.** State stays `not_yet_trained`
  until operator ratifies via the acceleration-ablation shadow scenario.
- **Not a substitute for the observation-plane wiring.** Real drift
  detection needs the substrate's decoder hook emitting
  `observation:inference:drafter_acceptance` receipts.

## Rollback

To uninstall:

```
rm -rf .venvs/dflash-mlx
```

Model weights cached under `~/.cache/huggingface/hub/` are unaffected;
remove manually if desired (each Qwen3-family model is 10-30GB).
