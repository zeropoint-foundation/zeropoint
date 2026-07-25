# ZeroPoint local-model benchmark — APOLLO — thinkoff

Target node: **APOLLO** (Apple Silicon / MLX). Default set is clear-license only; `--include-license-gated` appends operator-electable (Tier B) models. Emission evals run with thinking disabled - each model at its correct operating point.

## Summary

| model | tier | license | load s | decode tok/s | peak GB | structured | notes |
|---|---|---|---|---|---|---|---|
| qwen3-30b-a3b | resident-general | Apache-2.0 | 3.6 | 93.2 | 16.05 | 4/4 | |
| qwen3-coder-30b-a3b | resident-coder | Apache-2.0 | 3.2 | 86.5 | 16.05 | 4/4 | |
| qwen3-4b | fast-slm | Apache-2.0 | 0.9 | 93.8 | 2.21 | 4/4 | |
| qwen3-1.7b | classifier-edge | Apache-2.0 | 0.8 | 206.0 | 1.03 | 4/4 | |

## UC-1 feasibility by context length (prefill tok/s / peak GB / synthesis✓)

Each cell carries a real needle-synthesis task at that context length. `✓/✗` = did the model locate the right corpus section and answer. Where `✗` appears or the cell OOMs is your whole-chain-reflection ceiling — the number that decides UC-1's feasibility on this node.

| model | 4096 | 16384 | 32768 | 65536 |
|---|---|---|---|---|
| qwen3-30b-a3b | 790.2 / 17.06GB / ✓ | 482.1 / 18.16GB / ✓ | 286.0 / 19.63GB / ✓ | 179.7 / 22.59GB / ✓ |
| qwen3-coder-30b-a3b | 711.5 / 17.06GB / ✓ | 451.3 / 18.16GB / ✓ | 304.3 / 19.63GB / ✓ | 182.4 / 22.59GB / ✓ |
| qwen3-4b | 702.2 / 3.41GB / ✓ | 483.7 / 4.94GB / ✓ | 350.1 / 7.22GB / ✓ | 219.8 / 11.94GB / ✓ |
| qwen3-1.7b | 1803.4 / 2.07GB / ✗ | 1260.1 / 3.34GB / ✗ | 908.1 / 4.96GB / ✗ | 558.5 / 8.64GB / ✗ |

## Structured-output / tool-call detail

| model | receipt_json | tool_call_json | route_classifier | uc1_synthesis |
|---|---|---|---|---|
| qwen3-30b-a3b | ✓ | ✓ | ✓ | ✓ |
| qwen3-coder-30b-a3b | ✓ | ✓ | ✓ | ✓ |
| qwen3-4b | ✓ | ✓ | ✓ | ✓ |
| qwen3-1.7b | ✓ | ✓ | ✓ | ✓ |

## Reading the results (ZeroPoint routing implications)

- **decode tok/s** — is this tier interactive (realtime horizon) or background-only?
- **UC-1 feasibility curve** — the length where `✓` flips to `✗` (or OOMs) is APOLLO's whole-chain-reflection ceiling, i.e. how much corpus the flagship use case can actually reason over on this node. This is the single most decision-relevant number.
- **structured/tool (incl. uc1_synthesis)** — a model that can't hold this is not a Regent-emission candidate, regardless of speed.
- **peak GB** — headroom against the ~48–56GB budget; watch it climb with context (KV cache).
- **samples file (uc1_ontology + uc3_grounded_qa)** — read against each task's EXPECT line; a wrong number or fabricated section on UC-3 is int4 grounded-retrieval degradation, quietly.