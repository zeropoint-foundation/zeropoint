# ZeroPoint local-model benchmark — APOLLO — latest

Target node: **APOLLO** (Apple Silicon / MLX). Default set is clear-license only; `--include-license-gated` appends operator-electable (Tier B) models. Emission evals run with thinking disabled - each model at its correct operating point.

## Summary

| model | tier | license | load s | decode tok/s | peak GB | structured | notes |
|---|---|---|---|---|---|---|---|
| lfm2.5-350m | classifier-edge (electable) | lfm1.0 (per model card; revenue terms UNVERIFIED) | 0.6 | 415.9 | 0.43 | 4/4 | |

## UC-1 feasibility by context length (prefill tok/s / peak GB / synthesis✓)

Each cell carries a real needle-synthesis task at that context length. `✓/✗` = did the model locate the right corpus section and answer. Where `✗` appears or the cell OOMs is your whole-chain-reflection ceiling — the number that decides UC-1's feasibility on this node.

| model | 4096 | 16384 | 32768 | 65536 |
|---|---|---|---|---|
| lfm2.5-350m | 7574.7 / 2.25GB / ✗ | 6705.5 / 2.41GB / ✓ | 5167.0 / 2.64GB / ✗ | 3354.6 / 3.31GB / ✗ |

## Structured-output / tool-call detail

| model | receipt_json | tool_call_json | route_classifier | uc1_synthesis |
|---|---|---|---|---|
| lfm2.5-350m | ✓ | ✓ | ✓ | ✓ |

## Reading the results (ZeroPoint routing implications)

- **decode tok/s** — is this tier interactive (realtime horizon) or background-only?
- **UC-1 feasibility curve** — the length where `✓` flips to `✗` (or OOMs) is APOLLO's whole-chain-reflection ceiling, i.e. how much corpus the flagship use case can actually reason over on this node. This is the single most decision-relevant number.
- **structured/tool (incl. uc1_synthesis)** — a model that can't hold this is not a Regent-emission candidate, regardless of speed.
- **peak GB** — headroom against the ~48–56GB budget; watch it climb with context (KV cache).
- **samples file (uc1_ontology + uc3_grounded_qa)** — read against each task's EXPECT line; a wrong number or fabricated section on UC-3 is int4 grounded-retrieval degradation, quietly.