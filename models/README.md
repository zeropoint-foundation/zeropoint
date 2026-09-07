# Model Dossiers

Each subdirectory contains a `model_dossier.toml` — the substrate's structured
characterization of a model family before it is trusted with cognitive work.

## Canonical spec

**Schema, lifecycle, adversarial profiling, think-suppression profiling,
drafter sub-record, and receipt discipline are specified in
[`docs/design/MODEL-DOSSIER-2026-07.md`](../docs/design/MODEL-DOSSIER-2026-07.md).**

This directory holds the operational files (per-model dossier TOMLs, bench
outputs, evaluation report artifacts). This README covers the operational
side; the discipline lives in the Tier-2 doc.

## Files in this tree

- `<model_family>/model_dossier.toml` — the dossier itself, canonical
  serialization. Schema per MODEL-DOSSIER-2026-07 §"The canonical schema."
- `<model_family>/bench_results/` — raw output from `scripts/bench-local-models.py`.
  Referenced from the dossier's `evidence.evaluation_receipts`.
- `<model_family>/adversarial_probes/` — adversarial probe outputs feeding
  the dossier's `suitability.adversarial_resistance` field. Probe families
  per MODEL-DOSSIER-2026-07 §"Adversarial profiling."
- `<model_family>/think_suppression/` — think-suppression probe results
  feeding `suitability.think_suppression_profile`.
- `<model_family>/drafters/` — when a speculative-decoding drafter exists
  for this target, drafter checkpoint metadata and byte-identical parity
  receipts land here. Populates the dossier's `drafter` sub-record.

## Running the bench

```
python scripts/bench-local-models.py --model <family>/<variant>
```

Emits results under `<model_family>/bench_results/` and produces the
`evaluation_receipt` hashes that get inlined into the dossier.

## Bootstrap ceremony

The full bootstrap ceremony (candidate → validated → active) is specified
in MODEL-DOSSIER-2026-07 §"Bootstrap ceremony." The Regent's
`regent:config:inference` receipt is the sovereign-signature seat.

## Adding a drafter

Drafter adoption follows the same discipline. See
MODEL-DOSSIER-2026-07 §"Two serializations, one artifact" and the drafter
adoption ceremony under §"Immediate design work."
