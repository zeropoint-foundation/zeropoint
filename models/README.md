# Model Dossiers

Each subdirectory contains a `model_dossier.toml` — the substrate's structured
characterization of a model family before it is trusted with cognitive work.

Dossiers combine researched knowledge (published quirks, architecture notes,
community findings) with empirical measurements (bench results, prompt
compatibility testing). Together they form the input to the chain-validation
gate: the Regent reads the model dossier to know *what to test for*, runs the
bench to get *empirical results*, and emits a `regent:config:inference`
receipt with the full evidence. The operator signs the characterized pair.

## Lifecycle

1. **Research** — populate `[identity]`, `[architecture]`, `[quirks]`, `[research]`
2. **Bench** — run `scripts/bench-local-models.py`, populate `[bench]`
3. **Prompt testing** — test against regent prompt templates, populate `[prompt_compatibility]`
4. **Adversarial profiling** — the Regent runs the full battery including adversarial probes that test instruction conflict resolution, prompt injection resistance, framing sensitivity, context degradation, and compliance boundaries. A model that passes polite tests but fails adversarial ones has known deployment constraints. Failures are characterized in `[quirks]`, not treated as blocking — the dossier captures WHERE the model breaks so the substrate can deploy it within its safe envelope.
5. **Tier recommendation** — based on all evidence, populate `[tiers]`
6. **Chain validation** — Regent self-tests, emits receipt, operator signs

## Schema

See any `model_dossier.toml` for the canonical field set. The schema is
self-documenting via TOML comments.

## Think Suppression Profiling

The evaluation battery probes three think suppression mechanisms per model:

1. **`think: false`** — Ollama API option, portable across families
2. **`think` omitted** — don't send the parameter at all
3. **`/no_think` token** — model-specific token in the user message (qwen3)

Different variants of the same family may respond to different mechanisms.
The evaluation report's `think_suppression_profile` captures which mechanisms
are effective per variant, and the model dossier's `[quirks]` section records
the findings. The inference layer should use the model dossier to select the
right mechanism rather than assuming `think: false` works universally.

Model behavior differences around think suppression are diagnostic signal,
not noise. The inference layer logs leaked think tags at warn level but
does NOT strip them — the leak tells you the suppression mechanism isn't
working for that variant, which feeds back into the model dossier.
