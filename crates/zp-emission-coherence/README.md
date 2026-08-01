# zp-emission-coherence

Regent emission-coherence heuristics — H1 (n-gram repetition density),
H2 (response-length distribution collapse), and H3 (token entropy
anomaly) — plus composition into R0/R1/R2 response classes per
`docs/design/REGENT-DOOM-LOOP-DETECTION-2026-07.md`.

Standalone Rust crate. Same pattern as `zp-inference-observer` and
`rust-ast-extractor`: `[workspace]` opt-out, unit tests, small CLI, no
substrate integration in this crate.

## What ships

| Heuristic | Status | Needs |
|---|---|---|
| H1 — N-gram repetition density | **shipped** | text + token_ids |
| H2 — Response length distribution collapse | **shipped** | rolling window (owned by `EmissionAnalyzer`) |
| H3 — Token entropy anomaly | **shipped** | per-token log-probs + dossier baseline |
| H4 — Precedent-context degeneration | not shipped | embedding backend |
| H5 — Reasoning-step stagnation | not shipped | per-model reasoning-trace parsing |
| H6–H8 — Chronic-drift signals | not shipped | Cartographer materialization + officer runtime + baseline cycles |

The doc's Part X "Immediate work" list calls out H1–H3 as the first-shipping
instrumentation. This crate is that shipment.

## Build & test

```
cd crates/zp-emission-coherence
cargo test --release      # 19 tests, all green
cargo run --release -- --help
```

## CLI smoke tests

Healthy response — no findings:

```
echo '{
  "cycle_id":"c1","model":"qwen3:8b",
  "text":"The morning fog obscured the shape of the ships in the harbor as they moved toward the open sea.",
  "token_ids":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23],
  "sampling_params":{"temperature":0.7,"top_p":0.9}
}' | ./target/release/zp-emission-coherence
```

Doom-loop response — H1 fires (single flag, R0, still delivered):

```
python3 -c 'import json; p="the quick brown fox jumps over the lazy dog and "; \
print(json.dumps({"cycle_id":"c2","model":"qwen3:8b","text":(p*3).strip(),\
"token_ids":list(range(1,60)),"sampling_params":{}}))' \
  | ./target/release/zp-emission-coherence
```

Confident-token response with entropy baseline — H3 fires:

```
python3 -c 'import json; \
print(json.dumps({"cycle_id":"c3","model":"qwen3:8b",\
"text":"some content","token_ids":list(range(1,40)),\
"log_probs":[-0.01]*40,"sampling_params":{}}))' \
  | ./target/release/zp-emission-coherence --baseline 'qwen3:8b,2.0,0.5'
```

Baseline spec is `--baseline 'model,mean,std_dev'` — comma-separated so
model IDs with colons (`qwen3:8b`, `gemma4:26b-mlx`) work. Populate the
mean and std_dev from `models/<family>/model_dossier.toml`'s
`suitability.entropy_baseline` field once you've measured it (empty
today for every dossier — MODEL-DOSSIER-2026-07 calls this out as a
Layer B addition).

## Public API

```rust
use zp_emission_coherence::{
    EmissionAnalyzer, AnalyzerConfig, EntropyBaseline,
    Response, SamplingParams, ResponseClass, ReceiptFamily,
};

let mut config = AnalyzerConfig::default();
// Populate H3 baselines from dossiers (else H3 skips).
config.entropy_baselines.insert(
    "qwen3:8b".into(),
    EntropyBaseline { mean: 2.0, std_dev: 0.5 },
);

let mut analyzer = EmissionAnalyzer::new(config);

// Called once per Regent response — same slot Cognitive Self-Observer
// occupies, per the doc's "invoked in loop_runner.rs immediately after
// intent is produced but before delivery."
let outcome = analyzer.analyze(&Response {
    cycle_id: "cycle-abc",
    model: "qwen3:8b",
    token_ids: &[1, 2, 3, /* ... */],
    text: "the model's response text",
    log_probs: Some(&[-0.5, -1.2, /* ... */]),
    sampling_params: SamplingParams { temperature: 0.7, top_p: 0.9, seed: None },
});

match outcome.response_class {
    ResponseClass::LogAndContinue => {
        // R0: emit outcome.receipt_family, deliver response.
    }
    ResponseClass::RetryAdjustedSampling => {
        // R1: emit outcome.receipt_family, DO NOT deliver, retry with
        // outcome.retry_sampling_adjustment.
    }
    ResponseClass::Escalate => {
        // R2: emit doom_loop_confirmed, DO NOT deliver, engage fallback
        // per operator preference (SUBSTRATE-READINESS-CONTRACT
        // no_silent_degradation).
    }
}
```

## Substrate integration — the last mile (not built here)

The doc specifies the integration point precisely:
`crates/zp-regent/src/loop_runner.rs`, immediately after `intent` is
produced but before delivery. When ready to integrate:

1. Remove the `[workspace]` table from `Cargo.toml`.
2. Move under `crates/zp-emission-coherence/`, add to workspace members.
3. In `zp-regent/src/loop_runner.rs`, hold an `EmissionAnalyzer` on the
   runner state. On every emitted response:
   ```rust
   let outcome = self.emission_analyzer.analyze(&response);
   for finding in &outcome.findings {
       tracing::warn!("emission-coherence: {:?}", finding);
   }
   if let Some(rt) = outcome.receipt_family.receipt_type() {
       // Build zp_receipt::Receipt with this receipt_type key,
       // ClaimMetadata::Observation with observation_type = rt,
       // extensions under zp.emission.coherence.* carrying the
       // findings serialized as JSON.
       // Sign with Genesis + append.
   }
   match outcome.response_class {
       ResponseClass::LogAndContinue => deliver_response(response),
       ResponseClass::RetryAdjustedSampling => {
           let adj = outcome.retry_sampling_adjustment.unwrap();
           let retry_params = SamplingParams {
               temperature: params.temperature + adj.delta_temperature,
               top_p: params.top_p + adj.delta_top_p,
               ..
           };
           // Chain-anchor regent:emission:retry_adjusted_sampling,
           // re-invoke with retry_params (subject to detection again).
       }
       ResponseClass::Escalate => {
           // Chain-anchor doom_loop_confirmed + substrate:degraded:
           // regent_cognitive_capability. Route to fallback tier per
           // operator preference receipt.
       }
   }
   ```
4. Bootstrap H3 baselines from the model dossier at Regent boot; if a
   dossier is missing `entropy_baseline`, log per SUBSTRATE-READINESS-
   CONTRACT `substrate:degraded:entropy_baseline_missing` and skip H3
   for that model (already handled inside the analyzer — it silently
   skips when no baseline is present).

## Composition

- **`docs/design/REGENT-DOOM-LOOP-DETECTION-2026-07.md`** — this crate
  is the first-shipping instrumentation for that spec's Class R0 → R2
  ladder. Discipline preserved: instrumentation ships before
  remediation; substrate observes and chain-anchors evidence; operator
  policy determines the R2 escape.
- **`docs/design/MODEL-DOSSIER-2026-07.md`** §"The canonical schema" —
  H3 reads the dossier's `entropy_baseline` field; H1/H2 findings
  populate the dossier's `doom_loop_rate_per_1k_responses` empirical
  measurement over time.
- **`docs/design/COGNITIVE-SELF-OBSERVER-2026-07.md`** — this crate
  realizes the "proposed Class 8 (Emission Coherence)" extension listed
  in CSO's §"Proposed extensions (not yet integrated)" section. When
  the last-mile substrate integration lands, CSO's Class 8 flips from
  "proposed" to shipped.
- **`docs/design/CIRCUIT-BREAKER-2026-07.md`** — sustained
  `doom_loop_confirmed` receipts feed CIRCUIT-BREAKER's trigger dispatch
  per that spec.

## Non-goals

- **Not remediation.** The crate reports; substrate policy responds.
  R2 escape (fallback tier / operator escalation / refuse-and-narrate)
  is operator-declared per the doc's Part III.
- **Not vendor benchmarks.** Findings are evidence per response, not
  scores per model. Aggregation into per-model doom-loop rates lives
  in the substrate's empirical program consuming these receipts.
- **Not per-request-latency instrumentation.** H2's rolling window
  operates on completed responses, not on request-side latency. Latency
  telemetry is a separate observation surface.

## Rollback / uninstall

`rm -rf crates/zp-emission-coherence`. Standalone crate; no workspace
side-effects until deliberately added.
