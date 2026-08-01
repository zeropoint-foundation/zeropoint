# zp-inference-observer

Tails DFlash observation JSONL events (produced by
`scripts/dflash-observation-emitter.py`) and exposes each one as a typed
[`InferenceObservation`] value. Standalone Rust crate.

## Why this exists

Two-layer split per `docs/design/OBSERVATION-PLANE-2026-07.md` §"Inference
telemetry":

- **Python emitter** captures the signal from outside the dflash-mlx
  process by polling `POST /metrics`. Doesn't need to be inside the
  substrate.
- **Rust reader** (this crate) converts each JSONL event into a typed
  value the substrate can hand to its normal receipt-emission path.
  Needs to be inside the substrate because signing uses the Genesis
  key.

This crate stops at "typed values ready to become receipts." It does
NOT sign, it does NOT append to chain. Those are last-mile substrate
integration.

## Build & smoke test

```
cd crates/zp-inference-observer   # or wherever you drop this
cargo test --release              # 3 tests, all schema round-trips
cargo run --release --            \
  --path /path/to/drafter_acceptance-20260727.jsonl \
  --from-beginning --stop-at-eof
```

Digest output looks like:

```
[     1] offset=402 drafter_acceptance target=Qwen/Qwen3-8B drafter=Qwen3-8B-DFlash-b16 drafted=1104 rate=74.82% window=63s
[     2] offset=804 drafter_acceptance target=Qwen/Qwen3-8B drafter=Qwen3-8B-DFlash-b16 drafted=1200 rate=45.20% window=64s
[     3] offset=1192 drift_suspected  target=Qwen/Qwen3-8B drafter=Qwen3-8B-DFlash-b16 rate=45.20% < threshold=55.00% trigger=drafter_acceptance_below_threshold
```

Add `--raw` to dump JSON lines verbatim.

## Public API

```rust
use zp_inference_observer::{tail, TailConfig, InferenceObservation};

let config = TailConfig {
    path: "/path/to/drafter_acceptance.jsonl".into(),
    poll_interval: std::time::Duration::from_millis(500),
    from_beginning: false,   // production: only new events
    stop_at_eof: false,      // production: run forever
};

tail(config, |tailed| {
    match tailed.event {
        InferenceObservation::DrafterAcceptance(e) => {
            // build_receipt(&e).sign(&genesis_key).append_to_chain();
        }
        InferenceObservation::DriftSuspected(e) => {
            // build_drift_receipt(&e).sign(...).append();
            // also hand to CIRCUIT-BREAKER's trigger dispatch
        }
        InferenceObservation::Unknown => {
            // log-and-continue; unrecognized future event_type
        }
    }
})?;
```

The `TailedEvent` value carries `end_offset` and `raw_line` alongside the
parsed event so the substrate can persist "last processed offset" for
resume-after-restart, and can compute `content_hash` from the exact
observed bytes.

## Substrate integration — the last mile (not built here)

When this crate is added to the substrate workspace, the integration is
roughly this shape:

```rust
use zp_receipt::{Receipt, ClaimMetadata, Status, ClaimSemantics};
use zp_inference_observer::{DrafterAcceptanceEvent, DriftSuspectedEvent};

fn build_acceptance_receipt(
    e: &DrafterAcceptanceEvent,
    parent: Option<&str>,
) -> Receipt {
    let mut b = Receipt::observation("dflash-emitter")
        .status(Status::Success)
        .claim_semantics(ClaimSemantics::AuthorshipProof)
        .claim_metadata(ClaimMetadata::Observation {
            observation_type: "inference:drafter_acceptance".to_string(),
            observer_id: "dflash-emitter".to_string(),
            confidence: Some(1.0),
            tags: vec!["inference".to_string(), "drafter".to_string()],
        });
    if let Some(p) = parent {
        b = b.parent(p);
    }
    b.extension("zp.observation.inference.target_model_id", json!(e.target_model_id))
     .extension("zp.observation.inference.drafter_id",      json!(e.drafter_id))
     .extension("zp.observation.inference.window.start",    json!(e.window.start_wall_utc))
     .extension("zp.observation.inference.window.end",      json!(e.window.end_wall_utc))
     .extension("zp.observation.inference.window.duration_s", json!(e.window.duration_s))
     .extension("zp.observation.inference.target_tokens",   json!(e.target_tokens_in_window))
     .extension("zp.observation.inference.drafted_tokens",  json!(e.drafted_tokens_in_window))
     .extension("zp.observation.inference.mean_acceptance_rate", json!(e.mean_acceptance_rate))
     .finalize()
}
```

For `DriftSuspectedEvent`, use `observation_type = "substrate:characterization:drift_suspected"`
and mirror the extension keys. Additionally, hand the event to
CIRCUIT-BREAKER-2026-07's trigger-class dispatcher — sustained drift is
a specific trigger class that composes with operator-declared
escalation policy.

## Composition

- **`docs/design/OBSERVATION-PLANE-2026-07.md`** §"Inference telemetry" —
  this crate is the substrate-side reader for Surface 7's JSONL stream.
- **`docs/design/MODEL-DOSSIER-2026-07.md`** §"Continuous drift signal" —
  every `DrafterAcceptanceEvent`'s `mean_acceptance_rate` is the live
  drift signal the dossier's `drift_suspected_flag` was designed to
  surface.
- **`docs/design/CIRCUIT-BREAKER-2026-07.md`** — `DriftSuspectedEvent`
  is a trigger class per that spec; the substrate consumer must
  dispatch it there in addition to emitting the receipt.
- **`zp_receipt`** (workspace crate) — provides `Receipt::observation`,
  `ClaimMetadata::Observation`, and the extension API this crate's
  events map onto.

## When ready to integrate

1. Remove the `[workspace]` table from `Cargo.toml`.
2. Move the crate under `crates/zp-inference-observer/`.
3. Add `"crates/zp-inference-observer"` to the root `Cargo.toml`'s
   `workspace.members`.
4. Add a small consumer in `zp-server` (or a new
   `zp-inference-observation-emitter` crate) that runs a `tail(...)`
   loop on a dedicated thread and emits + signs + appends receipts
   per the shape above.

Everything else is downstream — the JSONL contract is stable, the types
are versioned via the `#[serde(other)]` fallback, and the emitter is
already producing events in the right shape.
