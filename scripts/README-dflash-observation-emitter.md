# DFlash observation emitter

Polls `dflash serve`'s `POST /metrics` endpoint and writes
`observation:inference:drafter_acceptance` events to a JSONL stream.
Realizes `docs/design/OBSERVATION-PLANE-2026-07.md` §"Inference telemetry"
(Surface 7) as a Python sidecar.

## Run

```
python3 scripts/dflash-observation-emitter.py \
  --target Qwen/Qwen3-8B \
  --drafter z-lab/Qwen3-8B-DFlash-b16
```

Assumes `dflash serve` is already running at `http://127.0.0.1:8000`. Events
land under `~/projects/zeropoint/.observations/inference/drafter_acceptance-<utc>.jsonl`
(daily rotation).

## Dry-run first

```
python3 scripts/dflash-observation-emitter.py --dry-run \
  --target Qwen/Qwen3-8B --drafter z-lab/Qwen3-8B-DFlash-b16
```

Verifies connectivity + that the `parse_metrics()` adapter matches your
installed dflash-mlx version's `/metrics` response shape. If the parse
fails, the CLI prints the raw payload so you can see exactly what fields
the server returned and adjust the ADAPTER-SEAM inline.

## What each event looks like

Every window closure emits one JSONL event. Fields match
MODEL-DOSSIER-2026-07 §"Continuous drift signal":

```json
{
  "event_type": "observation:inference:drafter_acceptance",
  "target_model_id": "Qwen/Qwen3-8B",
  "drafter_id": "z-lab/Qwen3-8B-DFlash-b16",
  "window": {
    "start_wall_utc": "2026-07-27T14:00:00Z",
    "end_wall_utc":   "2026-07-27T14:01:03Z",
    "duration_s":     63.0
  },
  "target_tokens_in_window":  742,
  "drafted_tokens_in_window": 1104,
  "mean_acceptance_rate":     0.7482,
  "position_wise_acceptance_curve": null,
  "workload_class_breakdown": null
}
```

When `mean_acceptance_rate` drops below `--drift-threshold` (default 0.55,
matching the `model_dossier.toml` template), a second event fires:

```json
{
  "event_type": "substrate:characterization:drift_suspected",
  "characterization_form": "drafter",
  "target_model_id": "Qwen/Qwen3-8B",
  "drafter_id": "z-lab/Qwen3-8B-DFlash-b16",
  "trigger": "drafter_acceptance_below_threshold",
  "observed_mean_acceptance_rate": 0.4820,
  "declared_threshold": 0.5500,
  "window": { ... }
}
```

## Two fields left null

`position_wise_acceptance_curve` and `workload_class_breakdown` are both
`null` in the current build. Both require signal that dflash-mlx's
`/metrics` endpoint doesn't expose today:

- **Position-wise curve** needs per-token accept/reject data (which draft
  position was accepted). Only available inside the dflash process.
- **Workload-class breakdown** needs per-request classification (which
  workload class each completion came from). Would require the emitter to
  also observe the OpenAI `/v1/chat/completions` path with a classifier,
  or DFlash to expose per-request metadata.

The event schema carries the fields as `null` placeholders so the
substrate-side reader always sees the same shape. Populate them when the
data becomes available (dflash upstream feature, or a patched build).

## Substrate-side reader (not built yet — this is the handoff)

The Rust side hasn't been written. When it is, the shape is:

1. A component in `crates/zp-server` (or a new `zp-inference-observer`
   crate) tails the JSONL files under
   `~/projects/zeropoint/.observations/inference/`.
2. Each JSONL event converts to a chain receipt using the existing
   receipt system:
   - `Receipt::observation(observer_id="dflash-emitter")`
   - `ClaimMetadata::Observation` with
     `observation_type="inference:drafter_acceptance"` (or
     `"substrate:characterization:drift_suspected"` for the drift event)
   - Extensions under `zp.observation.inference.*` carrying the specific
     fields (`target_model_id`, `drafter_id`, `mean_acceptance_rate`,
     window bounds, etc.).
3. Emit into the chain via the standard signing path.
4. For drift events, additionally hand off to CIRCUIT-BREAKER's trigger
   dispatch per that spec.

Deliberate choice to split Python (data capture) from Rust (receipt
emission): the capture layer only touches an HTTP endpoint and doesn't
need to be inside the substrate. The emission layer has to be inside the
substrate because it needs the Genesis signing key. Two layers, clean
boundary.

## Composition

- **`docs/design/OBSERVATION-PLANE-2026-07.md`** §"Inference telemetry" —
  this script IS the Layer A primitive for Surface 7, running as a
  sidecar rather than in the compiled Rust host. Reasonable because
  dflash-mlx itself is a Python process; a Python poller stays on the
  same side of the boundary.
- **`docs/design/MODEL-DOSSIER-2026-07.md`** §"Continuous drift signal" —
  every event's `mean_acceptance_rate` is the live drift signal that
  dossier drift-detection has been trying to approximate offline.
- **`docs/design/CIRCUIT-BREAKER-2026-07.md`** — sustained drift events
  are the trigger class that composes with circuit-breaker escalation
  policy per operator declaration.

## Operational hygiene

- **PID / lifecycle:** no PID file today. Wrap with `launchd` or `nohup ... &`
  as suits your ops style. `signal.SIGTERM` and `signal.SIGINT` both
  shut down gracefully after finishing the current window.
- **Log rotation:** daily by UTC date. Old files stay in place; delete or
  archive per your retention policy.
- **No auth:** the script assumes `dflash serve`'s `/metrics` is
  unauthenticated (default). If you've fronted it with auth, extend
  `fetch_metrics()` to add the appropriate header.
- **Poll cost:** `POST /metrics` is documented as debug-visibility; polling
  every 5s should be negligible. Tune `--poll-interval-s` up if you see
  overhead.
