# Hardware Dossier — Regent perceives its hardware, routing hard-blocks on capacity

**Tier 2 canonical elaboration (SKETCH — 2026-08-02).** Proposes per-node hardware dossiers as first-class corpus data, parallel to `models/*/model_dossier.toml`, informing every inference-routing decision the Regent makes. Elaborates `KEEL-2026-07.md` §II.13 P6 (physical foundation), §II.19 (composition contract), and Part XIV (inference envelope).

Composes with: `MODEL-DOSSIER-2026-07.md` (fit predictions cross-reference model dossier + hardware dossier), `HARDWARE-ROLE-SEPARATION-2026-07.md` (which nodes exist and what role each plays; this doc names their capabilities), `HARDWARE-OBSERVER-2026-07.md` (partially reserved via `observation:hardware:*`; hardware profile is one facet of what HARDWARE-OBSERVER watches), `INFERENCE-ROUTING-DISCIPLINE-2026-07.md` (fit + ceiling feed the Layer 2 classifier's routing decisions), `LOCAL-MODEL-SELECTION-2026-07.md` (its hardware-math section is the theoretical basis for the fit-prediction functions this sketch specifies), `EXECUTION-AUTHORITY-MODEL-2026-07.md` (capacity-fit failure escalates as an operator-approval ceremony), `TRAJECTORY-MAP-PRIMITIVE-2026-08.md` (map-shaped work with heavy-context tickets consults fit predictions before dispatch).

**Status.** Sketch, not committed spec. Load-bearing framing: **hardware capability is first-class corpus data. Every inference routing decision consults it. A model that would not fit on current hardware hard-blocks with an escalation receipt asking operator to disposition — never auto-escalates silently.**

## Framing

The corpus already has structured characterization of models (per MODEL-DOSSIER-2026-07 — Tier 2, canonical) but keeps hardware characterization as prose in LOCAL-MODEL-SELECTION-2026-07 and HARDWARE-ROLE-SEPARATION-2026-07. That asymmetry doesn't scale. When the Regent needs to route inference — "does qwen3.6:35b-a3b fit on this node with a 32k context window? what tok/s can I promise?" — it can't reason from prose. The hardware side needs the same dossier discipline.

The Regent-is-UX architectural stance (per AGENT-AS-UX-ARCHITECTURE-2026-05) makes this pressing: the operator asks the Regent a question; the Regent decides which inference target answers it; that decision has to be honest about what will actually fit and how fast the response will feel. Today the Regent chooses a model with no runtime awareness of "am I on APOLLO or on the Pi 5? do I even have the memory for what this operator is asking me to load?" The result is dispatch-then-fail-obscurely or, worse, dispatch-then-succeed-but-thrash-to-swap. Neither is sovereign.

Every inference routing decision needs three questions answered at decision time:

- **Does the target model fit on current hardware given the workload's context budget?** Capacity floor — binary. If weights + KV budget exceed effective memory, the model cannot run. There is no partial credit.
- **How fast will decode be on this hardware for this model?** Bandwidth ceiling — a promise the Regent can make to the operator (or an admission that the answer will be slow enough to route differently).
- **How long will prefill take for this context size?** Compute ceiling — matters for time-to-first-token when the context is large. `code:repo_wide` and `code:multi_file` prompts land here more often than `code` prompts do.

The sketch shipped in `70e3c0c` gave LOCAL-MODEL-SELECTION-2026-07 the theoretical framing for these three numbers. This sketch turns that framing into runtime substrate data the Regent actually consults.

## The hardware dossier

Per-node file at `hardware/<node_id>/hardware_dossier.toml`. Schema parallels the model-dossier pattern (identity + characterization + measurements + state).

### Sections

**`[identity]`** — name, hardware family, chassis form (unified vs discrete memory), physical location if fixed.

**`[capacity]`** — memory GB total, memory reserved for OS/other, effective memory available for substrate use. The last number is what fit predictions consult. Reserved-for-other is operator-declared (they know what else runs on the machine).

**`[bandwidth]`** — memory bandwidth in GB/s, both `published` (vendor-declared, static) and `measured` (from a calibration battery — same discipline as MODEL-DOSSIER's `entropy_baseline` state). Measured always trumps published when both are present. `state = "not_yet_calibrated" | "calibrated"` gates trust.

**`[compute]`** — FLOPS for prefill computation, again split into `published` and `measured`. `flops_prefill` per data-type (fp16, int4) since MoE prefill on int4 has different characteristics than fp16.

**`[thermal]`** — sustained-vs-boost envelope. How fast the machine throttles under sustained inference load. `sustained_watts`, `boost_watts`, `throttle_temp_c`. Optional but valuable for laptops.

**`[quirks]`** — same schema shape as model_dossier's `[quirks]`: known failure modes, ceiling-vs-floor observations, per-severity annotations. Example entries: "M4 Pro throttles decode ~15% under sustained 30min load", "Pi 5 with active cooling stable to 80°C; passive cooling loses 40% throughput after 5min".

**`[calibration]`** — analogous to `[entropy_baseline]` on model dossiers. `state`, `battery_receipt`, `calibrated_at`, `battery_prompt_count`. The calibration battery for hardware is a set of representative inference runs on known models with per-run bandwidth-utilization and prefill-time measurements. Script location: `scripts/calibrate-hardware.py` (to be written; parallel to `calibrate-h3-baseline.py`).

### Chain-anchoring

Three receipt families:

- **`hardware:profile:declared`** — operator signs the initial dossier. Content-addressed by dossier hash. Amendment via supersession per ARTIFACT-LIBRARY-2026-05 lifecycle.
- **`hardware:profile:probed`** — Regent-emitted at startup after auto-probing the machine. Records observed vs declared for reconciliation.
- **`hardware:profile:drift_suspected`** — emitted when observed decode/prefill performance persistently diverges from prediction beyond a threshold. Aegis-observable per TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT.

## Provenance discipline: operator-declared + auto-probed, with reconciliation

Both. Neither alone is honest.

**Operator-declared is source of truth.** The operator writes the dossier. Their signature anchors it. This is the sovereign move — the substrate does not decide what it thinks its hardware is; the operator declares it and the substrate honors the declaration. Same posture as every other corpus commitment.

**Auto-probe reconciles.** On startup, the Regent probes the machine via platform APIs (sysinfo, ioreg on macOS, /proc on Linux, PowerShell on Windows) plus a bandwidth micro-benchmark and a compute micro-benchmark. Results are compared field-by-field against the dossier:

- Fields matching within tolerance → confirmed. Regent emits `hardware:profile:probed` naming the reconciled profile.
- Fields diverging beyond tolerance → `hardware:profile:drift_suspected` receipt with per-field diff. Regent uses the declared value (operator sovereignty) but flags the discrepancy for operator disposition.

The reconciliation is HONEST about the two sources. The dossier isn't overwritten by auto-probe — that would break the sovereignty contract. But silent divergence isn't tolerated either. The chain records both, operator adjudicates.

## Fit predictions as pure functions

Given a hardware dossier and a model dossier, compute:

```rust
pub struct FitPrediction {
    pub fits: bool,
    pub fit_failure: Option<FitFailure>,
    pub decode_ceiling_tok_s: f64,
    pub prefill_estimate: Duration,
    pub confidence: Confidence,  // High if both dossiers calibrated; Low if either uncalibrated
}

pub enum FitFailure {
    WeightsExceedMemory { weights_gb: f64, effective_memory_gb: f64 },
    ContextKvExceedsRemainder { kv_gb: f64, remainder_gb: f64 },
    CombinedExceedsMemory { weights_gb: f64, kv_gb: f64, effective_memory_gb: f64 },
}

pub fn predict_fit(
    model: &ModelDossier,
    hardware: &HardwareDossier,
    context_tokens: usize,
) -> FitPrediction { ... }
```

Pure. Deterministic. No I/O. Testable in isolation. Same discipline as the WorkArc query methods and the `classify_code_scope` sub-classifier.

Derivations:
- `weights_gb` = model's quantized size from `model_dossier.deployment.footprint_gb`
- `kv_gb` = model's per-1k-token KV cost × (context_tokens / 1000) — new field needed on model dossiers, per-quantization.
- `effective_memory_gb` = hardware's `[capacity].effective_memory_gb`
- `decode_ceiling_tok_s` = `bandwidth_gb_s ÷ active_bytes_per_token` where active_bytes = model.active_params × bytes_per_param
- `prefill_estimate` = `context_tokens × prefill_flops_per_token ÷ hardware.compute.flops_prefill` — approximate; needs calibration refinement over time.

## Regent perceives its hardware

At Regent startup (in `zp-server/src/regent.rs`, right after model dossier corpus load):

1. Resolve current node id — operator-configured or hostname-derived.
2. Load `hardware/<own_id>/hardware_dossier.toml`. If absent, emit `hardware:profile:missing` and enter degraded routing mode (see §Escalation).
3. Auto-probe: sysinfo for capacity, quick micro-benchmark for bandwidth/compute.
4. Reconcile probe against dossier. Emit `hardware:profile:probed` naming the reconciled profile OR `hardware:profile:drift_suspected` if divergence exceeds tolerance.
5. Store resolved `HardwareProfile` on Regent for routing consultation.

Composes with the existing `set_dossier_corpus` pattern in `zp-server/src/regent.rs` — same shape, hardware corpus alongside model corpus. `DossierCorpus::hardware_profile()` becomes a new accessor.

## Classifier wiring

Layer 2 classifier extended:

**QueryHint gains** `estimated_context_tokens: Option<usize>`. Populated by a heuristic:
- `chat` / `code` (no scope) → small (assume 4k)
- `code:local_transform` → moderate (assume 16k)
- `code:multi_file` → large (assume 64k)
- `code:repo_wide` → very large (assume 200k)
- Or explicit override from caller.

**ClassifierDecision extended** to include per-candidate FitPrediction:
```rust
pub struct ClassifierDecision {
    // ... existing fields ...
    pub fit_predictions: HashMap<String, FitPrediction>,  // per candidate model
    pub routing_rationale: String,  // "chose qwen3.6:35b-a3b: fits (24.3GB of 60GB effective), decode ceiling 148 tok/s"
}
```

Routing algorithm (Layer 2, when envelope has multiple candidates):
1. Compute FitPrediction for each candidate model against current hardware.
2. Filter out any that don't fit — those are hard-blocked.
3. Among fitters, apply existing precedent-based selection but with `decode_ceiling_tok_s` as a tiebreaker: faster wins if all else equal.
4. Record the filtered-out models + their FitFailure reasons in the decision receipt.

## Hard-block ceremony (strong sovereignty)

When the operator's directive (via Regent's chosen model) cannot fit on current hardware, do NOT auto-escalate. The substrate hard-blocks and emits:

**`regent:routing:fit_denied`** — receipt carries:
- The workload class + estimated context tokens.
- The chosen model and its FitFailure (weights, KV, effective memory).
- The available fitting models (if any) and their tradeoffs.
- An operator disposition request per EXECUTION-AUTHORITY-MODEL Phase 7 proposal ceremony.

Operator dispositions:
- Approve escalation to a specific fitting model (e.g. downshift to a smaller local variant).
- Approve escalation to cloud inference (if envelope allows).
- Reject and return "cannot answer on current hardware; consider expanding memory or moving to a different node."
- Adjust hardware dossier (if the failure was a wrong dossier field, e.g. reserved-for-other overestimated).

No silent auto-escalation. Every fit failure is a moment of operator visibility. This is the strong-sovereignty answer per today's design decision. It's stricter than most systems would tolerate; it's exactly what a sovereign trust substrate should do — because the alternative is the substrate quietly picking a cheaper/faster model without asking, which is the failure mode ZP was designed to prevent.

Composes with the approvals machinery already in `zp-regent/src/approvals.rs` — fit_denied is a specific class of approval request, same ceremony.

## Continuous drift signal

After each inference completes (in `inference.rs`'s post-dispatch hook), measure observed decode tok/s and prefill time. Compare against the FitPrediction that gated this dispatch. If observed persistently under-performs prediction (> N inferences below threshold, e.g. 30% slower than ceiling), emit `hardware:profile:drift_suspected` with the observed vs predicted diff.

Aegis observes the drift receipt and surfaces to operator. Possible causes:
- Hardware degradation (thermal issues, memory pressure from other processes, physical fault).
- Wrong dossier — declared bandwidth optimistic, effective memory smaller than declared.
- Model dossier off — active_params or per-token bytes miscounted.

Operator dispositions by investigating; adjustments land as dossier supersedes.

## Composition summary

The hardware dossier + fit prediction primitive lands cleanly with existing corpus:

- **MODEL-DOSSIER-2026-07** — needs a new field on the dossier for `kv_cost_per_1k_tokens` per quantization level. Small schema addition.
- **HARDWARE-ROLE-SEPARATION-2026-07** — canonical claim about which node plays which role. This doc gives that claim structured runtime data.
- **HARDWARE-OBSERVER-2026-07** — reserved via `observation:hardware:*`; hardware profile is one facet of what the observer watches. Composition: HARDWARE-OBSERVER dispatches probes; hardware dossier receives the results.
- **INFERENCE-ROUTING-DISCIPLINE-2026-07** — Layer 2 classifier extended with fit predictions. No canon change; adds a routing input.
- **LOCAL-MODEL-SELECTION-2026-07** — its hardware-math section (2026-08 addition) is the theoretical basis for the fit-prediction functions here.
- **EXECUTION-AUTHORITY-MODEL-2026-07** — capacity failure hard-blocks via Phase 7 proposal ceremony. Existing machinery, new class of proposal.
- **TRAJECTORY-MAP-PRIMITIVE-2026-08** — map tickets whose dispatched work has heavy context (code:repo_wide) consult FitPrediction before dispatch. If dispatch would fit-fail, escalate before running any work.
- **ARTIFACT-LIBRARY-2026-05** — hardware dossiers land as artifacts under candidate → signed → superseded lifecycle. Same discipline as model dossiers.

## Reserved receipt families

Additions to RESERVED_RECEIPT_PREFIXES per Path C discipline (declare vocabulary ahead of implementation):

- `hardware:profile:` — declared, probed, reconciled, drift_suspected, missing
- `regent:hardware:` — perceived, and future variants
- `regent:routing:fit_denied` — the hard-block escalation
- `regent:routing:fit_predicted` — per-decision projection (optional, higher-volume)

## Design decisions carried from the 2026-08-02 conversation

- **Provenance: both** — operator-declared as source of truth, auto-probe reconciles, chain records both, drift flagged for operator disposition.
- **Capacity failure: strong-sovereignty hard-block** — never auto-escalate. `regent:routing:fit_denied` receipt asks operator to disposition. No silent downshift or cloud fallback.
- **Full loop** — dossiers, fit functions, Regent perception ceremony, classifier wiring, routing consumes predictions, continuous drift signal.
- **Multi-node fleet awareness: deferred.** Single-node awareness lands first; fleet-scoped routing composes cleanly once single-node ships.

## Not-in-scope for this sketch

- Fleet-scoped routing (defer to follow-up).
- Specific hardware micro-benchmark implementations for bandwidth and compute probing (implementation-phase concern; every platform has its own tools).
- Migration path for existing operators — greenfield, no existing hardware dossiers to migrate.
- Cost estimation for cloud escalation (adjacent concern; belongs in INFERENCE-ROUTING-DISCIPLINE follow-up).

## Open questions

1. **Reconciliation tolerance thresholds.** How much divergence between declared and probed before flagging drift? Per field: memory ±5%, bandwidth ±10%, compute ±15%? Needs empirical data from a few nodes.

2. **Prefill FLOPS estimation.** The prefill_time_estimate formula is approximate today. Refining it requires per-model calibration on per-hardware (analog to entropy baseline but for prefill). Same discipline; own work item.

3. **Where does the calibration battery live for hardware?** `scripts/calibrate-hardware.py`? Or a Rust binary in a new crate `zp-hardware-calibration`? Script is easier; binary composes better with the Regent's cognitive loop.

4. **KV-cache-cost-per-1k-tokens field on model dossiers.** Needs to land as a MODEL-DOSSIER schema addition. Small backward-compat change. Should ship in the same wave as this dossier's landing OR as a prerequisite.

5. **What happens when the substrate boots on a node with no hardware dossier?** Degraded mode: skip fit checks, route with confidence=Low, emit `hardware:profile:missing` receipt every N cycles until operator resolves. Or: refuse to route at all until a dossier exists. Sovereign answer probably the latter; ergonomic answer the former.

## Next step

Promotion path: (a) operator review; (b) implementation-design phase per open questions above; (c) landing as canonical Tier-2 elaboration alongside a MODEL-DOSSIER amendment adding the KV-cost field; (d) hardware calibration script + first dossier for APOLLO; (e) Regent perception + classifier wiring; (f) hard-block ceremony wiring through the approvals machinery.

Nothing lands until (a). Sketch does not obligate implementation.
