# Hardware Dossier — Regent perceives its hardware via a layered lookup, routing hard-blocks on capacity

**Tier 2 canonical elaboration (SKETCH — 2026-08-02, revised).** Proposes hardware capability as first-class corpus data reached through a **three-tier layered lookup** (identity → canon catalog → chain lookup → fresh probe), with the operator-declared dossier confined to what only the operator can know. Elaborates `KEEL-2026-07.md` §II.13 P6 (physical foundation), §II.19 (composition contract), and Part XIV (inference envelope).

Composes with: `MODEL-DOSSIER-2026-07.md` (fit predictions cross-reference model dossier + hardware dossier), `HARDWARE-ROLE-SEPARATION-2026-07.md` (which nodes exist and what role each plays), `HARDWARE-OBSERVER-2026-07.md` (partially reserved via `observation:hardware:*`; hardware profile is one facet of what HARDWARE-OBSERVER watches), `INFERENCE-ROUTING-DISCIPLINE-2026-07.md` (fit + ceiling feed the Layer 2 classifier's routing decisions), `LOCAL-MODEL-SELECTION-2026-07.md` (its hardware-math section is the theoretical basis for the fit-prediction functions this sketch specifies), `EXECUTION-AUTHORITY-MODEL-2026-07.md` (capacity-fit failure escalates as an operator-approval ceremony), `TRAJECTORY-MAP-PRIMITIVE-2026-08.md` (map-shaped work with heavy-context waypoints consults fit predictions before dispatch), `MULTI-DEVICE-OPERATION-2026-05.md` + `SUBSTRATE-COORDINATION-DISCIPLINE-2026-05.md` + `PEER-TRUST-ANCHOR-2026-05.md` + `SOVEREIGN-KINSHIP-PRIMITIVES-2026-06.md` + `HOUSEHOLD-COMPOSITION-2026-06.md` + `COMMUNITY-COORDINATION-ON-ZEROPOINT-2026-06.md` (fleet-extension seam — this sketch reserves the surface where these earlier commitments about multi-node substrate compose in).

**Status.** Sketch, not committed spec. Load-bearing framing: **the substrate reads hardware capability through a layered lookup so it costs the operator nothing to declare on a well-known machine. Every inference routing decision consults the resolved profile. A model that would not fit hard-blocks with an escalation receipt asking operator to disposition — never auto-escalates silently. The primitive is designed today with a seam where governed multi-node hardware rallying (deferred) will compose in without a redesign.**

## Framing

The corpus already has structured characterization of models (per MODEL-DOSSIER-2026-07 — Tier 2, canonical) but keeps hardware characterization as prose in LOCAL-MODEL-SELECTION-2026-07 and HARDWARE-ROLE-SEPARATION-2026-07. That asymmetry doesn't scale. When the Regent needs to route inference — "does qwen3.6:35b-a3b fit on this node with a 32k context window? what tok/s can I promise?" — it can't reason from prose. The hardware side needs structured, addressable data.

But the wrong move is to demand that every operator hand-characterize every machine before the substrate does anything useful. Most of what defines a hardware family (an M4 Pro Mac Mini, a Pi 5, an RTX 4090 workstation) is vendor-published and identical across every unit ever sold. The substrate should know this without asking. The operator should only have to declare what only they can know: which machine this actually is, what else runs on it, what quirks their specific unit exhibits.

The Regent-is-UX architectural stance (per AGENT-AS-UX-ARCHITECTURE-2026-05) makes this pressing: the operator asks the Regent a question; the Regent decides which inference target answers it; that decision has to be honest about what will actually fit and how fast the response will feel. Today the Regent chooses a model with no runtime awareness of "am I on APOLLO or on the Pi 5? do I even have the memory for what this operator is asking me to load?" The result is dispatch-then-fail-obscurely or, worse, dispatch-then-succeed-but-thrash-to-swap. Neither is sovereign.

Every inference routing decision needs three questions answered at decision time:

- **Does the target model fit on current hardware given the workload's context budget?** Capacity floor — binary. If weights + KV budget exceed effective memory, the model cannot run. There is no partial credit.
- **How fast will decode be on this hardware for this model?** Bandwidth ceiling — a promise the Regent can make to the operator (or an admission that the answer will be slow enough to route differently).
- **How long will prefill take for this context size?** Compute ceiling — matters for time-to-first-token when the context is large. `code:repo_wide` and `code:multi_file` prompts land here more often than `code` prompts do.

The sketch shipped in `70e3c0c` gave LOCAL-MODEL-SELECTION-2026-07 the theoretical framing for these three numbers. This sketch turns that framing into runtime substrate data the Regent actually consults — reached through a layered lookup that leans as heavily as possible on shared canon before falling back to operator declaration or fresh measurement.

## The layered lookup

Given "resolve the hardware profile for node N," the substrate walks a fixed sequence of sources. Each layer either produces a profile field (with provenance recorded) or defers to the next.

**Layer 1 — Identity probe (always runs).** Reads the platform's zero-cost self-identification: hostname, `uname`, macOS `system_profiler SPHardwareDataType`, Linux `/sys/class/dmi/id/product_name`, Windows `wmic csproduct`. Produces a `HardwareFamilyId` (e.g. `apple-m4-pro-mac-mini`, `raspberry-pi-5-8gb`, `dell-precision-5480-i9-13900h`). This is the key every later layer indexes by. Cost: microseconds, no calibration, no risk of drift.

**Layer 2 — Canon catalog.** A new corpus artifact: `hardware/catalog/<family_id>.toml`, curated per hardware family, holding vendor-published specifications: memory GB, memory bandwidth GB/s, prefill FLOPS by data-type, thermal envelope, chassis form (unified vs discrete). This is where an operator (or the ZeroPoint community) characterizes a hardware family **once, in one place, and every node running that family benefits**. Sovereign contribution point: the same posture MODEL-DOSSIER takes for models. Provenance is `CatalogPublished` — trustworthy for capacity and thermal envelope, indicative for bandwidth and compute (vendor numbers are aspirational).

**Layer 3 — Chain lookup.** Any prior `hardware:profile:measured` receipt on this node's chain gives us better numbers than the catalog. Recent calibration receipts trump older ones. This layer answers Ken's earlier observation: **by the time hardware information is needed for routing, the chain has often already exposed it** — the substrate has been running inferences, HARDWARE-OBSERVER has been watching, and the receipts already exist. This layer just reads them. Provenance is `ChainMeasured` — the strongest local evidence. This is the layer that grows the profile's confidence over time without asking the operator to do anything.

**Layer 4 — Fresh probe (last resort).** Only if a field is still unresolved after Layers 1–3, dispatch a live measurement: bandwidth micro-benchmark, prefill timing test on a known model. Emits a `hardware:profile:measured` receipt so the chain layer picks it up next time. This is the mechanism that fills in a truly novel field on a truly novel node — but on a well-known family with any history, it barely runs.

**Layer 0 — Operator dossier (overlay at any layer).** Independently, the operator may have a `hardware/<node_id>/hardware_dossier.toml` on disk (see next section for its narrow scope). Values from the dossier **override** whatever the lookup produced at any layer, with provenance `OperatorDeclared`. The operator is sovereign — if they say the machine has 48GB reserved for the substrate rather than 60GB, that number wins, and the lookup records both the declared and the discovered so drift can be flagged later.

Every resolved field carries provenance. Provenance quality is ranked (highest to lowest): `OperatorDeclared` (sovereignty) > `ChainMeasured` (empirical, local) > `PeerChainMeasured` (empirical, remote — reserved for fleet extension, not implemented) > `PeerCanonPublished` (community-declared, remote — reserved) > `CatalogPublished` (vendor-declared) > `IdentityInferred` (best-guess from family). Fit-prediction confidence rolls up from the weakest field's provenance.

## The dossier — narrow, operator-only

With the layered lookup carrying the weight, the operator dossier shrinks to what only the operator can know or wants to overrule.

**File.** Per-node at `hardware/<node_id>/hardware_dossier.toml`. Absent means "trust the layered lookup end-to-end for this node." Presence declares operator-specific facts.

**Sections.**

**`[identity]`** — canonical node id + hardware family id (must match a `hardware/catalog/<family_id>.toml`). The one piece of ground truth the substrate can't infer safely across every OS/platform edge case; declaring it here eliminates ambiguity.

**`[reserved_for_other]`** — how much memory, threads, or bandwidth the operator has committed to non-substrate workloads on this machine. Only the operator knows this. Fit predictions subtract these from the catalog's totals to derive `effective_*` values.

**`[quirks]`** — same schema shape as model_dossier's `[quirks]`: known failure modes for this specific unit, ceiling-vs-floor observations, per-severity annotations. Examples: "this M4 Pro throttles decode ~15% under sustained 30min load — mine specifically, warmer room", "Pi 5 with passive cooling loses 40% throughput after 5min — mine is passive". Distinct from the family-level quirks a catalog entry might list, which are population-wide.

**`[overrides]`** — explicit numeric overrides for any catalog or measured field, with a comment field mandatory. Escape hatch. Rare. When used, the layered lookup records both the override and what it would have resolved to, so future audit shows the human choice.

That's it. No published bandwidth, no compute FLOPS, no chassis form — those come from the catalog. No measured values — those come from the chain. The dossier is small, hand-authorable in minutes, and captures exactly the sovereign inputs.

**Chain-anchoring** of the dossier itself: `hardware:profile:declared` on write/amend. Amendment via supersession per ARTIFACT-LIBRARY-2026-05 lifecycle. Same as any other corpus commitment.

## Receipt families

- **`hardware:profile:declared`** — operator writes/amends the narrow dossier.
- **`hardware:profile:resolved`** — Regent emits at startup naming the fully-resolved profile with per-field provenance. Successor of the old "probed" receipt; reflects layered-lookup output.
- **`hardware:profile:measured`** — a Layer 4 fresh probe (or a HARDWARE-OBSERVER background measurement) completed and yielded a value now available to future Layer 3 chain lookups. This is the primary way the local chain accumulates truth over time.
- **`hardware:profile:drift_suspected`** — observed inference performance persistently diverges from prediction beyond a threshold. Aegis-observable per TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT.

Reserved but not yet emitted (fleet-extension seam, see below):

- `regent:rally:` — reserved namespace for governed multi-node hardware rallying. No emitters this pass.

## Fit predictions as pure functions

Given a hardware source and a model dossier, compute:

```rust
pub struct FitPrediction {
    pub fits: bool,
    pub fit_failure: Option<FitFailure>,
    pub decode_ceiling_tok_s: f64,
    pub prefill_estimate: Duration,
    pub confidence: Confidence,  // rolls up from weakest input field's provenance
}

pub enum FitFailure {
    WeightsExceedMemory { weights_gb: f64, effective_memory_gb: f64 },
    ContextKvExceedsRemainder { kv_gb: f64, remainder_gb: f64 },
    CombinedExceedsMemory { weights_gb: f64, kv_gb: f64, effective_memory_gb: f64 },
}

/// Hardware source is abstract so fleet extension can pass a peer profile
/// without changing this signature. See §Fleet-extension seam.
pub trait HardwareSource {
    fn resolved_profile(&self) -> &ResolvedHardwareProfile;
}

pub fn predict_fit(
    model: &ModelDossier,
    hardware: &dyn HardwareSource,
    context_tokens: usize,
) -> FitPrediction { ... }
```

Pure. Deterministic. No I/O. Testable in isolation. Same discipline as the WorkArc query methods and the `classify_code_scope` sub-classifier.

Derivations:
- `weights_gb` = model's quantized size from `model_dossier.deployment.footprint_gb`
- `kv_gb` = model's per-1k-token KV cost × (context_tokens / 1000) — new field needed on model dossiers, per-quantization.
- `effective_memory_gb` = catalog total − dossier `reserved_for_other.memory_gb`, subject to any override.
- `decode_ceiling_tok_s` = `bandwidth_gb_s ÷ active_bytes_per_token` where active_bytes = model.active_params × bytes_per_param.
- `prefill_estimate` = `context_tokens × prefill_flops_per_token ÷ compute.flops_prefill` — approximate; needs calibration refinement over time.

## Regent perceives its hardware

At Regent startup (in `zp-server/src/regent.rs`, right after model dossier corpus load):

1. Resolve current node id — operator-configured or hostname-derived.
2. Walk the layered lookup for this node's profile:
   - Layer 1 (identity) → `HardwareFamilyId`.
   - Layer 2 (catalog) → load `hardware/catalog/<family_id>.toml` if present; emit `hardware:catalog:missing` if not.
   - Layer 3 (chain) → scan this node's chain for `hardware:profile:measured` receipts; use most recent per field.
   - Layer 4 (fresh probe) → run only for fields still unresolved; emit `hardware:profile:measured` for what it learns.
   - Layer 0 overlay → apply `hardware/<node_id>/hardware_dossier.toml` if present.
3. Emit `hardware:profile:resolved` naming the resolved profile with per-field provenance.
4. Store `ResolvedHardwareProfile` on Regent for routing consultation.

**Bootstrap on a brand-new node** falls out of the layered lookup with no special case: Layer 1 gives an identity, Layer 2 gives catalog values if the family is characterized (usually yes for common hardware), Layer 3 returns nothing (no chain yet), Layer 4 fills any gaps with fresh probes. Confidence is Low initially and grows as chain measurements accumulate. First inference works; the routing decision just carries a `confidence: Low` marker for a while.

**Bootstrap on truly novel hardware** (no catalog entry): identity probe still succeeds, Layer 2 emits `hardware:catalog:missing`, Layer 4 fills every field with fresh probes on first run and the chain carries them forward. Operator is invited (via receipt-attached prompt) to contribute the catalog entry back once the shape is understood — sovereign contribution flywheel.

Composes with the existing `set_dossier_corpus` pattern in `zp-server/src/regent.rs` — same shape, hardware corpus (catalog + dossier) alongside model corpus. `DossierCorpus::resolved_hardware_profile()` becomes a new accessor.

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
    pub routing_rationale: String,  // "chose qwen3.6:35b-a3b: fits (24.3GB of 60GB effective), decode ceiling 148 tok/s, confidence High"
}
```

Routing algorithm (Layer 2, when envelope has multiple candidates):
1. Compute FitPrediction for each candidate model against current hardware source.
2. Filter out any that don't fit — those are hard-blocked.
3. Among fitters, apply existing precedent-based selection but with `decode_ceiling_tok_s` as a tiebreaker: faster wins if all else equal.
4. Record the filtered-out models + their FitFailure reasons + fit-prediction confidence in the decision receipt.

## Hard-block ceremony (strong sovereignty)

When the operator's directive (via Regent's chosen model) cannot fit on current hardware, do NOT auto-escalate. The substrate hard-blocks and emits:

**`regent:routing:fit_denied`** — receipt carries:
- The workload class + estimated context tokens.
- The chosen model and its FitFailure (weights, KV, effective memory).
- The provenance of the numbers that produced the failure — so operator can see whether the block came from CatalogPublished (maybe stale) or ChainMeasured (empirical) or OperatorDeclared (their own dossier).
- The available fitting models (if any) and their tradeoffs.
- An operator disposition request per EXECUTION-AUTHORITY-MODEL Phase 7 proposal ceremony.

Operator dispositions:
- Approve escalation to a specific fitting model (e.g. downshift to a smaller local variant).
- Approve escalation to cloud inference (if envelope allows).
- Approve dispatch to another node in the fleet (deferred — see §Fleet-extension seam).
- Reject and return "cannot answer on current hardware; consider expanding memory or moving to a different node."
- Adjust hardware dossier (if the failure was a wrong dossier field, e.g. reserved-for-other overestimated).

No silent auto-escalation. Every fit failure is a moment of operator visibility. Strong-sovereignty answer per today's design decision. It's stricter than most systems would tolerate; it's exactly what a sovereign trust substrate should do — because the alternative is the substrate quietly picking a cheaper/faster model without asking, which is the failure mode ZP was designed to prevent.

Composes with the approvals machinery already in `zp-regent/src/approvals.rs` — fit_denied is a specific class of approval request, same ceremony.

## Continuous drift signal

After each inference completes (in `inference.rs`'s post-dispatch hook), measure observed decode tok/s and prefill time. Compare against the FitPrediction that gated this dispatch. If observed persistently under-performs prediction (> N inferences below threshold, e.g. 30% slower than ceiling), emit `hardware:profile:drift_suspected` with observed vs predicted diff.

The same measurement, when it agrees with prediction, feeds a `hardware:profile:measured` receipt that improves Layer 3 for future lookups. Drift-detection and profile-improvement are the same mechanism observed from different angles.

Aegis observes drift receipts and surfaces to operator. Possible causes:
- Hardware degradation (thermal issues, memory pressure from other processes, physical fault).
- Wrong catalog or dossier — declared bandwidth optimistic, effective memory smaller than declared.
- Model dossier off — active_params or per-token bytes miscounted.

Operator dispositions by investigating; adjustments land as dossier supersedes or catalog PRs.

## Fleet-extension seam

This sketch lands as single-node. The corpus already carries substantial commitments about multi-node substrate — MULTI-DEVICE-OPERATION, SUBSTRATE-COORDINATION-DISCIPLINE, PEER-TRUST-ANCHOR, SOVEREIGN-KINSHIP-PRIMITIVES, HOUSEHOLD-COMPOSITION, COMMUNITY-COORDINATION-ON-ZEROPOINT — and the eventual rally primitive (deferred to its own future Tier-2 elaboration) needs to compose in without redesigning this one. The following seams are built in now so that composition is a change of implementation, not of API shape:

**Hardware source abstraction.** `predict_fit` takes `&dyn HardwareSource`, not a concrete profile. Local operation passes `&self.own_hardware`. Fleet routing will pass `&peer.hardware` for each candidate peer without changing the function.

**Provenance variants reserved.** The `Provenance` enum reserves `PeerChainMeasured` (empirical measurement from a peer's chain, transported via substrate coordination) and `PeerCanonPublished` (peer's published catalog contribution). Fit-prediction confidence weighting is defined for these ranks now (weaker than local `ChainMeasured` — you trust your own measurements more than a peer's assertion — but stronger than `CatalogPublished` when it's a peer whose PEER-TRUST-ANCHOR is established). Wire absent this pass; enum shape lands.

**Chain-lookup takes a node_id.** Layer 3 signature is `chain_lookup(node_id: NodeId) -> ProfileFields`, defaulting to `own_node_id()`. Fleet extension queries peers by passing their id. Substrate coordination discipline decides how the query travels; this API doesn't care.

**Receipt namespace reserved.** `regent:rally:*` is reserved in RESERVED_RECEIPT_PREFIXES this pass with no emitters, exactly per Path C discipline. When the rally primitive lands, its receipts have a name already declared as canonical.

**Hard-block ceremony leaves room for peer-dispatch disposition.** The `regent:routing:fit_denied` operator disposition list explicitly names "Approve dispatch to another node in the fleet (deferred)" today so the ceremony surface is already the shape it needs to be.

**Rally shape most likely to compose first: workload routing.** Ken and I discussed three shapes — routing (dispatch a workload to whichever peer fits it best), failover (peer takes over when local can't), sharded (split one workload across peers). Workload routing is the most adaptable foundation: it degenerates to local-only when there are no peers, generalizes to a fleet without changing the operator's mental model, and doesn't require the harder sharded-inference machinery. When the rally primitive is sketched, workload routing is its likely first shape and this fit-prediction API is what it will consult.

None of the above changes single-node behavior today. It just means the primitive doesn't have to be redesigned when rally lands.

## Composition summary

The hardware dossier + fit prediction primitive lands cleanly with existing corpus:

- **MODEL-DOSSIER-2026-07** — needs a new field on the dossier for `kv_cost_per_1k_tokens` per quantization level. Small schema addition.
- **HARDWARE-ROLE-SEPARATION-2026-07** — canonical claim about which node plays which role. This doc gives that claim structured runtime data.
- **HARDWARE-OBSERVER-2026-07** — reserved via `observation:hardware:*`; the observer is a primary source of `hardware:profile:measured` receipts feeding Layer 3.
- **INFERENCE-ROUTING-DISCIPLINE-2026-07** — Layer 2 classifier extended with fit predictions. No canon change; adds a routing input.
- **LOCAL-MODEL-SELECTION-2026-07** — its hardware-math section (2026-08 addition) is the theoretical basis for the fit-prediction functions here.
- **EXECUTION-AUTHORITY-MODEL-2026-07** — capacity failure hard-blocks via Phase 7 proposal ceremony. Existing machinery, new class of proposal.
- **TRAJECTORY-MAP-PRIMITIVE-2026-08** — map waypoints whose dispatched work has heavy context (code:repo_wide) consult FitPrediction before dispatch. If dispatch would fit-fail, escalate before running any work.
- **ARTIFACT-LIBRARY-2026-05** — hardware dossiers and catalog entries land as artifacts under candidate → signed → superseded lifecycle. Same discipline as model dossiers.
- **MULTI-DEVICE-OPERATION-2026-05 / SUBSTRATE-COORDINATION-DISCIPLINE-2026-05 / PEER-TRUST-ANCHOR-2026-05 / SOVEREIGN-KINSHIP-PRIMITIVES-2026-06 / HOUSEHOLD-COMPOSITION-2026-06 / COMMUNITY-COORDINATION-ON-ZEROPOINT-2026-06** — fleet-extension seam preserves the API surface these earlier commitments will need when the rally primitive lands. This sketch does not implement any of them; it doesn't break them either.

## Reserved receipt families

Additions to RESERVED_RECEIPT_PREFIXES per Path C discipline (declare vocabulary ahead of implementation):

- `hardware:profile:` — declared, resolved, measured, drift_suspected
- `hardware:catalog:` — missing (Layer 2 miss on a novel family)
- `regent:hardware:` — perceived, and future variants
- `regent:routing:fit_denied` — the hard-block escalation
- `regent:routing:fit_predicted` — per-decision projection (optional, higher-volume)
- `regent:rally:` — reserved for the deferred fleet-rally primitive; no emitters this pass

## Design decisions carried from the 2026-08-02 conversation

- **Provenance: layered lookup, operator overrides.** Identity → catalog → chain → fresh-probe → operator overlay. Provenance recorded per field. Operator dossier narrows to what only the operator can declare. Auto-probe fills gaps, not the whole picture.
- **Catalog as sovereign contribution point.** `hardware/catalog/<family_id>.toml` is the shared corpus artifact where community characterizes hardware families once. Parallel to how model dossiers are shared.
- **Capacity failure: strong-sovereignty hard-block.** Never auto-escalate. `regent:routing:fit_denied` receipt asks operator to disposition. No silent downshift or cloud fallback.
- **Full loop.** Dossiers, catalog, layered lookup, fit functions, Regent perception ceremony, classifier wiring, routing consumes predictions, continuous drift signal, measurements feed back into the chain.
- **Fleet-extension seam explicit.** Hardware source abstraction, provenance variants reserved, chain-lookup takes node_id, `regent:rally:*` reserved. Rally primitive itself deferred with corpus breadcrumbs named.
- **Rally shape most likely to compose first: workload routing.** Most adaptable foundation. Named here so future rally sketch has a starting point.

## Not-in-scope for this sketch

- The rally primitive itself (own future Tier-2 elaboration).
- Specific hardware micro-benchmark implementations for Layer 4 (implementation-phase concern; every platform has its own tools).
- Migration path for existing operators — greenfield, no existing hardware dossiers to migrate.
- Cost estimation for cloud escalation (adjacent concern; belongs in INFERENCE-ROUTING-DISCIPLINE follow-up).

## Open questions

1. **Reconciliation tolerance thresholds.** How much divergence between a resolved profile field and observed inference performance before flagging drift? Per field: memory ±5%, bandwidth ±10%, compute ±15%? Needs empirical data from a few nodes.

2. **Prefill FLOPS estimation.** The prefill_time_estimate formula is approximate today. Refining it requires per-model calibration on per-hardware (analog to entropy baseline but for prefill). Same discipline; own work item.

3. **Where does the calibration battery live for hardware?** `scripts/calibrate-hardware.py`? Or a Rust binary in a new crate `zp-hardware-calibration`? Script is easier; binary composes better with the Regent's cognitive loop.

4. **KV-cache-cost-per-1k-tokens field on model dossiers.** Needs to land as a MODEL-DOSSIER schema addition. Small backward-compat change. Should ship in the same wave as this dossier's landing OR as a prerequisite.

5. **First catalog entries.** Which hardware families ship in the initial `hardware/catalog/` set? APOLLO (M4 Pro Mac Mini) is the obvious first entry. Pi 5 8GB likely second. Beyond that, do we seed common developer machines (M-series Macs, common Linux workstations) or let the catalog grow organically as operators contribute?

6. **Chain-lookup performance.** Scanning the full chain for `hardware:profile:measured` receipts at every Regent startup is O(chain). Almost certainly needs a maintained index — a materialized view of "latest measurement per (node, field)". Where does the index live? Same shape as the receipt-tag indexes in `zp-server/src/receipt_index.rs`?

## Next step

Promotion path: (a) operator review; (b) implementation-design phase per open questions above; (c) landing as canonical Tier-2 elaboration alongside a MODEL-DOSSIER amendment adding the KV-cost field; (d) first `hardware/catalog/apple-m4-pro-mac-mini.toml` + narrow `hardware/apollo/hardware_dossier.toml`; (e) layered-lookup implementation + Regent perception; (f) classifier wiring; (g) hard-block ceremony wiring through the approvals machinery.

Nothing lands until (a). Sketch does not obligate implementation. Rally primitive is a separate sketch, not gated by this one.
