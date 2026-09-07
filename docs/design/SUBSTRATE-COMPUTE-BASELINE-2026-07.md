# Substrate Compute Baseline

**Document type:** Tier 2 canonical elaboration — design-target reference frame. Elaborates `KEEL-2026-07.md` Part XIV (Substrate Form and Operator Surface, specifically the decoupling of Substrate Form axis from Inference Sourcing axis) and Part V (Composition Contract). Names the assumed compute baseline for substrate cognitive-layer design, distinct from the Substrate Form sovereignty target.

**Author:** Ken Romero (2026-07-25). Synthesis assistance from Claude.

**Status:** Reference frame declaration. Resolves a latent framing tension in the corpus where "Pi 5 Sovereign Form" was being read as both the sovereignty target and the compute floor. Composes forward with every design decision that touches cognitive-layer capacity.

---

## What this establishes

**APOLLO-tier hardware is the assumed compute baseline for ZeroPoint substrate design.** Design decisions that touch the cognitive layer (Regent inference, Cognitive Self-Observer semantic classification, Cartographer trajectory materialization, semantic tabular reasoning, tree-search branch enumeration, ontology queries, Gate 5 build-execution) reason against APOLLO-class compute capacity — not against Pi 5 constraints.

APOLLO-tier means: modern developer workstation, ≥16GB RAM (32–64GB typical), fast local storage, capable of running mid-sized frontier models locally or via low-latency local inference, with substantial concurrent workload headroom.

**Substrate Form remains distinct from this baseline.** Pi 5 continues to constitute valid Sovereign Form per SUBSTRATE-FORM-2026-07.md — it is the operator's sovereignty anchor and rally endpoint. It is NOT the target for local cognitive-layer capacity.

---

## The two design-target axes (KEEL Part XIV, made explicit)

KEEL Part XIV.5 declares that Substrate Form is decoupled from Inference Sourcing. This doc names what each axis targets:

### Axis 1 — Substrate Form (sovereignty anchor)

Target floor: **Pi 5** (Sovereign Form minimum viable hardware). Reaches trust chain to hardware root, holds Genesis via hardware token, hosts substrate ceremony surface.

What lives here: operator identity anchor, sealed FDE / measured boot, chain storage, sovereignty-provider operations, delegation ceremony surface. This layer is compute-modest; Pi 5 is fully sufficient.

Sovereign Form graduation ceremony targets this layer. Failure to run Pi 5 as a valid Sovereign Form would violate KEEL Part XIV; running Pi 5 as the *only* compute substrate would not violate anything — it would just constrain what cognitive work is locally reachable.

### Axis 2 — Cognitive Compute (inference substrate)

Target floor: **APOLLO-tier** (modern developer workstation baseline). Runs Regent cognition, hosts foundation-model-scale weights when needed, executes semantic classifiers, materializes ontology, enumerates tree-search branches, dispatches shadow-evaluation candidate-vs-control passes.

What lives here: Regent's inference backend, Cartographer subprocess with ontology materialization, Cognitive Self-Observer semantic classifier (P2.2.5 v3+ with inference-assisted extraction), Aegis v2 trajectory scoring, extension-surface WASM modules with substantive compute needs.

Cognitive-layer design targets this baseline. Design that requires 13GB of RAM for a risk classifier, or a mid-tier foundation model for semantic classification, or a MuZero-style search tree — all are legitimate substrate design choices under this baseline. Not adopting them because "Pi 5 can't run them locally" is a category error.

---

## Composition — Pi 5 Sovereign Form + APOLLO cognitive substrate

The canonical composition per Decision C (Regent-follows-the-operator) already handles the two-axis decoupling: the Regent's presence lives on whichever device the operator is currently on; inference compute is a resource the active Regent orchestrates from anywhere in the sovereign's fleet.

Concretely, for a Pi 5 Sovereign Form + APOLLO daily-driver operator setup:

- **Pi 5 holds sovereignty anchor.** Genesis, sealed FDE, chain storage, ceremony surface. Trust chain reaches hardware root. Substrate integrity is Pi-anchored.
- **APOLLO hosts cognitive compute.** Regent inference, semantic classification, Cartographer, tree-search. Local model weights live here.
- **Rally protocol composes them.** When the operator is at Pi 5 (accessing via console, remote session, kiosk mode), Regent rallies from Pi 5 to APOLLO for heavy inference; when at APOLLO, cognitive compute is local. Rally invocations are Genesis-authenticated end-to-end, chain-anchored per invocation.

Pi 5 does not need to run local frontier inference. It does not need 32GB RAM. It does not need a TPU. Its role is sovereignty anchor and rally origin — both compute-modest.

This composition is not a workaround. It is the intended architecture per KEEL Part XIV's two-axis decoupling. Naming APOLLO-tier as cognitive-compute baseline makes the intended architecture explicit rather than latent.

---

## What this changes for design decisions

Design decisions previously constrained by "must fit on Pi 5 locally" are reframed:

- **Regent model tier** — targets APOLLO local inference (GLM 5.2 or successor at appropriate tier), not Pi-hostable model tier. Pi 5 rallies for Regent work when the operator is Pi-side.
- **Semantic classifier (P2.2.5 Shadow) inference-assisted extraction (v3)** — no Pi 5 hosting constraint. Can use tabular foundation models or larger classifiers if verification requires them.
- **Cartographer materialization** — ontology store and reasoner run APOLLO-side. Pi 5 queries via rally.
- **Tree-search / anomaly-scoring layers (Aegis v2 trajectory scoring, TabFM-style classifiers)** — architecturally coherent under APOLLO baseline. Not blocked by 8GB Pi 5 RAM.
- **Ontology-projection dashboard widgets** — heavy queries and Cartographer ontology reads compute APOLLO-side. Pi 5 dashboards proxy or rally.

What does NOT change:

- **Chain storage.** Chain lives on the sovereignty anchor (Pi 5). Rally reads pass through the chain-authoritative device.
- **Sovereignty ceremonies.** All sovereignty-touching operations require Pi 5 hardware Genesis token. Regardless of where compute runs, Genesis authority is Pi-hardware-anchored.
- **Officer cadre residency.** Officers operate on the Substrate-Form host (Pi 5) reading chain locally, emitting findings locally. Officer heartbeats do not rally.
- **Delegation gate.** Enforced Pi-side (per KEEL P8 P9). Regent proposals rally to APOLLO for reasoning; commitment decisions return to Pi-side for gate evaluation and operator signing.

---

## Composition with Substrate Form variants

### Sovereign Form (Pi 5 + APOLLO)

The canonical composition described above.

### Sovereign Form on APOLLO-class hardware (single-device deployment)

If an operator's Sovereign Form is itself APOLLO-tier (a workstation running the substrate as Sovereign Form rather than a Pi), both axes collapse to the same device. Sovereignty anchor and cognitive compute co-locate. This is a valid Sovereign Form; the two-axis framing still holds architecturally, and rally becomes optional / degenerate.

### Appliance Form

Same as Sovereign Form composition — appliance handles sovereignty, appliance-tier compute or rally to operator's daily driver handles cognitive layer.

### Companion Form

Cognitive substrate remains APOLLO-tier (operator's device); Companion Form provides vendor-bounded sovereignty ceremony surface. Rally does not cross the Companion boundary.

---

## Non-goals

- **Not deprecating Pi 5 Sovereign Form.** Pi 5 remains the canonical Sovereign Form assembly per SUBSTRATE-FORM-2026-07.md and the Pi 5 stand-up checklist. This doc clarifies its role, does not diminish it.
- **Not requiring operators to hold APOLLO-class hardware.** An operator with only a Pi 5 has a valid Sovereign Form. Their cognitive-layer options are bounded by Pi 5 local capacity, cloud mandate (per KEEL Part XIV.5), or rally to any authorized fleet device — the substrate does not refuse to operate. Design targets APOLLO-tier as the *assumption for what the substrate is built to do well*, not as a hardware requirement for operator participation.
- **Not committing to APOLLO's specific SKU.** "APOLLO-tier" is a class descriptor (modern developer workstation, ≥16GB RAM, capable local inference), not a specific machine. Ken's APOLLO instance is the reference implementation, not the specification.
- **Not amending KEEL.** KEEL Part XIV already declares Substrate Form / Inference Sourcing decoupling. This doc is a design-target clarification, not a KEEL-level change. If KEEL wants to reference APOLLO-tier explicitly in a future canonicalization ceremony, that's amendment territory.
- **Not authorizing autonomous rally without operator consent.** Rally invocations remain operator-authorized per Decision C. This doc names the compute assumption; delegation gates still enforce access.

---

## Framing note

The tension this doc resolves has been latent since Pi 5 hardware selection landed. Pi 5 Sovereign Form is a load-bearing sovereignty target — trust chain reaches hardware root, Genesis holds on hardware token, sealed FDE binds disk decryption to measured boot. All of that is real and worth the assembly work.

But somewhere in the substrate design process, "Pi 5 Sovereign Form" started being read as also *the compute substrate*. That reading conflicts with almost every cognitive-layer design decision that's landed: semantic classification, Cartographer ontology, foundation-model-scale inference for Regent, tree-search anomaly scoring, dashboard widgets querying rich state. None of these fit Pi 5 local compute comfortably; all fit APOLLO-tier easily.

The intended composition — Pi 5 sovereignty + APOLLO cognitive compute + rally between them — is coherent under KEEL Part XIV. Naming APOLLO-tier as the cognitive-layer baseline makes the intent explicit and stops the "we can't do X, Pi 5 can't run it locally" objection from surfacing on every architectural decision. Pi 5 is not supposed to run it locally. That's what rally is for.

## What composes from here

Immediate:
1. Add compact reference to this doc in `SUBSTRATE-FORM-2026-07.md` (cross-reference, not content duplication) so future readers connect the two.
2. Any pending design decision blocked on "Pi 5 can't run it locally" concerns — re-evaluate under APOLLO baseline.
3. Extension of TabFM/tree-search evaluation: the compute-footprint tension collapses; license and layering tensions remain (see the current discussion arc).

Near-term:
1. Formalize rally protocol per Decision C — how the Pi-side substrate authenticates rally requests to APOLLO, how APOLLO-computed results return signed, how latency budgets are chain-anchored per invocation.
2. Document the multi-device fleet composition patterns operators can build (Pi 5 + APOLLO, Pi 5 + APOLLO + laptop, Pi 5 fleet + shared APOLLO, etc.).

Longer:
1. As Substrate Form variants proliferate (Sovereign Appliance, Sovereign Workstation, Companion variants), each declares its cognitive-compute posture per this doc's frame.
2. Rally-latency measurements chain-anchored per fleet as empirical data for INFERENCE-ROUTING-DISCIPLINE tuning.
