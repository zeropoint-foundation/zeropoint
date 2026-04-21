# Cognitive Accountability — Parked Until Foundation Hardening is Complete

*Status: intentionally deferred. Dated 2026-04-14. Pick up when ZP core is*
*production-grade and the governance primitives are battle-tested.*

---

## Why this is parked

The cognitive layer sketched below depends on primitives that are currently
being hardened. Knowledge-edit receipts need the receipt schema to be final.
Trace commitments need the audit chain to be forgery-resistant under
adversarial conditions, not merely tamper-evident in the happy path. The
multi-signing / quorum architecture in the sovereignty provider notes is
exactly what eventually lets federated knowledge-edit ceremonies work
— an LLM fact inserted under an M-of-N quorum of trusted curators is a
materially stronger claim than one signed by a single party.

If the foundation isn't rock-solid, everything built on top inherits the
wobble. Cognitive provenance in particular is the kind of claim that
cannot afford to be shaky — the moment it's shown to be forgeable, the
whole thesis dies. This doc is the pin.

## The vision in one paragraph

ZeroPoint extends from portable trust for actions and delegations to portable
accountability for cognition itself, organized as a three-layer stack. Layer
1 (receipt chain) records what happened — actions, delegations, outcomes.
Layer 2 (observation loop) enforces policy — did what happened violate
constraints? Layer 3 (trace layer) reveals the computational substrate —
what reasoning path produced the decision, and is that path healthy? Layers
1 and 2 are implemented today. Layer 3 combines LARQL-style FFN decomposition
(what the model knows, as a queryable graph) with MEDS-style activation
fingerprinting (how the model reasons, as classifiable trajectory signatures)
anchored to ZeroPoint's receipt chain. The long-term result is an IDE for
minds: debuggable, auditable, surgically editable model cognition with
cryptographic rigor.

## What depends on current hardening work

Do not start the cognitive layer until these are true:

- **Receipt schema is final.** Knowledge-edit receipts extend the schema;
  they can't be built on shifting ground.
- **Audit chain is adversarial-tested.** Trace commitments are only as
  strong as the chain they anchor to.
- **Sovereignty providers are stable across v0.2+ implementations.**
  Especially Trezor (passphrase path), Touch ID (Secure Enclave), and
  Windows Hello (native WinRT). Knowledge-edit quorum ceremonies will
  reuse this surface.
- **Multi-signing / quorum architecture is designed.** Even if not fully
  implemented, the `QuorumProvider` trait extension and per-device
  enrollment file layout must anticipate knowledge-edit use cases.
- **ZP Guard allowlist is tuned.** Guard blocking routine operations will
  block trace emission too. Latency budget matters.

## The three-layer accountability stack (formalized in whitepaper v2.1, §1)

The cognitive accountability layer is specifically Layer 3 of a three-layer
accountability architecture now formalized in the whitepaper:

- **Layer 1 — Receipt chain (what happened).** Implemented today. Receipts,
  delegations, outcomes — hash-linked, tamper-evident, replayable.
- **Layer 2 — Observation loop (did what happened violate policy?).** Implemented
  today. GovernanceGate pipeline, reflection patterns, collective audit.
- **Layer 3 — Trace layer (what computational path produced what happened?).**
  Future work. This is what this document designs.

Each layer catches failures the others miss:
- Output-level observation (Layer 2) catches policy violations but cannot see
  degenerate reasoning that produces acceptable outputs.
- Trace-level introspection (Layer 3) catches degenerate reasoning but has no
  authority model — it doesn't know who authorized the computation.
- The receipt chain (Layer 1) binds both to a signed, ordered, portable
  evidence structure.

The gap *between* Layer 2 and Layer 3 is itself a signal: when observation
says "output looks fine" but the trace says "this reasoning fingerprint is
deep in an error cluster," you have caught a model producing correct answers
for wrong reasons — fragile in ways that surface under distribution shift.
This is the **confabulation gap** (see whitepaper Glossary).

## The three-layer visualization architecture

### Viz Layer 1 — Static knowledge graph (maps to LARQL)
Vindex decomposed into persistent queryable graph. Nodes are entities,
edges are relations, edge properties include layer, feature index, gate
and down vector references. Substrate: FalkorDB (Cypher-compatible,
Redis-backed, built for LLM-adjacent workloads). LARQL's SELECT/DESCRIBE
map nearly one-to-one onto Cypher queries.

### Viz Layer 2 — Decision trajectory (maps to LARQL traces + MEDS fingerprints)
Live rendering of a forward pass as motion through the static graph.
Nodes light up, edges fire, activations pulse in layer order. This is a
trajectory in the whitepaper's precise sense: evidence (activations),
ordering (layer sequence), replayability (Vindex enables bit-exact
rerun). It is literal autoregression rendered — each layer conditioned
on prior layer activations.

Overlay: MEDS-style fingerprint classification. After the trajectory
renders, the deep-layer fingerprint is computed and matched against the
error-basin clustering. If the fingerprint lands in a known dense cluster,
the visualization flags it — this reasoning path is a known failure mode,
even if the output looks correct.

### Viz Layer 3 — Provenance overlay (maps to ZP receipt chain)
Every node and edge carries its receipt lineage. Click an edge: who
inserted this fact, under what delegation, when, trust tier, revocation
status. Click a node: all facts referencing it, aggregate trust scores,
audit history. This is the layer that makes ZeroPoint's contribution
legible at a glance.

## Tool mapping

- **FalkorDB** — canonical substrate for the static knowledge graph.
  Cypher compatibility with LARQL's query surface, Redis-backed
  latency for interactive use.
- **Graffiti** (decentralized social graph protocol, if that's the
  intended tool) — federated knowledge mesh layer. Agents on different
  ZP nodes publish knowledge graph fragments with per-edge provenance
  receipts. Verifiable cross-agent knowledge transfer.
- **Graphify** (Neo4j NLP / relational extraction, if that's the
  intended tool) — training fidelity audit. LARQL tells you what
  relations the model learned; Graphify on source text tells you
  what relations the corpus actually contained. The delta is a new
  category of audit.

Confirm tool identities with Ken when this is picked up — several
projects share these names.

## Vertical-slice plan

Three incremental slices. Each slice ships independently and produces
value.

**Slice 1 — Static graph + provenance shell**
Take a small open-weights model (1B–7B range). Run Vindex extraction.
Load result into FalkorDB. Build minimal web UI for browsing the
knowledge graph and clicking edges to see a placeholder provenance
card. No trace replay yet, no real receipts yet. Validates the UI
metaphor and FalkorDB performance at scale. ~2 weeks.

**Slice 2 — Trace replay**
Capture trace at forward-pass time. Pipe layer-by-layer activation
events to the visualizer. Render trajectory as motion through the
static graph. Differential rendering to avoid full redraws. Start
with pre-recorded traces, then move to live streaming. ~3 weeks.

**Slice 3 — Real receipts on knowledge edits**
Implement the proposal → attestation → commit flow for INSERT
operations. Emit chain receipts for each phase. Surface them in the
provenance overlay. Requires zp-skills integration and the receipt
schema extensions from `docs/design/larql-integration.md`. ~3 weeks.

Total: ~8 weeks for an end-to-end demo of cognitive accountability
with visualization.

## Strategic audiences

- **Researchers** — mechanistic interpretability as a standard
  operation rather than a specialist skill.
- **Operators** — debug agent failures by replay; identify where bias,
  jailbreak, or hallucination entered the reasoning path.
- **Regulators** — answer "how was this decision made" with something
  auditable rather than a post-hoc narrative.
- **Users (long arc)** — eventually, "why did my assistant suggest
  this" becomes a graph you can inspect.

First two are immediate value. Third is the enterprise compliance
story. Fourth is the consumer-legible thesis.

## Honest caveats to carry forward

- **Polysemanticity** — single feature indices fire for multiple
  unrelated concepts. Signing "feature N asserts X" is a probabilistic
  claim, not deterministic. May require signing joint (gate, down,
  layer, context) tuples. Reconciling statistical decomposition with
  cryptographic-grade provenance is open.
- **Attention gap** — LARQL decomposes FFN. Attention routing is not
  in the graph. Trace captures which features were consulted, not why
  attention routed there. A real limit. Do not oversell.
- **Compute overhead** — full trace emission per forward pass may be
  prohibitive. Plan for tiered model: lightweight commitment hashes
  always, full traces on sampled or high-stakes calls.
- **Architecture coverage** — LARQL targets standard transformer FFN.
  MoE, state-space models, hybrids will need separate decomposition
  primitives. Consider an architecture-neutral abstraction.
- **Provenance ≠ correctness** — a fact inserted correctly through the
  two-phase commit can still be false. Chain proves authorship, not
  truth. Must be stated explicitly because people will expect
  cognitive provenance to mean cognitive correctness, and it does
  not.
- **Verifier access to weights** — trace commitments only help if a
  verifier can reconstruct and check them, implying Vindex access.
  Confidential-weight scenarios need a different model (ZK proofs
  over trace verification? deferred problem).

## Rendering engineering notes

- Transformer FFN graphs reach millions of edges. Naive rendering
  melts. Need hierarchical clustering, progressive disclosure, WebGL.
  Candidates: Cytoscape.js with WebGL renderer, custom regl/Three.js,
  Deck.gl for very large graphs. d3 alone is not enough.
- Polysemanticity makes single-node-per-feature misleading. UI should
  separate "feature" and "relation" as distinct node types with a
  toggleable view.
- Provenance lookups on edge-click at scale: materialize receipt
  attribution into FalkorDB edge properties, lazy-load the full
  chain on inspection.

## Related artifacts in this repo

- `docs/design/governed-agent-runtime.md` — **the GAR spec (Phase 4)**.
  The GAR's reasoning attestation layer (Section 5.5) is the concrete
  precursor to this document's Layer 3 vision. The GAR provides:
  `reasoning_hash` linkage on every receipt, three inference trust tiers
  (attested/observed/unattested), and the process-level containment that
  makes full trace capture possible for local models. When this cognitive
  accountability work resumes, the GAR's attestation infrastructure is
  what LARQL decomposition and MEDS fingerprinting plug into.
- `docs/ARCHITECTURE-2026-04.md` — north star document. Phase 4 section
  positions the GAR as the bridge between the current substrate (Phases 0-3)
  and this cognitive accountability layer.
- `docs/related-work-larql.md` — whitepaper §15 stub entries (LARQL + MEDS)
- `docs/design/larql-integration.md` — cognitive accountability layer design
  note with schema sketches (TraceCommitment, KnowledgeEditProposal,
  ReasoningFingerprint, DriftSignal) and open questions
- `docs/whitepaper-v2.md` §1 — "The Three Layers of Accountability"
  subsection (formalized in whitepaper)
- `docs/whitepaper-v2.md` §12, item 9 — roadmap entry for cognitive
  accountability layer
- `docs/whitepaper-v2.md` Appendix B — glossary entries for Trace
  Commitment, Error Basin, Confabulation Gap
- `docs/whitepaper-v2.md` Appendix D — new row for subsurface
  accountability (three-layer stack)

When this work resumes, start with the design note, then re-read this
doc, then update the receipt schema stubs against whatever the hardened
core looks like.

## Unresolved questions to revisit at resume

1. Has the receipt schema settled? If not, wait longer.
2. Is the quorum architecture in place, or still aspirational? A
   single-party knowledge-edit ceremony is fine for a slice 3 demo
   but is not the production target.
3. Which open-weights model family is the first target? Llama, Mistral,
   Phi — all have different FFN structures and tokenizer quirks. Pick
   one and commit.
4. Does LARQL (Bytez) have a stable public release by then, or are we
   reimplementing the decomposition ourselves? This changes the
   engineering scope materially.
5. Has anyone else shipped something in this space in the meantime?
   Check mechanistic-interpretability landscape before starting.
6. What is the relationship between MEDS fingerprints and LARQL traces
   at inference time? Are they redundant, complementary, or orthogonal?
   Hypothesis: complementary (LARQL = knowledge path, MEDS = reasoning
   quality), but needs empirical validation.
7. Can HDBSCAN clustering run at inference-time latencies, or does it
   need to be a batch/offline operation? If offline, the drift signal
   is retrospective, not preventive. Both are useful but the policy
   implications differ.
8. How does the confabulation gap metric relate to existing
   chain-of-thought faithfulness research? Literature review needed
   before committing to a specific measurement approach.
9. What is the relationship between Mastra-style observation loops
   (external, output-level) and MEDS-style introspection (internal,
   activation-level)? ZP already has observation via `zp-observation`
   and reflection hooks. The trace layer must complement, not replace,
   this existing surface. Architectural boundary: observation catches
   output-level violations; traces catch reasoning-level degeneration.
   The gap between them is the confabulation signal.

---

*Pin set. Return when foundation is rock-solid.*
