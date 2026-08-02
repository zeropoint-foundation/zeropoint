# Regent Orchestration Artifacts — Node-RED, Temporal, and the Visualization Stack

**Tier 2 canonical elaboration (SKETCH — 2026-08-02).** Proposes adoption of `@node-red/runtime` as a flow-orchestration artifact the Regent dispatches, with Temporal as an optional durability substrate beneath, composing with the existing visualization discipline (LENS-DISCIPLINE, four canonical lenses, molecular notation, Cartographer) and the Regent-is-UX architectural stance (AGENT-AS-UX-ARCHITECTURE, AGENTIC-SURFACE, SURFACE-BOUNDARIES). Elaborates `KEEL-2026-07.md` §II.13 P6, §II.19, Part V, Part VIII, Part XIV.

Composes with: `LENS-DISCIPLINE-2026-07.md` (all Regent-produced visualizations are `lens:declared:*` receipts), `zp-visual-language.md` (four canonical view-in lenses), `RECEIPT-MOLECULAR-NOTATION-2026-05.md` (rendering vocabulary for CodeFlow-shaped artifacts), `AGENT-AS-UX-ARCHITECTURE-2026-05.md` and `AGENTIC-SURFACE-2026-05.md` (Regent is the operator's UX; no HTML surface the operator visits), `SURFACE-BOUNDARIES-2026-05.md` (canonical reference for what surface serves what concern), `TRAJECTORY-MAP-PRIMITIVE-2026-08.md` (map waypoints dispatched through Node-RED runtime; map-shape composes with subflow-shape), `ARTIFACT-LIBRARY-2026-05.md` (all Regent-produced flow runs, visualizations, and reports are artifacts under standard lifecycle), `OFFICER-ACTION-SURFACES-2026-07.md` (five-phase ceremony per flow run), `SUBSTRATE-SELF-CONSTRUCTION-2026-07.md` (Regent-dispatched builders execute flows).

**Status.** Sketch, not committed spec. Load-bearing framing: **Node-RED and the rest are artifacts the Regent uses to be the operator's UX, not user interfaces the operator visits directly.**

## Framing

The corpus takes a specific architectural stance on operator UX: **the agent IS the UX architecture**. There is no HTML surface the operator visits (per AGENTIC-SURFACE-2026-05: *"'Where does the UI live' is a 2020 question. The 2026 answer is: there is no UI, in the sense of an HTML surface a human visits."*). The operator interacts with the Regent; the Regent decides what to render, when, in what vocabulary, at what fidelity — for the current interaction, informed by the current cognitive context.

Under this stance, tools like Node-RED and Temporal are not candidates for "the ZP dashboard." They are candidates for **artifacts in the Regent's toolkit**: capabilities the Regent dispatches when appropriate, whose outputs become chain-anchored artifacts under ARTIFACT-LIBRARY's standard candidate → signed → superseded lifecycle. The dashboard question was miscast — the substrate never wanted a dashboard; it wanted a durable, chain-anchored flow-orchestration primitive the Regent could invoke, and a visualization rendering runtime whose outputs the Regent could compose into responses.

This sketch names the shape of that adoption. The pieces already exist in corpus form:

- **Visualization discipline** (LENS-DISCIPLINE Tier 2): every Regent-produced visualization is a `lens:declared:*` receipt with formal schema (focus, dimensions, keyword_composition, transformation_question, cross_references).
- **Four canonical lenses** (zp-visual-language): Abacus (temporal), Weave (authority), CodeFlow (derivation), Walk (transport). Each is a view-in lens the Regent instantiates.
- **Molecular notation** (RECEIPT-MOLECULAR-NOTATION Tier 3): the rendering vocabulary the Regent uses inside CodeFlow-shaped artifacts. Chemistry-inspired: atoms, heteroatoms, bonds, aromatic rings, functional groups, valence.
- **MorphoHDL patterns** (bookmarked): grammar-shape constraints on how visual elements compose (rewrite composition, dimensional inference, growth-driven rendering).
- **Trajectory-map primitive** (2026-08 sketch): map waypoints that need dispatch semantics beyond linear WorkArc.

What's been missing is the runtime that lets the Regent actually dispatch flow-shaped work with the durability and message-passing guarantees the substrate needs. This sketch proposes Node-RED's `@node-red/runtime` as that primitive, with Temporal as an optional durability substrate beneath.

## Load-bearing framing: everything is a Regent-dispatched artifact

The reframe from the 2026-08-02 conversation, stated as principle:

- Node-RED runtime is an artifact the Regent uses to orchestrate flow-shaped work. Not a dashboard the operator visits.
- Temporal (if adopted) is an artifact the Regent uses for durable execution guarantees. Not operator-visible.
- Node-RED's Dashboard 2.0 (FlowFuse, Vue-based) is a rendering runtime the Regent uses when producing widget-shaped visualization artifacts. Not the operator's home surface.
- The four canonical lenses are artifact schemas the Regent instantiates. When the Regent needs to show trajectory, it produces a CodeFlow artifact; when it needs to show delegation, a Weave artifact.
- Molecular notation is the rendering vocabulary the Regent uses inside CodeFlow-shaped artifacts to convey chain structure.
- MorphoHDL patterns are design constraints on how any of these compose.

The Regent decides which artifacts to invoke, produce, or reference for the current interaction. The operator interacts with the Regent. That is the entirety of the operator-facing surface. Artifacts appear inline with the interaction — sometimes rendered visually, sometimes narrated, sometimes both — per the Regent's judgment about the operator's current cognitive context.

## The stack

### Runtime layer: `@node-red/runtime` (Apache 2.0)

Adopted for its fit with substrate discipline:

- **Explicitly decomposable.** Runtime is published as its own npm package, designed to operate without the editor. Substrate embeds it; Regent dispatches to it.
- **Pluggable storage.** Storage interface swappable — implement receipt-chain-backed storage so flows, subflows, and credentials persist as receipts.
- **Message-passing with send/done lifecycle.** Each node-to-node message correlates via `msg._msgid` and `done()` callback. Maps 1:1 onto receipt open/complete. Every message-send emits a delegation receipt; every done() completes it.
- **Subflows as capabilities.** Node-RED's subflow primitive (reusable flow compositions acting as single nodes) maps directly onto ZP's capability/delegation model. A subflow IS a capability. Instantiating it IS a delegation.
- **Message routing on path to pluggable** (Node-RED roadmap). When it lands, this is the seam for generating trajectory receipts at map scope per TRAJECTORY-MAP-PRIMITIVE-2026-08.

### Durability layer: Temporal (Apache 2.0 / MIT core) — default on

Node-RED's event loop does not survive process crashes with exact-once resumption. A waypoint in flight that disappears without a resolution receipt is exactly the class of un-anchored substrate event the chain discipline was built to eliminate. Temporal's durable execution guarantee — workflows survive crashes, resume exactly where they left off, produce receipts at deterministic points — fills that gap.

The safety-net posture across the substrate is durability-on-by-default. This sketch adopts the same posture for the flow-orchestration layer specifically: **Temporal beneath Node-RED is default on whenever Node-RED runtime is active.** The operator can opt out for local/dev/light deployments where operational simplicity is preferred over exact-once guarantee, but opting out is an operator-signed receipt with rationale — same discipline as tieoffs.toml or any other declared exception. Silent absence of the safety net is not a posture the substrate allows.

Layering clarifies the "always on" claim without pretending Temporal covers cases it doesn't:

- **Chain-anchored idempotency: always on** (property of the substrate; not opt-outable). Every action produces a receipt; duplicates dedupe by hash. This is the substrate's foundational durability floor.
- **Node-RED runtime with receipt-chain-backed storage: on when flow-orchestration is being used** (presence of open trajectory maps or Regent-dispatched flow work signals it).
- **Temporal beneath Node-RED: default on when Node-RED is active.** Opt-out is a `regent:config:durability:temporal_disabled` receipt (or equivalent) carrying operator signature and rationale. Audit trail then shows the reduced-posture choice explicitly; future operators or the operator's future self can reason about the rationale and reopen the question if it no longer holds.

What Temporal specifically adds beyond the chain's idempotency floor is *mid-flow exact-once resumption for multi-step flows with side effects between steps* — a workflow that crashes at step 3 of 5 resumes at step 3, not from scratch. This is the class of guarantee that matters for flow-orchestration workloads (Node-RED runtime, trajectory-map waypoints, long-running builder dispatches). For linear WorkArc and individual tool dispatches, the chain's idempotency floor is already sufficient — Temporal is not consulted for those.

Trade-off note on Trigger.dev vs Temporal (a decision named as still-open in earlier substrate thinking): Trigger.dev's at-least-once + idempotency composes cleanly with the chain (which already provides idempotency by hash). Temporal's exact-once is belt to the chain's suspenders, not replacement. This sketch defaults to Temporal because belt-and-suspenders is what the substrate wants for the specific class of receipts operator sovereignty depends on — but the opt-out path lets operators choose Trigger.dev-or-equivalent if operational simplicity is more important than the exact-once guarantee.

### Rendering layer: FlowFuse Dashboard 2.0 (Apache 2.0)

The Vue-based rendering runtime for widget-shaped visualization artifacts. NOT adopted as "the operator's dashboard" — adopted as one deployment target the Regent uses when producing widget-shaped visualizations.

The visualization discipline (LENS-DISCIPLINE + four lenses + molecular notation) is the source of truth for what to render. Dashboard 2.0 is one embedding of it. Other embeddings (SVG artifacts inline with Regent responses, ASCII CLI outputs for `zp` verbs, HTML documents deposited to ARTIFACT-LIBRARY) all consume the same lens declarations, differing only in rendering runtime.

## Composition with the visualization discipline

The visualization discipline is Tier-2 canonical and load-bearing. Node-RED-integrated visualizations must comply with it — not because it's convenient but because that's the mandatory schema for any Regent-produced visualization per LENS-DISCIPLINE §2.

Concretely:

**Every Regent-produced visualization artifact declares as a `lens:declared:*` receipt.** The declaration carries `focus`, `dimensions`, `keyword_composition`, `transformation_question`, `cross_references` per LENS-DISCIPLINE §1. Not optional. Not "we'll formalize later." The lens discipline exists to prevent ad-hoc UI accretion; this sketch does not undo that.

**Widget-shaped visualizations map to the four canonical lenses.**

- **Abacus** — temporal + volume. Any widget answering "when did this happen and how much of it?" produces an Abacus-lens artifact. Beads-on-wires rendering; time flows left → right; bead-zero always leftmost; count-before-narrate; no re-sort animation. Node-RED can render this in Dashboard 2.0 via a custom Vue widget consuming an Abacus lens declaration.
- **Weave** — authority topology. Any widget answering "who can do this, authorized by whom?" produces a Weave-lens artifact. Hierarchy from Genesis; typed nodes; one hop at a time; stable between refreshes. Node-RED renders via a Weave-lens Vue widget.
- **CodeFlow** — derivation and provenance. Any widget answering "how was this derived?" produces a CodeFlow-lens artifact. Layered DAG (dagre); labeled edges; integrity as first-class color. **Molecular notation is the rendering vocabulary inside CodeFlow** — atoms for routine receipts, heteroatoms for sovereign events, bonds for hash-links, aromatic rings for closed ceremonies, functional groups for named patterns, open valence for pending attestation.
- **Walk** — the temporal transport operator, composes with any spatial lens. Replay, scrub, live-flow-highlight. Node-RED can drive Walk-shaped interactions by dispatching timed messages through the runtime.

**New lens declarations** — if the Regent needs a visualization shape not covered by the four canonical lenses, it declares a new one through the LENS-DISCIPLINE receipt ceremony. Novel lens types escalate to operator per EXECUTION-AUTHORITY-MODEL; precedent-matching types auto-proceed. Same governance the substrate applies to novel receipt families everywhere else.

**Cartographer materializes lens receipts into ontology nodes.** Node-RED does not replicate Cartographer's role — it composes with it. Flow runs the Regent dispatches through Node-RED emit lens-declaration receipts; Cartographer projects them into the ontology; the Regent queries the ontology as part of cognitive input plane composition.

## Composition with the trajectory-map primitive

The 2026-08 trajectory-map sketch proposes map-shaped work with waypoints, blocking relationships, frontier, fog, and emergent destinations. Node-RED's runtime is a strong fit:

- **Waypoints dispatch as subflow invocations.** Each map waypoint becomes a subflow instantiation with typed inputs and typed outputs. Waypoint resolution IS the subflow completing.
- **Blocking relationships as message dependencies.** A waypoint blocked-on another waypoint's resolution is a Node-RED node waiting on an inbound message from the resolution node. Native to the runtime.
- **Frontier is the set of takable subflows** — subflows whose inbound-message dependencies are all satisfied. Node-RED already knows how to compute this; the trajectory-map primitive queries the runtime for its frontier per cycle.
- **Fog visualization** — the map's un-takeable waypoints render as un-fired Node-RED nodes; Dashboard 2.0 can show the flow graph with fired vs unfired distinguished. This is the operator-visible surface for a map-in-progress, if the Regent judges the operator wants to see it.
- **Aegis trajectory observation** — Node-RED's message-routing seam (when pluggable) intercepts every node-to-node message; the interceptor emits trajectory receipts Aegis reads.

Landing Node-RED and the trajectory-map primitive together means neither has to bespoke-implement the other's mechanism. They co-design cleanly.

## Shaping influences (design constraints from adjacent corpus)

Even though this sketch adopts Node-RED wholesale for the runtime, three influences constrain HOW the integration is designed:

1. **MorphoHDL patterns** (per zp-visual-language bookmark and 2026-08-02 conversation): compositions should be rewrite-rule-shaped rather than ad-hoc; layout should derive from grammar not be manually painted; visual should emerge from flow structure. Node-RED's subflow primitive is already close to rewrite-rule composition — the constraint is to make subflow definitions declarative-grammar-shaped rather than opaque node constructors.

2. **Molecular notation** (per RECEIPT-MOLECULAR-NOTATION-2026-05): edge-type explicitness is Phase 2 of the molecular adoption plan. Any Node-RED-integrated flow that emits chain receipts should emit typed edges (hash-link, reference, derivation) — enables the CodeFlow-lens artifact to render with molecular vocabulary. This is a schema commitment on the receipt side, not just a rendering choice.

3. **Regent-is-UX** (per AGENT-AS-UX-ARCHITECTURE and AGENTIC-SURFACE): no operator-facing surface that isn't mediated by the Regent. If Dashboard 2.0 accidentally becomes something operators bookmark and visit directly, the integration has failed. Success criterion: operator finds Dashboard 2.0 only when the Regent produces a widget in response to a specific question, opens the widget inline with the interaction, and closes it when the interaction ends. Widget URLs should not be memorable or shareable outside a Regent-mediated context.

## Ceremony

### Dispatching Node-RED

Regent identifies flow-shaped work (per novel-vs-precedent classification, per EXECUTION-AUTHORITY-MODEL). If precedent-matching, dispatches via a `regent:tool:node_red_dispatch` receipt referencing the subflow and its typed inputs. If novel, escalates to operator per approval-request ceremony.

The dispatch triggers Node-RED runtime execution. Every node-to-node message inside the runtime emits a `flow:message:sent` receipt via the pluggable message-routing seam. Every subflow completion emits a `flow:subflow:completed` receipt. Every flow-run completion emits a `regent:tool:flow_run:completed` receipt with the outputs. Cartographer materializes the flow-run into an ontology node.

### Producing a visualization artifact

Regent decides a widget-shaped visualization serves the current interaction. Regent chooses (or declares) the appropriate lens. Regent emits a `lens:applied:<lens_id>:<invocation_id>` receipt carrying the work context and the transformation_question result. Regent dispatches Node-RED to render the visualization via Dashboard 2.0's widget runtime, targeting the appropriate lens. Output is an artifact under ARTIFACT-LIBRARY (candidate → operator can sign to promote → superseded when a newer rendering of the same context lands).

### Amending a flow

Flows themselves are artifacts. Regent-authored subflows land as candidates; operator signs to promote to signed; a newer version supersedes an old one via the standard ARTIFACT-LIBRARY lifecycle. Node-RED's storage plugin persists subflows as chain-anchored artifacts, not local JSON files.

## Design decisions carried from the 2026-08-02 conversation

- **Node-RED runtime, yes.** Adopted for the reasons above.
- **Node-RED Dashboard 2.0, as a rendering target only.** Not adopted as "the dashboard the operator visits."
- **Temporal beneath Node-RED, default on.** Adopted as the substrate's flow-orchestration durability layer. Operator opt-out is an operator-signed receipt with rationale — declared exception, not silent absence. Aligns with substrate discipline: safety-off-by-default is the wrong posture for infrastructure that must survive operator death and hardware failure.
- **Visualization discipline is authoritative.** Every Regent-produced visualization is a `lens:declared:*` receipt per LENS-DISCIPLINE. Non-negotiable.
- **Four canonical lenses are the operator-facing question framework.** Node-RED-embedded widgets fit within them or introduce new ones via the declaration ceremony.
- **Molecular notation is the rendering vocabulary for CodeFlow-shaped artifacts.** Not aspirational; Phase 2 of its adoption (edge-type schema) is a prerequisite for CodeFlow-lens artifacts to reach their designed fidelity.
- **MorphoHDL patterns as design constraints, not code adoption.** Rewrite composition, dimensional inference, growth-driven rendering.
- **Regent-is-UX is the architectural stance.** No HTML surface the operator visits. Dashboard 2.0 exists in service of Regent-mediated interactions.

## Not-in-scope for this sketch

- Specific receipt-family names beyond the sketch above (want per-family review during full spec).
- Concrete Vue component designs for Dashboard 2.0 widgets rendering the four lenses (a spec concern for the visualization surface, not this integration primitive).
- Implementation of Phase 2 of molecular notation adoption (edge-type schema — its own change).
- Migration path from any current Node-RED-adjacent tooling (there is none in ZP today; this is greenfield).
- Cross-substrate coordination when multiple substrates each run Node-RED runtimes (a distributed-systems question orthogonal to the primitive).

## Open questions

1. **Opt-out receipt schema for Temporal disable.** Default is on; opt-out is an operator-signed receipt with rationale. Exact receipt shape (family name, required rationale fields, whether it's per-deployment or per-map or global) needs spec. Suggested family: `regent:config:durability:*`.

2. **Which node-registry seam extends to substrate capabilities.** Node-RED discovers nodes from npm `node-red` entries in package.json. Substrate capabilities aren't npm packages; they're chain-declared delegations. The registry-extension shape (Node-RED plugin? capability-to-node adapter? substrate-native replacement?) needs design.

3. **Authentication replacement.** Node-RED has built-in auth; substrate replaces with Officer/Regent identity per KEEL. The replacement shape is standard (auth plugin) but needs spec.

4. **Storage plugin implementation.** Receipt-chain-backed storage of subflows, credentials, and flow-run metadata. Straightforward in shape (implement Node-RED's storage interface); the schema decisions inside (how do subflows map to artifact_ids? how do credentials interact with vault?) need spec.

5. **Molecular notation Phase 2 sequencing.** CodeFlow-lens artifacts want typed edges. Landing Node-RED without Phase 2 means CodeFlow renders lose fidelity. Should Phase 2 land as a prerequisite, in parallel, or as a follow-up?

6. **Rendering-runtime portability.** Dashboard 2.0 is one runtime; SVG-in-artifact-library is another; ASCII-for-CLI is a third. All should consume the same lens declarations. The renderer-interface spec is a needed sibling to this doc.

## Next step

Promotion path: (a) operator review; (b) implementation-design phase per the open questions above; (c) landing as a canonical Tier-2 elaboration alongside the TRAJECTORY-MAP-PRIMITIVE sketch it composes with; (d) PoC — fork `@node-red/runtime`, implement a minimal chain-storage plugin, run a hello-world flow that generates typed receipts per node transition, prove the seam.

Nothing lands until (a). Sketch does not obligate implementation.
