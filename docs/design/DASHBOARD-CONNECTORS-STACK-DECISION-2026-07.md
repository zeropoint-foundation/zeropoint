# Dashboard and Connectors Stack — Decision

**Document type:** Tier 2 canonical elaboration — architectural stack decision. Elaborates `KEEL-2026-07.md` §II.13 P6 (a tool is intent, crystallized), §II.19 (extensions), Part V (composition contract), Part VIII (bounded operator sovereignty — third-party OSS licensing gates), Part XIV (substrate form and operator surface). Records the strategic decision on ZeroPoint's operator-surface stack layers for workflows, durable execution, and dashboards.

**Author:** Ken Romero (2026-07-25), decision approved. Synthesis assistance from Claude.

**Status:** Decision landed. Trigger.dev-vs-Temporal choice deferred to implementation-phase evaluation. Integration-seam specification arcs open per §"What composes from here."

---

## Decision at a glance

| Layer | Chosen | License | Rationale |
|---|---|---|---|
| Visual flow editor | **Workflow Builder** ([synergycodes/workflowbuilder](https://github.com/synergycodes/workflowbuilder)) | Apache 2.0 | React SDK, embeddable components, back-end agnostic, Temporal-proven |
| Durable execution | **Trigger.dev** or **Temporal** | Apache 2.0 (both) | Choice deferred; both meet license + durability criteria |
| Dashboard | **Custom ZP-native widgets** | ZP-owned | Receipt-chain-aware governance views on Workflow Builder React foundation |

Design cues for dashboard UX taken from n8n (clean-room, no code reuse — n8n's SUL prevents redistribution).

## Formal lens declaration

Per `LENS-DISCIPLINE-2026-07.md`, this decision doc declares the following lens as its first-class canonical form. The stack rationale below elaborates the declaration.

- **`lens_id`**: `dashboard_connectors_stack`
- **`focus`**: how third-party OSS stacks for visual workflow authoring, durable execution, and dashboarding compose with the substrate's sovereignty discipline (Genesis-anchored auth, chain-anchored state, delegation-scoped execution, officer-observability)
- **`dimensions`**: license compatibility (fork-and-modify freedom), architectural fit (embeddable vs standalone), auth substitutability (built-in-auth replaceable by Genesis-anchored), state substitutability (built-in-storage replaceable by receipt chain), durability guarantees (checkpointing vs exact-once), TypeScript ecosystem alignment, React embedding surface, Temporal-integration precedent, sandboxing shape, node/connector discovery model
- **`keyword_composition`**: [workflow builder, visual flow, node editor, connector, dashboard, durable execution, Temporal, Trigger.dev, n8n, Node-RED, Windmill, Activepieces, Apache 2.0, AGPL, SUL, embeddable, React SDK, checkpointing, exact-once, workflow state, receipt chain, delegation-scoped, capability registry, custom auth, governance widget, Regent activity, officer status]
- **`transformation_question`**: *"does this third-party stack layer compose with substrate sovereignty (Genesis auth, chain state, delegated execution) without ceding the trust root or requiring fork-hostile relicensing?"*
- **`cross_references`**: `KEEL-2026-07.md` §II.13 P6, §II.19, Part V, Part VIII, `EXTENSION-SURFACE-2026-07.md`, `CHAIN-WATCHER-AND-COMMITMENTS-2026-07.md`, `TOOL-GOVERNANCE-LIFECYCLE-2026-07.md`, `ONTOLOGY-AND-CARTOGRAPHER-2026-07.md`, `REGENT-SELF-BUILDOUT-TRAJECTORY-2026-07.md` (Gate 5), `SHADOW-EVALUATION-PRIMITIVE-2026-07.md`, `MEDIA-PROVENANCE-INTEROP-2026-07.md`, `AI-LANDSCAPE-SIGNAL-2026-07.md`

When chain-anchored as a `lens:declared:dashboard_connectors_stack` receipt, invocation semantics follow the lens discipline: any work context matching the keyword composition triggers a `lens:applied:dashboard_connectors_stack:<invocation_id>` receipt. Silent-lens over a long observer window signals that dashboard/workflow work has drifted from the decision (either the decision is being revisited or the substrate stopped attending to the constraint set the decision resolved). Directional: outside-in (external OSS ecosystem evaluation → substrate composition).

---

## Framing

The substrate needs three operator-surface layers that are structurally distinct from its trust primitives:

- A **visual workflow authoring surface** so operators (and downstream tools) can compose multi-step actions without hand-writing every dispatch chain.
- A **durable execution engine** so workflow state survives process restarts, crashes, and long-running steps without silent-fail loss.
- A **dashboard** where governance state (chain integrity, officer findings, Regent activity, delegation posture, workflow status) is legible in one place.

Building all three from scratch would consume substrate-development capacity for years on problems the OSS ecosystem has already solved. But adoption criteria are strict: the substrate's trust discipline — Genesis-anchored auth, chain-anchored state, delegation-scoped execution — cannot be delegated to a third-party stack's built-in mechanisms. Anything the substrate adopts must be **structurally decomposable**: the stack provides authoring/execution/rendering; the substrate provides trust, identity, state, and delegation.

Two constraints filter the OSS landscape:

1. **License compatibility.** The substrate ships under its own terms; anything incorporated must permit fork-and-modify without infecting substrate licensing or requiring commercial-fork relicensing. Rules out anything under SUL (n8n), AGPL (Windmill), or restrictive commercial licenses.
2. **Architectural decomposability.** The stack must expose auth, state, node/connector discovery, and execution as substitutable seams. Rules out anything designed as an integrated product where trust primitives are baked into the app shell.

The decision below resolves these constraints for each layer.

---

## Layer 1 — Visual flow editor: Workflow Builder

**Repository:** [`synergycodes/workflowbuilder`](https://github.com/synergycodes/workflowbuilder)
**License:** Apache 2.0
**Distribution:** npm-installable React components
**Back-end coupling:** None by design — components emit workflow definitions; execution is caller's problem
**Integration precedent:** Proven with Temporal integration in the repo's examples

### Why chosen

- **Apache 2.0** permits substrate fork + modification without upstream permission or relicensing pressure. Meets constraint 1.
- **React SDK model** — the editor is a set of components (`<WorkflowCanvas />`, `<NodePalette />`, etc.) that mount into the substrate's own dashboard React tree rather than running as a standalone app. Meets constraint 2 (decomposability).
- **Back-end agnostic by design** — the editor emits workflow definitions as data; the substrate chooses execution engine, storage, auth. No built-in-auth to strip out, no built-in-database to route around.
- **Swappable execution engine** — the same reference architecture that proves Temporal integration proves substitutability. Trigger.dev integration follows the same seam.

### What this doesn't decide

The visual editor is authoring surface only. It doesn't execute workflows, doesn't persist state, doesn't authorize actions. Those are Layer 2 and substrate concerns. Choosing Workflow Builder does not commit the substrate to any specific runtime or storage model.

---

## Layer 2 — Durable execution: Trigger.dev or Temporal

Both meet license (Apache 2.0) and architectural (self-hostable, decomposable) constraints. Choice deferred to implementation-phase evaluation.

### Trigger.dev

- **TypeScript-native** — aligns with Workflow Builder's React/TS ecosystem, minimizes language-boundary friction in the operator-surface tier
- **Self-hostable** via Docker + Postgres — no cloud dependency, respects sovereignty
- **Checkpointing model** — workflow steps checkpoint their state; resumption re-runs from last checkpoint
- **Lower operational complexity** — simpler infrastructure footprint than Temporal cluster

### Temporal

- **Stronger durability guarantees** — exact-once semantics via full event-history replay
- **Crash recovery discipline** — production-battle-tested at scale (Uber, Netflix, Coinbase, etc.)
- **Language-agnostic workers** — allows Rust/Go workers alongside TypeScript, useful if substrate wants deep-runtime execution paths
- **Higher operational floor** — Temporal cluster requires Cassandra/MySQL/Postgres + task queues + history service

### The deferred decision

Trade-off matrix at implementation start:

| Criterion | Favors |
|---|---|
| TypeScript ecosystem alignment | Trigger.dev |
| Operational simplicity | Trigger.dev |
| Rust worker integration (native substrate work) | Temporal |
| Exact-once durability under crash/restart | Temporal |
| Long-running workflow complexity (days/weeks) | Temporal |
| Rapid-iteration workflow set | Trigger.dev |

The choice will be made when workflow use cases are concretized. If early workflows are short-lived operator actions (notification chains, coordinated tool dispatch, delegated remediations), Trigger.dev's simplicity wins. If workflows include long-running substrate ceremonies with tight durability requirements (multi-day delegation-negotiation flows, cross-sovereign coordination arcs), Temporal's exact-once discipline wins.

Both options preserve substrate sovereignty: state stored in operator-controlled Postgres, auth substituted at the runtime seam, no cloud dependencies.

---

## Layer 3 — Dashboard: Custom ZP-native widgets

**Approach:** Purpose-built widgets on the Workflow Builder React foundation, showing receipt-chain-aware governance state.
**Design cues:** Taken from n8n's UX polish (clean-room; no code reuse — n8n's SUL prohibits redistribution).

### Why not adopt an existing dashboard

Every dashboard in the OSS ecosystem is *product-shaped* — built around the assumed data model of its parent workflow tool. n8n's dashboard shows n8n workflows; Node-RED's shows Node-RED flows; Temporal's shows Temporal executions. None of them natively show *governance* state: chain integrity trends, officer findings correlated with delegation activity, Regent cognitive-cycle traces, standing-correction posture, quarantine-plane admissions.

Retrofitting a product dashboard to show governance state would mean either (a) shoehorning the receipt chain into a foreign data model, or (b) writing so much custom rendering that the base dashboard becomes overhead. Either path costs more than building governance-native widgets on the same React foundation the workflow editor uses.

### Widget classes (initial set)

- **Chain integrity trend** — receipt count over time, signature-verification pass rate, hash-linkage continuity, Steward attestation timeline
- **Officer status board** — per-officer heartbeat cadence, finding severity distribution, sweep coverage
- **Regent activity view** — cognitive cycle timeline, tool dispatch history, confabulation-gap findings (from Cognitive Self-Observer), current standing corrections
- **Delegation posture** — active delegations, expiring soon, revocation history, capability envelopes
- **Workflow status** — running workflows, checkpoint state, delegation gate outcomes, receipt trail per workflow step
- **Quarantine plane** — pending admissions, admitted extensions, revocations
- **Circuit breaker state** — current level, recent escalations, reset ceremonies

Each widget is a projection of chain state (per KEEL §II.13 P4 — every bit counts; the chain is the source of truth, widgets are cheap derivations). Widget authoring itself becomes a workflow of the same kind the visual editor composes.

---

## Alternatives evaluated and rejected

### n8n — rejected

- **License:** Sustainable Use License (SUL). Permits use but prohibits commercial redistribution of forks; substrate embedding + adoption would trigger SUL restrictions.
- **Verdict:** Cannot fork-and-modify commercially. Design cues (UX polish) taken clean-room only.

### Node-RED — rejected

- **License:** Apache 2.0 (would qualify).
- **Architecture:** Designed as standalone tool; jQuery-era editor UI; not decomposable into React components for embedding.
- **Verdict:** Correct license, wrong architectural shape. Would require rewriting the editor to embed; at that point, adopting Workflow Builder (already React) is cheaper.

### Windmill — rejected

- **License:** AGPLv3 — copyleft with network-use trigger. Substrate integration exposing UI over network would require substrate re-licensing under AGPL, which conflicts with substrate's own licensing intent.
- **Verdict:** License is the poison pill. Would require Windmill relicensing (not going to happen) or substrate AGPL-adoption (not going to happen).

### Activepieces — rejected

- **License:** MIT (would qualify).
- **Architecture:** Product-shaped rather than toolkit-shaped. Built-in auth, built-in state, built-in dashboard; extracting the workflow editor as embeddable requires rewriting the frame.
- **Verdict:** Correct license, wrong shape. Same reason Node-RED was rejected — building on the wrong architectural assumptions costs more than starting with a toolkit-shaped stack.

---

## Integration seams

Five substrate seams substitute for the third-party stack's built-in equivalents.

### Seam 1 — Receipt-chain storage plugin for workflow state

Workflow state (running workflows, checkpoints, event history) persists via a substrate plugin that writes to the receipt chain rather than to a foreign SQL schema. Every workflow step becomes a chain-anchored receipt; every checkpoint anchors state hash; every workflow completion anchors outcome. Composes with KEEL §II.13 P5 (store-and-forward primary) — the chain survives outages, workflow state survives with it.

Consumer: chosen durable execution engine's storage adapter interface. Both Trigger.dev and Temporal expose storage as a substitutable seam.

### Seam 2 — Message-routing interceptor for delegation receipts

Workflows dispatch actions. The substrate's delegation gate (per KEEL §II.13 P8, delegation narrowing) enforces that every dispatched action falls within the workflow's delegated capability envelope. A message-routing interceptor sits between workflow-engine action dispatch and substrate execution, checking each action against the workflow's chain-anchored delegation before permitting execution.

Consumer: workflow engine's middleware/interceptor hook. Both engines support this.

### Seam 3 — Capability registry extending node/connector discovery

The visual editor discovers available nodes/connectors from a registry. The substrate substitutes a capability-registry adapter that presents delegated capabilities as nodes, chain-anchored tool registrations as connectors, and extension-surface capabilities (per EXTENSION-SURFACE-2026-07.md) as further node classes. Operator's delegation state shapes what nodes appear in the editor — undelegated capabilities are absent, not grayed out (per the chain-configures-the-cockpit heuristic in CLAUDE.md).

Consumer: Workflow Builder's node registry interface.

### Seam 4 — Officer/Regent auth replacing built-in auth

The substrate substitutes Genesis-derived Officer and Regent authentication for the workflow engine's built-in user/session model. Workflow editor sessions authenticate via active Regent presence; dashboard access authenticates via operator Genesis + hardware token; officer-triggered workflows authenticate via officer signing keys per KEEL §II.6.

Consumer: workflow engine's auth adapter. Both engines expose this; Workflow Builder editor uses a session provider we substitute.

### Seam 5 — Governance-specific dashboard widgets

Custom widgets showing chain state, officer status, Regent activity replace generic workflow-engine dashboard views. Widgets read from substrate primitives (chain, ontology, officer findings) via the substrate's query interfaces, not from the workflow engine's data model.

Consumer: dashboard React tree — the widgets are peers of workflow-editor components, mounted into the same shell.

---

## Composition with existing corpus

### With EXTENSION-SURFACE-2026-07.md

Workflow nodes are functionally extensions. Third-party workflow nodes (community-contributed connectors for external APIs) map onto the Extension Surface capability declaration language. The Quarantine Plane admission ceremony gates community nodes at admission; the delegation gate enforces per-invocation. Adopting Workflow Builder does not create a new extension mechanism — it renders extensions visually.

### With CHAIN-WATCHER-AND-COMMITMENTS-2026-07.md

Workflows carry commitments (a workflow step that emits a notification when a chain event fires *is* a commitment). Workflow commitment receipts chain-anchor via the existing commitment primitive. Workflows survive cognitive-cycle boots because commitments do (per the chain-watcher composition property).

### With TOOL-GOVERNANCE-LIFECYCLE-2026-07.md

Every connector the workflow editor exposes as a node is a governed tool per TOOL-GOVERNANCE-LIFECYCLE. The tool's monitored → hardened → governed progression determines what workflows can invoke it. Undelegated tools don't appear in the palette; hardened tools appear normally; governed tools carry visible operator-attestation state in the node's rendering.

### With ONTOLOGY-AND-CARTOGRAPHER-2026-07.md

Workflow executions produce receipt streams the Cartographer materializes as Trajectories, Decisions, Insights, Artifacts, Frictions. A running workflow *is* a Trajectory; its checkpoints are Decisions; its outcomes are Artifacts; its failures are Frictions. The dashboard queries ontology (not raw workflow-engine tables) for status views once Cartographer lands. Pre-Cartographer, dashboard queries chain directly with structural filters.

### With REGENT-SELF-BUILDOUT-TRAJECTORY-2026-07.md

This decision partially unblocks **Gate 5** (bounded build-execution delegation). Workflows are the natural expression form for Regent-executable action classes: a `regent:build:proposed:*` receipt names a candidate build workflow; operator ceremony signs it into an executable workflow; the durable execution engine runs it within delegated scope; precedent-based (III.19) future instances of the same class run autonomously. The workflow layer supplies the "hands to keyboard" mechanism the trajectory doc names as Gate 5's core gap.

Also touches **Gate 6** (corpus consistency verification). Dashboard widgets showing lens-invocation cadence, silent-lens detection, and cross-lens composition become operator-facing surfaces for the coherence tooling Gate 6 lands.

### With SHADOW-EVALUATION-PRIMITIVE-2026-07.md

Workflow variants can be shadow-evaluated: a candidate workflow (proposed via operator ceremony) runs against the same inputs as the control workflow (currently canonical); chain-anchored comparison receipts inform the next ceremony change. Workflow-level shadow evaluation composes cleanly with the general primitive per Context 6 (extension configurations).

### With MEDIA-PROVENANCE-INTEROP-2026-07.md

Workflows involving media signing (capture-time provenance, edit-chain preservation) dispatch to substrate signing endpoints per MEDIA-PROVENANCE-INTEROP's custom-signer seam. The workflow engine sees a normal HTTP endpoint; the substrate holds the signing root.

### With AI-LANDSCAPE-SIGNAL-2026-07.md

Multi-model routing per INFERENCE-ROUTING-DISCIPLINE renders naturally as workflow nodes: a "route by precedent-vs-novelty" node dispatches to SLM vs LLM based on inference-routing evidence. Model dossier state (per EXECUTION-AUTHORITY-MODEL Phase 5) informs node availability. Provider disruption (per AI-LANDSCAPE-SIGNAL signal 6) triggers workflow-level failover paths declared operator-side, not vendor-side.

---

## Non-goals

- **Not a commitment to Workflow Builder's UI aesthetics as final.** The React foundation is the load-bearing choice; visual polish is downstream work that may involve custom styling, alternate palettes, embedding shell variations. The editor is scaffolding, not the finished cockpit.
- **Not adopting either durable execution engine's ecosystem wholesale.** Neither Trigger.dev's SaaS integrations nor Temporal's enterprise features become substrate capabilities by default. Both are used as substrate-controlled execution runtimes; ecosystem components are evaluated case-by-case against sovereignty criteria.
- **Not a decision on dashboard theming or brand posture.** Design cues from n8n are UX-pattern-level (node placement, palette organization, execution visualization), not visual-brand-level. Brand is separate work.
- **Not a commitment to keep third-party stacks forever.** If Workflow Builder's maintenance falters, or if a better toolkit-shaped alternative emerges, the decision is revisitable per the substrate's operator-signs-changes discipline. The seams designed here (auth, state, discovery, routing) make replacement possible without rewriting workflows.
- **Not authorization for Regent to autonomously execute workflows outside delegation scope.** All workflow execution runs through the delegation gate per KEEL P8 + P9. This decision provides the execution mechanism; delegation ceremony (per Gate 5) authorizes what Regent can run.

---

## Open positions

- **Trigger.dev vs Temporal — final choice.** Deferred to implementation-phase evaluation. Concrete workflow use cases will inform the trade-off. Interim design work can proceed against either.
- **Workflow definition format canonicalization.** Workflow Builder emits its own JSON schema for workflow definitions. Whether ZP adopts that schema directly or wraps it in a substrate-canonical form (with additional fields for delegation scope, chain anchoring, capability declarations) is a downstream spec arc.
- **Community node/connector admission ceremony.** How third-party workflow nodes reach the substrate: via Extension Surface admission (per EXTENSION-SURFACE + Quarantine Plane), via operator direct-install with individual ceremony, or via a workflow-node-specific admission flow with its own criteria. Prefer routing through Extension Surface for consistency.
- **Dashboard-vs-Regent surface boundary.** Some information could live in either the dashboard (visual, always-visible) or a Regent query (conversational, on-demand). Which pattern applies to which data class is UX work per the cockpit-pairing heuristic in CLAUDE.md (both surfaces, chain-anchored state underneath).
- **Multi-operator dashboard rendering.** When multiple operators share a substrate (household use case per SOVEREIGN-KINSHIP-PRIMITIVES), which dashboard widgets show whose data. Composes with coordination-not-oversight discipline (KEEL III.23) — dashboards should not become surveillance surfaces.
- **Node execution sandboxing.** Each workflow node executes with some capability envelope. Sandbox model needs specification — WASM (per Extension Surface) is the strong candidate. Composes with the general sandbox arc under Gate 5.

---

## What composes from here

Immediate design work:
1. **Integration seam specification** for each of the five seams (interface shapes, adapter contracts, error paths, chain-receipt schemas per seam).
2. **Workflow definition schema** decision — adopt Workflow Builder JSON directly or wrap.
3. **First-widget spec** — pick the highest-value dashboard widget and design it end-to-end as a reference implementation. Recommended: Officer Status Board (simplest chain query, high operator utility, exercises all seam classes at moderate depth).

Near-term implementation:
1. **Workflow Builder embedding proof-of-concept** — mount the editor in a substrate React shell, wire the capability-registry adapter as node source, verify substitution works.
2. **Chain-receipt storage adapter** for chosen execution engine — deferred until Trigger.dev-vs-Temporal decision, but seam interface can be specified now.
3. **Auth-adapter prototype** — replace built-in auth with Genesis-derived Officer/Regent session provider.

Longer-term:
1. **Node/connector admission ceremony** — route through Extension Surface per Quarantine Plane discipline.
2. **Widget suite build-out** — dashboard reaches parity with governance-state legibility that CLAUDE.md's lsof-test heuristic implies (substrate mature when its state is legible to the operator).
3. **Workflow-shadow-evaluation integration** — candidate-vs-control workflow variants per SHADOW-EVALUATION-PRIMITIVE Context 6.

---

## Framing note

This decision is not architecturally novel — it's *the* natural composition given (a) substrate sovereignty discipline as fixed constraint and (b) OSS ecosystem as the resource pool. The alternatives were narrowed by license and shape, not by preference. Both permitted execution engines meet criteria; the choice between them is downstream and low-stakes because both plug into the same substrate seams.

The load-bearing move is naming the seams explicitly. Substrate-provides-trust, third-party-provides-scaffolding is only coherent if the seams between them are specified as first-class contracts rather than discovered ad-hoc during integration. The five seams named here are the contract surface; every substrate primitive listed under §Composition-with-existing-corpus is a party to that contract.

Workflow authoring, durable execution, and dashboard rendering are operator-surface work — necessary for adoption, not central to trust discipline. Adopting well-designed OSS for them lets substrate development capacity focus on what only substrate development can do: the chain-anchored sovereignty primitives that no external tool can supply.
