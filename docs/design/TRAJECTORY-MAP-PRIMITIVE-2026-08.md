# Trajectory Map Primitive

**Tier 2 canonical elaboration (SKETCH — 2026-08-02).** Proposes a substrate primitive for coordinating multi-cycle, multi-arc work whose destination may be unknown or emergent. Elaborates `KEEL-2026-07.md` §II (WorkArc / cognitive loop) and §II.18 (chain-watcher and commitments). Composes with `TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT-2026-07.md` (Aegis observes map trajectory), `OFFICER-ACTION-SURFACES-2026-07.md` (five-phase ceremony per waypoint), `SUBSTRATE-SELF-CONSTRUCTION-2026-07.md` (builder dispatch executes waypoints), `EXECUTION-AUTHORITY-MODEL-2026-07.md` (novel-vs-precedent gate for waypoint types), `SHADOW-EVALUATION-PRIMITIVE-2026-07.md` (prototype waypoints dispatch to shadow-eval), `ARTIFACT-LIBRARY-2026-05.md` (destinations are artifacts under the standard lifecycle), `CHAIN-WATCHER-AND-COMMITMENTS-2026-07.md` (blocking relationships are commitments). Canonical claims live in KEEL; this sketch would need promotion + KEEL amendment to become canon.

**Status.** Sketch, not committed spec. Emerged from a 2026-08-02 conversation about Matt Pocock's Wayfinder skill (a session-scoped agent planning tool) and the question of how ZP handles ambitious multi-cycle work when the destination is fog. The Wayfinder shape is instructive; the ZP version diverges around chain-anchored truth, sovereignty, and trajectory-aware constitutional enforcement.

## Framing

The current `WorkArc` primitive (`crates/zp-regent/src/context.rs`) is a linear thread: an operator directive opens an arc, the Regent works cycles until it responds or abandons, `tool_history` accumulates monotonically, `directive` carries what the arc exists to satisfy. This works for arcs whose destination is known when the directive lands: "batch-sign the unsigned entries," "compact the chain to N," "run substrate validation." The Regent knows what done looks like and pathfinds directly there.

The trajectory map primitive is **not a peer struct to WorkArc — it is what WorkArc grows into when it takes on waypoints**. Every arc is a map with zero waypoints. A directive that stays arc-shaped just never opens any waypoints and its `tool_history` alone carries the work. A directive that opens waypoints promotes the same arc into map mode; the waypoint set, blocking relationships, heading, trajectory, and destination hypotheses are fields on the existing `WorkArc`. This is a structural continuity choice, not a modeling one — it preserves the invariant that "a WorkArc is one unit of coherent work the Regent is doing" and lets the map affordances be lit up incrementally rather than requiring a whole parallel machinery for the fog-shaped case.

Two classes of directive break this model:

**Directives with foggy destinations.** "Figure out how the emission-observer should behave." "Design a Layer 2 classifier that supports multi-model envelopes." "Understand what the operator-visible artifact-review UX should look like." The operator names a heading; the destination emerges as understanding sharpens; the work is a mix of research, prototypes, conversations, and eventual concrete construction. Linear WorkArc cannot express this shape — the arc has no destination to path toward, only a heading, and its cycles keep bumping into "we can't decide X yet because we haven't researched Y."

**Directives with no destination at all.** "Explore the space of what Layer 2 could enable if we ran with it." "Think about the shape of substrate hardening we don't yet have a mechanism for." The operator wants exploration; the value IS the trajectory, not any arrival. Every existing primitive assumes eventual arrival, which forces these directives to either be shoehorned into false destinations or handled entirely off-chain.

The trajectory map primitive names both classes as first-class substrate work. A map has a **heading** (operator-signed, always present, the directional signal), an evolving set of **waypoints** (research, prototype, grilling, task — each a scoped sub-arc dispatchable through existing builder machinery), an emergent **trajectory** (the projection over resolved waypoints that shows where the work is heading), and — optionally, and only if it crystallizes — a **destination** (which is an artifact under `ARTIFACT-LIBRARY` lifecycle, not a mutable map field). Nothing about the map violates append-only. The map itself is a query over receipts.

## Load-bearing principle: destination is a diagnostic, not a goal

The mistake would be to model the map as "here is your target, path to it." That framing forces the fog-only case to look degenerate ("map has no target — it's broken"). The correct framing is: **the map is trajectory-forming work; a destination is what has happened when the trajectory has converged enough to name.**

Concretely:

- A map may open with a destination hypothesis (operator says "figure out X, I think the answer will look like Y"). The hypothesis is a receipt like any other — subject to the same supersede-and-anchor discipline artifacts already follow.
- A map may open with no destination at all (operator says "explore X"). This is a normal state, not a defective one. The heading is enough to open the map; destination emerges from work or doesn't.
- Trajectory is observable at any point — it's the projection over the map's resolved waypoints. Aegis watches it (per `TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT-2026-07`) and surfaces divergence to the operator.
- Destination-declaration is a *diagnostic*: "the trajectory has converged enough that we can name where we're going." Not-yet is a valid state. Never is a valid outcome (the map settles as `abandoned` or `settled-without-destination`, both of which preserve the trajectory record as evidence for future maps in the same heading area).

This inverts the assumption baked into most planning systems (including Wayfinder), which model destination as the goal to reach. Here, destination is the *outcome you observe if it emerges* — the substrate primitive is trajectory; destination is one possible thing trajectory does.

## The map primitive

A **Trajectory Map** is a chain-anchored coordination structure with these components:

### Heading

Operator-signed, always present, the directional signal. Distinct from an artifact-library destination (specific target); relates directly to `WorkArc.directive` (see below). Heading is: "the space I'm interested in mapping." Examples:

- "chain-hygiene tooling"
- "emission-observer design"
- "what Layer 2 classifier envelopes could look like"
- "operator-visible artifact-review UX"

**Relationship to `WorkArc.directive`.** The heading is the directive re-typed for map-shape work — same field, same operator signature, same anchor receipt, different classification. An arc-shaped directive stays as-is (specific instruction, no map affordances light up). A map-shaped directive IS the heading; the WorkArc's `directive` field carries it verbatim. Operator or Regent may amend a map's heading through the standard directive-superseded ceremony (see `EXECUTION-AUTHORITY-MODEL` phase 7 — proposing a mechanism change), which structurally opens a new arc that supersedes the current one.

Encoded as an `arc:map:opened` receipt (or the existing arc-open receipt with map-shape flag — implementation detail) carrying `heading: String` and an optional `destination_hypothesis` field.

### Waypoints

Scoped sub-arcs of work. Each waypoint has:

- **Type**: one of `research`, `prototype`, `grilling`, `task`. Type is a scheduling signal — the substrate dispatches different mechanisms per type (research and task go to builder dispatch per SUBSTRATE-SELF-CONSTRUCTION; prototype dispatches to shadow-evaluation per SHADOW-EVALUATION-PRIMITIVE; grilling opens an operator conversation via approval-request machinery).
- **Rationale**: why this waypoint, what fog it's clearing.
- **Blocking set**: receipt ids that must exist in the chain before this waypoint becomes takable. Empty set means the waypoint is on the frontier. Non-empty means it's in fog awaiting resolution.
- **Expected outcome**: what the waypoint's resolution receipt is expected to contain (used by Aegis to detect trajectory divergence when actual outcomes don't match).

Waypoints are opened via `arc:waypoint:opened` receipts (map-scoped). Resolved via `arc:waypoint:resolved` receipts that reference the opening receipt and carry the outcome. Waypoints themselves follow the five-phase officer ceremony (`OFFICER-ACTION-SURFACES` §"five-phase action ceremony lifecycle") — a waypoint's resolution IS the ceremony completing.

### Trajectory

The projection over resolved waypoints. Not a field — a query. Given a map, its trajectory is: the sequence of waypoint resolutions in chain order, with each resolution treated as a directional signal (either confirming the heading or bending it). Aegis reads the trajectory continuously and emits `aegis:action:trajectory_alert` if the trajectory diverges beyond a threshold from the heading, or from prior maps in the same heading area.

### Fog

The set of waypoints known to be needed but not yet takable (blocking set non-empty). Fog is a first-class state — a waypoint in fog is not a defect, it's a named uncertainty the map is tracking. When a fog waypoint's blockers all resolve, it promotes to the frontier automatically (via query, not receipt).

### Frontier

The set of waypoints currently takable (blocking set empty, not yet resolved). This is the primary operator-and-Regent view of "what can we do next in this map." Empty frontier + non-empty fog means the map is waiting on the resolution of blocking waypoints. Empty frontier + empty fog means the map has run out of waypoints — either the destination emerged (settle with artifact) or the exploration converged (settle with abandonment + rationale).

### Destination

Optional. If the trajectory converges enough to name a target, an `arc:map:destination_proposed` receipt names it (the target is an artifact per ARTIFACT-LIBRARY — a spec, a design decision, a config change, whatever the domain wants). The operator signs `arc:map:destination_accepted`, promoting it to the current destination. A later understanding may supersede it via `arc:map:destination_superseded` + a new proposal. The current destination is a query over the sequence: "the most recent proposal that has been accepted and not superseded."

Destination is never a mutable field. Every transition is a receipt. This is how append-only survives the fog-clarifying case cleanly.

## Ceremony

### Opening a map

1. Operator issues a directive.
2. Regent classifies the directive as map-shaped or arc-shaped (novel-vs-precedent per EXECUTION-AUTHORITY-MODEL). Arc-shaped directives use the existing WorkArc; map-shaped directives escalate.
3. For a map-shaped directive, Regent emits `arc:map:proposed` naming a heading, an optional destination hypothesis, and an initial waypoint set. This is an approval-request per the existing approvals machinery.
4. Operator signs `arc:map:opened` (perhaps modifying the initial waypoint set or heading). The map is now open.
5. Regent begins working the frontier.

### Working the frontier

Each cycle, Regent picks a takable waypoint (heuristic — probably deepest-current-fog-clearer or operator-prioritized-if-any) and dispatches it via the appropriate mechanism per its type. On resolution, the waypoint's outcome may:

- Confirm the current trajectory (no map change).
- Open new waypoints (fog resolves into concrete work). Each new waypoint is an `arc:waypoint:opened` receipt referencing the resolving waypoint. Novel waypoint types (types the map's precedent hasn't seen) escalate to operator per EXECUTION-AUTHORITY-MODEL; precedent-matching types auto-proceed.
- Propose a destination (`arc:map:destination_proposed`), awaiting operator disposition.
- Bend the trajectory enough to trigger Aegis alert.

### Operator contribution

The operator can, at any time, sign receipts that mutate the map:

- Add a waypoint (`arc:waypoint:opened` operator-signed).
- Reprioritize the frontier (`arc:map:priority_hint`).
- Reject a Regent-proposed waypoint (`arc:waypoint:rejected`).
- Accept or reject a destination proposal.
- Split a waypoint into multiple (`arc:waypoint:split` referencing the original).
- Redirect the heading — but this opens a new map that supersedes the current one, rather than mutating in place.

### Closing a map

Three terminal states, each an operator-signed receipt:

- `arc:map:settled_with_destination` — a destination artifact was signed; the map's work is complete; downstream work (e.g. implementation of the spec) proceeds under a new arc.
- `arc:map:settled_without_destination` — the exploration converged; the operator has learned enough about the heading area; no build results but the trajectory is preserved as future evidence.
- `arc:map:abandoned` — the map is being closed without settlement (operator changed priorities, the space turned out to be different than expected, etc.). Requires a rationale receipt.

None of the terminal states delete anything. The map remains queryable; its receipts remain on chain; the trajectory remains evidence for future maps in the same heading area.

## Composition

- **`TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT-2026-07`.** Aegis observes each map's trajectory. Divergence within a map, across maps, or from prior settled maps in the same heading area triggers constitutional review. The map primitive gives Aegis a scoped surface to reason about — instead of watching the substrate's total trajectory, it can watch per-map trajectories with different thresholds per heading area.

- **`OFFICER-ACTION-SURFACES-2026-07`.** Each waypoint is an officer-action-shaped work item. The five-phase ceremony (written → executed → tested → verified → signed) applies per waypoint. The map coordinates waypoints; waypoint ceremony is unchanged.

- **`SUBSTRATE-SELF-CONSTRUCTION-2026-07`.** Builder dispatch is the mechanism for research and task waypoints. The Regent charts the map; builders execute individual waypoints; results return to the Regent's chain.

- **`SHADOW-EVALUATION-PRIMITIVE-2026-07`.** Prototype waypoints dispatch to shadow-evaluation. A prototype waypoint's resolution IS a shadow-eval outcome. This is the antidote to waterfall — high-fidelity feedback on candidate directions before committing to them.

- **`EXECUTION-AUTHORITY-MODEL-2026-07`.** The precedent-vs-novel gate applies at map-open (does this directive have precedent for map-shape?) and at waypoint-open (does this waypoint type have precedent for auto-proceed?). The Regent's Phase 7 states (`regent:proposal:*`) compose naturally with map ceremony.

- **`ARTIFACT-LIBRARY-2026-05`.** Destinations ARE artifacts. Destination-proposed → candidate. Destination-accepted → signed. Destination-superseded → superseded. This is the discipline that already handles operator-signed outputs; maps just declare that a settled destination is an artifact of the map's work.

- **`CHAIN-WATCHER-AND-COMMITMENTS-2026-07`.** Blocking relationships between waypoints are commitments — a waypoint in fog is a `check-at` commitment waiting on the presence of specific resolution receipts. This is not a separate mechanism from commitments; it IS commitments applied at map scope. Worth deciding whether to unify or keep parallel.

## Divergences from Wayfinder

For operator-familiarity with Matt Pocock's tool, worth naming what's different:

- **Chain-anchored, not issue-tracker-backed.** Wayfinder stores its maps in GitHub Issues (or Linear, etc.). ZP maps are receipt sequences on chain. Sovereignty and append-only require this.
- **Destination is emergent, not required.** Wayfinder assumes a destination exists somewhere; you just haven't found it. ZP treats destination as one possible outcome of trajectory work; not-emerging is a valid outcome.
- **Trajectory is first-class.** Wayfinder has no analog to Aegis-watching-trajectory. Divergence detection is manual in Matt's tool; it's a substrate discipline here.
- **Precedent-vs-novel is explicit.** Wayfinder implicitly trusts the agent's judgment on when to escalate vs proceed. ZP requires the escalation gate per EXECUTION-AUTHORITY-MODEL.
- **Specs are superseded, not deleted.** Matt deletes the spec issue after implementation lands. ZP supersedes it via ARTIFACT-LIBRARY. The chain preserves the whole evolution.

## Design decisions and remaining open questions

Some of the questions raised during the 2026-08-02 conversation have provisional answers; others remain open. Recording both so future spec work has a starting point.

### Provisionally decided

**Map is an extension of WorkArc, not a peer primitive.** Every arc is a map with zero waypoints. Waypoint-set growth is what promotes an arc into map mode. Field additions on `WorkArc` (waypoint set, blocking relationships, heading marker, destination hypotheses, trajectory projection cache if any) are all optional-null for the arc-shaped case, so existing linear WorkArc behaviour is untouched. See "Framing" and "Heading" sections for the load-bearing consequences.

**Multi-operator maps are supported.** A map opened by one operator can be contributed to or continued by another operator with delegation to the arc. The chain structurally supports this; the ceremony detail (whose signatures matter when — for destination acceptance, waypoint rejection, heading amendment) will need spec work but the answer is "multi-operator, not single-operator-locked."

**A practical trigger for map-shape classification.** Rather than over-engineer the classifier, ship the simplest thing that works: Regent reads the directive and, if it looks map-shaped by any heuristic (exploratory verb, "figure out / explore / understand" language, or the directive is genuinely too big to path directly), Regent emits a `regent:proposal` per the existing Phase-7 EXECUTION-AUTHORITY-MODEL ceremony. Operator confirms or corrects the classification. Regent's confidence and criteria improve over time via precedent — the same precedent machinery already used for autonomous-vs-escalation decisions applies here. No new classifier subsystem needed; just wire directive intake through the existing proposal→confirm path with a "this is map-shaped" claim in the proposal.

### Still open

**How Regent chooses which frontier waypoint to work each cycle.** A heuristic (deepest-fog-clearer, operator-priority-hint, dependency-graph-topological), or Regent's own judgment? Both compose with the primitive but produce different substrate behaviors. Deferred; the machinery to test either is what needs to ship first.

**Trajectory divergence thresholding.** Aegis needs a metric to compare "trajectory bends toward X" against "trajectory diverges from heading." Requires design work per heading category — and the categories aren't known yet. Deferred pending empirical maps to observe: several settled maps in-tree would give Aegis actual trajectories to threshold against.

**Retirement / archival.** A settled map has value as evidence, but at what point does it stop mattering as active context? Never (all maps forever queryable)? By heading area (superseded maps in heading X archived when a new map opens)? Operator-declared? Deferred until enough maps exist to feel the operational shape of the question.

## Not-in-scope for this sketch

- Specific receipt-family names beyond the sketch above (they'll want per-family review during full spec).
- Cockpit UI for the operator-visible map view (a spec concern for the cockpit surface, not this primitive).
- Multi-Regent coordination on the same map (two Regent instances working the same map — a genuine question but bigger than this sketch).
- Cross-map dependencies (map A blocks on map B settling — probably worth a follow-up primitive).

## Next step for this sketch

Promotion path: (a) operator review, (b) if approved, KEEL amendment adding trajectory-map to §II WorkArc section, (c) implementation-design phase per the open questions above, (d) landing as a canonical Tier-2 elaboration.
