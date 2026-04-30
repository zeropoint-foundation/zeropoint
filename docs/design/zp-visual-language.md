# ZeroPoint Visual Language

ZeroPoint's visual substrate is four lenses. Each lens answers exactly one question. The question you need to answer determines which lens you open. The lenses compose — you can drill from any one into any other without leaving context behind.

## Abacus

*When? How many?*

Domain: event streams, audit beads, live telemetry, preflight checks, ASCII CLI summaries.

- Bead = receipt. One signed event = one bead. Fixed size, circle or capsule.
- Wire = conversation / tool / provider / session. Horizontal rail. Time flows left → right.
- Bead-zero is always leftmost and always visible. If it's off-screen, the wire is wrong.
- Beads accrete rightward. A placed bead never moves — the audit chain guarantees this.
- Color = claim_type + outcome. Small fixed palette: accent1 lifecycle, accent2 content, warn tool calls, muted telemetry, danger refusals/errors. Palette does not grow.
- Vertical stacking = domain separation. One wire per tool / session / provider.
- Epoch bars — thick horizontal lines at daily / weekly / per-genesis boundaries.
- Count before narrate. "14 beads since genesis, 2 refusals" before any descriptive summary.
- No animation of existing beads. New beads slide in from the right. Re-sort is a lie.

## Weave

*Who can, authorized by whom?*

Domain: delegation trees, capability maps, sovereignty hierarchy, tool × provider dependency.

- Nodes = identities (keys, agents, tools, providers). Edges = organizational relationships (delegates-to, holds-capability, consumes-credential).
- Hierarchy flows top-down from Genesis. Root always visible.
- Typed nodes with distinct shapes — circles for identity keys, squares for capabilities, rounded rectangles for agents and runs.
- One hop at a time. Default view shows direct neighbors; click to expand.
- Weave is stable between refreshes. If structure changes, the change itself is a bead on the abacus.

## CodeFlow

*How was this derived?*

Domain: receipt chains, memory trees, claim-to-evidence provenance, chain-integrity diagnostics.

- Each node = a computed output (receipt, memory, claim). Each edge = a derivation relation (signed-by, chains-from, attests, supersedes, contradicted-by).
- Layout is layered DAG — inputs left or above, derived outputs right or below.
- Edges are labeled. The derivation relation is never implicit.
- Integrity is a first-class color — broken derivation edges render danger-red. A CodeFlow view is also a live verifier.
- Use CodeFlow when structure is the primary signal; use abacus when time is primary.

## Walk

*What happened, in what order, along what path?*

Walk is the interaction layer. It composes with any spatial lens.

### Feasible now

- Replay: scrub timestamps forward/backward; nodes light pending → active → settled.
- Live flow highlight: new events pulse along their causation path across all three lenses.

### Needs instrumentation (roadmap)

- Decision-tree walk. Requires capturing alternatives, not just the chosen path: tools considered but not invoked, policy branches not taken, reasoning paths not emitted.

### Interaction grammar

- Transport bar idiom: play, pause, scrub, speed, jump-to-event. Users already know this from video.
- Time units: event-step, wall-clock, causal depth. User picks.
- Node activation is three-state: pending (dim), active (glowing), settled (full-color static).
- Edges light by color pulse (dim → bright → settled) as traversal completes. No particle animation in v1 — stays readable at density.

## The Unique ZP Angle

Every replay tool in software reruns something and hopes the reconstruction is faithful. ZP does not rerun anything. The receipt chain *is* the record. The chain was not assembled after the fact from logs — it was written as the events occurred, each bead cryptographically bound to the one before it. Walking the chain is not re-simulation; the chain carries its own proof of ordering and authenticity. Reconstruction error is not possible because there is nothing to reconstruct.

*ZP does not let you re-run — it lets you re-see.*

## Drill-Through

The four lenses compose losslessly. Click a bead on the abacus and it opens the CodeFlow view of that receipt — how it was derived, what it attests, what it chains from. Click a node in CodeFlow and it opens the Weave context — who authorized this identity, what capabilities it holds, what delegation path reaches it. Click a Weave certificate and it opens the abacus of that principal's activity across every wire it touches. The Walk transport layer operates over any of the three spatial lenses without reconfiguration. One substrate, four lenses, drill-through in every direction.

## Library Notes

- Use `dagre` for layered DAG layouts. Same engine under most CodeFlow-style visualizers. ~10KB gzipped.
- Render with vanilla SVG + D3 transitions. No framework dependency.
- Target footprint ~30KB gzipped for the whole visual substrate.
- Forking Claude.ai's CodeFlow is the wrong move. Copy the grammar; the code is replaceable.

## Closing

*A bead is a receipt, crystallized.*
