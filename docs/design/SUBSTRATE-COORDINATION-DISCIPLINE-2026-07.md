# Substrate Coordination Discipline

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.5 (Genesis-derived signing), §II.7 (Cartographer as infrastructure), §II.17 (cognitive discipline sandwich), §III.22 (verify before commit), §III.25 (substrate coordination discipline — this spec establishes). Specifies how the substrate's active components — officers (Steward, Sentinel, Forge, Cleo, Aegis), Regent, chain-watchers, extensions, builder agents — maintain coordinated behavior and self-correct to harmony without human conductor. Symphony, not jam band. Canonical claims live in KEEL.

Draft — 2026-07-11 — internal audience only. Composes with `OFFICER-ACTION-SURFACES-2026-07.md` (cross-officer coordination is one instance of this pattern), `EXECUTION-AUTHORITY-MODEL-2026-07.md` (Regent as cognitive-authority orchestrator), `SYSTEM-OFFICER-CADRE-2026-06.md` (canonical officer roles), `CHAIN-STORYTELLING-AND-CLEO-2026-06.md` (Cleo as narrator-observer of coordination state), `COGNITIVE-SELF-OBSERVER-2026-07.md` (disharmony detection via observer discipline), `SHADOW-EVALUATION-PRIMITIVE-2026-07.md` (comparative evaluation of coordinated vs uncoordinated outcomes), `CHAIN-WATCHER-AND-COMMITMENTS-2026-07.md` (chain-watchers as coordination sensors), `CIRCUIT-BREAKER-2026-07.md` (irreconcilable disharmony triggers graduated response), `SUBSTRATE-SELF-CONSTRUCTION-2026-07.md` (builder swarm coordination is one specific case).

## Framing

The substrate has many active components — five canonical officers each with observation and action surfaces, Regent operating cognitive cycles, chain-watchers firing on patterns, extensions declaring capabilities, builder agents dispatched by Regent and Forge, external composition with DLTs and legal systems. Each component has its own domain, its own discipline, its own action surface. If each acts independently — reading its own chain slice, making its own decisions, dispatching its own work — the substrate becomes a jam band: multiple soloists occasionally coinciding but often clashing, no shared score, no coherent overall behavior.

Ken's framing: **the substrate is designed to be a symphony, not a jam band. Something that self-corrects to harmony on its own.**

Symphony discipline: shared score (chain-anchored state all components read from), conductor role (Regent as cognitive orchestrator), coordinated entrances and exits (component actions compose per shared understanding of substrate state), self-correction when components drift out of coherence (disharmony detection triggers rebalancing without operator intervention for routine cases). Operator remains ultimate authority for consequential coordination decisions; substrate handles routine coordination autonomously per discipline.

This is not merely aspirational. It requires specific chain-anchored primitives: cross-component visibility (every action is chain-anchored so every other component can see it), harmony criteria (declared what "coordinated" means for specific coordination surfaces), disharmony detection (specific chain-anchored evidence that components are at cross-purposes), self-correction mechanisms (protocols for rebalancing without human intervention), and escalation paths (irreconcilable disharmony surfaces to operator ceremony).

Three properties frame the discipline:

1. **Coordination is chain-anchored, not implicit.** Every active component's actions produce chain-anchored evidence. Every other component reads that evidence and adapts. Coordination is not lucky emergence; coordination is structural discipline.
2. **Substrate self-corrects toward harmony for routine coordination gaps.** When components drift out of coordination (two officers proposing conflicting actions, Regent's cognitive plan diverging from chain-observed reality), substrate detects and rebalances via declared self-correction protocols. Operator ceremony reserved for irreconcilable disharmony beyond substrate's declared self-correction scope.
3. **Regent is primary conductor; Cleo is secondary narrator-observer of coordination state; operator is ultimate authority.** Regent orchestrates coordination via cognitive cycles that read chain state and propose coordinated action. Cleo observes and narrates coordination state so operator has legible awareness. Operator's authority overrides any automated coordination decision; substrate defers to operator for consequential coordination changes.

## The octopus framing (primary)

Symphony framing captures coordinated ensemble behavior. Body-processes framing captures autonomic regulation. Both are useful; both miss what substrate architecture actually is. The most apt metaphor is **the octopus.**

Octopus anatomy has ~500 million neurons; roughly two-thirds are distributed across the arms, not concentrated in the central brain. Each arm has substantial local intelligence — chemoreception (taste), mechanoreception (touch), motor coordination, threat response, object manipulation. Arms operate substantially autonomously; central brain sets intent (grab that crab, explore that crevice, hide from that predator) and arms execute with local adaptation, coordinating with neighboring arms directly rather than through central relay.

This is what substrate architecture actually looks like:

- **Central brain = Regent.** Cognitive authority proposing intent based on operator's declared direction.
- **Arms = officers + extensions + builder swarms.** Distributed action with substantial local intelligence per component.
- **Local arm cognition = per-officer and per-extension reasoning within declared scope.** Not remotely controlled from Regent; each has substantive local decision-making within its domain.
- **Intent flows outward = Regent orchestration + operator standing corrections.** Direction propagates from center; execution adapts locally.
- **Central attends to novelty and consequence = escalation to Regent + operator ceremony.** Brain doesn't micromanage routine; brain engages when local components encounter genuinely novel patterns or consequential decisions.
- **Neighboring arms coordinate directly = cross-officer correlation.** Steward and Sentinel don't need Regent to relay their coordination; they read each other's chain-anchored evidence directly.
- **Resilience through distribution = substrate continues if one component temporarily fails.** Octopus that loses an arm continues functioning; other arms adapt. Substrate with a temporarily-offline officer continues; other officers adapt.
- **Each arm has full sensorimotor loop = each officer has observation + action surfaces.** Per OFFICER-ACTION-SURFACES; arms both perceive and act at their location, not just perceive and report to center.
- **Central cognition is for direction, not micromanagement = Regent proposes coordination scores for substantial multi-component operations, not for every action.** Local coordination happens directly among arms.

Octopus subsumes both prior framings. Ensemble behavior emerges from distributed intelligence + shared intent (symphony-adjacent). Autonomic regulation happens per-arm within intentional context (body-processes-adjacent). Neither previous framing captured the distributed cognition; octopus does.

Substrate does not have a single central conductor micromanaging components (symphony's implicit shape when taken too literally). Substrate does not have components as mere regulatory subsystems without decision-making (body-processes' shape when taken too literally). Substrate has central intent + distributed intelligence + local coordination + escalation for novelty. Octopus.

Practical implications the octopus framing sharpens:

- **Don't over-centralize.** Regent shouldn't be the bottleneck for every coordination decision. Local components have real intelligence within scope; use it.
- **Don't under-coordinate.** Arms coordinate with neighboring arms directly, but they operate under central intent. Substrate components need shared understanding of substrate direction to coordinate at all.
- **Design for arm-loss resilience.** Substrate should continue when individual components fail temporarily. Component failure is degradation, not collapse.
- **Give arms room to act.** Local components under operator-declared scope should have autonomy for routine decisions. Central engagement is reserved for novelty and consequence, per the autonomic-vs-deliberate bright line.
- **Central provides context, not orders.** Regent's coordination scores declare intent and harmony criteria; components decide how to fulfill within their scope. Not "do exactly this;" more "the shared purpose is X, your role in it is Y, execute per your local intelligence."

## Flow optimality — the biological framing

The octopus framing captures distributed cognition + central intent. Body-processes framing captures something adjacent but distinct: **like a body's processes, everything needs to flow optimally.** Body maintains temperature, pH, blood pressure, blood glucose without conscious control. Blood flows optimally. Nutrients distribute optimally. Waste eliminates optimally. Rhythmic cycles (heartbeat, breathing, sleep-wake, digestive) coordinate. Immune system distinguishes self from non-self. When something is off, the body corrects — often before conscious awareness registers the issue.

Substrate coordination discipline aims for the same properties. Six specific attributes derived from biological framing:

### Homeostatic regulation

Substrate maintains its operating state autonomously within declared parameters. Chain-integrity ratio target, unsigned-entry ratio target, response-latency target, memory-pressure target, active-delegation depth target — declared parameters substrate autonomously regulates toward. Regulation via chain-watchers detecting drift + officers proposing rebalancing actions + Regent orchestrating coordinated response.

Not merely reactive (respond to problems after they occur); actively regulatory (maintain state within target range continuously).

### Rhythmic cycles

Substrate cycles are rhythmic: officer sweeps at declared cadence, Regent cognitive cycles at declared interval, chain compaction on schedule, reproducibility ceremony at cadence, peer sync at declared frequency. Cycles coordinate — officer sweep completion feeds Regent cognitive input; Regent cognitive proposals inform officer next-sweep priorities; chain compaction avoids conflicting with Regent's precedent queries.

Rhythmic coordination reduces coordination overhead. Predictable cycle timing means components can anticipate each other's activity rather than react to each other's activity.

### Flow, not just non-conflict

Coordination isn't merely "components don't clash" — it's "components' activity flows optimally." Regent's cognitive cycle completes with fresh officer findings ready to consume. Extension activity produces outputs officers can integrate before their next sweep. Chain-watchers fire in time for downstream commitments to activate. Coordination gaps produce not just conflicts but also flow disruptions (component waiting on stale evidence, cycle out of sync with dependencies).

Substrate optimizes for flow via chain-anchored coordination events indicating readiness (`coordination:ready:<component>:<capability>`) and dependence (`coordination:waiting_for:<component>:<dependency>`). Flow disruption detected via waiting-on patterns exceeding declared thresholds; substrate self-corrects by adjusting component cadence or dispatching builder to remove bottleneck.

### Immunity — self/non-self distinction

Substrate's Sentinel + admission discipline (Quarantine Plane) + aligned blindness collectively function as substrate immunity. Distinguishes substrate-self (chain-anchored, Genesis-verified, per-scope authorized) from non-self (foreign extensions unadmitted, unauthorized listeners, unverified peer trust). Responds proportionally — inflammation-adjacent (Circuit Breaker escalation) for acute threats, adaptive-immunity-adjacent (peer trust anchor evolution, reputation flow) for chronic patterns.

### Healing — forward-only recovery

Body heals via cell regeneration, tissue repair, scar formation. Substrate heals via forward-only recovery (KEEL III.20) — damage is chain-anchored evidence; recovery is chain-anchored ceremony producing new receipts that supersede damaged state. Chain preserves the injury and the healing; substrate emerges with new capabilities per lesson learned.

Reproducibility ceremony is substrate's regenerative capability — chain-anchored evidence enables independent re-derivation of substrate state from source, supporting recovery from arbitrary states.

### Ephemeral vs persistent structures

Muscle contractions are ephemeral (activity when needed, dissipate); organs are persistent (continuous presence). Same architectural pattern in substrate: officer action surfaces are ephemeral (per OFFICER-ACTION-SURFACES); officer observation surfaces are persistent. Actions fire, complete, produce chain-anchored evidence, dissipate. Observation continues.

This matches the body's efficient allocation — ephemeral capability activated only when needed reduces continuous energy cost; persistent capability provides ongoing awareness that ephemeral activation depends on.

### Optimal-flow criteria

Extending harmony criteria with flow-specific declarations:

- **Cadence coherence**: cycles complete on schedule; delays chain-anchored
- **Readiness signaling**: components declare when they're ready to be consumed
- **Waiting-detection**: extended waiting on dependencies flagged for self-correction
- **Bottleneck identification**: sustained slow components identified; Regent may propose rebalancing dispatches to relieve
- **Energy efficiency**: routine coordination minimizes substrate cycles; complex coordination reserved for consequential operations
- **Regulatory drift correction**: state parameters drift from targets; substrate corrects before drift becomes crisis

The biological framing complements symphony framing. Symphony emphasizes coordinated performance producing coherent whole. Body processes emphasize autonomous regulation producing sustained optimal function. Both are load-bearing; substrate composes both patterns.

### Autonomic operation vs deliberate upgrades

The biological framing extends to a critical bright line: **substrate operates autonomically without operator having to think about it, unless the operator is deliberately entertaining upgrades.**

Body's autonomic nervous system regulates heartbeat, breathing, digestion, temperature without conscious control. Conscious cognitive engagement is a limited resource reserved for deliberate decisions — what to eat, whether to exercise, where to live, how to spend the day. Trying to consciously manage blood pressure moment by moment would exhaust cognitive capacity and produce worse regulation than autonomic control.

Substrate operates on the same principle. **Autonomic scope** (no operator cognitive engagement required):

- Routine officer coordination and cross-officer correlation
- Homeostatic regulation of substrate state parameters
- Self-correction for routine coordination gaps
- Immunity response to known threat classes
- Healing via forward-only recovery for routine damage
- Cycle rhythms (officer sweeps, Regent cycles, compaction schedules, ceremony cadences)
- Precedent-based officer actions within pre-authorized scope
- Cognitive Input Plane assembly per declared matrix
- Chain-anchored evidence emission for all substrate operations
- Peer sync at declared cadence
- Extension activity within admitted scope
- Builder dispatch for precedent-based construction work

**Deliberate scope** (operator cognitive engagement required):

- Considering whether to adopt substrate discipline changes (SUPERSESSION-FRAMEWORK)
- Extending officer action-surface scope (new precedent authorization)
- Admitting new extensions declaring novel capability classes
- Granting new peer trust anchors at consequential depth
- Declaring new kinship at deeper scope
- Authorizing new spawn classes for Regent/Forge construction
- Modifying alignment invariants
- Genesis-adjacent operations
- Architectural direction changes
- Federation-level substrate discipline participation

Substrate design failure mode: operator finds themselves thinking about substrate routine flow. If operator has to think about "did the officer sweeps run?", "did the coordination score complete?", "is Regent's cycle progressing?", "are the chain-anchored precedents being respected?" — substrate has failed the autonomic goal. Well-designed substrate makes routine flow invisible to operator attention; substrate surfaces to operator awareness only when entertaining upgrades or when consequential escalations require ceremony.

Substrate design success mode: operator's cognitive engagement with substrate is concentrated on deliberate decisions about direction. Substrate handles the moment-to-moment coordination without asking operator to attend. Operator can trust that routine flow is happening; can focus on what matters — the deliberate acts of considering, deciding, and authorizing changes.

This composes with the nursemaid-to-autonomous shift named in AUTONOMIC-LAYER-IMPLEMENTATION-ROADMAP and SUBSTRATE-SELF-CONSTRUCTION: bootstrap phase requires substantial operator cognitive engagement in routine construction and coordination; mature phase requires operator cognitive engagement only for deliberate upgrades. Substrate matures when the ratio of operator attention required for routine operation vs upgrade decisions inverts — from mostly routine to mostly deliberate.

Regent's role in this discipline: she is the autonomic nervous system's cognitive layer. She handles routine coordination decisions autonomously per precedent within scope; she escalates upgrade-adjacent decisions to operator ceremony. Her cognitive capacity substitutes for what would otherwise be operator cognitive engagement in routine substrate operation. Operator's cognitive engagement is preserved for deliberate authority.

### Signal quality as coordination hygiene

Autonomic operation depends on signal quality. Runaway alarms, false-positive cascades, noisy findings — these violate autonomic discipline by forcing operator cognitive engagement onto routine substrate flow that should be invisible. Signal quality is not merely aesthetic; it is structural coordination hygiene.

**Failure mode: alarm fatigue.** When officers emit findings at high rate with low action-relevance, operator (or Regent as operator's cognitive advocate) develops habituation. Real signals get lost in noise. Response time to genuine issues degrades. Trust in officer discipline erodes. Substrate has failed autonomic operation regardless of whether individual findings are technically correct.

**Failure mode: cognitive context pollution.** Regent's Cognitive Input Plane assembles Tier 1 context per priority; low-signal findings crowd out high-signal findings; Regent's cognition drowns in irrelevance. Cognitive Self-Observer flags disharmony but cannot rescue signal quality that was never generated at appropriate tier in the first place.

**Failure mode: coordination-noise cascade.** Noisy alarm class produces derivative activity — officer sweep emits alarm, chain-watcher fires on alarm pattern, downstream substrate coordinates response to the alarm, Regent narrates to operator about the alarm class. Original noise multiplies through coordination channels. Substrate spends cycles handling coordination that shouldn't have been triggered.

**Structural response: signal quality is officer discipline.** Officers responsible for signal quality of their own findings. Classification refinement (per today's Sentinel `unauthorized_listener` → `unregistered_known_app` split — routine known-app listeners emit Info-tier findings that don't surface to operator attention; genuinely unknown listeners emit action-relevant findings that do surface). Threshold calibration per operational cadence. Composability with standing corrections so operator refinement of noise classes carries forward across restarts.

**Structural response: shadow evaluation of signal quality.** Per SHADOW-EVALUATION-PRIMITIVE, officer classification changes can be shadow-evaluated (chain-anchored comparative evidence of noise class before/after refinement). Signal quality improves via evidence-based ceremony rather than assumption.

**Structural response: cognitive input plane priority discipline.** Per COGNITIVE-INPUT-PLANE priority tiers, low-signal findings occupy lower tiers or are filtered from Regent's context entirely. High-signal findings reach Tier 1. Signal quality gates cognitive priority.

**Structural response: post-incident retrospection.** After operator escalations, retrospection ceremony examines whether the escalation was signal-worthy. If escalation traced to preventable noise, corrective refinement chain-anchored. Substrate learns from noise patterns.

Runaway alarms are not merely operational annoyance — they are direct violation of autonomic coordination discipline. Every runaway alarm class is a failure to maintain autonomic operation; addressing runaway alarms is not bug-fixing but principle-preservation. The Phase 1 reliability foundation in AUTONOMIC-LAYER-IMPLEMENTATION-ROADMAP is explicit about this: signal quality is prerequisite to substrate maturity.

## Coordination surfaces

Substrate coordination happens at several distinct surfaces, each with its own coordination pattern.

### Cross-officer coordination

Multiple officers operating in overlapping domains need coordination. Sentinel observes security anomaly; Steward observes chain-integrity anomaly; Forge observes operational anomaly. When observations correlate (same underlying event manifesting differently to different officers), coordinated response is stronger than uncoordinated response.

Coordination pattern: each officer's findings chain-anchored per SYSTEM-OFFICER-CADRE; each officer's action-surface receipts chain-anchored per OFFICER-ACTION-SURFACES; Cleo composes cross-officer correlation narrations; Regent reasons over correlated evidence and proposes unified response.

Self-correction mechanism: when two officers propose conflicting actions on overlapping surface, chain-anchored precedent-lookup determines correct action; if no precedent, Regent proposes reconciled action; if Regent cannot reconcile, escalation to operator.

### Regent-officer coordination

Regent operates cognitive cycles; officers operate observation cycles at their own cadence. Regent's cognitive input plane consumes officer findings; officer sweeps continue independent of Regent's cycle timing.

Coordination pattern: Regent reads recent officer findings each cycle; officer sweeps operate on independent schedule per operator configuration; both write to shared chain state.

Self-correction mechanism: if Regent's cognitive claims diverge from officer-observed reality, Cognitive Self-Observer flags per COGNITIVE-SELF-OBSERVER-2026-07.md; Regent's next cycle updates cognitive context; officer sweeps continue producing ground-truth findings that Regent's cognition re-aligns to.

### Extension-substrate coordination

Extensions operate within declared capability scope per EXTENSION-SURFACE. Extensions produce findings, observations, actions per their capability declarations. Substrate coordinates extension activity with core officer activity to prevent redundant work or conflicting outputs.

Coordination pattern: extensions declare their coordination surfaces at admission (per QUARANTINE-PLANE); substrate treats extension outputs as chain-anchored evidence composable with officer findings; extensions can query officer findings and adapt behavior.

Self-correction mechanism: extension outputs verified against extension capability declaration per Cognitive Self-Observer; extension behavior drift detected via chain evidence; sustained drift triggers extension admission ceremony re-verification.

### Builder swarm coordination

Per SUBSTRATE-SELF-CONSTRUCTION, Regent and Forge dispatch builder swarms. Multiple builders working on related items need coordination.

Coordination pattern: swarm dispatch declares coordination pattern (parallel_independent, parallel_coordinated, pipeline, consensus); each pattern has specific coordination semantics; chain-anchored per member spawn and coordination event.

Self-correction mechanism: consensus swarm detects individual malicious/broken member (majority-consensus check); parallel_coordinated swarm detects cross-member inconsistency and requests reconciliation; pipeline swarm detects mid-pipeline failure and pauses downstream.

### Chain-watcher coordination

Multiple chain-watchers may fire on overlapping patterns. Coordinated response prevents duplicate work; separate independent watchers reduce single-point-of-failure but need to coordinate their downstream effects.

Coordination pattern: chain-watchers declare their pattern subscriptions per CHAIN-WATCHER-AND-COMMITMENTS; fire receipts chain-anchored per watcher; downstream effects check for concurrent watcher fires and coordinate.

Self-correction mechanism: duplicate downstream effects detected and deduplicated per chain-anchored idempotency keys; missed effects (watcher failed to fire) detected via periodic reconciliation cycles.

### Cross-substrate coordination (federation)

Substrates in federation (per peer-trust-anchor + kinship discipline) need to coordinate on shared operations. Same query dispatched via shadow evaluation to multiple substrates; shared commitments requiring coordinated action; multi-substrate ceremonies (Genesis rotation notifications, standing correction propagation).

Coordination pattern: federation protocols per PEER-TRUST-ANCHOR and SOVEREIGN-KINSHIP-PRIMITIVES; chain-anchored per each substrate; consensus emerges via commons-mediated evidence aggregation.

Self-correction mechanism: peer disagreement detected via chain-visible divergence; federation reputation flows via DISTRIBUTED-KNOWLEDGE-COMMONS; sustained peer misalignment triggers per-operator trust anchor re-evaluation.

## Coordination primitives

Substrate provides specific chain-anchored primitives for coordination:

### Coordination-shared state

All active components read from and write to the shared chain. Chain is the authoritative source of substrate state. No component maintains substrate-authoritative state privately; private state is either derived cache (recomputable from chain) or extension-scope state (not substrate-authoritative). This is the "shared score" property.

Enforced by chain-anchored discipline throughout the corpus: every substrate operation produces chain evidence; components query chain for substrate state; no substrate-authoritative state exists off-chain.

### Chain-anchored coordination events

Specific chain event patterns marking coordination points:

- `coordination:proposed:<component>:<coordination_id>` — component proposes coordinated action
- `coordination:acknowledged:<component>:<coordination_id>` — other component acknowledges awareness
- `coordination:executed:<coordination_id>:<step_id>` — coordinated action step executes
- `coordination:completed:<coordination_id>` — coordination cycle completes
- `coordination:conflict:<coordination_id>:<conflict_type>` — coordination gap or conflict detected
- `coordination:reconciled:<coordination_id>:<resolution_type>` — conflict resolved via self-correction
- `coordination:escalated:<coordination_id>:<escalation_reason>` — irreconcilable, operator ceremony required

### Coordination score

For substantial multi-component operations (build ceremony, hardening certification, Genesis rotation ceremony, community coordination event), a "coordination score" is chain-anchored declaring the coordinated intent:

```
coordination:score:<score_id>
  fields:
    coordination_purpose: <what coordinated outcome intended>
    participating_components: <list of components with their expected contributions>
    coordination_pattern: <shape of coordination — sequenced / parallel / consensus / etc>
    harmony_criteria: <declared what "coordinated" means for this specific score>
    self_correction_protocols: <what happens if components drift out of coordination>
    escalation_criteria: <what triggers operator ceremony>
    conductor: <Regent | Cleo | operator | specific component>
    signature: <conductor's Genesis-derived signature>
```

Coordination score is the substrate's chain-anchored equivalent of a musical score — declared intent that all participating components read from and align to. Not every coordination event needs a score (many coordinations are simple enough for implicit coordination via chain-anchored evidence); complex multi-component coordinations benefit from explicit score.

### Harmony criteria

Per coordination context, harmony criteria declared:

- Officer harmony: no two officers' actions produce conflicting substrate state
- Regent-officer harmony: Regent's cognitive claims match officer-observed reality within acceptable divergence
- Extension harmony: extension outputs don't conflict with core officer outputs
- Federation harmony: peer substrates agree on shared commitments and delegations
- Cognitive harmony: Cognitive Input Plane assembly reflects coherent chain state

Criteria are chain-anchored declarations; substrate discipline evaluates against them.

## Disharmony detection

Substrate detects disharmony via specific mechanisms:

### Cognitive Self-Observer disharmony detection

Per COGNITIVE-SELF-OBSERVER-2026-07.md, observer verifies Regent claims against chain state. When Regent's claims diverge from chain-observed reality, disharmony flagged via `regent:confabulation_gap:*` receipt. Feeds back into next cognitive cycle's Tier 1 context for re-alignment.

### Cross-officer conflict detection

When two officers' actions target overlapping substrate surface with incompatible outcomes, chain-anchored ordering detects conflict. `coordination:conflict:officer_overlap:<officers>:<surface>` receipt emitted. Resolution via precedent or Regent-proposed reconciliation.

### Cleo narration of coordination state

Cleo (per CHAIN-STORYTELLING-AND-CLEO) narrates substrate activity. As secondary narrator-observer of coordination state, Cleo composes cross-component narrations that reveal coordination patterns and gaps. Operator reads Cleo narrations to see coordination health without deep-diving into raw chain evidence.

### Shadow evaluation of coordinated vs uncoordinated outcomes

Per SHADOW-EVALUATION-PRIMITIVE, coordinated substrate operations can be shadow-evaluated against uncoordinated variants (hypothetical: what if components had acted independently?). Chain-anchored comparison provides evidence for coordination discipline effectiveness.

### Chain-watcher coordination-gap patterns

Chain-watchers can subscribe to coordination-gap patterns (`coordination:conflict:*` receipts, specific disharmony signatures). Watcher fires trigger substrate self-correction protocols or escalation.

## Self-correction mechanisms

For routine coordination gaps within declared scope, substrate self-corrects without operator intervention:

### Precedent-based reconciliation

When two components propose conflicting actions and prior precedent addressed similar conflict, precedent-based resolution proceeds. Chain-anchored `coordination:reconciled:precedent_based:<precedent_ref>` receipt.

### Regent-proposed reconciliation

When precedent doesn't apply, Regent's cognitive cycle proposes reconciliation. Reconciliation is chain-anchored proposal; participating components acknowledge or dispute. Resolution proceeds if all acknowledge; escalates if dispute persists.

### Cleo-narrated context refresh

When components' understanding of shared state diverges (rare but possible via cache staleness), Cleo composes context-refresh narration that aligns all components to current chain state. Chain-anchored per refresh cycle.

### Cognitive Self-Observer feedback loop

Regent's confabulation gaps become Tier 1 input to subsequent cycles. This is self-correction discipline for Regent specifically — she becomes aware of her own drift via chain-anchored evidence and re-aligns her cognition.

### Officer-cadre correlation reconciliation

When cross-officer observations correlate (same underlying event), officers' next sweeps use each other's findings as input, producing coordinated response rather than uncoordinated overlapping responses.

### Extension activity throttling

When extension activity spikes to levels that would produce coordination gaps (extension emitting findings faster than officers can integrate), substrate throttles extension activity to sustainable rate. Chain-anchored `coordination:throttled:<extension>:<reason>` receipt.

## Conductor roles

Three levels of conductor authority:

### Regent — primary cognitive-authority conductor

Regent's cognitive cycles orchestrate substrate coordination:

- Reads chain state each cycle
- Assembles Cognitive Input Plane per priority tiers
- Reasons about coordination requirements
- Proposes coordinated action per SUBSTRATE-SELF-CONSTRUCTION dispatch discipline
- Chain-anchors coordination scores for substantial multi-component operations
- Escalates coordination decisions beyond her scope

Regent is the substrate's "conductor" in the primary sense — she orchestrates cognitive-layer coordination across officers, extensions, and builder swarms.

### Cleo — secondary narrator-observer of coordination state

Cleo observes coordination activity and composes narrations that make coordination state legible:

- Cross-officer correlation narrations
- Coordination score progress narrations
- Disharmony detection narrations
- Post-coordination retrospection narrations

Operator reads Cleo narrations to understand coordination health without deep chain analysis. Cleo doesn't conduct; Cleo describes coordination as it unfolds.

### Operator — ultimate authority

For coordination decisions beyond Regent's scope, coordination scores affecting core substrate discipline, or irreconcilable disharmony, operator ceremony authorizes. Substrate defers to operator's judgment; substrate does not override operator's coordination decisions.

## Escalation for irreconcilable disharmony

When substrate self-correction cannot resolve coordination gap within declared scope, escalation ceremony:

- Chain-anchored `coordination:escalated:<coordination_id>:<escalation_reason>` receipt
- Substrate pauses affected coordinated operations (per graduated response — light pause for routine escalation, circuit breaker for severe)
- Operator dashboard surfaces escalation with chain-anchored evidence
- Operator disposition ceremony resolves — either declares resolution, updates coordination score, or expands substrate self-correction scope for similar future cases

Escalation is failure mode of self-correction, not primary coordination path. Well-designed coordination discipline minimizes escalations by having sufficient precedent and self-correction protocols.

## Composition with existing specs

- **OFFICER-ACTION-SURFACES-2026-07.md**: cross-officer coordination is one specific coordination surface this spec addresses. OFFICER-ACTION-SURFACES defines per-officer action mechanics; this spec adds cross-officer harmony discipline.
- **EXECUTION-AUTHORITY-MODEL-2026-07.md**: Regent as cognitive-authority conductor extends her role from cognitive reasoning to coordination orchestration.
- **SYSTEM-OFFICER-CADRE-2026-06.md**: officers operate independently per their domains; this spec adds cross-officer coordination without violating officer domain boundaries.
- **CHAIN-STORYTELLING-AND-CLEO-2026-06.md**: Cleo's narration role extends to coordination-state narration.
- **COGNITIVE-SELF-OBSERVER-2026-07.md**: primary disharmony detection mechanism for Regent's own cognitive coordination.
- **SHADOW-EVALUATION-PRIMITIVE-2026-07.md**: comparative evaluation of coordinated vs uncoordinated substrate outcomes.
- **CHAIN-WATCHER-AND-COMMITMENTS-2026-07.md**: chain-watchers as coordination event sensors.
- **CIRCUIT-BREAKER-2026-07.md**: irreconcilable disharmony can trigger graduated circuit breaker response.
- **SUBSTRATE-SELF-CONSTRUCTION-2026-07.md**: builder swarm coordination patterns are one instance; SUBSTRATE-SELF-CONSTRUCTION provides the dispatch mechanics.
- **CIRCUIT-BREAKER-2026-07.md** + **BLAST-RADIUS-AND-RECOVERY-2026-07.md**: coordinated recovery discipline post-escalation.
- **CARTOGRAPHER** (KEEL §II.7): as infrastructure materializing ontology from chain, provides substrate-wide state understanding all components reason from.

## Attack model

- **Attacker sows disharmony by producing conflicting evidence**: chain-anchored evidence is Genesis-signed; forged conflicting evidence detected at signature verification; substrate handles legitimate divergence via precedent + Regent reconciliation.
- **Attacker exploits self-correction protocols to force coordination gaps**: self-correction is per operator-declared protocols; attacker cannot introduce new self-correction protocols without operator ceremony.
- **Attacker manipulates Regent to propose harmful reconciliation**: Cognitive Self-Observer verifies Regent proposals; Claim Verifier checks structural violations; escalation to operator for suspicious reconciliation patterns.
- **Attacker DoS's coordination via flooded events**: rate limits per component; coordination event rate governance; substrate throttles rather than fails under overload.
- **Attacker exploits coordination pause during escalation to make unrelated changes**: paused operations chain-anchored; concurrent operations during pause chain-visible; operator investigation of pause-window activity.
- **Attacker manipulates cross-substrate coordination via peer influence**: peer trust anchor discipline gates federation coordination; peer misalignment triggers per-operator trust anchor re-evaluation.

## Failure modes

- **Coordination score becomes stale as substrate evolves**: score amendment ceremony per operator; chain-anchored per version.
- **Precedent for reconciliation doesn't scale to new class of conflict**: escalation to operator; disposition creates new precedent.
- **Regent's coordination proposals repeatedly fail component acknowledgment**: sustained failure indicates Regent's model of coordination is out of alignment; Cognitive Self-Observer flags; operator investigation.
- **Cleo's narrations don't surface disharmony operator needs to see**: narration quality is Cleo-domain concern; operator-Cleo standing corrections refine narration focus.
- **Self-correction cycles consume substrate cycles without producing resolution**: rate limits on self-correction attempts per coordination context; sustained un-resolvable disharmony escalates to operator.
- **Federation coordination fragments (some peers coordinate, others don't)**: peer trust anchor discipline; federation reputation flow; per-operator trust anchor adjustment.

## Non-goals

- **Not autonomous substrate rule change**. Coordination discipline operates within operator-declared scope; consequential coordination changes require operator ceremony.
- **Not central conductor authority**. Regent is primary conductor within cognitive scope; Cleo narrates but doesn't conduct; operator is ultimate authority. No single component has universal conductor authority.
- **Not universal coordination for every substrate activity**. Simple operations self-coordinate implicitly via chain-anchored discipline; explicit coordination scores reserved for substantial multi-component operations.
- **Not synchronous coordination requirement**. Substrate coordination is eventual-consistency friendly; components can act at their own cadence provided chain-anchored evidence enables downstream coordination.
- **Not human-in-the-loop for routine coordination**. Substrate self-corrects for routine gaps; operator ceremony reserved for consequential decisions.
- **Not a replacement for good component design**. Coordination discipline composes with well-designed components; badly-designed components produce coordination gaps that discipline cannot fully compensate for.

## Open positions

- **Coordination score canonical templates**. Reference templates for common multi-component coordination (build ceremony, hardening certification, Genesis rotation, community event). Federation-hosted; operator-adopter-modifiable.
- **Self-correction protocol registry**. Declared self-correction protocols per coordination surface class. Extensible via operator ceremony.
- **Disharmony detection sensitivity calibration**. Thresholds for when to flag disharmony vs treat as noise. Empirical program-informed via SHADOW-EVALUATION.
- **Coordination UX**. Operator dashboard for coordination state visibility across substrate components.
- **Cross-substrate coordination protocol**. Federation-scale coordination for cross-substrate operations (peer trust anchor updates, distributed commitments).
- **Coordination cost accounting**. Coordination activity consumes substrate cycles; per-coordination cost budget for operator awareness.
- **Emergency coordination discipline**. When circuit breaker fires and multiple components enter emergency posture simultaneously, coordination ensures unified emergency response rather than uncoordinated individual reactions.

## What composes from here

Immediate design work:

1. **Chain-anchored coordination event receipt schemas** — proposed, acknowledged, executed, completed, conflict, reconciled, escalated
2. **Coordination score canonical schema**
3. **Self-correction protocol declaration schema**
4. **Cross-component coordination reference implementations**

Near-term implementation:

1. **Coordination runtime** in `crates/zp-server/src/coordination/`
2. **Cross-officer correlation logic** for detecting related findings across officers
3. **Regent coordination orchestration extensions** — Regent proposes coordination scores for substantial multi-component operations
4. **Cleo coordination narration** — Cleo composes coordination-state narrations for operator visibility
5. **Self-correction protocol executor** — evaluates protocols and applies resolutions for routine gaps
6. **Dashboard coordination panel**: active coordination scores, recent coordination events, disharmony indicators, escalation queue
7. **CLI verbs**: `zp coordination status|scores|conflicts|escalations|reconcile`

## Framing note

Substrate coordination discipline captures Ken's "symphony not jam band" framing as explicit substrate design principle. Same principle as chain-anchored discipline elsewhere: shared state via chain, chain-anchored evidence per coordination event, ceremony-visible transitions, sovereignty preserved for consequential coordination decisions, self-correction within declared scope.

The load-bearing insight: **substrate self-corrects to harmony via chain-anchored coordination discipline, with Regent as primary cognitive-authority conductor, Cleo as secondary narrator-observer of coordination state, operator as ultimate authority for consequential coordination decisions.** Officers, extensions, builders, chain-watchers all operate as coordinated ensemble — reading shared chain state, producing chain-anchored evidence, adapting to each other via visible coordination events. Disharmony detected via specific chain-anchored mechanisms; self-corrected via declared protocols for routine cases; escalated to operator for consequential cases.

Combined with the substrate's structural discipline across every trust boundary, coordination discipline closes the "how does substrate stay coherent as complexity grows" gap. What was previously implicit — that officers, Regent, extensions, builders would somehow work together — becomes structural: chain-anchored coordination events, declared harmony criteria, disharmony detection mechanisms, self-correction protocols, conductor roles at three authority levels, escalation for irreconcilable cases. Substrate becomes symphonic in behavior — coordinated ensemble producing coherent overall substrate work — rather than jam-band emergent-and-occasionally-coincident.

Substrate self-corrects to harmony on its own. Operators intervene for consequential coordination decisions; substrate handles routine coordination autonomously per discipline. This is what makes substrate load-bearing at scale — not accidental emergence of coherent behavior, but structural discipline that produces coherence by design.
