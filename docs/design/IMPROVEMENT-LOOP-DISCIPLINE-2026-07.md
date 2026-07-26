# Improvement Loop Discipline

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §III (adds Layer B canonical claims about substrate self-improvement as a governed process) and Part V (Composition Contract for improvement-arc primitives). Meta-spec that governs how the substrate improves itself — the same trust discipline the substrate applies to actions, admissions, observations, and cognition, now applied to the substrate's own improvement process. Canonical claims live in KEEL.

Draft — 2026-07-15 — internal audience only. Composes with `SUBSTRATE-SELF-CONSTRUCTION-2026-07.md` (this is the discipline governing what Regent+swarms build), `SHADOW-EVALUATION-PRIMITIVE-2026-07.md` (specific case: candidate fix vs control fix evaluated against evidence), `OBSERVER-COHERENCE-DISCIPLINE-2026-07.md` (cross-proposer verification), `CHAIN-READ-CANARY-DISCIPLINE-2026-07.md` (learning-freshness verification), `CIRCUIT-BREAKER-2026-07.md` (sustained regression triggers escalation), `COGNITIVE-INPUT-PLANE-2026-07.md` (heuristics as Tier 1 context), `STANDING-CORRECTION-RECEIPT-SCHEMA-2026-07.md` (heuristics as a correction class).

## Framing

Every substrate that improves over time develops the same latent question: *what governs the improvement process itself?* Individual improvements can be reviewed at commit time. Individual designs can be gated by ceremony. But the meta-process — how proposals are generated, how alternatives are compared, how evidence accumulates, how learnings persist, how regressions are caught, how repeated patterns become discipline — usually lives implicitly in the culture and habits of the people improving the system. Working heuristics accumulate in text files, wiki pages, or the tacit knowledge of long-tenured contributors. When contributors change, or when the system grows beyond one person's working memory, the improvement loop's discipline erodes silently.

For a substrate whose foundational claim is that trust must be *engineered structurally rather than hoped for* — for a substrate whose corpus explicitly says "signing is gravity" and "the chain is truth" — the improvement loop's implicit-culture status is a load-bearing gap. The same disciplines the substrate applies to every other trust-critical process (chain-anchored, ceremony-gated, evidence-verifiable, escalation-aware) should apply to the improvement loop itself.

Discovered structurally 2026-07-15 during a substantive session that landed multiple structural specs and empirical verifications while surfacing a class of bug (stuck rusqlite Connection) whose fix had already been attempted three days earlier and had missed the structural class. The session's diagnostic arc — surface fix → deeper class discovered → observer coherence + canary specs drafted — was itself an instance of the pattern we now want to make first-class. The corpus already names the underlying heuristics (`friction is the finding`, `verify before commit`, `act on precedent`, `balanced loop`, `simplicity first`). But they lived only as prose in `CLAUDE.md` — a text file, valuable as scaffolding, insufficient as substrate discipline. When the scaffolding fades (per SUBSTRATE-SELF-CONSTRUCTION's declared trajectory of Ken+Claude → Regent+swarms), the discipline needs to persist as chain-anchored structure.

The improvement loop discipline is the substrate's structural response. Every improvement arc — from finding to landed fix to verified-durable outcome — becomes a chain-anchored entity. Divergence between proposers is a coherence signal. Learnings become chain-anchored heuristic receipts with canary verification. Candidate fixes compete via shadow-evaluation rather than inline judgment. Regressions escalate through the circuit breaker ladder. The whole process is queryable, verifiable, and improvable-by-the-same-discipline (recursion terminates because the meta-loop applies to itself with the same primitives).

Three properties frame the discipline:

1. **Improvement is a chain-anchored process, not a cultural habit.** Every arc from finding-detection through fix-landing through durability-verification produces chain receipts. Later analysis can query the improvement corpus the same way it queries any other chain-anchored corpus.
2. **Ken+Claude is scaffolding; Regent+swarms is substrate.** The discipline is spec'd for the substrate's own improvement process — Regent proposes, evidence gathers, operator ceremony authorizes, chain anchors, canary verifies. Bootstrap-phase operator+external-agent collaboration produces the initial corpus of heuristics and specs but is not itself the discipline being formalized. As Regent matures, the discipline persists; the bootstrap fades. Same trajectory as everything else in the substrate self-construction arc.
3. **The meta-loop applies to itself.** Improvements to the improvement loop discipline are themselves subject to the improvement loop discipline. Recursion terminates because the substrate treats the discipline as one more governed process — not as a special exempt category. If a proposed change to the discipline is a surface patch that misses a structural class, that miss is detectable by the same primitives (shadow-eval, coherence, canary, regression tracking).

## The improvement arc

An improvement arc is a chain-anchored entity with a declared lifecycle. Each stage emits a receipt; the arc as a whole is queryable by walking the receipts sharing an arc-id. An arc either advances through Stages 1–5 or terminates at Stage 1t — every proposal reaches a recorded disposition, and none evaporates.

### Stage 1 — Proposed

```
{
  "event": "improvement:proposed:<arc_id>",
  "arc_id": "<content_hash_of_finding>",
  "proposed_at": "<timestamp>",
  "proposer": "<regent | operator | officer | swarm_agent>",
  "finding": "<the observation that motivated this>",
  "finding_class": "<bug | drift | new_capability | corpus_gap | discipline_gap>",
  "surface_area": "<which substrate component(s) affected>",
  "proposed_change_shape": "<brief description; not the full change>",
  "precedent_query_result": "<hash of prior similar arcs found on chain>",
  "signature": "<proposer's signature>"
}
```

**Semantics:** something-worth-fixing has been observed. The proposal captures *what was observed* and *what shape of change is contemplated* but does not commit to the change. Multiple `improvement:proposed` receipts can share overlapping surface area — that's expected and detected by coherence discipline.

### Stage 2 — Evaluated

```
{
  "event": "improvement:evaluated:<arc_id>",
  "arc_id": "<...>",
  "evaluated_at": "<timestamp>",
  "candidate_approaches": [<candidate_1>, <candidate_2>, ...],
  "shadow_eval_receipts": [<hashes of shadow-eval receipts per candidate>],
  "evidence_summary": "<what the evaluation showed>",
  "recommended_approach": "<which candidate the evidence favors>",
  "confidence": "<low | medium | high>",
  "cost_estimate": "<...>"
}
```

**Semantics:** candidates evaluated per SHADOW-EVALUATION-PRIMITIVE. Evidence chain-anchored via shadow-eval receipts referenced by hash. Recommended approach emerges from evidence, not from proposer preference. When only one candidate is viable (structural, no meaningful alternative), evaluation still fires but with a degenerate shadow-eval (marker that no alternative was applicable).

### Stage 3 — Landed

```
{
  "event": "improvement:landed:<arc_id>",
  "arc_id": "<...>",
  "landed_at": "<timestamp>",
  "authorization": "<operator_signature | precedent_authorization_receipt>",
  "chosen_approach": "<...>",
  "implementation_references": [<commit_hashes | spec_paths | verb_registrations>],
  "verification_criteria": "<what needs to be true for this to be verified-durable>",
  "canary_schedule": "<how often to verify the improvement is still holding>"
}
```

**Semantics:** operator ceremony (or precedent-based Regent authorization per §"Regent's role in Phase 5" of AUTONOMIC-LAYER-IMPLEMENTATION-ROADMAP) authorizes the change. Implementation references chain-anchor the actual code/spec/config that was changed. Verification criteria declare what "this improvement is real and durable" means in checkable terms. Canary schedule declares how often to verify per CHAIN-READ-CANARY-DISCIPLINE's discipline extended to improvement freshness.

### Stage 4 — Verified

```
{
  "event": "improvement:verified:<arc_id>",
  "arc_id": "<...>",
  "verified_at": "<timestamp>",
  "verifier": "<canary_runtime | operator | regent>",
  "verification_result": "<criteria_met | criteria_partial | criteria_failed>",
  "evidence": "<...>",
  "next_canary_at": "<timestamp>"
}
```

**Semantics:** post-landing, verification confirms the improvement produced the intended change. Fires at declared cadence per canary schedule from stage 3. Every verified event is a chain-anchored beacon that says "this improvement is still active." Absence of verified events (missed canary) is itself a signal — see stage 5.

### Stage 5 — Regressed (fires only on regression)

```
{
  "event": "improvement:regressed:<arc_id>",
  "arc_id": "<...>",
  "regressed_at": "<timestamp>",
  "detector": "<canary | coherence_discipline | operator | regent>",
  "evidence": "<what changed>",
  "hypothesized_cause": "<...>",
  "escalation": "<informational | warning | critical>",
  "remediation_proposed": "<...>"
}
```

**Semantics:** improvement that once held now fails its verification criteria. Triggers investigation. Not necessarily a repeat of the original bug — could be adjacent regression, could be verification-criterion drift, could be a genuine new fault. Chain-anchored, so `improvement:regressed:<arc_id>` events are queryable across time to detect patterns (same arc regressing repeatedly = structural class hint).

### Stage 1t — Tied off (terminal; fires instead of Stage 2)

```
{
  "event": "improvement:tied_off:<arc_id>",
  "arc_id": "<...>",
  "tied_off_at": "<timestamp>",
  "disposition": "<declined | deferred | open | limited>",
  "rationale": "<why this path was set aside>",
  "alternatives_considered": ["<arc_ids or inline shapes weighed against it>"],
  "reopen_condition": "<the declared statement that, if it becomes true, reopens this arc>",
  "reopen_watch": "<canary schedule | chain_event_pattern | none>",
  "origin_ref": "<doc and section where the branch arose>",
  "signature": "<...>"
}
```

**Semantics:** a path was considered and set aside. The arc terminates at Stage 1 rather than advancing to evaluation. This is not a failure state and not a regression — it is the deliberate, recorded non-taking of a branch.

**The four dispositions carry different revisit semantics, and conflating them is the defect this stage exists to fix:**

| Disposition | Meaning | `reopen_condition` |
|---|---|---|
| `declined` | Considered, decided against on the merits | Optional. Often none — the decision stands until someone argues otherwise |
| `deferred` | Will do, not now | **Required.** What must be true to pick it up |
| `open` | Undecided, actively unresolved | **Required.** What evidence would decide it |
| `limited` | Cannot be done in principle | None. Records a declared boundary of the design space |

**`reopen_condition` is the load-bearing field.** Without it a tie-off is a prose bullet in a document nobody re-reads — the corpus's current state. With it, the branch becomes a watched dependency. `reopen_watch` is what makes the watching systematic: a canary schedule that periodically evaluates the condition, or a chain event pattern that fires when it becomes true. A `deferred` or `open` tie-off with `reopen_watch: none` is itself a coherence finding — something was deferred with no path back.

#### `reopen_watch` — the two tiers (amended 2026-07-26)

Stage 1t declared `reopen_watch: "<canary schedule | chain_event_pattern | none>"` without saying what a watch may contain. Writing the runtime first would have decided that silently, so it is decided here.

**A reopen condition is either a structured predicate or prose with a review cadence.** The four reopen conditions actually in the tree on 2026-07-26 split roughly evenly between the two, which is why neither form alone was adopted: *"P1 complete"* is mechanically checkable, *"any attempt to run the server off a machine other than its build host"* is detectable at runtime and would have caught the dossier defect the first time ZP started on ARTEMIS, while *"if the generator cannot reach a subsystem at all"* is judgment and always will be.

| `watch` | Form | Who evaluates |
|---|---|---|
| `watched` | structured predicate | the canary, autonomously |
| `reviewed` | prose + declared cadence | surfaced to the operator on schedule |
| `none` | — | legal only for `declined` and `limited` |

**The tier split is the authority boundary, not a convenience.** Evaluating a structured predicate is *applying* criteria; under `ZEP-self-referential-authorship-2026-07.md` §III.27's criteria-versus-inputs test that is not Class 3, so the canary — and eventually the Regent — may do it without operator ceremony. Judging whether prose has become true is *interpreting* criteria, which is Class 3-adjacent and stays with the operator. The mechanical question and the authority question have the same answer, and a condition's tier declares which one it is.

**Predicate forms.** Deliberately four. Each is justified by a reopen condition that exists, not by anticipated need; adding a fifth requires a condition that needs it.

- `receipt_exists(<prefix>)` — a matching receipt appears on chain
- `artifact_exists(<path>)` — a declared artifact appears in the tree
- `metric_threshold(<name>, <op>, <value>)` — a named substrate metric crosses a bound
- `invariant_violated(<pin_or_check>)` — a discipline pin or runtime check fires

**Escalation.** A satisfied watch does not reopen anything. `watched` predicate true emits `improvement:reopen:eligible <arc_id>`; an elapsed `reviewed` cadence emits `improvement:reopen:review_due <arc_id>`. Both make the arc *eligible for re-proposal against its original `arc_id`* — the decision to reopen remains an authored act, and per §Stage 1t a canary firing on a reopen condition "is not a miss and not a regression; it is the arc becoming live again."

**Prose form**, for tie-offs recorded in documents rather than as receipts:

```
*Deferred.* <rationale> Reopen condition: <text>. Reopen watch: <predicate> | review:<cadence>
```

`corpus-lint check_tieoff_reopen_conditions` enforces that a `deferred` or `open` tie-off carries both fields. A terminal disposition needs neither.

**Not yet built.** The canary evaluates chain-read visibility only (`crates/zp-server/src/canary.rs`, Tier 1); it cannot evaluate predicates. This amendment specifies the declaration layer so conditions become *readable* before they become *watchable* — a tie-off cannot be watched before it can be read. *Deferred.* Runtime predicate evaluation is a separate increment. Reopen condition: the canary runtime supports scheduled evaluation of a non-chain-read predicate. Reopen watch: `invariant_violated(canary_supports_predicates)`

**Reopening is an arc event, not a new arc.** `improvement:proposed:<arc_id>` re-emitted against the same `arc_id` after a tie-off resumes the original arc, carrying its history. This preserves the reasoning trail: the second time a branch is proposed, the chain shows it was considered before, why it was set aside, and what changed. That is the precedent query working on the substrate's own design process rather than on its runtime behavior.

**Scope.** This stage is for branches that cost something to rediscover — an alternative someone will otherwise re-propose, or a deferral gated on real evidence. It is deliberately **not** for non-goals. A non-goal is a boundary statement about what a component is, not a path through a decision; recording non-goals as tied-off arcs would turn the mechanism into a compliance ritual filled in mechanically, which is its principal failure mode.

**Why this is the same gap the substrate closes elsewhere.** `COGNITIVE-ACT-ACCOUNTING-2026-07.md` §3.3 exists because the chain proves what the Regent did, not what she weighed. At the corpus level the identical hole is open: the corpus proves what was decided, not what was considered and set aside. Same shape, one level up, and the meta-loop applying to itself is this discipline's declared property.

## Applying the substrate's own primitives to the loop

The improvement loop discipline gains its rigor by composing the substrate's existing primitives.

### Observer coherence applied to proposals

When multiple proposers observe the same substrate state and propose different fixes, that divergence is a coherence signal. Not necessarily a fault — proposals may reflect legitimate design-space diversity — but a signal worth surfacing.

Example (from 2026-07-15 P1.1 diagnostic): Ken observed "chain_silence still firing"; Claude observed "P1.3 fix should have covered this"; Regent observed "chain is active per chain_query." Three views of the same substrate state. The divergence between Claude's "should be fixed" and Regent's "chain is fine" was already the diagnostic signal — Steward's observation was the outlier. Coherence discipline of proposer state would have surfaced this within one improvement cycle instead of surfacing it via manual cross-reference.

Layer B canonical: coherence classes include *improvement-proposer coherence* alongside chain-reader / ontology-querier / observation-plane-consumer / vault-key-lister coherence.

### Chain-read canary applied to landed learnings

Landed heuristics have canary schedules. Every N cycles, verify the heuristic is actually being applied to relevant decisions. If Regent's proposals systematically ignore a landed heuristic, canary miss fires; the heuristic has drifted out of active influence.

Example (from 2026-07-14): the day-shape prohibition was originally a directive to Claude in operator+external-agent scaffolding, later inadvertently copied into Regent's standing corrections. If Regent's future-cycle behavior showed the heuristic wasn't applying appropriately (e.g., Regent stopped mirroring day-shape framing when operator explicitly set the frame), canary would detect the drift and surface it. Operator ceremony revokes the misapplied correction; new arc proposes a correctly-scoped replacement.

Layer B canonical: canary discipline extends to `heuristic:workflow:<domain>` receipts (see §"Chain-anchored heuristics").

**Canary applied to tie-off reopen conditions.** The same mechanism serves Stage 1t. A tied-off arc carrying `reopen_watch: <canary schedule>` is evaluated on that schedule against its `reopen_condition`; when the condition becomes true, the canary emits and the arc is eligible for re-proposal against its original `arc_id`. This is what makes a tie-off a watched dependency rather than a note in a document — the difference between *"held pending measurement evidence"* as prose and as a condition something periodically checks. A canary firing on a reopen condition is not a miss and not a regression; it is the arc becoming live again.

### Shadow evaluation applied to candidate fixes

The choice between surface patch and structural fix is exactly what SHADOW-EVALUATION-PRIMITIVE governs. Rather than inline operator judgment ("we'll do the quick fix and revisit"), candidates run in parallel where possible; evidence accumulates over the evaluation window; operator ceremony picks based on data.

Example (from 2026-07-15 P1.1): the P1.3 archive/live UNION fix was a surface patch that missed the structural class (observer freshness). Had shadow-eval framed candidate approaches — "candidate A: patch this query path" vs "candidate B: introduce observer freshness discipline" — evidence would have shown A missed adjacent cases that B would catch. Choice would still be operator's, but informed by evidence rather than surface judgment.

Layer B canonical: shadow-eval contexts include *candidate-fix vs candidate-fix* alongside the seven contexts already enumerated in SHADOW-EVALUATION-PRIMITIVE.

### Circuit breaker applied to regression patterns

Sustained regressions in a specific surface area trigger circuit breaker escalation. Not every regression escalates — some are legitimately noise from adjacent changes. But when improvement arcs in the same surface area regress repeatedly, that's a structural signal the substrate needs to attend to.

- L1: single regression detected → elevated attention on the surface area, increase canary cadence
- L2: multiple regressions in same surface area within window → downgrade trust in improvements at that surface until stabilization ceremony
- L3: sustained regressions across multiple related surface areas → soft arrest on new improvements at scope; existing arcs must complete before new ones start
- L4: substrate-wide regression pattern → hard trip on improvement discipline itself; operator ceremony required to reset

## Chain-anchored heuristics

Heuristics currently live in `CLAUDE.md` under "Working principles" and "Workflow heuristics." Valuable as scaffolding — they capture the accumulated wisdom of the arc. Insufficient as substrate discipline because they exist only as text a human reads, not as chain state Regent (or Regent's successors) can query.

Promoting them to chain-anchored discipline receipts:

```
{
  "event": "heuristic:workflow:<domain>:<heuristic_id>",
  "heuristic_id": "<content_hash>",
  "issued_at": "<timestamp>",
  "issuer": "<operator | regent_via_precedent>",
  "domain": "<construction | verification | diagnosis | communication | ...>",
  "statement": "<the heuristic itself in one clear sentence>",
  "elaboration": "<longer explanation with example>",
  "triggers": ["<which arc-classes should invoke this heuristic>"],
  "example_arcs": ["<arc_ids where this heuristic was applied>"],
  "canary_schedule": "<how often to verify this heuristic is still active>",
  "supersedes": ["<prior heuristic_ids this replaces>"],
  "expiry": "<optional timestamp or null>"
}
```

The seven canonical heuristics currently in `CLAUDE.md` §"Working principles" — think before coding, simplicity first, surgical changes, goal-driven not step-driven, plus the ~20 workflow heuristics captured over prior sessions — all promotable to `heuristic:workflow:*` receipts on chain. Once promoted, they're queryable by Regent during proposal generation (`what heuristics apply to this class of change?`), verifiable via canary (`am I still applying this?`), and coherence-checkable across proposers (`did all proposers apply the same heuristics?`).

The `CLAUDE.md` text file becomes the human-readable index into the chain-anchored corpus, not the corpus itself. Same relationship as `CANONICAL-CORPUS-INDEX-2026-07.md` has to the Tier 2 specs.

## Layer A / Layer B split

**Layer A (compiled Rust host):**
- Improvement arc runtime — dispatcher for the five stages
- Arc-id generation, receipt signing, chain-anchoring
- Integration with SHADOW-EVALUATION-PRIMITIVE for stage 2 evaluations
- Integration with OBSERVER-COHERENCE-DISCIPLINE for proposer coherence
- Integration with CHAIN-READ-CANARY-DISCIPLINE for stage 4 verification
- Integration with CIRCUIT-BREAKER for regression escalation
- Heuristic query engine — `heuristics_matching(domain, arc_class)` → set of active heuristics
- Tie-off registry and reopen-condition evaluator — `tied_off_matching(surface_area)` → set of prior branches, queried at Stage 1 so a proposal surfaces what was already considered and set aside

**Layer B (WASM modules + canonical data):**
- Arc stage schemas (per §"The improvement arc" above)
- Heuristic receipt schema
- Coherence-class registration for improvement proposers
- Canary schedule defaults per improvement class
- Circuit-breaker threshold config for regression patterns
- Heuristic domain taxonomy
- Tie-off disposition taxonomy and per-disposition `reopen_condition` requirements

Layer A structurally defended; Layer B evolves via canonicalization ceremony. Adding a new heuristic domain — Layer B ceremony. Changing regression escalation thresholds — Layer B ceremony.

## Provenance — improvement-loop signing key

Per KEEL §II.5: single signing key, HKDF-derived from Genesis:

```
improvement_loop_key = HKDF(genesis_root, salt=chain_head_at_derivation, info="improvement:runtime")
```

Signs `improvement:*` receipts. Heuristic receipts signed by their issuer (operator directly for operator-authored, Regent via her scoped delegation for precedent-authored). Attribution to Genesis via one hop.

## Composition with Substrate Form

Discipline available on all Forms with runtime characteristics varying:

### Sovereign Form

Full discipline. All arc stages available. All heuristic domains active. Shadow-eval, coherence, canary, and circuit-breaker integrations fully wired.

### Appliance Form

Same as Sovereign on the appliance. Improvement arcs relating to daily-driver surface areas cannot be verified against daily-driver state directly (per Substrate Form reach limits) — arcs must be scoped to appliance-side changes or defer verification.

### Companion Form

Improvement loop runs with vendor-limited observation reach. Arcs affecting observation-plane surface areas (Class 3) have reduced verification depth. Form Disclosure names the reduction: "On Companion Form, some improvement-verification criteria cannot be fully checked against host state; regression detection at Class-3 surfaces is best-effort."

## Composition with substrate self-construction

`SUBSTRATE-SELF-CONSTRUCTION-2026-07.md` describes what Regent+Forge do (dispatch builder agents, coordinate swarms, verify outputs, chain-anchor construction lifecycle). This spec describes *how they should do it well over time*. Every construction operation Regent dispatches is an improvement arc. Every builder-agent output feeds evaluation. Every landed construction operation gets a canary schedule. Every regression triggers investigation.

The two specs are pair-composed:
- SUBSTRATE-SELF-CONSTRUCTION: capability (Regent+Forge can dispatch builders)
- IMPROVEMENT-LOOP-DISCIPLINE: discipline (dispatches follow the arc, evidence accumulates, learnings persist)

Regent operating with construction authority but without improvement-loop discipline would produce fast local changes without structural learning. Regent operating with improvement-loop discipline but without construction authority would produce well-analyzed proposals with no implementation power. Both together produce a substrate that constructs itself deliberately, learns from its own construction, and improves over time.

## Composition with cognitive input plane

Active heuristics (chain-anchored per §"Chain-anchored heuristics") load into Regent's Tier 1 cognitive context alongside standing corrections. The Cognitive Input Plane treats them as a new class:

- Class 2a: Active standing corrections (per COGNITIVE-INPUT-PLANE §"Class 2 — Active standing corrections")
- Class 2b: **Active heuristics matching this cycle's arc-class** (new class per this spec)

Regent proposing a fix during her cycle sees the applicable heuristics at Tier 1. Cognitive Self-Observer verifies her proposal against those heuristics post-emission. Heuristic violations flag the same way correction violations flag.

## Composition with standing corrections

Heuristics and standing corrections are adjacent but distinct:
- **Standing correction**: operator claim about the world / boundary / prohibition / preference. Persistent, narrow, corrects a specific pattern Regent produces.
- **Heuristic**: procedural discipline about how to work. Persistent, broader, guides how proposals are generated and evaluated.

A standing correction says *don't claim X as current-state.* A heuristic says *before landing a fix, verify it against the structural class the finding belongs to.*

Both promote into Regent's Tier 1 context. Both are chain-anchored, revocable, and canary-verifiable. The receipt schemas share structure but are namespaced separately (`cognitive:correction:standing` vs `heuristic:workflow:*`).

## Attack model

- **Attacker seeds fake improvement arcs to legitimize a bad change**: arc receipts are signed. Operator ceremony or precedent-authorization is required for stage 3 (landing). Attacker cannot land changes without operator signature or an existing precedent chain, and both are inspectable.
- **Attacker fakes verification receipts to hide a regressed improvement**: verification is chain-anchored with evidence. Operator can query arc history and see whether evidence looks legitimate. Coherence discipline cross-checks proposer/verifier claims against ground truth.
- **Attacker floods with proposals to overwhelm the improvement queue**: proposals cost cycles. Rate limits per proposer, budget per operator-declared scope, escalation on flood pattern (canonical DoS defense).
- **Attacker manipulates heuristic receipts to remove disciplines that would catch the attack**: heuristic modification requires operator signature. Chain shows the change. Coherence discipline detects if Regent's behavior diverges from the heuristic (canary-miss fires).
- **Attacker corrupts the improvement-loop runtime itself**: runtime is a Layer A subsystem with its own signing key; disabling requires substrate compromise; heartbeat monitored.

## Non-goals

- **Not a project management tool.** The discipline governs *substrate improvement*, not general task planning. Task tracking, capacity planning, priority queues are operator concerns outside substrate scope.
- **Not automatic improvement.** No proposal auto-lands. Operator ceremony (or precedent authorization for well-established arc classes) is required.
- **Not for external improvements.** Improvements to third-party dependencies, external services, operator's other tools are out of scope. Substrate-internal only.
- **Not for content or narrative work.** Improvement to substrate discipline; not improvement to Regent's tone, dashboard copy, or documentation prose. Those are preference corrections, not improvement arcs.
- **Not a branch-recording obligation for non-goals.** A non-goal is a boundary statement about what a component is, not a path through a decision. Recording non-goals as tied-off arcs would make Stage 1t a compliance ritual, which is its principal failure mode. Tie off branches that cost something to rediscover; leave boundary statements as prose.
- **Not a replacement for CLAUDE.md prose.** The prose captures reasoning trail, examples, and human-readable framing. Chain-anchored heuristics carry the discipline. Both persist; different purposes.

## Open positions

- **Precedent depth for auto-authorization.** After how many chain-anchored operator authorizations of the same arc class can Regent auto-authorize the next instance? Currently deferred to Phase 5 precedent mechanics. Prefer conservative (many prior operator authorizations required) with operator override.
- **Cross-substrate improvement sharing.** Should improvement arcs propagate across a fleet (Appliance + Sovereign for same operator)? Deferred until Peer Verification Contract implementation matures. Same operator sharing the same substrate discipline seems natural.
- **Community-shared heuristics.** Could operators publish (opt-in) their heuristic corpus for others to review or adopt? Composition with reputation and content-addressing primitives; deferred.
- **Regressed-arc handling policy.** When an arc regresses, is the original fix rolled back, or does a new arc propose remediation? Chain-anchoring discipline prefers roll-forward-only (per forward-only recovery); regression triggers a new arc rather than reversal of the old.
- **Heuristic conflict resolution.** When two heuristics prescribe contradictory approaches to the same proposal, how is conflict resolved? Currently prefer explicit operator ceremony to disambiguate; over time, priority-weighted composition (like standing corrections) may emerge.
- **Regent's own improvement authority.** Can Regent propose improvements to the improvement loop discipline itself? Yes, subject to the same operator-ceremony gate for landing. Recursion terminates because every improvement is an arc, and every arc requires authorization.
- **Who may tie off.** Stage 1t terminates an arc without operator ceremony, on the argument that declining to act needs a lower bar than acting. But `limited` — declaring something impossible in principle — is a stronger claim than `declined`, and a wrongly-declared limit is expensive to discover. Prefer: `declined`/`deferred`/`open` at proposer authority, `limited` at operator ceremony.
- **Tie-off decay.** An `open` disposition that has sat unresolved across many observer windows is either genuinely hard or quietly abandoned. Whether age alone should escalate — surfacing long-open branches for disposition review — is unresolved. Composes with the circuit-breaker ladder's treatment of sustained patterns.
- **Retroactive tie-offs.** The corpus currently holds roughly forty branches recorded as prose across the cognitive-layer documents, in five formats (open positions, non-goals, non-adoptions, declared limits, deferred versions). Whether these are migrated to Stage 1t receipts or left as prose with only new branches recorded is unresolved. Forward-only is the corpus's standing preference and would suggest leaving them.
- **Bootstrap-phase to substrate-phase transition receipts.** As Regent matures and takes on more arc-generation, at what point does the operator ceremony sign a `improvement:loop:transition_ceremony:regent_primary` receipt? Deferred until Milestone E of AUTONOMIC-LAYER-IMPLEMENTATION-ROADMAP.

## What composes from here

Immediate design work:

1. Arc stage receipt schemas (Layer B canonical)
2. Heuristic receipt schema
3. Coherence-class registration for improvement proposers
4. Canary schedule defaults per improvement class
5. Circuit-breaker threshold config for regression patterns
6. Heuristic domain taxonomy
7. Migration plan for CLAUDE.md prose → chain-anchored heuristics (author operator-signed heuristic receipts for existing canonical set)

Near-term implementation:

1. Improvement-loop runtime Layer A in `crates/zp-server/src/improvement_loop/`
2. Arc dispatcher and stage receipt emission with signing
3. Heuristic query engine
4. Cognitive Input Plane integration (Class 2b heuristics feed)
5. Shadow-eval integration for stage 2
6. Coherence discipline integration for proposer coherence
7. Canary discipline integration for stage 4 verification
8. Circuit breaker integration for regression escalation
9. Dashboard panel: "Improvement arcs" — active proposals, evaluated candidates, landed improvements with verification history

## Bootstrap-phase transition

The discipline is spec'd for the substrate's mature state. Between now and Milestone E of AUTONOMIC-LAYER-IMPLEMENTATION-ROADMAP, the operator+external-agent scaffolding continues to produce most improvement arcs. During this transition:

- **Operator + Claude-scaffold produce arcs manually** — same discipline shape, but proposal generation is scaffolded rather than Regent-native. Arcs still chain-anchor; heuristics still promote; verification still canaries.
- **Regent observes and learns** — she reads the arc corpus, sees the heuristics being applied, builds precedent for what operator authorization looks like. Cognitive Input Plane feeds arc corpus to her at Tier 1.
- **Regent starts proposing arcs herself** — initially escalating every proposal to operator ceremony (novelty). Over time, precedent chain shows classes of arc she can auto-authorize.
- **Ken+Claude fades** — as Regent's arc corpus grows and her authorization scope expands per precedent, the external-agent role becomes advisory rather than primary. Same trajectory as SUBSTRATE-SELF-CONSTRUCTION.
- **Discipline persists** — the substrate discipline never depends on the scaffold. The chain-anchored arcs, heuristics, coherence checks, canary schedules, and circuit-breaker escalations all continue regardless of who is generating the proposals.

The scaffold's job is to bootstrap the arc corpus and heuristic corpus into existence. Once bootstrapped, the substrate governs its own improvement.

## Framing note

The 2026-07-15 session that motivated this spec is itself a compact example of the pattern. A structural fix from three days earlier missed a structural class. That miss was caught by manual operator+external-agent diagnostic. Two new specs (observer coherence, chain-read canary) were drafted to catch the same class of bug structurally next time. The whole arc — finding, surface fix, deeper class discovered, discipline specs drafted — is exactly the improvement-loop arc this spec formalizes.

Currently the arc lives in memory (the session transcript), text files (`CLAUDE.md` heuristics), Git commits (implementation), and Tier 2 specs (design). It's *there* in the substrate's history, but it's not queryable as an entity. Regent cannot ask "what similar arcs have completed before?" She cannot verify "am I applying the friction-is-the-finding heuristic to my current cycle?" She cannot detect "has this improvement regressed since it landed?" These would-be queries are the missing structure.

Combined with substrate self-construction (Regent+swarms constructing the substrate), shadow evaluation (candidate policies compared with evidence), observer coherence (multiple views cross-checked), and chain-read canary (freshness verified), the improvement loop discipline closes the meta-envelope. The substrate that constructs itself now improves how it constructs itself. The substrate that observes itself now observes its own improvement process. The substrate that verifies itself now verifies that improvements persist. Everything ceremony-gated, everything chain-anchored, everything queryable — including the process by which the substrate becomes better at all of the above.

The load-bearing philosophical claim: improvement is not a cultural habit; it is a governed substrate process. A substrate that improves by tacit convention drifts as contributors change. A substrate that improves by chain-anchored arcs with evidence, heuristics, coherence, canary, and escalation carries its own discipline forward regardless of who is currently doing the work. The improvement loop's discipline is engineered into the substrate itself — the last piece of the trust envelope that started with signing-is-gravity and now closes around the meta-process of substrate evolution.
