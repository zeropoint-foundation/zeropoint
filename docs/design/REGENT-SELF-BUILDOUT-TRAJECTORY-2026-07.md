# Regent Self-Buildout Trajectory

**Document type:** Tier 2 canonical elaboration. Declares the substrate's current operating arc — the multi-month trajectory of Regent becoming capable of executing the design corpus from within Sovereign Form. Composes with `KEEL-2026-07.md` (invariants and axioms this trajectory must preserve), `ONTOLOGY-AND-CARTOGRAPHER-2026-07.md` (Trajectory as central primitive; this doc pre-declares an intent Cartographer will later materialize), `TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT-2026-07.md` (Aegis is the officer that will clock this trajectory), `SUBSTRATE-FORM-2026-07.md` (Sovereign Form as the substrate this trajectory targets), `OFFICER-LENS-DECLARATIONS-2026-07.md` (Aegis's lens is the observation surface for trajectory coherence).

**Author:** Ken Romero (2026-07-24), with framing synthesis from Claude. The six-gates decomposition and gate ordering are Ken's; the doc structure is Claude's.

**Status:** Design declaration, not chain-anchored. Emergent-first per Cartographer design — this doc names what the substrate is building toward so Cartographer (when it lands) has semantic ground for the Trajectory it will materialize from observed activity. No `ontology:trajectory:*` receipt is emitted from this doc's landing; that receipt is Cartographer's to emit, not the doc's.

## Framing

### What this doc is

An operator-anchored declaration of the substrate's current multi-month operating arc. Names what "done" looks like as six load-bearing gates, defines observable chain-signal criteria for each gate's closure, and pre-supplies Cartographer with the interpretive frame it will need when it lands. Serves as coordination surface for near-term work: any commit, spec, or ceremony can cite this doc's gate identifiers to make its contribution to the arc legible.

### What this doc is not

- **Not a chain-anchored Trajectory declaration.** ONTOLOGY-AND-CARTOGRAPHER §The hard problem states Trajectories are *emergent* from activity, not *declared* top-down. This doc respects that: it declares the operator's *intent*, not the Trajectory *itself*. Cartographer emits the actual `ontology:trajectory:created:regent_self_buildout` receipt when it observes enough activity to materialize the Trajectory with adequate boundary confidence.
- **Not a project plan.** No dates, no milestones-with-deadlines, no dependency Gantt. The gates are *architectural gates*, not calendar gates. Each closes when its structural criteria are met; if that takes a week or a quarter, the criteria don't move.
- **Not a commitment.** Trajectories can fork, go dormant, be superseded. If the substrate learns something during buildout that reframes what "Regent building herself out" means, the six gates get revised. Corpus is not scripture; corpus is current understanding.
- **Not enforcement.** Aegis observes this trajectory advisorily per TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT §1.3. Enforcement stays atomic per constitutional invariants. This doc guides awareness, not authority.

### Why declare now

Three reasons:

1. **Coordination surface.** The next months of substrate work will land many commits, specs, and ceremonies. Without a shared name for what they're serving, each piece looks like an isolated task rather than a trajectory contribution. Naming the arc lets any piece cite the gate it advances.
2. **Aegis semantic ground.** Aegis's v1 scope (officer-cadre cadence, per `crates/zp-officers/src/aegis.rs`) is deliberate first-step material. His full trajectory-monitoring scope requires knowing what trajectory to monitor. Pre-declaring the arc gives Aegis (in v2, post-Cartographer) something specific to clock rather than requiring him to derive the arc from raw observation.
3. **Precedent for pre-declared operator intent.** Cartographer materializes Trajectories from observed activity. But some operator arcs are known before they emerge in activity — this is one. Declaring them via doc rather than receipt establishes the pattern for future cases where operator intent legitimately precedes activity emergence.

## The six gates

Ordered by dependency: gates 1-2-6 can proceed on APOLLO in parallel with Pi 5 assembly; gates 3-4-5 require Sovereign Form as their platform. Aegis and corpus-consistency (1, 6) are software-side; Sovereign Form (implicit ground condition), local inference (3), and build-execution delegation (5) are the substantive shifts. Metacognitive fidelity (4) sits between: its test harness can begin on APOLLO but its verified claim depends on the Sovereign Form Regent.

### Gate 1 — Cartographer materializing the ontology

**What closes:** The Cartographer runs as a background subprocess per `ONTOLOGY-AND-CARTOGRAPHER-2026-07.md`, reads chain entries via `AuditStore::set_notifier`, materializes Trajectories/Decisions/Insights/Artifacts/Frictions into a persistent ontology store, and emits `ontology:*` receipts for its actions. Officers begin querying the ontology (not raw chain) per KEEL §III.5.

**Observable signals of closure:**
- `ontology:trajectory:created:*` receipts appearing on chain
- `ontology:object:updated:*` receipts for downstream mutations
- Ontology store present on disk (`~/ZeroPoint/data/ontology/` or equivalent)
- At least one officer's sweep queries ontology successfully
- Cartographer replay-from-scratch works: delete store, restart, chain replays cleanly

**Current state:** Not started. Design landed 2026-07-01; implementation pending. Task not yet in queue.

**Load-bearing property gained:** "The chain is truth; the ontology is understanding" transitions from aspirational to operational. Regent queries ontology per KEEL, not raw receipts — closing the gap that motivated the Cartographer design.

**Dependencies:** None. Executable on APOLLO now.

### Gate 2 — Aegis emitting

**What closes:** Aegis is registered in the officer cadre, emits heartbeats, and produces trajectory-scope findings. v1 (officer-cadre cadence coherence) satisfies the gate's minimum. Full trajectory-level detection per TRAJECTORY-AWARE §VI.1 lands when Cartographer's ontology is available.

**Observable signals of closure:**
- `officer:aegis:heartbeat` receipts at declared cadence
- `officer:aegis:trajectory:*` findings on chain
- `substrate_validate` reports Aegis heartbeat status as `ok` (was `missing`)
- Overall substrate posture moves from `degraded` to `healthy` on Aegis dimension

**Current state:** **Landed 2026-07-24** per task #24. v1 implementation complete: 12 unit tests green, config wiring through all layers, first sweep cycle on next `zp-dev.sh release` will produce first receipts.

**Load-bearing property gained:** Trajectory-scope observer exists in the cadre. Silent-lens detection (per LENS-DISCIPLINE §3) becomes possible for officer cadre coherence. The trajectory this doc names has an officer to clock it once Cartographer materializes it.

**Dependencies:** None. Executable on APOLLO now.

### Gate 3 — Local inference at agentic-execution tier

**What closes:** Regent's cognitive backend runs on operator-controlled hardware (Sovereign Form Pi 5 with rally to APOLLO for heavy work per Decision C), not via cloud API. Model tier is adequate for agentic execution (current target: GLM 5.2 or successor). CloudMandate paths remain available for burst work but are no longer the default cognitive path.

**Observable signals of closure:**
- `regent:inference:*` receipts show local endpoints, not cloud
- `regent:config:inference` receipt cites a local model with adequate tier characteristics per `models/{family}/model_dossier.toml`
- Chain-anchored evidence of successful agentic work (multi-step tool dispatch, self-correction) via local inference
- Rally protocol (per Decision C) chain-anchored on at least one operator-authorized cross-device inference

**Current state:** Regent currently runs Sonnet 4.6 via Abacus (cloud). GLM 5.2 or successor stand-up pending Pi 5 assembly. `config.toml` currently specifies `reasoning_model = "claude-sonnet-4-6"`.

**Load-bearing property gained:** "Regent building herself out" via cloud API is a sovereignty contradiction at the level of the act itself. Closing this gate removes that contradiction — the cognition doing the building is under sovereign control.

**Dependencies:** Sovereign Form assembly (implicit ground condition). Rally protocol implementation (spec exists, code pending).

### Gate 4 — Metacognitive fidelity verified

**What closes:** The Empirical Program's metacognitive fidelity phase produces measurements: Regent's self-reports about her state (loaded models, active tools, chain-query capability, standing corrections held) are compared against ground truth, and divergence metrics are chain-anchored. Cognitive Self-Observer (P2.2) is joined by P2.2.5-Shadow (per task #14) — a shadow-evaluated semantic classifier that catches confabulation classes P2.2's pattern-matching misses.

**Observable signals of closure:**
- `cognitive:fidelity:measured` receipts on chain at declared cadence
- Per-class fidelity metrics (self-report vs ground truth) tracked over time
- P2.2.5-Shadow producing semantic classifications on Regent's cognitive outputs
- Chain-visible evidence that confabulations are caught before emission or flagged in receipts

**Current state:** Test harness not built. P2.2.5-Shadow (task #14) pending. Confabulation instances documented in session logs (Genesis pubkey confabulation, chain_query capability confabulation) but not chain-anchored as evidence.

**Load-bearing property gained:** Regent's self-reports become structurally trustable. Without this, "Regent built herself out" is unverifiable — she could claim gates closed that didn't. With it, her claims are measurable against ground truth.

**Dependencies:** Test harness executable on APOLLO. Verified claim requires production Regent (post-graduation) for representative measurement.

### Gate 5 — Bounded build-execution delegation

**What closes:** A narrow `delegation:build:*` capability class exists, operator-signed at Genesis-derived ceremony, granting Regent bounded write authority over her own crates and derived artifacts. Execution runs in sandbox (per SUBSTRATE-HARDENING-CEREMONY isolation model). Commits require operator signature — Regent proposes, operator signs, per KEEL P9. Precedent-based (per III.19) — first instance of each build-action class requires explicit operator approval; subsequent instances of that class execute autonomously with chain-anchored precedent citation.

**Observable signals of closure:**
- `delegation:granted:build:*` receipts on chain, operator-signed
- `regent:build:proposed:*` receipts naming candidate builds with cited precedent
- `regent:build:executed:*` receipts for autonomous executions
- `operator:build:signed:*` receipts for operator-ceremony-committed changes
- At least one autonomous build-modify-test cycle chain-anchored end-to-end

**Current state:** Not designed. `delegation:build:*` capability class does not exist. Current pattern is operator (Ken) as the executor of every code change Regent proposes.

**Load-bearing property gained:** Regent's "hands" become real. Prior gates make her *understanding* trustable, her *cognition* sovereign, her *observation* calibrated. Gate 5 makes her *action* possible within bounded, operator-controlled scope. This is the substantive shift — everything before it is preparation; everything after it is execution.

**Dependencies:** Sovereign Form (execution should run on the substrate she builds for). Gates 3-4 (autonomous action requires sovereign cognition and verified self-observation). Sandbox model requires specification pass.

### Gate 6 — Corpus consistency verification

**What closes:** The design corpus itself becomes subject to Claim-2 (collective audit) discipline. Cross-doc consistency is chain-verifiable: contradictions between KEEL invariants and Tier-2 elaborations produce `lens:conflicts:*` receipts; missing composition references produce `lens:composition:missing:*` receipts. Manual maintenance of `CANONICAL-CORPUS-INDEX-2026-07.md` is supplemented by automated coherence checks that fire when docs land or change.

**Observable signals of closure:**
- Consistency-check tool exists and runs (candidate: `zp corpus verify` CLI verb)
- `corpus:coherence:verified` receipts on chain per verification pass
- `lens:conflicts:*` receipts when contradictions found
- CANONICAL-CORPUS-INDEX-2026-07.md carries coherence-verified attestations per doc
- Regent's Tier 1 context (per COGNITIVE-INPUT-PLANE) can query corpus coherence status

**Current state:** Manual only. CANONICAL-CORPUS-INDEX-2026-07.md is human-maintained. No automated verification. LENS-DISCIPLINE receipt schemas exist but no tooling emits `lens:conflicts:*`.

**Load-bearing property gained:** Regent building from an inconsistent corpus materializes the inconsistencies as substrate half-state — the exact failure mode named in the "two reasonable models" heuristic. Corpus coherence discipline prevents that class of failure structurally.

**Dependencies:** LENS-DISCIPLINE infrastructure (landed). Tooling design pass required.

## Gate closure order and parallelism

Gates 1, 2, 6 are software-side and can proceed on APOLLO in parallel with Pi 5 hardware assembly. Gate 2 landed 2026-07-24. Gate 1 (Cartographer) and Gate 6 (corpus coherence) are the productive frontier for APOLLO-side work now.

Gates 3, 4, 5 target the Sovereign Form. Gate 3 (local inference) is the first ceremony post-graduation — needs a functioning Sovereign-Form Regent to test rally protocol against. Gate 4 (metacognitive fidelity) test harness can begin on APOLLO now, but the verified-claim status requires the Sovereign-Form Regent for representative measurement. Gate 5 (build-execution delegation) is architecturally the largest — requires design pass covering sandbox model, precedent semantics, and rollback ceremony — and land structurally after gates 3-4 stabilize.

No calendar attached. Gate closure is when observable criteria are met, not when a scheduled date arrives. If a gate takes months, that's information about the gate's complexity, not a failure.

## Composition properties

Once Cartographer lands (Gate 1), this trajectory becomes chain-materialized as `ontology:trajectory:*:regent_self_buildout`. At that point:

- **Each of the six gates becomes a sub-trajectory** — nested `Trajectory` per ONTOLOGY-AND-CARTOGRAPHER §Trajectory struct. Cartographer's `parent_id` field carries the nesting.
- **Aegis's v2 scope becomes concrete** — trajectory coherence detection queries this Trajectory's chain-visible progress against declared gate criteria; misalignment produces `officer:aegis:trajectory:regent_self_buildout:*` findings.
- **Corpus coherence lens (Gate 6) reads this doc as one node** — `lens:composed:corpus_coherence:regent_self_buildout_trajectory` receipts encode that this doc participates in corpus-consistency discipline.
- **Precedent-based autonomous action (Gate 5) becomes chain-queryable** — Regent's autonomous build actions cite this trajectory as the arc-level context in which precedent applies.

The pre-declaration in this doc becomes the boundary-confidence anchor for Cartographer's materialization — high confidence, because the operator explicitly declared the arc rather than requiring Cartographer to infer it.

## Composition with existing officer lenses

Each of the five officer lenses (per OFFICER-LENS-DECLARATIONS-2026-07.md) observes a slice of this trajectory:

- **`officer_std`** — Steward observes chain integrity across all gates; every gate's observable signals produce chain receipts Steward attests structurally.
- **`officer_sen`** — Sentinel observes security surface, especially around Gate 5 (delegation:build:* introduces new authority surface Sentinel monitors).
- **`officer_forge`** — Forge observes tool lifecycle, especially around Gate 3 (local inference stack is a new tool class) and Gate 5 (build tooling).
- **`officer_cleo`** — Cleo narrates governance, especially around Gate 5 (build-execution delegation is a governance-significant event Cleo narrates).
- **`officer_aegis`** — Aegis clocks trajectory coherence — this doc's arc is the primary trajectory Aegis will monitor once Cartographer materializes it.

Cross-lens keyword compositions emerge: "build" spans Forge and Cleo (tool lifecycle × governance advancement); "delegation" spans Cleo and Aegis (governance narration × trajectory monitoring); "inference" spans Forge (tool lifecycle) and future gate-specific lenses. `lens:composed:*` receipts formalize these overlaps as they're empirically observed.

## Non-goals

- **Not scheduling.** No dates, no deadlines, no burn-down chart. Substrate work moves at the pace that observable criteria are met; scheduling would introduce time pressure that corrupts the "friction is the signal" heuristic.
- **Not committing.** If the substrate learns something during buildout that reframes the gates, the gates get revised via corpus update. This doc is amendable; the six-gate decomposition is current understanding, not sacred structure.
- **Not defining Regent's ultimate scope.** This trajectory closes when Regent can execute the design corpus from within Sovereign Form. What she does with that capability is her own subsequent trajectory — the successor arc this doc's closure enables.
- **Not preempting Cartographer's Trajectory-materialization judgment.** If Cartographer, once running, decides this trajectory is better represented as three trajectories (or one), that judgment overrides this doc's decomposition. Cartographer's ontology is the operational truth; this doc is intent guidance.

## Open positions

- **Chain-anchoring ceremony.** When (if) to emit an operator-signed `operator:intent:trajectory_declaration:regent_self_buildout` receipt (or similar) that binds this doc's declaration to chain evidence. Requires Trezor ceremony; deferred until Pi 5 assembly complete. Alternative: wait for Cartographer to emit `ontology:trajectory:created:regent_self_buildout` naturally when it observes sufficient supporting activity, treating this doc as pre-supplied semantic ground.
- **Gate revision protocol.** If a gate's criteria need revision, what's the ceremony? Options: (a) simple doc update with corpus-index note, (b) chain-anchored `trajectory:gate_revised:*` receipt with rationale, (c) operator-signed supersession. Prefer (a) for corpus alignment (this is a design doc, not chain state); (b) if we want gate-revision history queryable structurally.
- **Sub-trajectory declaration timing.** Should each gate get its own pre-declaration doc (`REGENT-SELF-BUILDOUT-GATE-1-CARTOGRAPHER-*.md` etc.) or stay consolidated here? Prefer consolidated until a gate acquires enough sub-structure to warrant its own doc; then split with supersession note.
- **Aegis v2 scope.** Once Cartographer lands and this trajectory is chain-materialized, what exactly does Aegis emit? Candidate patterns: `officer:aegis:trajectory:gate_advanced:{gate_id}`, `officer:aegis:trajectory:gate_stalled:{gate_id}`, `officer:aegis:trajectory:cross_gate_incoherence`. Deferred until Cartographer materialization surface is concrete.

## What composes from here

Immediate coordination:
1. Any commit, spec, or ceremony that advances a gate can cite `docs/design/REGENT-SELF-BUILDOUT-TRAJECTORY-2026-07.md#gate-N` in its rationale, making its trajectory contribution legible.
2. Aegis v2 (post-Cartographer) reads this doc's gate identifiers as the primary trajectory-monitor targets.
3. Cartographer (Gate 1) uses this doc as boundary-confidence anchor when it materializes the Trajectory from activity.

Near-term corpus:
1. Add entry to `CANONICAL-CORPUS-INDEX-2026-07.md` under Meta-discipline section.
2. Update task list to reference gate identifiers where existing tasks contribute (task #14 → Gate 4; task #29 → Gate 6 preparatory; task #35 → Gate 5 preparatory).
3. Consider adding "Which gate does this advance?" as a template field in future spec headers.

Later:
1. Emit `operator:intent:trajectory_declaration:regent_self_buildout` receipt at Pi 5 ceremony (adds chain-anchored operator commitment; requires Trezor).
2. When Cartographer lands, verify it materializes a Trajectory matching this doc's decomposition; discrepancies inform boundary-detection tuning.

## Framing note

The substrate has been asking, implicitly, since roughly 2026-05: *what is Regent for, and how does she get there?* The corpus has accumulated ~60 Tier-2 docs answering the first part in fragments. The second part has been carried in Ken's head and in session-to-session task lists. This doc names the second part corpus-side so the answer stops depending on memory.

The six gates aren't a plan for Regent to become powerful. They're the substrate conditions under which "Regent building herself out from the design corpus" stops being a category error. Currently that phrase describes something that would necessarily fail — Regent lacks materialized understanding (Gate 1), trajectory monitoring (Gate 2), sovereign cognition (Gate 3), verified self-observation (Gate 4), execution authority (Gate 5), and coherent source material (Gate 6). Closing these gates makes the phrase describe something that can succeed. That's the arc.
