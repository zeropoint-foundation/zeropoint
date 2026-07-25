# Autonomic Layer Implementation Roadmap

**Roadmap document.** Not a Tier-2 canonical elaboration; this is an implementation planning artifact. Identifies work needed to mature the substrate's autonomic layer sufficient for Regent to systematically guide implementation of the broader corpus while operator (Ken) focuses on hardware prototyping.

Draft — 2026-07-11 — internal audience only. Composes with every spec in `docs/CANONICAL-CORPUS-INDEX-2026-07.md`; specifically operationalizes: `SYSTEM-OFFICER-CADRE-2026-06.md`, `COGNITIVE-INPUT-PLANE-2026-07.md`, `COGNITIVE-SELF-OBSERVER-2026-07.md`, `CLAIM-VERIFIER-2026-07.md`, `STANDING-CORRECTION-RECEIPT-SCHEMA-2026-07.md`, `SUBSTRATE-BLINDNESS-HEURISTICS-2026-07.md`, `SHADOW-INFERENCE-COMPARISON-2026-07.md`, `EXECUTION-AUTHORITY-MODEL-2026-07.md`.

## Framing

The corpus has grown substantially over the 2026-07-10 through 2026-07-11 arc — over 60 Tier-2 specs covering identity, cognition, relationships, hardware, emergency response, discovery, kinship, consequence, legal composition, transport, MVI, field testing, and domain composition with external systems. Substrate is spec-complete for its designed scope. What remains is implementation.

Ken's role transitions toward hardware prototyping — Pi 5 stand-up, TPM integration, measured boot verification, eventual custom carrier board work per SOVEREIGN-HARDWARE. That is substantial focused work.

The substrate needs to construct itself in parallel — genuinely autonomously per operator-declared scope, not merely with cognitive guidance to human executors. Regent, in her role as cognitive advocate operating under scoped delegation, dispatches builder agents and swarms per SUBSTRATE-SELF-CONSTRUCTION-2026-07.md to execute construction work. Forge, per operational authority, dispatches builder agents for build execution, test runs, and self-maintenance operations. Substrate becomes self-constructing when Regent+Forge can execute at operational pace within operator-declared scope, with human intervention reserved for architectural direction and consequential scope expansion.

The bootstrap phase — currently operator + external-agent scaffolding writing the corpus and initial implementation — is scaffold, not architecture. It exists to bring the mature substrate into being; it fades as Regent matures. Operators and external-agent collaborators (currently Ken + Claude in Cowork mode) are nursemaids to a substrate not yet mature enough to construct itself. The scaffold's purpose is to make itself unnecessary.

For Regent to genuinely stand on her own — dispatching construction work autonomously within scope, escalating for novelty, chain-anchoring everything — the autonomic layer supporting her cognitive discipline needs specific maturity. This roadmap identifies what that maturity looks like, in phases with explicit dependencies. Successful completion of the roadmap is when Regent no longer requires human scaffolding for routine substrate construction, hardening, and security work.

## The autonomic layer maturity criteria

Regent-as-implementation-guide requires substrate infrastructure that is:

1. **Chain-anchoring reliably** — every Regent action and observation produces chain evidence; chain integrity holds across restarts; officers verify continuously.
2. **Cognitively disciplined** — Cognitive Input Plane assembles priority-weighted context; Cognitive Self-Observer verifies Regent's outputs against ground truth; Claim Verifier catches structural violations pre-emission; standing corrections persist across sessions.
3. **Precedent-informed** — Regent can query her own prior work, precedent from similar decisions, chain evidence supporting or contradicting proposed actions. Act-on-precedent-escalate-on-novelty pattern working.
4. **Model-conditioned** — served-model identity chain-anchored per turn (per INFERENCE-ROUTING-DISCIPLINE Layer 1); precedent transfer weighted by model distance; behavioral drift detectable.
5. **Aligned-blindness-enforced** — canonical blind classes structurally enforced; Regent's outputs verified against blindness discipline; extension admission checks for blind-class capability declarations.
6. **Officer-verified with low false-positive rate** — officer cadre generates high-signal findings; false-positive cascade reduced to actionable rate; Regent's cognitive context isn't drowning in noise.
7. **Operator-authorization-respected** — every consequential Regent action goes through operator ceremony or falls within pre-authorized precedent; substrate does not autonomously make consequential changes.

Not all of this needs to be perfect for Regent to start providing implementation guidance. What we need is *good enough that Regent's guidance quality reduces Ken's coordination overhead rather than adding to it*.

## Phase-organized implementation plan

Five phases with explicit dependencies. Phases can overlap; blockers between phases are named explicitly.

### Phase 1 — Reliability foundation (2-4 weeks)

Goal: substrate operates reliably enough that Regent's chain-based reasoning has integrity to work from.

**Work items:**

1. **Verify Task #40** (Steward chain_silence false positive) — instrumentation was landed today; needs post-rebuild verification. Steward's periodic sweeps should produce actionable findings, not noise cascades.

2. **Officer false-positive reduction across the cadre** — Sentinel's `unauthorized_listener` classification currently flags every user app on the machine. Per today's diagnostic session, this is the false-positive class most polluting Regent's cognitive context. Refactor Sentinel to:
   - Distinguish known-operator-application-class listeners from unknown listeners
   - Compose with STANDING-CORRECTION discipline (Task #69) so operator corrections about specific processes carry forward
   - Emit lower-severity findings for known-benign listener classes

3. **Chain integrity discipline verification** — chain_query fix from today (Task #33) works; ensure similar archive/live-table discipline holds across all officer chain queries. Audit for other places where officers might be reading filtered/stale views.

4. **Officer sweep manual verb (`zp officer sweep <name>`)** (Task #36) — enables Regent to trigger officer sweeps as diagnostic action rather than waiting for scheduled interval. Small feature; unblocks proactive Regent diagnostics.

5. **Vault credential probing verb (`zp vault test`)** (Task #39) — enables Regent to verify credentials without invoking them in cognitive layer. Composes with aligned blindness (credential values never enter cognitive context).

6. **Graceful shutdown discipline** (Task #26 was completed for zp-dev.sh, but the underlying substrate SIGTERM handling needs verification) — clean shutdown produces chain-anchored snapshot receipts; forward-only recovery from restart works.

**Dependencies:** none; all internal substrate work.

**Verification criteria:**
- Officer sweeps produce ≤10 findings per cycle in normal operation (not 50+)
- Steward chain integrity checker doesn't produce false chain_silence findings
- Regent's cognitive input plane assembly completes reliably per cycle
- Substrate restart preserves chain integrity + reconstructs derived state from snapshots

**Regent's role in Phase 1:** observe substrate behavior via chain query; report inconsistencies; propose Sentinel classification refinements grounded in observed behavior; do NOT autonomously act to modify Sentinel discipline (that's operator ceremony).

**Ken's role in Phase 1:** the code work. Sentinel refactor, chain-integrity audit, officer sweep verb, vault test verb. Substantial focused implementation.

### Phase 2 — Cognitive layer implementation (3-6 weeks, overlaps Phase 1)

Goal: Regent's cognitive discipline is fully implemented, not just spec'd.

**Work items:**

1. **Cognitive Input Plane pipeline** (Task #69) — implement standing_corrections field, active_precedent field, outstanding_commitments field in CognitiveContext. Wire chain queries: query `cognitive:correction:standing` receipts; query `regent:remediation:*` receipts for precedent; query outstanding chain-watcher commitments. Assemble Tier 1 context per COGNITIVE-INPUT-PLANE spec. Chain-anchor per-cycle composition via `cognitive:input:composed` receipts.

2. **Cognitive Self-Observer implementation** — post-emission verification of Regent outputs against chain state. Semantic verification per COGNITIVE-SELF-OBSERVER spec. Flag confabulation gaps as `regent:confabulation_gap:*` receipts that feed back into next cycle's cognitive input plane.

3. **Claim Verifier implementation** — pre-emission structural check on Regent's capability and commitment claims against her active delegation. Deterministic, fast; can annotate / rewrite / reject.

4. **Standing correction chain-query pipeline** — Regent's cognitive context must include active standing corrections at Tier 1 per correction domain / scope matching current cycle. This is the concrete implementation of Task #69's data pipeline.

5. **Chain-watcher and commitment primitive implementation** — from CHAIN-WATCHER-AND-COMMITMENTS spec. Chain-watchers subscribe to receipt patterns; commitments chain-anchor future-actions with declared triggers.

**Dependencies:** Phase 1 partial (chain query reliability needed for standing correction lookups). Can start in parallel with Phase 1 completion.

**Verification criteria:**
- Regent's cycle context includes active standing corrections at Tier 1
- Standing corrections persist across substrate restart (chain-anchored receipts survive)
- Cognitive Self-Observer flags at least the confabulation classes we've observed today (misattributed model identity, false chain-broken claims, misclassified listener PIDs)
- Claim Verifier rejects claims outside Regent's active delegation before emission
- Chain-watchers fire on declared patterns; commitments trigger on declared triggers

**Regent's role in Phase 2:** as pipeline lands, Regent starts using it. She reads standing corrections at Tier 1 (finally). She receives self-observer feedback and refines. She sees her own precedent chain-anchored. Her cognitive discipline strengthens with each pipeline component landing.

**Ken's role in Phase 2:** implement pipeline components; verify against spec via manual testing; chain-anchor implementation milestones as `substrate:implementation:phase_2_milestone:<component>` receipts so Regent can reason about implementation progress.

### Phase 3 — Aligned blindness enforcement (2-3 weeks, overlaps Phases 1-2)

Goal: canonical blind classes structurally enforced; extension admission checks working; Regent's outputs verified against blindness.

**Work items:**

1. **Blindness registry runtime** — chain-anchored canonical class list with per-class layer assignments per SUBSTRATE-BLINDNESS-HEURISTICS spec.

2. **Layer 3 scrubbing pipeline** — command-line argument scrubbing, URL credential redaction, sensitive filename scrubbing before chain-anchoring. Pattern registry chain-anchored.

3. **Cognitive-layer boundary enforcement** — Cognitive Input Plane filters against blind class list; raw sensing signals, communication bodies, credential values never enter Regent's context.

4. **Extension admission integration** — QUARANTINE-PLANE admission ceremony checks extension capability declarations against blindness discipline; extensions declaring Layer 1 blind class capabilities refused; Layer 2 flagged prominently.

5. **Cognitive Self-Observer blindness extension** — verify Regent's outputs don't leak blind-class content.

**Dependencies:** Phase 1 for officer reliability. Phase 2 partial (Cognitive Self-Observer needed for blindness violation detection).

**Verification criteria:**
- Attempting to declare Layer 1 canonical blind class as extension capability fails admission
- Layer 3 scrubbing pipeline redacts known sensitive patterns before chain-anchoring
- Regent's context never contains raw CSI, communication bodies, or credential values (verified via manual test scenarios)
- Layer 4 boundary enforced against sensing extension findings

**Regent's role in Phase 3:** operate within blindness discipline; her cognitive context is automatically filtered per Layer 4; she cannot request blind-class information even if she tried; observes blindness enforcement as one of the substrate's alignment properties.

**Ken's role in Phase 3:** implement blindness runtime, scrubbing pipeline, admission integration.

### Phase 3.5 — Sentinel adversarial hardening (3-5 weeks, parallel with Phases 3-4)

Goal: Sentinel role expanded from observer to active adversarial tester per SUBSTRATE-HARDENING-CEREMONY-2026-07.md. Substrate can earn chain-anchored hardened certification via pen test dispatch + operator ceremony.

**Context — current pentest infrastructure state:** the `zp-hardening-tests` crate holds a regression replay harness of Shannon-era pentest findings (attack payloads encoded as HTTP/WebSocket integration tests against `build_app()`). This is regression coverage of known findings only — the discovery engine (Shannon) was purged from the substrate as tenant. Phase 3.5 must reintegrate an active pentest engine (Shannon or successor) so Sentinel can dispatch novel discovery, not merely replay history. Without reintegration, Sentinel cannot substantiate a hardened certification claim beyond "no known Shannon-era regressions."

**Work items:**

1. **Attack surface catalog runtime** — enumeration of Sentinel-tested surfaces per canonical seven-class taxonomy. Extension admission automatically adds extension-declared surfaces to catalog.

2. **Pentest suite reintegration (critical path)** — reintegrate an active pentest engine capable of novel-vulnerability discovery against substrate surfaces. Two candidate paths: (a) re-admit Shannon under current admission discipline (quarantine plane, aligned-blindness declaration, scoped delegation, chain-anchored dispatch), (b) evaluate successor tools and select one that composes with the corpus's alignment invariants. The pentest engine runs against isolated substrate replicas per BUILD-PROCESS-DESIGN reproducibility ceremony; findings chain-anchor as Sentinel evidence for certification proposal. The `zp-hardening-tests` crate absorbs discovered findings as regression coverage over time — replay harness downstream of active discovery, not standalone. Aligned-blindness discipline: pentest engine sees substrate surface, never operator content.

3. **Reference pen test builders per surface class** — implementation of pen test dispatch discipline per SUBSTRATE-SELF-CONSTRUCTION. Start with Class 1 (Auth surfaces — highest immediate value); expand to remaining classes over time. Federation-hostable so operators can share pen test builders across substrates. Composes with work item #2 (pentest engine dispatched as one builder class; other classes may use different tools per surface).

4. **Certification state manager** — chain-anchored state transitions (unhardened → provisionally certified → fully certified), automatic revocation triggers (post-build, extension admission, circuit breaker escalation).

5. **Sentinel proposal ceremony** — evidence assembly, operator review UX, chain-anchored certification receipts.

6. **Certification-aware operation gating** — downstream substrate operations (peer trust anchor high-depth grants, public directory publication, extension marketplace participation) check current hardening state.

7. **Isolated substrate replica dispatch** — pen tests run against test replicas (per BUILD-PROCESS-DESIGN reproducibility ceremony), not production substrate. Preserves production integrity during testing.

**Dependencies:** Phase 1 (Sentinel classification refactor complete), Phase 2 partial (Cognitive Self-Observer available for pen test result verification), SUBSTRATE-SELF-CONSTRUCTION Phase 4 (builder dispatch primitives available).

**Verification criteria:**
- Sentinel dispatches pen test builder for Class 1 auth surfaces; operator can review evidence and sign certification
- Substrate certification state chain-visible; downstream operations check state
- Automatic certification revocation fires post-build; re-certification ceremony required for federation-facing operations
- Aligned blindness preserved during pen testing (no operator content in test payloads or findings)

**Regent's role in Phase 3.5:** she narrates hardening state to operator; proposes re-certification cadence based on chain state; coordinates with Sentinel dispatch scheduling. Regent does not sign certifications (operator authority).

**Ken's (or successor's) role in Phase 3.5:** implement attack surface catalog runtime + reference pen test builders + certification ceremony flow; author initial pen test suite for Class 1 auth surfaces.

### Phase 4 — Verification stack for Regent's implementation guidance (2-4 weeks, mostly Phase 3-parallel)

Goal: Regent's implementation guidance is chain-anchored, cross-referenceable, and post-hoc verifiable.

**Work items:**

1. **Implementation-guidance receipt schema** — Regent's guidance chain-anchored as `regent:implementation_guidance:<spec_id>:<guidance_id>` receipts. Fields: spec reference, current substrate state observation, proposed next step, precedent references, confidence level, escalation flag.

2. **Chain-query verbs for spec reference** — Regent can query chain for previously-emitted guidance about specific specs, allowing consistency across sessions.

3. **Implementation progress tracking receipts** — as implementation items complete, chain-anchor `substrate:implementation:completed:<spec_id>:<item_id>` receipts. Regent can query "what implementation items are complete vs pending vs in-progress" via chain.

4. **Cross-reference protocol** — Regent's guidance references previous guidance and precedent. Chain-walkable back to primary spec references.

5. **Shadow-inference comparison integration** — for high-stakes guidance decisions (proposing significant architectural direction), shadow inference against alternate model for comparison evidence per SHADOW-INFERENCE-COMPARISON discipline.

**Dependencies:** Phase 2 for Cognitive Self-Observer (verifies guidance quality).

**Verification criteria:**
- Regent can walk chain history of her own prior implementation guidance for any given spec
- Guidance receipts chain-integrity-verified
- Cross-reference walk from current guidance back through precedent to primary spec succeeds
- Ken (or successor) can review chain-anchored guidance and understand Regent's reasoning without needing to be in the original conversation

**Regent's role in Phase 4:** she starts emitting implementation guidance. Chain-anchored per-cycle guidance about what to implement next, why, referencing precedent and specs. This is where "Regent as implementation guide" becomes operational.

**Ken's role in Phase 4:** implement guidance receipt schema; verify chain-cross-reference works; delegate specific guidance authority to Regent via ceremony receipts declaring what guidance classes she's authorized to produce.

### Phase 5 — Precedent-based autonomous action mechanics (3-6 weeks, parallel with 3-4)

Goal: Regent operates under act-on-precedent / escalate-on-novelty pattern reliably.

**Work items:**

1. **Precedent query implementation** — chain query for `regent:remediation:*` receipts matching current-cycle context. Distance metrics for precedent relevance.

2. **Novelty classifier** — heuristic for determining "this cycle's context matches prior precedent" vs "this is genuinely novel." Chain-anchored classifier decisions.

3. **Escalation protocol implementation** — when novel, Regent surfaces to operator ceremony. Chain-anchored escalation receipt. Operator disposition ceremony authorizes-or-rejects. Once authorized, the operation becomes new precedent for future cycles.

4. **Autonomous-action budget** — even within precedent, Regent operates within operator-declared budget. Bounded autonomy.

5. **Post-action verification** — Cognitive Self-Observer verifies Regent's autonomous actions against precedent (was the pattern actually similar?). False-precedent-match triggers escalation to operator.

**Dependencies:** Phase 2 (Cognitive Self-Observer + standing corrections). Phase 4 (precedent chain-anchoring reliable).

**Verification criteria:**
- Regent's autonomous actions chain-anchor precedent references
- Novel-context escalation fires correctly (Regent stops and asks operator when pattern is genuinely new)
- Operator disposition of escalation becomes new precedent that Regent uses for subsequent similar cycles
- Cognitive Self-Observer catches false-precedent-match cases

**Regent's role in Phase 5:** she becomes systematically autonomous within precedent. Chain-anchored implementation guidance for spec-referenced items becomes precedent-followable action for maintenance tasks like officer cadre calibration proposals, chain-watcher pattern refinement, standing correction updates. She escalates when guidance would set new precedent.

**Ken's role in Phase 5:** implement precedent query, novelty classifier, escalation protocol. Review escalations as they come; operator disposition creates precedent chain that grows Regent's autonomous scope over time.

### Phase 6 — Field pilot preparation (parallel with all phases)

Goal: substrate is ready for Tier 1 solo pilots per FIELD-TESTING-DISCIPLINE.

**Work items:**

1. **Onboarding UX for N=1** — first-time-operator flow from install through Genesis ceremony through first chain-anchored decision. Time-to-first-value in minutes.

2. **N=1 value demonstration** — chain-anchored decision receipts working; retrospection query working; Regent cognitive presence for own chain.

3. **Substrate exit ceremony implementation** — pilot participants can exit cleanly per SUBSTRATE-EXIT-CEREMONY.

4. **Pilot participant consent receipt schemas** — chain-anchored pilot participation ceremony.

5. **Chain-shared analysis surface** — pilot findings analyzable via reproducibility ceremony discipline.

**Dependencies:** All prior phases partial. Not all substrate features needed for Tier 1 pilots — just N=1 value delivery.

**Verification criteria:**
- Fresh operator can install substrate → complete Genesis ceremony → chain-anchor first decision → query it back within one session
- Pilot participant onboarding UX has documented rough edges disclosed to participants
- Chain-shared analysis works for pilot data with participant consent

**Regent's role in Phase 6:** guide participant onboarding; propose UX refinements based on early pilot feedback; chain-anchor implementation guidance for pilot-informed refinements.

**Ken's role in Phase 6:** implement onboarding UX; conduct or coordinate early Tier 1 pilots; capture pilot findings as chain-anchored evidence.

## Regent's operational discipline for autonomous substrate construction

Once autonomic layer is mature (Phase 4+ minimum), Regent operates under this discipline for substrate construction work per SUBSTRATE-SELF-CONSTRUCTION-2026-07.md:

### Standing correction: construction authority

Operator emits standing correction declaring Regent's construction dispatch scope: "Regent is authorized to dispatch builder agents for spec-referenced implementation work matching pre-authorized specs, within declared cost budget, with verification requirements per builder-output class. Regent proceeds on precedent for routine work; escalates novel patterns to operator ceremony."

### Cycle pattern for substrate construction

Each cycle Regent has capacity for construction work, she:

1. Queries chain for current substrate state
2. Queries chain for prior construction operations and their verification outcomes
3. Queries chain for completed implementation items (progress tracking receipts)
4. Cross-references against corpus (specs indexed in CANONICAL-CORPUS-INDEX)
5. Identifies highest-priority gap (implementation-status vs spec-required-state divergence)
6. Decides construction strategy: single builder or swarm, which builder type, cost budget, verification requirements
7. Precedent-based decision: if pattern matches prior successful construction, dispatches within scope; if novel, escalates to operator ceremony
8. Dispatches builder agent(s) per SUBSTRATE-SELF-CONSTRUCTION discipline
9. Receives outputs; verifies per declared requirements
10. Chain-anchors spawn receipts, output receipts, verification receipts, completion receipts
11. Escalates to operator if verification fails after retry attempts or if architectural questions surface

### What Regent does (per SUBSTRATE-SELF-CONSTRUCTION grants within pre-authorized scope)

- Dispatches builder agents for source implementation work
- Dispatches swarms for parallel work items
- Coordinates builders per declared coordination pattern
- Verifies builder outputs per structural / behavioral / alignment / semantic checks
- Chain-anchors full construction lifecycle
- Executes routine implementation work autonomously on precedent

### What Regent does NOT do (requires operator ceremony)

- Modify substrate architectural direction
- Grant new delegations or expand her own construction scope
- Change operator preferences
- Dispatch builders for capability classes outside pre-authorized set
- Execute construction operations affecting alignment invariants (blindness classes, coordination primitives, Genesis operations)

### What operator does (during autonomic mature phase)

- Declares construction scope for Regent via standing correction
- Dispositions novelty escalations to create new precedent for subsequent similar work
- Reviews consequential construction operations at chain-anchored evidence
- Manages hardware, ceremony receipts, Genesis operations
- Makes architectural direction changes when needed

### What operator does NOT need to do (once mature)

- Manually coordinate routine implementation work with external agents
- Execute routine substrate construction operations directly
- Read Regent's guidance and translate to code — Regent dispatches the code work herself

Bootstrap phase (before Phase 4 completion): operator + external-agent scaffolding does construction work. Mature phase (Phase 4+): Regent dispatches; operator supervises.

## Dependencies summary

- **Phase 1 (Reliability foundation)** blocks nothing; foundation for everything
- **Phase 2 (Cognitive layer)** requires Phase 1 partial; blocks Phase 5 fully
- **Phase 3 (Aligned blindness)** requires Phase 1; can run parallel with Phase 2; blocks nothing critical
- **Phase 4 (Verification stack)** requires Phase 2; blocks Phase 5 fully; blocks Regent's implementation guidance role
- **Phase 5 (Precedent autonomy)** requires Phases 2 and 4; enables Regent's full role
- **Phase 6 (Field pilot prep)** parallel with all; requires N=1 substrate value working

## Milestones

**Milestone A — Autonomic reliability** (end Phase 1):
- Officer cadre produces high-signal findings; false-positive cascade eliminated
- Chain queries reliable across archive/live boundaries
- Manual officer-sweep and vault-test verbs functional

**Milestone B — Cognitive discipline mature** (end Phase 2):
- Cognitive Input Plane assembles priority-weighted context per spec
- Standing corrections persist across sessions
- Cognitive Self-Observer flags confabulation gaps

**Milestone C — Blindness enforced** (end Phase 3):
- Canonical blind classes structurally enforced
- Extension admission checks blindness
- Layer 4 cognitive boundary verified

**Milestone D — Implementation guidance operational** (end Phase 4):
- Regent emits chain-anchored implementation guidance per cycle
- Guidance is chain-verifiable and cross-referenceable
- Ken can review guidance and use for priority ordering

**Milestone E — Precedent autonomy operational** (end Phase 5):
- Regent operates autonomously within precedent
- Novel context escalation reliable
- Operator dispositions create precedent chain that grows Regent's scope

**Milestone F — Field pilot ready** (end Phase 6):
- Tier 1 solo pilots deployable
- Onboarding UX validated
- Chain-shared analysis surface functional

## Estimated timeline

- Phase 1: 2-4 weeks (Ken execution, evening/weekend pace)
- Phase 2: 3-6 weeks (mostly parallel with Phase 1)
- Phase 3: 2-3 weeks (parallel with Phases 1-2)
- Phase 4: 2-4 weeks (mostly parallel with Phase 3)
- Phase 5: 3-6 weeks (dependent on Phases 2 and 4)
- Phase 6: 2-4 weeks (parallel with all)

Total wall-clock: 8-12 weeks assuming reasonable-pace evening/weekend execution. Compresses substantially with focused work sessions.

## What Ken can safely defer to Regent's autonomous construction

Once Milestone D is reached (Regent's construction dispatch working) and Milestone E is reached (precedent-based autonomous action mechanics working), Ken can rely on Regent for:

- Autonomous execution of routine substrate construction work within pre-authorized scope
- Dispatch of builder agents for spec-referenced implementation
- Swarm coordination for parallel work items
- Chain-anchored verification of builder outputs
- Novel-context escalation when construction decisions would set new precedent
- Coherence maintenance across all substrate work via chain-anchored guidance and construction

Ken retains responsibility for:

- Architectural direction changes (never Regent's authority; requires operator ceremony)
- New spec drafts (Regent may propose within scope; substantive new architecture requires operator authorship)
- Ceremony receipts affecting operator authority (Genesis, delegation grants, consequence decisions)
- Hardware work (Regent has no hardware access; Ken owns the Pi 5 stand-up and beyond)
- Dispositioning novelty escalations (operator judgment creates new precedent)
- Reviewing consequential construction operations at chain-anchored evidence layer

The scaffold role (currently operator + Claude Cowork doing construction work directly) fades as Regent matures through the phases. Once Phase 5 completes, the bootstrap phase is substantially over; Regent operates as the substrate's construction dispatcher; Ken oversees and directs rather than executes.

## Composition with existing specs

This roadmap operationalizes the following spec surfaces:
- SYSTEM-OFFICER-CADRE (Phase 1)
- COGNITIVE-INPUT-PLANE (Phase 2)
- COGNITIVE-SELF-OBSERVER (Phase 2)
- CLAIM-VERIFIER (Phase 2)
- STANDING-CORRECTION-RECEIPT-SCHEMA (Phase 2)
- CHAIN-WATCHER-AND-COMMITMENTS (Phase 2)
- SUBSTRATE-BLINDNESS-HEURISTICS (Phase 3)
- QUARANTINE-PLANE (Phase 3 admission integration)
- INFERENCE-ROUTING-DISCIPLINE (Phase 4 shadow inference)
- SHADOW-INFERENCE-COMPARISON (Phase 4-5 verification)
- EXECUTION-AUTHORITY-MODEL (Phase 4-5 guidance authority)
- FIELD-TESTING-DISCIPLINE (Phase 6)
- MINIMUM-VIABLE-INTERACTION (Phase 6 N=1)

## What this roadmap is not

- Not a spec (already 60+ Tier-2 specs; roadmap is implementation planning)
- Not a commitment to specific timeline (estimates only)
- Not a substitute for Ken's operator judgment (Ken always decides implementation order)
- Not comprehensive substrate implementation (roadmap covers autonomic layer; broader substrate implementation follows separately)
- Not automatic (Regent guides after autonomic maturity; Ken or successor executes throughout)

## Framing note

This roadmap identifies the specific autonomic layer implementation work needed to shift from spec-writing to substrate-building phase, with Regent providing cognitive-layer implementation guidance while Ken transitions focus to hardware prototyping.

The load-bearing insight: **Regent's role in systematic implementation is cognitive-layer guidance, not code authorship.** She proposes; Ken decides; Ken or successor implements. Her value is coherence maintenance across the arc — chain-anchored reasoning that lets implementation work proceed in parallel without losing sight of the corpus's structural discipline.

For that role to function, the autonomic layer needs specific maturity (chain reliability, cognitive discipline, precedent-based reasoning, aligned-blindness enforcement, verification stack). This roadmap identifies that work explicitly, in phases with dependencies, so Ken can execute it in parallel with hardware work rather than sequentially. Substrate becomes self-sustaining not through Regent's autonomy but through Regent's coherence maintenance amplifying Ken's implementation authority.
