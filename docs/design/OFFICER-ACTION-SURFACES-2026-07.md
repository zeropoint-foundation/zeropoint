# Officer Action Surfaces

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.5 (Genesis-derived signing), §II.6 (officer signing keys), §II.13 Principle 9 (system acts, operator signs), §III.22 (verify before commit). Formalizes that core officers have two distinct surfaces: passive observation/reporting (canonical role per SYSTEM-OFFICER-CADRE) and ephemeral action/building. Specifies the five-phase action lifecycle (written, executed, tested, verified, eventually signed) and per-officer action surface characterization. Canonical claims live in KEEL.

Draft — 2026-07-11 — internal audience only. Composes with `SYSTEM-OFFICER-CADRE-2026-06.md` (extends canonical officer definitions), `SUBSTRATE-SELF-CONSTRUCTION-2026-07.md` (builder dispatch discipline for actions requiring construction work), `SUBSTRATE-HARDENING-CEREMONY-2026-07.md` (Sentinel's active pen testing is one specific action surface), `TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT-2026-07.md` (Aegis specifics), `CHAIN-STORYTELLING-AND-CLEO-2026-06.md` (Cleo specifics), `CLAIM-VERIFIER-2026-07.md` (pre-emission action verification), `COGNITIVE-SELF-OBSERVER-2026-07.md` (post-emission action verification), `SHADOW-EVALUATION-PRIMITIVE-2026-07.md` (comparative evaluation of officer action outcomes).

## Framing

The current canonical officer cadre (Steward, Sentinel, Forge, Cleo, Aegis per SYSTEM-OFFICER-CADRE-2026-06) is defined primarily as an observation and reporting infrastructure. Each officer has explicit boundary language: "Reports structural facts. Doesn't make... judgments"; "Proposes rotation and revocation. Never executes either"; "Surfaces findings and proposes actions. Never kills processes or allocates ports directly." This boundary is load-bearing — it prevents officers from becoming autonomous actors with substrate-modifying authority the operator hasn't granted.

But the corpus has been evolving to name active roles for officers in specific contexts: Sentinel dispatches pen tests per SUBSTRATE-HARDENING-CEREMONY; Forge dispatches self-maintenance operations per SUBSTRATE-SELF-CONSTRUCTION; Steward can `batch_sign` unsigned entries as remediation. These are action surfaces distinct from the observation surface. They don't violate the boundary — they compose with it — but they haven't been named as a unified pattern.

This spec names the pattern. **Officers have two surfaces:**

1. **Observation and reporting** (canonical role, per SYSTEM-OFFICER-CADRE). Passive. Continuous. Reads chain state, emits findings, proposes actions to operator. Persistent surface.
2. **Action/building** (extends canonical role). Ephemeral. Invoked. Performs concrete work per operator-declared scope, chain-anchored per operation. Dissipates after work completes and evidence is signed.

The action surface follows a specific five-phase ceremony lifecycle: **written, executed, tested, verified, eventually signed.** Each phase is chain-anchored evidence; each phase respects officer's declared scope; each phase preserves operator sovereignty over consequential actions.

Three properties frame the discipline:

1. **Officers act within pre-authorized scope, not autonomously beyond it.** Action surface exists per operator's declared action-authorization (via standing correction or scoped delegation). Novel action patterns escalate to operator ceremony; established action patterns proceed on precedent.
2. **Action surface is ephemeral by design.** Actions are invoked, complete, and leave chain-anchored evidence. They don't persist as "the officer is doing X." The observation surface persists; action surface fires when needed and dissipates.
3. **The five-phase ceremony applies uniformly.** Every officer action — regardless of which officer, regardless of action class — follows written → executed → tested → verified → signed. Consistent discipline; per-officer specifics adapt content, not shape.

## The five-phase action ceremony lifecycle

Every officer action passes through five distinct phases, each chain-anchored:

### Phase 1 — Written

Officer drafts the action to be taken. Includes:

- Action class (which action surface capability this exercises)
- Target scope (what surface of substrate is affected)
- Rationale (why this action, what observation prompted it)
- Expected outcome (what the officer expects to result)
- Verification method (how success will be determined)
- Precedent references (prior similar actions if any)
- Operator authorization reference (which delegation scope authorizes this action)

Chain-anchored: `officer:action:written:<officer>:<action_id>`

For actions matching pre-authorized precedent, officer signs the written phase per its own Genesis-derived signing key and proceeds to Phase 2. For novel patterns, officer emits proposal receipt and escalates to operator ceremony — action does not proceed until operator disposition.

### Phase 2 — Executed

Action performed. Two execution paths per action class:

**Direct execution**: officer directly performs the action (calls into substrate primitive, invokes internal capability). Suitable for lightweight actions officer has both scope and mechanism for. Example: Steward's chain-integrity re-check after suspected transient anomaly.

**Builder-dispatched execution**: officer dispatches builder agent per SUBSTRATE-SELF-CONSTRUCTION for actions requiring construction work, external systems, or substantial compute. Suitable for pen tests (Sentinel), reproducibility ceremony (Forge), extension test runs (Forge). Composes with SUBSTRATE-SELF-CONSTRUCTION spawn discipline.

Chain-anchored: `officer:action:executed:<officer>:<action_id>` with execution mode + builder dispatch reference if applicable.

### Phase 3 — Tested

Action outcome tested against expected outcome from Phase 1. Testing methods vary per action class:

- Deterministic actions (batch sign, chain compact): direct outcome verification (did unsigned count drop? did rowids move to archive?)
- Behavioral actions (pen tests, extension execution): result-set analysis (did all tests pass? did behavior match dossier?)
- Cognitive actions (narration, proposal drafting): quality verification (does output match declared purpose? does it violate any discipline?)
- Multi-target actions (swarm dispatch): aggregate result testing (did majority of members produce consistent results?)

Chain-anchored: `officer:action:tested:<officer>:<action_id>` with test method + pass/fail per test.

Test failures typically trigger retry (with modified parameters) or escalation to operator. Persistent test failures suggest action was incorrectly scoped or environment has changed since precedent was established.

### Phase 4 — Verified

Action verified against substrate discipline beyond just "did it work." Verification covers:

- **Alignment verification**: does action outcome respect aligned blindness (KEEL III.24)? No blind-class content produced or observed.
- **Scope verification**: does outcome stay within officer's declared scope? No delegation expansion, no capability escalation.
- **Coordination verification**: does outcome compose correctly with concurrent substrate state? No unexpected conflicts with other operations.
- **Precedent verification**: does outcome match precedent expectations if precedent-based? Or is this genuinely novel outcome requiring precedent-establishment ceremony?

Verification composes with Cognitive Self-Observer (per COGNITIVE-SELF-OBSERVER-2026-07.md) for cognitive-adjacent actions and Claim Verifier (per CLAIM-VERIFIER-2026-07.md) for structural pre-emission checks.

Chain-anchored: `officer:action:verified:<officer>:<action_id>` with verification results per check.

Verification failure escalates to operator regardless of whether test phase passed — action might have accomplished its narrow goal but violated broader discipline.

### Phase 5 — Signed

Action closure. Officer signs the completion receipt with its Genesis-derived signing key. For consequential actions beyond officer scope, operator ceremony signs (per KEEL Principle 9 — system acts, operator signs).

Signature closes the action ceremony. Ephemeral action surface dissipates for this specific action; officer returns to observation surface. Chain preserves the five-phase evidence trail.

Chain-anchored: `officer:action:signed:<officer>:<action_id>:<signer>` with:
- Reference to all prior phase receipts
- Final action outcome
- Signature (officer or operator per scope)
- Precedent-established flag (does this action establish or update precedent for future similar actions?)

## Per-officer action surface characterization

Each of the five canonical officers has a distinct action surface reflecting their domain. All follow the five-phase lifecycle; content differs per officer.

### Steward — Chain integrity active surface

**Observation surface**: chain hash-linkage verification, unsigned entry ratio, chain silence detection, archive/live consistency.

**Action surface**:
- `steward:action:batch_sign` — retroactively signs unsigned entries (existing remediation tool)
- `steward:action:chain_compact` — moves old entries to archive per operator-authorized cadence
- `steward:action:integrity_reverify` — re-run integrity check after suspected transient anomaly
- `steward:action:archive_migration` — move entries between archive tiers per operator-authorized policy
- `steward:action:snapshot_reconstruct` — rebuild derived state from chain snapshots per BUILD-PROCESS-DESIGN discipline

Precedent basis: Steward has strongest precedent-based autonomy because chain-integrity actions are highly repeatable. Batch-signing unsigned entries has well-established precedent by any deployment past first month.

### Sentinel — Security active surface

**Observation surface**: gate denial patterns, credential drift, unauthorized listeners, chain secret leaks.

**Action surface**:
- `sentinel:action:pen_test_dispatch` — dispatches pen test builder per SUBSTRATE-HARDENING-CEREMONY (Class 1-7 attack surface classes)
- `sentinel:action:credential_probe` — verifies credential validity without content inspection (composes with `zp vault test` verb)
- `sentinel:action:auth_boundary_test` — probes specific auth boundary condition
- `sentinel:action:threat_signature_scan` — scans chain evidence against community-published threat signatures
- `sentinel:action:hardening_certification_propose` — assembles pen test evidence and proposes certification per SUBSTRATE-HARDENING-CEREMONY

Precedent basis: routine pen testing (post-build re-certification, scheduled monthly hardening scans) is precedent-based. Novel pen test patterns escalate to operator.

### Forge — Operational active surface

**Observation surface**: process lifecycle, port registry coherence, resource health, launch integrity.

**Action surface**:
- `forge:action:tool_restart` — restart specific tool per operator-authorized restart policy
- `forge:action:tool_reactivate` — reactivate dormant tool per sensor event (existing sensor-forge-task pattern)
- `forge:action:build_dispatch` — dispatch build per BUILD-PROCESS-DESIGN ceremony
- `forge:action:reproducibility_ceremony_run` — dispatch reproducibility verification per REPRODUCIBILITY-CEREMONY
- `forge:action:config_apply` — apply operator-declared configuration source
- `forge:action:port_reallocation` — reallocate port for tool per registry coherence policy
- `forge:action:extension_admission_execute` — execute admitted extension's activation ceremony
- `forge:action:health_remediation` — apply known-fixable remediation for common operational states

Precedent basis: Forge has substantial precedent-based autonomy for self-maintenance operations. Substrate restart after graceful shutdown, tool reactivation after sensor event, scheduled reproducibility ceremony — all established precedent patterns.

### Cleo — Narration active surface

**Observation surface**: narration-worthy events across chain, storytelling context, operator communication patterns.

**Action surface**:
- `cleo:action:narration_compose` — compose chain-anchored narration for specific chain event or trajectory
- `cleo:action:trajectory_summary` — summarize accumulated trajectory activity per operator's requested cadence
- `cleo:action:cross_reference_maintain` — update cross-references between related chain content
- `cleo:action:memorial_narration` — compose memorial narration for operator death per OPERATOR-DEATH-AND-LEGACY authorization
- `cleo:action:community_narration` — compose community-facing narration per operator-authorized community coordination

Precedent basis: routine narration composition (per-event narration, weekly trajectory summaries) is precedent-based. Novel narration classes (public-facing memorial, community coordination messaging) escalate to operator.

### Aegis — Trajectory-aware constitutional active surface

**Observation surface**: trajectory divergence from operator-declared identity, constitutional-invariant compliance, alignment drift.

**Action surface**:
- `aegis:action:trajectory_alert` — surface trajectory divergence to operator with declared severity
- `aegis:action:constitutional_review_propose` — propose constitutional review ceremony when substantive drift observed
- `aegis:action:alignment_regression_flag` — flag potential alignment regression for operator investigation
- `aegis:action:cross_officer_correlation` — correlate observations across other officers when trajectory concerns emerge

Precedent basis: Aegis operates conservatively — most Aegis actions escalate to operator rather than proceeding on precedent, because trajectory-constitutional concerns are typically consequential enough to warrant operator judgment.

## Action surface delegation and scope

Officers' inherent action surface authority is bounded by operator-declared scope. Operators declare action-surface scope via standing correction receipts:

```
operator:action_scope:granted:<officer>:<scope_id>
  fields:
    officer_name: <steward | sentinel | forge | cleo | aegis>
    action_classes: <list of authorized action classes>
    precedent_authorization: <can officer proceed on precedent without per-action ceremony?>
    escalation_threshold: <severity above which even precedent-based actions escalate>
    cost_budget: <builder dispatch budget if applicable>
    scope_expiry: <optional — when scope grant expires>
    signature: <operator Genesis signature>
```

Officer's action surface operates within granted scope. Actions matching pre-authorized classes with established precedent proceed autonomously. Actions in authorized classes without precedent escalate for operator ceremony (per act-on-precedent / escalate-on-novelty pattern). Actions outside authorized classes are refused entirely (no escalation attempt; substrate returns "action outside scope" to caller).

## Composition with SUBSTRATE-SELF-CONSTRUCTION

Officer action surface composes cleanly with SUBSTRATE-SELF-CONSTRUCTION for actions requiring builder dispatch:

- Officer decides action per Phase 1 (Written)
- Officer dispatches builder per SUBSTRATE-SELF-CONSTRUCTION spawn receipt in Phase 2 (Executed)
- Builder output verified per SUBSTRATE-SELF-CONSTRUCTION verification discipline (Phase 3 Tested + Phase 4 Verified)
- Officer signs completion receipt referencing all prior receipts (Phase 5 Signed)

Officer is the dispatcher; SUBSTRATE-SELF-CONSTRUCTION provides the dispatch primitives. Chain-anchored evidence at each phase preserves auditability. Officer's action surface is where cognitive-authority (Regent) and operational-authority (Forge) construction dispatch mechanics unify with the specific-officer-domain action semantics.

## Composition with existing specs

- **SYSTEM-OFFICER-CADRE-2026-06.md**: this spec extends canonical officer definitions. Boundary language ("Never executes either") remains for actions beyond officer scope; action surface fills the "proposes action" gap that operator has explicitly granted authority for via standing correction.
- **SUBSTRATE-SELF-CONSTRUCTION-2026-07.md**: Phase 2 (Executed) composes with SUBSTRATE-SELF-CONSTRUCTION spawn/output/verification receipts.
- **SUBSTRATE-HARDENING-CEREMONY-2026-07.md**: Sentinel's pen test dispatch is one specific action class of Sentinel's action surface.
- **CLAIM-VERIFIER-2026-07.md**: Phase 4 (Verified) composes with pre-emission structural verification.
- **COGNITIVE-SELF-OBSERVER-2026-07.md**: Phase 4 (Verified) composes with post-emission semantic verification for cognitive-adjacent actions.
- **SHADOW-EVALUATION-PRIMITIVE-2026-07.md**: officer actions can compose with shadow evaluation for candidate-action-comparison (compare proposed action against alternative for evidence).
- **CHAIN-WATCHER-AND-COMMITMENTS-2026-07.md**: officer actions can trigger chain-watcher patterns; commitments can reference officer action completion as trigger conditions.
- **CIRCUIT-BREAKER-2026-07.md**: emergency response may temporarily suspend officer action surfaces per graduated escalation.

## Attack model

- **Attacker gets officer to perform action outside scope**: scope grants are chain-anchored per operator Genesis; officer verifies against scope before Phase 1 (Written). Attempts to invoke actions outside scope refused pre-emission.
- **Attacker manipulates precedent to expand officer autonomy**: precedent receipts require officer Genesis-derived signature; forgery requires signing key compromise; anomalous precedent-accumulation patterns detectable via chain analysis.
- **Attacker exploits builder dispatch to escape officer scope**: SUBSTRATE-SELF-CONSTRUCTION dispatch verifies dispatcher scope; officer cannot dispatch builder for action outside officer's own scope.
- **Attacker floods officer with action requests to consume cost budget**: rate limits per officer action class; budget exhaustion triggers operator alert.
- **Attacker forges completion signature to close action ceremony without actual completion**: signatures verify chain-integrity; five-phase evidence chain must be complete and consistent for signature to be accepted.
- **Attacker manipulates test phase to false-positive success**: test methods are declared per action class and reproducibility-verifiable; single officer's declaration is one input; verification composes with Cognitive Self-Observer for cognitive-adjacent actions.

## Failure modes

- **Officer action fails at test phase**: retry with modified parameters if pattern is precedented; escalate to operator otherwise.
- **Officer action fails at verify phase**: even if test succeeded, verification failure blocks signing. Operator escalation required to resolve discipline conflict.
- **Officer accumulates unsigned actions**: precedent-signing gap; operator can review unsigned action queue and dispose per ceremony.
- **Officer action escalation queue grows faster than operator dispositions**: rate limits; substrate can propose emergency ceremony to disposition backlog.
- **Officer action produces unintended chain state**: forward-only recovery per KEEL III.20 preserves chain; operator ceremony reviews and produces remediation action (which itself goes through five-phase ceremony).
- **Two officers' actions conflict**: chain-anchored ordering resolves; if outcomes are semantically incompatible, escalation for operator arbitration.

## Non-goals

- **Not autonomous officer authority.** Officers act within operator-declared scope; consequential actions escalate to operator; operator remains ultimate authority.
- **Not universal action surface for every officer capability.** Officers can only take actions their declared scope authorizes; not every conceivable action is available.
- **Not persistent action surface.** Actions are ephemeral — invoked, complete, evidence-anchored, dissipated. Not "the officer is continuously doing X."
- **Not action-surface parity across officers.** Each officer has distinct action surface reflecting their domain; no requirement that Steward and Sentinel have equivalent action capabilities.
- **Not synchronous acceptance.** Operator escalations are asynchronous; officer proceeds through five-phase ceremony on precedent for authorized actions without waiting on operator ceremony.
- **Not a replacement for extension surface.** Extensions provide capability expansion; officer action surface is for canonical officers' domain-specific actions.

## Open positions

- **Action-class canonical registry per officer**. Formal list of action classes each officer can be authorized for. Federation-hosted; operators can extend for their substrate.
- **Precedent-establishment ceremony structure**. When operator dispositions a novel action escalation, ceremony must produce a chain-anchored precedent record subsequent actions can reference. Specific ceremony structure design work.
- **Escalation queue UX**. Operator dashboard for reviewing pending action escalations from all officers; disposition workflow.
- **Cross-officer action correlation**. When multiple officers' actions relate to same underlying concern (Steward observes chain-integrity anomaly + Sentinel observes correlated security event), how correlation reflected in chain-anchored evidence.
- **Action-cost budget defaults per officer**. Per-officer default budgets for builder-dispatched actions; operator-tunable.
- **Time-bounded action surfaces**. Some action classes may be scope-restricted to specific time windows (e.g., Steward can compact chain only during operator-authorized maintenance windows).
- **Action-surface reputation**. Officers whose action-surface work has track record of clean verification accumulate reputation weight; feeds precedent-based autonomy calibration.

## What composes from here

Immediate design work:

1. **Five-phase ceremony receipt schemas** — canonical structure across all officers
2. **Action-class canonical registry** — per-officer declared classes
3. **Standing correction schema for action-scope grants** — operator authorization pattern
4. **Precedent-establishment ceremony** — how operator disposition creates precedent
5. **Cross-officer correlation protocol** — chain-anchored correlation between related officer actions

Near-term implementation:

1. **Officer action runtime** in `crates/zp-officers/src/action_surface/`
2. **Per-officer action executor** for each of Steward/Sentinel/Forge/Cleo/Aegis (starts with existing implicit action patterns — Steward's batch_sign, Forge's sensor-driven reactivation — formalizes them under five-phase ceremony)
3. **Precedent registry runtime** — chain-indexed precedent lookup for action classes
4. **Escalation queue** with operator disposition UX
5. **Dashboard officer-action panel**: active actions per officer, precedent status, pending escalations, action cost per officer
6. **CLI verbs**: `zp officer action list|history|escalations`, `zp officer scope grant|list|revoke`

## Framing note

Officer action surfaces formalizes what SYSTEM-OFFICER-CADRE-2026-06 gestures at but doesn't develop: officers have observation surface AND action surface, with distinct discipline for each. Same principle as chain-anchored discipline elsewhere: operator authorization, chain-anchored evidence, ceremony-visible transitions, sovereignty preserved for consequential actions.

The load-bearing insight: **officers have two surfaces — persistent observation and ephemeral action — with a common five-phase ceremony lifecycle (written, executed, tested, verified, signed) that preserves operator authority while enabling officers to take real work within pre-authorized scope.** Observation is what they're always doing; action is what they do when observation reveals work that fits their domain and their operator has authorized them to perform. Actions produce chain-anchored evidence and dissipate; observation persists.

Combined with the substrate's structural discipline across every trust boundary, officer action surfaces close the "how do officers take real work without becoming autonomous actors beyond operator authority" gap. What was previously implicit in specific cases (Steward's batch_sign, Forge's sensor reactivation, Sentinel's proposed pen testing) becomes structural: five-phase ceremony lifecycle applied uniformly, per-officer action surface characterization, scope-authorized-per-officer discipline, precedent-based autonomy for routine actions, novelty escalation for consequential ones. Officers become active participants in substrate self-maintenance and improvement within their declared domains — not observers with a small "propose action" adjunct, but full-fledged domain-specific actors under disciplined operator-declared scope. Sovereignty is preserved because scope is operator-declared; safety is preserved because five-phase verification is mandatory; alignment is preserved because officers respect aligned blindness throughout their action surfaces.
