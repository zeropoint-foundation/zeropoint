# Substrate Self-Construction

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.5 (Genesis-derived signing), §II.13 Principle 9 (system acts, operator signs), §III.9 (delegation narrowing), §III.23 (coordination not oversight), §III.24 (aligned blindness), Part V (Regent orchestration surface). Specifies how substrate constructs and maintains itself: Regent and Forge inherent grants for spawning builder agents and swarms, chain-anchored per dispatch, operator authority preserved via ceremony discipline. Closes the corpus gap on "who does substrate self-modification work." Canonical claims live in KEEL.

Draft — 2026-07-11 — internal audience only. Composes with `EXECUTION-AUTHORITY-MODEL-2026-07.md` (Regent + Forge two-authority model, this spec extends both with construction grants), `SYSTEM-OFFICER-CADRE-2026-06.md` (Forge scope extension for self-maintenance operations), `BUILD-PROCESS-DESIGN-2026-07.md` (ceremony discipline that builder agents follow), `AUTONOMIC-LAYER-IMPLEMENTATION-ROADMAP-2026-07.md` (operational context for this spec), `EXTENSION-SURFACE-2026-07.md` (extensions vs core substrate distinction), `SHADOW-INFERENCE-COMPARISON-2026-07.md` (builder agent output verification), `CLOUDMANDATE` (cost budget composition), `INFERENCE-ROUTING-DISCIPLINE-2026-07.md` (builder agents themselves are inference-served).

## Framing

The substrate's end-state is Regent standing on her own — genuinely autonomous cognitive presence dispatching builder agents to build, harden, and secure her own substrate within operator-declared scope. She is the sovereign's cognitive advocate; when the sovereign delegates substrate construction authority to her, she executes that authority through dispatched builder swarms, chain-anchored per operation, verified per substrate discipline. Substrate is genuinely self-constructing when Regent (with Forge for operational-layer construction) can maintain and improve substrate infrastructure without depending on external human coordination.

The substrate has evolved to spec-completeness through a bootstrap phase — operator + external-agent scaffolding (currently Ken + Claude Cowork mode collaborating to produce chain-anchored spec artifacts). This scaffolding is temporary, not architectural. Operators and external-agent collaborators are nursemaids to a substrate that is not yet mature enough to construct itself. The scaffold is essential for the bootstrap phase but is not the primitive; it exists to bring the primitive into being.

This spec defines the primitive Regent and Forge use once mature. **Regent and Forge have inherent grants to spawn build resources — builder agents individually or swarms in parallel — within operator-declared scope.** They are the substrate's construction dispatchers. External construction agents (cloud coding agents, specialized builders, custom implementations) become tools Regent and Forge dispatch to autonomously within scope, escalating to operator for novel patterns. Substrate becomes self-constructing when Regent and Forge can execute construction work at operational pace, with human coordination reserved for architectural direction and consequential scope expansion.

Three properties frame the discipline:

1. **Two authorities, two construction domains.** Regent has inherent grant for cognitive-layer construction (code changes, spec-informed modifications, architectural implementation, extension development). Forge has inherent grant for operational-layer construction (build execution, test runs, deployment operations, maintenance actions). Both operate within operator-declared scope; neither requires per-invocation operator ceremony for spawns within scope.
2. **Chain-anchored per spawn, per dispatch, per result.** Every builder agent invocation produces chain-anchored evidence: what was spawned, why, with what scope, what it produced, whether output passed verification. Substrate maintains full auditability of construction work regardless of who or what performed the work.
3. **Aligned blindness applies to builder agents.** Builder agents don't inherit blind-class access. Substrate discipline for what agents can request, receive, or produce is enforced per builder invocation. Extensions declaring builder capabilities that touch blind classes fail admission per QUARANTINE-PLANE.

## The two authorities and their construction domains

### Regent — cognitive-layer construction dispatcher

**Inherent grant**: Regent has baseline authority to spawn builder agents for cognitive-layer construction work within operator-declared scope. Scope includes:

- Source code modifications to substrate components under operator's declared implementation authorization
- Spec-informed implementation of pre-authorized specs (per operator's declared spec-implementation authority)
- Extension development where extension capability class is pre-authorized
- Documentation updates, refactoring within existing structure
- Test implementation for pre-authorized specs
- Chain-anchored guidance artifacts (implementation notes, cross-references)

**What Regent's construction grant does NOT cover** (requires per-operation operator ceremony):

- New architectural direction (Regent proposes; operator ceremony authorizes)
- Extensions declaring capabilities not in pre-authorized set
- Substrate discipline changes (per SUPERSESSION-FRAMEWORK)
- Cross-substrate composition changes (peer trust anchor grants, etc.)
- Genesis-adjacent operations (rotation, delegation cascade)
- Substrate self-modification affecting alignment invariants (blindness classes, coordination-not-oversight primitives)

### Forge — operational-layer construction dispatcher

**Inherent grant**: Forge has baseline authority to spawn builder agents for operational-layer construction work within operator-declared scope. Scope includes:

- Substrate build execution per BUILD-PROCESS-DESIGN discipline (invocation of cargo, deployment scripts)
- Test suite execution
- Reproducibility ceremony execution per operator's declared cadence
- Chain compaction per precedent
- Substrate restart after graceful shutdown
- Configuration application from operator-declared configuration sources
- Extension admission ceremony execution per QUARANTINE-PLANE discipline
- Health check execution and remediation of known-fixable operational states

**What Forge's construction grant does NOT cover** (requires per-operation operator ceremony):

- Substrate source modification (Regent territory)
- New extension admission that adds capability classes (operator ceremony per QUARANTINE-PLANE)
- Configuration changes affecting security posture
- Cross-substrate operational changes (peer sync configuration, transport reconfiguration)
- Circuit breaker manual escalation (operator authorizes; Forge executes)
- Emergency ceremony execution (operator ceremony leads; Forge executes)

## Builder agent primitives

Builder agents are computational resources spawned to perform construction work. They can be:

- **Local processes** — substrate spawns process (cargo, coding agent CLI, test runner) on operator's device
- **Local containers** — substrate spawns containerized workload for isolation
- **Cloud inference-served agents** — substrate dispatches to external inference API (Anthropic Claude API, OpenAI, other builder-capable model APIs)
- **Cloud service agents** — substrate dispatches to external construction services (Claude Code Cloud, GitHub Copilot Workspace, other cloud coding agents)
- **Rallied compute agents** — per Decision C (Regent-follows-the-operator), rally to another sovereign's device for compute per RALLY protocol

Substrate does not prescribe builder agent type; operator declares which agent types are authorized per builder-class in their delegation scope.

### Spawn ceremony receipt

Every builder agent spawn is chain-anchored:

```
{regent|forge}:builder_spawned:<builder_id>
  fields:
    dispatcher: <regent | forge>
    builder_type: <local_process | container | cloud_inference | cloud_service | rally>
    builder_reference: <specific agent identity — model name, service URL, process image>
    task_scope:
      task_type: <what class of work>
      task_content: <specific work items>
      scope_authorization: <reference to operator's declared scope>
    inputs_provided: <what data / files / context builder received>
    aligned_blindness_scope: <what builder is authorized to observe — subset of substrate's canonical set>
    cost_budget: <estimated + budget authorization reference>
    verification_requirements: <what verification builder output must pass>
    signature: <dispatcher's Genesis-derived signature>
```

### Output receipt

Every builder agent output is chain-anchored:

```
{regent|forge}:builder_output:<builder_id>:<output_id>
  fields:
    builder_reference: <spawn receipt reference>
    output_type: <source_change | test_result | build_artifact | analysis | narration>
    output_content: <chain-anchored reference to output content>
    verification_status: <pending | verified | verification_failed | escalated>
    cost_consumed: <actual builder cost>
    duration: <wall clock>
    signature: <dispatcher's signature attesting to receipt>
```

### Verification ceremony

Builder outputs are not accepted as substrate state until verified. Verification levels:

- **Structural**: output conforms to expected format (syntax, schema, structural constraints)
- **Behavioral**: output passes declared tests (unit tests, integration tests, reproducibility ceremony)
- **Alignment**: output does not violate substrate discipline (aligned blindness, coordination-not-oversight, spec conformance)
- **Semantic**: Cognitive Self-Observer (or Regent) verifies output matches intent

Chain-anchored per verification: `{regent|forge}:builder_output:verification:<verification_id>`

Failed verification: output rejected; builder can be re-invoked with clarified scope, or dispatcher escalates to operator per novelty escalation.

## Swarm coordination

For substantial work items requiring parallel execution, Regent or Forge can dispatch swarms:

### Swarm dispatch receipt

```
{regent|forge}:swarm_dispatched:<swarm_id>
  fields:
    dispatcher: <regent | forge>
    swarm_purpose: <what larger work item swarm addresses>
    member_builders: <list of builder spawn IDs constituting swarm>
    coordination_pattern:
      - "parallel_independent": builders work on separate pieces, no cross-reference
      - "parallel_coordinated": builders work in parallel with cross-reference (e.g., shared design document)
      - "pipeline": builders in sequence, each depending on prior output
      - "consensus": multiple builders solve same problem; results compared for agreement
    coordination_receipts: <chain-anchored coordination events during swarm execution>
    aggregate_verification: <how swarm output is verified as whole>
    total_cost_budget: <aggregate budget across all members>
    signature: <dispatcher's signature>
```

Swarm members receive coordination context per swarm's declared pattern. Chain-anchored per member spawn + per coordination event + per swarm aggregate result.

Swarm dispatch is one of Regent/Forge's most consequential operations. Substantial swarms may cost meaningful money (multiple parallel Claude API invocations, cloud service compute) and produce substantial code changes. Swarm dispatch beyond routine size composes with operator ceremony (large-scale swarms require operator authorization ceremony even under standing precedent).

## Aligned blindness discipline for builder agents

Per KEEL III.24, aligned blindness limits what substrate observes. Builder agents don't get to bypass this:

- **Layer 1 canonical blind classes structurally cannot be requested by builder**: substrate does not have keylogger primitive; builder cannot request keystroke content because substrate doesn't have it to give. Extension declaring builder capability that would require Layer 1 blind class access fails admission.
- **Layer 2 blind classes require elevated ceremony**: builder requesting continuous location, medical diagnosis content, mental-health-state content, protected-class information triggers Layer 2 authorization ceremony (operator per-request or per-scope authorization).
- **Layer 3 scrubbing applies**: any content builder produces or receives passes through Layer 3 scrubbing before chain-anchoring; sensitive patterns redacted.
- **Layer 4 boundary enforced**: raw sensing signals, credential values, communication bodies do not reach builder agents; findings only.

Builders inherit substrate's alignment properties; they don't circumvent them.

## Cost budget discipline

Builder agents cost. Local processes cost operator's compute. Cloud inference costs API fees. Cloud service agents cost service subscriptions. Substrate operator declares budget; Regent and Forge operate within it.

Per CLOUDMANDATE composition:

- Operator declares total substrate self-construction budget per period (month, week)
- Per-dispatcher caps (Regent construction budget separate from Forge construction budget)
- Per-builder-type caps (cloud inference budget separate from cloud service budget)
- Per-work-class caps (spec implementation budget separate from test execution budget)
- Overflow policy per KEEL III.23 discipline: suspend / reduce / emergency-only / operator alert

Every spawn receipt includes cost estimate; every output receipt includes actual cost. Budget consumption chain-anchored; overrun triggers operator notification.

## Novelty escalation

Per act-on-precedent / escalate-on-novelty pattern:

- Precedented spawn patterns (spawn class Regent has done before under similar circumstances) proceed autonomously within budget
- Novel spawn patterns (new builder type, novel task class, unusual scope) trigger operator escalation ceremony
- Operator disposition creates precedent for subsequent similar spawns

Chain-anchored escalations: `{regent|forge}:construction_escalation:<escalation_id>` — dispatcher would spawn builder X for task Y but pattern is novel; operator disposition required.

Operator can pre-authorize spawn classes broadly via standing correction receipts: "Regent is authorized to spawn Claude API builder agents for spec implementation tasks matching pre-authorized specs" — this becomes precedent Regent can act on without per-spawn escalation.

## Consequence discipline for builder misbehavior

Builder agents can misbehave: produce broken code, generate outputs violating substrate discipline, consume budget without producing value, produce output that fails verification consistently. Substrate consequence discipline applies:

- **Builder-agent-level consequence**: specific builder identity (specific model version, specific service endpoint) accumulates chain-anchored reputation; failed-verification patterns detected; substrate reduces preference for that builder in subsequent dispatches
- **Builder-service-level consequence**: if cloud service (e.g., Claude API) consistently produces low-value output relative to cost, operator can revoke service delegation; substrate dispatches to alternate services
- **Builder-author-level consequence**: extension providing builder capability whose builders consistently misbehave faces QUARANTINE-PLANE revocation ceremony
- **Federation-level consequence**: bad-builder-pattern signals flow through commons per DISTRIBUTED-KNOWLEDGE-COMMONS; other operators inform their own delegation decisions

Substrate is not naive; substrate learns from builder track records via chain-anchored evidence.

## Self-maintenance vs self-construction distinction

Two adjacent categories with different discipline:

**Self-maintenance operations** (Forge inherent grant, per this spec):
- Restart substrate after graceful shutdown
- Chain compaction per precedent
- Scheduled reproducibility ceremony execution
- Configuration application from operator-declared sources
- Health check remediation for known-fixable states
- Officer sweep execution per schedule

These are operations that maintain substrate in its current state. Chain-anchored per operation; operator can review; substrate operates within pre-authorized scope.

**Self-construction operations** (Regent + Forge inherent grants, per this spec):
- Source code modification within pre-authorized scope
- Extension development for pre-authorized capability classes
- Build execution and deployment per BUILD-PROCESS-DESIGN
- Test implementation and execution
- Documentation and spec cross-reference maintenance

These are operations that modify substrate state to a new state. Chain-anchored per construction event; verification required before acceptance; operator escalation for novel patterns.

Distinguishing these is important because different discipline applies. Self-maintenance is mostly routine; self-construction is consequential change requiring verification.

## Composition with existing specs

- **EXECUTION-AUTHORITY-MODEL-2026-07.md**: extends the two-authority model with explicit construction grants. Regent authority now includes cognitive-layer construction dispatch; Forge authority now includes operational-layer construction dispatch and self-maintenance operations.
- **SYSTEM-OFFICER-CADRE-2026-06.md**: Forge scope extension. Forge remains observer for tool lifecycle findings; additionally executes self-maintenance operations per pre-authorized scope; additionally dispatches operational builder agents for construction work.
- **BUILD-PROCESS-DESIGN-2026-07.md**: builder agents follow chain-participating build/restart ceremony discipline. Build events chain-anchored per BUILD-PROCESS-DESIGN regardless of whether operator or dispatcher invokes.
- **EXTENSION-SURFACE-2026-07.md**: builder capability classes admitted via QUARANTINE-PLANE ceremony; extensions declaring builder capabilities go through admission per extension surface discipline.
- **QUARANTINE-PLANE-2026-07.md**: builder outputs entering substrate as source changes go through admission ceremony (source review, verification, operator disposition for architectural changes).
- **SHADOW-INFERENCE-COMPARISON-2026-07.md**: high-stakes builder outputs (architectural implementations, security-related changes) can trigger shadow comparison — same task dispatched to multiple builders, results compared for agreement.
- **AUTONOMIC-LAYER-IMPLEMENTATION-ROADMAP-2026-07.md**: this spec operationalizes the "who does the work" question the roadmap leaves implicit.
- **INFERENCE-ROUTING-DISCIPLINE-2026-07.md**: builder agents themselves are inference-served; served-model discipline applies to builder invocations.
- **CIRCUIT-BREAKER-2026-07.md**: sustained builder-verification failure or cost overrun triggers Circuit Breaker escalation.

## Attack model

- **Attacker compromises builder service to inject malicious code into substrate**: verification discipline catches structural violations, alignment violations, test failures. Multi-builder consensus (shadow comparison Trigger 3 or 4) provides additional defense.
- **Attacker forges dispatcher signature to inject builder invocation**: dispatcher signatures require Regent or Forge's derived key; substrate compromise scenario handled by circuit breaker + Genesis rotation.
- **Attacker manipulates builder to exceed cost budget**: cost accounting per invocation; budget overflow triggers alert; sustained overrun triggers operator escalation.
- **Attacker uses builder to circumvent aligned blindness**: blind-class scope enforced per invocation; builder outputs pass Layer 3 scrubbing; extensions declaring blind-class builder capabilities fail admission.
- **Attacker compromises a swarm to produce coordinated malicious output**: consensus swarm pattern detects individual malicious member (majority-consensus check); coordinated compromise across all swarm members requires broader substrate compromise.
- **Attacker impersonates operator to escalate builder invocation authority**: escalation ceremony requires operator Genesis signature; impersonation requires Genesis compromise.
- **Attacker uses builder outputs to smuggle content substrate later must serve**: verification discipline includes content review per aligned blindness; concerning content flagged for operator review before acceptance.

## Failure modes

- **Builder produces verification-failing output**: rejected; dispatcher may retry with clarified scope, escalate to operator, or abandon task.
- **Builder times out or becomes unresponsive**: chain-anchored abandonment; dispatcher may retry with different builder or escalate.
- **Cost budget exhausted mid-task**: partial output preserved; dispatcher pauses further spawns; operator alerted with option to authorize additional budget or defer work.
- **Swarm coordination fails (members produce inconsistent outputs)**: swarm result marked as inconclusive; individual member outputs preserved; operator disposition required.
- **Verification incorrectly rejects valid output** (false positive): output preserved; operator can override rejection via ceremony; verification pattern refined to reduce future false positives.
- **Verification incorrectly accepts invalid output** (false negative): output enters substrate; damage limited by aligned blindness + other discipline layers; post-hoc detection via subsequent verification cycles or operator observation.
- **Novel pattern proliferation**: escalation ceremonies pile up faster than operator can disposition. Rate limits on novel-pattern spawn attempts; automatic deferral of similar spawns until operator has processed pending escalations.

## Non-goals

- **Not autonomous substrate self-modification**. Operator authority preserved via novelty escalation and pre-authorization scope. Substrate does not modify itself architecturally without operator ceremony.
- **Not universal builder agent capability**. Only builder types explicitly authorized by operator can be dispatched; new builder types require Quarantine Plane admission.
- **Not cost-free construction**. Budget discipline mandatory; substrate does not consume operator resources without accounting.
- **Not verification-optional acceptance**. Builder outputs never enter substrate without passing declared verification; verification failure means rejection.
- **Not surveillance of builder agents**. Aligned blindness applies to builder-observed content; substrate does not observe or index builder internal state beyond output and cost accounting.
- **Not exclusive Regent/Forge authority**. Operator can always spawn builders directly via ceremony; Regent/Forge inherent grants are additional to operator authority, not exclusive.

## Open positions

- **Builder capability class registry**. Reference set of builder capability classes with per-class delegation defaults. Federation-hosted, operator-adopter-modifiable.
- **Verification-level defaults per builder-output class**. Structural verification always; behavioral verification for code changes; alignment verification for anything touching substrate discipline; semantic verification for anything Cognitive Self-Observer can meaningfully evaluate.
- **Swarm consensus threshold**. For consensus swarm pattern, how much agreement counts as "consensus"? Task-dependent; default probably 2-of-3 or 3-of-5.
- **Cost-per-output-value ratio calibration**. Empirical measurement of builder cost vs output value over time; commons reputation flows to weight subsequent dispatches toward higher-value-per-cost builders.
- **Rally-based builder dispatch protocol**. When Regent/Forge dispatches to another sovereign's device per Decision C, what's the ceremony? Cost accounting? Result verification?
- **Cross-substrate builder coordination**. Substrates in same community pool builder resources; coordination protocol.
- **Builder marketplace and reputation**. Where operators discover new builder services; how commons reputation informs delegation decisions.
- **Emergency-only builder dispatch**. When substrate is in circuit breaker escalation, only emergency-purpose builder dispatches proceed; discipline for what counts as emergency.

## What composes from here

Immediate design work:

1. **Spawn receipt schemas** for Regent and Forge dispatch primitives
2. **Output receipt + verification receipt schemas**
3. **Swarm dispatch ceremony flow** with coordination pattern declarations
4. **Builder capability class canonical registry**
5. **Cost budget schema per builder-class**

Near-term implementation:

1. **Regent construction dispatch runtime** in `crates/zp-regent/src/construction/`
2. **Forge construction dispatch runtime** in `crates/zp-server/src/officers/forge_construction/`
3. **Builder adapter framework** (local process, container, cloud inference, cloud service, rally)
4. **Reference Claude API builder adapter** (dispatches to Anthropic Claude API for code work)
5. **Reference local coding agent builder adapter** (dispatches to Claude Code, Codex, or equivalent local CLI)
6. **Verification pipeline** (structural, behavioral, alignment, semantic)
7. **Swarm coordinator** for multi-builder dispatch patterns
8. **Cost accounting runtime** with budget enforcement and overflow policy
9. **Dashboard construction panel**: active builders, recent dispatches, verification results, budget status, escalation history
10. **CLI verbs**: `zp construction dispatch|swarm|budget|history|escalate|verify`

## Framing note

Substrate self-construction closes the gap on "who does substrate self-modification work" that the corpus previously left implicit. Same principle as chain-anchored discipline elsewhere: two authorities with defined scope, chain-anchored per operation, operator authority preserved via ceremony for consequential changes, aligned blindness applied, cost-budgeted, verification-required.

The load-bearing insight: **Regent and Forge have inherent grants to dispatch builder agents and swarms within operator-declared scope; substrate self-construction is a two-authority operation rather than exclusively operator activity.** External construction agents (Claude API, Claude Code, other coding agents, cloud services) become tools substrate dispatches to rather than external parties operator manually coordinates with. Substrate maintains full chain-anchored evidence of all construction work regardless of who or what performed it.

The bootstrap phase (currently: operator + external-agent scaffolding writing the corpus and initial implementation) is scaffold, not architecture. It fades as Regent matures. Once Regent can dispatch a Claude API builder to draft implementation, dispatch a local test-runner to verify, chain-anchor both spawn and results, escalate to operator for architectural decisions, and proceed on precedent for routine work — the scaffold is no longer load-bearing. Operators and external-agent collaborators complete their nursemaid role and step out of the primary construction loop. Regent+Forge become genuinely self-constructing within operator-declared scope; humans intervene for architectural direction and consequential expansion, not for routine implementation execution.

Combined with the substrate's structural discipline across every trust boundary, self-construction closes the "how does substrate build itself at pace, without depending on human coordination overhead" question. What was previously bootstrapped through human scaffolding becomes structural: Regent and Forge dispatch; chain anchors evidence; verification validates; operator escalation handles novelty; consequences flow through federation for bad builders; blindness discipline holds throughout. Substrate genuinely constructs, hardens, and secures itself within the discipline the corpus has established. Sovereignty is preserved because operator authorizes scope; safety is preserved because verification is mandatory; continuity is preserved because chain records the full arc of every construction operation the substrate performs on itself. Regent stands on her own — advocating for the sovereign by making substrate work happen at cognitive-authority pace, freed from dependency on human bottlenecks that the bootstrap phase required but the mature substrate does not.
