# Shadow Evaluation Primitive

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.5 (Genesis-derived signing), §II.17 (cognitive discipline sandwich), §III.19 (detectability over invulnerability), §III.20 (forward-only recovery), §III.22 (verify before commit), Part VIII (bounded operator sovereignty). Specifies the substrate's general shadow-evaluation primitive: parallel candidate-vs-control evaluation with chain-anchored comparison evidence, generalized from shadow-inference into a system-wide discipline. Canonical claims live in KEEL.

Draft — 2026-07-11 — internal audience only. Composes with `SHADOW-INFERENCE-COMPARISON-2026-07.md` (specialization for inference paths), `EMPIRICAL-PROGRAM-2026-07.md` (this primitive is the runtime mechanism for continuous empirical program), and every substrate spec that declares an operator-configurable policy — including OBSERVATION-PLANE, CIRCUIT-BREAKER, CHAIN-WATCHER-AND-COMMITMENTS, COGNITIVE-INPUT-PLANE, EXTENSION-SURFACE, SOVEREIGN-KINSHIP-PRIMITIVES.

## Framing

The substrate has many policy surfaces where the operator has declared a current way of doing X and could benefit — over time — from evidence about whether a candidate way would produce better outcomes on the same inputs. Which model serves Regent's cognition. Which threshold triggers Sentinel's escalation. Which pattern the chain-watcher fires on. Which cadence beacons emit at. Which weighting the cognitive input plane uses. Which extension configuration governs a capability. Which scope grant policy shapes a kinship. Every one of these is a decision the operator made, chain-anchored via ceremony, that could — as substrate use accumulates history — be re-informed by chain-anchored evidence.

Shadow-inference comparison (per SHADOW-INFERENCE-COMPARISON-2026-07.md) established the shape for one class: comparing a candidate model's response against a control model's response on the same query. The mechanism generalizes cleanly to every policy surface in the substrate. **Shadow evaluation** is the general primitive: dispatch candidate-vs-control against the same input, chain-anchor the comparison, accumulate evidence over time, inform the operator's next ceremony change with chain-anchored data rather than intuition alone.

Three properties frame the primitive:

1. **Evidence-based ceremony, not automated policy change.** Substrate accumulates chain-anchored comparative evidence; operator ceremony changes policies. Substrate does not autonomously update policies based on shadow evidence. Chain-anchored evidence informs operator judgment; it does not replace it.
2. **Operator-declared triggers, per-policy-surface.** Substrate does not shadow-evaluate every decision by default. Operator declares which policy surfaces run shadow evaluation, at what sampling rate, against what controls, with what budget.
3. **Cost-budgeted per surface, chain-anchored per invocation.** Shadow evaluation is expensive across surfaces the same way it's expensive in inference. Operator declares budgets per surface; substrate operates within them; budget events chain-anchored, never silent.

## The seven canonical shadow-evaluation contexts

Each substrate policy surface where shadow evaluation applies naturally. Shadow-inference comparison is context 1; the others follow the same primitive shape.

### Context 1 — Inference paths (specialized in SHADOW-INFERENCE-COMPARISON)

Candidate: novel model, drift-suspected model, alternate model in envelope, judge model.
Control: operator's pinned model, dossiered high-confidence model, prior known-good snapshot.
Input: the operator's or Regent's actual query.
Evidence: response comparison at graduated levels (structural / embedding / judge / operator).
Consumer: INFERENCE-ROUTING-DISCIPLINE, EXECUTION-AUTHORITY-MODEL Phase 5 empirical program.

Fully specified in SHADOW-INFERENCE-COMPARISON.

### Context 2 — Officer thresholds and configurations

Candidate: Sentinel with candidate threshold X (proposed by operator ceremony or by empirical proposal).
Control: Sentinel with current threshold (operator's declared).
Input: chain events, listener observations, credential-drift signals.
Evidence: comparison of finding sets — same events produce more/fewer/different findings under X vs current.
Consumer: SYSTEM-OFFICER-CADRE, operator ceremony for threshold recalibration.

Concrete case emerging today: Sentinel's `unauthorized_listener` classification produces high false-positive rates on user machines with normal application populations. Shadow evaluation would compare current classifier against a candidate classifier that recognizes known operator-application classes. Evidence accumulates over time; operator ceremony updates the threshold with confidence.

### Context 3 — Chain-watcher patterns

Candidate: chain-watcher with pattern P' (broader / narrower / differently-scoped).
Control: chain-watcher with current pattern P.
Input: live chain event stream.
Evidence: detection-rate comparison, false-positive-rate comparison, latency to fire.
Consumer: CHAIN-WATCHER-AND-COMMITMENTS, operator ceremony for pattern refinement.

Useful for tuning chain-watcher patterns as substrate usage evolves — patterns that made sense at initial deployment may drift out of match as event schemas change or new receipt types are added.

### Context 4 — Circuit breaker thresholds and escalation ladders

Candidate: alternate escalation ladder (faster / slower, broader / narrower scopes).
Control: current escalation ladder per operator declaration.
Input: real substrate incident traces (from chain history) or synthetic scenarios.
Evidence: comparison of recovery time, cascade scope, false-trip rate, missed-genuine-emergency rate.
Consumer: CIRCUIT-BREAKER-2026-07.md, operator ceremony for ladder recalibration.

High-stakes context: circuit breaker changes touch emergency response. Shadow evaluation on historical incidents is safer than shadow evaluation on live incidents; both are chain-anchored evidence for operator judgment on the ladder shape.

### Context 5 — Cognitive input plane weightings

Candidate: alternate Tier-1/2/3/4 weighting scheme.
Control: current Cognitive Input Plane assembly per operator's declared matrix.
Input: Regent's cognitive cycles as they occur.
Evidence: Cognitive Self-Observer's post-emission verification results across both weightings.
Consumer: COGNITIVE-INPUT-PLANE-2026-07.md, operator ceremony for matrix refinement.

Tied directly to Task #69 — as standing correction discipline gets wired up, shadow evaluation can compare Regent's outputs under different weighting schemes to inform matrix tuning.

### Context 6 — Extension configurations

Candidate: extension version B, or extension A with configuration variant.
Control: extension A with current configuration.
Input: capability invocations as they occur.
Evidence: capability-outcome comparison per extension protocol.
Consumer: EXTENSION-SURFACE-2026-07.md, QUARANTINE-PLANE-2026-07.md admission ceremony extensions.

Same query, same context, both extensions execute; compared outputs inform operator on extension-version upgrade ceremonies without needing extensive standalone empirical program studies.

### Context 7 — Kinship coordination policies

Candidate: alternate grant configuration for a kindred sovereign (broader / narrower per-scope).
Control: current grant configuration.
Input: coordination events (household presence, safety check-ins, commitment coordination).
Evidence: coordination-effectiveness comparison — same events surface differently under different grants.
Consumer: SOVEREIGN-KINSHIP-PRIMITIVES-2026-07.md, operator ceremony for grant refinement.

Useful for households and multi-kindred relationships: does adding `mood_signals` to a specific kinship improve coordination or add friction? Chain-anchored evidence over time answers.

## Common ceremony pattern

Every shadow-evaluation context follows the same ceremony shape, adapted to the surface's specifics.

### Phase A — Policy candidate declaration

Operator declares a candidate policy variant for a specific surface via chain-anchored ceremony:

- Candidate identity (candidate model, candidate threshold, candidate pattern, etc.)
- Comparison target (control identity)
- Trigger conditions (which events invoke the shadow evaluation)
- Comparison protocol (context-specific structural / semantic / behavioral comparison)
- Disposition mode (evaluate-only / advise-operator / substitute-on-clear-win / never-substitute)
- Cost budget
- Evaluation window (how long to accumulate evidence before proposing operator decision)

Receipt: `substrate:shadow_evaluation:candidate_declared:<surface>:<candidate_id>`.

### Phase B — Trigger firing

Substrate operations proceeding as normal; when a trigger condition matches, substrate additionally dispatches the candidate policy against the same input.

Receipt: `substrate:shadow_evaluation:triggered:<candidate_id>:<invocation_id>`.

### Phase C — Comparison and evidence accumulation

Substrate compares candidate outcome to control outcome using context-specific comparison protocol. Evidence chain-anchored.

Receipt: `substrate:shadow_evaluation:comparison:<invocation_id>` with agreement / divergence classification and quantitative evidence.

### Phase D — Evaluation window closes

At end of declared evaluation window (time-based, sample-count-based, or operator-triggered), substrate assembles the accumulated evidence into a proposal.

Receipt: `substrate:shadow_evaluation:proposal_ready:<candidate_id>` with:
- Summary statistics
- Per-outcome distribution
- Anomalous cases surfaced individually
- Recommended disposition per operator's declared preference framework
- Cost accounting

### Phase E — Operator disposition ceremony

Operator reviews the proposal and dispositions via ceremony:

- **Adopt**: candidate becomes the new policy via standard operator-ceremony (kinship scope update, threshold change, extension upgrade, etc.). Ceremony chain-anchored per surface's existing spec.
- **Reject**: candidate discarded; control remains authoritative.
- **Extend evaluation**: evidence insufficient; window extends with new budget.
- **Modify candidate**: candidate revised and evaluated in new cycle.

Receipt: `substrate:shadow_evaluation:disposition:<candidate_id>:<action>`.

## Cost budget across contexts

Shadow evaluation is expensive across every context; costs compound if multiple contexts have active evaluations. Operator declares budgets:

- **Per-context caps**: distinct budgets per policy surface (inference shadow may deserve more budget than kinship shadow)
- **Global cross-context cap**: total substrate shadow-evaluation spend across all contexts
- **Emergency budget**: reserved allocation for recovery-mode evaluations (Trigger 5 from SHADOW-INFERENCE-COMPARISON extended across all contexts)
- **Overflow policy**: as with shadow-inference — suspend / reduce / emergency-only / operator alert

Budget accounting is chain-anchored per invocation across contexts. Dashboard surfaces shadow-evaluation spend by context for operator's total-picture awareness.

## Chain-anchored evidence discipline

Every shadow-evaluation invocation produces the same receipt family as SHADOW-INFERENCE-COMPARISON, generalized:

- Invocation receipt: what triggered, what candidate ran, what control ran
- Outcome receipts: per-target results (may be structured or unstructured depending on surface)
- Comparison receipt: agreement classification, quantitative comparison
- Disposition receipt: what substrate did with the comparison (shadow / substitute / etc.)
- Budget receipt: cost accounting per invocation

Same chain-visibility discipline. Full evidence trail per candidate lifecycle. Operator can reconstruct why a policy changed (or didn't) by walking the chain.

## Not universal metric collection

Critical distinction: shadow evaluation is not the substrate's equivalent of universal telemetry, always-on A/B testing, or continuous silent experimentation on the operator.

- **Operator declares triggers.** Substrate does not evaluate policies the operator has not declared candidates for. Silent widespread evaluation would violate coordination-not-oversight (KEEL III.23) and would consume operator's budget without their authorization.
- **Substrate does not autonomously change policies.** Evidence informs operator ceremony changes; substrate never substitutes candidate for control without operator disposition ceremony.
- **Substrate is not competitive with operator preference.** Operator may reject a candidate that shows quantitative improvement because they prefer the current policy for reasons beyond the substrate's evaluation. Substrate accepts operator judgment as authoritative.
- **Chain-anchored evidence, not opaque metrics.** No off-chain telemetry pipeline. All evidence is chain-visible and auditable by operator and operator-authorized reviewers.
- **Cost-budgeted, not free.** Evaluation costs are visible and constrained. Runaway experimentation is structurally impossible under budget discipline.

## Composition with existing specs

- **SHADOW-INFERENCE-COMPARISON-2026-07.md**: Context 1 specialization. This spec generalizes the pattern; SHADOW-INFERENCE-COMPARISON specifies inference-specific mechanics.
- **EMPIRICAL-PROGRAM-2026-07.md**: this primitive is the runtime mechanism for continuous empirical program. The empirical program's investigations map to shadow-evaluation candidates; empirical findings map to chain-anchored comparison evidence. Punctuated investigations become continuous calibration.
- **QUARANTINE-PLANE-2026-07.md**: extension version upgrades (Context 6) run shadow evaluation as part of admission evidence; comparison-outcome contributes to operator's admission decision.
- **COGNITIVE-SELF-OBSERVER-2026-07.md**: post-emission verification is a comparison mechanism structurally similar to shadow evaluation — verifying claim against ground truth. Cognitive Self-Observer's verification receipts and shadow-evaluation comparison receipts share receipt structure.
- **CIRCUIT-BREAKER-2026-07.md**: Context 4 uses shadow evaluation on historical incident traces to inform escalation-ladder ceremony changes. Live-incident shadow evaluation authorized only for recovery-mode verification (Trigger 5 from SHADOW-INFERENCE-COMPARISON extended).
- **CloudMandate**: cross-context budget composes with CloudMandate spending discipline.

## Attack model

- **Attacker declares candidate designed to disadvantage control**: candidate declaration is operator ceremony. Attacker cannot declare candidates without operator Genesis signature.
- **Attacker manipulates comparison evidence via biased trigger sampling**: trigger conditions are operator-declared. Attacker cannot skew triggers without operator ceremony.
- **Attacker exhausts operator budget across contexts to reduce shadow discipline**: rate-limits per context, global cap discipline, operator alert on approach to budget.
- **Attacker corrupts comparison logic**: comparison logic is substrate-side per operator envelope. Substrate compromise is broader concern, handled by Genesis rotation.
- **Attacker exploits evaluation window timing to force disposition before adequate evidence**: window duration is operator-declared. Attacker cannot shorten windows without operator ceremony.
- **Attacker uses shadow evaluation as covert channel to influence Regent cognition**: evaluation candidates that touch cognitive layer (Contexts 1, 5) are Cognitive Self-Observer-verified for scope compliance. Cross-context evaluation isolation.
- **Attacker manipulates operator's disposition ceremony via biased proposal presentation**: proposal contents are chain-anchored; operator can review raw evidence bypassing substrate summary; operator judgment remains authoritative.

## Failure modes

- **Comparison protocol unavailable for a context**: substrate cannot fire shadow evaluation. Emits `substrate:shadow_evaluation:protocol_missing:<surface>` receipt. Operator can define candidate-specific comparison logic or accept that surface has no shadow discipline.
- **Evaluation window closes with insufficient sample count**: proposal ready but confidence marked low. Operator can extend window or accept low-confidence disposition.
- **Candidate and control diverge but neither is clearly better**: proposal surfaces ambiguity; operator dispositions per their own judgment. Chain-anchored ambiguity indicates the policy surface may benefit from more evaluation dimensions.
- **Cross-context budget exhaustion**: overflow policy applies. Some contexts may suspend before others per operator-declared priority.
- **Candidate has emergent bad behavior (e.g., candidate model exhibits confabulation not shown in control)**: high-divergence comparisons flag; operator sees the pattern; disposition ceremony may reject candidate for cause with chain-anchored rationale.
- **Substrate's shadow evaluation impacts substrate performance**: evaluations run in parallel with primary operations; if evaluation load impacts substrate responsiveness, operator sees latency evidence and can adjust budgets or triggers.

## Non-goals

- **Not universal A/B testing.** Substrate does not run experiments the operator has not declared.
- **Not automatic policy optimization.** Substrate does not autonomously replace policies based on evidence. Evidence informs operator ceremony.
- **Not competitive with operator preference.** Operator may reject quantitatively-preferred candidates for their own reasons; substrate accepts.
- **Not opaque telemetry.** All shadow-evaluation activity is chain-visible.
- **Not free evaluation.** Every evaluation costs operator budget; discipline enforces awareness of the cost.
- **Not attacker-proof against combined compromise.** If attacker compromises candidate declaration + comparison logic + operator disposition ceremony simultaneously, the substrate cannot detect. Individual defenses layer to raise attacker cost.

## Open positions

- **Cross-context evidence composition**. When candidate policies interact across contexts (e.g., candidate model + candidate cognitive input plane weighting), how does shadow evaluation compose?
- **Historical replay vs live triggering**. Some contexts (Circuit Breaker on real incidents) benefit from historical replay. Which contexts support replay evaluation?
- **Candidate-of-candidate evaluation**. Nested shadow evaluations (evaluating one candidate against another candidate rather than the current control). Bounded to prevent recursion.
- **Evidence-standard calibration per context**. What counts as "sufficient evidence" for a policy change varies by context. Circuit breaker changes need higher evidence bar than beacon cadence changes.
- **Cross-operator evidence pooling**. Multiple operators running the same candidate could pool evidence via reproducibility ceremony. Trade-offs on evidence quality vs operator sovereignty.
- **Operator-preference framework**. Each context needs an operator-preference schema for how to weight comparison outcomes. Design work per context.
- **Extension-declared shadow-evaluation contexts**. Extensions may declare new policy surfaces that support shadow evaluation. Registry via extension surface capability declarations.

## What composes from here

Immediate design work:

1. **Common receipt schemas** across contexts — invocation, outcome, comparison, disposition, budget
2. **Comparison-protocol registry** — per-context comparison logic declarations
3. **Candidate-declaration schemas per context** — extending each spec's existing ceremony schemas
4. **Cross-context budget accounting** — dashboard, alert, overflow discipline

Near-term implementation:

1. Shadow-evaluation runtime as `crates/zp-substrate/src/shadow_eval/` — generalized dispatch layer
2. Per-context adapter implementations (starting with the six non-inference contexts; SHADOW-INFERENCE-COMPARISON's runtime is one adapter)
3. Comparison-protocol interface with pluggable per-context implementations
4. Chain-anchored evidence emitters
5. Dashboard shadow-evaluation panel: active candidates across contexts, recent invocations, evidence summaries, budget status
6. CLI verbs: `zp shadow-eval candidate declare|status|history|dispose`

## Framing note

Shadow-evaluation primitive names what shadow-inference comparison already demonstrated in one context, generalized across the substrate. Same principle as chain-anchored discipline elsewhere: operator-declared triggers, chain-anchored evidence, ceremony-visible dispositions, cost-budgeted, sovereignty preserved.

The load-bearing insight: **the substrate learns not by trusting its own judgment about what works, but by continuously comparing candidate policies against controls and accumulating chain-anchored evidence that informs operator ceremony.** This is evidence-based substrate improvement — distinct from automated optimization (which cedes authority) and distinct from ceremony-without-evidence (which leaves operator guessing). Substrate provides evidence; operator provides judgment; ceremony enacts change.

Combined with the substrate's structural discipline across every trust boundary, shadow evaluation completes the improvement envelope. What was previously implicit — "we made this decision at some point and we could probably do better if we knew more" — becomes structural: candidates declared, evidence accumulated, dispositions ceremony-visible, cost budgeted. Sovereignty is preserved because operator authorizes every candidate and dispositions every proposal. Safety is preserved because evidence is chain-visible and auditable. Continuity is preserved because the substrate's policy history is chain-anchored evidence trail, so future operator judgments compose with past reasoning rather than starting from zero.

The empirical program becomes continuous rather than punctuated. Substrate improvement becomes evidence-based ceremony rather than intuition-driven ceremony or vendor-decreed update. Trust in the substrate deepens over time not through the substrate proving itself but through the substrate transparently accumulating and surfacing the evidence that lets the operator prove it for themselves.
