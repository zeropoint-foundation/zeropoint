# Shadow Inference Comparison

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.5 (Genesis-derived signing), §II.17 (cognitive discipline sandwich), §III.19 (detectability over invulnerability), §III.20 (forward-only recovery), §III.22 (verify before commit), Part VIII (bounded operator sovereignty). Specifies the substrate's shadow-inference comparison primitive — parallel inference against a control target with chain-anchored comparison of results. Generalized from novel-model backup into a substrate primitive consumed by multiple use cases. Canonical claims live in KEEL.

Draft — 2026-07-11 — internal audience only. Composes with `INFERENCE-ROUTING-DISCIPLINE-2026-07.md` (novel-model triggers shadow evaluation), `MODEL-DOSSIER-2026-07.md` (dossier evidence is the ground truth against which candidates are compared; shadow-eval outcomes feed dossier suitability fields; the shadow-evaluated unit extends to `(base, drafter)` pairs per that spec), `EXECUTION-AUTHORITY-MODEL-2026-07.md` (Phase 5 empirical program consumes shadow comparisons), `REPRODUCIBILITY-CEREMONY-2026-07.md` (comparative verification of same query across peers), `CIRCUIT-BREAKER-2026-07.md` (drift-triggered recovery verification), `COGNITIVE-SELF-OBSERVER-2026-07.md` (comparison as verification input), `QUARANTINE-PLANE-2026-07.md` (shadow comparison contributes to admission evidence).

## Framing

The substrate has multiple use cases where running the same query against a second model — a control — produces evidence that no single-model inference could produce. Novel-model backup (per INFERENCE-ROUTING-DISCIPLINE) is one. Drift detection on stable-name models is another. High-stakes operator queries where comparative evidence informs decision-making is a third. Empirical program sampling for systematic model evaluation is a fourth. Recovery-mode verification when substrate returns from degraded state is a fifth.

Each of these use cases has been sketched independently. Their common mechanism is: **dispatch the same query to two (or more) inference targets in parallel; substrate compares the responses; chain-anchor the comparison; disposition per operator-declared policy.** That's a single primitive worth naming and specifying once rather than reinventing per use case.

Three properties frame the primitive:

1. **Shadow inference is chain-anchored evidence, always.** Every triggered comparison emits chain receipts documenting the trigger, the targets, both responses' identities and hashes, the comparison result, and the disposition applied. Comparisons are auditable post-hoc.
2. **Trigger conditions are operator-declared policy.** Substrate does not autonomously shadow-inference every call — that would 2x cost with no operator authorization. Operator declares which triggers activate shadow evaluation, which comparison targets to use, and what to do with divergent results.
3. **Cost budget discipline.** Shadow inference is expensive by construction. Operator declares budget; substrate operates within it. Budget exhaustion is a chain-anchored event, not silent degradation.

## The five canonical trigger conditions

Shadow inference fires when one of the operator-declared trigger conditions applies to an inference call. Canonical set:

### Trigger 1 — Novel model served

Under INFERENCE-ROUTING-DISCIPLINE Phase 1, response's served-model has no dossier. Shadow inference compares against a dossiered control model per operator's declared policy. Purpose: backup (known-good response available if novel diverges materially) and empirical evidence (provisional dossier fragment accumulation).

### Trigger 2 — Dossier drift suspected

Cognitive Self-Observer flags a response's behavioral pattern as inconsistent with the served model's dossier (per MODEL-DOSSIER-2026-07). Shadow inference dispatches the same query to a snapshot-defined known-good target (either the same model at a prior version, or a family-adjacent model). Purpose: distinguish "provider drifted the model behind stable name" from "this specific query happens to be at the edge of the dossier."

### Trigger 3 — High-stakes operator flag

Operator flags a query as high-stakes at query time (via UI signal, verb modifier, or standing correction that classifies query classes as high-stakes). Shadow inference dispatches to a distinct target — often a stronger model, or the operator's most-trusted model, or both. Purpose: comparative evidence before operator acts on high-consequence output.

### Trigger 4 — Empirical program sampling

The substrate's empirical program (per EXECUTION-AUTHORITY-MODEL Phase 5, consuming MODEL-DOSSIER evidence) samples a fraction of production queries for comparative evaluation. Shadow inference dispatches to peer models in the operator's dossier and records the comparison for systematic model-behavior calibration. Purpose: continuous empirical data collection informing model dossiers over time.

### Trigger 5 — Recovery-mode verification

Substrate returning from Circuit Breaker escalation (per CIRCUIT-BREAKER + BLAST-RADIUS-AND-RECOVERY) enters a reduced-authority verification mode. Every inference call runs shadow comparison against a control target until N successful convergent responses are chain-anchored, at which point substrate exits verification mode. Purpose: cognitive integrity verification after emergency recovery.

Operators may declare additional triggers via extension surface (per EXTENSION-SURFACE), but the five above are the canonical substrate-native set.

## Shadow target selection

Trigger conditions specify the invocation; shadow target selection specifies who serves the comparison. Operator declares per-trigger policy:

- **Fixed control target**: named model + provider (e.g., "shadow against `claude-sonnet-4-6` via direct Anthropic access")
- **Envelope selection**: substrate-side classifier picks from operator's envelope per trigger context (novel-model trigger uses the operator's most-trusted envelope model)
- **Multi-target**: comparison against N targets simultaneously; useful for empirical program and recovery verification
- **Snapshot target**: comparison against a chain-anchored prior response to the same query (for drift detection)
- **Peer-federation target**: comparison against a peer's response to the same query, per PEER-TRUST-ANCHOR delegation (for reproducibility ceremony variants)

Target selection is chain-anchored via the invocation receipt. Same target may be declared for multiple triggers; different targets per trigger is common.

## Comparison protocol

Comparing two LLM outputs is not a string diff. The substrate supports graduated comparison depth based on output type and operator preference.

### Level 1 — Structural agreement

For structured outputs (JSON schema mode, tool calls, form completions), comparison is structural: same schema fields present, values match per type-specific comparison, tool call arguments align. Highest confidence when structural agreement is exact; degraded confidence on partial agreement.

Cheap, deterministic, no additional inference required.

### Level 2 — Prose similarity

For natural-language responses, comparison uses embedding similarity: both responses embedded via a fixed dossiered embedding model, cosine similarity computed. Threshold-based agreement tiers:

- Cosine ≥ 0.90 → semantic agreement (high confidence)
- Cosine 0.70-0.89 → moderate agreement (prose divergent, meaning aligned)
- Cosine 0.50-0.69 → mixed agreement (partial overlap)
- Cosine < 0.50 → material divergence (different substantive content)

Embedding model itself must be dossiered — same discipline as any other model in the trust chain.

### Level 3 — Judge-model verification

For material-divergence cases or high-stakes triggers, substrate optionally dispatches a third inference call to a "judge" model with both responses and the original query as input. Judge is prompted to identify substantive differences and rate agreement.

Judge introduces its own inference cost and its own model-conditioned bias. Operator declares whether judge escalation is authorized per trigger. Chain-anchored per judgment.

### Level 4 — Operator review

For triggers with divergence-gated disposition mode (see below), the substrate surfaces both responses plus comparison receipt to operator. Operator makes the disposition call; substrate chain-anchors the operator's judgment.

Every comparison receipt names the level used and the agreement result. Higher-level comparisons are opt-in per operator budget.

## Disposition modes

What the substrate does with the comparison result. Operator declares per trigger:

### Mode A — Shadow

Primary response (from originally-requested target) is presented to operator. Shadow response and comparison result chain-anchored for post-hoc analysis. Preserves transparency about what routing / novel-model / high-stakes handling actually returned. Does not delay operator experience beyond the parallel dispatch time.

Default for novel-model triggers under Layer 1 (transparency principle) and for empirical program sampling.

### Mode B — Control-preferred substitution

Control (shadow) response is presented to operator. Primary response chain-anchored for provisional dossier accumulation but not shown. Preserves cognitive continuity — operator interacts with a known-good model. Makes routing invisible to operator.

Default for novel-model triggers under Layer 2 when operator has declared shadow-substitution policy.

### Mode C — Divergence-gated

If comparison agreement is above operator's declared threshold, primary response is presented. If agreement falls below threshold, both responses plus comparison receipt surface to operator with divergence flag. Operator makes disposition call.

Default for high-stakes triggers and recovery-mode verification.

### Mode D — Convergent-only substitution

If comparison shows convergent agreement, primary response is accepted. If comparison shows divergence, substrate refuses to serve either response; operator is notified and asked to disposition.

Strictest mode. Suitable for safety-critical operator flags where any divergence should block action.

Chain-anchored per invocation via `regent:inference:shadow_disposition:<invocation_id>:<mode>` receipt.

## Cost budget discipline

Shadow inference is expensive by construction — every triggered comparison is 2x (or more) the base inference cost. Operator declares budget; substrate operates within it.

Budget declaration composes with CloudMandate:

- **Monthly cap**: maximum shadow-inference spend per calendar period
- **Per-trigger cap**: distinct budgets per trigger class (novel-model triggers may deserve more budget than empirical program sampling)
- **Overflow policy**: what happens when budget approaches or exceeds limit
  - **Suspend triggers**: shadow inference stops firing until budget resets
  - **Reduce triggers**: switch from all-fires to sampled fires (e.g., 10% of novel-model events)
  - **Emergency-only**: only recovery-mode and high-stakes triggers continue firing; empirical program suspended
  - **Operator alert**: substrate notifies operator, awaits ceremony for policy change

Budget accounting is chain-anchored: `regent:inference:shadow_budget_consumed:<amount>:<trigger>` receipts per invocation; `regent:inference:shadow_budget_status:<remaining>` receipts on schedule.

Budget exhaustion is a chain-anchored event, never silent. Operator sees clearly when discipline reduced or suspended due to budget.

## Chain-anchored evidence

Every shadow inference invocation produces a chain-anchored evidence trail:

**Invocation receipt** — `regent:inference:shadow_invoked:<invocation_id>`:
- Original inference call reference (turn_id from primary)
- Trigger class (which of the five, or extension-declared)
- Trigger-specific context (novel-model identity, high-stakes flag reason, empirical sample seed, etc.)
- Shadow target(s) selected
- Cost estimate
- Signature

**Response receipts** — `regent:inference:shadow_response:<invocation_id>:<target>`:
- One per shadow target
- Same content as regent:inference:served for that call
- Signature

**Comparison receipt** — `regent:inference:shadow_comparison:<invocation_id>`:
- Comparison level used (structural, embedding, judge, operator)
- Agreement tier (semantic / moderate / mixed / divergent)
- Numeric similarity if applicable
- Divergence summary if applicable
- Signature

**Disposition receipt** — `regent:inference:shadow_disposition:<invocation_id>`:
- Mode applied (shadow / substitute / divergence-gated / convergent-only)
- Which response presented to operator
- Operator judgment if applicable (Mode C or D operator escalation)
- Signature

**Budget receipt** — `regent:inference:shadow_budget_consumed:<invocation_id>`:
- Cost breakdown per target
- Cumulative spend for current budget period
- Signature

Full comparison lifecycle is chain-visible. Any operator or auditor can reconstruct the full trail post-hoc.

## Composition with existing specs

- **INFERENCE-ROUTING-DISCIPLINE-2026-07.md**: consumes shadow-inference primitive for novel-model handling (Trigger 1) and dossier-drift detection (Trigger 2). INFERENCE-ROUTING-DISCIPLINE's novel-model quarantine composes with this spec's shadow-comparison evidence.
- **EXECUTION-AUTHORITY-MODEL-2026-07.md**: consumes shadow-inference for empirical program sampling (Trigger 4). Provisional dossier fragments produced under Trigger 1 or 4 accumulate into model dossier evidence for eventual ratification.
- **REPRODUCIBILITY-CEREMONY-2026-07.md**: peer-federation shadow target (dispatching same query to a peer's substrate) is a specific realization of reproducibility comparison. Comparison receipt structure shared between local shadow inference and cross-peer verification.
- **CIRCUIT-BREAKER-2026-07.md**: recovery-mode verification (Trigger 5) uses shadow comparison as the substrate's discipline for returning to full authority. Failed convergence keeps substrate in reduced-authority mode.
- **COGNITIVE-SELF-OBSERVER-2026-07.md**: comparison results are input to Cognitive Self-Observer's post-emission verification. Divergent shadow comparison strengthens Cognitive Self-Observer's flag; convergent comparison provides positive evidence for claim reliability.
- **QUARANTINE-PLANE-2026-07.md**: novel-model shadow evidence contributes to admission ceremony. Provisional dossier fragments accumulate as chain-anchored evidence during quarantine phase.
- **CLOUDMANDATE**: shadow-inference cost budget composes with CloudMandate spending limits.

## Attack model

- **Attacker exploits shadow-inference cost to force budget exhaustion**: rate-limiting on trigger firing; operator alert on approach to budget; overflow policy specifies safe degradation mode. Attacker forcing budget exhaustion transitions substrate to reduced-shadow discipline but not to silent-failure discipline.
- **Attacker manipulates trigger conditions to force shadow inference on manipulated queries**: trigger conditions are operator-declared. Attacker cannot declare new triggers without operator ceremony. Extension-declared triggers require QUARANTINE-PLANE admission.
- **Attacker compromises comparison logic to force false convergence**: comparison logic is substrate-side, delegated per operator envelope. Compromise of substrate-side comparison logic is a broader substrate compromise, handled by Genesis rotation and reproducibility ceremony.
- **Attacker forces material divergence via prompt injection**: divergence-gated disposition surfaces to operator; operator judgment determines whether the divergence indicates attack or benign edge case. Chain-anchored operator judgment builds precedent for future similar divergences.
- **Attacker manipulates judge model in Level 3 comparison**: judge model is dossiered. Judge-model compromise handled per general model discipline. Multi-judge comparison optional for high-stakes operator flags.
- **Attacker times comparison to slip through pre-comparison authority window**: chain-anchored ordering enforces comparison-precedes-disposition. Primary response cannot be presented to operator (in modes B, C, D) before comparison receipt is anchored.

## Failure modes

- **Comparison level unavailable (embedding model missing dossier, judge model unauthorized)**: comparison degrades to next-lower level. Substrate emits `regent:inference:shadow_degraded:<invocation_id>:<reason>` receipt. Operator sees reduced-confidence disposition.
- **Shadow target inference fails or times out**: comparison abandoned; substrate emits `regent:inference:shadow_incomplete:<invocation_id>` receipt. Primary response presented under Mode A default (transparency), or held for operator disposition per Mode C/D.
- **Budget exhausted mid-invocation**: shadow response completes but budget deficit is chain-anchored. Operator alerted; policy determines whether future triggers suspend or reduce.
- **Cost estimate inaccurate at invocation time (actual cost differs materially from estimate)**: cost accounting reconciles at completion; operator sees actual spend on chain.
- **Novel-model shadow accumulates without operator disposition**: eventual budget pressure surfaces the pattern. Substrate proposes emergency envelope-narrowing to reduce novel-model events. Composes with INFERENCE-ROUTING-DISCIPLINE's extended-quarantine detection.
- **Comparison result is genuinely ambiguous (edge case, neither confidently convergent nor divergent)**: operator surface with the ambiguity flag. Ambiguous comparisons should be rare; recurring ambiguity in a trigger class indicates operator should tune the comparison threshold or level.

## Non-goals

- **Not universal parallel inference**. Substrate does not shadow every call by default. Operator declares triggers. Untriggered calls are single-inference as before.
- **Not automatic dispute resolution**. Comparison results are evidence; operator judgment resolves genuine divergence. Substrate does not overrule operator with comparison verdict.
- **Not comparison of unrelated queries**. Shadow inference compares responses to the same query. Cross-query comparison (e.g., precedent-transfer) is a different mechanism.
- **Not cost-free empirical program**. Shadow inference for empirical sampling costs operator budget; operator chooses sampling rate consistent with budget.
- **Not attacker-proof against colluding primary + shadow targets**. If attacker compromises both the primary target and the shadow target, comparison agrees on attacker-desired output. Multi-target shadow, cross-federation shadow, and human review escalation are the mitigation layers.

## Open positions

- **Embedding model dossier maintenance**. Embedding models drift the same as generative models; their dossiers need refresh discipline. Cadence and ceremony.
- **Judge-model selection defaults**. When Level 3 comparison is enabled, which model should judge by default? Same envelope models? Distinct trusted model? Operator preference.
- **Divergence threshold calibration**. What cosine similarity constitutes "material divergence"? Depends on query domain — code review may need higher threshold than conversational response. Per-domain calibration.
- **Trigger extension mechanism**. How do extensions declare new trigger conditions? Composition with EXTENSION-SURFACE capability declarations.
- **Cross-peer shadow protocol**. When shadow target is a peer's substrate, protocol for query dispatch, response return, comparison, and chain-anchoring across sovereigns.
- **Budget vs sampling trade-off**. When budget is tight, is it better to fire fewer triggers or fire triggers at reduced comparison level? Operator preference.
- **Multi-turn conversation shadow**. Individual-turn shadow comparison vs. conversation-level comparison. Trade-offs on cost and evidence quality.
- **Streaming-mode shadow**. Streaming responses complicate comparison — partial responses arrive over time. Shadow inference for streaming may require buffering; UX and cost implications.

## What composes from here

Immediate design work:

1. **Receipt schemas** — Layer B canonical spec for invocation, response, comparison, disposition, budget receipts
2. **Trigger-condition declaration schema** — operator envelope extension for shadow-inference policy
3. **Comparison-level protocol spec** — structural / embedding / judge / operator flow details
4. **Cost accounting integration** — with CloudMandate spend tracking
5. **Multi-target dispatch coordination** — parallel invocation with correlated result gathering

Near-term implementation:

1. **Shadow-inference runtime** in `crates/zp-regent/src/inference/shadow/`
2. **Trigger-condition registry** — configurable set of trigger classes and their conditions
3. **Comparison pipeline** — level-1 through level-3 comparison logic with graduated confidence
4. **Cost budget enforcement** — pre-invocation budget check, post-invocation accounting, overflow policy engine
5. **Chain-anchored evidence emitters** — for all five receipt types
6. **Dashboard shadow-inference panel** — active triggers, recent invocations, comparison distribution, budget status
7. **CLI verbs**: `zp shadow-inference envelope get|set`, `zp shadow-inference status`, `zp shadow-inference history <invocation_id>`

## Framing note

Shadow inference comparison generalizes what would otherwise be independent mechanisms — novel-model backup, drift detection, high-stakes verification, empirical sampling, recovery verification — into a single substrate primitive. Same principle as chain-anchored discipline elsewhere: operator-declared policy, chain-anchored per invocation, cost-budgeted, ceremony-visible.

The load-bearing insight: **comparative evidence is a distinct trust primitive**, valuable enough across multiple substrate use cases to deserve its own specification. Rather than each consuming spec reinventing "run a parallel call and compare," the substrate offers one canonical shadow-inference primitive that all use cases compose with. Consumers declare triggers; the primitive handles dispatch, comparison, chain-anchoring, and disposition per operator policy.

Combined with the substrate's structural discipline across every trust boundary, shadow inference completes the comparative-verification envelope for cognitive operations. What was previously implicit — "if we're unsure about a response, we could just run it again against something we trust more" — becomes structural: triggers are declared, targets are selected, comparison is graduated, disposition is chain-anchored, cost is budgeted, operator authority is preserved. Sovereignty is preserved because operator declares every aspect of when and how shadow comparison fires. Safety is preserved because comparison evidence feeds Cognitive Self-Observer's ground-truth verification. Continuity is preserved because chain records the full comparison lifecycle per invocation, enabling post-hoc audit of every case where the substrate had reason to seek comparative confirmation.
