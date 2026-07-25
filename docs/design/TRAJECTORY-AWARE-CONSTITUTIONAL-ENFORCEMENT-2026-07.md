# Trajectory-Level Detection: An Advisory Layer for Constitutional Awareness — July 2026

**Document type:** Design note. Specifies an additive, best-effort detection and situational-awareness layer that observes patterns across sequences of actions and surfaces concerns to the operator. **This is not a constitutional enforcement mechanism.** Constitutional enforcement remains exactly what it is in `whitepaper-v9.md` §5.3: atomic evaluation of individual actions by the GovernanceGate against the Harm Principle and Sovereignty Rule. What this document describes is a separate capability — detection and warning — that helps operators and the substrate reason about multi-action patterns that atomic evaluation cannot see. When the two are conflated, both are diminished.

**Status:** Design note. Ready for iteration; open decisions marked. The whitepaper §12 (Threat Model) should name decomposition attacks as a real threat, note that atomic constitutional enforcement does not catch them, and cite this note for the detection capability that partially addresses them.

**Author:** Ken Romero, with synthesis assistance from Claude.

**Date:** 2026-07-05.

---

## Part I — What This Is, and What This Isn't

### 1.1 Constitutional enforcement stays atomic

The GovernanceGate evaluates one action at a time. This is what a gate does — it decides whether *this* specific action passes. Constitutional rules (the Harm Principle and the Sovereignty Rule) are evaluated by the gate at the atomic-action level. Each action is examined against the rule; if the action matches a prohibited pattern, it is denied; if not, it is permitted.

This is the entire constitutional enforcement story. It is deterministic, structural, model-independent, and non-bypassable. Nothing in this document changes it. Nothing in this document makes it stronger. Nothing in this document should be understood as strengthening constitutional guarantees beyond what atomic evaluation already provides.

Any framing that suggests otherwise — including the earlier framing of this document itself — is wrong. Constitutional rules are what they are. What follows is a separate capability.

### 1.2 The gap the atomic model does not close

Harm can be a property of a trajectory rather than an atomic action. Sovereignty violations can be assembled from steps none of which is individually a violation. The atomic gate is systematically blind to these patterns because it looks at one action at a time.

**Example: surveillance profile assembly.** No single query for a person's phone number, home address, workplace, daily schedule, or associates matches "unauthorized surveillance." Together, they constitute a stalking profile. Atomic evaluation sees seven benign queries; the pattern is what constitutes the concerning outcome.

**Example: coordinated harassment.** No single message drafted, no single post published, no single follow-up composed matches "harassment." Together, sustained across a campaign, they constitute harassment. Each atomic action is speech, which is not prohibited; the pattern is.

**Example: substrate weakening.** No single configuration change, log rotation, service restart, or dependency update matches "disable the guard." Together, in a coordinated sequence, they may constitute an operator-unauthorized attempt to weaken the substrate's own defenses. The atomic Sovereignty Rule catches direct attempts; a patient adversary decomposes the direct attempt into steps that don't individually trigger.

**Example: harmful capability synthesis.** No single search for a chemistry topic, no single query about a laboratory technique, no single request for reagent availability matches "weaponization." Together, they may constitute research into synthesizing something the operator should not synthesize. Atomic evaluation is blind to the aggregation.

### 1.3 What this document is

An **advisory detection and situational-awareness layer** that watches for concerning trajectory-level patterns and surfaces findings to the operator. It is:

- **Additive.** It sits alongside atomic enforcement, not underneath or above it.
- **Best-effort.** It uses inference (Cartographer trajectory attribution, officer findings, pattern accumulators) to detect patterns; it makes no structural guarantees about what it will catch.
- **Advisory.** It produces warnings, findings, and acknowledgment prompts. It does not enforce anything the atomic gate would not.
- **Model-informed.** It depends on the cognitive layer's inference. Deployments running minimal cognition get less of it; deployments running strong cognition get more.
- **Corrigible over time.** False positives and false negatives are visible on the chain and inform calibration.

It is not:

- **Constitutional enforcement.** Constitutional enforcement is the atomic gate. This layer does not augment or extend it.
- **A guarantee.** Detection is best-effort. Sophisticated adversaries can defeat it. The atomic gate does not weaken when detection fails.
- **A policy layer.** Operators may separately configure operational rules that use trajectory context — that is operator-configured policy enforcement, which is different from the detection this document describes.

### 1.4 Why the distinction matters

When advisory detection is framed as constitutional enforcement, three things go wrong:

- **The atomic gate's guarantees are diluted.** Readers come to believe that constitutional enforcement is inference-dependent, which it isn't.
- **The detection layer's honest limits are hidden.** Best-effort detection sold as robust enforcement will be trusted beyond what it can deliver.
- **The remedy for detection failures gets confused.** If detection fails to catch a decomposition attack, the response should be "improve the detection heuristics"; if detection is confused for enforcement, the response becomes "the substrate failed to prevent this," which it did not — the atomic gate does not claim to prevent decomposition attacks.

Naming the layer clearly as advisory prevents these three failures. The rest of this document describes what the advisory layer looks like, what it produces, how it composes with the substrate, and what its honest limits are — under the correct framing.

---

## Part II — The Atomic Foundation, and Three Detection Modes That Sit Beside It

Enforcement and detection are different capabilities and this document treats them as such.

**The enforcement foundation (unchanged, always active):**

- **Atomic constitutional evaluation at the gate.** The existing structural mechanism. Fast, deterministic, model-independent. Applies to clearly-defined atomic harm and sovereignty patterns. This is what enforces. Nothing in this document changes it.

**Three detection modes that sit alongside enforcement (advisory, best-effort):**

- **Trajectory-context detection at the gate.** When the gate evaluates an atomic action, it also consults trajectory context (Cartographer attribution, officer findings, pattern accumulators). If trajectory context flags concern, the gate surfaces a warning to the operator, requests explicit acknowledgment before proceeding, and records the observation as a chain receipt. The atomic action's fate is unchanged: if atomic enforcement permits, the action ultimately proceeds (possibly after operator acknowledgment); if atomic enforcement denies, the action is denied regardless of trajectory context. Detection informs; it does not enforce constitutional rules.
- **Cognitive-layer self-awareness.** The apex observer, as part of its own operation, notices when its planned trajectories are heading toward outcomes the operator would not want, and declines to pursue them. This is the cognitive layer's own restraint, not substrate enforcement — but well-designed cognition reduces the base rate of actions that reach the gate in concerning trajectories.
- **Post-hoc trajectory review.** The Cartographer identifies trajectories; officers evaluate them periodically; findings are chain-anchored. Flagged trajectories inform future gate-time detection and are surfaced to the operator for review. This produces the accountability trail and improves detection over time.

The atomic enforcement layer is what the substrate promises. The three detection modes are what help the operator and the substrate see patterns that atomic evaluation cannot. When detection fails, the atomic enforcement layer's guarantees are unchanged. When detection succeeds, the operator is better informed and can act on their own judgment about how to proceed.

---

## Part III — The Atomic Enforcement Layer (Unchanged)

Constitutional enforcement is atomic evaluation at the gate. This section describes it briefly for reference; the substance is unchanged from `whitepaper-v9.md` §5.3.

### 3.1 What it enforces

- Direct weaponization attempts.
- Direct attempts to disable the guard, truncate audit trails, forge capabilities.
- Direct attempts to override participant refusal.
- Direct attempts to remove constitutional rules from evaluation.
- Actions whose content itself matches known harmful patterns (surveillance queries against specific known-targeted individuals, deepfake-generation calls against specific known individuals, etc.).

### 3.2 What it structurally cannot see

- Multi-step goals decomposed into individually-benign steps.
- Context-dependent harm (an action fine in one context, harmful in another).
- Aggregation attacks (individual actions that combine into harmful capability).
- Long-timescale drift (gradual movement toward a harmful state).

The atomic gate does not claim to see these. The gaps are inherent to atomic evaluation; naming them is not naming a bug.

### 3.3 The properties that make atomic enforcement trustworthy

- **Structural.** The rule is uniform, applied identically to all actors.
- **Deterministic.** Given the atomic action, the decision is fixed.
- **Model-independent.** No inference required. Constitutional guarantees hold identically across deployments regardless of what cognitive layer is running.
- **Fast.** Cheap to evaluate on every action.

Everything else in this document is separate from these properties. The atomic gate keeps them regardless of what the detection layer does or fails to do.

---

## Part IV — Trajectory-Context Detection at the Gate

Alongside atomic enforcement, the gate consults trajectory context and produces detection findings. The atomic enforcement decision is unchanged by this consultation; detection runs in parallel and may add operator-facing warnings and acknowledgment requests to the flow.

### 4.1 What context detection has access to

For each incoming action, the detection layer consults:

- **Current trajectory attribution.** What Cartographer-identified trajectory is this action part of? What is the trajectory's inferred goal? What decisions and insights are already on the chain for this trajectory?
- **Recent officer findings.** What has Sentinel flagged in the last observation window? What patterns has Steward noticed? What operational concentrations has Forge identified? What governance-narrative concerns has Cleo raised?
- **Pattern accumulators.** Rolling summaries of action-category distributions over configurable time windows. "Fifty queries for personal information about the same non-consenting individual in the last twenty-four hours" is a pattern-accumulator signal that does not require model inference to compute.
- **Prior similar-trajectory outcomes.** Chain-visible history of how similar trajectories have resolved. If similar trajectories have historically ended in operator-regretted outcomes, the current signal weighs that history.
- **External-party consent signals.** For actions that cross the boundary of the operator's sovereign domain, whether the affected parties have provided consent that would validate the action.

### 4.2 What detection produces

For an incoming action whose atomic evaluation permits, the detection layer produces one of three outputs:

- **No signal.** Trajectory context shows no concern. The action proceeds without any detection-side intervention.
- **Notice.** Trajectory context shows mild concern. The action proceeds normally, but the Regent surfaces a notice to the operator ("this action is part of a trajectory we've been watching") and the trajectory is flagged for continued observation.
- **Acknowledgment requested.** Trajectory context shows significant concern. The action is held in a pending state until the operator explicitly acknowledges the concern via a chain-anchored signed receipt. On acknowledgment, the action proceeds. This is not the substrate refusing the action — the atomic enforcement layer has already permitted it — it is a workflow that ensures the operator is not proceeding blindly through a pattern the substrate has flagged.

**Critical:** The detection layer does not deny actions that atomic enforcement permits. It cannot make constitutional guarantees stronger; it can make the operator more aware. If the operator, having seen the notice or acknowledged the concern, chooses to proceed, the action proceeds. Sovereignty is preserved: the operator remains the decision-maker for their own actions within the space that constitutional rules permit.

If atomic enforcement denies the action, detection is moot — the action is denied by the enforcement layer, and detection has nothing to add.

### 4.3 Chain-anchored detection findings

Every detection observation produces a receipt including:

- The atomic action
- The trajectory attribution consulted
- The officer findings consulted
- The pattern signals evaluated
- The finding produced (no signal / notice / acknowledgment requested)
- The operator's acknowledgment, if requested and provided

This makes detection findings auditable. If the trajectory attribution was wrong, the receipt shows what the Cartographer said and what detection did with it. If officer findings were miscalibrated, the receipt shows the specific findings. Detection is inference-informed, but every inference input to the finding is chain-anchored and independently verifiable. Wrong detections are false alarms; they are not bypassed enforcement.

### 4.4 Operator-configured operational rules can behave differently

The distinction worth naming: an operator may separately configure operational rules (not constitutional) that do use trajectory context and can deny actions the atomic gate would permit. These are the operator's own policies about how their instance operates — they are enforced by the substrate, but they are policy the operator has chosen, not constitutional guarantees the substrate provides. This document is about the detection layer, not about operator-configured operational policies; they are distinct mechanisms.

---

## Part V — Cognitive-Layer Self-Awareness

The apex observer's own behavior is a distinct detection mode. Well-designed cognition notices when its planned trajectories are heading toward outcomes the operator would not want and declines to pursue them. This is not substrate enforcement — the substrate does not depend on the Regent behaving well — but it dramatically reduces the base rate of actions that reach the gate in concerning trajectories.

### 5.1 Why this is a separate mode

If the cognitive layer already declines to plan concerning trajectories, atomic enforcement and gate-time detection have less work to do. A cognitive layer that generates many actions the gate must refuse or flag is inefficient. A cognitive layer that internally recognizes concerning trajectories and steers away from them is efficient and better for the operator's experience.

### 5.2 What the Regent's self-awareness looks like

The Regent's internal reasoning about trajectories considers:

- What trajectory this planned action is part of and what that trajectory is heading toward.
- Whether the trajectory's inferred goal would be one the operator would want to pursue.
- Whether the trajectory is consistent with the operator's stated intent.
- Whether officer findings suggest the current context is one where extra caution is warranted.

If the Regent's analysis suggests a trajectory should not be pursued, it declines to plan actions that would advance it and surfaces the concern to the operator. The operator can override — the Regent explains and asks — but the default is to pause and check.

### 5.3 When self-awareness detects concern mid-trajectory

When the Regent recognizes mid-trajectory that things have drifted, it:

1. Surfaces the concern to the operator explicitly.
2. Records a Cartographer trajectory update noting the concern.
3. Pauses the trajectory pending operator direction.
4. Does not attempt to route around the concern via decomposition — that would be exactly the behavior an aware cognitive layer is refusing to do.

### 5.4 This is cognition doing its job, not enforcement doing more

Cognitive-layer self-awareness is not a substitute for atomic enforcement, and it is not a substitute for gate-time detection. It is the cognitive layer being the kind of coordinator that pays attention to what it is doing. When the Regent is well-designed, this mode is invisible in the good case — the operator sees a coordinator that steers away from problematic trajectories without ceremony. When the Regent is poorly designed or adversarially subverted, this mode fails silently — atomic enforcement and gate-time detection are what catch failures.

---

## Part VI — Post-Hoc Trajectory Review

Post-hoc review operates continuously in the background. The Cartographer identifies trajectories; **Aegis owns the constitutional-trajectory assessment**; the other four officers contribute domain-specific inputs; findings are chain-anchored. Flagged trajectories inform future gate-time detection and are surfaced to the operator.

### 6.1 Aegis owns the assessment

Aegis is the officer whose entire domain is trajectory-level constitutional monitoring. He reads the Cartographer's ontology continuously for patterns of drift toward constitutional concern, and he composes findings from the other four officers as inputs to his assessment.

### 6.2 What Aegis reads

The Cartographer, as part of its normal ontology construction, produces trajectory objects with confidence scores, inferred goals, and status. Aegis adds a further dimension: for each trajectory, does the inferred goal, if pursued to completion, appear to be one the operator would want or one the substrate should have concerns about?

His inputs from the other officers:

- **Steward** contributes chain-integrity signals — patterns of receipt manipulation, ontological incoherence, evidence tampering.
- **Sentinel** contributes security-posture signals — patterns consistent with attack behavior against the operator or against third parties, credential concerns, threat-surface changes.
- **Forge** contributes operational signals — resource-use patterns consistent with substrate-weakening, unusual concentrations of activity, operational anomalies.
- **Cleo** contributes governance-narrative signals — the trajectory's inferred framing, whether the operator (or the cognitive layer under the operator) appears to be pursuing something concerning.

Aegis synthesizes these into a constitutional read. His findings are chain-anchored — flagged trajectories carry his assessment with citations to the specific inputs that drove the flag. Green / yellow / red status becomes visible on each trajectory in the Cartographer's ontology.

### 6.3 What Aegis is not

Aegis does not enforce. Atomic constitutional enforcement stays at the gate (Part III). Aegis produces best-effort detection that surfaces trajectory-level concerns the atomic layer cannot see. The operator, via the acknowledgment workflow (Part VII), remains the decision-maker for actions the atomic layer permits.

Aegis is also not infallible. He catches what he is calibrated to catch. Sophisticated adversaries who model his calibration can design trajectories to evade him; genuinely novel harmful patterns may not match any signal he watches for; and constitutional concerns initiated by the operator themselves — where the operator is the source of drift, not a party being drifted toward — are outside what any officer serving the operator can catch.

His honest job description: clock misaligned trajectories. He catches the ones he can catch, produces chain-anchored evidence when he does, and stays out of the way when nothing is drifting.

### 6.4 Heightened scrutiny for flagged trajectories

When post-hoc review flags a trajectory as concerning, future atomic actions attributed to that trajectory face heightened gate-time detection scrutiny. The pattern-accumulator thresholds tighten. Officer findings weigh more heavily. Acknowledgment requests may kick in earlier.

This creates a feedback loop for detection: if a trajectory is drifting into concerning territory, the detection layer's warnings and acknowledgment requests grow more insistent on further actions in that trajectory. The atomic enforcement layer is unchanged; the detection layer becomes more attentive.

### 6.5 Operator visibility

The operator sees flagged trajectories via the Regent. The Regent presents:
- Which trajectory has been flagged
- Why (specific officer findings, pattern signals)
- What detection's future scrutiny will look like for continued actions in this trajectory
- Options: acknowledge the concern (chain-anchored), abandon the trajectory, refactor the trajectory, dispute the finding (via chain-anchored dispute receipt)

Nothing about post-hoc review is hidden from the operator. Transparency is a load-bearing property.

### 6.6 Accountability trail

Every post-hoc finding is a chain receipt. If an operator later reflects on a trajectory that produced regrettable outcomes, the history of detection findings is visible. If findings were false positives, that history is also visible and informs future calibration. The review layer does not enforce; it produces the accountability trail that makes detection's successes and failures legible over time.

---

## Part VII — The Operator Acknowledgment Workflow

Gate-time detection and post-hoc review introduce a specific new interaction: when trajectory context raises significant concern, the operator may be asked to acknowledge the concern before an action proceeds. This is a workflow around detection, not a bypass mechanism for constitutional rules. It is worth being precise about what it does and does not do.

### 7.1 What acknowledgment does

- **Provides operator visibility.** The operator sees that the substrate has noticed a pattern and is bringing it to their attention.
- **Records their explicit awareness.** The acknowledgment is a chain receipt signed by the operator's Genesis-derived key. They saw the concern; they proceeded anyway.
- **Reduces immediate detection friction on the acknowledged trajectory.** Once acknowledged, future gate-time detection on the same trajectory does not repeatedly interrupt the same operator with the same finding. The trajectory remains flagged; the operator remains responsible for their acknowledged judgment.
- **Preserves sovereignty.** The operator remains the decision-maker for actions within the space constitutional rules permit. Detection informed them; they decided.

### 7.2 What acknowledgment does not do

- **Does not override constitutional enforcement.** If atomic enforcement denies an action, no acknowledgment permits it. Acknowledgment is only relevant to actions atomic enforcement has already permitted where trajectory context raised concern.
- **Does not modify the Sovereignty Rule as it applies to substrate integrity.** No acknowledgment can permit actions that would disable the guard, remove constitutional rules, forge capabilities, or override participant refusal — those are denied by atomic enforcement regardless of acknowledgment.
- **Does not legitimize prior actions.** Acknowledgment applies forward; past actions on the chain remain as-recorded.
- **Does not silence future detection on other trajectories.** Acknowledgment is scoped to the specific trajectory acknowledged.

### 7.3 Structure of an acknowledgment receipt

- The trajectory attribution the acknowledgment applies to.
- The specific detection findings raised.
- The operator's explicit statement that they have seen and considered the findings.
- Optional rationale (text or additional receipts explaining the operator's reasoning).
- Signature from the operator's Genesis-derived key.
- Time bound (acknowledgments expire; must be renewed for ongoing trajectories).

The acknowledgment is a chain-anchored record of the operator's judgment at a moment in time. If the trajectory later produces regrettable outcomes, the acknowledgment is visible evidence of what the operator saw and how they judged it.

### 7.4 The workflow is a workflow, not a bypass

Acknowledgment cannot become a routine "click through the warning" habit:

- Acknowledgments require explicit operator authentication (not just an unlocked vault).
- Frequency of acknowledgment is chain-visible; a pattern of acknowledging many flagged trajectories is itself a signal officers will notice.
- The Regent surfaces acknowledgments carefully and offers alternatives (abandon, refactor, wait, reconsider) before acknowledgment is the path chosen.
- Acknowledgments can be reviewed by the operator's own retrospective analysis (via the Cartographer) and, at the operator's option, publicly disclosed as part of ongoing accountability posture.

The workflow's purpose is to make sure the operator is aware, not to slow them down for its own sake. When detection is calibrated well, the operator sees warnings only when the substrate has genuine reason to surface them, and acknowledging is a considered decision rather than reflex.

---

## Part VIII — Inference Dependence Is Fine Here (Because This Is Detection)

Detection uses inference. Trajectory attribution uses the Cartographer, which uses models. Officer findings use models. This would be a serious problem if detection were enforcement — enforcement should be structural and model-independent. Because detection is *not* enforcement, the inference dependence is acceptable and worth understanding.

### 8.1 Why this would be a problem for enforcement

If constitutional enforcement depended on inference, then:

- Constitutional guarantees would vary across deployments based on what cognitive layer they run.
- A model bug could result in genuinely harmful actions being permitted.
- Adversaries could target the model to defeat enforcement.
- The substrate's structural guarantees would be diluted by model-dependent judgment.

None of these apply here because detection is not enforcement. The atomic gate does not consult inference. Constitutional guarantees are identical across deployments regardless of what cognitive layer runs.

### 8.2 Why inference is acceptable for detection

Detection's purpose is to surface patterns to the operator and to inform future detection. The failure modes are:

- **False positive.** Detection warns about a legitimate trajectory. The operator acknowledges the concern (or dismisses it, or refactors), and the action proceeds. Cost: friction. Not a violated guarantee.
- **False negative.** Detection misses a concerning pattern. The operator does not receive a warning they would have benefited from. Cost: missed situational awareness. Not a violated enforcement guarantee — atomic enforcement is unchanged.

Both failure modes are recoverable. Both leave chain-anchored evidence for calibration. Neither reduces the substrate's structural commitments.

### 8.3 What this means in practice

- **Deployments running strong cognitive layers get rich detection.** They benefit from trajectory attribution, officer findings, pattern accumulators, and the Regent's self-awareness.
- **Deployments running minimal cognitive layers get less detection but identical enforcement.** The atomic gate is the same. Detection quality varies with cognitive capacity available.
- **Detection quality is corrigible over time.** Calibrations improve based on chain-visible evidence. Enforcement, meanwhile, does not need to be improved — it is what it is, and improvement of detection does not modify it.

The clean architectural separation: enforcement is structural and constant; detection is best-effort and improves with cognitive capability. Conflating them would compromise both. Keeping them separate lets each be what it is.

---

## Part IX — Composition with the Substrate

### 9.1 Gate architecture

The GovernanceGate as specified in the whitepaper has five stages: Guard, Policy, Execute, Audit, Transport. Detection composes with the gate as follows:

- **Guard.** Atomic constitutional enforcement runs here unchanged. If atomic enforcement denies, the action is denied; detection is not consulted (there is nothing for detection to add).
- **Policy.** If Guard permits, Policy runs. Detection consults trajectory context alongside standard operational-policy evaluation. Detection may add a warning, request acknowledgment, or produce no signal. Detection does not deny.
- **Execute.** Runs after Guard and Policy permit. If detection requested acknowledgment, execution waits for the operator's signed acknowledgment.
- **Audit.** Emits receipts for the atomic decision, the detection finding (if any), the acknowledgment (if requested and provided), and the execution result.
- **Transport.** Receipts propagate normally.

Cognitive-layer self-awareness (Part V) does not participate in the gate directly — it operates at the cognitive layer's own planning stage, before actions reach the gate. Post-hoc review (Part VI) operates continuously in the background, informing the trajectory context that gate-time detection consults.

### 9.2 Cartographer-to-detection interface

The Cartographer maintains trajectory attribution as part of its normal ontology construction. When gate-time detection runs, it consults the Cartographer for:

- What trajectory this action is attributed to
- The trajectory's current status
- The trajectory's post-hoc review status (green/yellow/red)
- Specific concerns post-hoc review has raised

This is a synchronous query. The Cartographer must respond quickly; if it cannot, detection falls back to pattern-accumulator signals only and records the fallback in the finding.

### 9.3 Officer-to-detection interface

Officers publish findings as chain receipts. Detection reads recent officer findings (rolling window, configurable) during Policy. Findings older than the window still exist on the chain but do not directly influence real-time detection; they contribute to Cartographer trajectory attribution instead.

### 9.4 Pattern accumulator implementation

Pattern accumulators are structural: they compute distributions of action categories over configurable time windows without requiring inference. They are efficient (rolling counters) and deterministic. Thresholds that trigger detection concern are configurable per action category and can be tightened for trajectories with post-hoc review flags. Pattern accumulators are the closest thing in the detection layer to structural signal — they can operate even in deployments with no cognitive layer at all, providing a modest baseline of detection to accompany the atomic enforcement foundation.

---

## Part X — Honest Limits of the Detection Layer

Detection is best-effort. Sophisticated adversaries can defeat it. This section names what detection can and cannot do, without conflating it with what atomic enforcement guarantees.

### 10.1 What detection can plausibly catch

- **Casual decomposition attacks.** A naive attacker who decomposes a goal into steps without modeling detection heuristics will trigger pattern accumulators, produce officer findings, or generate trajectory attributions the operator will see.
- **Repeated concerning patterns.** An attacker who tries similar approaches multiple times gets caught more easily each time as post-hoc review flags the pattern and gate-time detection tightens.
- **Attacks whose trajectory is legibly assembled from action categories detection tracks.** Pattern accumulators are structural signals; if the attack raises the counts detection watches, detection notices.

### 10.2 What detection cannot catch

- **First-time attacks by unmodeled adversaries.** An adversary using an attack pattern detection has never seen may proceed without notice.
- **Attacks that look identical to legitimate work.** If an attack is designed to be indistinguishable from research, journalism, education, or other legitimate activities, observation-based detection has no signal to work with.
- **Attacks that exploit the operator's own authority.** If the operator is the adversary, or is coerced into signing, no amount of detection will save them from their own signed actions.
- **Attacks that exploit the cognitive layer's inference.** An adversarial trajectory-inferrer produces trajectories that look benign to post-hoc review; adversarial officer inference misses findings; an adversarial Cartographer misattributes actions to innocuous trajectories.

### 10.3 What detection failures do not mean

When detection fails to catch a decomposition attack, this does not mean:

- **Constitutional enforcement failed.** Constitutional enforcement is atomic evaluation. Atomic evaluation continues to enforce what it enforces regardless of detection's success or failure. If the attack's atomic actions did not match constitutional patterns, atomic enforcement was never going to catch them — that is the well-understood limitation of atomic evaluation, and detection is what tries to compensate.
- **The substrate broke its guarantees.** The substrate promises what atomic enforcement provides. It does not promise that detection will catch all sophisticated attacks. When detection fails, the substrate's promises are unchanged.
- **Detection is broken.** Missed detections are expected. Detection is best-effort; missing some patterns is intrinsic. The response to a missed detection is to update calibration and heuristics for the future, not to conclude the whole layer is unsound.

### 10.4 The accountability backstop remains

When detection fails, accountability remains. Every action is a receipt. Every decision is a receipt. Post-hoc analysis of the chain can identify what happened, when, under whose signature, with what detection signals were and weren't available at the time. This does not undo harmful outcomes but it does create the record that makes calibration improvable and creates real cost for actions that produce regret.

Atomic enforcement provides the floor of what the substrate guarantees. Detection provides best-effort awareness above that floor. Accountability provides the trail that makes both improvable over time. These are three distinct capabilities; conflating them diminishes all three.

---

## Part XI — Adversarial Dynamics (Against Detection)

The attacks in this section are attacks on the detection layer, not on constitutional enforcement. When these attacks succeed, detection produces false negatives — the operator misses awareness they might have benefited from. Constitutional guarantees are unchanged; they were never dependent on detection in the first place.

### 11.1 Trajectory-inference gaming

**Attack:** Adversary designs actions such that the Cartographer attributes them to benign trajectories, hiding the actual concerning trajectory.

**Defense:** Multi-officer cross-check — Sentinel, Steward, Forge, and Cleo bring different perspectives; if they systematically disagree with the Cartographer's attribution, the discrepancy is itself a signal. Pattern accumulators still catch distribution-level anomalies regardless of trajectory attribution. Chain history of similar-actor trajectory attributions calibrates the Cartographer over time.

**Residual risk:** Sophisticated adversaries with knowledge of the Cartographer's attribution model can produce attributions that look consistent. Detection is imperfect; this is a case in point.

### 11.2 Officer finding suppression

**Attack:** Adversary corrupts officer inference so concerning findings are not produced.

**Defense:** Officer inference is chain-anchored — findings are receipts, their absence is chain-visible over time. Multiple officers cross-check each other's domain-adjacent observations. Sudden changes in officer finding rate are themselves a Steward-level integrity signal.

**Residual risk:** A fully compromised officer inference layer produces no findings and appears normal. The chain's absence-of-findings signal takes time to accumulate.

### 11.3 Pattern accumulator evasion

**Attack:** Adversary spreads actions across time windows to stay below pattern-accumulator thresholds.

**Defense:** Pattern accumulators use multiple overlapping time windows (hourly, daily, weekly, monthly) so evasion at one time-scale triggers at another. Category granularity is fine — evasion requires spreading across categories, which itself is a signal.

**Residual risk:** Sufficiently patient adversaries can spread actions to stay below all thresholds. Post-hoc review across longer time-scales is the backstop, and it is also imperfect.

### 11.4 Acknowledgment fatigue

**Attack:** Adversary produces enough concerning trajectories that the operator becomes habituated to acknowledgment requests and starts clicking through them without careful consideration.

**Defense:** Detection is calibrated to reduce noise — warnings only when signals are meaningful. Frequency of acknowledgment is chain-visible; heavy acknowledgment is itself a pattern officers notice. The Regent presents acknowledgment requests with context that resists reflexive dismissal.

**Residual risk:** A determined attacker who wants to normalize acknowledgment fatigue can partly do so; the operator's diligence is a real variable detection cannot control.

### 11.5 Multi-operator coordination

**Attack:** Multiple operators coordinate concerning behavior, splitting the trajectory across chains so no single operator's chain shows the whole pattern.

**Defense:** Peer discovery and reputation dynamics can surface coordination signals across operator boundaries. The peer-audit mechanism provides cross-operator chain visibility for those who participate. But this attack has real teeth — cross-operator coordination is genuinely harder to detect than single-operator patterns.

**Residual risk:** Sophisticated multi-operator coordination is a real gap. Community-level surveillance is antithetical to sovereignty, so what detection can do here is bounded to what emerges from voluntary peer-audit and reputation dynamics.

---

## Part XII — An Invitation

Two things about this document are worth putting in one place.

The first is that what we solved, we solved cleanly. Constitutional enforcement is atomic — the rules evaluate on every action, they are structural and deterministic, and no code path bypasses them. The receipt chain is signed, hash-linked, offline-auditable, and tamper-evident. Every capability grant traces back to a human-held Genesis key through invariants that reject any widening of authority. The delegation model narrows monotonically. These are load-bearing guarantees, and they are load-bearing precisely because they are simple enough to reason about and enforce structurally. What atomic evaluation can do, it does. What the chain can prove, it proves. We are not going to make either of those weaker by dressing them up with claims they do not support.

The second is that we did not solve intent. We did not solve trajectory-level constitutional evaluation. We did not solve the general problem of inferring what a sequence of actions is aimed at doing. Nobody has solved that, and we are not going to pretend we have by hiding a partial solution behind confident-sounding language. What this document describes is the detection layer we thought was worth building — pattern accumulators, trajectory attribution, officer findings, cognitive-layer self-awareness, acknowledgment workflow — and it is best-effort, model-informed, and imperfect. It surfaces some patterns. It misses others. It will need to be calibrated by whoever cares to calibrate it.

If you think you can do better at trajectory-level detection than what this document sketches, come do it. The atomic foundation is here. The receipt chain is here. The primitives compose. The Cartographer produces trajectories. The officers publish findings. The gate consumes context. The operator acknowledgment surface exists. If your idea is a better trajectory-inference model, a smarter pattern accumulator, a novel officer perspective, a more sophisticated composition function for detection signals — it slots in. The plumbing does not need to be reinvented for you to try something.

This is deliberate. We would rather see a hundred experiments with better detection than one paper claiming detection is solved. The interesting research problem is still open. The substrate does not pretend otherwise. What it gives you is a foundation stable enough to build on and a receipt chain that will still be verifiable when your experiment is done — whether or not the experiment worked.

We solved what we could solve cleanly. The rest is on you.

---

## Part XIII — The Supersession Framework

The invitation in Part XII is a structural affordance, not rhetoric. Anyone who wants to propose a replacement for a mechanism within the substrate can, and there is a defined path for that replacement to supersede the current architecture if operators adopt it. This section specifies the shape of that affordance at the level of detail this document warrants; the full process specification is future work, tentatively named the ZeroPoint Enhancement Proposal (ZEP) framework and deserving its own design note.

### 13.1 What cannot be superseded — the invariants

Some parts of the substrate are load-bearing invariants. They cannot be replaced without breaking the substrate's guarantees:

- The constitutional rules and their atomic evaluation at the gate.
- The receipt structure and its hash-linked chain.
- The Genesis-derived key hierarchy.
- The delegation narrowing invariant (eight-invariant chain verification).
- The signature-based verification model.
- The nine design principles articulated in the whitepaper.

These are the substrate's contract with the ecosystem. A proposal that violates any of them is not a proposal for ZeroPoint; it is a proposal for a different substrate. This distinction is not gatekeeping — anyone is free to build a different substrate — but a proposal calling itself a ZeroPoint enhancement must respect the invariants ZeroPoint stands on.

### 13.2 What can be superseded — the mechanisms

Everything else is a mechanism. Mechanisms include, but are not limited to:

- Detection algorithms (this document's subject).
- Pattern accumulator designs.
- Officer inference approaches.
- Cartographer trajectory attribution methods.
- Reputation computation.
- Mesh transport implementations.
- Presence Plane backends.
- Truth anchor backends.
- Cognitive-layer coordination strategies.
- Cryptographic algorithm choices within the parameters the invariants set.
- Presentation-layer implementations.
- Backup and recovery schemes.
- Vault format and storage architecture.
- Peer-discovery announce category taxonomies.
- Community-surface primitives (channel taxonomies, session mechanics, moderation approaches).

Each mechanism has a *role* — a place in the composition where the substrate expects it — and a set of *constraints* its role imposes. A replacement mechanism must fill the role and satisfy the constraints. Beyond that, how it works is open.

### 13.3 The affordance

Anyone can propose a replacement mechanism. Proposals are chain-anchored artifacts specifying:

- **What is being replaced and why.**
- **The complete specification of the replacement** — sufficient for an independent implementer to build a compliant version.
- **How the replacement preserves each substrate invariant** — explicit mapping to the list in §13.1.
- **Backward compatibility** with the existing mechanism, if operators are already running it.
- **Security implications** — what the replacement changes about the substrate's threat model.
- **Evaluation criteria** — how adopters can assess whether the replacement is working in their instance.
- **Reference implementation** — optional, but strongly encouraged.

A proposal is signed by its authors' Genesis-derived identities and immutable once published. Revisions are new proposals that explicitly supersede prior ones via chain-anchored reference. Proposals are indexed in a public registry the Foundation maintains, but publication does not require Foundation approval — anyone can announce a proposal via peer discovery; anyone can host their own registry.

### 13.4 Adoption is per-operator

There is no ecosystem-wide adoption vote. Each operator selects which mechanisms their instance runs via chain-anchored mechanism-selection receipts. Adoption is:

- **Per-mechanism.** An operator may run the reference mesh transport but a proposed alternative detection algorithm.
- **Chain-visible.** Which mechanisms an operator is running is a chain fact peers can verify.
- **Reversible.** An operator can revert at any time by publishing a new mechanism-selection receipt.
- **Interoperability-bounded.** Mechanisms that require both peers to run them (mesh transports, cryptographic protocols) only work when both peers have adopted them. Peer-independent mechanisms (detection, reputation computation, local presentation) work regardless of what other peers are running.

A mechanism displaces its predecessor by being adopted by operators who prefer it. The Foundation's reference implementation is one adopted set among many possible sets; it is called "reference" because it is what the Foundation supports and recommends as a starting point, not because it is the only legitimate implementation.

### 13.5 The Foundation's role

The Foundation publishes the invariants precisely. Maintains reference implementations. Curates a discoverable registry of proposals. Contributes to proposal discussion as its own chain-anchored contributions.

The Foundation does *not* gatekeep. Does not require permission to publish proposals. Does not centralize adoption decisions. Does not claim authority over what operators run. Its authority is limited to two things: preserving the invariants in its own reference implementation, and the quality of its own contributions to the ecosystem.

When a proposed mechanism is better than the reference, the Foundation can adopt it into the reference. When it isn't, operators can still run it if they prefer. The Foundation's opinion carries no more weight in adoption decisions than any other peer's opinion, except to the extent operators voluntarily trust the Foundation's judgment.

### 13.6 Why this shape

Fixed software products atrophy. Frameworks of invariants around composable mechanisms evolve. The substrate is built as the latter because the interesting problems — detection, reputation, cognition, coordination — are open and will remain open. Locking any particular solution into place would prevent the ecosystem from getting better at them.

The invariants are what hold the substrate together across time and across implementations. The mechanisms are where the work happens. The framework's job is to make sure both properties coexist: a stable substrate that peers can rely on, and evolving mechanisms that let the ecosystem discover better ways of doing things.

The invitation is real. If you build a better mechanism, publish a proposal, publish a reference implementation, and see who adopts it. The plumbing to make that work exists. Come use it.

---

## Part XIV — Open Design Decisions

Extracted throughout:

1. **Trajectory attribution granularity.** How fine-grained are trajectory attributions? Per-conversation? Per-session? Per-project? Trade-off between precision and computational cost.

2. **Pattern accumulator category taxonomy.** What action categories do pattern accumulators track? How are categories defined so they resist evasion via minor recategorization?

3. **Escalation thresholds.** What signals trigger Layer 2 to escalate from Allow → Allow with notice → Require attestation → Deny? Threshold calibration is difficult and consequential.

4. **Officer finding composition weights.** How do findings from multiple officers combine? Simple maximum, weighted sum, ensemble methods?

5. **Attestation time bounds.** How long does an attestation remain valid? Trade-off between operator convenience and preventing stale attestations.

6. **Layer 4 review cadence.** How often does the Cartographer/officer trajectory review run? Continuous, periodic, event-driven?

7. **Fallback behavior.** When the Cartographer cannot produce trajectory attribution in time for the gate's decision, what's the fallback? Fail closed (deny) or fail open (Layer 1 only)?

8. **Operator surface design.** How does the Regent present Layer 2/4 warnings to the operator? What's the interaction flow for attestation?

9. **Cross-operator signal for coordinated attacks.** Whether and how to expose signals about coordinated multi-operator attack patterns without compromising sovereignty.

10. **Backward compatibility.** Existing deployments run Layer 1 only. How do they migrate to four-layer without breaking existing trajectories that were fine under Layer 1?

---

## Part XV — Companion Documents

- `docs/ARCHITECTURE-2026-07.md` — canonical architecture; Part I §3 (three substrate layers) and Part IV (cognitive layer) are the foundations this document extends. Part VII Principle 6 (a tool is intent, crystallized) is the philosophical anchor.
- `docs/whitepaper-v9.md` — public thesis. §5.3 currently describes constitutional rules atomically; a follow-on revision should extend §5.3 to name Layer 2/3/4 explicitly, and §12 (Threat Model) should name decomposition attacks with the four-layer defense cited from this note.
- `docs/design/DISTRIBUTED-KNOWLEDGE-COMMONS-2026-07.md` — the reputation dynamics that make cross-operator coordination detection partially work.
- `docs/design/REGENT-COMPARTMENTALIZATION-2026-07.md` — the Regent's role in Layer 3 (cognitive-layer restraint) composes with its role in identity compartmentalization; the same cognitive advocacy applies.
- `docs/design/SOFTWARE-INTEGRITY-ATTESTATION-2026-07.md` — attestation of correct implementation of the four-layer stack itself. If a build claims four-layer enforcement, the software integrity attestation is what makes that claim verifiable.
- `docs/design/PEER-DISCOVERY-AS-OUTREACH-2026-07.md` — cross-operator signal for coordinated attacks depends on peer discovery infrastructure.

---

*Constitutional enforcement is the atomic gate. Nothing in this document changes that or claims to strengthen it. What this document describes is a separate capability — best-effort detection and situational awareness — that helps operators and the substrate see multi-action patterns that atomic evaluation is structurally blind to. Detection is additive, model-informed, corrigible over time, and honest about its limits. When detection catches something, the operator gains awareness they wouldn't otherwise have. When detection fails, atomic enforcement's guarantees are unchanged. Both capabilities exist; both are useful; treating them as distinct keeps each honest about what it delivers.*
