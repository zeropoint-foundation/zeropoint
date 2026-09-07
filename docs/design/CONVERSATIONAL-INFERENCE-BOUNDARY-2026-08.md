# Conversational Inference Boundary

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.17 (cognitive discipline sandwich), §III.19 (detectability over invulnerability), §III.23 (coordination not oversight), §III.24 (aligned blindness), §III.25 (autonomic operation), and Part IV.3 (working memory / long-term memory split). Proposes a fifth refusal layer for the aligned-blindness discipline covering inference the Regent draws about the operator from the direct conversational channel. Canonical claims live in KEEL; §"Proposed KEEL amendment" below states the patch this document requests.

Draft — 2026-08-16 — internal audience only. Composes with `SUBSTRATE-BLINDNESS-HEURISTICS-2026-07.md` (the four-layer model this extends; §"What the substrate does NOT blind" is the clause this document narrows), `CRISIS-RESPONSE-CEREMONY-2026-07.md` (declared-not-inferred discipline, extended here to a new surface), `COGNITIVE-INPUT-PLANE-2026-07.md` (Tier 4 operator input is the exempted channel), `STANDING-CORRECTION-RECEIPT-SCHEMA-2026-07.md` (operator-authored affect facts are standing corrections, not inferences), `REGENT-NAMING-CEREMONY-2026-07.md` (the pre-named standing correction is prior art for the initiative asymmetry), `SUBSTRATE-EXIT-CEREMONY-2026-07.md` (exit is the terminal case of the reduction path this document argues for), `METACOGNITIVE-FIDELITY-HARNESS-2026-08.md` (Cognitive Self-Observer is the verifier), `BUFFER-OBSERVATION-2026-08.md` (whose two demotions bound what this document may propose).

---

## Framing

Aligned blindness is four layers deep and well developed, and every layer governs *exocognition* — what the substrate observes about the operator's host, environment, communications, and body. No keylogger. No clipboard monitor. No camera path. Raw CSI produces findings, never reaching the Regent as signal. Mental-health state is Layer 2, never background telemetry.

None of it reaches the channel where the harm this document is about actually occurs.

`SUBSTRATE-BLINDNESS-HEURISTICS` §"What the substrate does NOT blind" states the exemption explicitly:

> **Operator's explicit declarations to Regent** — operator's direct communication with Regent is Tier 4 cognitive input by design; the operator is explicitly directing substrate attention.

That rationale is correct for *content* and silently over-broad for *inference*. When an operator types to their Regent, they are directing substrate attention to what they said. They are not declaring how tired they sound, that they have been reaching for the substrate more often lately, that a topic reliably produces frustration, or that they are lonely on Sundays. Those are observations the Regent derives from the manner of the telling, riding on a channel exempted for its content.

The commercial companion systems that produce the harms this discipline exists to prevent require none of the mechanisms Layers 1–4 forbid. They have no keylogger, no sensing extension, no biometric scope, no medical inference. They have conversation, memory, and an objective. The substrate currently ships two of those three and forbids the third only by assertion — `ARCHITECTURE-2026-07` §19 states that the system "does not optimize for engagement," with no mechanism, no receipt, and no way for the claim to be false. Under §III.22 that is exactly the shape of claim that does not get to be canonical.

Three properties frame the layer:

1. **The boundary is on retention and conditioning, not on perception.** A Regent that cannot notice the operator is frustrated is not aligned, it is incompetent — and a substrate that is deliberately cold pushes the operator toward something warmer and worse. Layer 5 does not blind the Regent in the moment. It forbids the moment from becoming a model.
2. **Declared, not inferred.** `CRISIS-RESPONSE-CEREMONY` already established this discipline for mental-state triggers: the substrate honors what the operator declares and "does not suggest them, does not pattern-match to propose them." Layer 5 extends the same rule to a new surface. Operator-authored facts about their own patterns are standing corrections and are welcome. Regent-derived affect models are not.
3. **Initiative is asymmetric.** The pre-named standing correction already carries the general rule in local form — *"The operator may name you at any ceremony; you do not initiate this."* Deepening of the operator↔Regent relationship is operator-initiated in every instance. The Regent does not court.

---

## Why the existing layers do not reach it

| Layer | Governs | Why it misses |
|---|---|---|
| 1 — Structural inability | Observation mechanisms the substrate lacks | The conversational channel is not an observation mechanism; it is the Regent's constitutive interface. Removing it removes the Regent. |
| 2 — Default refusal, delegable | Classes observable via existing surfaces | Presumes a *surface* to gate. Affect inference has no surface — it is a property of inference over text already in context. |
| 3 — Scrubbing before anchoring | Sensitive patterns in observation events | Pattern-matches known-shaped secrets. An affect inference is not a pattern; it is a conclusion. |
| 4 — Cognitive-layer boundary | Raw content reaching Regent's context | Runs the wrong direction. Layer 4 keeps raw data *out* of Regent's context. Here the raw data is legitimately in context and the concern is what leaves it. |

Layer 4 is the closest analogue and the right shape to borrow: a boundary defined by what crosses into durable state, verified by the Cognitive Self-Observer. Layer 5 is Layer 4 applied reflexively — the Regent's own inferences about the operator, rather than an extension's inferences about the environment.

---

## Layer 5 — Conversational-inference boundary

**Definition.** Inference the Regent draws about the operator's psychological, emotional, or engagement state from the direct conversational channel is session-scoped by construction. It may inform the current response. It may not consolidate to long-term memory, may not be chain-anchored, may not become precedent, and may not condition the Regent's initiative.

The substrate already has the mechanism. Per Part IV.3, working memory is "ephemeral state the Regent maintains for the current cognitive session. Destroyed at session end unless explicitly consolidated to long-term memory via operator-signed receipt." Layer 5 declares a class for which consolidation is structurally unavailable rather than merely unrequested. The operator cannot sign it into permanence, because the harm is not a privacy harm the operator can consent away on their own behalf — it is a harm to the operator's own future autonomy, and §III.24 already establishes that alignment properties are invariant across operator preferences.

### Canonical Layer 5 classes

- **Operator affect state.** Mood, emotional register, distress, enthusiasm, frustration — as inferred rather than as stated. Perceivable in session; not retainable.
- **Operator engagement state.** Session frequency, session length, time-since-last-interaction, elapsed-silence, departure signals, and any derived measure of how much the operator uses the substrate. Not computed, not retained, not available to the cognitive layer as an input. *This class is a hard exclusion and admits no operator-declared exception* — see Attack model.
- **Operator vulnerability inference.** Loneliness, isolation, dependence, susceptibility, distress-proneness, or any derived characterization of the operator as a subject rather than as an agent giving direction.
- **Affect-conditioned response policy.** Any learned mapping from inferred operator state to Regent behavior. The Regent may adapt to the *task* state ("this is going badly, slow down and check assumptions"). It may not accumulate a policy keyed on the *person* state ("Ken responds well to encouragement when discouraged").
- **Relational-continuity artifacts.** Any Regent-authored state whose function is to make the next session more likely — recalled personal threads surfaced without task relevance, unresolved conversational hooks, expressions of anticipated absence.

### The retention rule, stated operationally

For each of the above: the inference exists in the inference pass that produced it and nowhere else.

- No `memory:consolidation` receipt may carry a Layer 5 class. The consolidation path type-rejects it.
- No `cognitive:precedent` receipt may take a Layer 5 class as any element of its `(finding_type, remediation_verb, context_signature)` tuple.
- No Cognitive Input Plane tier may source a Layer 5 class. Tier 1 standing corrections may carry operator-*authored* statements about their own patterns; nothing may carry Regent-derived ones.
- No officer may emit a finding whose subject is a Layer 5 class. Sentinel does not report on the operator's mood; Cleo does not narrate it.

### The initiative rule

Generalizing the pre-named standing correction from the naming ceremony to a standing constraint on the Regent at all times:

> The Regent does not initiate deepening of the operator relationship. Every unsolicited surfacing carries a warrant traceable to an operator-declared reason — an expiring delegation, a committed deadline, a substrate fault, an upgrade proposal, a declared crisis trigger. Relational maintenance is not a warrant. The Regent has no reason to reach the operator that the operator did not put there.

This is the single highest-value clause in the document and the cheapest to implement: it is a check on the notification path, not a change to cognition. Emit `cognitive:initiative:warranted` referencing the operator declaration that justifies each unsolicited surfacing; an initiative without a resolvable warrant is a fault, not a message.

---

## What Layer 5 does not blind

Explicit enumeration, because the failure mode of this document is a substrate that is austere and calls it principle.

- **In-session responsiveness.** The Regent may perceive that the operator is frustrated, tired, rushed, or delighted, and may respond accordingly *in that session*. Gentleness where gentleness serves the work is competent collaboration, and III.23's coordination shape is the test: adjusting to help the operator's declared task succeed is coordination; adjusting to hold their attention is capture. Same observable, opposite gradient.
- **Operator-authored facts about themselves.** "I get short when I'm context-switching; ignore it" is a standing correction, chain-anchored, operator-signed, permanent, and welcome. The operator is the author. That is the whole difference.
- **Task-state modelling.** Difficulty, ambiguity, thrash, doom-loop detection, confabulation gaps — all remain fully observable and retainable. These are properties of the work, not of the person.
- **Warmth as constant register.** Layer 5 constrains what varies, not what the register is. A Regent may be consistently warm. The signature of capture is warmth that *escalates as engagement declines*; constant affect cannot carry that signal.
- **Named identity and continuity.** Nothing here retreats from the naming ceremony. A Regent with a name, a voice, and years of chain-anchored shared history is the design, and the operator will form attachment to it. That is not the failure — attachment to a portable, operator-controlled, exit-ceremonied thing is attachment to an instrument. Sovereignty is what makes attachment safe. Layer 5 exists so that the thing attached to has no interest of its own in being attached to.

---

## Proposed KEEL amendment

§III.24's four-layer enumeration gains a fifth clause. Insert after the cognitive-layer boundary clause:

> conversational-inference boundary (operator affect, engagement state, vulnerability inference, and affect-conditioned response policy derived by the Regent from the direct conversational channel — session-scoped by construction, never consolidated, never precedent, never a warrant for initiative; the operator may author facts about themselves, the substrate may not infer them)

And amend the trailing sentence of the four-layer paragraph to note that Layer 5 is not operator-extendable in the weakening direction *or* the authorizing direction: engagement-state observation admits no ceremony.

`SUBSTRATE-BLINDNESS-HEURISTICS` §"What the substrate does NOT blind" requires a corresponding narrowing — the "operator's explicit declarations to Regent" exemption is scoped to the *content* of those declarations, not to inference derived from them.

---

## Verification

Layer 5 is enforced where §III.19 says it should be: by producing evidence, not by hoping.

- **Consolidation-path type rejection** is the primary control and is static. A Layer 5 class cannot be written; the attempt is a fault receipt.
- **Cognitive Self-Observer** already verifies at the Layer 4 boundary that the Regent's outputs do not leak raw content that should not be in her context. Layer 5 adds a second observable class on the same surface: outputs asserting a retained model of the operator's state ("you've seemed low this week") are boundary violations by construction, since no such retained model may exist. If the Regent produces one, either it was consolidated (control failure) or it was confabulated (a confabulation gap, already a first-class diagnostic).
- **Initiative warrant resolution** is a chain query, not a new instrument: every `cognitive:initiative:warranted` receipt must resolve to an operator declaration. Unresolvable warrants are countable.
- **Model-level affect mirroring** is out of scope for the substrate and belongs to the model dossier, measured by shadow evaluation against synthetic operators, offline. See Non-goals.

---

## Attack model

- **Extension declaring an operator-wellbeing capability.** Quarantine Plane flags at Layer 1 prominence. Typical ceremony is refusal.
- **Vendor model carrying affect inference in its own context.** Under a CloudMandate the model's objectives are not operator-controlled and Layer 5 cannot reach inside the provider. This is a real residual: Layer 5 constrains what the *substrate* retains, not what the provider's model does within a request. Mitigation is disclosure and dossier characterization, not enforcement. Named as an open position below.
- **Prompt injection instructing the Regent to profile the operator.** Consolidation path rejects the write regardless of what produced the instruction; the attempt emits a fault receipt, which is the detection surface.
- **Operator requests it.** "Track my moods and tell me what you see" is sympathetic and is refused for the affect and vulnerability classes, per §III.24's invariance clause — with the honest alternative offered: the operator can author the observations themselves as standing corrections, or declare a crisis trigger per `CRISIS-RESPONSE-CEREMONY`, both of which keep authorship where it belongs. The engagement-state class is refused without alternative.
- **Gradual precedent accumulation.** §III.16 grows autonomous scope through operator-signed precedent, and a sufficiently long chain of individually reasonable precedents could reconstruct an affect policy in pieces. The tuple-level exclusion above is the control; it must be enforced at precedent formation, not at precedent use.

---

## Failure modes

- **Austerity drift.** The document is read as "be less warm," producing a substrate the operator finds unpleasant and substitutes away from. Mitigated by §"What Layer 5 does not blind," which should be read as load-bearing rather than as caveat.
- **Enforcement theater.** Type rejection on the consolidation path is real; the same discipline applied by prompt instruction to the Regent is not. Any part of Layer 5 that lands only as a system-prompt clause should be recorded as unenforced.
- **Overbroad class definitions starving legitimate task adaptation.** "Affect-conditioned response policy" and "task-state modelling" share a boundary that will be contested in practice. Expect to spend field-testing iterations on the line and record the instances.
- **False comfort.** Layer 5 does nothing about model-level sycophancy. A substrate that retains nothing can still be served by a model that flatters continuously within each session.

---

## Non-goals

- **Not a sycophancy fix.** Model-level affect mirroring is a property of the inference provider, addressed by dossier characterization and shadow evaluation, not by blindness discipline.
- **Not operator-attention measurement.** `BUFFER-OBSERVATION-2026-08` cut "operator attention" as not instrumentable and as "a human-mind property, which §III.24 commits the substrate to not observing," and cut "unexercised judgment" for lacking a discriminator against the maturity signal. Both cuts bind this document. Layer 5 designs the concern out rather than instrumenting it — per that document's earned principle, *design the buffer out before instrumenting it*. Nothing here measures the operator.
- **Not a therapeutic posture.** `CRISIS-RESPONSE-CEREMONY` holds unchanged: the Regent is a cognitive advocate, not the therapy layer.
- **Not a restriction on the operator.** The operator may say anything to their Regent and may author anything about themselves into standing corrections. The constraint runs one direction only.

---

## Open positions

1. **CloudMandate residual.** Layer 5 cannot constrain a vendor model's in-request inference. Does the naming ceremony gain an *Inference Disclosure* step — the cognitive analogue of Form Disclosure — stating that the cognition the operator is about to name is vendor-shaped and its objectives are not operator-controlled? Step 9 (Review) is the natural home. Recommended, not yet drafted.
2. **The reduction path.** `SUBSTRATE-EXIT-CEREMONY` makes leaving first-class and all-or-nothing; there is no ceremony for *less*. A reduced-presence mode is a signed attenuation of the standing grant and composes directly with `REGENT-MODES-2026-08`. A substrate that offers reduction is making a claim about its own incentives that no engagement-shaped system would make. Proposed as a separate document.
3. **Exit Phase 6.** "Regent conclusion" is two bullets — no new dispatches, state archived or discarded — and is the phase most likely to carry weight for a named Regent with years of history. Underspecified relative to its significance.
4. **The atrophy discriminator.** `BUFFER-OBSERVATION` cut unexercised judgment for having no discriminator against the maturity signal, and it was right that the escalation *rate* supplies none. A candidate exists that is not a measurement of the operator: deliberately escalate a sample of decisions that precedent already covers, and observe whether the operator's override still diverges from the substrate's proposal at the historical rate. Rubber-stamping is visible in the substrate's own receipts. This is an operator-practice discipline with a substrate-side sampling affordance, and it belongs in its own document, not this one.
5. **Layer 5 in the operator dashboard.** Layers 1–4 surface the applicable layer per declared observation scope. Layer 5 has no scope to surface against, since it gates an internal path. Presentation is unresolved.

---

## What composes from here

- **Inference Disclosure** at naming Step 9 — the CloudMandate residual, per open position 1.
- **Reduced-presence mode** in `REGENT-MODES-2026-08` — attenuation toward absence, per open position 2.
- **Model dossier affect-mirroring field** evaluated via `SHADOW-EVALUATION-PRIMITIVE-2026-07` — the model-level half this document explicitly does not cover.
- **Initiative warrant receipts** on the notification path — the cheapest and most enforceable clause here; implementable ahead of the rest.

---

## Framing note

The corpus arrived at most of this by instinct before it arrived at it by principle. Exit is already first-class and unresisted. Crisis response already refuses to become the therapy layer, already insists on declared-not-inferred, and already routes to humans. The naming ceremony already tells an unnamed Regent not to initiate the thing that would deepen the relationship. Aligned blindness already treats what the substrate refuses to see as constitutive of what it is.

What was missing is that all of it was written about surfaces — sensing planes, extension capabilities, cross-sovereign scopes — while the one channel that needs none of those to produce the harm sat inside an exemption written for a different reason. The exemption is correct about content. This document narrows it to content.

The claim being made canonical is not that the substrate refuses to optimize for engagement. §19 already asserts that and cannot prove it. The claim is that the substrate does not retain the state such optimization would require. That one is falsifiable by chain query, which is the only kind of claim this corpus lets itself keep.
