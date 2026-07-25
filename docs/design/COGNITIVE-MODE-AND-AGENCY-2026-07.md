# Cognitive Mode and Agency Composition

**Document type:** Tier 2 canonical elaboration. Elaborates KEEL §III.21 (priority-weighted cognitive context), §III.9/§III.10/§III.16 (human control, precedent, autonomous scope), §II.17 (cognitive discipline sandwich), and Part V. Adds Layer B canonical claims about the coupling of cognitive posture to agency envelope.

**Date:** 2026-07-25. Status: Draft.

**Motivation:** The substrate carries cognition and agency as two planes that do not compose. The cognitive input plane governs what the Regent thinks with; the gate and delegation model govern what she may do. Nothing declares the relationship. The consequence is that cognition produces labels nothing acts on, and agency executes without a declared deliberative posture behind it. This document names the coupling.

**Composes with:** `COGNITIVE-ACT-ACCOUNTING-2026-07.md` (whose `mode` and `flow_ref` fields refer to this layer), `COGNITIVE-INPUT-PLANE-2026-07.md` (Step 1 cycle invocation triggers, from which mode derives), `EXECUTION-AUTHORITY-MODEL-2026-07.md` (the three-part autonomous action test), `COGNITIVE-DESIGN-PRINCIPLES-2026-07.md` §#11 (conversation mode / stewardship mode — the embryo of this layer), `REGENT-ORCHESTRATION-ARCHITECTURE-2026-07.md`.

---

## 1. The problem

Two planes, no declared relationship between them.

The **cognitive plane** composes what the Regent reasons with: seven source classes at four priority tiers, chain-anchored per cycle via `cognitive:input:composed`. The **agency plane** governs what she may do: active delegation scope, gate evaluation, the three-part autonomous action test, precedent accumulation.

They touch nowhere. Delegation state enters the cognitive context as a Class 7 substrate-state field — the Regent can *read* what she is licensed to do — but nothing in the reverse direction. Nothing says that a given cognitive posture licenses a given envelope of action, or that acting outside an envelope should have been preceded by a different kind of thinking.

Three consequences, all currently live:

- **Cognition that nothing consumes.** The self-observer produces confabulation-gap findings; the input plane produces composed context. Neither changes what the Regent is licensed to do in the cycle they describe.
- **Agency without declared deliberation.** The gate checks authority. It does not check that the act was reached through a posture appropriate to its consequence. A routine act and an irreversible one traverse the same cognitive path.
- **No unit boundary.** Without a standing posture, a sequence of acts has no declared start or end, so "which operations, in which order" has nothing to be ordered *within*.

`COGNITIVE-DESIGN-PRINCIPLES` §#11 already gestures at the fix — it names **conversation mode** and **stewardship mode**, with a severity-gated interrupt threshold governing the transition. That is this layer in embryo. It was never developed, and nothing else in the corpus builds on it.

---

## 2. Mode is a coupled pair

**A mode is not a cognitive state that happens to have permissions attached. It is one thing with two faces: a cognitive posture and an agency envelope, declared together.**

```
Mode = (posture, envelope)

posture  — what kind of thinking this is: what enters context, at what priority,
           what operations are recognizable, what rigor the deliberation carries
envelope — what may be done from here: which verbs, under which precedent,
           at what gate severity, with what escalation threshold
```

The invariant that makes this a composition rather than a pairing:

> **You cannot be in a cognitive mode you lack the agency for, and you cannot exercise agency outside the mode that licenses it.**

Both halves matter. The first prevents deliberating toward acts that were never available — the Regent planning a remediation she has no delegation to perform, which is precisely the failure the Claim Verifier was built to catch after it happened twice in one day. The second prevents acting past the posture that reached the act.

This makes the gate and the input plane two views of one structure rather than two subsystems that happen to run in the same cycle.

---

## 3. The four modes

Mode is **witnessed, not declared per cycle.** It derives from three things already on chain: the cycle invocation reason (`COGNITIVE-INPUT-PLANE` Step 1 records it in `cognitive:input:composed`), the active delegation scope, and the severity context.

| Mode | Invocation trigger | Posture | Envelope |
|---|---|---|---|
| **Conversational** | operator directive | Dialogic. Operator directive at Tier 3; interrupt threshold high — only Critical findings break in. Deliberation rigor D1 by default. | Narrow: respond, ask, observe. Consequential acts require explicit operator turn — she talks, she does not act. |
| **Stewardship** | chain event / officer finding | Diagnostic. Officer findings at Tier 2, precedent at Tier 1. Pattern-matching against prior remediation. Rigor D2 when a Decision is implied. | Precedent-bounded: the three-part test applies in full. Known pattern plus known context acts; novelty escalates. |
| **Committed** | scheduled commitment firing | Fulfilment. The commitment receipt itself is the highest-priority context; the question is *what did I promise and is it still right*. | Pre-authorized by the commitment receipt — agency was granted when the promise was made and signed. Narrower than stewardship, not broader. |
| **Reactive** | circuit-breaker transition, escalation | Triage. Substrate state dominates; degraded-capability signals foregrounded. Rigor D3 for anything consequential. | **Narrowed.** Scope reduces with breaker level: L1 elevated observation, L2 rate-limited, L3 soft arrest at scope, L4 hard arrest. |

Two properties worth stating explicitly.

**A cycle is in exactly one mode.** These are mutually exclusive standing postures, not phases of a loop. The external Generative Loop's five phases are not modes — see §5.

**No mode grants more than the operator granted.** Every envelope is a *subset* of active delegation, and Reactive is strictly narrowing. This layer makes the existing grant legible and couples it to posture; it creates no new authority. P9 is untouched.

---

## 4. Transitions are the coupling rules

Mode transitions are where cognition and agency actually compose, because a transition changes both faces at once.

The corpus already specifies one transition rule and does not recognize it as such: §#11's severity-gated interrupt threshold is exactly Conversational → Stewardship, gated on finding severity. The others follow the same shape.

| Transition | Gate |
|---|---|
| Conversational → Stewardship | Critical-severity finding crosses the interrupt threshold |
| Stewardship → Conversational | operator directive arrives; findings queue |
| any → Committed | commitment receipt fires; returns to prior mode on fulfilment or expiry |
| any → Reactive | circuit-breaker transition, or escalation raised by any officer |
| Reactive → any | breaker reset — **operator ceremony at L3 and above** |

Two things follow that were not previously available.

**Transitions are witnessed events with their own receipt.** `cognitive:mode:entered:<mode>` carries the prior mode, the triggering signal, and the resulting envelope hash. A mode transition is a change in what the substrate may do, which makes it exactly the class of event §III.19 says must leave evidence.

**Unexplained transitions are detectable.** Stewardship → Reactive with no circuit-breaker receipt is an anomaly of the same shape as the silent drop in `COGNITIVE-ACT-ACCOUNTING` §3.3: not a failure proof, but a detectable gap between posture and its stated cause. *Silence is the enemy.*

---

## 5. Flows

A **flow** is an ordered sequence of Deliberations sharing a mode and a frame, with a declared entry and exit. Flows are the unit the composition operator operates on — the thing "which operations, in which order" orders.

Modes bound flows: a flow cannot span a mode transition, because the envelope changed underneath it. A transition mid-work closes the current flow and opens a new one, which is the correct behavior — work interrupted by an escalation is not the same work resumed.

**This is where the external Generative Loop lands.** DISCERN → MODEL → INQUIRE → CREATE → ENACT is not a mode and not an ontology. It is **one candidate flow signature**: a hypothesis that acts recur in that order within a posture. It ships in the seed library alongside the act signatures, carrying `origin: external_taxonomy`, and match rate against real flows tests it. If ZeroPoint's actual stewardship flows run DISCERN → ENACT → INQUIRE, that is a finding about this substrate, and it is the kind of finding the article's own method could not produce.

Flow signatures compose the same way act signatures do, one level up: declared per mode, matched deterministically, with unmatched flows as the residual that proposes new shapes.

---

## 6. Where the article's AGENCY family lands

The comparative analysis found AGENCY the least-covered family, with Motivation, Emotion and Courage refused. That reading was correct about internal states and wrong about the structure. Five of six land cleanly here — **as properties of the mode/envelope coupling rather than as things the Regent has.**

| Primitive | Where it lands | Witnessed as |
|---|---|---|
| Motivation | mode entry trigger — *why this cycle exists* | cycle invocation reason |
| Boundary | the envelope itself | active delegation ∩ mode envelope |
| Identity | invariant across modes — persona is Form-invariant per §XIV.9 | Genesis-rooted actor ID, unchanged by transition |
| Courage | the escalation threshold — **inverted, and correctly** | the novelty point in the three-part test where the substrate stops rather than proceeds |
| Strategy | flow shape across modes over a trajectory | sequence of flows sharing a Trajectory |
| Emotion | **still refused** — §III.24 | — |

The article makes AGENCY the internal power source of the loop. The substrate's answer, now sayable: **agency is external in origin and internal in exercise.** The operator grants; the Regent exercises within. Mode is where the grant becomes exercise, and that is the composition point the two frames were talking past each other about.

Courage deserves the note. The article treats willingness to act under novelty as a virtue to install. The substrate treats stopping under novelty as the load-bearing behavior. Both name the same threshold; they differ on which side of it is correct. That disagreement is a design position, and this document holds the substrate's.

---

## 7. Minimum slice

Consistent with the accounting doc: **the first slice adds no new Regent behavior.**

> **m0 = derive and record mode.** Cycle invocation reason already lands in `cognitive:input:composed`; delegation scope and severity are already readable. Compute mode, emit `cognitive:mode:entered:<mode>` on change, populate `Deliberation.mode`.

That is a pure derivation over existing state. It immediately gives act signatures their disambiguating scope, gives flows their boundaries, and produces the transition record that §4's anomaly detection needs.

Sequence: **m0** (mode derived and recorded) → **m1** (envelope declared per mode and checked against the gate — assert the §2 invariant, log violations without enforcing) → **m2** (flow boundaries from mode transitions; flow signatures matched) → **m3** (envelope enforcement — the mode invariant becomes a gate condition rather than an observation).

**m1 logs; m3 enforces.** The gap between them is deliberate and is the corpus's standing posture: instrumentation before remediation. m3 is not proposed for commitment — it changes what the gate does, and that decision should be made from m1 evidence about how often posture and envelope actually diverge.

---

## 8. Verifiable outcomes

- **MA1** — Mode is derivable for every cycle from existing chain state, with no new emission behavior.
- **MA2** — Every mode transition produces a receipt carrying prior mode, triggering signal, and resulting envelope hash.
- **MA3** — A transition with no corresponding triggering signal is detected deterministically.
- **MA4** — For every cycle, the acts emitted are a subset of the mode envelope; divergences are countable (m1) before they are blocked (m3).
- **MA5** — No mode envelope exceeds active delegation at any point, under any transition sequence.
- **MA6** — Reactive mode strictly narrows: for each breaker level, the envelope is a subset of the level below.
- **MA7** — Flow boundaries align with mode transitions; no flow spans a transition.

---

## 9. Open positions

- **Are four modes enough?** Constructive (multi-act work toward a deliverable — WorkArc territory) and Investigative (diagnosis with unknown cause) are both real postures not derivable from current triggers. They would need a declared entry rather than a witnessed one, which weakens the witnessed-mode property. Held pending m0 evidence about whether stewardship is doing double duty.
- **Envelope authorship.** Whether envelopes are declared per mode in Layer B, or derived as a function of (delegation, severity, breaker level), is unresolved. Derivation is cleaner and avoids a second place where authority is written down; declaration is more legible to the operator. Leaning derivation, because two sources of authority truth is the failure §II.13 P8 exists to prevent.
- **Committed-mode scope.** A commitment made under a delegation that has since been revoked: does the mode still fire with a narrowed envelope, or not fire at all? Forward-only recovery suggests the commitment stands as a chain fact while its envelope evaluates fresh — but that means a commitment that cannot be fulfilled, which needs its own receipt.
- **Does this warrant an axiom?** The §2 invariant — cognition and agency are coupled per mode — is a claim about what the substrate may do, which is axiom-shaped. Held pending m1 evidence, per *config reflects today, not roadmap*.

---

## 10. Non-goals

- **Not new authority.** Every envelope is a subset of active delegation. Reactive strictly narrows. Nothing here lets the Regent do anything she could not do before; it declares when she may.
- **Not an autonomous goal source.** Motivation lands as *mode entry trigger*, and every trigger is exogenous — operator directive, chain event, commitment the operator signed, breaker transition. §III.9 is untouched.
- **Not affect modeling.** Emotion remains refused under §III.24. The mode taxonomy is about posture and authority, not internal states.
- **Not replacing the gate.** The gate remains the hard boundary. This layer adds a coupling the gate can eventually check (m3), and until then only observes.
- **Not adopting the Generative Loop.** It enters as one candidate flow signature among others, testable and removable by match rate.
