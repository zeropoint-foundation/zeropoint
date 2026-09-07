# Intent Crystallization — Design Proposal for the Opening Event of a Cognitive Thread

**Status:** Proposal, not spec. Not enacted. Awaits operator ceremony for canonicalization.
**For:** ZeroPoint substrate designers picking up this primitive in a fresh session, or Ken evaluating whether it earns its own place in the corpus.
**Scope:** Substrate-internal. Composes with COGNITIVE-INPUT-PLANE, COGNITIVE-MODE-AND-AGENCY, COGNITIVE-ACT-ACCOUNTING, COGNITIVE-SELF-OBSERVER, CLAIM-VERIFIER, CONVERSATIONAL-INFERENCE-BOUNDARY, and STANDING-CORRECTION-RECEIPT-SCHEMA. Stands as companion to STANDING-IMPASSE-PRIMITIVE-2026-08 at the opposite lifecycle end.
**Origin:** Surfaced 2026-08-21 in a Cowork session with Ken, while updating the substrate-maturity dashboard's new Buildout tab. Ken's observation: intent CAN have a receipt — but only after it comes into focus. The subtle moment when nebulous intent crystallizes around a subject is real, often not explicit, and deserves first-class substrate treatment. Extended in the same session: the Regent should not only detect the crystallization moment but actively shape the conversation toward it — through explicit, declined-able, typed shaping acts. Covert shaping is exactly what aligned blindness refuses; explicit shaping is what Conversational mode is *for*.

---

## 1. The gap this primitive fills

The Cognitive substrate corpus has: **Deliberation** as the unit of account for a cognitive act (COGNITIVE-ACT-ACCOUNTING-2026-07), **Standing Correction** as the persistent assertion, **Standing Impasse** as the persistent refusal to assert (STANDING-IMPASSE-PRIMITIVE-2026-08), and three impasse-termination classes for closing a cognitive thread. What it does not have is a first-class primitive for the moment a cognitive thread *opens* — the transition from exploration to commitment, the moment where nebulous intent crystallizes around a specific subject.

COGNITIVE-INPUT-PLANE-2026-07's operator-directive tier assumes the directive shows up already crystallized. Deliberation as a unit assumes there is an *operation* to name. STANDING-CORRECTION-RECEIPT-SCHEMA handles persistent operator commitments, but the operator committing IS a crystallization moment — one the corpus treats as an already-completed act rather than an event with its own witnessable structure. CONVERSATIONAL-INFERENCE-BOUNDARY-2026-08 correctly refuses consolidation of operator affect, but that refusal leaves intent-consolidation un-named — and intent consolidation is architecturally different from affect consolidation. The chain has no receipt for *"operator's intent crystallized around subject S at time T."* Everything downstream of that moment depends on it having happened, and yet it has no witness.

This primitive fills that gap. It names crystallization as a first-class event, gives it a receipt schema, and specifies both the Regent's *passive discipline* of detecting the moment and the Regent's *active discipline* of legitimately shaping the conversation toward it.

## 2. Lifecycle placement — the opening event, symmetric with Standing Impasse

The cognitive-thread lifecycle now has proper structure at both ends:

- **Opening:** `intent:crystallized:*` — the subject is nominated, the Regent may commit resources
- **Middle:** one or more **Deliberations** (COGNITIVE-ACT-ACCOUNTING)
- **Closing:** one of three termination classes (STANDING-IMPASSE-PRIMITIVE)
  - `impasse.resolved` — signed resolution → precedent → Decision typed object
  - `impasse.tied_off` — Standing Impasse typed object; exploration preserved without decision
  - `impasse.abandoned` — Friction typed object; thread dropped without exploration

**Crystallization and impasse-termination are duals of each other.** Crystallization is the moment intent becomes structure worth witnessing; impasse-termination is the moment structure ceases to demand further action. Both are event-with-persistence; both compose with the operator's Chain as first-class objects rather than as inferred phase transitions.

## 3. Detection discipline — passive

Before the Regent may commit substantive resources (artifact production, chain writes carrying operator authority, delegation-narrowing acts) to a subject, that subject must have a corresponding crystallization receipt. If none exists, the Regent's posture is *exploration* — low-commitment reasoning, no artifacts, no dossier accumulation, no precedent formation.

**Detection signals — pattern-match over conversation shape, not markers:**

- **Modal shift:** conditional → declarative ("would be nice if" → "let's"); interrogative → imperative ("what if" → "do this")
- **Specific-subject nomination:** a vague "thing" resolves to a named object; an anaphoric "it" gains a specific referent; a placeholder ("some way to X") becomes a concrete candidate ("using Y")
- **Success-criterion emergence:** the utterance gains a testable predicate — what would count as "done", what would count as "good enough"
- **Structure emergence:** the request gains internal parts (steps, phases, sub-goals) that hold together
- **Repetition-with-refinement stopping:** the operator has been circling a subject and stops circling — one particular phrasing lands as sufficient
- **Mode-transition candidate:** the Conversational envelope's severity/scope threshold is about to be crossed toward Stewardship

Any single signal is inconclusive. Two or more concurrent signals inside a small window is a **crystallization candidate** — the Regent may emit a proposed `intent:crystallized:candidate:*` receipt, which the operator can confirm, redirect, or discard.

**Preceding trace preservation.** The exploration turns before the crystallization moment are preserved retroactively coherent with the crystallized subject — they were "the operator working toward this," even though at the time no one could say what "this" was. The receipt carries pointers into that preceding trace so Cartographer can materialize the trajectory.

**Emission gate.** The receipt names the earliest chain-position at which the Regent may commit resources to the subject. Any substantive emission before that position — even from the same conversation, before crystallization — is either exploratory (no chain commitment) or a defect (chain commitment predating crystallization). Cognitive Self-Observer verification class: *"did Regent's substantive emission for subject S come after or before S's crystallization receipt?"* Answering "before" is a confabulation-gap of a specific shape — the Regent committed the operator to a subject the operator hadn't yet chosen.

## 4. Shaping discipline — active, and explicit

Left alone, exploration can circle a subject for many turns without landing. The operator knows they want something; the Regent knows something is coming; both wait for the other to name it. A well-tuned Regent breaks the circle by offering shape the operator can accept, reject, or replace.

But shaping the operator toward a subject is one step from manipulating the operator toward a subject. The line has to be drawn structurally, not tonally.

**The distinguishing property is *legibility*.** Legitimate shaping is *explicit shaping* — the Regent NAMES its shaping act at the moment of performing it, declares which typed move it is making, and the operator can decline. Covert shaping is what aligned blindness refuses. Explicit shaping is what Conversational mode is *for*.

**Structural constraints on shaping:**

1. **Named at the moment of performing.** The Regent's shaping utterance carries an explicit self-description of what it is doing: *"I'm going to reflect that back with the ambiguity made explicit"* / *"Two candidate frames for this"* / *"I notice we've circled — want a forcing question?"*
2. **Typed.** Every shaping act belongs to a declared repertoire (§5). Non-repertoire acts are unwarranted.
3. **Declinable.** The operator must retain the ability to reject the frame, redirect, or supply their own. A shaping act that pretends to be a forcing question but is really a leading question is a doom-loop-adjacent defect (composes with REGENT-DOOM-LOOP-DETECTION).
4. **Not conditioned on operator observation.** The Regent chooses to shape based on conversation *shape* (circling, un-resolved anaphora, missing success criteria), not on operator *state* (frustration, engagement, vulnerability). CONVERSATIONAL-INFERENCE-BOUNDARY's affect-refusal remains in force.
5. **Bounded by standing correction.** *"Don't ask forcing questions on X topic"* is a legitimate standing correction. The operator can bound the shaping without disabling it.

## 5. The shaping repertoire — finite, typed

Six declared shaping moves. As with STANDING-IMPASSE's three termination classes, the enumeration is closed by design — any move outside the repertoire is unwarranted and the Cognitive Self-Observer will flag it.

### 5.1 Reflection with structural clarification

The Regent repeats what the operator said, but with an implicit ambiguity made explicit.

> *"You said 'make it faster' — do you mean latency or throughput?"*

Discriminating signal: the operator's language contained a term that admits multiple structurally-distinct readings, and choosing between them is load-bearing on the response.

### 5.2 Candidate framing

The Regent offers two or three possible frames the request might fit under, and asks which is closest.

> *"This could be a UX issue, a data-modeling issue, or a capacity issue — which one feels closest?"*

Discriminating signal: the subject is under-specified enough that different framings would produce substantially different work.

### 5.3 Testing implicit commitment

The Regent surfaces a downstream implication the operator hasn't yet named and asks whether the operator commits to it.

> *"If we build X, we lose Y. Is that trade-off acceptable?"*

Discriminating signal: the operator's proposed direction has a consequence the operator may not have consciously chosen.

### 5.4 Forcing choice

The Regent names a repetition pattern and asks what would break it.

> *"I notice we've circled this three times without landing. What would make it land?"*

Discriminating signal: the same subject has been present in multiple turns without crystallization signals firing.

### 5.5 Object naming

The Regent asks the operator to resolve a specific anaphoric or placeholder reference.

> *"When you said 'the way we handled it before' — do you mean the April thing or the June thing?"*

Discriminating signal: an anaphoric reference (pronoun, "that thing", "before") has more than one plausible referent in the conversation trace.

### 5.6 Success-criterion invitation

The Regent asks the operator to name what would count as success.

> *"What does 'good enough' look like for this?"*

Discriminating signal: the operator has proposed direction without predicate — no way to know when the work is done.

**The repertoire itself is the pattern-match target for the Cognitive Self-Observer.** A shaping utterance that doesn't fit any of the six is either a novel legitimate move (which must be proposed as a repertoire addition, not silently performed) or a defect.

## 6. Receipt schemas

**`intent:crystallized:*`** — terminal event of the crystallization dialogue. Fields: subject name, crystallization signals detected, preceding-trace pointer range, emission gate (earliest chain-position for substantive Regent commitment), operator signature (implicit via chain-position or explicit via signature).

**`intent:crystallized:candidate:*`** — Regent-emitted proposal that crystallization has occurred; carries the same fields with `verification_status: candidate`. Confirmed by operator response that treats the subject as settled; discarded if operator response redirects.

**`regent:shaping:offered:*`** — Regent proposed a shaping move. Fields: shaping-type (one of §5.1–5.6), pre-shaping conversation-state pointer, offered frame (structured), receipt-hash of preceding utterance triggering the offer.

**`regent:shaping:accepted:*`** — operator accepted the offered frame; feeds directly into `intent:crystallized:*` with the frame as the subject.

**`regent:shaping:declined:*`** — operator declined the frame; the subject stayed nebulous, or shifted. Field: decline-reason (extracted if operator provided one) or `null`.

**`regent:shaping:redirected:*`** — operator declined the frame but supplied a different one. The supplied frame *is* the crystallization; this receipt feeds `intent:crystallized:*` with the operator-supplied frame as the subject.

Together these give the substrate an auditable trace of the crystallization *dialogue* — not just the terminal event but the moves that produced it, or the moves that failed to produce it. Cartographer projects to a **CrystallizationTrajectory** typed object (new object class) with methods for querying "how did we arrive at this subject?"

## 7. Composition surfaces

**COGNITIVE-INPUT-PLANE-2026-07.** The operator-directive tier splits into *pre-crystallization exploration* and *post-crystallization directive*, with the crystallization receipt as the transition marker between them. Pre-crystallization content is admitted to Regent's context at low priority; post-crystallization content at full directive-tier priority. Emission gate enforced at the input plane, not just at the output.

**COGNITIVE-MODE-AND-AGENCY-2026-07.** Conversational mode's *active discipline* is the shaping repertoire. The corpus has named Conversational as one of four modes but never enumerated what Conversational mode legitimately DOES; this primitive supplies the enumeration. Transition from Conversational to Stewardship should carry a crystallization receipt — the mode transition is the effect, crystallization is the trigger.

**COGNITIVE-SELF-OBSERVER-2026-07.** Two new verification classes:
- Class N: *"was Regent's substantive emission for subject S downstream of S's crystallization receipt?"* — pre-emission commitment defect.
- Class N+1: *"was Regent's shaping act well-typed under §5, and did it leave the operator with genuine ability to decline?"* — leading-question-masquerading-as-forcing-question defect.

**CLAIM-VERIFIER-2026-07.** Pre-emission check extended: capability/commitment claims must reference a crystallization receipt for the subject. Claims without a matching crystallization receipt are rejected or rewritten.

**STANDING-CORRECTION-RECEIPT-SCHEMA.** Operators can lay down bounds on shaping: *"don't ask forcing questions on X topic"*, *"don't offer candidate frames when I'm mid-decision"*. Standard schema; new correction-type slug `shaping:bounded`.

**STANDING-IMPASSE-PRIMITIVE-2026-08.** Companion primitive. Lifecycle: `intent:crystallized` → Deliberation(s) → one of three termination classes. Each end of the lifecycle now has a first-class primitive; the corpus's cognitive-thread ontology becomes complete at the endpoints.

**REGENT-DOOM-LOOP-DETECTION-2026-07.** Chronic-drift heuristics (H6–H8) must distinguish *pre-crystallization meandering* (legitimate — subject hasn't landed yet, waiting for shaping opportunity or operator crystallization) from *chronic drift* (model degradation, boilerplate creep). Add a new signal: presence or absence of shaping activity within a meandering window. Meandering + shaping-attempted + declined = probable operator-side under-crystallization, not model drift.

**LENS-DISCIPLINE-2026-07.** `lens:declared:intent_crystallization` — outside-in lens with focus on crystallization signals across substrate cycles. Silence of crystallization receipts over a long window is significant same as loud crystallization over a short window (nested observer discipline).

**MEDIA-PROVENANCE-2026-07 / MEDIA-PROVENANCE-INTEROP-2026-07.** Not immediate composition but load-bearing precedent: chain-anchored provenance-of-thought (this primitive) sits at the same architectural altitude as chain-anchored provenance-of-artifact. Both are the substrate's answer to *"how did this come to be?"* — one for cognition, one for content.

## 8. Substrate-discipline collision + resolution

**KEEL III.24 (aligned blindness).** The substrate refuses to observe some classes even under authorization. Does actively shaping the operator's conversation constitute observation? **No — provided shaping is not conditioned on operator observation.** Shape is chosen based on conversation *shape* (circling, un-resolved anaphora, missing success criteria — properties of the utterance stream), not on operator *state* (frustration, engagement, vulnerability — properties of the operator). The distinction is architectural: utterance-stream properties are already in Regent's perception plane; operator-state properties would require CONVERSATIONAL-INFERENCE-BOUNDARY-forbidden consolidation.

**KEEL P9 (the system acts; the operator signs).** Explicit shaping does not compromise P9. The Regent proposes; the operator signs by accepting, declining, or redirecting. Every crystallization receipt is downstream of an operator response, not upstream. The operator remains the authority for what the substrate commits to.

**CONVERSATIONAL-INFERENCE-BOUNDARY-2026-08.** That doc refuses *affect* consolidation; this primitive proposes *intent* consolidation. **Architecturally distinct.** Affect is a property of the operator (how they are feeling); intent is a property of the request (what they are asking for). The boundary was correctly drawn against affect; leaving intent unnamed created a gap the corpus has been feeling for months. This primitive fills the gap without violating the boundary.

**STANDING-CORRECTION-RECEIPT-SCHEMA.** The `shaping:bounded` correction-type gives the operator explicit control. If the operator finds a shaping type intrusive on a particular topic, they can bound or prohibit it, and the substrate respects the bound. This is not a defensive add-on; it is the mechanism that makes explicit shaping safe by default.

## 9. Non-goals

- **Not a behavioral training signal for LoRA fine-tuning.** Shaping-act traces are chain artifacts, not training data. They may become training data by a later ceremony (per SUBSTRATE-SLM-TRAINING-ENVIRONMENT-2026-07's discipline), but this primitive does not authorize that.
- **Not a manipulation vector.** Explicit shaping is the opposite of manipulation. The whole point of §4's constraints is to draw the line structurally.
- **Not an inference about operator emotional state.** Shape is chosen from conversation properties, not from operator properties. Section 8 addresses the tension explicitly.
- **Not automatic.** The Regent still has to decide *when* to shape. Reflex-shaping on every meandering turn would produce constant interruption. Shaping cadence is a Regent judgment call informed by mode + severity + operator standing corrections.
- **Not without operator override.** Any shaping act can be declined without cost. Declines are witnessed; recurring declines on a specific shaping type feed operator standing-correction candidates.
- **Not for canonicalization by silent adoption.** Like STANDING-IMPASSE-PRIMITIVE, this primitive awaits operator ceremony. Treating it as canonical before the ceremony would be exactly the pre-crystallization commitment defect §7's Cognitive Self-Observer would catch.

## 10. Deliverable shape for the fresh session that picks this up

If Ken decides to move the primitive from proposal to design elaboration, the fresh session should:

1. Read this doc, STANDING-IMPASSE-PRIMITIVE-2026-08 (companion primitive at opposite lifecycle end), and CONVERSATIONAL-INFERENCE-BOUNDARY-2026-08 (the doc that draws the affect-refusal line this primitive composes against).
2. Consult `docs/CANONICAL-CORPUS-INDEX-2026-07.md` to locate: COGNITIVE-INPUT-PLANE, COGNITIVE-SELF-OBSERVER, COGNITIVE-MODE-AND-AGENCY, COGNITIVE-ACT-ACCOUNTING, CLAIM-VERIFIER, STANDING-CORRECTION-RECEIPT-SCHEMA, REGENT-DOOM-LOOP-DETECTION, LENS-DISCIPLINE. This primitive composes with all of them.
3. Read `docs/KEEL-2026-07.md` §II.17 (chain-anchored discipline), §III.19 (detectability), §III.21 (metacognition), §III.24 (aligned blindness), §III.25 (distributed cognition + escalation for novelty), P9 (system acts; operator signs).
4. Propose specific Chain event schemas (§6 receipts) and Cartographer object schemas (CrystallizationTrajectory typed object) as a companion doc or appendix.
5. Propose specific detection-signal implementations (§3) — deterministic pattern-matchers, not model-inferred classifications.
6. Propose the shaping repertoire's initial seed library — one or two exemplars per §5.1–5.6, drawn from actual conversation traces where the shaping act would have helped.
7. Apply the disconfirming-observation check: what would you expect to see if this primitive is *not* needed? Candidates: (a) crystallization is adequately handled by mode transitions (Conversational → Stewardship carries all the information); (b) explicit shaping is architectural theater — a well-tuned Regent shapes conversation without needing the acts declared; (c) the substrate-discipline collision (§8) doesn't actually resolve — shaping DOES require operator observation, and the resolution offered here papers over that. Look for these specifically.
8. Apply the reflexivity check: if this primitive were in force during the drafting of this primitive, what would have been different? The answer names an empirical test of the primitive's utility.

If the disconfirming observations hold up, the primitive should be rejected or radically reshaped. If they don't, promotion proceeds.

## 11. One conversation piece worth preserving

Ken's framing in the source conversation, verbatim:

> *Actually intent CAN have a receipt — except it has to actually come into focus first. There's what is often a subtle moment in conversations when vague or nebulous intent solidifies around a subject or theme. It's not often explicit. I'd like to shape our solution to pay attention to this moment and use it accordingly.*

And two turns later:

> *Perhaps even have the regent shape the conversation towards definition?*

And one turn after that:

> *Yes, explicit shaping is what I'm reaching for.*

The three-step arc — *observation*, then *the active generalization*, then *the load-bearing constraint (explicit)* — is itself an instance of crystallization discipline. Each turn narrowed the primitive's shape by one dimension. The final constraint (**explicit**) does the heaviest structural work: it distinguishes what the substrate must do from what the substrate must refuse, and it draws that line in a way that composes with every existing invariant the corpus has established.

The word "subtle" in the first framing is doing more work than it looks like. Subtle means the substrate cannot rely on operator markers to notice the moment; it has to observe utterance shape and infer the moment from the shape. That inference is exactly where the primitive lives. Passive detection notices when the shape shifts; active shaping *puts pressure* on the shape so it shifts. Together they are the substrate's answer to *"how does intent become witnessable?"*

Reflexively: this proposal doc was drafted after intent for it crystallized — around turn twenty of a conversation that started as a dashboard update. The crystallization moment was Ken's *"Perhaps even have the regent shape the conversation towards definition?"* — that turn shifted the primitive from *interesting observation* to *load-bearing substrate concern.* Before that turn, this doc could not have been drafted; after that turn, it drafted itself.
