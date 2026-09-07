# Standing Impasse — Design Proposal for a Third Impasse-Termination Class

**Status:** Proposal, not spec. Not enacted. Awaits operator ceremony for canonicalization.
**For:** ZeroPoint substrate designers picking up this primitive in a fresh session, or Ken evaluating whether it earns its own place in the corpus.
**Scope:** Substrate-internal. Independent of any external architecture composition (Pathway/BDH, cognitive-architectures tradition survey). Load-bearing on its own merits.
**Origin:** Surfaced 2026-08-19 in a Cowork session with Ken, in the context of reviewing a cognitive-architectures survey (Soar, ACT-R, CLARION, CRAM, CALYSA). The survey flagged Soar's impasse primitive as the strongest steal candidate for the substrate. Ken's counter-move: don't just adopt impasse-and-resolve; recognize a third class of impasse termination that no cognitive architecture in the survey has as a first-class shape — the impasse that ties off cleanly without decisive resolution.

---

## 1. The gap this primitive fills

The Cognitive Architectures tradition assumes cognitive threads are terminable only two ways:

- **Resolve** — the thread produces a canonical answer that becomes procedural knowledge (Soar chunks, ACT-R production compilation, CLARION rule extraction).
- **Fail** — the thread hits a wall the system cannot cross; falls back to another mechanism, hangs, or is dropped as abandonment.

That's an assumption, not a discovery. It falls out of the tradition's commitment to compiling every resolution into a rule — if every resolution becomes a rule, then not-resolving is the same as not-learning, and not-learning reads as failure.

The substrate has already deliberately rejected automatic rule compilation (see the cognitive-architectures survey, "Direct steal candidates" and "Deliberate rejections" sections). New procedural capability enters only by operator ceremony — never by silent chunking. Given that rejection, the resolve-or-fail binary collapses. If a cognitive thread doesn't have to compile a rule to be worth having, then there is a third termination class the tradition has no name for and no shape for:

- **Tie off** — exploration preserved on the Chain, no canonical resolution reached, no default set for future cycles, closed by intentional operator or scoped-subagent judgment that this thread is complete-for-now rather than either resolved or failed.

Mature epistemics does this all the time. Research organizations hold questions open for years. Legal systems mark issues as "not reached on this record." Individuals live with productive uncertainty on questions that don't require immediate answers. The substrate expressing this shape structurally — rather than smuggling it in through operator memory, off-Chain notes, or forced pseudo-resolutions — is a genuine commitment worth naming.

The name proposed here: **Standing Impasse**. Parallels *standing correction* — both are persistent, operator-authored (or scoped-subagent-authored, per delegation gates) substrate objects that shape future cognition. A standing correction says *do this way*. A standing impasse says *do not force this to resolve; hold the exploration open*. They are duals of each other — one asserts, one refuses to assert — and the substrate is more complete when both are first-class.

## 2. The three termination classes

An impasse thread on the Chain must terminate in one of exactly three ways, each with distinct semantics and downstream effects:

### 2.1 `impasse.resolved`

- A candidate resolution was signed by an operator (or scoped-subagent with authority per delegation gates).
- Precedent established. The Chain now carries a signed decision that can be cited as rule-like precedent.
- Cartographer projects to a Decision typed object with resolution semantics.
- Future cycles hitting a similar impasse can consult this precedent and inherit the decision (subject to precedent-application discipline — precedent is guidance, not automation).

### 2.2 `impasse.tied_off` (a Standing Impasse)

- Exploration preserved on the Chain — the substate reasoning, the candidate resolutions generated, the evidence gathered, the officer findings raised — all of it stays.
- No canonical resolution reached. No default set for future cycles.
- Cartographer projects to a **Standing Impasse** typed object — a new object class, distinct from Decision (which requires resolution) and Friction (which registers unresolved tension expecting resolution).
- Future cycles that consult this precedent find *"this class of question has been explored; here is what came up; no decision was reached; the tie-off was intentional."* That is genuinely different information from either "here is how it was decided" or "nobody has looked at this."
- Revisitable by later operator ceremony — a Standing Impasse can be un-tied and re-explored if conditions change or the operator decides the tie-off was premature. The un-tie is itself a Chain event, so the trajectory of an impasse's tie-off and re-opening is auditable.

### 2.3 `impasse.abandoned`

- Thread dropped without exploration — insufficient time, insufficient authority, out of scope, or the substrate genuinely could not proceed.
- **This is the failure mode**, and it must be kept distinct from tie-off. Abandonment leaves nothing behind; tie-off leaves the exploration. Conflating the two would degrade both — tie-off would inherit abandonment's failure-signal, and abandonment would inherit tie-off's precedent value.
- Cartographer projects to a Friction typed object (existing shape). Frictions want resolution; unresolved abandonments accumulating in a class is exactly the signal the substrate should surface.

The critical design commitment: **tie-off is a first-class termination that reads as ordinary work completion, not as an exception, not as a failure, not as a temporary state.** If the substrate's UI, its query surfaces, its metrics, or its officer reports treat tie-off as anomalous, then pressure to force resolution will creep back in and the primitive collapses back into the resolve-or-fail binary.

## 3. Cartographer treatment

A new typed object class in the ontology: **Standing Impasse**.

- **Distinct from Decision.** A Decision is collapsed possibility with resolution semantics. A Standing Impasse is preserved possibility with non-resolution semantics.
- **Distinct from Friction.** A Friction registers unresolved tension that *wants* resolution and whose accumulation is itself an actionable signal. A Standing Impasse registers exploration that has been closed by choice; its accumulation is a meta-signal but not necessarily an action item.
- **Distinct from Insight.** An Insight is a stable observation carried forward. A Standing Impasse carries observations forward *and* explicitly marks that they were not converted to a decision.

The Cartographer surfaces Standing Impasses in ontology queries alongside Decisions and Frictions. A precedent lookup on a topic returns all three classes; the caller sees which shape each precedent takes and reasons accordingly.

The Cartographer additionally surfaces **patterns of related Standing Impasses** as an Insight. If a class of question has tied off N times, that pattern is itself worth naming — either because the class deserves canonical resolution ("we keep tying this off; maybe we should decide") or because the class is genuinely a Standing Impasse at the *class* level ("we keep tying this off, and that itself is the right answer for this class"). The Cartographer proposes the Insight; the operator disposes.

## 4. Precedent semantics

Citations from Standing Impasses carry the exploration but flag as **non-committal precedent**. The semantics differ from Decision-precedent in a specific way that must be preserved through the citation chain:

- **Decision-precedent** projects as rule-like: "this class of thing was decided this way; unless overridden, decide this way again."
- **Standing-Impasse-precedent** projects as context-like: "this class of thing has been thought about, here is the exploration, no decision was reached, so do not inherit a decision — either resolve fresh in current context, or tie off again if that is the honest posture."

This projection must survive citation across multiple hops. If Decision X cites Standing-Impasse Y as one of its precedents, the Decision's confidence weight must reflect that one of its inputs was non-committal. If a further Decision Z cites Decision X, the non-committal weight from Y must project through — Z cannot lose the fact that its rationale rested partly on non-committal precedent. The Cognitive Self-Observer's remit expands to catch cases where non-committal projection was dropped in citation chains.

Concretely, the Chain event for a Decision that cites Standing Impasses records the non-committal weight explicitly, and precedent-lookup APIs must return the weight alongside the citation.

## 5. Composition with existing substrate primitives

### 5.1 Cognitive Input Plane

The CIP already carries *what to do* at Tier 1 via standing corrections. Adding standing impasses as a Tier 1 class makes the plane express both sides of operator-authored epistemic hygiene: *what to do* and *what to leave undone*. A Regent cycle whose Tier 1 assembly pulls both standing corrections and standing impasses relevant to the current context enters reasoning with the full posture in view.

A worked example: Standing correction says *"when routing agent-to-agent trust decisions, always require both parties' identity attestation."* Standing impasse says *"the question of whether trust attenuates across N hops has been explored and tied off — do not force a policy answer; treat multi-hop trust as case-by-case."* A cycle assembling context on an agent-to-agent trust question gets both, and reasons with the assertion and the refusal-to-assert as complementary guidance.

### 5.2 Shadow-Evaluation Primitive

The shadow-evaluation primitive already accommodates non-disposition. Candidate ran, control ran, evidence accumulated over the evaluation window, and the operator ceremony can result in *no disposition* — neither candidate nor control gets promoted. Today that outcome is implicit in the primitive but not named as a first-class terminating shape. Standing Impasse gives it a name: a shadow evaluation that terminates in no-disposition is a Standing Impasse over the substrate-improvement question. The exploration (the parallel run, the accumulated evidence) is preserved; the substrate is not modified; the question is held open.

### 5.3 Cognitive Self-Observer

The Self-Observer's remit expands in two specific ways:

- **Watch for forced resolutions** — cycles that resolved an impasse when the honest posture was tie-off. The signature: a resolution that was signed under thin evidence, without adequate exploration, and where a tie-off would have preserved more of the substrate's honest epistemic state. This is the substrate-side analogue of the cognitive-architectures-survey warning against automatic rule compilation.
- **Watch for dropped non-committal projection** — Decisions that cite Standing Impasses but lose the non-committal weight in their own confidence signal. A citation-chain integrity check.

Both are the same shape: watch for cases where the substrate flattened epistemic posture into false certainty. The observer does not block; it flags for operator review.

### 5.4 Delegation Gates

Authority to tie off must be gated. Not everyone (and not every subagent) should be able to close an impasse without resolution. Rough shape:

- **Operator** — full authority to tie off any impasse in scope, without additional ceremony beyond the signing itself.
- **Regent** — authority to tie off impasses within its own scope after honest exploration, with the tie-off logged as a Chain event that the operator can review or reverse.
- **Officer** — authority to tie off impasses within its officer domain (Aegis over alignment questions, etc.), with the same log-and-reviewable discipline.
- **Scoped subagent** — no authority to tie off; must escalate an impasse either to resolution-within-scope or to the parent scope for tie-off decision.

The gate expresses the epistemic seniority required to responsibly close an impasse. A subagent tying off outside its authority is a delegation-scope violation and must fail-loud (per KEEL invariant on delegation narrowing).

### 5.5 Officers

Aegis and other officers gain a specific new check: **do not sign a resolution when the honest posture is tie-off.** Officer sign-off on a resolution requires that the officer affirm both (a) the resolution is correct on its merits and (b) forcing resolution rather than tying off is appropriate at this altitude. The second affirmation is new. Without it, officers become an accelerant for premature closure — they were signing the wrong thing type.

## 6. The correction/impasse duality at Tier 1

Naming this duality explicitly in the Cognitive Input Plane is where the primitive earns its shape as a design commitment rather than a bolt-on:

- **Standing corrections** assert. They shape reasoning by saying *do this way.*
- **Standing impasses** refuse to assert. They shape reasoning by saying *do not force a way; hold this open.*

Both are persistent, both are operator-authored (or scoped-authored under delegation), both enter Tier 1 of the CIP, both survive across cycles, both are auditable on the Chain, both can be revisited and modified by later operator ceremony. They are structurally symmetric. Making them symmetric in the CIP's design — rather than treating standing impasses as an afterthought or a subclass of corrections — is the commitment.

This duality is worth stating as a Layer-B principle-candidate for the substrate (not a KEEL principle; those are Layer A and require operator ceremony to promote). Something like:

> **Assert and refuse-to-assert are duals.** Operator-authored epistemic hygiene expresses both. The substrate is more complete when it can be told to do a thing and told to leave a thing undone with equal first-class weight.

Whether this rises to Layer A or stays at Layer B is a decision for the operator — I mark it as a candidate and stop there.

## 7. Failure modes and guards

Naming these now, before they surface under pressure, so the primitive does not have to be retrofitted later:

### 7.1 Tie-off as dumping ground

**Failure:** Adversarial or lazy tie-off. Threads that should have been resolved get tied off because resolution is hard or inconvenient. Over time the substrate accumulates Standing Impasses that are actually just avoided work.

**Guards:**
- The Cartographer surfaces patterns of related tie-offs and proposes them as Insights ("this class has tied off N times; worth resolving as a class?").
- Standing corrections can escalate — an operator-authored correction can flag "impasses of this class must be resolved, not tied off" as a Tier-1 constraint.
- Officers can register objection when a tie-off is proposed for an impasse whose class has a standing correction requiring resolution.

### 7.2 Tie-off hiding delegation-scope violations

**Failure:** A subagent that cannot resolve an impasse within its scope ties off rather than escalating to the parent scope. The tie-off masks the fact that the subagent was over-scoped for the question.

**Guards:**
- Tie-off authority is explicitly gated (§5.4). Subagents cannot tie off; they must escalate.
- The Chain event for any tie-off records the tying party's delegation scope. A retroactive audit can catch cases where the tie-off was structurally impossible for the party that logged it.

### 7.3 Non-committal projection dropped in citation

**Failure:** Standing-Impasse-precedent cited by a Decision loses its non-committal weight; downstream Decisions cite that Decision as if it were rule-like precedent.

**Guards:**
- Chain events for Decisions that cite Standing Impasses record the non-committal weight explicitly.
- Precedent-lookup APIs return the weight with the citation.
- The Cognitive Self-Observer watches for cases where the projection was dropped and flags the citation chain for operator review.

### 7.4 Class-level tie-off masking a real trend

**Failure:** The Cartographer surfaces a pattern of related tie-offs as an Insight; the operator disposes the Insight as "class-level tie-off is correct" without exploring whether the underlying trend is now resolvable given accumulated evidence.

**Guards:**
- Class-level tie-off dispositions have a required revisit interval — the substrate re-surfaces the Insight after N cycles or M months, whatever operator sets.
- New evidence entering the substrate that would affect the class-level disposition triggers early re-surface, not scheduled re-surface.

### 7.5 Officer capture of the "leave open" verdict

**Failure:** An officer with a specific bias (e.g. "don't ship anything I'm not certain about") starts refusing to sign resolutions and always proposing tie-off. Over time the substrate ties off things that should have shipped.

**Guards:**
- Officer disposition patterns are themselves surfaced by the Cartographer as Insights. An officer with a rate of tie-off-recommendations dramatically higher than substrate average gets flagged.
- Tie-off requires the same *positive affirmation* from officers as resolution does (§5.5). Officers cannot achieve tie-off by refusing to sign; they must actively sign a tie-off, which is auditable.

## 8. Design questions still open

These are for the fresh session picking this up, not for me to answer:

**Q1: What is the minimum Chain-event schema for `impasse.tied_off`?** At minimum: the impasse identifier, the tying party, the delegation scope of the tying party, the timestamp, the pointer to the exploration substate, and the tying party's stated reason. Should there also be a required officer countersign? A required minimum exploration depth before tie-off is allowed? An expiration on the tie-off after which it defaults to re-open?

**Q2: How does the Standing Impasse interact with rally / operator-authored default states?** Standing corrections change what the substrate does by default. Does a standing impasse change what the substrate does by default when no resolution exists? If yes, in what direction — does it default to "no action" or "propose to operator" or something else? The safest read is that a standing impasse *disables* default behavior for its class, but that is a decision, not an obvious answer.

**Q3: Should the primitive be lens-composable?** A lens application against a Standing Impasse — what does it produce? Perhaps: the lens's transformation question applied to the exploration substate rather than to a resolved decision, yielding either a re-opened impasse (the lens changed the picture) or confirmed tie-off (the lens agrees the tie-off holds). This would give lens discipline a natural interaction with the primitive.

**Q4: What is the relationship between a Standing Impasse and a Standing Correction that says "hold this open"?** Are they the same thing named twice, or distinct with different discipline? Working intuition: a correction is authored by the operator directly; an impasse arose from substrate exploration and was closed by tie-off. They can produce similar effects but they carry different provenance. Whether that provenance difference is load-bearing for how the substrate handles them is worth deciding.

**Q5: Does the primitive need a Layer-A principle in KEEL?** The correction/impasse duality (§6) is a principle-candidate. Whether it rises to KEEL Layer A or lives at Layer B or in this design doc alone is for the operator to decide. I mark it as a candidate and note that adopting it as a KEEL principle would formalize the substrate's commitment to first-class epistemic refusal.

## 9. Scope boundary

This is a proposal, not a spec. Naming it does not enact it. Enactment requires operator ceremony per the substrate's canonical corpus discipline — either promotion of this doc into `docs/design/` alongside other canonical design elaborations (SHADOW-EVALUATION-PRIMITIVE, COGNITIVE-INPUT-PLANE, LENS-DISCIPLINE), or supersession by a revised proposal that changes the shape.

Not to be done in the same session or by the same session that authored this proposal:

- No Rust code prototyping.
- No changes to Chain event schemas.
- No changes to Cartographer object classes.
- No changes to KEEL.

Not to be done at all without explicit operator ceremony:

- No treatment of Standing Impasses as if the primitive were already canonical.
- No citation of this doc as authoritative from other substrate work; cite it as a proposal.
- No promotion of the correction/impasse duality to Layer A without KEEL ceremony.

## 10. Deliverable shape for the fresh session that picks this up

If Ken decides to move the primitive from proposal to design elaboration, the fresh session should:

1. Read this doc, the cognitive-architectures survey (`/tmp/zp-cognitive-architectures-survey-2026-08-19.md`), and the Pathway-BDH handoff (`docs/handoffs/zp-pathway-bdh-vector-graph-composition-2026-08.md`) as the origin context.
2. Consult `docs/CANONICAL-CORPUS-INDEX-2026-07.md` to locate: current design docs for CIP, Shadow-Evaluation, LENS-DISCIPLINE, Cartographer, Delegation. The Standing Impasse primitive must compose with them, not fight them.
3. Read `docs/KEEL-2026-07.md` to check whether the correction/impasse duality principle-candidate has any tension with existing Layer A invariants.
4. Read the current proposal-candidate spec (wherever it is canonicalized) — the un-collapsed-possibility framing of proposal candidates is closely adjacent to the tie-off framing here, and the two must be distinguished cleanly.
5. Propose a specific placement in the corpus (this document's initial placement is at `docs/design/STANDING-IMPASSE-PRIMITIVE-2026-08.md`, indexed under "Cognitive discipline sandwich (Regent I/O)" — the fresh session may propose relocation if it sees a better home).
6. Propose specific Chain event schemas and Cartographer object schemas as an appendix or a companion doc.
7. Apply the disconfirming-observation check: what would you expect to see if this primitive is *not* actually needed? Some candidates: (a) tie-off is redundant with a "provisional Decision" object that defers resolution; (b) tie-off is just an unresolved Friction with a longer patience window; (c) the tradition's resolve-or-fail binary is correct and the substrate should not add a third class. Look for these specifically.

If the disconfirming observations hold up, the primitive should be rejected or radically reshaped. If they don't, promotion proceeds.

## 11. One conversation piece worth preserving

Ken's framing in the source conversation, verbatim as best I remember it:

> *I think ZP needs a way of seamlessly handling impasse threads that tie off, rather than resolve decisively to a particular goal or reason.*

The word "seamlessly" is doing more work than it looks like. It means tie-off cannot be an exception, cannot be an anomaly, cannot be a fallback. It has to be an ordinary shape of thread completion — visible in the same query surfaces as resolutions, weighted appropriately in the same precedent lookups, treated with the same officer discipline. If the substrate treats tie-off as anomalous, the primitive collapses; the pressure to force resolution creeps back in and the tradition's resolve-or-fail binary reasserts itself through the substrate's own UI and metrics.

The whole design commitment is: *make refusing-to-assert as ordinary as asserting.* Everything downstream of that in this proposal is engineering.
