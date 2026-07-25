# Cognitive Primitives as Substrate Operations — Opportunity Mapping

**Document type:** Design intent / opportunity mapping. Not a Tier 2 canonical elaboration — no KEEL claim elaboration — an outside-in framing that shapes how substrate primitives compose to account for cognitive acts. Direction: **outside-in** (external taxonomy → substrate composition).

**Date:** 2026-07-25.

**Source:** *Cognitive Primitives: The Architecture of a Thinking Mind*, articles.intelligencestrategy.org, fetched 2026-07-25. Proposes intelligence as 31 irreducible, trainable cognitive operations in six families composing into a recursive Generative Loop.

**Attribution:** The 31-primitive taxonomy and the Generative Loop are the article author's framing. The substrate mapping, the frequency-band assignment, the non-adoption positions, and the gap analysis are the ZeroPoint reading. Both are captured here as one intent record with attribution preserved. Where the two disagree, this document says so rather than harmonizing.

**Composes with:** `COGNITIVE-TOOLS-OPPORTUNITY-MAPPING-2026-07.md` (outside-in sibling; its Verified Cognitive Objects are the candidate CREATION surface), `COGNITIVE-SYSTEM-APPROXIMATION-2026-07.md` (inside-out mirror at faculty granularity; both composes with and conflicts with this lens — see §Composition), `COGNITIVE-DESIGN-PRINCIPLES-2026-07.md` §#2 (band assignment is mandatory for any cognitive component), `LENS-DISCIPLINE-2026-07.md` (this document's canonical form), `VERB-SET-INVENTORY-2026-05.md` §Architectural surprises (the unassigned cognition service this mapping points at).

---

## Formal lens declaration

Per `LENS-DISCIPLINE-2026-07.md`, this document declares the following lens as its first-class canonical form. The mapping below elaborates the declaration.

- **`lens_id`**: `cognitive_primitives`
- **`focus`**: how substrate mechanisms correspond to discrete cognitive operations, at which frequency band, and which operations have no substrate surface
- **`dimensions`**: discernment, modeling, inquiry, creation, enactment, agency, composition order, operation granularity, frequency band, trainability, transmission
- **`keyword_composition`**: [primitive, composition, decomposition, hypothesis, critique, metacognition, originality, elegance, scenario, formulation, decision, transfer, role, priority, relevance, taste, framework, analogy, generative loop, which operation, in what order]
- **`transformation_question`**: *"which cognitive operation is this move, at which frequency band, and is the substrate's evidence that it ran chain-anchored?"*
- **`cross_references`**: `COGNITIVE-TOOLS-OPPORTUNITY-MAPPING-2026-07.md` (outside-in sibling), `COGNITIVE-SYSTEM-APPROXIMATION-2026-07.md` (inside-out mirror, faculty granularity), `COGNITIVE-DESIGN-PRINCIPLES-2026-07.md` §#2 (frequency bands) and §#8 (confabulation gap), KEEL §II.19 (the single composition primitive), §III.12 (metacognition), §III.21 (priority-weighted context), §III.22 (verify before commit), `REGENT-DOOM-LOOP-DETECTION-2026-07.md` §Ontology gap (`RegentEmission`), `VERB-SET-INVENTORY-2026-05.md` §Architectural surprises (unassigned cognition service)

When chain-anchored as a `lens:declared:cognitive_primitives` receipt, invocation semantics follow the lens discipline: any work context matching the keyword composition triggers a `lens:applied:cognitive_primitives:<invocation_id>` receipt. Silent-cognitive-primitives-lens over a long observer window signals that substrate work has stopped asking which cognitive operation it is performing — either the question stopped mattering (retire the lens) or the substrate drifted from it (re-invoke deliberately). Directional: outside-in (external taxonomy → substrate composition).

---

## Framing

Three properties make this lens worth declaring.

**1. The two frames are at different altitudes, and that is the whole finding.** The article is a taxonomy of *what a mind does*. ZeroPoint is an architecture for *making what a mind claims to have done verifiable*. Every substrate analog of an article primitive turns out to be a verification or composition discipline applied to a capacity the model supplies — not the capacity itself. `COGNITIVE-SELF-OBSERVER-2026-07.md` states the posture in its own voice: *"Metacognitive fidelity is not a property of the model; it's a property of the substrate… Fidelity is engineered, not hoped for."* The substrate owns the envelope; the generator is rented. This lens exists to ask which operation just ran, not to run it.

**2. The taxonomy exposes a gap the corpus has approached three times and never closed.** The article's punchline — *"the scarce thing is the human who knows which primitives to run, in which order"* — names the composition-of-operations problem. The substrate has a primitive set (53 verbs across 7 services), a composition primitive for modules (KEEL §II.19, WASM implementing a trait), an ordered multi-stage arc for improvement, and a composition/conflict operator for lenses. It has no canonical operator for composing operations into named, ordered sequences. `VERB-SET-INVENTORY-2026-05.md` flagged the adjacent hole in May 2026 — *"The cognition pipeline has no verb-set home… This looks like an 8th service"* — and it is still open.

**3. The corpus makes one structural correction to the article, and it should be visible in the artifact.** `COGNITIVE-DESIGN-PRINCIPLES-2026-07.md` §#2 requires any cognitive component to declare its frequency band, because *"band mismatch between components is a structural defect, not a config issue."* The article's 31 are enumerated flat. Under the corpus's own rule, Identity (Sovereign band, near-permanent) and Priority (Fast band, per-call) cannot be peers in one list. Every mapping row below carries a band. Where a primitive spans bands, that is itself a signal that it is not one primitive.

---

## The core mapping

Coverage classification: **Built** (named mechanism, shipped or spec'd to Tier 2 depth) · **Partial** (slot exists, deferred, or the analog is oblique) · **Absent** (no mechanism, no marker) · **Refused** (the corpus has pre-committed against it).

Band per `COGNITIVE-DESIGN-PRINCIPLES-2026-07.md` §#2: **Fast** (per-call, ms–s) · **Session** (min–hr) · **Trajectory** (days–weeks) · **Sovereign** (near-permanent).

### DISCERNMENT

| Primitive | Band | Status | Substrate mechanism |
|---|---|---|---|
| Ignorance | Fast → Trajectory | Built (externalized) | Confabulation gap (`COGNITIVE-DESIGN-PRINCIPLES` §#8, `UserStateDissonance`); Cognitive Self-Observer Classes 4 and 6; Friction as a counted ontology object; doom-loop R2 refuse-and-narrate. The *substrate* locates where the Regent's knowing breaks; the Regent does not. |
| Relevance | Fast | Built | Cognitive Input Plane per-class filters; false-positive suppression; lens `keyword_composition` matching; Cartographer trajectory-boundary detection with `boundary_confidence`. |
| Value | Sovereign | Partial — different faculty | KEEL §III.24 aligned blindness is *refusal to see*, not *judgment of worth*. `importance: u8` deferred to Phase 2+ on Trajectory and Insight. See Open position E2. |
| Quality / Taste | Session | Partial — floor only | Doom-loop heuristics H1–H8 detect degeneracy: repetition, entropy collapse, template lock, boilerplate creep. They measure the absence of quality; nothing recognizes its presence. `COGNITIVE-SELF-OBSERVER` rules itself out: *"Not a truth referee for Regent's opinions."* |
| Priority | Fast | Built | KEEL §III.21; CIP Tier 0–3 stack; severity-gated interrupt threshold; Sentinel elevation authority. *"Ordering IS signal"* is sharper than the article's formulation. |

### MODELING

| Primitive | Band | Status | Substrate mechanism |
|---|---|---|---|
| Mechanism & Consequence | Session | Partial | CSO Class 2 diagnosis-claim verification; medium observer window trend computation; ontology `InfluencedBy` / `MitigatedBy` edges. But `Insight.implications` and `Decision.outcome` are Phase 2+, and the ontology records only *observed* causality — *"not because an inference model guessed."* |
| Decompose ⇄ Compose | Fast | Partial — one direction | Regent Layer 2 planner `TaskGraph` is designed; Phase 1 declines it: *"No `Intent::Plan` type. No DAG executor… The chain is the plan."* Compose exists only as `assemble_report_html()`. |
| Connection & Analogy | Trajectory | Absent (marked) | `COGNITIVE-TOOLS-OPPORTUNITY-MAPPING` §4 proposes analogy as a first-class object with typed relationship semantics and a `cognitive:analogy:*` receipt family. Not implemented. Memory retrieval is keyword-based, not analogical. |
| Framework | Trajectory | Built | The lens primitive is exactly this, formalized: `(dimensions × keyword_composition)` with a transformation question, cross-references, and four chain-anchored receipt types. Also model dossiers as a schema for characterizing a class of thing. |

### INQUIRY

| Primitive | Band | Status | Substrate mechanism |
|---|---|---|---|
| Question & Hypothesis | Session | Built as process, absent as object | Lens `transformation_question`; `improvement:proposed` stage 1. But there is no `Intent::Question` and no `Hypothesis` type — the Regent cannot pose a question to the world as a distinct cognitive act. |
| Experiment & Feedback | Session → Trajectory | Built | `SHADOW-EVALUATION-PRIMITIVE`; `improvement:evaluated`; `EMPIRICAL-PROGRAM`; canary discipline; `COGNITIVE-DESIGN-PRINCIPLES` §#9 feedback-runs-downward. Aimed inward at the substrate rather than outward at the world. |
| Metacognition | Fast + Session + Trajectory | Built, and more precise than the article | KEEL §III.12 as a standing axiom; nested observer windows; Cognitive Self-Observer Classes 1–7. **KEEL §IV.3 splits what the article calls one primitive into five terms with distinct scopes** — Metacognition, Reflexivity, Introspection, Self-awareness, Metacognitive fidelity. The band-span is the tell. |
| Critique | Fast | Built | Claim Verifier (pre-emission, structural, deterministic against delegation state) + Cognitive Self-Observer (post-emission, semantic) — the cognitive discipline sandwich of KEEL §II.17. |

**INQUIRY is complete.** The substrate independently built a chain-anchored, ceremony-gated implementation of one of the article's six families — and it is the family the article's own installation method (simulated experience) is worst at delivering, because inquiry quality is only measurable against real ground truth.

### CREATION

| Primitive | Band | Status | Substrate mechanism |
|---|---|---|---|
| Originality | Session | Absent, and inverted | Nothing produces or rewards novel output. Doom-loop H4 flags responses that are *too similar* (cosine > 0.98) as pathological. `COGNITIVE-SYSTEM-APPROXIMATION` concedes the cost: explicitness *"may be a weakness for creativity."* |
| Depth | Fast | Structurally capped | `ModelTier::Deep` means compute class, not cognitive depth. Meta-recursion capped at 2–3 levels *"at cost of losing some capacity for very-deep self-analysis."* |
| Elegance | Session | Absent | No mechanism, no marker, no open position. Nearest cousin is P4 *every bit counts* applied to task graphs as an unmeasured prompt instruction. |
| Contrast | Fast | Partial | `lens:conflicts:<a>:<b>`; CSA's holds/adds/breaks tri-partition; shadow evaluation compares candidate against control — but on models, not on ideas. |
| Scenarios | Session | Absent | Nothing branches into counterfactuals. `GraphStatus` has no `Explored`/`Rejected` state. **There is no receipt for a path considered and not taken.** |
| Formulation | Session | Partial, outsourced | Cleo does the transmissibility work, not the Regent — *"turns the Regent's receipt trail into a governance story."* Insight is the closest object type and the corpus calls it *"the hardest object type to materialize deterministically."* |

The article's EQ thesis — the tragedy of the gifted is a deficit of transmission — lands squarely on this family, and this is where the substrate is thinnest. See Open position E1.

### ENACTMENT

| Primitive | Band | Status | Substrate mechanism |
|---|---|---|---|
| Application | Fast | Built | `IntentExecutor::execute()`; extension surface; Artifact ontology objects with provenance to the producing Decision. |
| Efficiency / Leverage | Fast | Built | Cheapest-capable routing; token and cost budgets under CloudMandate; verification cost bounds; the diagnostic-order discipline (*"steps 1 and 2 are free; step 3 costs 4–16x"*). |
| Decision | Trajectory | Built | The three-part autonomous action test (authority / precedent / context novelty); Decision as an ontology object — though `pros`, `cons`, `confidence`, `outcome` are Phase 2+, so what ships is a *record of* a decision, not a decision procedure. |
| Perspective | Session | Partial | Lens direction (outside-in / inside-out / view-in); Regent⇄Forge peer conflict surfaced to the operator as competing receipts. Genuine multi-perspective structure, but *inter-agent* — the Regent receives Forge's receipts; she cannot take Forge's view. |
| Transfer | Trajectory | Built | Precedent as trust corpus; `lens:composed` + `cross_references`; CSA's *"the lens generalizes"* to any composed cognitive system. |
| Role | Sovereign | Partial — static | CIP Class 1 Tier 0 identity block (*"never displaced"*); officer cadre with distinct charters. Role is a declared field, not a switchable cognitive stance. |

### AGENCY

| Primitive | Band | Status | Substrate mechanism |
|---|---|---|---|
| Motivation | Sovereign (operator-held) | Refused | Goals arrive exogenously as Tier 3 operator directives. KEEL §III.9: every action traces to threshold M-of-N humans consenting through their individual Geneses. A substrate Motivation primitive would be an autonomous goal source — which the delegation model exists to prevent. |
| Emotion | — | Refused agent-side; modeled operator-side | KEEL §III.24 names mental-health state in the default-refusal tier; affect-reading is gated behind per-signal `observe:operator:face:affect` delegation. But `COGNITIVE-DESIGN-PRINCIPLES` §#3/#4/#6 model the *operator's* emotional state and Enneagram type as slow-layer objects. **The substrate models the operator's psychology and declines to have one.** Coherent, and worth naming. |
| Boundary | Sovereign | Built, unusually well | KEEL §III.18 delegable safety, §III.23 coordination-not-oversight, §III.24 aligned blindness; per-doc Non-goals discipline; delegation narrowing. More developed than the article's. |
| Courage | — | Inverted | The article valorizes acting under novelty. KEEL §III.9/§III.16 mandate *escalating* under novelty: *"Known pattern + novel context = new precedent → escalate."* Direct opposition, not a gap. |
| Identity | Sovereign | Built, and stronger than the article's | Genesis-rooted keys with lineage; KEEL §III.11 self-understanding is chain-anchored and *"not the output of any inference"*; §VIII.3 the substrate defends its own identity at Layer A regardless. Identity is a key, not a self-concept. |
| Strategy | Trajectory | Partial | Trajectory is retrospective — *"emerges from activity, not declared top-down."* WorkArc is forward-looking and unimplemented, with its central question open. |

### Coverage summary

| Family | Built | Partial | Absent / Refused | Assessment |
|---|---|---|---|---|
| DISCERNMENT | 2 | 3 | 0 | **Reveals a gap** — discernment is pointed at substrate state, not at worth |
| MODELING | 1 | 2 | 1 | **Raises urgency on** the deferred Phase 2+ ontology fields |
| INQUIRY | 4 | 0 | 0 | **Confirms** current direction — the strongest convergence |
| CREATION | 0 | 3 | 3 | **Reveals a gap**, and one the substrate may correctly decline — see E1 |
| ENACTMENT | 4 | 2 | 0 | **Confirms** current direction |
| AGENCY | 2 | 1 | 3 | **Confirms** — three refusals are load-bearing, not omissions |
| **Total (31)** | **13** | **11** | **7** | |

---

## Where the frames diverge structurally

Every gap above traces to one architectural commitment, stated plainly in `REGENT-PHASE-0-1-DESIGN-2026-07.md` §1.1:

> "the model holds its plan in its context window… The receipts record every step — you can reconstruct the plan from the chain. **The chain is the plan.**"

Cognition not emitted as a receipt is architecturally invisible. MODEL, INQUIRE, and CREATE are internal operations producing no external act, so they emit nothing, so the substrate cannot observe, govern, score, or improve them. **The substrate governs acts; the article's taxonomy is largely about thoughts.**

That is not a defect to fix wholesale. It is the correct posture under P9 and the rented-generator framing. What it does mean is that the substrate currently has **no unit of account for a cognitive act** — and that single absence is what five of the seven downstream items below are actually about.

---

## What this lens does NOT adopt

Seven positions in the source article that the corpus has already pre-committed against, in writing. Named here so this document is not read as endorsement.

**1. Mind-identity.** The article is titled *The Architecture of a Thinking Mind*. `COGNITIVE-SYSTEM-APPROXIMATION` refuses exactly this: *"The substrate is not a mind. It is a cognitive infrastructure with mind-analog functional properties… Approximation is a real thing to name; identity is a category error to avoid."* That guardrail is inherited here verbatim.

**2. "The mind is not a database."** `COGNITIVE-DESIGN-PRINCIPLES` §#1: *"The chain is already a Continuum Memory System… Never build a parallel user-model store alongside the chain."* §#10: *"Catastrophic forgetting is structurally impossible; exploit it."* CIP: *"Not a memory system… Memory-per-se lives on the chain."* ZeroPoint's cognitive design is database-anchored by construction, and CSA frames that as an advantage: *"The substrate has access to its own past mental states directly."* The partial reconciliation is that CIP also rejects naive accumulation — ordering, not content, is the mechanism.

**3. Trainable via simulated experience.** This inverts the substrate's method. KEEL §III.22 verify-before-commit; `EMPIRICAL-PROGRAM`'s founding motive; and `SUBSTRATE-SLM-TRAINING-ENVIRONMENT`'s entire claim to novelty: *"No need to build a simulator that approximates operator behavior; the substrate's own operational chain IS the environment."* Its Prerequisite 3 states the negative-example corpus *"is populated only by real operation; can't be synthesized."* **The substrate's position: simulation is what you build when you lack a chain.**

**4. Irreducibility as premise.** Under §III.22, irreducibility is an assertion requiring verification before it becomes canonical. The corpus already shows the failure mode: what the article calls one primitive (Metacognition) KEEL §IV.3 splits into five. If Metacognition decomposes under scrutiny, the irreducibility of the other 30 is an open empirical question. The corpus bar — N distinct instances before canonization — applies.

**5. AGENCY as internal power source.** The article's loop is *powered by* AGENCY. KEEL's loop (§V.3 `perceive → reason → execute`) is powered by delegation: execute routes through the gate, P9 requires operator authority for every consequential act, and the Claim Verifier rejects responses claiming authority the Regent lacks. This lens relocates AGENCY to the operator — which is coherent, because the article's own residual human scarcities (selection, question-framing, judgment, formulation, orchestration) map onto exactly the surfaces ZeroPoint keeps in operator ceremony by invariant.

**6. Unbounded recursion.** The Generative Loop is recursive with no declared depth bound. The corpus bounds recursion three ways: §III.12's policy cap (2–3 nesting levels), `LENS-DISCIPLINE` §8's structural termination, and `IMPROVEMENT-LOOP-DISCIPLINE`'s ceremony gate. CSA defends the cap on the merits: *"Human deep reflexivity also produces deep confabulation, infinite regress, and false meta-narrative."*

**7. Flat enumeration.** Adopted only with band assignment attached, per `COGNITIVE-DESIGN-PRINCIPLES` §#2. See §Framing property 3.

Related, and non-adopted for a different reason: CSA's Non-goals include *"Not claiming other cognitive systems are inferior — the comparative framework is analytical, not evaluative,"* which sits uneasily with any scarcity-ranking of which primitives matter most. This lens takes the analytical posture.

---

## Downstream substrate work suggested by this mapping

Seven items. The first five are one gap seen from five angles — **the substrate has no unit of account for a cognitive act** — and they form a dependency chain, not a list.

1. **`RegentEmission` as a sixth ontology type.** Already proposed in `REGENT-DOOM-LOOP-DETECTION-2026-07.md` §Ontology gap, which recommends a new type over extending Artifact on semantic-drift grounds (Artifacts are signed canonical renderings; emissions are observational records). Blocked on a Cartographer amendment ceremony. **Critical path for items 2–5**, and needed independently by the chronic-drift heuristics H6–H8.

2. **Frequency-band assignment for cognitive operations.** §#2 mandates it; no existing enumeration carries one — not CSA's seventeen faculties, not CSO's seven claim classes, not CIP's seven source classes. Cheap once item 1 gives emissions a type.

3. **A hypothesis receipt class.** No `Intent::Question`, no `Hypothesis` type. `improvement:proposed` is the nearest and is scoped to substrate self-improvement. Would strengthen INQUIRY from well-covered-reflexively to well-covered-outwardly.

4. **A branch-considered receipt class.** Nothing records a path weighed and rejected; `Decision.pros` / `Decision.cons` are the deferred slot. **Closes a real accountability gap independent of this article: the chain currently proves what was done, not what was weighed.**

5. **A composition operator for operations, and the Cognition service.** Three existing near-misses to build from: lens composition (`lens:composed` / `lens:conflicts`, plus Walk as a lens-composition transport operator), the improvement arc (the only ordered multi-stage chain-anchored entity), and the 53-verb catalog with nothing above verb level. KEEL §II.19's composition primitive composes modules, not sequences. `VERB-SET-INVENTORY` §Architectural surprises is the declared endpoint: *"do not assign cognition routes to any of the 7 services without an explicit decision."*

6. **Analogy as a first-class object.** Already proposed in `COGNITIVE-TOOLS-OPPORTUNITY-MAPPING` §4 with a `cognitive:analogy:*` receipt family. This lens raises urgency on it: Connection & Analogy is the only MODELING primitive with no substrate surface at all.

7. **Verified Cognitive Objects as the CREATION surface.** If CREATION is the model's job (Open position E1), the substrate's contribution is making creative claims attributable and verifiable — which is what `COGNITIVE-TOOLS-OPPORTUNITY-MAPPING` already proposes. **That connection is drawn nowhere in the corpus.** Drawing it is most of the work.

---

## Open positions

**E1 — Is CREATION the model's job or the substrate's?** Six primitives, zero mechanisms, and the corpus concedes the cost itself: explicitness *"may be a weakness for creativity."* Under the rented-generator posture the answer is probably the model's — in which case the substrate's job is attribution and verification, and item 7 above is the destination. Answering "the model's" is a positioning decision, not a retreat. Unresolved.

**E2 — Value as worth, distinct from blindness as refusal.** The substrate has an unusually developed refusal faculty (§III.18, §III.23, §III.24) and no valuation faculty. `importance` is deferred on both Trajectory and Insight, and the Phase 3 plan proxies it with recency and activity density — activity, not worth. Whether the substrate should have a valuation faculty at all, or whether valuation is properly operator-held like Motivation, is unresolved. **Named here rather than closed by shipping a scoring heuristic.**

**E3 — Does the band-span of Metacognition indicate a decomposition?** Metacognition is the only primitive in the mapping spanning three bands, and KEEL §IV.3 already splits it five ways. `COGNITIVE-DESIGN-PRINCIPLES` §#5 holds that cross-frequency coupling is weak and asymmetric — which suggests a band-spanning primitive is not one primitive. Whether the other 30 survive the same test is the empirical form of non-adoption item 4.

---

## Composition with existing corpus

- **`lens:composed:cognitive_primitives:cognitive_system_approximation`** — same territory at different resolution. CSA enumerates seventeen faculties; this enumerates 31 operations. Faculties versus trainable operations is a granularity relationship, not a contradiction, and naming it prevents the two maps being read as competing.
- **`lens:composed:cognitive_primitives:cognitive_tools`** — CREATION's candidate substrate surface is Verified Cognitive Objects. This receipt makes item 7's connection durable rather than incidental.
- **`lens:conflicts:cognitive_primitives:cognitive_system_approximation`** — **also warranted, and both apply.** CSA's Non-goals refuse mind-identity and refuse comparative evaluation of cognitive systems; the source article asserts an architecture *of a mind* and ranks primitives by scarcity. Two lenses prescribing contradictory transformations over overlapping contexts is exactly what the conflict receipt is for. Declaring composition and conflict against the same lens is unusual and honest: they overlap on territory and diverge on claim.

---

## Non-goals

- **Not a Tier 2 canonical elaboration.** No KEEL section is elaborated. The article's central claims are the ones §What this lens does NOT adopt refuses.
- **Not a new empirical claim.** A 31-primitive taxonomy is a way of looking at the substrate, not a claim about it. If item 3, 4, or 5 becomes a design commitment, *that* earns a claim in `EMPIRICAL-PROGRAM-2026-07.md` Part II with a protocol row.
- **Not a CLAUDE.md heuristic.** One instance. Something like *"name the cognitive operation and its frequency band before building the mechanism"* is a plausible future nomination pending the N-instances test. It stages; it does not land.
- **Not an attempt to build CREATION.** E1 names the question rather than answering it with a mechanism, per §III.22.
- **Not a claim that the substrate should run these operations.** The lens asks which operation ran and whether the evidence is chain-anchored. Asking is not performing.

---

## Framing note

The source article is worth composing with not because its taxonomy is correct — irreducibility is unverified, the recursion is unbounded, and three of its six AGENCY members are things the substrate refuses on purpose — but because it asks a question the corpus has never asked in this form: *which operation is this, and did it run?*

The substrate can answer that for acts. It cannot answer it for thoughts, because thoughts emit nothing. That is the honest state of things and it is also the correct design given P9 and the rented-generator posture. What changes with this lens is that the gap now has a vocabulary, and the five-item dependency chain that closes it has a name.

A `lens:applied:cognitive_primitives` receipt on a piece of substrate work is the substrate asking itself which cognitive move it just made. That is not the same as making the move, and it is exactly the kind of thing ZeroPoint is for.
