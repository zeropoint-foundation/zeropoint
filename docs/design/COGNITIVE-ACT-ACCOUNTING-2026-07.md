# Cognitive Act Accounting — the Deliberation Object

**Document type:** Tier 2 canonical elaboration. Elaborates KEEL §III.13 (chain is truth; ontology is understanding), §II.17 (cognitive discipline sandwich), §III.21 (priority-weighted cognitive context), and Part V. Adds Layer B canonical claims about the unit of account for cognitive acts. Proposes one new ontology object, four ontology-definition terms, two receipt classes, and a deliberation rigor tier.

**Date:** 2026-07-25. Status: Draft.

**Motivation:** `COGNITIVE-PRIMITIVES-OPPORTUNITY-MAPPING-2026-07.md` established that the substrate governs acts while cognition largely produces none, and named the consequence: *the substrate has no unit of account for a cognitive act.* Five separate downstream items in that document turned out to be one absence. This document builds the missing object.

**Composes with:** `COGNITIVE-MODE-AND-AGENCY-2026-07.md` (the base layer this object's `mode` and `flow_ref` fields refer to), `REGENT-DOOM-LOOP-DETECTION-2026-07.md` §Ontology gap (whose `RegentEmission` proposal this subsumes), `COGNITIVE-INPUT-PLANE-2026-07.md` (source of the witnessed fields), `COGNITIVE-SELF-OBSERVER-2026-07.md` and `CLAIM-VERIFIER-2026-07.md` (the sandwich that verifies the asserted fields), `ONTOLOGY-AND-CARTOGRAPHER-2026-07.md` (the five existing object types), `LENS-DISCIPLINE-2026-07.md`.

---

## 1. What the outside source actually contributes

The external taxonomy of 31 cognitive operations is not ZeroPoint-shaped and should not be adopted as an ontology. Its value is narrower and more useful than that: **it names, precisely, which fields a record of a cognitive act needs that the substrate's existing act-records do not have.**

Read the six families as field groups rather than as capabilities:

| Family | What it says a cognitive act has | Substrate coverage today |
|---|---|---|
| DISCERNMENT | a **scope** — what was attended to, and what was set aside | **Recorded.** `cognitive:input:composed` carries per-class source hashes and the suppressed-filter application record |
| MODELING | a **frame** — the structure assumed, the prior invoked | Partial. `lens:applied` records an active framing; nothing links it to a specific act |
| INQUIRY | a **question** — what was being tested | **Absent.** No `Intent::Question`, no hypothesis field anywhere |
| CREATION | **alternatives** — what was weighed and rejected | **Absent.** `GraphStatus` has no `Explored`/`Rejected`; `Decision.pros`/`cons` deferred |
| ENACTMENT | an **act** under authority | **Recorded, thoroughly.** Gate decision, intent receipt, tool receipts, outcome |
| AGENCY | **whose intent, under what delegation** | **Recorded, thoroughly.** Delegation scope, operator signature, mandate |

The substrate records ENACTMENT and AGENCY beautifully and records DISCERNMENT without knowing it. It records nothing of MODELING, INQUIRY, or CREATION. **Those three are the missing fields, and that is the entire contribution.** No taxonomy adoption required.

This also settles where the 31 names belong. Not as an ontology, not as an enum of substrate capabilities — as the **seed set for a declared library of act-signatures** (§3.4), matched against witnessed fields rather than claimed. Which of the 31 are real in this substrate then becomes an empirical question answered by match rate, not a premise. That satisfies the irreducibility objection raised in the opportunity mapping instead of arguing with it.

---

## 2. The object

### IV.4 extension — the sixth ontology object

```markdown
- **Deliberation** — a bounded cognitive act within a trajectory: what was attended to,
  what frame was applied, what was weighed, what was emitted, and under what authority.
  Materialized per cognitive cycle. Witnessed fields derive from chain receipts; asserted
  fields are Regent claims carrying verification status.
```

**On the name.** The five existing objects are nouns of work — direction (Trajectory), choices (Decision), understanding (Insight), output (Artifact), resistance (Friction). The gap in that vocabulary is *reasoning*: the thing that happens between a Friction and a Decision. `Deliberation` fits the register. `RegentEmission` (the working name in the doom-loop doc) is narrower than the object needs to be — it frames the record around output for drift detection, when output is one field of six.

**This subsumes the `RegentEmission` proposal rather than competing with it.** The doom-loop doc's chronic-drift heuristics H6–H8 need a per-emission record; Deliberation's witnessed fields provide exactly that, and a Deliberation with no asserted fields *is* a RegentEmission. One type now instead of a sixth type now and a seventh later.

### Placement against the existing five

Deliberation sits below Decision and above nothing. A Trajectory contains Deliberations; some Deliberations produce Decisions; Decisions cite the Deliberations that produced them via a new `DeliberatedIn` relationship kind. Insights and Frictions may be emitted from a Deliberation. Artifacts remain linked to the producing Decision, unchanged.

The existing constraint holds: *"the relationship exists because specific receipts justify it — not because an inference model guessed."* Every Deliberation edge traces to a receipt.

---

## 3. The witnessed / asserted split

This is the load-bearing structure and it is what keeps the object honest.

**A record of what the Regent attended to is derivable from the chain. A record of what she considered and rejected is a claim she makes about herself.** Collapsing the two would make Deliberation a confabulation surface — the substrate would be storing, as fact, assertions of the exact class `COGNITIVE-SELF-OBSERVER` Class 6 exists to catch. `COGNITIVE-DESIGN-PRINCIPLES` §#7 states the general rule: *"If a user model update cannot be traced to a signed artifact and a chain of receipts that produced it, it has no authority. Unsigned user models are cognitive confabulation."* The same applies to self-models of reasoning.

So the object carries two field groups with different epistemic status, and the boundary is explicit in the schema rather than implied.

### 3.1 Witnessed fields — derived, not asserted

| Field | Derived from |
|---|---|
| `act_id` | content hash of the cycle |
| `cycle_ref` | the `cognitive:input:composed` receipt hash |
| `attended` | per-class source content hashes from that receipt |
| `suppressed` | suppressed-filter application record from that receipt |
| `frame` | `lens:applied:*` receipts active in the cycle window |
| `emitted` | `regent:intent:*` receipt hash and intent type |
| `enacted` | gate decision receipt, tool receipts |
| `outcome` | `IntentOutcome` |
| `band` | frequency band, derived from the receipt types touched |
| `mode` | the standing cognitive posture, derived from cycle invocation reason + delegation scope + severity — see `COGNITIVE-MODE-AND-AGENCY-2026-07.md` |
| `flow_ref` | the flow this act belongs to, if any — the composition unit |
| `operation` | the declared act-signature this act matches, within `mode`, or `unmatched` — see §3.4 |

**Implementation status, verified against `crates/` 2026-07-25.** An earlier draft of this document asserted that all witnessed fields existed on chain today. That was read from the Cognitive Input Plane spec rather than from the runtime, and it was wrong in three places.

| Field | Status |
|---|---|
| `cycle_ref`, `emitted`, `enacted`, `outcome` | **Shipped.** `emit_composition_receipt` at `zp-regent/src/loop_runner.rs:719`; all seven `regent:intent:*` kinds in `zp-server/src/regent.rs`; gate receipts throughout `zp-policy` |
| `attended` | **Partial.** The receipt carries correction and finding counts plus two content hashes, not per-class content hashes across all seven classes. `basis`-checking (CA2) is therefore scoped to corrections and findings until the receipt widens |
| `mode` | **Derivable.** `invocation_reason` is populated — see `COGNITIVE-MODE-AND-AGENCY-2026-07.md` §3, which rederives the mode set from the four values the runtime actually emits |
| `suppressed` | **Not emitted, and nothing to emit yet** — see §3.3 Layer 1 |
| `frame` | **No source.** Zero `lens:applied` or `lens:declared` occurrences in `crates/`. The lens primitive is specified and unimplemented |
| `operation` | Requires the signature library; see §3.4 |
| `flow_ref` | Requires flow boundaries; see the mode document §5 |

### 3.2 Asserted fields — Regent claims, verification-bearing

| Field | Content | Verified by |
|---|---|---|
| `operation_claimed` | which operation the Regent claims she ran. Optional second channel — the primary `operation` is witnessed (§3.4) | compared against derived `operation`; divergence is diagnostic, not error |
| `question` | the hypothesis or question under test, if any | Self-Observer Class 3 (interpretation) |
| `basis` | what she claims she reasoned from | Self-Observer Class 6 (self-state) — **checkable against `attended`** |
| `alternatives` | paths weighed and rejected, with reason | see §3.3 — resolved by rigor tier, not by verification |

Each asserted field carries a `verification_status` of `verified | unverified | contradicted`, set by the sandwich. An asserted field is never promoted to witnessed.

**`basis` is the interesting one.** It is the only asserted field that is *structurally checkable* — a claim to have reasoned from something not present in `attended` is a confabulation gap by construction, detectable without inference. That check is nearly free and it is the strongest single argument for building this object at all.

### 3.3 Alternatives — four layers, not one gap

*"The chain proves what was done, not what was weighed"* reads as a single gap. It is four, with different resolutions, and one of them is already closed.

**Layer 1 — alternatives never attended to. Specified, not shipped, and currently vacuous.** The Cognitive Input Plane specifies a suppressed-filter application record in its Step 6 receipt. The runtime emits counts and hashes instead, and `zp-regent` performs no filtering or false-positive suppression at all.

The honest consequence is narrower than a gap: **if nothing is filtered, nothing is silently withheld**, so this layer is satisfied by the absence of the mechanism rather than by the presence of a record. It opens the moment filtering ships — and the filter application record must ship in the same change, or the substrate acquires an attention-layer blind spot it did not previously have. That coupling is the actionable item, not the field itself.

**Layer 2 — alternatives attended to and rejected. Closes by restructuring.** An internal weighing cannot be verified, so it should not be claimed — it should be made to emit. Where the Regent emits candidate intents before committing to one, each candidate is a witnessed emission and each rejection is witnessed by non-selection. The corpus already runs this pattern: `improvement:evaluated` carries `candidate_approaches[]` and `shadow_eval_receipts[]`, and `regent:route:assigned` records alternatives considered. **Alternatives become witnessed by being acts rather than thoughts.**

**Layer 3 — the cost of Layer 2, gated.** Candidate emission costs N inference calls where one would do, and pressures `MAX_TOOL_TURNS`. It cannot be the default. The gate is a **deliberation rigor tier**, parallel in shape to §II.11's ceremony rigor tiers:

| Tier | Applies to | Requirement |
|---|---|---|
| D1 — routine | acts producing no Decision, within active precedent | single emission; no candidates |
| D2 — consequential | acts producing a Decision, or novel context per the three-part test | candidate emissions required; rejections witnessed by non-selection |
| D3 — irreversible | acts crossing a gate at critical severity, or requiring operator signature | D2 plus rationale surfaced to the operator before commit |

Rigor scales with consequence, which is the discipline the substrate already applies to ceremony, escalation, and interrupt thresholds.

**Layer 4 — the residue, handled by inversion.** Within a single inference call at D1 rigor, an alternative may be considered and rejected with no trace. That is irreducible: no mechanism the substrate has or could have distinguishes a genuinely-weighed alternative from a plausible post-hoc reconstruction.

So do not verify the positive claim — **detect the omission.** Content present in `attended` that appears in neither `emitted` nor `alternatives`, and receives no disposition, is a *silent drop*: not proof that deliberation failed, but detection that something entered consideration and vanished without account. This is §III.19 applied to cognition — *"Silence is the enemy, not compromise."* The check is deterministic and requires no inference.

**Declared limit:** a rejection occurring entirely inside one inference call at D1 rigor, over content that was also silently dropped from the emission, is not recoverable. The substrate declares this rather than filling it with an unverifiable field.

---

### 3.4 Operations are recognized, not claimed

The external source treats a cognitive operation as something a mind *runs* and therefore knows it is running. Adopting that framing would make `operation` a self-report about internal process — the weakest epistemic class the substrate handles, and a confabulation surface with no compensating benefit.

**An operation is instead defined as a signature over witnessed fields:** a declared pattern of (`attended` shape, active `frame`, `emitted` type, `outcome`), scoped to a `mode`. Matching is deterministic and requires no inference. The label becomes evidence rather than assertion.

Signatures are declared per (mode, pattern) rather than per pattern alone. The same act shape means different things in different postures — a chain query while diagnosing a fault and the same query while assembling a report are structurally identical and cognitively different. Mode is what disambiguates them, and it is already witnessed. See `COGNITIVE-MODE-AND-AGENCY-2026-07.md`.

The substrate already runs this pattern in two places, which is the argument that it is the right shape here. The doom-loop heuristics H1–H8 are signatures over emissions. Cartographer trajectory-boundary detection is five deterministic signals over receipts, with a confidence score and the triggering signals emitted so the operator can read why. Neither asks the Regent what she did.

Three properties follow, and they are what make the labels useful rather than decorative:

- **Composable.** A sequence of signature-matched acts under a shared frame is a recognizable higher-order move. This is the input the composition operator needs; a self-reported label would not compose, because two claims have no structural relationship.
- **Falsifiable.** If no act matches a declared signature across N cycles, either the signature is wrong or the substrate does not perform that operation. Both are findings.
- **Generative.** Acts matching **no** signature are the residual: the substrate doing something the vocabulary has no name for. Clusters over that residual propose new signatures. This is how the library grows past what was imported.

**The library is designed, not derived, and ships that way.** A vocabulary is not a claim about substrate behavior, and holding it hostage to evidence inverts the order of inquiry: you need names before you can gather evidence about what you named. §III.22's *verify before commit* governs canonical claims, not the words used to describe acts. Corpus practice is consistent on this — the doom-loop heuristics H1–H8 were authored a priori from knowledge of how models fail, not from clustering this substrate's own emissions; CSA's seventeen mind features and §IV.3's imported cognitive-science terms were designed the same way. **The seed library is authored up front from the external taxonomy and from act shapes the corpus already knows.** Match rate is feedback on the vocabulary, not permission to hold one.

**What that requires instead is provenance.** Each signature carries an `origin` — `external_taxonomy`, `corpus_practice`, or `observed_cluster` — plus its match history. This keeps the question *which of these names have we actually earned?* answerable at any time without it ever blocking use of the name. The drift being guarded against is not naming-without-evidence; it is a name quietly hardening from "a shape we recognize" into "a capability we have," and provenance plus match history makes that hardening visible.

**On keeping the claim anyway.** `operation_claimed` is retained as an optional second channel precisely because it can disagree with the derived label. Per `COGNITIVE-DESIGN-PRINCIPLES` §#8, that disagreement is signal, not error: it means either the Regent's self-model has drifted, or the signature is mis-specified, or the act is genuinely novel. Do not resolve it by defaulting to either side — surface it as a typed state, the same treatment the confabulation gap already receives.

## 4. Why this makes composition possible

The composition operator (opportunity-mapping item 5, the unassigned Cognition service) has been stuck for fifteen months of substrate time for a reason that is now visible: **there was nothing to compose.** A flat catalog of 53 verbs composes into nothing because a verb is an act, not a move — it carries no record of what it attended to or what frame it applied, so two verbs in sequence have no structure relating them beyond order.

Deliberations compose because they carry the joins:

- `attended` and `suppressed` chain across acts — the scope of act N+1 is a function of what act N surfaced or withheld.
- `frame` gives a lens continuity, so a sequence of acts under one framing is identifiable as one move rather than N moves.
- `question` opens and closes across acts, which is what makes a multi-act inquiry a single unit.
- `band` prevents the composition of acts at mismatched frequencies — `COGNITIVE-DESIGN-PRINCIPLES` §#2's structural-defect rule, enforced at composition time rather than discovered at debug time.
- `operation` is witnessed rather than claimed (§3.4), so a sequence of matched signatures is itself structure. Two self-reported labels would compose into nothing, because claims have no structural relationship to each other.

A named, ordered sequence of Deliberations under a shared frame is what "which operations, in which order" means concretely. That object is the input the Cognition service needs, and it is what the improvement arc already is a special case of.

---

## 5. Receipt classes

Two, following the corpus's existing shapes.

**`cognitive:act:recorded:<act_id>`** — emitted per cognitive cycle after emission handling completes. Carries the witnessed fields, plus the asserted fields with `verification_status` populated by the sandwich. Deterministic given the cycle's receipts. Signed by the cognitive-act runtime key, derived as `cognitive_act_key = HKDF(genesis_root, salt=chain_head_at_derivation, info="cognitive_act:runtime")`, consistent with the input-plane and self-observer key derivations.

**`cognitive:act:signatures:<version>`** — **Specified, not shipped.** Per §6, only v0 and v1 are proposed for commitment now; the seed library ships with v1, gated on `attended` and `frame` reaching field granularity (§6). The Layer B canonical record declaring the act-signature library: for each operation, the pattern of (`attended` shape, active `frame`, `emitted` type, `outcome`) that constitutes a match, a match-confidence threshold, and an `origin` of `external_taxonomy | corpus_practice | observed_cluster`. Amendable by ceremony. **This is where the 31 names land**, as seed signatures carrying `origin: external_taxonomy` — and where evidence removes the ones that never match, splits the ones matching structurally different acts, and admits new ones from clusters of `unmatched` acts carrying `origin: observed_cluster`. §IV.3's five-way split of Metacognition is the precedent for what a split looks like in practice.

Signature authorship follows the Cartographer precedent: matching is deterministic, the triggering signals are emitted with the match, and a confidence score accompanies it so the operator can read why an act was labelled as it was.

**New Self-Observer claim class — Class 8: deliberation claims.** *"Assertions about the Regent's own cognitive process — which operation she ran, what she reasoned from, what she weighed."* Verification sources: the cycle's `cognitive:input:composed` receipt for `basis`; the derived `operation` for `operation_claimed`, where divergence surfaces as a typed state rather than a finding against her; candidate-emission receipts for `alternatives` at D2 rigor and above.

---

## 6. Minimum shippable slice

The risk this document runs is the one already named in the opportunity mapping: the substrate carries a lot of specification ahead of runtime, and a cognitive meta-layer no mechanism consumes would be the same shape as the confabulation it is meant to catch.

So the first slice adds **no new Regent behavior at all.**

**There is no Cartographer.** `ONTOLOGY-AND-CARTOGRAPHER-2026-07.md` is a design document; the only occurrence of the word in `crates/` is a string inside a model-evaluation fixture. No `Trajectory` struct, no materializer. An earlier draft of this section proposed v0 as a Cartographer projection, which was not implementable.

The constraint improves the design. Under §III.13 — *chain is truth; ontology is understanding* — the **receipt is the fact and the ontology object is the projection**, so the receipt should come first regardless. The original sequencing had it backwards.

> **v0 = emit `cognitive:act:recorded` at cycle exit, citing the composition receipt.**
> The act receipt carries `cycle_ref` (the composition receipt it reasoned from), `attended` at current receipt granularity, `mode` derived from `invocation_reason`, plus `emitted`, `enacted` and `outcome`. `frame`, `suppressed`, `operation` and `flow_ref` are absent-by-status rather than null-by-choice, and each carries its reason. Every asserted field is null.

**Corrected 2026-07-25 against the runtime.** An earlier draft of this section placed the emission *beside* `emit_composition_receipt`. That is wrong: `emit_composition_receipt` fires at `zp-regent/src/loop_runner.rs:719`, immediately after perception and **before** `reason()`, so `emitted`, `enacted` and `outcome` do not exist at that point. The composition receipt is a perception-time record; the act receipt is a cycle-completion record and cites it.

The relationship is better this way — one cycle produces one composition and one act, and the act names the composition it reasoned from. But note the implementation consequence: `run_cycle` has **six exit paths**, four of them after the composition receipt. A single emission at the bottom of the function would silently drop the `reason failed` path at line 733, which is precisely the class of act this object exists to make visible. See `BRIEF-cognitive-act-v0-m0-2026-07.md` §2.

Deliberation as an ontology object materializes later, when a Cartographer exists, from these receipts. Nothing about the object's schema changes — only which layer instantiates it first.

That is a pure projection over existing chain data, consistent with *"the ontology is a derived, rebuildable projection,"* and it ships as instrumentation rather than remediation. It immediately satisfies the doom-loop doc's H6–H8 need for a per-emission record, and it produces the evidence that tells us whether the asserted half is worth building.

Sequence from there: **v0** (act receipt emitted from the loop runner at current field granularity) → **v1** (`basis` asserted and checked against `attended` — the free confabulation check; first signature revision from match rate and unmatched residual) → **v2** (`operation_claimed` as second channel; divergence surfaced as a typed state) → **v3** (composition operator over Deliberation sequences; the Cognition service decision).

The seed library ships **with v1 rather than v0**, and this is a change forced by implementation reality rather than by the evidentiary argument that was correctly rejected earlier. Signature matching is scoped to `(mode, pattern)` over `attended` shape, `frame`, `emitted` and `outcome`. With `frame` sourceless and `attended` at count granularity, a signature declared today could only discriminate on intent type and outcome — too coarse to be worth declaring, and declaring it anyway would populate the library with signatures we would immediately have to retire.

The principle stands unchanged: the library is designed, not derived, and evidence revises it rather than authorizing it. It waits on field granularity, not on evidence.

Only v0 and v1 are proposed for commitment now. v2 and v3 are gated on what v0 and v1 show.

---

## 7. Ontology binding

Three terms enter §IV.3 alongside the existing cognitive-layer definitions:

```markdown
- **Cognitive act** — one bounded unit of the Regent's reasoning, spanning a single
  cognitive cycle: the input she was given, the frame she applied, what she emitted,
  and under what authority. The unit of account for cognition. Materialized as a
  Deliberation object.
- **Witnessed field** — a property of a cognitive act derivable from chain receipts
  without inference. Carries the chain's authority.
- **Asserted field** — a property of a cognitive act claimed by the Regent about her own
  reasoning. Carries a verification status, never the chain's authority. An asserted field
  is never promoted to witnessed.
```

A fourth term binds the vocabulary itself:

```markdown
- **Cognitive operation** — a named, recurring move in the Regent's reasoning, defined as
  a declared signature over the witnessed fields of a Deliberation and matched
  deterministically. Not asserted to be irreducible; the set is not asserted to be
  exhaustive. Membership is empirical: signatures that never match over an observer window
  are removable by ceremony, signatures matching structurally different acts are candidates
  for splitting, and clusters of unmatched acts are candidates for admission.
```

**On the noun.** *Operation* rather than *primitive* only because §II.19, §IV.7 and §IV.9 already use "primitive" for irreducible composable units *of the substrate*, and overloading it would create the ambiguity Part IV exists to prevent. Nothing turns on the word. §IV.3 already binds *metacognition*, *reflexivity*, *introspection* and *self-awareness* — imported cognitive-science vocabulary, taken and given substrate boundaries — which is the correct treatment of a useful external term and the treatment applied here.

**What does turn on something is the definition.** Binding the term to a *witnessed signature* rather than to a *claimed label* is the load-bearing choice, and it follows from how the substrate handles evidence everywhere else rather than from how the external source frames cognition. The source treats an operation as something a mind runs and therefore knows it is running; the substrate treats it as something recognizable in the record. That is the adaptation.

---

## 8. Lens composition edges

With Deliberation defined, the relationships between the corpus's six cognitive enumerations become declarable rather than implicit:

- `lens:composed:cognitive_primitives:cognitive_system_approximation` — 31 operations against seventeen faculties: different resolution over one territory, related through the `operation` vocabulary.
- `lens:conflicts:cognitive_primitives:cognitive_system_approximation` — as declared in the opportunity mapping; both edges apply.
- `lens:composed:cognitive_primitives:cognitive_tools` — Verified Cognitive Objects as the candidate CREATION surface.

The remaining enumerations are not lenses and do not take lens edges. Their relationship to Deliberation is structural and belongs in the schema rather than in a receipt: CSO's seven claim classes verify the asserted fields (now eight, per §5); CIP's seven source classes populate `attended`; CDP's four frequency bands type the `band` field. **Declaring the relationships is the reconciliation — not merging the enumerations into one map.** The substrate has no center; its cognitive vocabulary should not acquire one.

---

## 9. Verifiable outcomes

- **CA1** — A `cognitive:act:recorded` receipt is emittable for every cognitive cycle from state already assembled at the composition point, requiring no new perception or reasoning behavior.
- **CA2** — A `basis` claim naming content absent from the same cycle's `attended` set is detected deterministically, without inference. **Scoped to standing corrections and officer findings** until the composition receipt carries per-class content hashes.
- **CA3** — Deliberations of mismatched `band` are rejected at composition time rather than surfacing as behavioral defects downstream.
- **CA4** — Chronic-drift heuristics H6–H8 operate against Deliberation without extending Artifact semantics.
- **CA5** — Over N cycles, the match rate per declared signature is measurable, partitioned by `origin`; signatures that never match are removable by ceremony.
- **CA6** — The ontology remains fully rebuildable from chain with Deliberation included; no Deliberation field is unrecoverable after a rebuild.
- **CA7** — A silent drop (§3.3 Layer 4) is detected deterministically: content present in `attended`, absent from `emitted` and `alternatives`, with no recorded disposition.
- **CA8** — Deliberation rigor tier is derivable from the act's own properties (Decision production, gate severity, precedent novelty) without operator input at cycle time.
- **CA9** — Acts matching no declared signature are identifiable as a set, and cluster analysis over that residual yields candidate new signatures — the growth path (§3.4).
- **CA10** — Divergence between derived `operation` and `operation_claimed` is surfaced as a typed state and never silently resolved to either side.
- **CA11** — For any operation name, its `origin` and full match history are queryable, so "is this a shape we recognize or a capability we have?" is answerable without inference.

---

## 10. Open positions

- **Deliberation rigor tier thresholds** — §3.3 Layer 3. The three tiers are proposed; where exactly D1/D2 divides is unresolved and should be set from v0 evidence about how often acts produce Decisions. Setting it too low makes every cycle cost N inferences; too high and the accountability gap stays open where it matters.
- **Silent-drop false-positive rate** — §3.3 Layer 4. Content can legitimately enter `attended` and receive no disposition simply because it was irrelevant. Whether the detector is useful or noisy is an empirical question for v1, and it composes with the false-positive suppression discipline already in the input plane.
- **Can one act match several signatures?** If so `operation` is a set, and overlapping signatures need a precedence rule or a declared composition. Deferred until v2 match-rate evidence exists.
- **Who authors signatures?** Operator by ceremony is the safe default for the seed library. Whether the Regent may propose one from an unmatched cluster — subject to operator signature, as with any improvement arc — is unresolved and is the point where this discipline becomes self-extending.
- **Seed library scope.** Whether all 31 external names ship as seed signatures, or only those with a plausible act-signature against ZeroPoint's actual emission shapes, is unresolved. Shipping all 31 gives a cleaner falsification test; shipping a subset avoids a library where most entries never match. Leaning toward all 31 with `origin: external_taxonomy`, since a signature that never matches is itself the finding.
- **Deliberation retention.** The other five object types are long-lived; Deliberations accrue per cycle and will dominate the ontology by count within weeks. Whether they compact into their parent Trajectory after a window, and whether that compaction is lossy, is unresolved. Composes with `epoch-compaction.md`.
- **Does this warrant a KEEL axiom?** The witnessed/asserted distinction is a claim about what the substrate may treat as true about its own cognition, which is axiom-shaped. Held pending v0/v1 evidence, per *config reflects today, not roadmap*.

---

## 11. Non-goals

- **Not adopting the 31-operation taxonomy as substrate structure.** It seeds a signature library (§3.4, §5), marked `origin: external_taxonomy`, that the chain then revises by match rate.
- **Not withholding vocabulary pending evidence.** The library is designed and ships with v0. Evidence revises it; evidence does not authorize it.
- **Not recording model-internal reasoning.** Deliberation records what entered, what was emitted, what signature the act matched, and what the Regent claims — never a reasoning trace. The trace is not available and would not be verifiable if it were.
- **Not asking the Regent to classify herself.** The primary `operation` is recognized from the record. `operation_claimed` is optional, and exists for its disagreement value rather than as the source of truth.
- **Not a new authority surface.** Recording deliberation grants nothing. P9 is untouched.
- **Not a replacement for Decision.** A Decision is a committed choice; a Deliberation is the act that may or may not produce one. Most Deliberations produce no Decision.
- **Not observing the operator.** Every field concerns the Regent's own cycle. Aligned blindness is untouched.
