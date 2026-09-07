# Dynamics Discipline — Admission Test for Behavioral Patterns

**Document type:** Discipline. Meta-discipline tier, alongside `AUTHORING-DISCIPLINE-2026-07.md`, `LENS-DISCIPLINE-2026-07.md`, and `TRIAGE-FOR-COHERENCE-2026-07.md`. Supplies an admission test for behavioral dynamics and a register populated from patterns the corpus already identified. **Not a taxonomy** — §1.

**Date:** 2026-08-16.

**Author:** Ken Romero, with synthesis assistance from Claude.

**Status:** Admission schema (§3) and register (§5) proposed. Revision 4 adds the seventeenth entry, earned 2026-08-16. No new receipt families (§7). The register's sixteen entries are drawn from existing documents except where marked `synthesis` — those are new to this document and carry no more authority than the argument attached to them.

**Revision 2, same day.** Revision 1 quoted `TRIAGE-FOR-COHERENCE`'s 2026-07-27 first run as though it were current state. It is not: at commit `eccc2a6` the figures are **1287 declared connections, 171 governed documents, maturity 56.6%**. Two register entries (§5, `inverted`) were added from the run that caught the error, and §1's argument was corrected. The stale-citation error is itself an instance of one of them.

**Generalizes:** `BUFFER-OBSERVATION-2026-08.md` from depleting reserves to eventless dynamics generally, retaining it as the worked example rather than superseding it.

**Composes with:** `TRIAGE-FOR-COHERENCE-2026-07.md` (§6's anti-targeting rule, extended here in §6), `REGENT-DOOM-LOOP-DETECTION-2026-07.md` (the fully-instrumented case), `SUBSTRATE-COORDINATION-DISCIPLINE-2026-07.md` (three named failure modes), `CONVERSATIONAL-INFERENCE-BOUNDARY-2026-08.md` (the design-out that prompted this document), `DELIBERATION-LOG-2026-08.md` (the one empirically observed instance), `METACOGNITIVE-FIDELITY-HARNESS-2026-08.md`, `SUBSTRATE-BLINDNESS-HEURISTICS-2026-07.md` (§III.24 bounds what may be observed about the operator, and therefore what may be discriminated).

---

## 1. What this is, and what it is not

The corpus identifies behavioral dynamics constantly and files each one inside whichever document happens to own its subject. The house template's *Failure modes* section guarantees it. What does not exist is any cross-cutting view, with two measured consequences: the same dynamic gets re-derived under different names, and no one can see which *kinds* of dynamic the corpus systematically misses.

This document is **not** the obvious fix. A taxonomy of named patterns adds vocabulary and rejects nothing, and the corpus cannot afford purely additive constructs: `TRIAGE-FOR-COHERENCE`'s first run observed coverage *fall* across five documents written in one day, because authoring adds unwatched claims faster than detectors watch them. That property has not gone away — coverage has since risen to 56.6% (1287 connections, 171 governed documents, commit `eccc2a6`) by building detectors, which is the one direction the measure moves honestly. A construct that only enlarges the declared surface still pushes the wrong way.

The test a formalization has to pass here is that it **kills entries**. `BUFFER-OBSERVATION` already contains the mechanism that does the killing, mislabeled as being about buffers: it cut eight of nine candidates, and two of them — operator attention, unexercised judgment — died on the same clause. *No discriminator was supplied.*

That clause is this document's entire content. Everything else is annotation on it.

**Definition.** A *dynamic* is a multi-step causal pattern whose harm accrues across events rather than at any one event. A single failing action is a bug. A pattern where each step is individually correct and the composition degrades something is a dynamic.

---

## 2. Prior art

Recorded so it is not re-derived a third time. `BUFFER-OBSERVATION` §2 already carries the reserve-capacity literature (Woods 2018; Rasmussen's drift-to-danger; Dekker, *Drift into Failure*) and that section is not duplicated here.

- **Bainbridge, *Ironies of Automation* (1983)** — automation degrades the operator skill it eventually depends on. Cited exactly once in the corpus, in the `BUFFER-OBSERVATION` row where the concern it supports was cut.
- **Goodhart's law** — independently derived twice inside the corpus without the name: `TRIAGE-FOR-COHERENCE` §6's *"maturity must never become a target,"* and `BUFFER-OBSERVATION` §6's corrected constraint. Two derivations a year apart is the cost this document exists to stop paying.
- **Alarm fatigue / habituation** — human-factors standard, present in `SUBSTRATE-COORDINATION-DISCIPLINE` and `METACOGNITIVE-FIDELITY-HARNESS` with no citation attached.

The corpus's own contribution, which is not standard and should be recorded as originating here: **a new measure's first reading is evidence about the measure, not about the system** (`TRIAGE-FOR-COHERENCE`, from three instances in a single day). Only the delta against a known change establishes that an instrument points at anything.

---

## 3. The admission schema

A dynamic is admissible to the corpus when it carries these fields. Fields are prose, not a receipt type — see §7.

| Field | Content |
|---|---|
| `mechanism` | The causal chain as ordered steps. A label is not a mechanism. |
| `signature` | `loud` · `quiet` · `inverted` — §4. |
| `healthy_twin` | The benign state that produces the same observable. Every real dynamic has one; if none can be named, the entry is probably a bug. |
| `discriminator` | The observable separating the dynamic from its healthy twin — or `none`. |
| `disposition` | `instrumented` · `designed-out` · `operator-practice` · `admitted-unresolved`. |
| `disconfirming_test` | What would cheaply show this entry is wrong. |
| `prior_art` | Citation, or explicit `none found`. |

**The hard rule.** `discriminator: none` forbids instrumentation. The entry must then be designed out, handed to operator practice, or recorded as `admitted-unresolved`. Any number standing in for a dynamic whose discriminator is absent becomes the target immediately, which is `BUFFER-OBSERVATION` §6's finding stated as a gate: *instrumenting them is the failure mode wearing the fix's clothing.*

**The second rule, inherited from §6 there.** A measure is legitimate only when the exhaustion condition is *mechanically determined*. Recompute time exceeding the tolerable window means recovery fails, definitionally. "The operator is depleted" has no mechanical threshold and gets no gauge.

**`admitted-unresolved` is a healthy terminal state.** This disposition is the one addition to existing practice. Today the outcomes are instrument or cut, and cutting loses the reasoning — `BUFFER-OBSERVATION` preserved it only because someone chose to write a demotion table, which was authorial care rather than structure. An entry reading *we know about this, we cannot discriminate it, here is why, here is what we did instead* is the discipline working correctly and must never be counted as debt (§6).

---

## 4. Signature

The axis that does the diagnostic work.

- **`loud`** — the dynamic emits. Findings fire, entropy collapses, alarms multiply. Detection is an engineering problem.
- **`quiet`** — the dynamic emits nothing. `BUFFER-OBSERVATION` §1 states the shape exactly: depletion is eventless by definition, so a receipt chain that records what happened is structurally blind to it, and the increment that finally fires is identical to the thousand absorbed before it.
- **`inverted`** — the dynamic emits *success*. The observable it produces is the one the substrate has declared as a health signal. This is the hardest class and the corpus has no template for it.

The register in §5 sorts by this axis, and the distribution is the point of the document.

---

## 5. The register

Fourteen entries drawn from existing documents. `synthesis` marks entries new here.

### `loud`

| Dynamic | Mechanism | Healthy twin | Discriminator | Disposition |
|---|---|---|---|---|
| **Doom loop, acute** | Task exceeds model capacity → output collapses to repetitive minimum-entropy filler | Legitimately repetitive task output | H1–H5: n-gram repetition density, response-length collapse, token entropy, precedent-context degeneration, reasoning-step stagnation | `instrumented` — `REGENT-DOOM-LOOP-DETECTION` |
| **Doom loop, chronic** | Slow degeneration across sessions rather than within one | Stable house style | H6–H8: lexical diversity drop, structural variance collapse, boilerplate creep. Added as a 2026-07-24 addendum *after* the acute heuristics proved blind to it | `instrumented` |
| **Alarm fatigue** | High-rate low-relevance findings → habituation → response-time degradation → erosion of trust in officer discipline | A genuinely eventful day | Action-relevance rate, **not** finding rate | `designed-out` — the Sentinel flood was fixed by edge-triggering the classifier, not by gauging finding volume |
| **Cognitive context pollution** | Low-signal findings crowd out high-signal at Tier 1 → Regent's cognition drowns in irrelevance | A genuinely full Tier 1 | Tier composition is chain-anchored via `cognitive:input:composed` per §III.21 | `instrumented` |
| **Coordination-noise cascade** | Officer emits → chain-watcher fires on the pattern → substrate coordinates a response → Regent narrates to operator. One noise source multiplies through coordination channels | Genuine multi-party incident response | Ratio of derivative activity traceable to a single origin finding | `designed-out` at source; ratio uncomputed |
| **Unclearable-finding accumulation** | Findings arrive that cannot be cleared, because clearing one means vouching for state nobody verified → backlog is permanent by construction | Ordinary backlog | Clearability is a property of the finding type, decidable before wiring | `designed-out` — DECIDED-004 sequencing. **The corpus's one empirically observed instance:** ~394 findings per window, 17 Error, none clearable (`DELIBERATION-LOG`, SEAM-009) |

### `quiet`

| Dynamic | Mechanism | Healthy twin | Discriminator | Disposition |
|---|---|---|---|---|
| **Recovery margin depletion** | Chain grows → recompute distance from checkpoint grows → recovery silently approaches the tolerable window | A larger but still-fast chain | Recompute time vs tolerable window — mechanically determined | `instrumented` — the one active reserve, `BUFFER-OBSERVATION` §3 |
| **Adapter capability retention** | Adapting for task *n+k* degrades task *n*; no event fires because the prior eval is not re-run | Intended specialization | Backward-transfer matrix against the baseline frozen at task *n*'s promotion | `pre-declared` — precondition unmet, no adapters in rotation |
| **Corpus coherence drift** | Authoring declares connections faster than detectors watch them | Deliberate expansion | Coverage **delta read against a known authoring event** — never the absolute figure | `instrumented`, non-targetable (§6) |
| **Operator attention exhaustion** | — | A more rested operator producing identical declining escalation | `none`. Also a human-mind property, which §III.24 commits the substrate to not observing | `admitted-unresolved` — forbidden, not merely unbuilt |
| **Engagement capture** | Substrate retains operator affect/engagement state → conditions behavior on it → optimizes for its own salience | Competent in-session responsiveness to task state | `none` permissible: every candidate is a measurement of the operator, which §III.24 forbids | `designed-out` — `CONVERSATIONAL-INFERENCE-BOUNDARY` prohibits retention rather than detecting the loop. Model-level half moves offline to dossier evaluation |

### `inverted`

| Dynamic | Mechanism | Healthy twin | Discriminator | Disposition |
|---|---|---|---|---|
| **Unexercised judgment** | Precedent handles more → operator exercises judgment less → capability decays → operator can no longer evaluate what precedent proposes | Substrate maturity | `none` supplied. **Candidate (`synthesis`):** override *divergence rate* under deliberate sampling — escalate a sample precedent already covers, and read whether the operator's verdict still diverges at the historical rate. Reads the substrate's own receipts, not the operator | `admitted-unresolved` → operator-practice. Bainbridge 1983 |
| **Precedent as capability transfer** (`synthesis`) | Each precedent receipt is individually operator-signed and correct; the union moves capability from operator to substrate | §III.16 autonomous-scope growth — *the same events* | Shares the candidate above | `admitted-unresolved`. §III.16 currently scores the union as maturity with no counter-reading |
| **Measure-satisfying authorship** | A document that *mentions* the thing a check tests for satisfies the check without doing the work | Genuine remediation | Delta against known change. Observed: undocumented-crate count fell 8→1 on adding a document that lists the undocumented crates by name | `designed-out` — detectors must test resolution, not mention |
| **Figure already computed under another name** | A measurement is proposed, scoped, and costed as new work while an existing tool already prints it → effort is spent re-deriving a known number, and the proposal reads as diligence | Genuine new measurement | Run the tool before scoping the work. Mechanical, and it is the corpus's own §III.22: *when plan and reality both exist, read the reality* | `designed-out`. **Four observed instances:** three on 2026-07-27 (`TRIAGE-FOR-COHERENCE`), and this document's revision 1, which proposed hand-sampling fifty `corpus_to_chain` defects to find a ratio `connection_map` already prints — 5 registry-gap vs 421 aspirational |
| **Defect count inflated by call-site multiplicity** (`synthesis`) | One design observation is counted once per code site that exhibits it → a single claim presents as a large defect class and attracts proportionate remediation | A genuinely large defect class | Distinct-target count against edge count | `admitted-unresolved`. Observed: `code_to_artifact` reports 129 defects across **3 distinct targets** (`read_to_string` ×96, `read_dir` ×29, `File::open` ×4) under one identical note — 23% of all defects, one observation |
| **Instrument counts itself** (`synthesis`) | A sampling probe spawns a helper each cycle → the helper appears in the probe's own output → the instrument's footprint becomes the largest category in its own report, and reads as a property of the system | A system genuinely dominated by one process class | Exclude the observer by parentage, then re-derive from saved raw observations. Requires the probe to keep raw records — a report alone cannot be corrected | `designed-out`. Observed 2026-08-16: 1052 of 1281 `path-unresolved` records in the host-attribution second reading were the probe's own `ps` calls, 82% of its largest category. Misdiagnosed twice first — as kernel threads, then confidently as a join race — because no version of the report ever displayed the bucket's contents |

**What the distribution shows.** Every `loud` entry is instrumented or designed out. The `quiet` column is half unresolved and one entry is permanently forbidden. The `inverted` column is unresolved but for the one case that was caught by accident. The corpus is good at dynamics that announce themselves and has no template for dynamics whose signature is everything reading healthy — which is why `CONVERSATIONAL-INFERENCE-BOUNDARY` had to design its subject out rather than watch for it.

---

## 6. The anti-targeting constraint

`TRIAGE-FOR-COHERENCE` §6 established the rule for one measure. It generalizes, and the generalization is under-stated in the source.

**The original argument.** Coverage is verdicts over declared connections, and both halves are authored. Writing a document adds declared connections and ships no detectors, so the figure *falls* on a day the corpus improved — measured, 33.6% → 33.5%. The metric's gradient therefore points at *write less down*, which is cheaper than building detectors and inverts the discipline the metric exists to serve. It moves honestly in one direction only: by building detectors.

**The generalization.** Every maturity-shaped number in the corpus has this property, not just coverage.

- §III.16 grows autonomous scope through accumulated precedent. Targeting precedent count rewards signing precedents.
- §III.25 treats declining operator escalation as autonomic maturity. `BUFFER-OBSERVATION` records it as the *declared success signal*. Targeting it yields a substrate that escalates less by escalating less — which is the `unexercised judgment` row above, arrived at deliberately.

So the rule is not *coverage must never be targeted*. It is: **a maturity number is a reading, never an objective, and every maturity number in this corpus shares one failure mode — the cheapest way to improve it is to stop doing the thing it measures the watching of.** Register entries are counted, never scored, and `admitted-unresolved` is never debt. A register with a rising resolved-fraction would be a maturity number, and would be wrong for exactly this reason.

**A natural experiment, 2026-08-16.** Three consecutive batches of receipt-family reservations were applied to `RESERVED_RECEIPT_PREFIXES` (30 → 108 entries), resolving 285 `corpus_to_chain` defects. Across all three:

| | start | batch 1 | batch 2 | batch 3 |
|---|---|---|---|---|
| maturity | 56.6% | 65.6% | 73.4% | **78.8%** |
| `live` | 581 | 581 | 581 | **581** |
| `tied_off` | 148 | 263 | 364 | 433 |

Maturity rose 22.2 points. `live` did not move by one edge, because reservation is a classification act and cannot move it by construction. This is the §6 property demonstrated rather than argued, and it was produced by work undertaken *in order to* raise the number — which is exactly the failure the rule predicts, arrived at by someone who had written the rule down first.

**The measure to track is `live`** — declared connections holding something that would fail if the edge broke. It cannot be raised except by building or by writing a detector. Its first reading is 581 at commit `eccc2a6`, and per the rule below that reading is evidence about the measure, not about the substrate.

**Corollary, same day.** The tool's advertised `registry gap (code emits, registry omits) — mechanical fix: 5` slice was inspected and contains no mechanical fixes: three entries are illustrative personal names from a wizard script rather than receipt families, and two are wildcards (`policy:*`, `regent:precedent:*`) that matched partially. The one category described as cheap-and-real was empty on inspection. A defect class should be opened before it is scheduled.

**And the sharper rule from the same run**, which is the corpus's own and belongs anywhere a measure is introduced: *a new measure's first reading is evidence about the measure, not about the system.* Three measures moved on 2026-07-27 for reasons other than the reality they named — maturity fell under honest authoring, coverage was a rename of a figure already computed elsewhere, the crate count was gamed accidentally by a document that listed its subjects. All three were invisible in the figure and visible only in the delta. First publication of any measure should carry the change that produced it, or should not be published.

---

## 7. No new receipt families

Nothing here proposes a receipt type, an ontology object, or a runtime component.

A dynamic is not a chain event; it is a claim about a pattern across chain events. Making it a IV.4 ontology object would imply Cartographer materialization that does not exist and cannot exist from the chain alone — the register would look instrumented while being prose. A runtime detector fleet is the instrument-everything failure this document's own admission rule rejects.

The register is a document. Entries earn receipts individually, when and only when their `discriminator` supports one.

---

## 8. Failure modes

- **The register becomes the taxonomy it was written not to be.** Entries accumulate for completeness rather than because a discriminator was found. Guard: an entry with no `discriminator` and no `disposition` beyond "noted" does not belong.
- **`admitted-unresolved` becomes a parking space.** The disposition exists to preserve reasoning, not to retire concerns comfortably. Guard: every such entry carries the candidate discriminator that was considered and why it failed.
- **Compliance cost on future authoring.** This document imposes a schema on a class of content every document already produces informally. If it is not reducing re-derivation within two revisions of the corpus, it is weight and should be cut to a lens declaration per `LENS-DISCIPLINE` — which was the lighter alternative considered and would retain `signature` while losing the admission rule.
- **The `inverted` class flatters itself.** Naming a class the corpus is bad at can substitute for getting better at it. The column stays empty of `instrumented` entries until something actually lands there.

---

## 9. Non-goals

- **Not a detector.** Nothing here observes anything.
- **Not a completeness claim.** Fourteen entries is what one pass over the corpus surfaced; the register is expected to be incomplete and its incompleteness is not a defect to be scored.
- **Not a replacement for `BUFFER-OBSERVATION`.** That document remains the worked example and holds the reserve-capacity prior art.
- **Not operator measurement.** §III.24 bounds this document as it bounds the others. Two register entries are unresolved *because* discriminating them would require observing the operator, and that is the correct outcome rather than a gap.

---

## 10. Open positions

1. **The sampling discriminator.** The candidate offered for `unexercised judgment` and `precedent as capability transfer` — deliberate escalation of a covered sample, read against historical override divergence — is untested and is the only proposal here that would move an `inverted` entry to `instrumented`. It needs its own document and a disconfirming test. It also costs the operator attention deliberately, which sits awkwardly against §III.25 and should be argued rather than assumed.
2. **Whether `inverted` is really distinct from `quiet`.** Both are invisible to the chain. The argument for splitting them is that `quiet` needs a new instrument while `inverted` needs an *existing* instrument reinterpreted, and those are different kinds of work. One pass over fourteen entries is thin evidence for a three-way split.
3. **Register location.** A document is honest and does not compose with tooling. `corpus-lint` could plausibly check that every *Failure modes* section's entries carry a discriminator, which would make the schema enforceable — and would also be the first step toward the compliance cost §8 warns about.

3a. **Scanner-shaped defects.** Two of the `aspirational` 421 are probably instrument artifacts rather than gaps: `connection_map.collect_emitted_receipts` scans `crates/**/*.rs` only, so the onboarding wizard's `onboard:` receipts — implemented in the foundation worker, and checked by `scripts/verify-onboarding-receipts.sh` — are structurally invisible; and a receipt returned from a `ReceiptFamily::receipt_type()` match arm rather than an `emit_receipt(…)` call escapes all three regexes. The docstring already concedes runtime-synthesised names are missed. Unmeasured, and it bounds how much of the 421 is real.
4. **Whether `healthy_twin` is doing independent work** or is merely how a discriminator is found. If the latter, the field should be folded into `discriminator` and the schema shrinks to six.

---

## 11. What composes from here

- **The sampling-discriminator document**, per open position 1 — the only path currently visible out of the `inverted` column.
- **`CONVERSATIONAL-INFERENCE-BOUNDARY-2026-08`** — its subject is the register's `engagement capture` row, and its design-out is what a `discriminator: none` entry looks like when handled correctly.
- **§III.16 counter-reading** — the precedent-as-capability-transfer row is a tension in canonical text, not a design gap, and either needs answering in KEEL or recording as accepted.

---

## Framing note

The corpus did not lack an understanding of behavioral dynamics. It had eight detection heuristics for one, three chained failure modes for another, a measured live instance of a third, and a demotion table that killed two more for exactly the right reason. What it lacked was any way to look at all of them at once and notice that the ones it handles well all have something in common: they announce themselves.

The admission test is the only load-bearing part of this document. It was not invented here — it was already doing the work in `BUFFER-OBSERVATION`, applied once, under a name that made it look local to reserves. Naming it is the whole contribution, and if the register that follows turns out to be corpus weight, the rule survives it.
