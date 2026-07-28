# Triage for Coherence

**Document type:** Working discipline. **Not** a Tier 2 canonical elaboration — it elaborates no KEEL section. It defines the ranking rule that decides which coherence question gets asked next, and the receipt states that make *unexamined* distinguishable from *examined and fine*. Belongs in *Investigations and programs* alongside `AUTHORING-DISCIPLINE-2026-07.md`.

**Date:** 2026-07-27. **Status:** Draft. Ranking rule and state model proposed. The denominator is settled and the first coverage figure is recorded in §First run; the receipt family and the four-state model remain unimplemented.

**Motivation:** The corpus treats coherence as a state to be checked — observer coherence, emission coherence, spec-implementation coherence. It has no operation that decides *what to check next*, and no way to tell a claim that was verified from a claim nobody has ever looked at. Both present as silence. Every finding of 2026-07-27 was incidental: surfaced while doing something else, true for weeks beforehand, and reachable in most cases within one tool call.

**Source:** The term is Ken's, coined 2026-07-27 after a session in which seven divergences were found by accident. The ranking rule, the state model and the coverage measure below are the ZeroPoint reading of what the term demands if taken as a primitive rather than a description.

**Composes with:** `CONNECTION-INTEGRITY-PROGRAM-2026-07.md` (**the primary relationship** — that program supplies the taxonomy C1–C9, the connection object, the tie-off, and the detectors; this document supplies the ranking rule it does not have, and the reading of its maturity figure as a coverage measure), `STRUCTURAL-FIT-INVENTORY-2026-07.md` (a hand-run instance of this discipline over representations; its SF-4 is the template for why structural beats vigilant), `SPEC-IMPLEMENTATION-COHERENCE-INVESTIGATION-2026-07.md` (the same operation over behaviour; its §2 records why the naive search direction is unsound), `AUTHORING-DISCIPLINE-2026-07.md` (A11 is the rule this discipline exists because writing down was not sufficient to enforce), `OBSERVER-COHERENCE-DISCIPLINE-2026-07.md` (cross-observer agreement — a different coherence class, deliberately not merged here), `CHAIN-READ-CANARY-DISCIPLINE-2026-07.md` (the same insight applied to reads: silence must be made loud).

---

## Framing

**1. Vigilance is the wrong instrument, not an insufficiently applied one.** Absence is not salient. Nothing prompts a check for something that is not there, which is why a written rule produces a heuristic and the heuristic does not fire. `AUTHORING-DISCIPLINE` A11 exists because three documents in one session asserted mechanisms that did not exist; A11 did not prevent two further instances of the same error on 2026-07-27, one of them by the agent that wrote the inventory. This is a category property, not a diligence failure, and the response is to make checks a consequence of actions already being taken.

**2. Attention is the scarce resource, so the sorting rule is the whole discipline.** Triage without a stated criterion is a queue with a better name. Medicine's criterion is survivability times urgency, applied consistently. §The ranking rule below states this one, and the inversion it carries is the substantive claim: cheap-to-verify is promoted rather than deferred.

**3. The substrate can hold a distinction nothing else can, and currently does not.** *Verified coherent* and *never examined* are different facts, and only chain-anchored state can hold that difference durably across sessions and operators. Until it does, coverage is unanswerable and the queue depends on somebody happening to notice.

---

## The ranking rule

For each candidate claim, priority rises with **blast radius**, rises with **staleness risk**, and falls with **verification cost**.

**Blast radius** — the cost of the belief being wrong, not the severity of the underlying defect. It rises with the tier of the claim (Tier 1 highest), with the number of documents elaborating it, and sharply if the claim enters agent context as identity rather than as reference — a Cognitive Input Plane Tier 0 block is read as settled and is never re-derived. A wrong sentence in KEEL outranks a wrong sentence anywhere else by construction.

**Staleness risk** — whether the inputs the last verdict was taken against have changed. This follows `CONNECTION-INTEGRITY-PROGRAM` C9's corrected rule: the trigger is *inputs changed*, not *time passed*. A verdict against code that has not moved is as good as the day it was recorded.

**Verification cost** — tool calls, or zero where a mechanical detector already covers it.

**The inversion.** Where verification cost is trivial, promote regardless of blast radius. Medical triage defers the walking wounded because their cost is bounded and known. An unresolved cheap unknown is neither: it is a standing liability against every future decision that reads the artifact, and it compounds because later work builds on the unchecked claim. On 2026-07-27, three of seven findings were one tool call from resolution and had been silently true for weeks. Cheap unknowns are how a map goes stale while everyone believes it.

---

## The state model

Four states. The first is the one that does not currently exist and is the reason for this document.

- **`untriaged`** — nobody has ever examined this claim. Not a defect; an absence of information, and the default state of everything.
- **`coherent`** — examined; claim and implementation agree. Carries the commit it was checked against, the method, and who or what issued it.
- **`divergent`** — examined; they do not agree. Carries a tie-off with disposition and reopen condition per the connection program's existing object.
- **`stale`** — a prior `coherent` verdict whose inputs have since changed. Derived, never issued directly.

`stale` is the recursion that keeps the discipline honest: **a triage verdict is itself a derived artifact**, and therefore subject to C9. A verdict that does not declare what it was checked against cannot be aged, which makes it indistinguishable from a guess. Every `coherent` verdict names its commit or it is not a verdict.

Proposed receipt family, reusing existing shapes rather than inventing:

```
coherence:triaged:<claim_id>
  verdict:            coherent | divergent
  checked_at_commit:  <sha>
  method:             detector:<name> | manual | agent:<id>
  cost:               <tool_calls | 0>
  tie_off:            <tie_off_id>       // divergent only
```

---

## Coverage

**Coverage is the fraction of load-bearing claims holding a non-stale verdict.** A load-bearing claim is one another document elaborates or a code path depends on — derivable from the connection object rather than authored, per `CONNECTION-INTEGRITY-PROGRAM` §6.

This number is the thing vigilance cannot produce at any level of skill. It also makes the discipline self-correcting: once coverage is measurable, the uncovered set *is* the queue, and the queue stops depending on anyone noticing. The gap between "we check things" and "we know what fraction of what matters has been checked" is the entire distance between the current practice and a system.

---

## Verifiable outcomes (TC)

- **TC1** — Every load-bearing claim resolves to exactly one of the four states, with `untriaged` as the default rather than an implied absence.
- **TC2** — Every `coherent` verdict names the commit it was checked against; a verdict without one is rejected, not warned.
- **TC3** — Coverage is computable as a number and reported, including when the number is unflattering. **First satisfied 2026-07-27** — see §First run.
- **TC4** — The queue is derived from the uncovered set and the staleness set, not authored.
- **TC5** — A claim whose inputs change transitions to `stale` without human action.
- **TC6** — Triage that finds no divergence still emits a receipt. *Examined and fine* is a fact worth holding.

---

## First run — 2026-07-27

**Coverage is 331 of 987 declared connections: 33.5%,** at commit `b548fb8`, across 122 governed documents, with 9 frozen documents dropped explicitly rather than silently. The figure is `connection_map`'s own maturity computation; this document contributes the reading of it as a coverage measure and the denominator ruling above.

Three things the first run established that the design did not anticipate.

**The number was never going to be zero.** This document's m0 predicted publishing a denominator with an empty numerator. That was wrong: `CONNECTION-INTEGRITY-PROGRAM`'s P1 had already computed both halves, and its rule that an unwatched edge lands as `defect` and never as *unknown* means its statuses are already triage verdicts. The 656 defects are not 656 broken things — they are 656 declared dependencies that nothing would notice breaking. m0 turned out to be a reading task, not a building task.

**The measure moves the wrong way under authoring.** Coverage fell from 33.6% to 33.5% across the five documents written on 2026-07-27, because each new document declares connections and ships no detectors. That is correct behaviour — a claim genuinely is unwatched the moment it is written — but it means **maturity must never become a target.** Anyone optimising the percentage is incentivised to stop writing things down, which inverts the discipline. The number moves honestly in one direction only: by building detectors.

**The queue is not heterogeneous, which weakens the case for an elaborate ranking rule.** Of 656 defects, **498 are `corpus_to_chain`** — documents naming receipt types with no emitting code. One shape holds 76% of the unwatched surface, and `corpus-lint receipt-coverage` already measures it. The remaining 158 divide as 127 `code_to_artifact`, 28 `corpus_to_code`, 3 `derived_artifact`. So the ranking rule in §The ranking rule governs a minority of the queue, and the majority is a single bulk problem with an existing instrument. Rank the 158; measure the 498.

---

## Next slice

Not more measurement. The first run shows the denominator, the numerator and the composition are all available today, so the binding constraint is the detector surface — 289 of 987 connections have something that would fail if the edge broke.

The three cheapest additions, each of which converts a class rather than an instance:

1. **Every backticked path in `docs/` resolves.** Catches `AGENT-TOOL-CONTRACT`'s `src/tools/wasm/capabilities.rs` and `EXTENSION-SURFACE`'s `crates/zp-server/src/extensions/`, both dangling as of this date.
2. **Symbol references in doc comments become rustdoc intra-doc links**, so `cargo doc -D rustdoc::broken_intra_doc_links` fails the build. Catches the phantom `narrow_capability` class, and moves the check from convention to compiler.
3. **Every `pub` type has a non-test consumer** or an annotation declaring it deliberately ahead of one. Catches `MerkleProof` and `DiscoveryManager`, and is `CONNECTION-INTEGRITY-PROGRAM` C2 at type granularity — a form that program's own text notes nothing currently generalizes.

None of these needs the receipt family, the four states, or any part of this document's proposed machinery. They are worth doing first for exactly that reason.

---

## Open positions

- **A — What exactly counts as load-bearing?** **RESOLVED 2026-07-27.** The denominator is `corpus_lint.governed()` — *"The corpus the conventions actually govern: what the index lists (Tier 1/2)"* — minus documents matching the frozen predicate. No new rule was needed and none should be added: a second definition would fork the measure on the day it was published. Two consequences worth stating. **Indexing is registration** — a document absent from `CANONICAL-CORPUS-INDEX-2026-07.md` is outside the measure, which retroactively converts the indexing convention from bookkeeping into the act that admits a claim to the corpus. And the apparent gap between 122 governed documents and 277 `.md` files under `docs/` is not a definitional dispute; it is documents predating the index convention, which the corpus already holds as a separate stratum that is *"counted, not flagged."*
- **B — Who may issue a `coherent` verdict?** A detector can. An agent reading source can. Whether an agent's verdict counts without operator adoption is the same Class 3 question `CONNECTION-INTEGRITY-PROGRAM` §4 settles for tie-offs. *Resolution: adopt that document's answer rather than a second one — agent proposes, operator adopts, until precedent supports otherwise.*
- **C — Does a `coherent` verdict ever expire on time alone?** C9's corrected rule says inputs-changed, not time-passed. Some claims have inputs outside the repo — an external dependency, a regulatory posture. *Resolution: an explicit inputs list per claim, with claims whose inputs are unrepresentable marked as such rather than silently aged.*
- **D — Does this merge with observer coherence?** `OBSERVER-COHERENCE-DISCIPLINE` compares two observers on one question; this compares one claim against reality. Same word, different operations. *Resolution: kept separate here deliberately; revisit only if the receipt families turn out to share a consumer.*

---

## What is specified vs. what is shipped

Per A11: **the ranking rule, the four states and the receipt family are unimplemented.** The coverage figure in §First run is not — it is `connection_map`'s existing output, read through this document's denominator ruling. The ranking rule, the four states, the receipt family and the coverage measure are all proposals. What exists and is being composed with rather than duplicated: `CONNECTION-INTEGRITY-PROGRAM`'s C1–C9 taxonomy, its connection object and tie-off, its P0/P1 detectors shipped 2026-07-26, and `corpus-lint`'s `receipt-coverage`, `check_doc_crossrefs` and `connection-map` `derived_artifact` checks. No `coherence:triaged:*` receipt exists. No coverage figure has ever been computed.

---

## Non-goals

- **Not a replacement for the connection integrity program.** That program owns the taxonomy, the object, and the detectors. This supplies the ranking rule and the coverage notion it lacks, and nothing else.
- **Not automated repair.** Triage decides what to look at and records what was found. Fixing is a separate decision with a separate authority.
- **Not a quality bar.** A `coherent` verdict says a claim matches reality, not that either is any good.
- **Not a schedule.** Nothing here runs on a cadence; the trigger is inputs changing and the queue being non-empty.
- **Not applicable to Tier 3.** Historical documents are frozen at authoring frame and are not triaged for divergence from current reality — that divergence is expected and is the point.
