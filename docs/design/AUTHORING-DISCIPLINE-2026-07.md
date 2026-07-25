# Authoring Discipline — the `heuristic:workflow:authoring:*` domain

**Document type:** Tier 4 working discipline, **not** a Tier 2 canonical elaboration. It elaborates no KEEL section — it describes how corpus documents are authored, which is behavioral rule rather than substrate claim. Registers the `authoring` domain in the heuristic taxonomy declared Layer B canonical by `IMPROVEMENT-LOOP-DISCIPLINE-2026-07.md`. This document deliberately follows the form it describes; that self-application is the strongest available argument for the rules.

**Date:** 2026-07-25. Status: Draft, ten heuristics staged for promotion.

**Motivation:** The Regent will author her own decision records. Today she receives the nine design principles as Tier 0 identity context and nothing else — the twenty-eight workflow heuristics in `CLAUDE.md` have no delivery path into her cycle, and the conventions governing document *form* have never been written down at all. They are demonstrated across roughly a hundred corpus documents and stated nowhere. An agent authoring her first ADR would have to infer the form by reading widely, which is precisely the tacit-knowledge erosion `IMPROVEMENT-LOOP-DISCIPLINE` §Framing exists to prevent.

**Composes with:** `IMPROVEMENT-LOOP-DISCIPLINE-2026-07.md` (the heuristic receipt schema, the domain taxonomy this registers into, and Stage 1t which mechanizes A6), `COGNITIVE-INPUT-PLANE-2026-07.md` (Class 2b is the delivery path; without it these reach nobody), `SUPERSESSION-FRAMEWORK-2026-07.md` §4.1 (the ZEP Rationale requirement, which A6 generalizes), `CANONICAL-CORPUS-INDEX-2026-07.md` (the four-tier definitions A1 operationalizes), `EXECUTION-AUTHORITY-MODEL-2026-07.md` (the corpus's cleanest ADR instance, and the shape A3 and A10 are extracted from).

---

## Framing

**1. The form is load-bearing, not decorative.** A document declaring its tier lets a reader know what authority it carries. A document naming its compositions makes the corpus navigable by traversal rather than by search. A document declaring non-goals tells the next author where the boundary is. These are not style preferences; they are what makes a hundred-document corpus usable by someone who did not write it.

**2. The bar is met.** The canonization rule requires N distinct instances before a pattern becomes discipline. The form below is extracted from documents that already exist — five authored in a single session on 2026-07-25, against a corpus of roughly a hundred that demonstrate the same conventions. This is extraction, not invention, and every heuristic cites an instance.

**3. Heuristics are for the author, whoever that is.** These are written to be equally applicable to operator, external agent, and Regent. Nothing here assumes a human reader, which is the property that makes them promotable to `heuristic:workflow:authoring:*` receipts rather than remaining prose in an operator's context file.

---

## The ten heuristics

### A1 — Declare the tier and the elaboration target in the opening line. If you cannot name the KEEL section, it is not Tier 2.

The negative test is the useful half. Tier 2 is defined by two conjunctive conditions: implementation-level elaboration of a Tier 1 section, *and* explicit declaration of which section. An author who cannot complete the sentence "elaborates KEEL §___" is holding something else — an opportunity mapping, a signal brief, a working discipline — and should say so in the same line.

*Instance:* `COGNITIVE-PRIMITIVES-OPPORTUNITY-MAPPING-2026-07.md` self-classifies as "Not a Tier 2 canonical elaboration — no KEEL claim elaboration," while `COGNITIVE-ACT-ACCOUNTING-2026-07.md` names §III.13, §II.17, §III.21 and Part V. The same session produced both; the difference is the test.

*Triggers:* any document creation in `docs/`.

### A2 — Name compositions with their reason, never as a bare list.

Every entry in a "Composes with" line carries a parenthetical stating the relationship — what that document supplies, or what this one supplies to it. A bare list of filenames is a search result, not a map, and it decays because nobody can tell whether the relationship still holds.

*Instance:* `COGNITIVE-ACT-ACCOUNTING-2026-07.md` — "`COGNITIVE-INPUT-PLANE-2026-07.md` (source of the witnessed fields)" tells you why to open it; the filename alone does not.

*Triggers:* document creation; adding a cross-reference to an existing document.

### A3 — Lead with framing as numbered properties. Mechanism comes after.

Two or three numbered properties stating what makes the document worth having, before any schema, table, or receipt shape. A reader who stops after the framing should still have gained the argument.

*Instance:* the pattern is corpus-wide — `COGNITIVE-INPUT-PLANE`, `COGNITIVE-SELF-OBSERVER`, and `COGNITIVE-SYSTEM-APPROXIMATION` each open with three numbered framing properties.

*Triggers:* document creation; substantial revision.

### A4 — Quote the corpus. Do not paraphrase it.

When citing an existing document, quote the language with a section reference. Paraphrase drifts, and drift in a corpus that governs substrate behavior is how a claim quietly becomes something it was not. For an agent author this is stronger than a style rule: paraphrase of one's own prior context is where confabulation enters, and a quote is checkable against the chain while a paraphrase is not.

*Instance:* the accounting document quotes `REGENT-PHASE-0-1-DESIGN` §1.1 — *"the model holds its plan in its context window… The chain is the plan"* — because the paraphrase "the Regent plans internally" loses the load-bearing claim that the chain reconstructs the plan.

*Triggers:* any citation of another corpus document.

### A5 — Name the load-bearing structure explicitly.

Every design document should be able to say which part carries the weight, in a sentence, marked as such. If no part can be named, the document is a survey rather than a design and should be reclassified.

*Instance:* `COGNITIVE-ACT-ACCOUNTING` §3 — "This is the load-bearing structure and it is what keeps the object honest." `COGNITIVE-MODE-AND-AGENCY` §2 marks the coupling invariant the same way.

*Triggers:* document creation; design review.

### A6 — Record alternatives considered as tie-offs, not as prose asides.

A path weighed and set aside is recorded with its disposition and, where applicable, the condition that would reopen it. `SUPERSESSION-FRAMEWORK` §4.1 already requires this of ZEPs — "comparative analysis with alternatives considered" — and `IMPROVEMENT-LOOP-DISCIPLINE` Stage 1t generalizes it to any arc with a queryable receipt and a canary on the reopen condition.

This is the hardest ADR field to author honestly and the easiest to hand-wave, and it is the one an agent author most needs mechanized: `tied_off_matching(surface_area)` surfaces prior branches over the same ground without anyone remembering to look.

*Instance:* the III.26 proposal records three alternatives — do nothing, §II.21 invariant instead, fold into §III.21 — each with the reason it lost.

*Triggers:* ADR authoring; any document proposing one approach over identifiable others.

### A7 — Every open position carries what would resolve it.

An open position without a resolution condition is a wish. State the evidence, decision, or event that would close it. This is the same field Stage 1t requires for `deferred` and `open` dispositions, and for the same reason: without it the item is unwatchable and sits until someone rediscovers it by accident.

*Instance:* `COGNITIVE-MODE-AND-AGENCY` §9 — "Held pending m0 evidence about whether stewardship is doing double duty" names the evidence. An earlier draft of the accounting document carried "unresolved" with no condition; it was rewritten.

*Triggers:* document creation; adding an open position to an existing document.

### A8 — Propose a minimum slice, and prefer one that adds no new behavior.

Where the design can be partly satisfied by deriving from state that already exists, that derivation is the first slice. This is the corpus's standing *instrumentation before remediation* posture applied to authoring: a document that proposes only its finished state produces no evidence and cannot be revised by anything except argument.

*Instance:* both cognitive-layer documents authored 2026-07-25 ship a v0/m0 that is a pure projection over existing receipts. The first draft of the accounting document deferred signature matching to v1 on evidentiary grounds and was corrected — the seed library ships with v0, because deferring it would have left the field empty across exactly the corpus the revision learns from.

*Triggers:* any document proposing new substrate behavior.

### A9 — Declare non-goals, and keep them boundary statements rather than deferred work.

Non-goals say what the thing is not. Deferred work says what it is not *yet* — that belongs in open positions or a tie-off. Conflating them turns the non-goals section into a backlog and destroys its value, which is telling a reader when not to reach for this document.

*Instance:* `COGNITIVE-MODE-AND-AGENCY` §10 — "Not new authority," "Not an autonomous goal source," "Not affect modeling" are boundaries; "m3 enforcement" is deferred work and correctly sits in §7 instead.

*Triggers:* document creation.

### A10 — Number verifiable outcomes under a per-document prefix.

Outcomes get a short document-specific prefix and sequential numbers, so they are citable from elsewhere in the corpus without ambiguity. The prefix is a namespace, and per-document namespaces are already accepted practice.

*Instance:* DL1–DL7 (doom-loop), TE1–TE7 (SLM training), CA1–CA11 (act accounting), MA1–MA7 (mode and agency).

*Triggers:* document creation for any design or elaboration document.

---

## Receipt shape

Each heuristic promotes to the schema declared in `IMPROVEMENT-LOOP-DISCIPLINE-2026-07.md` §"Chain-anchored heuristics", with `domain: authoring`:

```
{
  "event": "heuristic:workflow:authoring:<heuristic_id>",
  "heuristic_id": "<content_hash>",
  "issued_at": "<timestamp>",
  "issuer": "<operator | regent_via_precedent>",
  "domain": "authoring",
  "statement": "<the A-numbered statement above, verbatim>",
  "elaboration": "<the paragraph and instance above>",
  "triggers": ["<the trigger line above>"],
  "example_arcs": ["<arc_ids where applied>"],
  "canary_schedule": "<per authored document, or per N documents>",
  "supersedes": [],
  "expiry": null
}
```

**Canary for this domain is document-shaped rather than cycle-shaped.** The natural verification is: for the last N documents authored, did each satisfy the heuristics whose triggers fired? That check is deterministic for A1, A2, A9 and A10 — the structural ones — and requires reading for A4, A5 and A8. Start with the structural four; the others accumulate evidence before they get a canary.

---

## Delivery

**These reach the Regent through Class 2b or they reach nobody.** `IMPROVEMENT-LOOP-DISCIPLINE` specifies Class 2b — *active heuristics matching this cycle's arc-class* — as a Tier 1 cognitive-input class alongside standing corrections. It is specified and unimplemented. Until it exists, the Regent's authoring context is the nine design principles in Class 1 and nothing else, and this document is scaffolding for operator and external agent only.

`triggers` is the field that makes Class 2b selective: an authoring cycle loads the authoring domain, a remediation cycle does not. Without trigger-matching the alternative is loading all heuristics every cycle, which contradicts *context is a priority-weighted stream, not a bucket*.

---

## Open positions

- **Does the ADR shape itself become an eleventh heuristic?** `EXECUTION-AUTHORITY-MODEL` demonstrates a clean section sequence — Decision, Context, Target State, Migration Path, Impact on Existing Subsystems, Relationship to Design Principles, What This ADR Does Not Decide, Success Criteria. Whether to promote that sequence as a template or leave it as a demonstrated instance is unresolved. Templates are easier for an agent author and produce more uniform documents; they also produce documents that fill sections rather than make arguments. Resolution: whether Regent-authored ADRs under A1–A10 alone come out well-formed, measurable once she authors any.
- **Canary scope for A4, A5, A8.** These require reading to verify, which means either an inference call per document or operator spot-check. Whether the cost is worth it, or whether the structural four carry enough of the discipline, is unresolved pending evidence about which heuristics actually get violated.
- **Who may issue authoring heuristics.** `issuer` permits `regent_via_precedent`. Whether the Regent may propose a *form* rule — as opposed to applying one — is a stronger authority than proposing a remediation, since it shapes every subsequent document. Prefer operator ceremony for this domain specifically, at least until the promotion path has evidence behind it.

---

## Non-goals

- **Not a template.** These are constraints a document must satisfy, not sections to fill. A document that satisfies all ten and makes no argument has failed at something the discipline cannot check.
- **Not a substitute for the nine design principles.** Those govern what the substrate is. These govern how a document about it is written. An authoring heuristic never overrides a design principle.
- **Not applicable to Tier 3.** Historical documents are frozen at authoring frame and are never amended for corpus pivots, including for conformance to this domain.
- **Not tone or voice.** Register, length, and phrasing are operator preference and stay in `CLAUDE.md`. Nothing here constrains how a sentence sounds.
- **Not a gate.** No document is blocked on conformance. The canary observes; it does not enforce, per *instrumentation before remediation*.
