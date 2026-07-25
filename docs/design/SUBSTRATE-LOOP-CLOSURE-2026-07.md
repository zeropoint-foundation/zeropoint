# Substrate Loop Closure — Investigation

**Document type:** Investigation. Not a Tier 2 canonical elaboration — it elaborates no KEEL section, it audits the correspondence between the loop the corpus describes and the loop the runtime implements. Tier 3 input, frozen at authoring frame. Nominates instrumentation for three edges and names one structural question the corpus has not asked.

**Date:** 2026-07-25. Method: code-declared spec citations and module inspection at commit `4cb9e44`, per `SPEC-IMPLEMENTATION-COHERENCE-INVESTIGATION-2026-07.md` §2 — not symbol matching.

**Motivation:** The design corpus has grown to roughly 130 documents and has produced seams of its own. Six were found incidentally in one session while working on something else, which is the diagnostic signature named in `CLAUDE.md` — *when a PoC keeps surfacing new friction at every layer, the friction is the finding*. This investigation asks the systemic version of that question: the corpus describes the substrate as a closed loop; is it closed?

**Composes with:** `SPEC-IMPLEMENTATION-COHERENCE-INVESTIGATION-2026-07.md` (the audit method and the E1 findings this generalizes), `ONTOLOGY-AND-CARTOGRAPHER-2026-07.md` (the specification for the two broken edges), `COGNITIVE-INPUT-PLANE-2026-07.md` (E5, the one fully live cognitive edge), `IMPROVEMENT-LOOP-DISCIPLINE-2026-07.md` (Class 2b, the mechanism E6 needs), `AUTHORING-DISCIPLINE-2026-07.md` (E7's discipline, written the same day and dependent on E6), `SYSTEM-OFFICER-CADRE-2026-06.md` (the officers whose read path E4 concerns).

---

## Framing

**1. The corpus describes a cycle, not a stack.** Specs govern code; code emits receipts; receipts materialize as ontology; officers and Regent read the ontology; Regent authors specs. Each document describes its own edge correctly. No document describes the loop, so no document notices where it is open.

**2. Three of seven edges are broken, and the breaks are not independent.** Two cascades, not three faults. That is the load-bearing structure of this audit and it changes the work order.

**3. The corpus asserts a property the runtime contradicts.** `CLAUDE.md` states "Officers query the ontology, not raw receipts." KEEL §III.5 states the Cartographer "provides read-only ontology access to officers and Regent." Officers read `AuditStore` directly. This is not a documentation lag — it is a fragility the corpus says is structurally impossible.

---

## 1. The seven edges

| # | Edge | Status | Enforcement | Evidence |
|---|---|---|---|---|
| **E1** | Corpus → Code | **Unenforced** | none | ~20 of ~130 documents carry a `//! Spec:` citation from `crates/`; 17 discipline pins exist, none checks spec conformance |
| **E2** | Code → Chain | **Live, partly instrumented** | receipt-prefix registry | `zp-server/src/substrate_validate.rs` holds a hardcoded list of known receipt prefixes, including the cognitive ones |
| **E3** | Chain → Ontology | **Broken** | — | No Cartographer, no `Trajectory` struct. Only occurrence of "Cartographer" in `crates/` is a string in a model-evaluation fixture |
| **E4** | Ontology → Officers | **Broken by consequence** | — | Officers read `AuditStore` and `search_by_keyword` directly — `zp-officers/src/governance_posture.rs:224` |
| **E5** | Chain → Regent context | **Live** | composition receipt | `emit_composition_receipt`, `zp-regent/src/loop_runner.rs:719` |
| **E6** | Corpus → Regent cognition | **Broken** | — | Class 1 carries the nine design principles; Class 2b (active heuristics) specified in `IMPROVEMENT-LOOP-DISCIPLINE` and unimplemented. The 28 workflow heuristics have no delivery path |
| **E7** | Regent → Corpus | **Aspirational** | — | `AUTHORING-DISCIPLINE-2026-07.md` written 2026-07-25; depends entirely on E6 |

Officers → Chain, where findings emit as receipts, is live and sits inside E4's return path. It is not broken and is omitted from the table for that reason.

---

## 2. The two cascades

**Cascade A: E3 → E4.** The absent Cartographer does not merely leave the ontology unbuilt. Officers still need to read chain state, so they fell back to raw receipt queries — which couples them to receipt string formats. That coupling is the specific thing the ontology layer exists to prevent, and it means **a receipt-format change can break an officer silently**, in a substrate whose corpus asserts officers are insulated from receipt formats.

This is worse than an absence, because absence is visible and this is not. Nothing fails; the officers work. The fragility only surfaces when a receipt string changes, at which point the failure appears in a component that has no declared dependency on the thing that changed.

**Cascade B: E6 → E7.** The Regent cannot author against a corpus she does not receive. `AUTHORING-DISCIPLINE-2026-07.md` was written to give her the document form; Class 2b is the only path by which it, or the 28 workflow heuristics, reaches her cycle. Until E6 closes, E7 is scaffolding for operator and external agent, and the authoring discipline says so in its own §Delivery.

**Consequence for work order.** The Cartographer has been sequenced as a dependency inside the cognitive-act arc. It is not — it is the highest-leverage absence in the substrate, because it is the only one that breaks two edges and manufactures a fragility the corpus denies. That is a re-prioritization, not a new finding.

---

## 3. The structural question the corpus has not asked

The loop is a **cycle**. Closing E7 means the Regent authors the corpus that governs her own cognition, which arrives back through E6 to shape the context she reasons in.

That is a self-modification path. It is gated — P9 requires operator signature on every consequential act, and `AUTHORING-DISCIPLINE` §Open positions already prefers operator ceremony for authoring heuristics specifically. So the cycle is not ungoverned. But **no document names it as a cycle**, which means nothing has evaluated the feedback properties: whether a Regent-authored heuristic that shapes her own context assembly is stable, whether drift accumulates across generations of authored corpus, or whether the operator signature is a sufficient damper at the rate corpus changes.

The substrate bounds recursion carefully everywhere else — §III.12 caps observer nesting at two or three levels, `LENS-DISCIPLINE` §8 terminates lens-of-lens structurally, `IMPROVEMENT-LOOP-DISCIPLINE` terminates its meta-loop by requiring authorization per arc. The corpus→cognition→corpus cycle is the one recursion that has never been bounded, because it has never been named.

Naming it is the contribution of this document. Bounding it is not proposed here.

---

## 4. Minimum slice

Consistent with the substrate's standing posture: instrumentation before remediation. **None of the following requires the Cartographer.**

**S1 — Close E1 with a linter.** `tools/corpus-lint/` running over `docs/` and `crates/`: tier declarations present per A1; Tier 2 documents naming KEEL sections that exist; cross-document and section references resolving; duplicate headings; stated counts against table rows; documents missing from the corpus index and index entries pointing at absent files; `//! Spec:` citations resolving in both directions. Every check is justified by a defect found in one session.

**S2 — Close E2's gap by making the registry canonical.** `substrate_validate.rs`'s receipt-prefix list is already the de-facto receipt vocabulary. Check documented receipt strings against it. This is the check that catches the standing-correction name split (`regent:standing_correction:*` in the input-plane spec versus `cognitive:correction:*` in the schema doc and in the code) and the circuit-breaker collision, automatically.

**S3 — Contain E4's coupling.** Not a fix — a containment. Centralize officer chain reads behind one helper so the receipt-string dependency is in a single place with a declared list, rather than distributed across officers via `search_by_keyword`. When the Cartographer lands, that helper is the seam it replaces. Until then the fragility is visible and enumerable instead of silent.

S1 and S2 are mechanical and can run in CI. S3 is a small refactor with a clear boundary. Together they make three edges honest without building anything large.

---

## 5. Verifiable outcomes

- **SC1** — Every `//! Spec:` citation in `crates/` resolves to a file in `docs/`, and every document claiming an implementing module names one that exists.
- **SC2** — Every receipt string appearing in `docs/` either appears in the `substrate_validate.rs` registry or is marked as specified-not-shipped.
- **SC3** — Every Tier 2 document names a KEEL section that exists in `KEEL-2026-07.md`.
- **SC4** — No document contains duplicate section headings, and no cross-document section reference resolves to a section that does not exist.
- **SC5** — Officer chain reads are enumerable from a single location; the set of receipt strings officers depend on is a queryable list.
- **SC6** — Every document in `docs/` appears in the corpus index, and every index entry resolves to a file.

---

## 6. Alternatives considered

Recorded per A6 as tie-offs rather than prose asides.

- **Full corpus audit of all ~130 documents.** *Declined.* Unbounded, and its output is a document rather than a standing property — which reproduces the problem it diagnoses. Reopen condition: if S1's finding rate is low, the defects are semantic rather than mechanical and a read pass is the only instrument that would find them.
- **Build the Cartographer first.** *Deferred.* It is the highest-leverage single piece and it is large. S1–S3 are cheaper, and E2's registry plus S3's enumerated read set are direct inputs to its design — you want to know exactly which receipt shapes officers depend on before designing the projection that replaces those reads. Reopen condition: S3 complete, or v0/m0 evidence available.
- **Resolve E4 by ratifying raw chain reads as the officer contract.** *Declined.* It would make the corpus consistent by removing the ontology claim rather than by building the ontology, and it would canonize the receipt-format coupling as intended design. The coupling is real; making it official does not make it safe.

---

## 7. Open positions

- **Should the corpus→cognition→corpus cycle be bounded, and by what?** §3. Operator signature is the current damper and has never been evaluated as one. Resolution: whether Regent-authored corpus material, once E6 and E7 are live, shows drift across generations that operator review does not catch.
- **Does E1 want enforcement or only reporting?** A linter that fails CI on a missing tier declaration is enforcement; one that reports is instrumentation. The substrate's posture favors instrumentation first, but E1 is the edge with no enforcement at all and 110 documents on the wrong side of it. Resolution: S1's first full run — if the failure count is small, enforce; if large, report and burn down.
- **Is E7 desirable at all?** The whole cycle assumes the Regent should author corpus. That was assumed rather than decided. Resolution: whether her first ADRs under A1–A11 come out well-formed enough to be worth the feedback path §3 describes.

---

## 8. Non-goals

- **Not a claim that the substrate is broken.** Every absence found is planned and tracked in code. The finding is that the loop is described as closed and is not.
- **Not a proposal to build the Cartographer.** It re-prioritizes it; it does not design it.
- **Not a corpus-wide document audit.** Seven edges, not 130 documents. The alternative was considered and declined in §6.
- **Not an assessment of implementation quality.** A live edge means the mechanism exists and runs, not that it is correct.
- **Not a proposal to bound the cycle in §3.** Naming it is the contribution; bounding it needs evidence that does not exist yet.
