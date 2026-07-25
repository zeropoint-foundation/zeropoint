# Spec–Implementation Coherence — Investigation

**Document type:** Investigation. Not a Tier 2 canonical elaboration — it elaborates no KEEL section, it audits the relationship between the corpus and `crates/`. Records a bidirectional audit, a failed audit method, and nominates one convention plus one discipline pin. Tier 3 input, frozen at authoring frame.

**Date:** 2026-07-25. Method: code-declared spec citations at commit `4cb9e44`, after an initial symbol-grep pass was discarded as unsound (§2).

**Motivation:** Three documents authored earlier this session asserted mechanisms existed because Tier 2 specifications described them; a read of `crates/` found two absent. `AUTHORING-DISCIPLINE-2026-07.md` A11 was extracted from that failure. This investigation applies A11 to the corpus at large — and in doing so committed the inverse error, which turned out to be the more useful finding.

**Composes with:** `AUTHORING-DISCIPLINE-2026-07.md` §A11 (the heuristic this operationalizes and amends), `COGNITIVE-SELF-OBSERVER-2026-07.md` (whose implementing module is the exemplar the nominated convention generalizes), `crates/zp-discipline/tests/verbs_must_match_schema.rs` (the existing pin whose shape the nominated fix copies), `EMPIRICAL-PROGRAM-2026-07.md` (where a coherence claim would live if adopted).

---

## Framing

**1. The status information already exists — in the code, not the corpus.** `crates/zp-regent/src/cognitive_observer.rs` opens by citing its spec, declaring its v1 scope, and naming five deferred items with tracking identifiers. That module header is a more accurate status document for KEEL §II.17 than KEEL is. The corpus has no equivalent, so the honest state of the substrate is legible from the code and not from the document set that governs it.

**2. Direction of audit determines correctness.** Spec-to-code auditing by symbol name produces false negatives, because code names things differently than documents do. Code-to-spec auditing by declared citation is reliable, because the citation is authored by whoever implemented the thing. This investigation got that wrong first and is the instance.

**3. The gap is representational, not structural.** Every absence found is planned and tracked. Nothing here indicates substrate failure. What it indicates is that a reader — and specifically the Regent, who is being designed to author against this corpus — cannot tell a specified component from a shipped one without reading Rust.

---

## 1. Findings

Built from code-declared spec citations (`//! Spec: docs/…`) and module inspection, not from symbol matching.

| KEEL Layer A component | Status | Evidence |
|---|---|---|
| Chain schema, crypto primitives, Genesis | **Shipped** | pervasive across `zp-core`, `zp-keys`, `zp-audit` |
| Officer trait | **Shipped** | `trait Officer` in `zp-officers` |
| Canonicalization ceremony machinery | **Shipped** | 194 occurrences |
| Cognitive Input Plane (§II.15, §II.17) | **Shipped** | `emit_composition_receipt`, `zp-regent/src/loop_runner.rs:719`; cites `COGNITIVE-INPUT-PLANE-2026-07.md` |
| **Cognitive Self-Observer (§II.17)** | **Shipped, v1 scope** | `cognitive_observer.rs` (764 lines) + `cognitive_observer_semantic.rs` (990 lines); emits `cognitive:correction:violated`, `cognitive:observer:verified` |
| **Claim Verifier (§II.17)** | **Specified** | referenced only as a deferred item, `cognitive_observer.rs:18` — "Class 7 capability verification (P2.3 Claim Verifier)" |
| **Cartographer trait (Part I, §II.10)** | **Specified** | no trait, no materializer; `cognitive_observer.rs:16` notes Class 2 "needs Cartographer ontology" |
| **Chain-watcher + commitments (§II.18)** | **Specified** | `cognitive_observer.rs:17` — "needs P2.4 commitment primitives" |
| Circuit-breaker L1–L4 ladder | **Specified** | `cognitive_observer.rs:20` — "Circuit breaker integration (L1-L4 escalation)" deferred. `circuit_breaker_threshold` in `zp-policy/src/gate.rs` is a **different mechanism** — a consecutive-failure counter — sharing a name |
| WASM sandbox surface (§II.19) | **Thin** | 6 occurrences; `zp-server/src/wasm_policy.rs` |

**The `cognitive_observer.rs` header is the exemplar.** It cites its spec, declares v1 scope, and enumerates its own deferrals with tracking IDs. Every one of the "specified" rows above was recovered *from that file*, not from the corpus. The code is doing the corpus's job.

**The circuit-breaker name collision is the one hazard that inspection cannot catch.** A reader grepping for the mechanism finds a hit, confirms it exists, and is wrong — the ladder five documents compose with by name is not the counter that resolves. Only a link between the spec and its implementing module distinguishes them.

---

## 2. The failed method, recorded

The first pass of this investigation searched `crates/` for symbols derived from document language — `ClaimVerifier`, `SelfObserver`, `confabulation_gap`, `ChainWatcher` — and returned zero for all four. It concluded that KEEL §II.17 and §II.18 were entirely unimplemented, and drafted a finding that the substrate binary was non-conformant to its own invariant layer.

That conclusion was false. The Cognitive Self-Observer is 1,754 lines across two modules. It does not contain the string `SelfObserver` because the code calls it `cognitive_observer`.

**The error is the same class as the one that motivated the investigation**, inverted. Reading a spec as inventory assumes the document describes the code. Grepping doc-derived symbols assumes the code is named after the document. Both assume a correspondence that nothing enforces — which is precisely the finding.

Recorded here rather than quietly corrected because A11 is weaker without it: the heuristic says distinguish specified from shipped, and this establishes that *how you check* determines whether you can.

---

## 3. Assessment

**Confirm** — the corpus does not distinguish specified from shipped, and A11 was correctly extracted.

**Reveal a gap** — the fix is not to invent a status marker for the corpus. It is to **propagate upward the status the code already declares**, and to make the spec↔implementation link explicit in both directions so that either side can be checked against the other.

**Raise urgency on** — the Regent is being designed to author decision records against this corpus. Of the roughly 130 documents in `docs/`, about 20 are cited from code. She has no way to tell the other 110 apart from the 20 without reading Rust, and the mechanism that would catch a resulting confabulated capability claim is the Claim Verifier, which is itself specified rather than shipped.

---

## 4. Nominated action

**(a) A convention, already in practice.** Every module implementing a spec carries a citation in its header — `//! Spec: docs/design/X.md` — as `cognitive_observer.rs`, `canary.rs`, `coherence.rs` and about seven others already do. Make it a rule rather than a habit.

**(b) A reciprocal section in the corpus.** Every Tier 2 document carries `## Implementation status`, naming implementing modules or declaring `specified`. Source it from the code's own deferral list rather than authoring it fresh — `cognitive_observer.rs`'s five-item list is the template.

**(c) A discipline pin: `crates/zp-discipline/tests/spec_links_resolve.rs`.** Two assertions, both mechanical:

1. Every `//! Spec:` citation in `crates/` resolves to a file that exists in `docs/`. Catches renamed and deleted specs.
2. Every document declaring an implementing module names one that exists. Catches the reverse drift.

Neither assertion requires symbol matching, which §2 established is unsound. Both fail the build rather than a later design session, which is the property the seventeen existing pins have and this gap does not.

**Effect.** A11 stops being a heuristic an author must remember and becomes a build-time assertion — and the circuit-breaker class of name collision becomes structurally detectable, because the link is to a document rather than to a string.

---

## 5. Open positions

- **Does KEEL Layer A itself need status markers?** Part I says Layer A is "compiled into the substrate binary." Four of its named components are not. Either the sentence acquires a qualifier, or the unimplemented components move to Part IX until they ship. The second is cleaner and larger — §II.17 and §II.18 are cited by name across at least eight Tier 2 documents. Resolution: whether those documents read coherently with the sections relocated.
- **Retroactive application.** About 110 documents have no code citation. Adding `## Implementation status` to all of them is a large mechanical pass with modest yield, since most describe things nobody has started. The forward-only preference argues for applying the convention to new and amended documents only. Undecided.
- **Who authors the status section.** Sourcing it from code deferral lists means the implementer's view wins, which is right for accuracy and wrong if the deferral list is stale. A canary on the pin would catch staleness; whether that is worth its cost is unresolved.

---

## 6. Non-goals

- **Not a claim that the substrate is broken.** Every absence found is planned and tracked in code. The finding concerns how the corpus represents its own state.
- **Not a proposal to implement the missing components.** Sequencing for the cognitive-layer members sits in `COGNITIVE-PRIMITIVES-ARC-PLAN-2026-07.md`.
- **Not an audit of implementation quality.** A resolving citation is evidence a module exists and claims a spec, not evidence it satisfies it.
- **Not a corpus-wide sweep.** Layer A and the cognitive path only. Extending it is an open position, not a commitment.
