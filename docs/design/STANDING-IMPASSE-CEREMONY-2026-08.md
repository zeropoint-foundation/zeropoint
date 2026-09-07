# Standing Impasse — Canonicalization Ceremony

**Status:** Proposal, not enacted. This document specifies the *enactment protocol* for STANDING-IMPASSE-PRIMITIVE-2026-08. The primitive doc is the design; this doc is what turns the design into force. Neither the ceremony nor the primitive is in force until the operator performs the signed act specified below.
**Companion to:** INTENT-CRYSTALLIZATION-CANONICALIZATION-CEREMONY-2026-08 (parallel ceremony for the opening-event primitive).
**Composes with:** KEEL Part VI (canonicalization discipline), Cartographer typed-object registry, PRECEDENT-APPLICATION discipline (undocumented but active), STANDING-CORRECTION-RECEIPT-SCHEMA.

---

## 1. What this ceremony is for

The STANDING-IMPASSE-PRIMITIVE-2026-08 exists as a Tier-2 proposal. Its discipline is currently *descriptive* — cognitive threads today terminate via resolve (compile to precedent) or abandon (fail, hang, drop). Tie-off exists as a shape the substrate has been reaching toward but not naming; operators recognize it in conversation, the Chain preserves the exploration when threads simply end without decision, but no receipt attests to *"this thread ended intentionally without resolution"* as distinct from *"this thread ended because we ran out of things to say."*

This ceremony moves the primitive from proposal to enacted Layer-B canonical. Post-ceremony:

- Cognitive threads terminate via one of exactly three classes: `impasse.resolved`, `impasse.tied_off`, `impasse.abandoned`
- Cartographer materializes a new typed object class, `StandingImpasse`, distinct from Decision (resolved) and Friction (abandoned)
- Precedent-application discipline extends: a query returning a Standing Impasse informs the caller *"this class of question has been explored; no decision reached; the tie-off was intentional"* — genuinely different information from "no precedent" or "resolved as X"
- Un-tie ceremony shape becomes registered: a Standing Impasse can be re-opened by later operator ceremony, with the re-opening itself chain-anchored as a Chain event

## 2. Pre-ceremony state

Fixed at ceremony start via `cognitive:ceremony:precondition_check:v1` receipt. Fields recorded:

- Primitive doc content hash: SHA-256 of `docs/design/STANDING-IMPASSE-PRIMITIVE-2026-08.md` as read
- Corpus-index entry hash: SHA-256 of the STANDING-IMPASSE line in `docs/CANONICAL-CORPUS-INDEX-2026-07.md`
- Substrate version: substrate binary git SHA at ceremony moment
- Chain-tip: chain position at ceremony moment
- Cartographer schema-registry state: witness that no existing typed-object class conflicts with the proposed `StandingImpasse` schema

If Cartographer's schema registry conflicts (e.g., an existing typed object shares the name), the ceremony aborts and emits `cognitive:ceremony:precondition_failed:cartographer_schema_conflict:*`. No enactment occurs.

## 3. Ceremony steps

**Step 3.1 — Operator primary read.** Operator reads the primitive doc in full at primary. Emphasis on §2's three-termination-class enumeration (that the set is closed at three, not left open) and §11's preservation of Ken's original framing (*"seamlessly handling impasse threads that tie off, rather than resolve decisively"*). The word *seamlessly* is the load-bearing constraint: tie-off must not be an exception, an anomaly, or a fallback. Emits `cognitive:ceremony:operator_read:complete:v1` with content-hash attestation.

**Step 3.2 — Historical-impasse survey.** Operator (or scoped subagent) surveys existing threads on the chain that terminated via the pre-canonicalization resolve-or-abandon binary. For each terminated thread, does the termination match the intended semantics of `impasse.resolved` (signed decision → precedent) or `impasse.abandoned` (dropped without exploration)? Or would it, under the three-class discipline, be more accurately classified as `impasse.tied_off`? This is *not* a re-classification ceremony — historical receipts remain as they were emitted. It is a witness that the primitive's three-class enumeration matches the population of terminations the substrate has actually produced. Emits `cognitive:ceremony:historical_survey:complete:v1` with counts per class and a small sample of edge-case terminations for future audit.

**Step 3.3 — Disconfirming-observation check.** Operator explicitly considers the three disconfirming observations in §10.7 of the primitive doc: (a) tie-off is redundant with a "provisional Decision" object that defers resolution; (b) tie-off is just an unresolved Friction with a longer patience window; (c) the tradition's resolve-or-fail binary is correct and the substrate should not add a third class. For each, operator records whether the observation holds. If any hold, the ceremony aborts. If none hold, emits `cognitive:ceremony:disconfirmation_rejected:v1`.

**Step 3.4 — Un-tie ceremony shape agreement.** Operator agrees to the shape of the un-tie ceremony: a Standing Impasse may be re-opened by later operator ceremony emitting `impasse.tied_off:untied:v1`, chain-anchored, Genesis-signed, referencing the original tie-off receipt. The un-tie ceremony is not a retirement of the tie-off — the original tie-off receipt remains valid; the un-tie is a new chain event that says *"exploration on this subject resumes; the tie-off is superseded but not repudiated."* The re-opened thread runs under whatever cognitive-thread discipline is currently in force.

**Step 3.5 — Operator signature.** Operator emits `cognitive:primitive:canonicalized:standing_impasse:v1`, chain-anchored, Genesis-signed. Fields: primitive-doc-hash, ceremony-doc-hash, precondition-receipt-hash, historical-survey-receipt-hash, disconfirmation-receipt-hash, un-tie-ceremony-shape-agreed-hash, effective-chain-position.

**Step 3.6 — Post-ceremony emission cascade.** The following receipts emit automatically once §3.5 signs:

- `cartographer:schema:registered:standing_impasse:v1`
- `cognitive:termination_classes:enumerated:three:v1`
- `precedent:application_discipline:extended:standing_impasse_awareness:v1`
- `cognitive:ceremony:shape_registered:impasse_untied:v1`

## 4. Post-ceremony state

The primitive is enacted. Cognitive threads terminate via three classes. Cartographer materializes Standing Impasse typed objects from the receipt stream and makes them queryable via the same interfaces that surface Decisions and Frictions — with the semantic distinction preserved. Precedent lookups on subjects find "here is what has been explored; no decision; tie-off intentional" as a first-class result, not as "no precedent" or "resolved as X."

Threads that were terminated before this ceremony under the resolve-or-abandon binary retain their historical classifications on chain. They are not automatically re-classified; a specific operator ceremony could re-classify individual threads if desired, but that is a separate operator judgment call and not a consequence of this canonicalization.

## 5. Retire path

If the primitive proves to be a mistake — the disconfirming observations from §3.3 begin to hold, or the three-class enumeration proves insufficient (a fourth class needed) or excessive (tie-off collapses back into abandonment) — the operator emits `cognitive:primitive:retired:standing_impasse:v1`, chain-anchored, Genesis-signed. Fields: reason narrative, effective-chain-position, cascade-receipts-to-retire.

Retirement is forward-only per KEEL III.20. Standing Impasse typed objects emitted during the enacted period remain on chain as historical objects and remain queryable. Post-retirement, no new Standing Impasse objects are created; new tie-offs would fall back to whatever classification schema is currently in force (likely resolve-or-abandon binary). Historical Standing Impasse objects are still visible to Cartographer but flagged as "from retired schema."

## 6. Non-goals

- Does not enact INTENT-CRYSTALLIZATION-PRIMITIVE (separate ceremony)
- Does not automatically re-classify historical impasse events (opt-in per-thread only)
- Does not amend KEEL Layer A (though it composes with §III.20 forward-only recovery and §III.13 chain-truth invariants)
- Does not add a fourth termination class in the future without a subsequent ceremony (the three-class enumeration is closed by design; opening it requires a distinct ceremony that names the fourth class and the discriminating semantics)
- Does not silently propagate to sovereign peers

## 7. Composition ordering with INTENT-CRYSTALLIZATION ceremony

Either primitive can be canonicalized without the other. If crystallization is enacted first, the standing-impasse ceremony's operator-read and disconfirmation-check phases run under crystallization discipline — which improves them. If standing-impasse is enacted first, cognitive threads gain three-class closing before they gain first-class opening, which is a valid but asymmetric substrate state.

Recommended ordering: crystallization first, standing-impasse second. Both landing produces a cognitive-thread lifecycle ontology complete at both endpoints.
