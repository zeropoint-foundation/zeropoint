# Intent Crystallization — Canonicalization Ceremony

**Status:** Proposal, not enacted. This document specifies the *enactment protocol* for INTENT-CRYSTALLIZATION-PRIMITIVE-2026-08. The primitive doc is the design; this doc is what turns the design into force. Neither the ceremony nor the primitive is in force until the operator performs the signed act specified below.
**Companion to:** STANDING-IMPASSE-CANONICALIZATION-CEREMONY-2026-08 (parallel ceremony for the closing-event primitive).
**Composes with:** KEEL Part VI (canonicalization ceremony as a discipline), ARTIFACT-LIBRARY-2026-05 (candidate → signed lifecycle), STANDING-CORRECTION-RECEIPT-SCHEMA (retire pathway), COGNITIVE-INPUT-PLANE-2026-07 (post-ceremony tier addition), COGNITIVE-MODE-AND-AGENCY-2026-07 (post-ceremony active repertoire).

---

## 1. What this ceremony is for

The INTENT-CRYSTALLIZATION-PRIMITIVE-2026-08 exists as a Tier-2 proposal. Its discipline is currently *descriptive* — the corpus knows what crystallization is, what the shaping repertoire looks like, what receipts would be emitted, what verification classes would fire. But no substrate behavior currently checks for crystallization warrant; no Regent shaping act is currently well-typed against the §5 repertoire; the Cognitive Self-Observer does not currently fire on pre-emission commitment defects. The primitive is *shelved intention*, not enacted discipline.

This ceremony moves the primitive from proposal to enacted Layer-B canonical. Post-ceremony:

- CLAIM-VERIFIER requires a crystallization receipt for any capability/commitment claim
- COGNITIVE-INPUT-PLANE distinguishes pre-crystallization exploration from post-crystallization directive at the tier level
- COGNITIVE-MODE-AND-AGENCY declares the §5 shaping repertoire as Conversational mode's active discipline
- COGNITIVE-SELF-OBSERVER gains two verification classes (pre-emission commitment defect; leading-question-masquerading-as-forcing defect)
- REGENT-DOOM-LOOP-DETECTION chronic-drift heuristics distinguish pre-crystallization meander from model degradation
- LENS-DISCIPLINE gains `lens:declared:intent_crystallization`

## 2. Pre-ceremony state

Fixed at ceremony start via `cognitive:ceremony:precondition_check:v1` receipt. Fields recorded:

- Primitive doc content hash: SHA-256 of `docs/design/INTENT-CRYSTALLIZATION-PRIMITIVE-2026-08.md` as read
- Corpus-index entry hash: SHA-256 of the INTENT-CRYSTALLIZATION line in `docs/CANONICAL-CORPUS-INDEX-2026-07.md`
- Substrate version: substrate binary git SHA at ceremony moment
- Chain-tip: chain position at ceremony moment
- Composition-surface preconditions: for each of the six composition surfaces in §7 of the primitive doc, a witness that the surface currently has no invariant that would be violated by enactment

If any composition-surface precondition check fails, the ceremony aborts and emits `cognitive:ceremony:precondition_failed:*` with the failing surface named. No enactment occurs.

## 3. Ceremony steps

**Step 3.1 — Operator primary read.** Operator reads the primitive doc in full at primary. Not a subagent-summarized read; the operator's own eyes over the six detection signals (§3.1-3.6), six shaping repertoire moves (§5.1-5.6), six receipt schemas (§6), nine composition surfaces (§7), five substrate-discipline collision resolutions (§8), six non-goals (§9), and Ken's preserved three-turn crystallization arc (§11). Emits `cognitive:ceremony:operator_read:complete:v1` with content-hash attestation.

**Step 3.2 — Disconfirming-observation check.** Operator explicitly considers the three disconfirming observations in §10.7 of the primitive doc: (a) crystallization is adequately handled by mode transitions; (b) explicit shaping is architectural theater; (c) the substrate-discipline collision doesn't actually resolve. For each, operator records whether the observation holds. If any hold, the ceremony aborts and emits `cognitive:ceremony:disconfirmation_upheld:*`. If none hold, emits `cognitive:ceremony:disconfirmation_rejected:v1`.

**Step 3.3 — Reflexivity check.** Operator considers: if this primitive were in force during the drafting of *this ceremony doc*, what would have been different? The answer is recorded on the chain as a witness that the operator has personally applied the primitive's own discipline reflexively. Emits `cognitive:ceremony:reflexivity_witnessed:v1`.

**Step 3.4 — Scoped-subagent verification (recommended).** A scoped subagent reads the primitive doc against each of the nine composition surfaces (§7) and reports whether any composition surface has a currently-broken invariant that the primitive's activation would violate or amplify. Subagent-report hash is recorded. If the subagent identifies a broken invariant, operator judgment determines whether to abort, defer, or proceed with the invariant noted for correction post-ceremony.

**Step 3.5 — Operator signature.** Operator emits `cognitive:primitive:canonicalized:intent_crystallization:v1`, chain-anchored, Genesis-signed. Fields: primitive-doc-hash, ceremony-doc-hash, precondition-receipt-hash, all step-attestation-hashes, enacted-scope enumeration (the nine composition surfaces), retire-path pointer, effective-chain-position.

**Step 3.6 — Post-ceremony emission cascade.** The following receipts emit automatically once §3.5 signs:

- `regent:cognitive_input_plane:tier_added:pre_crystallization_exploration:v1`
- `regent:mode:conversational:active_repertoire:enacted:v1`
- `regent:self_observer:class_added:pre_emission_commitment_defect:v1`
- `regent:self_observer:class_added:leading_question_masquerade_defect:v1`
- `regent:claim_verifier:constraint_added:crystallization_warrant_required:v1`
- `regent:doom_loop:heuristic_added:pre_crystallization_meander_distinction:v1`
- `regent:lens:declared:intent_crystallization:v1`

Each cascade receipt is a Layer-B canonical claim traceable to the ceremony's `cognitive:primitive:canonicalized:*` receipt.

## 4. Post-ceremony state

The primitive is enacted. Its discipline is prescriptive, not descriptive. Concretely:

- Any Regent substantive emission on a subject not backed by a `intent:crystallized:*` receipt is a Class-N defect. The Cognitive Self-Observer will flag it.
- Any Regent shaping utterance not typed against one of §5.1-5.6 of the primitive doc is unwarranted and flagged.
- Operator standing corrections may now use `correction_type: shaping:bounded` to constrain shaping on specific topics.
- Cartographer materializes `CrystallizationTrajectory` typed objects from the receipt stream.

The Cowork session that performs this ceremony emits its own `intent:crystallized:*` receipt for the ceremony's subject as its final act (self-application) — the ceremony is the crystallization moment for the primitive itself.

## 5. Retire path

If the primitive proves to be a mistake — the disconfirming observations from §3.2 begin to hold post-enactment, or the shaping repertoire proves not to be closed as claimed, or a specific composition surface breaks — the operator emits `cognitive:primitive:retired:intent_crystallization:v1`, chain-anchored, Genesis-signed. Fields: reason narrative, effective-chain-position, cascade-receipts-to-retire (mirrors §3.6).

Retirement is forward-only per KEEL III.20. The primitive is not "un-enacted" — its enacted period between canonicalization and retirement remains permanently on chain as an audit trail. The primitive-doc file is not deleted; it gains a header annotation naming the canonicalization date, the retirement date, and the reason.

Cascade retirements fire automatically:

- Verification classes retire from Cognitive Self-Observer
- CLAIM-VERIFIER constraint retires
- CIP tier reverts to pre-canonicalization structure
- Conversational mode's active repertoire reverts to unenumerated

Historical receipts (`intent:crystallized:*`, `regent:shaping:*`) remain on chain and remain valid witnesses of the acts they attested. They just no longer feed the retired verification classes.

## 6. Non-goals

- Does not enact STANDING-IMPASSE-PRIMITIVE (that's a separate ceremony)
- Does not amend KEEL Layer A (Layer A amendments require substrate binary release per KEEL III.6)
- Does not authorize training-data extraction from crystallization receipts (per primitive §9)
- Does not authorize the substrate to modify its own §5 repertoire without a subsequent operator ceremony
- Does not silently propagate to sovereign peers — peer substrates enact via their own ceremonies, or compose via KEEL Part VII peer-verification (a peer that has not enacted the primitive is not defective; it is at a different canonicalization state)

## 7. Composition ordering with STANDING-IMPASSE ceremony

Either primitive can be canonicalized without the other. The corpus is not corrupted if one is enacted and the other remains proposal. If both are enacted, the cognitive-thread lifecycle ontology is complete at both endpoints (crystallization opens, three-class impasse closes). If only crystallization is enacted, cognitive threads open with witness but close via the pre-existing resolve-or-abandon binary. If only standing-impasse is enacted, cognitive threads close with three-class witness but open under pre-crystallization discipline.

Recommended ordering: crystallization first. Its own discipline can then guide the standing-impasse ceremony's operator-read and reflexivity-check phases.
