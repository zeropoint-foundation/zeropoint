# Information Verification

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.5 (Genesis-derived signing), §II.8 (chain-anchored receipts), §III.19 (detectability over invulnerability), §III.22 (verify before commit), Part VII (Peer-Verification Contract). Specifies how the substrate composes citation, attribution, provenance, and verification primitives into an information verification stack. Composes reproducibility ceremony + chain evidence + peer verification into a citation/attribution/verification/provenance layer. Canonical claims live in KEEL.

Draft — 2026-07-11 — internal audience only. Composes with `REPRODUCIBILITY-CEREMONY-2026-07.md` (independent verification of source-to-outcome correspondence), `MEDIA-PROVENANCE-2026-07.md` (C2PA-composing provenance for media artifacts), `SOFTWARE-INTEGRITY-ATTESTATION-2026-07.md` (five-layer attestation stack for software), `PEER-TRUST-ANCHOR-2026-07.md` (peer verification requires trust anchor), `DISTRIBUTED-KNOWLEDGE-COMMONS-2026-07.md` (commons hosts verification signal aggregation), `SUBSTRATE-BLINDNESS-HEURISTICS-2026-07.md` (aligned blindness for claims about non-substrate parties), `CONSEQUENCE-AND-FEDERATION-DISCIPLINE-2026-07.md` (bad-actor false-claim consequence).

## Framing

Substrate participants make claims about the world — what happened, what a source said, who authored something, whether a fact has been checked. Currently these claims circulate with little verification infrastructure — screenshots claim quotes without provenance, articles cite sources readers can't independently verify, images and video circulate without attribution, "fact-checks" from various sources reach conflicting conclusions. This is a coordination and trust failure at civilization scale, not a substrate-specific problem.

Substrate does not attempt to solve the civilization-scale problem. Substrate provides a specific piece: chain-anchored citation, attribution, provenance, and verification primitives that operators use to make their own claims and evaluate others' claims with cryptographic integrity. When operator says "here's what I saw," the claim is Genesis-signed. When operator says "this quote came from X," the citation is chain-anchored with reference to X's chain if X is a substrate participant. When operator says "I verified this," the verification is chain-anchored with reproducibility ceremony discipline supporting independent re-verification.

The stack composes upward: primary sources (chain-anchored observations by original participants) → attributions (who said what, chain-anchored) → citations (this claim references that source) → verifications (this claim has been checked by these verifiers) → provenance chains (trace claim back through citations to primary sources with chain-anchored integrity at every link).

Three properties frame the stack:

1. **Verification is chain-anchored, not authority-declared.** Substrate does not identify authoritative fact-checkers whose declarations become truth. Verification is chain-anchored evidence of who checked what against what; readers evaluate verification chains per their own trust judgments.
2. **Provenance chains are traceable end-to-end.** Any claim in the substrate can be traced through citations to primary chain-anchored sources (where sources are substrate participants) or to external references (with substrate providing chain-anchored evidence of the external reference at time of citation).
3. **Aligned blindness applies to claims about non-substrate parties.** Substrate cannot verify claims about people who don't run substrate (their statements aren't chain-anchored). Substrate can chain-anchor evidence about the claim (screenshot of tweet, recording of speech) but cannot verify the underlying claim without out-of-substrate mechanisms.

## The four verification primitives

Substrate provides four chain-anchored primitives that compose into the verification stack.

### Citation

Chain-anchored reference from one claim to a source:

```
info:citation:<citing_receipt>:<citation_id>
  fields:
    citing_content: <the claim making the citation>
    source_reference:
      chain_reference: <optional — content ID of source receipt if source is substrate>
      external_reference: <optional — URL, DOI, ISBN, other identifier>
      external_snapshot: <optional — chain-anchored hash of source content at citation time>
    citation_type: <quotation | paraphrase | supporting_evidence | contradicting_evidence>
    citation_scope: <what part of source is being referenced>
    signature: <citer's Genesis signature>
```

Citation composes with primary source when available (chain-anchored substrate content) or with external reference when necessary (web content, published works, video recordings). External references include chain-anchored snapshot hash so readers can verify the cited content matches what was cited even if the external source changes later.

### Attribution

Chain-anchored claim about who authored / said / created something:

```
info:attribution:<attributed_content>:<attribution_id>
  fields:
    attributed_content_reference: <content being attributed>
    attributed_to:
      substrate_identity: <optional — attributed party's Genesis pubkey if substrate participant>
      external_identity: <optional — name, role, organization for non-substrate parties>
    attribution_confidence: <first_person | direct_witness | secondhand | claimed | disputed>
    attribution_evidence: <what supports the attribution>
    signature: <attributer's Genesis signature>
```

Attribution to substrate participants: first-person attribution (participant's own claim) is Genesis-signed and unambiguous. Third-party attribution (someone else's claim about who said what) is chain-anchored per attributer with declared confidence level.

Attribution to non-substrate parties: chain-anchored claim about the non-substrate person; verification requires out-of-substrate mechanisms. Substrate does not automatically verify attribution accuracy; substrate chain-anchors who made the attribution.

### Verification

Chain-anchored evidence that a claim has been checked against ground truth:

```
info:verification:<verified_claim>:<verification_id>
  fields:
    verified_claim_reference: <content ID of claim being verified>
    verifier: <verifier's Genesis pubkey>
    verification_method: <what verifier did to check>
      - "direct_observation": verifier witnessed the fact
      - "source_check": verifier consulted cited sources
      - "reproducibility_ceremony": per REPRODUCIBILITY-CEREMONY discipline
      - "cross_reference": verifier compared with independent sources
      - "expert_consultation": verifier consulted domain expert (chain-anchored if expert is substrate participant)
    verification_outcome: <verified | partially_verified | contradicted | uncertain>
    verification_evidence: <what specifically supports outcome>
    verification_scope: <what part of claim is verified>
    signature: <verifier's Genesis signature>
```

Verification is not oracle declaration; it's chain-anchored evidence of what verifier did to check. Reader evaluates verification per verifier's reputation (via commons) and per verification method's rigor.

### Provenance

Chain-anchored traceability from claim through citations back to primary sources:

```
info:provenance:<traced_claim>:<provenance_id>
  fields:
    traced_claim: <content ID of claim being traced>
    provenance_chain: <sequence of citation references>
      - citation_1: <citation_id>
      - citation_2: <citation_id>
      - ...
    primary_sources: <chain-anchored substrate sources or external references at chain endpoints>
    provenance_confidence: <integrity assessment>
      - "cryptographically_traceable": full chain of chain-anchored citations to primary sources
      - "partially_traceable": some links external without snapshot, some substrate-anchored
      - "attribution_only": claim exists but chain does not reach primary sources
    traced_at: <when provenance chain was walked>
    signature: <tracer's Genesis signature>
```

Provenance is derived from citations — walk citation chain from claim back through source references until reaching primary sources. Chain-anchored provenance receipt records the traversal for future reference.

## The stack composition

Four primitives compose into the verification stack:

**Primary source layer.** Substrate participants make first-person observations, publish original works, produce media, share direct experiences. These are chain-anchored by the original substrate participant with Genesis signature. Primary source is the ground truth in substrate; everything else references back to primary sources.

**Attribution layer.** Claims about non-substrate content (published article, historical quote, video recording) get chain-anchored attribution — who says what about whom. Attribution to substrate participants is unambiguous (their own Genesis signature). Attribution to non-substrate parties is chain-anchored per attributer with declared confidence.

**Citation layer.** Every claim references its sources via chain-anchored citations. Substrate-source citations reference the source receipt's content ID; external-source citations include external identifier plus snapshot hash. Citation chains form the graph structure of the information layer.

**Verification layer.** Claims that have been checked accumulate chain-anchored verification receipts from verifiers who used declared methods. Verification is not authoritative declaration; it's evidence for readers' own trust judgments.

**Provenance layer (derived).** Given a claim, provenance chain is derived by walking citations back through the graph until reaching primary sources or external references. Chain-anchored provenance receipts record the traversal for a specific tracing operation.

## Reproducibility ceremony composition

Some claims are reproducibility-verifiable: given the same source data and same analysis method, any verifier can produce the same conclusion. Scientific measurements, statistical analyses, computed results, deterministic transformations. These claims compose with REPRODUCIBILITY-CEREMONY-2026-07.md:

- Original claim publishes source data + analysis method + result
- Verifier independently runs analysis method against source data
- Verifier's chain-anchored `info:verification:` receipt records their outcome
- If verifier's outcome matches original claim's result, claim is reproducibility-verified

This is stronger than attestation-based verification because it doesn't require trust in the verifier's judgment — only trust in the verifier having actually run the analysis (which is itself chain-anchored via reproducibility ceremony evidence).

Reproducibility-verifiable claims are a minority of claims in general discourse but are extremely important where they apply (research findings, statistical claims, computed conclusions).

## Composition with MEDIA-PROVENANCE

Media artifacts (images, video, audio) have specific provenance discipline per MEDIA-PROVENANCE-2026-07.md, which composes C2PA (Content Provenance and Authenticity) standards with substrate chain-anchoring:

- C2PA-embedded provenance in media file
- Substrate-side chain-anchored attribution receipt referencing the media
- Peer verification receipts for the media's authenticity claims

This spec extends MEDIA-PROVENANCE to non-media content. Text claims, structured data, curated collections all get citation/attribution/verification/provenance discipline. MEDIA-PROVENANCE remains authoritative for media-specific mechanics; this spec provides the broader information layer they compose with.

## Composition with SOFTWARE-INTEGRITY-ATTESTATION

Claims about software integrity compose with SOFTWARE-INTEGRITY-ATTESTATION-2026-07.md five-layer stack:

- Substrate build reproducibility (per REPRODUCIBILITY-CEREMONY)
- Software identity attestation (Genesis-signed release records)
- Behavior attestation (chain-anchored test results, capability declarations)
- Composition attestation (chain-anchored dependency graphs)
- Deployment attestation (chain-anchored actual-running-version)

Verification claims about software ("I ran the substrate build reproducibly and got matching binary hash") compose SOFTWARE-INTEGRITY-ATTESTATION evidence with `info:verification:` receipts.

## Cross-substrate verification

Verification is stronger when multiple independent substrates verify the same claim:

- Original claim published by substrate A
- Substrate B independently verifies (per their own method); emits verification receipt
- Substrate C independently verifies; emits verification receipt
- Aggregated verification evidence across B, C, and others provides multi-verifier confirmation

Aggregation happens via commons per DISTRIBUTED-KNOWLEDGE-COMMONS. Commons hosts verification-receipt collections for specific claims; readers can query commons for "all verification receipts for claim X." Verifier reputation flows via commons — verifiers with track records of rigorous verification carry more weight in reader trust judgments.

Cross-substrate verification requires peer trust anchor grants (per PEER-TRUST-ANCHOR-2026-07.md) — readers weight verification evidence by their trust in the verifier's substrate.

## Aligned blindness for claims about non-substrate parties

KEEL III.24 aligned blindness has specific implications for information verification:

**Substrate does not verify claims about individuals who don't run substrate.** If claim is "X (non-substrate person) said Y," substrate cannot chain-anchor X's original statement (X doesn't have substrate to sign it). Substrate can chain-anchor:
- Attributer's claim about X (attribution receipt)
- Evidence supporting attribution (recording, screenshot, transcript)
- Multiple independent attributions if attributers exist

But substrate cannot make the attribution *true* if it isn't. Reader evaluates attribution evidence per their own trust judgment; substrate provides chain-anchored infrastructure for the evaluation, not the evaluation itself.

**Substrate does not build cross-source-tracking profiles of non-substrate parties.** Attributions to non-substrate person X accumulate in operator's chain per their own citations; substrate does not aggregate "everything anyone has attributed to X" into a substrate-side profile. Aggregation happens at query time per operator's authority, not as substrate-side discipline.

**Substrate does not verify or contest external published works substrate-side.** External sources are external; substrate provides citation infrastructure but does not attempt to verify external source content (that's external editorial process). Substrate can chain-anchor external content snapshots so reader can verify "cited content matches what claimed"; substrate does not verify "external content is true."

## Consequence for bad-actor false claims

Operators making chain-anchored false claims face substrate consequence per CONSEQUENCE-AND-FEDERATION-DISCIPLINE-2026-07.md:

- False attribution receipts contradict primary sources when primary source is substrate participant; primary source can emit contradicting-attribution receipt; commons reputation flows against false attributer.
- Manipulated citations (citing content that doesn't match what's cited) are detectable via chain-anchored snapshot comparison; commons reputation flows against manipulator.
- False verification receipts (claiming to have verified when verifier didn't actually check) are hard to detect internally but reproducibility ceremony catches structural cases; commons reputation flows against verifiers with pattern of unreliable verification.
- Sustained bad-actor information behavior triggers peer trust anchor revocations per PEER-TRUST-ANCHOR discipline.

Substrate is not truth-oracle; substrate is accountability infrastructure. Operators who consistently make false chain-anchored claims accumulate chain-visible evidence of their unreliability; peers withdraw trust; readers weight their future claims accordingly.

## Composition with existing specs

- **REPRODUCIBILITY-CEREMONY-2026-07.md**: reproducibility-verifiable claims compose with reproducibility ceremony for strongest verification tier.
- **MEDIA-PROVENANCE-2026-07.md**: media-specific provenance (C2PA composition) is one specific instance of provenance discipline in this stack.
- **SOFTWARE-INTEGRITY-ATTESTATION-2026-07.md**: five-layer software attestation composes with software-claim verification.
- **PEER-TRUST-ANCHOR-2026-07.md**: peer trust anchor discipline informs verification weighting — reader weights verifier evidence by their trust in verifier.
- **DISTRIBUTED-KNOWLEDGE-COMMONS-2026-07.md**: commons hosts verification-receipt aggregation and verifier reputation flow.
- **SUBSTRATE-BLINDNESS-HEURISTICS-2026-07.md**: aligned blindness applies to claims about non-substrate parties; substrate does not verify claims it cannot verify.
- **CONSEQUENCE-AND-FEDERATION-DISCIPLINE-2026-07.md**: false chain-anchored claims face substrate consequence per federation discipline.
- **CHAIN-WATCHER-AND-COMMITMENTS-2026-07.md**: chain-watchers can subscribe to verification events for specific claims; commitments can reference verification-receipt-existence as trigger conditions.
- **DISCOVERY-AND-BOOTSTRAP-2026-07.md**: verifier discovery — how readers find verifiers whose work they should weight — composes with commons reputation flow.

## Attack model

- **Attacker publishes false claim with fabricated citations**: fabricated citations reference non-existent chain content or misrepresent external content; snapshot hash comparison catches misrepresentation; substrate participants can emit contradicting evidence.
- **Attacker impersonates substrate participant to make false attribution**: substrate identity is Genesis-signed; impersonation requires Genesis compromise.
- **Attacker uses substrate to create false verification of false claim**: false verifier's reputation degrades via commons as their verifications don't stand up to cross-verification; sustained false-verification triggers consequence per federation discipline.
- **Attacker floods commons with fake verification receipts to overwhelm signal**: rate limits on verification receipts per verifier; commons reputation weighting reduces impact of new-verifier signal.
- **Attacker uses citation manipulation to construct false provenance chain**: chain-anchored snapshots at each citation link enable readers to independently walk chain and verify links match; manipulation is detectable.
- **Attacker exploits aligned blindness to make unverifiable claims about non-substrate parties**: substrate cannot verify; readers evaluate per their own judgment. Substrate provides no false confidence but also provides no protection against maliciously-attributed unverifiable claims.
- **Attacker targets primary source with contradicting attributions to manufacture doubt**: primary source's own Genesis signature is authoritative; contradicting attributions are chain-visible; commons reputation flows.

## Failure modes

- **Verification evidence exists but reader unable to evaluate rigor**: substrate provides evidence structure; reader trust judgment is inherently human process.
- **Provenance chain reaches external references without chain-anchored snapshots**: some external content wasn't snapshotted at citation time; provenance chain has weaker integrity at that link.
- **Multiple contradictory verifications for same claim**: substrate does not resolve contradictions; reader evaluates verifier reputation and evidence quality.
- **Verifier operates without adequate expertise**: substrate does not verify verifier expertise; commons reputation over time reveals verifiers whose work stands up.
- **Attribution to non-substrate party remains unresolvable**: substrate provides evidence infrastructure; some claims about non-substrate parties remain uncertain regardless of substrate discipline.

## Non-goals

- **Not truth oracle.** Substrate does not declare truth or falsity of claims. Substrate provides chain-anchored evidence infrastructure for readers' own trust judgments.
- **Not authoritative fact-checker registry.** Substrate does not identify who is authorized to verify what. Anyone can be a verifier; readers evaluate verifiers per their own judgment.
- **Not censorship mechanism.** Substrate does not suppress claims. Substrate accumulates evidence about claims; readers evaluate.
- **Not replacement for editorial process.** Traditional journalism, academic peer review, professional editorial oversight remain valuable; substrate provides chain-anchored infrastructure they compose with.
- **Not substitute for domain expertise.** Substrate does not certify who is qualified to make claims about specific domains.
- **Not universal citation standard.** Substrate provides citation primitives that compose with existing citation standards (academic, journalistic, legal); substrate does not attempt to replace them.
- **Not moderation.** Substrate does not remove content, hide claims, or downrank information. All chain-anchored content remains chain-visible; reader trust judgments determine what they weight.

## Open positions

- **Verifier reputation weighting algorithm**. How commons reputation for verifiers translates into reader-facing weighted evidence. Federation working spec.
- **External source snapshot format standardization**. How chain-anchored snapshots of external content should be structured for interoperability across substrates.
- **Citation graph query UX**. How readers explore citation chains — dashboard tooling, CLI queries.
- **Reproducibility-verifiable claim identification**. How substrate helps readers identify which claims are reproducibility-verifiable vs which require other verification.
- **Cross-substrate verification aggregation protocol**. Federation working spec for verification-receipt collection and query.
- **Verification method rigor calibration**. How different verification methods (direct observation, cross-reference, expert consultation, reproducibility ceremony) get weighted; not universal standard but per-community-declared.
- **Legal-jurisdiction citation composition**. Legal proceedings have specific citation requirements; substrate citation primitives compose with legal citation standards how.
- **Academic citation composition**. Academic works have specific citation formats; substrate citations compose with DOI systems, ORCID identifiers, etc.

## What composes from here

Immediate design work:

1. **Chain-anchored receipt schemas** for citation, attribution, verification, provenance
2. **External source snapshot format**
3. **Citation graph query API**
4. **Verifier reputation aggregation protocol**
5. **Cross-substrate verification federation working spec**

Near-term implementation:

1. **Information verification runtime** in `crates/zp-server/src/info_verification/`
2. **Citation graph indexer** for local chain content
3. **External source snapshot pipeline**
4. **Dashboard information verification panel**: recent citations made, verifications performed, verifier reputation, citation-graph exploration
5. **CLI verbs**: `zp info cite <source>`, `zp info attribute`, `zp info verify <claim>`, `zp info trace-provenance <claim>`

## Framing note

Information verification captures how substrate provides chain-anchored citation, attribution, verification, and provenance primitives that compose into a verification stack for civilization-scale information coordination. Same principle as chain-anchored discipline elsewhere: primitives declared, operator authorship, chain-anchored evidence, no substrate-side truth-oracle.

The load-bearing insight: **substrate provides verification primitives, not verification authority. Chain-anchored evidence of who cited what, who attributed to whom, who verified against what — readers evaluate per their own trust judgment.** Verification is not oracle declaration; it's evidence for evaluation. Provenance is traceable; attribution is chain-anchored; citation is verifiable. But truth is what readers determine per their own reasoning over the chain-anchored evidence — substrate does not attempt to determine truth on their behalf.

Combined with the substrate's structural discipline across every trust boundary, information verification closes the "coordination on information without becoming truth oracle" gap. What was previously implicit — that substrate would somehow help operators coordinate on what's true — becomes structural: four chain-anchored verification primitives, cross-substrate verification composition, reproducibility ceremony integration for reproducibility-verifiable claims, aligned blindness for claims about non-substrate parties, consequence discipline for bad-actor false claims. Substrate is complementary infrastructure to civil society's editorial, academic, journalistic, and legal information processes. Substrate makes claims chain-anchored and verifiable; humans evaluate; readers judge; truth emerges from the collective sensemaking substrate infrastructure supports without substrate arrogating decision-making authority.
