# External Anchor Tier Contract — What External-Anchoring Must, May, and Must Not Do

*Dated 2026-06. The runtime-neutral contract between the External anchor
tier and the external ground truth it publishes to. Names which affordances
an external-anchoring implementation MUST have, which it MAY have, and
which it MUST NOT have, so that affordance gaps are classifiable without
re-deriving from structural first principles each time.*

*Updates to this doc are architectural acts and should be treated as such.*

---

## 1. What this doc is

This is the External anchor tier contract — the operational complement to
`docs/ARCHITECTURE-2026-04.md` §9a (Commitment E: external truth anchoring).
Where §9a names the commitment — the chain publishes proofs to external
ground truth when something is at stake; the external ground records whatever
it records; the chain incorporates the resulting confirmation — this document
partitions that commitment into Required, Optional, and Forbidden affordances
so that any proposed anchoring feature can be classified in one lookup rather
than re-derived from principles.

The architectural spine of this contract is the non-dependency commitment:
external anchoring is an enrichment, not a dependency. The chain is self-
verifying via internal integrity primitives; external anchoring extends the
guarantee across organizational boundaries by publishing a timestamped witness
that no single party controls. The substrate operates correctly whether or
not any anchor backend is reachable. Conformance at this tier is calibrated
against that commitment — anything that converts anchoring from enrichment
into a runtime dependency is architecturally wrong regardless of the
operational convenience it provides.

The contract is runtime-neutral and backend-neutral by construction. Hedera
Hashgraph HCS is the reference backend; Bitcoin OpenTimestamps, Ethereum L2,
Sigstore/Rekor, RFC 3161 timestamping authorities, and any other external
ground truth service that satisfies the `TruthAnchor` trait semantics are
equally conformant. The contract names the semantics; the backend is operator
choice.

This document is the spoke for Tier 10 in
`docs/SUBSTRATE-CONFORMANCE-CONTRACT-2026-06.md`. The External anchor tier
composes with adjacent tiers at multiple boundaries: the Operator substrate's
Receipt sub-layer (anchor publications and receipts are chain entries), the
Storage tier (anchor receipts persist with the same atomic-append semantics
as other chain entries), the Cross-substrate peer tier (cross-mesh
introduction uses anchor identifiers for trust-bootstrap between strangers),
and the Verifier tier (anchor receipts are cross-checkable during chain walks
per Verifier Optional #8).

---

## 2. The category statement

The External anchor tier covers the substrate's outbound publication of chain
proofs to external ground truth — public ledgers, notaries, timestamping
authorities, transparency logs — and the incorporation of the resulting
confirmations as chain entries. When one of the six `AnchorTrigger` variants
fires, the substrate produces an `AnchorCommitment`: a compact cryptographic
fingerprint of the chain's current state (head hash, sequence number,
operator signature). That commitment is published to the configured backend
via the `TruthAnchor` trait's `anchor()` method. The backend records whatever
it records. The substrate verifies the resulting `AnchorReceipt` and
incorporates it as a chain entry, attesting "we published this commitment to
this backend at this time; here is the ledger's confirmation."

The chain is honest about what was published. It does not require the ledger
to validate the chain's content, to endorse the operator's decisions, or to
arbitrate disputes. The anchor is a witness: an external party, at a
deterministic moment, observed that this operator's chain was in this
cryptographic state. What the chain attests to in reality remains a question
the chain's own signed receipts answer; the anchor adds only "and this state
was witnessed externally at this time." An anchored chain is not thereby more
correct than an unanchored chain; a chain whose anchor backend is unreachable
is not thereby less internally valid than one whose backend is responsive.
The enrichment is real and operationally meaningful; the non-dependency is
structural and unconditional.

---

## 3. Required affordances

An implementation lacking any of these cannot serve as a conformant external-
anchoring implementation. The fallback when the External anchor tier is
entirely absent — no `TruthAnchor` wired at all — is for the substrate to
operate without external witnessing, which is architecturally correct but
means the operator has not declared their anchoring posture. The declaration
itself is the Required affordance; `NoOpAnchor` is the conformant declaration
for "no active backend."

**1. `TruthAnchor` trait implementation wired into the anchor-emission path.**
The substrate must have at least one `TruthAnchor` implementation active,
even when no external backend is configured. `NoOpAnchor` satisfies this
affordance: a substrate that explicitly configures no anchor backend has
declared its posture — anchoring trait wired, no active publication. A
substrate with no `TruthAnchor` implementation at all has not decided about
anchoring; that is not a conformant posture, because the decision itself is
the structural commitment. The `TruthAnchor` trait's three methods —
`anchor()` (publish commitment), `verify()` (verify receipt), and
`query_range()` (query anchor history by time range) — are the programmatic
surface the operator and adjacent tiers interact with. `NoOpAnchor`
implements all three as no-ops with appropriate error variants; it is the
explicit structural declaration that anchoring is part of the substrate's
design, even when no backend is active. **P3, P8.**

**2. Event-driven publication only via the six `AnchorTrigger` variants.**
Anchor publication must be triggered by one of the six canonical `AnchorTrigger`
variants: `OperatorRequested` (operator-initiated explicit publication via
CLI or Sage tool), `CrossMeshIntroduction` (trust-bootstrap when two substrates
first meet), `ComplianceCheckpoint` (periodic attestation for regulated
deployments), `DisputeEvidence` (anchoring a chain state relevant to an
active dispute), `Opportunistic` (embedding the chain head in a blockchain
transaction already in flight for other reasons), or `GovernanceEvent`
(anchoring at a significant governance inflection point). No timer-driven
schedule. No receipt-count threshold. Anchoring is an expression of
substrate intent when something is at stake — dispute, compliance, introduction,
explicit request — not a background process that fires on a schedule. The
`AnchorTrigger` variant is included in the `AnchorCommitment` the substrate
publishes, making the reason for every anchor publication queryable from
the chain. **P8.**

**3. Compact commitment only — not chain content.** What gets published to
the external ground is the `AnchorCommitment`: the chain head hash, the
sequence number, the `prev_anchor_hash` linking this commitment to the prior
anchor publication, the operator's signature, and the trigger variant.
Nothing more. Receipt bodies, actor identifiers, policy decisions, delegations,
and any other governed content must not cross the anchor publication boundary.
The ledger sees a cryptographic fingerprint and a signature; it does not see
what the fingerprint summarizes. The compact commitment is what enables
external verification without external disclosure — a third party who holds
the chain can confirm the commitment matches; a third party who holds only
the ledger record learns nothing about what the chain contains. **P4.**

**4. Sign anchor publications with the substrate's Genesis-derived identity
key.** The `AnchorCommitment`'s `operator_signature` field must be signed
with the same Genesis-derived signing key that signs canonical chain receipts.
There is no separate anchor-signing key with its own lifecycle or credential
store entry. The external ledger sees the operator's own identity signature
— the same cryptographic identity that anchors the entire chain — not a
delegated or separate key whose relationship to the chain's authority must
be separately established. **P1, P2.**

**5. Verify `AnchorReceipt` before incorporation.** Before the substrate
accepts an `AnchorReceipt` from the backend as a chain entry, it must verify
the receipt against the backend's expected proof shape via `TruthAnchor::verify()`.
The `AnchorReceipt` carries the backend's `external_id`, consensus timestamp,
the original commitment (enabling commit-receipt binding verification), and
opaque `ledger_proof` data the `verify()` implementation uses. A receipt that
fails verification must be reported as an `AnchorError::VerificationFailed`
and must not enter the chain. Accepting a malformed or unverifiable anchor
receipt would produce a chain entry that appears to attest external witnessing
while actually attesting only that the substrate received something from the
backend, which is a different and weaker claim. **P1.**

**6. Incorporate verified `AnchorReceipt` as a chain entry.** A verified
anchor confirmation lands on the local chain as a receipt, making anchor
history queryable from the chain itself without requiring access to the
external backend. The receipt records the backend identity, the published
commitment, the backend's confirmation, and the time of that confirmation
from the ledger's own clock (not the local clock). Anchor history that exists
only in the external backend is not chain-anchored; any consumer of the chain
who wants to verify the anchor history must query the external backend
independently. Incorporating the receipt as a chain entry means the chain is
the single queryable record of both the substrate's own governance events and
its external witnessing history. **P1, P5.**

**7. Honest failure when the backend is unreachable.** When the anchor backend
is unreachable, the substrate must report the failure — not silently skip
anchoring, not fabricate a confirmation, and not block chain operations
waiting for the backend. Transient failures may be retried within operator-
configured policy bounds. Permanent failures, or failures on high-stakes
trigger variants (`DisputeEvidence`, `ComplianceCheckpoint`), must themselves
be chain entries: a receipt attesting that anchoring was attempted at this
chain state, for this trigger, and the backend returned this failure. The
failure record is part of the operator's honest account of what was attempted.
**P1, P5.**

**8. Anchor backend is operator choice, not architectural prescription.**
The substrate must route anchor publications through the `TruthAnchor` trait
rather than calling any specific backend directly at the call site. A substrate
that hard-codes a call to Hedera's HCS API, or to any other specific backend,
rather than dispatching through the trait is not conformant — not because the
specific backend is wrong, but because hard-coding removes the operator's
choice. The trait abstraction is the structural commitment that any conformant
backend is interchangeable and that no backend is required. **P3.**

---

## 4. Optional affordances

Each optional affordance improves the anchoring deployment's operational
coverage or operator experience without affecting the chain's internal
integrity or the anchoring tier's structural commitments.

**Specific anchor backend.** Hedera Hashgraph HCS is the reference backend:
sub-second deterministic finality, low transaction cost, public mirror nodes
for independent verification, council governance model. Bitcoin OpenTimestamps,
Ethereum L2, Sigstore/Rekor, RFC 3161 timestamping authorities, Ceramic
streams, Certificate Transparency logs, Internet Archive snapshots, and any
other service implementing the `TruthAnchor` trait are all conformant
backends. Backend choice is an operator decision calibrated to their latency
tolerance, cost constraints, threat model, and verification ecosystem.

**Multiple parallel anchor backends.** A substrate may configure multiple
`TruthAnchor` implementations and publish to all of them on each trigger
event, producing independent external witnesses. Multiple anchors reduce
single-backend dependency risk — if one backend is unavailable or compromised,
the others provide independent corroboration — and broaden the set of parties
who can independently verify the chain's anchoring history. The chain operates
correctly with zero, one, or many parallel backends.

**Cross-mesh introduction protocol.** When two substrates first meet, each
announces its anchor backend identifier (for example, a Hedera HCS topic ID);
each independently queries the other's anchor history to establish trust
between strangers via shared external proof rather than mutual assertion. A
new peer that has published consistent anchor history across many interactions
provides a verifiable trajectory of external attestations that a newly
fabricated chain cannot reproduce. Composes with the Cross-substrate peer tier
(`docs/CROSS-SUBSTRATE-PEER-CONTRACT-2026-06.md`) as the trust-bootstrap
mechanism for first peer contact, parallel to trust-on-first-use key pinning
for the cryptographic identity path.

**Opportunistic anchoring.** When a deployment already has blockchain
transactions in flight as part of its application's business logic, the
substrate may embed the chain head hash as metadata in those transactions
at effectively zero marginal cost. This is the `Opportunistic` trigger
variant — anchoring when the path is already open rather than opening the
path specifically to anchor. The enrichment is free; it is never required.

**Range queries against anchor history.** The `TruthAnchor` trait's
`query_range()` method is implementable by some backends (Hedera mirror nodes,
Bitcoin block explorers, Certificate Transparency log monitors) and not by
others. Backends that support range queries enable richer verification
protocols — a verifier can confirm that the chain was anchored consistently
across a time range without examining every individual anchor receipt. Backends
without this capability are still conformant for one-shot anchor verification.
Composes with the Verifier tier's Optional #8 (anchor cross-checking during
chain walks).

**Backend health monitoring.** Periodic liveness probes against configured
anchor backends, with cached results that surface to the operator before
trigger events fire, improve failure-mode operator experience. Without this
affordance, the operator discovers backend unavailability only when a trigger
fires and `TruthAnchor::anchor()` returns an error; with it, the operator
can reconfigure before a high-stakes trigger arrives.

**Pre-anchor batching.** Grouping multiple trigger events into a single
publication when the trigger semantics permit — for example, several
`Opportunistic` triggers within a single transaction window collapsed into one
commitment — is an optional performance optimization. The batched commitment
carries the most recent chain head hash; intermediate trigger events that
arrive before the batch closes wait for the batch to publish rather than
triggering individual publications.

**Compaction of anchored chain prefixes.** A verified anchor receipt that
attests "chain prefix up to entry N hashes to X" can serve as a shortcut for
verifiers who trust the anchor — they may accept the anchored prefix without
re-walking every entry from Genesis. This is Optional and composes with the
Verifier tier's Optional #3 (verifier-side caching of verified prefixes): the
anchor receipt is the authenticated checkpoint the verifier caches against.

**Operator-readable anchor surface.** A `zp anchor` CLI subcommand (or
equivalent Sage tool) that lets the operator trigger publication via
`OperatorRequested`, view anchor history from the chain, query the configured
backend directly, and reconfigure the active `TruthAnchor` implementation is
an optional operator-experience surface. Composes with the cockpit and Console
tiers.

---

## 5. Forbidden affordances

The Forbidden category at the External anchor tier is calibrated against one
architectural commitment: anchoring is an enrichment, not a dependency. Any
use that converts the anchor backend from an enrichment into something the
chain's operation depends on breaks that commitment. Any use that lets
anchoring claim authority it doesn't have — over chain content, over the
chain's correctness, over the operator's identity — breaks the chain's own
authority model. The substrate uses network calls, signing, external service
interactions, and ledger primitives extensively at other tiers; the Forbidden
entries below name what the External anchor tier itself must not do.

**1. Timer-driven anchor publication.** Publishing an anchor commitment on a
recurring schedule — "anchor every hour," "anchor at midnight," "anchor every
five minutes when the backend is reachable" — is forbidden. External witnessing
is valuable when something is at stake; timer-driven anchoring creates
publication overhead without trigger semantics, pollutes anchor history with
events whose trigger cannot be reconstructed, and makes anchor history harder
to interpret by any consumer who must understand why each anchor was published.
The six `AnchorTrigger` variants are the canonical trigger set; timer-driven
publication does not correspond to any of them. **P8.**

**2. Receipt-count-driven anchor publication.** "Anchor every N receipts"
is forbidden for the same structural reason as timer-driven anchoring. A
receipt-count trigger is a proxy for time (if the substrate receives receipts
at a steady rate) or a proxy for activity (if not), neither of which corresponds
to "something is at stake." The result is the same: anchor history that is
not interpretable from the trigger variant, and a publication cadence that
does not reflect the operator's governance intent. **P8.**

**3. Treating anchor confirmation as authority over chain content.** An
`AnchorReceipt` attests that the chain was in a specific cryptographic state
at a specific externally-witnessed time. It does not attest that the chain
content is correct, that the operator's policy decisions were sound, that the
receipts the commitment summarizes are authorized, or that any external party
has endorsed the chain's narrative. A substrate that elevates anchor
confirmation — "this was anchored, therefore it is authoritative" — has
introduced a second source of authority alongside the operator's own signed
chain receipts. The chain's authority comes from the operator's Genesis-derived
signing key; the anchor adds external witnessing of that authority, not a
parallel or superior one. **P1.**

**4. Blocking chain operations on anchor backend availability.** The chain's
internal operations — receipt emission, gate evaluation, delegation, policy
enforcement — must not wait for the anchor backend to respond before
proceeding. Code paths that make chain operations contingent on successful
anchor publication, that hold transactions open pending anchor confirmation,
or that refuse to append receipts when the backend is unavailable are
forbidden. The non-dependency commitment is structural: anchoring enriches;
it does not gate. **P3, P5.**

**5. Publishing chain content to the external ground.** What crosses the
`TruthAnchor::anchor()` boundary is the `AnchorCommitment`: head hash,
sequence number, operator signature, trigger variant. Receipt bodies, actor
identifiers, claim types, policy decisions, delegation grants, and any other
governed chain content must not be published to the external ledger. The
compact commitment design is what enables an operator to anchor a chain that
contains sensitive governance decisions without disclosing those decisions
to the external ground or to any party that accesses the ledger's public
record. Publishing content instead of proof would break the confidentiality
model the compact commitment was designed to protect. **P4.**

**6. Silent failure on anchor publication failure.** A failed anchor
publication — backend unreachable, commitment rejected, receipt verification
failure — that goes unreported is forbidden. The substrate surfaces publication
failures to the operator; for high-stakes trigger variants (`DisputeEvidence`,
`ComplianceCheckpoint`), the failure must itself become a chain entry recording
that anchoring was attempted, with this trigger, at this chain state, and
returned this result. An anchor failure that produces no chain entry creates
a gap in the operator's honest account of their anchoring history — a gap
that is exactly the kind of omission that adversarial chain analysis would
look for. **P1, M3.**

**7. Anchoring before the committed chain state exists on the local chain.**
The `AnchorCommitment`'s `chain_head_hash` must correspond to an entry that
has already been atomically appended to the local chain via the Storage tier's
canonical insertion path. Publishing a commitment to a chain head that is
speculative, provisional, or not yet durably appended is forbidden — the
commitment would attest to a state the chain does not actually hold at the
time of publication. Any external party who later walks the chain from Genesis
would find the commitment points to a state they cannot re-derive, which is
the external-anchoring equivalent of a hash-link break. **P1.**

**8. Requiring a specific anchor backend as a structural dependency.**
A substrate that will not start, that will not append receipts, or that
degrades to an error state when a specific anchor backend is unavailable has
made that backend a structural dependency rather than an enrichment. Requiring
configuration of a specific backend — by making the trait accept only Hedera,
by refusing to accept `NoOpAnchor`, or by any other mechanism that removes
the operator's backend choice — creates a center that no single party should
control. **P3.**

**9. Treating an anchor confirmation as a substitute for chain integrity.**
A chain that has been anchored to an external ledger is not thereby
well-formed. An anchored chain whose `entry_hash` chain is broken, whose
signatures fail, or whose timestamps are non-monotone remains corrupt. The
anchor attests to the chain's state at a moment; it does not repair or
validate the chain's internal structure. A substrate that treats anchor
receipt presence as sufficient evidence of chain integrity — shortcutting the
Verifier tier's re-derivation walk on the grounds that "the chain was
anchored" — has made the anchor a substitute for verification, which it
structurally is not. **P1, M3.**

**10. Signing anchor publications with anything other than the substrate's
Genesis-derived identity key.** A separate anchor-side signing key — with its
own credential store entry, its own sovereignty provider path, its own key
lifecycle — would create a side identity whose relationship to the chain's
authority must be separately established by every external party who verifies
the anchor publication. The substrate's Genesis-derived identity key is the
one cryptographic identity that all chain consumers already know how to verify;
using it for anchor publications means the external ledger record is
immediately attributable to the same operator who signed the chain's receipts.
A substrate that generates or uses a separate anchor key has introduced a
second sovereign root in all but name. This is the `singular_sovereign_root`
principle applied to the anchor-publication boundary: the anchor publication's
signing key derives from Genesis on the same canonical loading path as the
chain receipt signing key, with no second credential-store entry by another
name. See `docs/SINGULAR-SOVEREIGN-ROOT-2026-05.md` and the Operator substrate
contract's Identity binding sub-layer for the structural enforcement that
covers this boundary. **P2, P1.**

---

## 6. Composition with principles

The External anchor tier composes with five principles that together define
what "enrichment not dependency" means structurally. The tier is also the
outbound publication mode of the Witness-not-arbitrate integration pattern
from `docs/SUBSTRATE-CONFORMANCE-CONTRACT-2026-06.md` §6; that pattern's
composition is named explicitly after the principle composition below.

**P1 (signing is gravity) is the load-bearing principle for the anchor
publication and receipt paths.** Required affordances #4 (sign with the
substrate identity key) and #5 (verify before incorporation) both derive
from P1: the anchor commitment is signed because an unsigned publication has
no attributable witness; the receipt is verified before incorporation because
an unverified receipt is an untested claim. Forbidden entries #3, #6, #7, #9,
and #10 all protect P1 at this tier — preventing anchoring from being used
to claim authority it doesn't have, from covering failures in silence, from
attesting to states the chain doesn't hold, or from introducing a side
authority via a separate anchor key.

**P2 (identity is a key, not a location) is the structural basis for Required
#4 and Forbidden #10.** The operator's Genesis-derived key is the identity;
the anchor backend's address is a deployment coordinate. Publishing with the
substrate's own identity key means the anchor publication is attributable to
the same cryptographic identity as the chain's receipts — by any verifier,
at any time, without requiring the backend's location to be stable. A separate
anchor key would create a second identity whose attribution to the operator
requires the backend record to confirm it.

**P3 (there is no center) is the primary principle for Required #8 and
Forbidden #4 and #8.** The `TruthAnchor` trait architecture exists to ensure
no single external party is required. The backend is operator choice;
`NoOpAnchor` is a conformant posture; multiple backends can be deployed in
parallel. A substrate that requires a specific backend for correctness, or
that blocks chain operations on backend availability, has introduced a center
— an external party whose responsiveness gates substrate operation. P3 is
why the non-dependency commitment is structural rather than operational.

**P5 (store-and-forward primary) is the structural basis for Required #7
(honest failure) and Forbidden #4 (no blocking on backend availability).**
The chain survives anchor backend outages because the chain's integrity
primitives are internal. P5 is also why Required #6 (incorporate anchor
receipt as a chain entry) matters: the chain is the primary record; an anchor
history that exists only in the external ledger is a primary record that is
external, which inverts the architecture. The chain records what was anchored;
the ledger is the external corroboration.

**P8 (one canonical path) is the structural basis for Required #2
(event-driven publication via the six `AnchorTrigger` variants) and Forbidden
#1 and #2 (no timer or count triggers).** The six trigger variants are the
canonical trigger set — the enumeration of reasons the substrate has determined
are worth anchoring. A timer or count trigger is a second path for "when to
anchor" alongside the canonical set; P8 prohibits it for the same reason it
prohibits multiple chain insertion paths or multiple gate-evaluation paths.

**Witness-not-arbitrate: the External anchor tier as outbound publication
mode.** The Witness-not-arbitrate integration pattern from SCC §6 describes
how the substrate interacts with external services that record but do not
govern: the substrate signs and publishes its own view; the external service
does whatever it does; the substrate incorporates whatever attestation the
external service returns, treating the attestation as evidence of external
observation rather than as an endorsement of chain content. The External
anchor tier is this pattern's outbound publication mode: the substrate
publishes an `AnchorCommitment` (its signed view of the chain at a trigger
moment); the anchor backend records the commitment in its own ledger (whatever
its consensus mechanism does); the substrate verifies the returned
`AnchorReceipt` and incorporates it as a chain entry attesting "we published
this commitment to this backend at this time; the ledger returned this
confirmation." The substrate is honest about what was published; it does not
require the ledger to arbitrate disputes, to validate content, or to endorse
the chain's narrative. The chain's authority remains with the operator's own
signed receipts; the anchor's authority is limited to "an external party
witnessed this state at this time." Forbidden entries #3, #7, and #9 are
the direct expressions of Witness-not-arbitrate's prohibition on the anchor
claiming arbitrative authority it was never given.

---

## 7. Portability sketches

The `TruthAnchor` trait is backend-agnostic. These seven sketches demonstrate
that conformance is achievable across substantively different external ground
truth services.

**Hedera Hashgraph HCS (reference backend).** The `TruthAnchor::anchor()`
implementation submits a `ConsensusSubmitMessage` to a configured HCS topic;
the Hedera network provides sub-second deterministic finality and a consensus
timestamp from the distributed council's clock. `TruthAnchor::verify()`
checks the receipt against the topic's running hash via a mirror node query.
`TruthAnchor::query_range()` is available via Hedera mirror node REST APIs.
Best-fit trigger variants: `CrossMeshIntroduction` (trust bootstrap via shared
HCS topic), `ComplianceCheckpoint` (auditability with sub-second confirmation),
`DisputeEvidence` (deterministic timestamp for chain state at a specific moment),
`OperatorRequested`.

**Bitcoin OpenTimestamps.** `TruthAnchor::anchor()` submits the commitment
hash to a public OTS calendar server, which aggregates it into a Bitcoin
transaction within a block. Confirmation latency is block-time (minutes to
hours). `TruthAnchor::verify()` confirms the OTS proof against the Bitcoin
blockchain. `query_range()` is not naturally available; implementations must
maintain a local index. Best-fit trigger variants: `ComplianceCheckpoint` and
`DisputeEvidence` where latency tolerance is high and Bitcoin's network
effects as an external witness are valued over response speed.

**Ethereum L2 (Optimism, Arbitrum, Base).** `TruthAnchor::anchor()` submits
a calldata transaction with the commitment hash. L2 finality is faster and
cheaper than L1; the underlying L1 batch settlement provides long-term
corroboration. `TruthAnchor::verify()` confirms via L2 RPC. Best-fit trigger
variants: `Opportunistic` (when L2 transactions are already in flight),
`GovernanceEvent` (when the operator's application already uses L2 for other
governance primitives).

**Sigstore / Rekor transparency log.** `TruthAnchor::anchor()` uploads the
commitment as a Rekor log entry; Rekor's append-only Merkle tree provides
inclusion proofs. `TruthAnchor::verify()` checks the inclusion proof from
the log's public API. `query_range()` is available via log range queries.
Aligned with the substrate's own parser-not-checker verification model; well-
suited for software supply chain contexts where Sigstore is already in the
verification ecosystem.

**RFC 3161 timestamping authority.** `TruthAnchor::anchor()` sends the
commitment hash to a configured TSA (FreeTSA, DigiCert, or any other RFC 3161
server); the TSA returns a signed timestamp token. `TruthAnchor::verify()`
validates the token against the TSA's certificate chain. Centralized by
design, but well-understood and widely verifiable. Best-fit for regulated
deployments where an accredited TSA is a compliance requirement.

**Internet Archive Wayback Machine snapshots.** `TruthAnchor::anchor()` POSTs
a canonical URL encoding the commitment (e.g., a JSON document served from
the operator's own domain) to the Archive's `save` endpoint. The snapshot URL
becomes the `external_id` in the `AnchorReceipt`. Human-readable; free; not
cryptographically verifiable in the same sense as ledger-based backends. Best
suited as a supplementary witness alongside cryptographic backends, or for
contexts where human-readable corroboration has independent value.

**NoOpAnchor (no active backend).** The `NoOpAnchor` implementation's
`anchor()` method returns `AnchorError::NotAvailable`; `verify()` and
`query_range()` return appropriate no-op responses. A substrate using only
`NoOpAnchor` is conformant — Required #1 is satisfied (the trait is wired),
Required #7 is satisfied (failure is surfaced, not silently swallowed), and
Required #8 is satisfied (the operator has made an explicit backend choice:
none). No chain entries are produced for anchor publications when `NoOpAnchor`
is active. The posture is explicit, honest, and architecturally sound.

---

## 8. Autoregressive update triggers

1. **A new `AnchorTrigger` variant is added.** The six canonical trigger
   variants are Required #2's enumeration. Adding a seventh variant expands
   the canonical set and requires this contract to be updated — both to name
   the new variant in Required #2 and to confirm that the new trigger's
   semantics are consistent with the event-driven (not timer or count)
   commitment.

2. **A new anchor backend is adopted.** If the substrate ships a new
   `TruthAnchor` implementation — a new DLT, a new transparency log, a custom
   notary service — this doc should be updated with a new portability sketch
   naming the backend's specific primitives, best-fit trigger variants, and
   operational trade-offs.

3. **A Required affordance proves hard to implement portably.** If "sign with
   the substrate identity key" proves infeasible for a backend that requires
   a different signature format, or if `TruthAnchor::verify()` cannot be
   implemented for a backend without a verifiable proof mechanism, the question
   is whether to relax the affordance, accept that the backend is out of scope,
   or define a conformance note for the specific constraint. Either answer
   belongs in this document.

4. **A Forbidden affordance is proposed for relaxation.** If someone proposes
   "allow timer-driven anchoring for compliance deployments that require
   regular audit exports," this document is what the proposal must justify
   against. The `ComplianceCheckpoint` trigger variant exists precisely to
   address this use case; if the trigger variant is being invoked on a timer,
   that is Required #2 used as intended, not a Forbidden #1 exception.

5. **Cross-mesh introduction protocol evolves.** If the trust-bootstrap
   protocol between first-meeting substrates (Optional #3) develops new
   anchor-based verification semantics, Required #2 (`CrossMeshIntroduction`
   trigger) and the portability sketches' composability notes should be
   updated.

6. **A new principle is added to Architecture Part V½.** Each new principle
   may make existing Optional affordances Required, add new Forbidden entries,
   or clarify the composition of existing ones with the new principle.

---

## 9. Refs

- `docs/handoffs/external-anchor-tier-affordance-pass-2026-06.md` — the
  architectural-decisions source; the Required / Optional / Forbidden partition
  and the Commitment E mapping this contract synthesizes
- `docs/ARCHITECTURE-2026-04.md` §9a — Commitment E (external truth anchoring
  as enrichment); the substantive source for this contract's structural spine
- `docs/SUBSTRATE-CONFORMANCE-CONTRACT-2026-06.md` — the hub contract;
  §4 Tier 10 entry ("External anchor tier"); §5 contract template; §6
  Witness-not-arbitrate integration pattern (this tier's outbound mode)
- `docs/STORAGE-TIER-CONTRACT-2026-06.md` — the adjacent tier where anchor
  receipts persist as chain entries with the same atomic-append semantics
- `docs/VERIFIER-TIER-CONTRACT-2026-06.md` — the adjacent tier that may cross-
  check anchor receipts during chain walks (Verifier Optional #8)
- `docs/CROSS-SUBSTRATE-PEER-CONTRACT-2026-06.md` — the adjacent peer tier;
  cross-mesh introduction (Optional #3) composes here as a trust-bootstrap
  mechanism
- `docs/EDGE-TIER-CONTRACT-2026-06.md` — the contract template exemplar
- `crates/zp-anchor/src/lib.rs` — the `TruthAnchor` trait, `AnchorCommitment`,
  `AnchorReceipt`, six `AnchorTrigger` variants, `NoOpAnchor` fallback, and
  the `AnchorError` variants that Required #7 references
- `crates/zp-audit/src/store.rs` — where anchor receipts land as chain entries
  via the Storage tier's canonical atomic-append path
