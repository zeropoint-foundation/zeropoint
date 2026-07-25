# The Supersession Framework — July 2026

**Document type:** Design note. Specifies the ZeroPoint Enhancement Proposal (ZEP) mechanism through which any operator can propose a replacement for any mechanism in the substrate, and the process by which such proposals supersede current implementations if operators adopt them. Extracts and expands the summary given in `docs/design/TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT-2026-07.md` Part XIII into its own canonical specification. Composes with `docs/design/COMMUNITY-COORDINATION-ON-ZEROPOINT-2026-07.md`, which specifies how the ecosystem coordinates the ZEP lifecycle without depending on any platform.

**Status:** Design note. Ready for iteration; open decisions marked. This document is the specification of the framework; the framework's first proposal (**ZEP-000**) will be the meta-proposal defining the ZEP format formally on-chain.

**Author:** Ken Romero, with synthesis assistance from Claude.

**Date:** 2026-07-05.

---

## Part I — The Framework at a Glance

ZeroPoint is not a fixed software product. It is a framework of invariants around which mechanisms compose. The invariants are non-negotiable and load-bearing; the mechanisms are experiments that can be replaced when better ones emerge. Over time, better mechanisms displace worse ones because operators adopt them.

The framework has three parts:

- **The invariants.** A small, precise set of substrate properties that cannot be replaced without breaking the substrate's guarantees. Enumerated in Part II.
- **The mechanisms.** Everything else — the specific implementations that fill in around the invariants. Enumerated in Part III.
- **The supersession process.** The formal mechanism by which proposals for new mechanisms are published, reviewed, adopted, and superseded. Specified in Parts IV–VIII.

The framework exists because ZeroPoint's interesting problems — detection, reputation, cognition, coordination — are open and will remain open. Locking any particular solution into place would prevent the ecosystem from getting better at them. The framework's job is to keep the invariants stable while letting the mechanisms evolve.

---

## Part II — The Invariants

The invariants are the substrate's contract with the ecosystem. Any implementation that calls itself ZeroPoint must preserve them.

### 2.1 The complete list

**I-1. Genesis-derived key hierarchy.** All authority in a deployment derives from the operator's Genesis key through a well-defined three-level certificate hierarchy (Genesis → Operator → Agent). No non-Genesis root is a valid trust root.

**I-2. The receipt structure and its hash-linked chain.** Every receipt has the wire fields specified in `whitepaper-v9.md` §4.1. The chain is append-only, hash-linked via the `pr` field, and independently verifiable offline.

**I-3. The eight-invariant delegation chain verification.** Delegation chains verify against the eight invariants specified in `whitepaper-v9.md` §5.2. Any violation rejects the entire chain.

**I-4. Constitutional rules and their atomic evaluation at the gate.** The Harm Principle Rule and the Sovereignty Rule are non-removable, evaluate at fixed positions 1 and 2 in the policy engine, and cannot be bypassed by any capability grant or WASM module.

**I-5. The signature-based verification model.** Every consequential action is signed by an Ed25519 key. Verification of any claim reduces to verification of one or more signatures against known keys.

**I-6. The nine design principles.** The principles articulated in `whitepaper-v9.md` — signing is gravity, identity is a key not a location, there is no center, every bit counts, store-and-forward is primary, a tool is intent crystallized, contact does not commit, one canonical path per substrate concern, the system acts and the operator signs — are structural commitments that mechanism replacements must respect.

**I-7. Sovereignty preservation.** The operator holds the Genesis key. No entity — including the Foundation — can revoke, override, or condition an operator's control of their own instance. Every mechanism must preserve this property; a mechanism that made sovereignty contingent on any third party is disqualified.

**I-8. Local-first operation.** The substrate functions on the operator's own hardware without requiring any remote service. Every mechanism must preserve this; a mechanism that required cloud connectivity for core function is disqualified.

### 2.2 Why these and not others

The invariants share four properties that justify their permanence:

- **They are precise enough to test.** Any implementation can be verified against each invariant with concrete checks. Invariant preservation is not a matter of interpretation.
- **They are load-bearing.** Removing any of them would collapse other substrate guarantees. Constitutional rules depend on gate-atomic evaluation; the gate depends on the receipt structure; the receipt structure depends on Genesis-derived signatures. The invariants form a coherent whole.
- **They compose without conflict.** No pair of invariants is in tension. A mechanism can preserve all of them simultaneously without needing to trade off.
- **They are not mechanism choices.** They constrain what mechanisms can do without dictating how mechanisms do it. Ed25519 is specified because it is what signature verification uses today, but the invariant is "signature-based verification," not "Ed25519 forever" — a future invariant amendment could replace the algorithm if post-quantum needs required it, provided the replacement preserved the signature-based verification property.

### 2.3 Amending the invariants

Invariants are stable but not immutable. Amendment requires:

- A ZEP explicitly proposing the amendment.
- A demonstration that the amendment does not break any other invariant or any load-bearing substrate property.
- Reference implementation of the amended invariant.
- Explicit adoption cadence — because changing an invariant changes the substrate's contract, adoption requires broader consensus than typical mechanism ZEPs.

Amendments are expected to be rare. The framework is designed such that most improvement happens at the mechanism layer, not at the invariant layer.

---

## Part III — The Mechanisms

Everything not on the invariant list is a mechanism. Mechanisms are how the substrate implements what the invariants require without the invariants dictating how.

### 3.1 Enumerated mechanism categories

The following are all mechanisms, subject to replacement via ZEP:

- **Detection algorithms** (per `TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT-2026-07.md`)
- **Pattern accumulator designs**
- **Officer inference approaches** (Steward, Sentinel, Forge, Cleo, Aegis implementations)
- **Cartographer trajectory attribution methods**
- **Reputation computation**
- **Mesh transport implementations** (Reticulum-compatible, TCP, UDP, HTTP, future transports)
- **Presence Plane backends**
- **Truth anchor backends** (which distributed ledger to anchor to)
- **Cognitive-layer coordination strategies** (how the apex observer orchestrates)
- **Cryptographic algorithm choices within invariant parameters** — e.g., XChaCha20-Poly1305 vs. AES-256-GCM for AEAD, HKDF-SHA256 vs. HKDF-SHA512 for KDF, provided the resulting scheme preserves the signature-based verification and the substrate's threat model
- **Presentation-layer implementations** (browser harness, semantic canvas, minimal-fidelity terminal)
- **Backup and recovery schemes** (per `BACKUP-AND-RECOVERY-LANDSCAPE-2026-07.md`)
- **Vault format and storage architecture**
- **Peer-discovery announce category taxonomies**
- **Community-surface primitives** (channel taxonomies, session mechanics, moderation approaches)
- **Media provenance formats and integrations**
- **Non-recording attestation implementations**
- **Software integrity attestation implementations**
- **Compute mandate protocols** (how cloud escalation is structured)
- **Officer sweep cadences and coordination protocols**

The list is not exhaustive. Anything not on the invariant list is a mechanism.

### 3.2 What makes something a mechanism vs. an invariant

A mechanism is anything that:

- Fills a specific role the substrate needs but doesn't require any particular implementation of.
- Can be replaced without breaking other substrate guarantees.
- Has meaningful alternatives worth exploring.
- Is not itself dictated by the invariants.

An invariant, by contrast, is a property the substrate needs to preserve for its guarantees to hold. If two implementations preserve the invariants and both fill the same role, they are alternative mechanisms.

### 3.3 The role-and-constraints spec

Each mechanism has a **role** (what it does in the composition) and a set of **constraints** (what it must satisfy to fill the role). A replacement mechanism must fill the role and satisfy the constraints. Beyond that, its internal design is open.

For example: the "detection algorithm" role is "given an atomic action that atomic enforcement permits, produce a detection finding (no signal / notice / acknowledgment requested) and optionally flag the trajectory for post-hoc review." The constraints are: preserve invariants I-1 through I-8; produce chain-anchored receipts for findings; cannot deny actions that atomic enforcement permits (per the reframing in the detection design note). Any implementation that fills this role and satisfies these constraints is a valid detection mechanism.

Formal role-and-constraints specifications for each mechanism category are future work — ZEP-000 will require them, but they don't yet exist as canonical artifacts.

---

## Part IV — ZeroPoint Enhancement Proposals (ZEPs)

A ZEP is the formal document type for proposing a mechanism replacement. Every ZEP is a chain-anchored artifact.

### 4.1 The ZEP format

A ZEP contains the following sections:

**Header:**
- **ZEP number.** Assigned at publication (see §4.4 on numbering).
- **Title.**
- **Author(s).** Operator identities.
- **Type.** "Standard" (mechanism replacement), "Informational" (documentation or clarification), "Meta" (about the ZEP process itself).
- **Status.** Draft / Published / Adopted / Superseded / Withdrawn (see §5).
- **Chain reference.** The receipt ID under which this ZEP is published.
- **Supersedes / Superseded by.** References to prior or successor ZEPs.
- **Created.** Timestamp.

**Body:**
- **Abstract.** One paragraph describing what the ZEP proposes.
- **Motivation.** Why the current mechanism is insufficient or improvable.
- **Specification.** Complete, unambiguous description of the replacement mechanism. Precise enough that an independent implementer can build a compliant version.
- **Rationale.** Why this design and not others; comparative analysis with alternatives considered.
- **Backward compatibility.** How instances currently running the existing mechanism migrate. Whether the replacement is interoperable with the existing mechanism during transition.
- **Security implications.** What the replacement changes about the substrate's threat model. New threats introduced or existing threats mitigated.
- **Invariant preservation.** Explicit mapping to each of the eight invariants (I-1 through I-8) demonstrating how the replacement preserves each.
- **Evaluation criteria.** How adopters can assess whether the replacement is working in their instance. What metrics, what test cases, what observation surfaces.
- **Reference implementation.** Optional but strongly encouraged. If present, includes a chain-anchored content hash of the implementation and a build attestation (per `SOFTWARE-INTEGRITY-ATTESTATION-2026-07.md`).
- **Copyright / license.** ZEP text is CC BY 4.0 or public domain per author preference; reference implementations follow their own licensing but should be permissive.

### 4.2 Signature and immutability

A ZEP is signed by its authors' Genesis-derived operator identities. Once published, its content is immutable — the content hash is fixed and independently verifiable. Revisions are new ZEPs that explicitly supersede prior ones via the `Supersedes` field; the prior ZEP's status becomes "Superseded" when a superseding ZEP is published and its content hash referenced.

Authors can withdraw a ZEP by publishing a withdrawal receipt referencing the ZEP's content hash. Withdrawal status is chain-visible; withdrawn ZEPs remain retrievable but are marked as no longer under active development or advocacy by their authors.

### 4.3 Types of ZEP

- **Standard ZEP.** Proposes a mechanism replacement. Most ZEPs are of this type.
- **Informational ZEP.** Provides clarification, documentation, or guidance without proposing a change to any mechanism. Used for design conventions, best practices, or reference material.
- **Meta ZEP.** Proposes a change to the ZEP process itself. Rare, high-scrutiny.

### 4.4 ZEP numbering

ZEP numbers are assigned in sequence as ZEPs are published. Number assignment is coordinated by the Foundation's registry as a convenience — an operator publishes a draft, requests a number, receives one, then publishes the finalized ZEP with the number embedded. Alternative registries can assign numbers in parallel namespaces (e.g., "COMMUNITY-ZEP-014" vs. "ZEP-014") if they choose to operate independently.

Number assignment is not authority. A ZEP with a number is not thereby adopted or endorsed; it's simply indexed.

**ZEP-000** is reserved for the meta-proposal that formally defines the ZEP process on-chain. Until ZEP-000 is published, this document serves as the working specification.

---

## Part V — The ZEP Lifecycle

A ZEP moves through a well-defined lifecycle. Each transition is a chain event.

### 5.1 Draft

The ZEP is being written. Not yet published on-chain. Circulated informally for feedback via community channels or direct communication with prospective reviewers.

### 5.2 Published

The ZEP has been chain-anchored via a signed receipt from its authors. The content hash is fixed; the ZEP number is assigned; the ZEP is discoverable via peer-discovery announces under `foundation:proposal:*` or `community:proposal:*` (depending on author affiliation).

Publication does not require Foundation approval. Publication is a unilateral action any operator can take.

### 5.3 Under Review

Not a formal status distinct from Published — review is a continuous process that begins at publication. Reviewers publish attestation receipts referencing the ZEP's content hash. Attestations may endorse, dispute, request changes, or offer specific technical feedback. Attestations accumulate on the chain and are discoverable alongside the ZEP.

The Regent presents attestation summaries to operators considering the ZEP, weighted by attester reputation.

### 5.4 Adopted

An operator adopts a ZEP by publishing a mechanism-selection receipt on their own chain referencing the ZEP's content hash. Adoption is per-operator, per-mechanism, chain-visible, and reversible.

There is no ecosystem-wide "adopted" status. A ZEP is adopted by those operators who have published mechanism-selection receipts for it. Aggregate adoption patterns are observable by anyone who queries the network.

### 5.5 Superseded

A ZEP is superseded when a new ZEP is published that references it in the `Supersedes` field. The superseded ZEP remains chain-anchored and retrievable; its status flag updates to indicate it has been superseded and by which successor ZEP.

Superseded does not mean unusable. Operators can continue running a superseded mechanism if they prefer it. Superseded simply means a successor has been published; the ecosystem is aware of the successor's existence.

### 5.6 Withdrawn

The ZEP's authors have withdrawn active support for the proposal. A withdrawal receipt is chain-anchored referencing the ZEP's content hash. Withdrawn ZEPs remain retrievable; their status flag indicates withdrawal.

Withdrawal by the authors does not prevent others from adopting the mechanism or maintaining a fork. Withdrawal signals that the original authors are no longer advocating for or maintaining the proposal.

---

## Part VI — Adoption Semantics

There is no ecosystem-wide adoption vote. Each operator selects which mechanisms their instance runs via chain-anchored mechanism-selection receipts. The framework's adoption semantics preserve per-operator sovereignty over which mechanisms run.

### 6.1 The mechanism-selection receipt

An operator publishes a receipt of type `mechanism_selection` containing:

- The mechanism role (e.g., "detection algorithm", "mesh transport", "reputation computation").
- The ZEP content hash identifying the selected mechanism.
- The specific implementation content hash (from the reference implementation or an alternative build).
- Effective timestamp.
- Signature from the operator's Genesis-derived identity.

The receipt is chain-anchored on the operator's own chain. Peers who interact with this operator can verify which mechanism is in effect for which role.

### 6.2 Per-mechanism selection

An operator can adopt different ZEPs for different mechanisms independently. A common pattern: run the Foundation reference implementation for most mechanisms while adopting a specific alternative for one mechanism the operator has evaluated and prefers. There is no all-or-nothing adoption.

### 6.3 Reversibility

An operator can revert to a prior mechanism at any time by publishing a new mechanism-selection receipt referencing the earlier ZEP. Adoption is not a one-way commitment; it is an operational choice the operator can update as their assessment evolves.

### 6.4 Interoperability boundaries

Some mechanisms require both peers to be running them for interaction to work. Examples: mesh transport protocols, session cryptography, capability-grant formats.

For these, adoption forms compatibility groups. Two peers can interact if they share compatible mechanisms in the roles their interaction requires. A peer running a novel mesh transport can only interact with peers who have also adopted that transport.

Other mechanisms are peer-independent. Detection algorithms, reputation computation, presentation-layer implementations — these are local to the operator and don't require peer coordination.

Backward compatibility fields in ZEPs specify whether a proposed mechanism is interoperable with the existing mechanism during transition. Mechanisms that maintain interoperability during transition can be adopted incrementally without splitting the ecosystem.

### 6.5 Emergent displacement

A mechanism displaces its predecessor by being adopted by operators who prefer it. There is no formal moment when the ecosystem "adopts" a ZEP; there is a growing pattern of individual adoption decisions that eventually reaches whatever critical mass matters for the mechanism in question.

The Foundation's reference implementation is one adopted set among many possible sets. It is called "reference" because it is what the Foundation supports and recommends as a starting point, not because it is the only legitimate implementation. When a proposed ZEP is broadly better than the current reference, the Foundation can adopt it into the reference; when it isn't, operators can still run it if they prefer.

---

## Part VII — The Foundation's Role in the ZEP Process

The Foundation is a peer in the framework it seeded. Its role is bounded to specific functions that do not constitute authority over other operators.

### 7.1 What the Foundation does

- **Publishes the invariants precisely** as a chain-anchored artifact.
- **Maintains the reference implementations** of each mechanism.
- **Coordinates ZEP number assignment** as an indexing convenience.
- **Runs a discoverable registry** of published ZEPs and their statuses.
- **Contributes proposals as its own operator identity.** Foundation-authored ZEPs go through the same lifecycle as anyone else's.
- **Contributes attestations** as its own operator identity, weighted by adopters' trust in the Foundation's judgment.
- **Adopts mechanisms into its reference implementation** when it determines a ZEP is better than the current reference, and publishes updated reference releases accordingly.

### 7.2 What the Foundation does not do

- **Does not gatekeep proposals.** Anyone can publish a ZEP without Foundation approval.
- **Does not certify ZEPs.** There is no Foundation seal of approval that changes a ZEP's status or authority.
- **Does not centralize adoption.** Which mechanisms an operator runs is the operator's choice.
- **Does not require accounts** or any registration for participation.
- **Does not moderate ZEP content.** ZEPs that violate the substrate's constitutional rules are structurally impossible to execute against the substrate; other content decisions are left to community and reputation dynamics.

### 7.3 Alternative authorities

Other release-signing authorities can operate in parallel with the Foundation. A community can maintain its own release chain for a fork of the reference implementation; another organization can publish its own recommended ZEP set; a research group can maintain reference implementations of alternative mechanisms.

The Foundation is one such authority — the initial one, and the one that shipped the substrate. It has no structural monopoly on the role.

---

## Part VIII — ZEP-000: The Meta-Proposal

ZEP-000 is the meta-proposal that formally defines the ZEP framework on-chain. Until it is published, this document is the specification.

### 8.1 What ZEP-000 will contain

- The formal ZEP format specification (superseding Part IV of this document).
- The ZEP lifecycle formal specification (superseding Part V).
- The mechanism-selection receipt specification (superseding §6.1).
- The role-and-constraints specification for each mechanism category (an addition beyond this document).
- The invariant list, formally chain-anchored (superseding §2.1).
- The Foundation-role specification for the framework (superseding Part VII).
- The amendment process for ZEP-000 itself.

### 8.2 Bootstrapping

ZEP-000 is a self-referential document. It specifies the process by which it can itself be superseded. This creates a bootstrap dependency: the first published ZEP defines the format all subsequent ZEPs use.

Bootstrapping proceeds as follows:

1. The Foundation drafts ZEP-000 based on this specification.
2. The draft is circulated for community review through the community-surface channels.
3. When review has converged on a coherent draft, the Foundation publishes ZEP-000 as the first chain-anchored ZEP.
4. From that point forward, ZEP-000 is the authoritative specification; this document becomes historical.

### 8.3 Amending ZEP-000

Once published, ZEP-000 is like any other Meta ZEP — it can be superseded by a new Meta ZEP that references it in the `Supersedes` field. Amending ZEP-000 is expected to be rare and high-scrutiny because it changes the fundamental process the ecosystem uses.

Amendment adoption is per-operator like any ZEP, but Meta ZEP adoption has an implicit coordination cost: operators running divergent ZEP process specifications may have difficulty coordinating on any subsequent proposals. This is a structural pressure toward consensus on the meta-process without requiring formal consensus mechanisms.

---

## Part IX — Adversarial Dynamics

### 9.1 Proposal spam

**Attack:** An operator publishes many low-quality ZEPs to flood the ecosystem's attention.

**Defense:** ZEP publication requires computational cost (per the peer-discovery proof-of-work anti-spam mechanism). Reviewer attention allocates via reputation dynamics — high-reputation reviewers' engagement with a ZEP signals its quality; consistent low-quality ZEP authors accumulate reputation costs. The Regent filters ZEP announces by author reputation and ZEP quality signals; low-signal proposals don't reach operators who haven't specifically requested to see all proposals.

**Residual risk:** New operators with no reputation history can publish. This is a feature (new voices can enter the ecosystem) that has some cost (initial spam potential).

### 9.2 Sybil-authored proposals

**Attack:** An operator creates many Sybil identities and publishes ZEPs signed by different identities to fabricate the appearance of broad ecosystem interest.

**Defense:** Sybil identity creation is expensive (per the substrate's Sybil-resistance mechanisms). ZEP reception weighs author reputation, and fresh Sybil identities have no reputation. Cross-attestation from independent reviewers (whose reputation is not linked to the author) is what actually moves a ZEP toward adoption; Sybil-authored attestations do not accumulate meaningful weight.

**Residual risk:** Sophisticated Sybil coordination can produce apparent momentum. Reputation dynamics eventually reveal Sybil clusters but not instantly.

### 9.3 Bad-faith adoption tracking

**Attack:** An operator publishes fake mechanism-selection receipts claiming to have adopted a mechanism they haven't, to inflate the appearance of ecosystem adoption.

**Defense:** Adoption is verifiable — peers interacting with the operator can verify which mechanism is actually running via runtime attestation (per `SOFTWARE-INTEGRITY-ATTESTATION-2026-07.md`). Discrepancy between claimed adoption and actual runtime state is chain-visible and reputationally costly.

**Residual risk:** For mechanisms whose actual use is not peer-observable (e.g., local-only detection algorithms), false adoption claims are hard to detect. This is a bounded concern because the point of adoption is the operator's own use; misrepresenting adoption has limited attack surface.

### 9.4 Proposal capture

**Attack:** A well-resourced actor publishes ZEPs designed to look like community consensus but that subtly favor the actor's interests.

**Defense:** All ZEPs are chain-anchored with author identities. Author-affiliation patterns are visible over time. Reputation for author trustworthiness accumulates. Adoption remains per-operator; an operator considering a ZEP can inspect the author's history and the attestation pattern.

**Residual risk:** Sophisticated actors can build reputation over long time horizons. This is the same residual risk that applies to any reputation-mediated system.

### 9.5 Invariant-violation proposals

**Attack:** A ZEP proposes a mechanism that appears to preserve the invariants but actually violates one.

**Defense:** The invariant-preservation section of the ZEP requires explicit mapping. Reviewers verify the mapping. Reference implementations can be tested against invariant test suites. Operators considering adoption can run their own invariant tests before publishing a mechanism-selection receipt.

**Residual risk:** Subtle violations may pass initial review. If adopted, the violation would become visible when it manifested. The chain-anchored nature of adoption means retroactive discovery of a violation is possible; operators can revoke their adoption via a new mechanism-selection receipt reverting to a compliant alternative.

---

## Part X — Open Design Decisions

1. **ZEP-000 authoring cadence.** When does the Foundation draft ZEP-000? What review period precedes its publication?

2. **Registry format.** The Foundation's ZEP registry format — TOML? JSON? Structured chain receipts? How is it discoverable? What does it index?

3. **Role-and-constraints specifications.** Each mechanism category needs a formal role-and-constraints spec that ZEPs can be measured against. Who authors these? How are they versioned?

4. **Invariant test suite.** Chain-anchored test suite for each invariant. Implementation. Automation for reference-implementation validation.

5. **Attestation format for reviewers.** Structure of attestation receipts. Standardized fields for endorsement, dispute, technical feedback.

6. **Alternative-registry discovery.** How do non-Foundation registries advertise themselves? What allows an operator to subscribe to multiple registries?

7. **Meta-ZEP scrutiny mechanisms.** Higher review bar for Meta ZEPs than Standard ZEPs. What formal or emergent mechanisms ensure this?

8. **Withdrawal semantics.** If an author withdraws a ZEP that operators have adopted, what happens? Do operators receive notification? Do reference implementations get maintenance commitments elsewhere?

9. **Fork-of-a-fork semantics.** If a ZEP is superseded, and someone wants to revive the superseded mechanism with modifications, is that a new ZEP that also references the original? How is the lineage tracked?

10. **Language and format for ZEP prose.** English is the default; are other languages accepted? Are translations formal ZEPs of their own?

---

## Part XI — Companion Documents

- `docs/ARCHITECTURE-2026-07.md` — canonical architecture record; principles 6 and 8 (a tool is intent crystallized; one canonical path per substrate concern) shape how mechanism replacements should behave.
- `docs/whitepaper-v9.md` — public thesis; the invariants enumerated here map to specific whitepaper sections.
- `docs/design/TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT-2026-07.md` — Part XII (An Invitation) and Part XIII introduced the supersession framework at a summary level; this document is the full specification that Part XIII pointed at.
- `docs/design/COMMUNITY-COORDINATION-ON-ZEROPOINT-2026-07.md` — specifies how the ecosystem coordinates the ZEP lifecycle without depending on any platform. This framework and that coordination model compose.
- `docs/design/PEER-DISCOVERY-AS-OUTREACH-2026-07.md` — the transport for ZEP publication announces.
- `docs/design/SOFTWARE-INTEGRITY-ATTESTATION-2026-07.md` — the mechanism by which reference implementations attest to their build integrity.
- `docs/design/DISTRIBUTED-KNOWLEDGE-COMMONS-2026-07.md` — the reputation and knowledge substrate on which ZEP reviewers accumulate attestation history.

---

*The substrate is not a fixed product; it is a framework of invariants around which mechanisms compose. The invariants stay stable so the substrate's guarantees hold across time and across implementations. The mechanisms evolve because the interesting problems remain open. The ZEP process is the affordance that makes this evolution real: anyone can propose a replacement; adoption is per-operator; displacement is emergent; the Foundation is a peer, not a gatekeeper. The framework exists so that no one — including the Foundation — needs to be trusted with authority over how the substrate improves. The improvement happens in the open, on the chain, verifiable by anyone who cares to verify it.*
