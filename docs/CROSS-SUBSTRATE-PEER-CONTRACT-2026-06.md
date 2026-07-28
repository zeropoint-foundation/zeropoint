# Cross-Substrate Peer Tier Contract — What the Peer Interface Must, May, and Must Not Do

*Dated 2026-06. The runtime-neutral contract between a substrate's peer
communication surface and the substrates it connects to. Names which
affordances a peer implementation MUST have, which it MAY have, and which
it MUST NOT have, so that affordance gaps are immediately classifiable as
degradations vs disqualifications vs correct postures.*

*Updates to this doc are architectural acts and should be treated as such.*

---

## 1. What this doc is

This is the Cross-substrate peer tier contract — the operational complement
to `docs/rfc-mesh-inbound-auth-v1.md` and the `crates/zp-mesh` surface at
the substrate-to-substrate integration boundary. Where the RFC addresses a
specific authentication gap in the inbound receipt and delegation paths, this
document partitions the full peer communication surface — inbound and outbound,
delegation crossing, audit attestation, peer chain queries — into Required,
Optional, and Forbidden affordances so that any proposed peer feature can be
classified without re-deriving from principles.

**Tier distinctions.** Three tiers of the Substrate Conformance Contract
involve cross-boundary trust, and the boundaries differ structurally:

- The **edge tier** (`docs/EDGE-TIER-CONTRACT-2026-06.md`) covers
  external-traffic-to-substrate via the foundation worker. One side is an
  unauthenticated external requester; the other side is the operator's
  substrate. The edge is a thin authenticator-router-directory.

- The **peer tier** (this document) covers substrate-to-substrate
  exchanges. Both sides are full sovereign substrates: both hold chains,
  both sign with Genesis-derived keys, both can delegate and attest. Neither
  side is an edge or a client; both are first-class trust principals.

- The **verifier tier** covers third-party-verifies-substrate-publicly.
  One side has a chain; the other side has no authority to emit on behalf of
  the first. The verifier is a parser producing verdicts about well-formedness,
  not a participant in the governance exchange.

The peer tier is the protocol of decentralization in operation — what happens
when two sovereign roots need to establish shared trust without a common
authority. Every affordance in this contract follows from that premise.

This document is the spoke for Tier 9 in
`docs/SUBSTRATE-CONFORMANCE-CONTRACT-2026-06.md`. The contract is
runtime-neutral: the current `crates/zp-mesh` implementation (Reticulum-
compatible, libp2p adapter, TCP and WiFi interfaces, Ed25519 envelope
authentication) is the reference implementation; other transports,
implementations, and deployment shapes conform to the same contract.

---

## 2. The category statement

The peer tier is the substrate's outbound and inbound surface for
operator-to-operator communication: delegation grants that cross substrate
boundaries, audit attestations that support Claim 2 (present state compresses
full history), peer chain queries, joint-action receipt visibility, and any
other exchange that requires both parties to be sovereign substrates rather
than one substrate plus a client, an edge, or a public verifier.

Two design commitments shape every affordance in this tier. First, peer
identity is Genesis-derived, not URL-derived. A peer is recognized by its
Ed25519 public key and by the chain of receipts anchored to that key — not
by the IP address or hostname at which its substrate is currently reachable.
A peer that migrates to a different host, rotates its transport endpoint, or
moves from a datacenter to a private server retains the same identity,
because identity is the cryptographic lineage, not the deployment coordinates.
Principle 2 (identity is a key, not a location) is the foundational claim; the
peer tier is where it operates most visibly.

Second, the peer connection is convenience; the chain is correctness. The
peer tier allows two substrates to exchange information efficiently while
connected, but every exchange that matters is chain-anchored on both sides.
When the connection drops, both operators retain a verifiable local record
of what was exchanged — not a cached copy of the peer's chain, but a signed
receipt describing what the local substrate received and from whom. Principle 5
(store-and-forward is primary) is what makes the peer tier honest: the chain
survives the outage; the peer connection is an optimization over walking the
chain.

---

## 3. Required affordances

An implementation lacking any Required affordance cannot serve as a
conformant peer interface. The fallback when the peer tier is absent is for
each operator to interact with other operators out-of-band, producing no
chain-anchored record of cross-substrate exchanges. Capability degradation
is significant — no verifiable cross-substrate delegation, no peer audit
attestation supporting Claim 2, no receipted joint action — but each
operator's own chain remains intact and the substrate's local correctness
is unaffected.

**1. Verify peer identity by Genesis-derived public key, not by transport
address.** When a peer connection is established or a peer message is
received, the substrate must authenticate the peer against an Ed25519
verifying key that is itself anchored to a chain position — the peer's
`peer:canonicalized` receipt or equivalent bead-zero entry. The peer's
IP address, hostname, or port is a reachability hint; it is not the peer's
identity. An implementation that accepts a peer's claimed identity solely
on the basis of transport-layer provenance has made the peer tier dependent
on DNS, BGP, or certificate authority correctness — precisely the attack
surfaces Principle 3 eliminates by removing the center. **P2, P3.**

**2. Authenticate every inbound peer message by Ed25519 signature.** Every
`CompactReceipt`, `CompactDelegation`, `PolicyAdvertisement`, audit response,
and other structured payload received from a peer must carry an Ed25519
signature over the canonical preimage of the payload, verifiable against the
sender's registered verifying key. The `mesh-auth-v1` policy table from the
inbound-auth RFC names the correct graduated response: signed-and-valid is
full-trust acceptance; signed-and-invalid is rejection with the failure
attested in a chain receipt; signed-with-unknown-key is conditional
acceptance with `unverified` flag and logged warning; unsigned is acceptance
with `unsigned` flag and logged warning, never silent full-trust. (The RFC
also mentions a "negative reputation signal" for invalid signatures; this
is forward-looking against a reputation primitive the substrate does not
yet have — see `docs/rfc-mesh-inbound-auth-v1.md` §6 for the deferral.) An implementation that
silently accepts unsigned peer messages — the v0 behavior that the RFC
exists to fix — cannot distinguish a legitimate peer from a forged or
replayed one. **P1.**

**3. Sign every outbound peer message with the substrate's identity key.**
Messages the substrate sends to peers — receipts, delegation grants,
audit responses, capability proposals, heartbeats — must be signed with
the substrate's own Ed25519 signing key, derived from Genesis via the
established key-derivation path. The signature binds the message to the
sending substrate's cryptographic identity. A peer that receives an unsigned
outbound message from this substrate has no basis to distinguish it from
a fabricated or replayed payload. **P1, P2.**

**4. Maintain a peer registry with explicit operator consent per entry.**
The substrate must maintain a registry that maps peer identity (Ed25519
verifying key, plus the 128-bit Destination hash derived from it) to
reachability hint (current transport endpoint, interface type). Each entry
in the registry must have been explicitly authorized by the operator — either
via a `peer:registered` receipt from the operator's own chain, or via an
equivalent ceremony that produces a chain-anchored authorization. The
substrate must not auto-populate the registry from network discovery alone.
A peer that announces itself on the mesh is a candidate for registration,
not a registered peer. Operator consent is the gate. **P3** (a registry
populated without operator consent is a center forming in the transport
layer), **P7** (contact does not commit — peer contact is not peer
authorization).

**5. Honest failure on peer unreachability.** When a peer is unreachable
— connection refused, timeout, transport error — the substrate must record
a `peer:unreachable` or equivalent receipt on the local chain and surface
the failure to the operator, rather than silently retrying, fabricating
state, or routing the message via an unregistered relay. The chain is the
primary mode (Principle 5); the peer connection is the secondary path. If
the peer connection fails, the chain records that it failed, and the pending
exchange waits for the peer to become reachable again or for the operator
to take explicit action. **P3** (fabricating reachability is asserting a
center-style truth about a peer's state that only the peer can assert),
**P5** (the chain record of the failure is itself correct state; silence
is not).

**6. Chain-anchor every cross-substrate exchange locally.** Every peer
exchange that has governance significance — receiving a delegation grant,
receiving an audit attestation, responding to a chain query, forwarding a
receipt from a peer — must produce a receipt on the local chain. The
receipt captures what was received, from which peer identity, at what chain
position the receipt was appended, and whether the peer's signature was
verified. The receipt is the local substrate's own account of the exchange;
it is distinct from the peer's receipt of the same exchange. Both substrates
anchor the exchange independently; neither substitutes for the other.
**P1** (the local receipt is the structural attestation that the exchange
happened and was authenticated), **P3** (one canonical local record of
cross-substrate events, not a shared registry or a merged chain).

**7. Honor the peer chain query protocol.** When a peer requests verifiable
chain state — an AuditChallenge under the Claim 2 mechanism, a request for
specific receipt entries, a delegation chain walk — the substrate must return
signed entries the peer can re-derive against. The response must carry the
signature of the entries' original signer (the local operator's key), not
a re-signature by the substrate as the responding party. The peer's ability
to verify the response independently — by walking from Genesis, applying the
grammar — is the structural content of Claim 2. An implementation that
returns unsigned or re-signed entries in response to chain queries has broken
the peer's ability to independently verify the claimed state. **P1, P3**
(the local substrate is the authority for its own chain entries; it cannot
speak with authority about another substrate's chain, and the peer must be
able to tell the difference).

**8. Reject inbound delegation grants that widen authority.** A delegation
grant received from a peer must be evaluated against the eight delegation
invariants in `DelegationChain::verify()` before it is accepted into the
local chain. The envelope-monotonicity rule applies across substrate
boundaries with the same force it applies within a single chain: a child
grant cannot claim broader scope, longer lease, greater depth, or higher
trust tier than the parent grant that authorized it. A delegation arriving
from a peer that claims authority not present in the grantor's chain must
be rejected and the rejection chain-anchored. The peer tier is not a
surface through which the delegation envelope can be widened by transit.
**P1** (accepting an unauthorized widening produces a receipt that attests
to a grant the chain cannot verify), **P3** (cross-substrate delegation
authority flows from chain lineage, not from the peer connection).

---

## 4. Optional affordances

Each optional affordance improves peer communication without affecting the
correctness of either substrate's chain.

**Active peer discovery.** The substrate may broadcast its own presence
to known peers and subscribe to peer reachability updates, so that peer
registry entries stay current without manual operator maintenance. Discovery
results are *candidates* for operator-authorized registration, not automatic
registry entries. Without this affordance, peer registry entries must be
configured or updated manually; peer reachability goes stale more quickly.

**Connection pooling, persistent connections, and multiplexing.** The
substrate may maintain long-lived connections to registered peers, pool
connections across concurrent exchanges, and multiplex multiple logical
channels over a single transport connection. Without this affordance, each
exchange opens and closes a connection; operational overhead increases but
no chain entries are affected.

**Chain digest replication to specific peers.** The substrate may share
Merkle digests, epoch roots, or other compact chain summaries with specific
registered peers as a prelude to audit challenge-response, enabling the
peer to quickly locate a chain-tip discrepancy without walking from Genesis.
Without this affordance, Claim 2 verification requires full AuditChallenge
round-trips from Genesis; with it the round-trip cost is amortized across
the replicated digests.

**Content-blind connection telemetry.** The substrate may log peer
connection metrics — round-trip latency, reachability windows, retry counts,
envelope authentication success/failure rates, message throughput — without
logging receipt contents or operator-derived material. Without this
affordance, peer health visibility is limited to what the chain records in
`peer:unreachable` and related receipts.

**Multiple reachability hints per peer identity.** A peer registry entry
may carry more than one reachability hint — a primary endpoint, one or more
fallback endpoints, a relay path via a mutually known third peer — so that
the substrate can attempt alternative transport paths before recording an
unreachability event. Without this affordance, a peer registry entry has
one endpoint; a transport failure is immediately an unreachability event
regardless of whether alternative paths exist.

**Pre-emptive peer chain verification before exchange.** The substrate may
issue an AuditChallenge to a peer before the first governance-significant
exchange, verifying that the peer's claimed chain state is well-formed
against the grammar, rather than trusting the peer's claimed state at
exchange time and verifying afterward. Without this affordance, chain
verification happens reactively (on dispute or audit); with it, the
substrate establishes a baseline of mutual chain-honesty before the first
delegation or attestation crosses the boundary.

---

## 5. Forbidden affordances

The forbidden category names things a technically capable peer
implementation must not do at this tier. Lacking a forbidden affordance
is correct posture here, not degradation.

**1. Accepting unsigned inbound peer messages as fully trusted.** The peer
tier must not treat an unsigned `CompactReceipt`, `CompactDelegation`, or
other peer payload with the same trust level as a signature-verified payload.
The `unsigned` flag in the inbound policy table exists precisely to allow
honest degradation — the payload can be accepted with reduced trust weight
— but silent full-trust acceptance of unsigned material is the failure mode
the RFC exists to fix. ZeroPoint signs receipts throughout the substrate;
the forbidden thing at the peer tier is accepting *peer-originated* messages
without verifying those signatures, treating the peer connection's transport
provenance as a substitute for cryptographic attestation. **P1** (an
unsigned peer receipt is an assertion without a witness; transport-layer
provenance is not a witness).

**2. Signing or forwarding receipts on a peer's behalf.** This substrate
must not produce a receipt that carries another operator's signing key
material — not as a proxy, not as a relay, not as a "convenience
re-signature." Only the operator whose Genesis key anchors a chain may
produce receipts on that chain. If this substrate receives a receipt from
a peer and wishes to anchor the exchange, it produces its own receipt — a
local `peer:receipt-received` entry signed by *this* operator's key,
referencing the peer's receipt by content hash. The peer's receipt is not
re-emitted under this substrate's authority. **P1** (a receipt signed by
a key other than the chain's Genesis-rooted authority is decorative by
that chain's verification), **P3** (a substrate that can sign on behalf of
peers is a signing center for those peers' chains).

**3. Asserting chain authority on a peer's behalf.** This substrate must
not respond to a third party's query about a peer's chain state by
producing an authoritative-sounding claim that represents what the peer
*can* do, what the peer *has done*, or what the peer's current delegation
scope *is*. It may relay the peer's own signed chain entries to a third
party — a pass-through of the peer's own signed evidence — but the relay
must be clearly a relay: the peer's signature is preserved, not replaced
with this substrate's signature. A substrate that asserts peer authority
has become a certificate authority for that peer's chain. **P3.**

**4. Holding a peer's private key material or operator-derived secrets.**
This substrate may register a peer's Ed25519 verifying key (public key)
in the peer registry — that is a Required affordance. It must not acquire,
hold, or store a peer's private signing key, a peer's vault-encrypted
credential, or any other secret material that the peer's sovereign root
owns. Peer keying material that crosses a substrate boundary is either a
public verifying key (fine, register it) or a compromise of the peer's
sovereign root (not fine under any circumstance). The `derive-not-replicate`
pattern from `docs/SINGULAR-SOVEREIGN-ROOT-2026-05.md` applies here at
the inter-substrate level: each sovereign root is held by exactly one
operator; distributing key material across substrates creates multiple
points of compromise. **P2** (identity is a key — distributing the key
distributes the identity, which defeats the sovereign-root model), **P3**
(a substrate that holds another operator's private key is an authority
center for that operator's identity).

**5. Auto-accepting cross-substrate delegation grants without operator
consent.** When a delegation grant arrives from a peer, the substrate must
not incorporate it into the local chain's active delegation state without
an explicit operator-side receipt authorizing the acceptance. Peer contact
is not peer authorization. The grant may arrive, be chain-anchored as
`peer:delegation-received` in a pending state, and be surfaced to the
operator for review; it becomes active only after an operator-authorized
`delegation:accepted` receipt is appended. An implementation that
automatically widens the local operator's delegation scope upon peer
request has made peer contact the mechanism of authority expansion — the
failure mode Principle 7 exists to prevent. **P1** (no chain receipt
authorizes the automatic acceptance), **P7** (contact does not commit —
a delegation arriving over the peer channel is a proposal, not a fait
accompli).

**6. Routing messages based on peer-asserted routing without signature
verification.** The substrate must not forward, relay, or re-route a
message based solely on routing metadata asserted by a peer — destination
identity, suggested next hop, claimed delivery guarantee — without
verifying that the routing assertion is signed by a key with chain-standing
to make it. A peer that claims "forward this to operator X at address Y"
is making a routing assertion; if that assertion is unsigned, it is
indistinguishable from a fabricated misdirection. The substrate may honor
routing suggestions from peers whose signing keys are registered and whose
signatures verify; it must reject unsigned routing assertions. **P1**
(unsigned routing assertions are claims without witnesses), **P3** (a
relay that trusts unsigned routing is a center-shaped attack surface —
any peer can instruct it to route arbitrarily).

**7. Merging peer chain entries directly into the local chain.** The local
chain is this operator's own signed, hash-linked record. A peer's chain
entries are that peer's signed record. The substrate must not append a
peer's receipt entries into the local `audit_entries` table as if they
were local receipts — not as a performance optimization, not as a
replication strategy, not as a "unified view." The correct shape is
a local receipt that references the peer's entry by content hash and
records the peer's signature as the authority. The `audit-invariant.md`
non-negotiable — there is exactly one chain, written by one writer, signed
by one operator's key — holds absolutely at the peer boundary. **P3**
(merging peer state into the local chain makes the local chain a center
for peer state, violating the one-chain-per-operator invariant), **P1**
(a peer's entry in the local chain would carry the peer's signature but
be positioned in a chain the local operator's key anchors — the two
signature contexts are irreconcilable).

**8. Acting as the source of truth for a peer's key rotation.** If a peer
rotates its Genesis-derived signing key — establishing a new identity root
via its own chain's key-transition receipts — this substrate must not
assert the new key independently, claim the rotation happened before the
peer's own chain records it, or refuse to update the peer registry until
some substrate-external confirmation arrives. The peer's own chain is
the source of truth for its identity transitions. This substrate learns
of a key rotation when it receives a signed key-transition receipt from
the peer, verifies it against the previous key, and updates its registry.
A substrate that maintains its own authoritative record of peer key state
has become a PKI for that peer — the structural shape Principle 3
specifically rules out. The conformant positive shape — what the
substrate _does_ do during peer key rotation (observe, verify against
the previous key, surface for operator confirmation, transition the
keystore on operator-signed `peer:identity:rotated` receipt) — is
specified in `docs/handoffs/peer-key-rotation-2026-06.md`, including
the edge cases for lost-key and compromised-key rotation. **P2** (the
peer's identity is its cryptographic lineage; only the peer can advance
that lineage), **P3** (a substrate-held authoritative record of peer
identity is a PKI center).

---

## 6. Composition with principles

The peer tier's contract derives from three principles that together define
what it means for two sovereign operators to exchange trust without a center.

**P2 (identity is a key, not a location) is the foundational commitment
for the Required affordances.** Required #1 (verify by pubkey, not URL)
is the direct operational expression: the peer's transport endpoint is
ephemeral; the peer's Genesis-rooted key is permanent. Required #3 (sign
outbound messages) and #4 (peer registry with operator consent) both flow
from the same commitment: a peer exchange is only as trustworthy as the
key that signed it. The Forbidden entries #4 (no peer private keys) and #8
(no acting as PKI for peer key rotation) are P2's negative expressions: the
key is the peer's own, not held or managed by others.

**P3 (there is no center) is the load-bearing principle for the Forbidden
category.** Entries #2, #3, #7 all prevent this substrate from becoming
a signing, asserting, or merging center for peer chains. Entries #5 and #6
prevent the peer connection from becoming an authority surface — a channel
through which peer contact expands local authority or routes traffic
without verification. Entry #4 prevents a credential center. Entry #8
prevents a PKI center. Every Forbidden entry at the peer tier is a way a
substrate could accumulate center-like authority over its peers, and P3
prohibits centers by construction. The peer tier is also where P3 is most
directly tested: two sovereign operators communicating necessarily creates
the temptation to create a shared authority or a shared state, and the
contract names the refusal.

**P5 (store-and-forward is primary) is the structural basis for Required
#5 (honest failure) and Required #6 (chain-anchor every exchange).** The
chain is not the record of successful peer connections; it is the record
of what the local substrate knows happened. A failed peer connection is
a fact worth anchoring. A received message is a fact worth anchoring before
acting on it. The peer connection is the fast path; the chain anchor is the
durable record. P5 is why the contract does not treat peer unreachability
as a transient error to be retried silently: the chain records the state
of knowledge, and "peer was unreachable at this chain position" is genuine
state.

**P1 (signing is gravity) justifies Required #2, #3, #7, #8 and Forbidden
#1, #2, #6, #7.** Every Required affordance that involves signature
verification traces to P1: an unsigned peer receipt has no witness; a peer
delegation grant without a verified signature cannot be evaluated against
the delegation invariants; a chain query response without the original
signer's key material cannot be independently re-derived. Every Forbidden
affordance that involves accepting, forwarding, or emitting unsigned or
re-signed material at this tier traces to the same principle: the receipt
is only as authoritative as the key that signed it.

**P7 (contact does not commit) is the structural basis for Forbidden #5.**
A delegation grant arriving over the peer channel is the peer tier's
canonical contact-without-commitment case. The grant arrives; it is
chain-anchored as received; it waits for operator consent. The peer
connection does not commit the local operator to accepting the grant.
P7 is also what makes Required #4 (explicit operator consent per registry
entry) structurally necessary: discovering a peer on the mesh is contact;
registering the peer is a substrate commitment that requires an operator
act.

---

## 7. Portability sketches

The contract is runtime-neutral. These sketches demonstrate that
conformance is achievable across substantially different transport choices,
deployment topologies, and implementation languages.

**`crates/zp-mesh` on Reticulum-compatible interfaces (current reference).**
A Rust implementation using Ed25519 + X25519 keys, Reticulum-compatible
128-bit Destination hashes, and support for LoRa, WiFi, TCP, and serial
interfaces. All Required affordances are present: peer identity derives from
the Ed25519 public key (`MeshIdentity`); inbound authentication is staged
behind the `mesh-auth-v1` feature flag (RFC migration plan); outbound
messages are signed via the substrate's signing key; the `NodeRegistry`
holds the peer registry; `MeshStore` provides persistent mesh state for
chain anchoring. The libp2p adapter (`Libp2pInterface`) demonstrates that
the same identity and signature model works over a different transport
stack.

**A Go or TypeScript implementation on HTTP/2.** The contract does not
require Rust, Reticulum, or any specific wire format. A Go peer service
that verifies inbound Ed25519 signatures over canonical JSON payloads,
signs outbound messages with a Genesis-derived key, maintains an explicit
peer registry with operator-consented entries, and produces a local
chain receipt for each verified inbound exchange is conformant. The
transport is HTTP/2; the Required affordances are transport-agnostic.
Optional affordances (connection pooling, persistent connections) are
naturally available in HTTP/2 without additional work.

**Two substrates on the same machine for development or testing.** A peer
pair where both operator substrates run on APOLLO, communicating over
`localhost` TCP. The contract is identical: each substrate has its own
chain, its own Genesis-derived key, its own peer registry with an entry
for the other. The `localhost` transport endpoint is a reachability hint;
the identity is the key. The same chain-anchoring requirements apply; the
same Forbidden affordances apply. This deployment shape is useful for
testing delegation-crossing semantics without requiring two physical hosts.

**Indirect attestation via a third peer.** If operator A and operator B
have no direct connection, but both have registered operator C as a peer,
operator C may relay a signed chain query response from A to B. The
contract handles this as honest indirect attestation: B receives A's
entries signed by A's key (preserved through the relay), and B also
receives a receipt from C attesting that C relayed the content. B can
verify A's entries independently; B also knows the delivery path. This is
not substitution — C does not re-sign A's entries — it is transport over
an indirect path with an explicit relay receipt. Required affordance #3
(C signs its relay receipt with C's own key) and Forbidden #2 (C does not
re-sign A's entries as C's own) are what make this honest.

**A public overlay as the rendezvous medium (targeted, not implemented).**
Freenet — a serverless peer-to-peer network whose peers form a small-world
ring and hold content-addressed state — is targeted as a compatible
transport per `docs/design/FREENET-TRANSPORT-CONFORMANCE-2026-07.md`
(operator ruling 2026-07-27). The sketch is included here per §8 trigger 1,
ahead of implementation, because the contract's answer is what determines
whether the implementation is worth building. Conformance is unremarkable:
the overlay carries an opaque signed announce blob or a signed
`MeshEnvelope`, and every Required affordance is satisfied above it exactly
as it is over TCP. Peer identity still derives from the Ed25519 public key;
outbound messages are still signed before they reach the medium; the peer
registry is still local and operator-consented; inbound entries are still
verified against the sender's key and never merged into the local chain
(Forbidden #7). What differs is not the contract but the population: the
medium is reachable by anyone rather than by peers the operator attached,
which makes Required inbound authentication load-bearing in a way a private
TCP mesh lets it not be. The contract already forbids the failure mode
(Forbidden #1, no unsigned messages); a public medium is what makes the
gap between the contract and its current enforcement operationally visible.
The overlay is never an authority — a rendezvous contract's validity rule
is signature verification and nothing else, and no capability, delegation,
or membership decision is expressible in it.

---

## 8. Autoregressive update triggers

1. **A new peer transport is adopted.** If the substrate adds QUIC, WebRTC,
   or another transport beyond TCP and Reticulum-compatible interfaces, this
   doc should be updated with the affordance availability notes for that
   transport and any implementation-specific considerations, even if
   conformance is straightforward.

2. **Delegation-crossing semantics evolve.** If the substrate introduces
   transitive delegation (operator A delegates to operator B, who re-delegates
   to operator C) or multi-party joint actions, Required #8 (reject inbound
   grants that widen authority) and Forbidden #5 (no auto-acceptance) will
   need to name the new delegation shapes explicitly.

3. **Peer identity rotation protocol is defined.** The current contract names
   Forbidden #8 (no acting as PKI for peer key rotation) but does not specify
   the positive shape of a conformant key-rotation receipt. When the substrate
   defines the `peer:key-rotated` receipt and its verification protocol, this
   doc should be updated to make the Required affordance explicit.

4. **A Required affordance proves hard to implement portably.** If "every
   inbound peer message must carry an Ed25519 signature" turns out to exclude
   a mesh transport worth supporting — perhaps a constrained radio transport
   where MTU is too small for a 64-byte signature — the question is whether
   to relax the Required affordance, define a compact-signature variant, or
   accept that the transport is out of scope for full-trust peer exchanges.

5. **A Forbidden affordance is proposed for relaxation.** If someone proposes
   "allow the substrate to cache and re-emit peer receipts in a combined
   bundle for bandwidth efficiency," this doc is what the proposal must
   justify against. The default answer is no; justification must advance at
   least one of the four claims without weakening any other.

6. **Claim 2 mechanism evolves.** If the AuditChallenge → AuditResponse →
   PeerAuditAttestation protocol changes shape — different hash structure,
   different response format, Merkle-based compact proofs — Required #7
   (honor the peer chain query protocol) should be updated to name the new
   shape and its verification semantics.

7. **A new principle is added to Architecture Part V½.** Each new principle
   may reclassify existing Optional affordances as Forbidden or make Required
   affordances more specific.

---

## 9. Refs

- `docs/rfc-mesh-inbound-auth-v1.md` — the inbound authentication RFC;
  the immediate source for Required #2 (inbound signature verification) and
  the graduated policy table that distinguishes full-trust, unverified, and
  unsigned payloads
- `docs/SUBSTRATE-CONFORMANCE-CONTRACT-2026-06.md` — the hub contract;
  §4 Tier 9 entry ("Cross-substrate peer tier"); §5 contract template;
  §6 integration patterns (verify-by-re-derivation)
- `docs/EDGE-TIER-CONTRACT-2026-06.md` — the template exemplar; the edge-
  tier contract whose §1 "what this doc closes" and Forbidden category
  structure this doc follows; also the adjacent tier whose distinction from
  the peer tier is named in §1 above
- `docs/ARCHITECTURE-2026-04.md` Part I §2 — the four claims; Claim 2
  (present state compresses full history via AuditChallenge → AuditResponse
  → PeerAuditAttestation) is the structural load the peer tier carries
- `docs/ARCHITECTURE-2026-04.md` Part V½ — the eight design principles;
  P1, P2, P3, P5, P7 are the primary sources for the affordance partition
- `docs/audit-invariant.md` — the one-chain-per-operator invariant;
  directly cited in Forbidden #7's reasoning
- `docs/audit-architecture.md` — the single-ownership diagram for the
  audit chain; the structural context for why peer chain merging is
  forbidden
- `docs/SINGULAR-SOVEREIGN-ROOT-2026-05.md` — the sovereign root tier
  contract; the `derive-not-replicate` pattern cited in Forbidden #4
- `docs/handoffs/delegation-lifecycle-2026-06.md` — cross-substrate
  delegation context; the lifecycle model that Forbidden #5 (no auto-
  acceptance) and Required #8 (reject widening grants) extend to the peer
  boundary
- `crates/zp-mesh` — the reference implementation; `MeshIdentity`,
  `NodeRegistry`, `CompactReceipt`, `CompactDelegation`, `MeshEnvelope`,
  `MeshStore`, `Libp2pInterface` are the current expressions of the
  Required affordances
