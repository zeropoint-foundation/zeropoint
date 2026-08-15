# Substrate Conformance Contract — 2026-06

*Dated 2026-06. This is the hub. Any ZeroPoint implementation conforms
to this contract; per-tier spoke contracts specify details for individual
integration surfaces. The contract is runtime-neutral and
implementation-plural.*

*Updates to this doc are architectural acts and should be treated as
such — not edited casually.*

*Indexed 2026-08-14 as Tier 2 (Meta-discipline). It had never appeared in
`CANONICAL-CORPUS-INDEX-2026-07.md` and therefore fell under the Tier-3
catch-all — "read as historical unless explicitly reclassified" — which
contradicted the hub status this header declares and would have made the
2026-08-14 external-falsifier note an amendment to a frozen document.
Resolved in favour of the header. Owed: an explicit declaration of which
KEEL sections this contract elaborates, since it predates the July 2026
KEEL declaration; and a reconciliation of its "eight principles" with
KEEL's nine.*

---

## 1. What this doc is

The Substrate Conformance Contract is the foundational reference for
ZeroPoint's per-tier contract architecture. It names every integration
surface the substrate exposes, states the structural template that each
surface's contract follows, and points at the spoke document where each
surface's Required / Optional / Forbidden partition lives. It does not
inline those partitions. This doc is the map; the spokes are the terrain.

`docs/SURFACE-BOUNDARIES-2026-05.md` is the sibling document at the
surface-layer slice — it names and pins the specific named surfaces
(Core ZP, ZP Console, ZP Surface Spec, Cockpit, foundation Console,
public site) and their dependency arrows. This doc is the meta-level
analog: rather than naming the surfaces around the substrate, it names
the substrate's own integration tiers and establishes the contract shape
that governs each. The two documents are peers, not duplicates. Where
SURFACE-BOUNDARIES says "these are the named concepts and their
dependency direction," this doc says "these are the integration seams
and the structural commitments each seam carries."

The contract template was established empirically by
`docs/EDGE-TIER-CONTRACT-2026-06.md`, which partitioned the foundation
worker's affordances into Required, Optional, and Forbidden categories,
explained the composition with architectural principles, and established
the autoregressive update structure. That document remains the template
exemplar. This hub generalizes the template to the substrate as a whole
and establishes the vocabulary that every spoke inherits.

---

## 2. The substrate identity statement

ZeroPoint is an autorecursive trust substrate: a Rust-implemented
protocol layer in which every action is a step in a hash-linked, signed,
replayable derivation, and the derivation is well-formed if and only if
it parses against a fixed grammar of constitutional, delegation, and
continuity invariants. That sentence is the substrate's load-bearing
identity. Each clause is structural, not descriptive.

The grammar reframe matters for implementers. Verification in ZeroPoint
is re-derivation, not checking. The verifier does not ask "is this state
valid?" It asks "can I re-derive this state from the productions,
starting from Genesis?" A chain is well-formed iff all three modal
layers — Required (constitutional invariants), Possible (delegation
envelope), Actual (the hash-linked receipt sequence) — agree at every
step. This is what makes O(n) chain walking not overhead but
architecture: the verification walk *is* the proof.

The cockpit-OS framing in Architecture §4b completes the picture for
runtime implementers. ZeroPoint is the operator's runtime for coherent
agent authority. Each cockpit — CLI, conversational agent, visual panel —
is a pure projection of chain-anchored state into a native interaction
mode, not a seat of authority unto itself. The chain decides what the
operator can currently do; the cockpit renders that decision as flags,
tools, buttons, or affordances. Affordances appear when the chain grants
them and disappear when the chain withdraws them. This is not a UX
convention; it is a structural commitment. A cockpit that maintains its
own authority claims has drifted from the substrate's identity.

An implementer reading cold needs to hold these three things together:
the substrate is a grammar (verified by re-derivation); the operator's
Genesis key is the root from which all authority is derived (no central
authority, no remote truth server); and every surface that presents
operator capabilities must project the chain, not add to it.

---

## 3. The four claims and eight principles

### The four claims

These are the substrate's acceptance criteria. Any implementation should
move at least one claim closer to empirically true with each meaningful
phase of work. Claims are falsifiable propositions, not aspirations —
each has a named falsifier.

**Claim 1 — Each step is conditioned on all prior context.**
Mechanism: `pr` linkage, Blake3 transitivity. Falsifier: any receipt
whose `pr` does not point to the previous receipt's `id`. Currently
true after the transactional-append fix (AUDIT-01).

**Claim 2 — Present state compresses full history.**
Mechanism: collective audit (AuditChallenge → AuditResponse →
PeerAuditAttestation). Falsifier: a peer claiming a state that does not
match its full chain. Currently: mechanism exists; not yet load-tested
against adversarial peers.

**Claim 3 — System-wide coherence from local evaluation.**
Mechanism: PolicyEngine fixed evaluation order, constitutional rules at
positions 1 and 2. Falsifier: any side effect that did not pass through
P3 (the gate). Currently true after the EXEC-01..04 gate-enforcement
fix.

**Claim 4 — Future actions narrowed by trajectory.**
Mechanism: the eight delegation invariants in `DelegationChain::verify()`.
Falsifier: a delegation chain that widens authority anywhere along its
length. Currently believed to hold; not yet adversarially tested under
full delegation pressure.

**External falsifier vocabulary (added 2026-08-14).**
`draft-reece-wimse-cross-org-delegation` — an IETF **individual**
Internet-Draft, -00 published 22 June 2026, marked on its own face as
not endorsed by the IETF and carrying no standards standing — states
nine requirements for cross-organisational agent delegation and
explicitly declines to specify a solution. Four are this section's
discipline written by someone with no knowledge of ZeroPoint, which is
worth more than an internally-authored falsifier because it lets Claims
2 and 4 be scored by a stranger.

- **R1** — a relying party verifies *from the conveyed authority alone*
  that no hop exceeds its predecessor. Mechanism here:
  `DelegationChain::verify()` walks parent-link, depth increment, depth
  ceiling, grantor-equals-parent's-grantee,
  `parent.capability.contains(child.capability)`, and lease
  non-escalation. ZP passes on its face. One subtlety worth carrying
  rather than glossing: ZP verifies with the **whole chain in hand**,
  where R1 asks what a relying party can verify **from the credential it
  was handed**. Same property, different possession assumption — and the
  difference is what an offline third-party verifier meets first.
- **R3** — an authorization decision without a synchronous call to the
  originating organization on the critical path. ZP is structurally
  stronger: there is no originating organization.
- **R7** — revocation verifiable offline and **whose staleness is
  bounded**, so a relying party can fail safe. Revocation here is
  chain-anchored and offline-verifiable; *bounded staleness under
  partition* is not specified anywhere the corpus currently reaches.
  **Treat R7 as the open one.**
- **R8** — each participant's record resistant to undetectable
  alteration, the records composing into an end-to-end account of an
  action's provenance. This is Claim 2, whose status above is "mechanism
  exists; not yet load-tested against adversarial peers." R8 supplies
  that load test a vocabulary that did not originate here.

**Where it diverges, and why that matters more than the agreement.** R2
roots verification in another organization's trust anchor: the principal
is bound but not sovereign. The draft's §7 names substitution of a
relying party's trust root as the attack a solution must prevent, while
rooting every chain in an institution. That is the Sovereign/Companion
axis of `SUBSTRATE-FORM-2026-07` arriving at the delegation layer — see
that document's §"Trust-chain reach is stated per layer". Recording the
convergence without recording the divergence would be the misreading:
the mechanisms are converging and the root question is untouched.
Three sweeps across the WIMSE, OAuth and AIP drafts and OIDC-A have
found no draft that roots the chain in the principal's own key.

Source: `AI-LANDSCAPE-SIGNAL-2026-07.md` §"Signal 5". Read in full at
datatracker by the landscape sweep; the requirement text above is that
reading, not a re-read. Confidence is high on what the draft says and
low on what it becomes — individual drafts frequently expire without
issue, which is why nothing above is a claim change.

### The eight principles

Principles are conservation laws, not policy preferences. Every per-tier
contract derives its Required / Optional / Forbidden partition from one
or more of these. A per-tier contract entry that cannot be traced to a
principle belongs either in documentation or not at all.

**Principle 1 — Signing is gravity.**
Unsigned receipts are structurally meaningless. The receipt's
`content_hash` is the routing logic of trust; the governance gate
validates cryptographic proofs, not permissions; the reconstitution
engine replays signed evidence, not log messages. If a feature works
without signing, signing is decorative — which means the feature is not
actually governing anything.

**Principle 2 — Identity is a key, not a location.**
A tool's identity is its bead zero — the `CanonicalizedClaim` receipt
signed by the Genesis key. Not a port, not a hostname, not a service
registration. The cryptographic lineage is the identity; deployment
coordinates are ephemeral projections.

**Principle 3 — There is no center.**
Trust state is derived locally from the audit chain, never from a remote
authority. There is no DNS to hijack, no certificate authority to
compromise, no API endpoint to make authoritative. A feature that
requires phoning home to establish trust has introduced a center.

**Principle 4 — Every bit counts.**
Every field on a receipt exists because removing it would break a
verifiable claim. Every data path earns its place through cryptographic
necessity. Duplicate data paths, redundant stores, and translation layers
between representations are the failure mode this principle catches.

**Principle 5 — Store-and-forward is the primary mode.**
The chain survives outages. You do not ask "is the system healthy right
now?" You ask "what does the chain say?" Readiness state is derived from
accumulated evidence, not from a live heartbeat. An implementation that
requires live connectivity to derive trust state has made store-and-forward
a fallback, which inverts the architecture.

**Principle 6 — A tool is intent, crystallized.**
The governance gate is not a guardrail; it is the protocol. Constitutional
rules (HarmPrincipleRule, SovereigntyRule) are non-removable,
non-overridable, and evaluated first. They are conservation laws. The
claim type, the metadata structure, the signature — these are not logging
conventions but the grammar of trust. Semantics live in structure, not
in comments.

**Principle 7 — Contact does not commit.**
The receipt chain is not a log that faithfully records everything that
happens. It is the substrate's own account of what it chose to commit
to. Adaptive use of existing capabilities produces a signed receipt on
an existing wire. Creation of new operational capabilities produces an
unsigned artifact held in quarantine, signed only after operator review.
The substrate decides what the system is allowed to become because of
contact; it does not transcribe contact as governance.

**Principle 8 — One canonical path per substrate concern.**
Every substrate concern resolves through exactly one canonical
implementation. Multiple paths for the same concern produce half-state:
the failure mode where two reasonable approaches drift apart and the
substrate breaks differently every restart. The singular sovereign root,
the canonical audit chain, the PortRegistry, the verb set — each of
these exists because a previous multi-path implementation surfaced this
failure mode empirically.

### Bidirectional implication

The principles constrain implementations: any affordance that would
require violating a principle is Forbidden, not Optional. The four claims
are what implementations make testable: each claim's falsifier names a
specific structural condition that running code can either exhibit or
prevent. The relationship between the two sets is not parallel but
causal. Principles determine what implementations may be; claims measure
whether those implementations are working.

---

## 4. The tier taxonomy

Each integration tier has one contract. The contract follows the template
in §5. Where a spoke exists, it is the authoritative document for that
tier's partition. Where a spoke is partial or absent, the hub's principles
and claims fill the gap until the spoke is written.

The tier list is ordered from outermost (closest to external network) to
innermost (implementation integrity), reflecting the flow of trust through
the substrate.

---

**1. Edge tier**
*The outward-facing gateway, proxy, or CDN integration point that
authenticates, routes, and forwards external traffic to operator
substrates without holding policy authority.*
Spoke: `docs/EDGE-TIER-CONTRACT-2026-06.md` — complete.
Conformance looks like: all Required affordances present, no Forbidden
affordances exercised, with Cloudflare Workers as the reference
implementation and alternative runtimes (Bun, Fastly, self-hosted Rust)
conforming to the same contract.

---

**2. Operator substrate tier**
*The canonical Rust core — chain, gate, receipts, verbs, policy engine,
vault, and audit. The thing all other tiers compose with.*
Spoke: `docs/OPERATOR-SUBSTRATE-CONTRACT-2026-06.md` (complete —
partitions seven sub-layers: chain, receipt, verb-set, gate, policy,
identity binding, surface; affordance pass at
`docs/handoffs/operator-substrate-affordance-pass-2026-06.md` is the
architectural-decisions source). Implementation across `crates/zp-server`,
`crates/zp-core`, `crates/zp-policy`, `crates/zp-gate-envelope`,
`crates/zp-receipt`, `crates/zp-audit`, `crates/zp-verbs`,
`crates/zp-keys`. The four claims and eight principles remain the
load-bearing structural backbone the contract formalizes.
Conformance looks like: all four claims empirically true, all eight
principles enforced by the type system or by discipline pins with CI
enforcement.

---

**3. Console tier**
*The operator workspace shell — navigation, tile renderer, cockpit slot,
chain visualization. The reference surface through which the operator
reads and acts on chain-anchored state.*
Spoke: `docs/CONSOLE-CONFORMANCE-CONTRACT-2026-06.md` (complete);
`docs/SURFACE-BOUNDARIES-2026-05.md` for the broader surface taxonomy
and dependency direction.
Conformance looks like: Console is a pure projection of chain state into
a workspace surface; it holds no authority not present in the chain; it
decomposes cleanly from the substrate and can be replaced by any
implementation that conforms to the ZP Surface Spec.

---

**4. Cockpit tier**
*The pluggable conversational agent that integrates with ZP Console via
the ZP Surface Spec. The foundation runs IronClaw; adopters may run
Ember, KiloCode, Agent Zero, or any cockpit that implements the Surface
Spec.*
Spoke: `docs/ZP-SURFACE-SPEC-2026-06.md` (complete — the contract form);
`docs/SURFACE-BOUNDARIES-2026-05.md` for the broader surface taxonomy.
The versioned protocol-level spec (event wire format, lifecycle message
shapes, capability declaration schema) is downstream work — the contract
names what the protocol must commit to; the protocol spec names the
bits. Console tier and Cockpit tier are adjacent peers, not nested:
Console provides the slot; the Cockpit fills it; the ZP Surface Spec is
the contract between them.
Conformance looks like: the cockpit projects chain-anchored state into
conversational affordances; it does not hold its own authority claims;
its tool invocations produce chain receipts; its affordance set is
determined by the current chain state, not by a static capability
declaration.

---

**5. Sovereign root tier**
*Operator identity-material provisioning, holding, and use. The
ceremony by which Genesis is loaded, the derivation by which all other
secrets flow from it, and the constraint that there is exactly one
credential-store access per process lifetime.*
Spoke: `docs/SINGULAR-SOVEREIGN-ROOT-2026-05.md` — complete.
Quorum sovereignty variant (M-of-N hardware devices) in
`docs/design/quorum-sovereignty.md`.
Conformance looks like: one canonical `load_sovereign_root()` call site
per process, the `singular_sovereign_root` discipline pin enforced in CI,
and every sovereignty provider (Touch ID, YubiKey, Trezor, file-based,
M-of-N quorum) funneling through the same consumer-facing surface.

---

**6. Agent / tool integration tier**
*What agents and tools must do to compose with the gate — receipt
emission shape, capability envelope structure, dispatch-time gate
contract, artifact-creation quarantine, and the distinction between
adaptive use of existing capabilities and creation of new ones.*
Spoke: `docs/AGENT-TOOL-CONTRACT-2026-06.md` (complete — contract form,
agent-side and tool-side affordances partitioned within each category);
`docs/design/governed-agent-runtime.md` for the broader runtime
architecture and operational deployment context. A future SCC revision
may split this into adjacent peers (Tier 6a Agent, Tier 6b Tool) if the
unified contract becomes unwieldy; the boundary is clean at the gate,
which is the coupling point.
Conformance looks like: every agent action passes through the gate before
any side effect; every tool invocation produces a receipt triple (intent
+ policy + exec); new operational capabilities (skills, memory facts,
DOM helpers) land in quarantine, not in the chain, until operator review
promotes them.

---

**7. Storage tier**
*The shape of chain persistence — the SQLite-backed audit chain, its
crash-safety invariants, the atomic-append protocol, the compaction
strategy, and the restore-from-chain guarantee.*
Spoke: `docs/STORAGE-TIER-CONTRACT-2026-06.md` (complete — flat-list
contract, 8 Required / 8 Optional / 10 Forbidden, calibrated against the
AUDIT-03 incident; affordance pass at
`docs/handoffs/storage-tier-affordance-pass-2026-06.md` is the
architectural-decisions source). `docs/audit-architecture.md` and
`docs/audit-invariant.md` carry the substantive content the contract
distills; `crates/zp-audit` is the implementation site.
Conformance looks like: the chain is self-verifying (M3, M4); atomic
append with `BEGIN IMMEDIATE` and `UNIQUE(prev_hash)`; any chain that
can be read can be re-derived from Genesis; no external store is the
authoritative source of truth.

---

**8. Verifier tier**
*Third-party chain verification — the protocol by which an entity that
is not the operator walks the chain and confirms it is well-formed
against the catalog's grammar. The verifier is a parser, not a checker.*
Spoke: `docs/VERIFIER-TIER-CONTRACT-2026-06.md` (complete — flat-list
contract, 11 Required / 10 Optional / 10 Forbidden, anchored on the
parser-not-checker framing from Architecture §4; affordance pass at
`docs/handoffs/verifier-tier-affordance-pass-2026-06.md` is the
architectural-decisions source). Named in Architecture §2 Claim 2 and
§8 Commitment B; `docs/CAPABILITY-VERIFICATION-RECEIPTS.md` is
adjacent. `crates/zp-verify` is the reference implementation of the
parser.
Conformance looks like: the verifier makes no network calls during
verification; it walks the chain from Genesis; it reports which catalog
rules pass and which fail; it emits no trust claims of its own — only
verdicts about the claims in the chain.

---

**9. Cross-substrate peer tier**
*Communication between distinct operator substrates — grant propagation,
attestation exchange, audit challenge-response, and the protocol by
which two substrates establish trust without a common authority.*
Spoke: `docs/CROSS-SUBSTRATE-PEER-CONTRACT-2026-06.md` (complete);
`docs/rfc-mesh-inbound-auth-v1.md` for the inbound auth protocol details
the contract derives from. `crates/zp-mesh` contains the transport
implementation. A future SCC revision may carve out a sub-tier for
peer policy synchronization (capability negotiation, policy sync,
consensus) — the `capability_exchange`, `policy_sync`, and consensus
modules in `crates/zp-mesh` are substantive enough that they warrant
watching for divergence from point-to-point receipt exchange.
Conformance looks like: each substrate anchors its own chain; cross-
substrate trust flows through explicitly receipted grant propagation and
audit attestation, not through shared secret material or delegated
platform authority; a newly-introduced peer cannot claim authority it
has not been explicitly granted by a chain-level receipt.

---

**10. External anchor tier**
*The substrate publishing proofs to external ground truth — public
ledgers, notaries, timestamping authorities. An enrichment, not a
dependency: the chain is self-verifying; external anchoring extends the
guarantee across organizational boundaries.*
Spoke: `docs/EXTERNAL-ANCHOR-TIER-CONTRACT-2026-06.md` (complete —
flat-list contract, 8 Required / 9 Optional / 10 Forbidden, calibrated
against Architecture §9a Commitment E's enrichment-not-dependency
commitment and explicitly named as the outbound publication mode of
the Witness-not-arbitrate integration pattern; affordance pass at
`docs/handoffs/external-anchor-tier-affordance-pass-2026-06.md` is the
architectural-decisions source). Described in Architecture §9a
(Commitment E). `crates/zp-anchor` defines the `TruthAnchor` trait,
the `AnchorCommitment`, and the `AnchorReceipt` types; `NoOpAnchor`
is the no-backend fallback that satisfies the trait-wiring affordance
without active publication.
Conformance looks like: anchoring is event-driven (six named
`AnchorTrigger` variants), never timer-driven; the anchor backend is
the choice of the operator, not a dependency; the chain's internal
integrity is never contingent on the anchor backend being reachable;
`zp-anchor`'s trait architecture makes any DLT a drop-in backend.

---

**11. Supply chain tier**
*Implementation-integrity attestation — build reproducibility, dependency
manifests, signed binaries, and public-asset subresource integrity. The
tier that makes the substrate itself verifiable, not just the chains it
produces.*
Spoke: `docs/SUPPLY-CHAIN-TIER-CONTRACT-2026-06.md` (complete —
flat-list contract, 8 Required / 9 Optional / 10 Forbidden, covers
both slices (public-asset SRI and substrate-binary supply chain) as
one coherent tier; six principles do load-bearing work — P1, P2, P3,
P4, P7, P8 — more than any other spoke; affordance pass at
`docs/handoffs/supply-chain-tier-affordance-pass-2026-06.md` is the
architectural-decisions source). `docs/SUPPLY-CHAIN-MANIFEST.md`
remains the canonical pinned-asset register for the public-asset
slice. Several Required affordances (release signing, reproducible-
build attestation, install-time verification, transparency log
participation) are currently aspirational in the implementation; the
contract names the conformance target and substrate-readiness work
brings the implementation up to the contract.
Conformance looks like: every published binary has a verifiable
provenance chain; every public asset has an SRI hash; dependency
manifests are pinned and committed; build reproducibility is tested in
CI, not assumed.

---

## 5. The contract template

Every per-tier spoke inherits this structure. The categories are not
categories of feature richness — they are categories of architectural
meaning. An implementer working from a spoke can classify any proposed
affordance in O(1) time rather than re-deriving from principles.

### a. Required affordances

What an implementation must have to serve that tier. Lacking any single
Required affordance disqualifies the implementation from serving in that
tier. Required affordances should name their fallback explicitly: what
the substrate degrades to if this tier is dropped entirely, and whether
that degradation affects correctness (it should not) or capability (it
may).

The discipline for naming Required affordances is to ask: if this is
absent, does the tier function at all? If the answer is "the tier exists
but produces incorrect results," the affordance is Required. If the
answer is "the tier exists but with reduced capability," the affordance
is Optional. If the answer is "the tier should not produce this output
regardless," the affordance is Forbidden.

### b. Optional affordances

What an implementation may or may not have. Lacking an Optional
affordance degrades capability without breaking correctness. Optional
affordances should be accompanied by an honest account of what degrades:
"without this, operators lose X" is the right shape, where X is a
specific operational property, not vague "value." Optional affordances
can graduate to Required if the substrate's correctness turns out to
depend on them.

### c. Forbidden affordances

What an implementation must not exercise even if the runtime technically
supports it. This is the architecturally interesting category.

Forbidden affordances are the things a runtime might be technically
capable of doing at a given tier — an edge worker's WebCrypto can sign,
its D1 can store chains — but doing them is the structural failure
mode for that tier. The examples are tier-scoped on purpose: ZeroPoint
*uses* WebCrypto, persistent storage, and WASM trust boundaries
elsewhere in the architecture, and the same capability that's
foundational in one tier can be forbidden in another. An implementation
that *lacks* the ability to sign canonical receipts at the edge is, in
that specific respect, more architecturally honest than one that has
the ability and must be disciplined into not using it. Lacking a
Forbidden affordance is correct posture, not degradation.

The foundation-canonical-v1 architectural correction is the canonical
empirical instance of this distinction: the edge worker *was* signing
receipts and holding chain state (both technically possible in the
runtime) and the correction was not to improve the implementation but to
eliminate those capabilities from the tier's contract entirely. The
Forbidden category exists so that "can we add X?" has an answer that
doesn't require re-deriving from principles each time.

The discipline pin `no_edge_signed_canonical_chain` (documented in
`docs/handoffs/discipline-pin-audit-2026-06.md`) is the structural
enforcement of one Forbidden line. Other Forbidden lines across all
tiers warrant similar pin coverage over time.

### d. Composition with principles

Which of the eight principles structurally justify each category boundary
for that tier. Required affordances typically trace to the principles
that name what the tier must do to be genuine (P1 for any signing-
capable tier; P3 for any tier that claims authority; P8 for any tier
that claims to be the canonical path). Forbidden affordances typically
trace to the principles that name what the tier must not appropriate
(P1 + P3 together for most edge-tier and cockpit-tier Forbidden entries).

A contract entry without a principle trace is either using the wrong
category or is documenting an operational preference rather than a
structural constraint.

### e. Portability sketches

Concrete examples of implementations against the same contract,
demonstrating runtime-neutrality. A contract that has only one plausible
implementation is either too narrowly scoped (name the implementation,
not the contract) or its Required affordances are implementation details
in disguise. The portability sketches reveal the difference.

Each sketch should name the runtime, state whether all Required
affordances are available, identify which Optional affordances are
naturally available vs. require additional work, and note any
implementation-specific considerations without relaxing the contract.

### f. Autoregressive update triggers

Conditions that should provoke a revision to the contract. The contract
is not static — it is conditioned on what the substrate has learned from
running. The standard triggers, applicable to every tier:

1. A new runtime is adopted for that tier.
2. A Required affordance proves harder than expected to implement
   portably — raising the question of whether to relax the contract or
   accept that certain runtimes are out of scope.
3. A Forbidden affordance is proposed for relaxation — the proposal
   must justify itself against the four claims without weakening any
   of them.
4. A new Optional affordance is added — and must be interrogated for
   whether it is genuinely optional or has quietly become load-bearing.
5. A new architectural principle is added to Part V½ — which may
   reclassify existing Optional affordances as Forbidden.

Affordances should move between categories only with explicit reasoning
landed in the contract. Each transition is a substrate-readiness signal
and belongs in the version record.

---

## 6. Integration patterns

Tiers compose through recurring structural patterns. These patterns
already exist in the substrate; they are named here so that future
per-tier contracts can reference them by name rather than re-deriving
them.

**Forward-not-mediate** (edge tier → operator substrate tier): the
gateway is transport, not interpretation. It authenticates, routes, and
transforms; it does not evaluate policy, produce authority claims, or
augment chain results with its own judgment. The distinction between
"do I forward this?" (the gateway's call) and "does this action pass
policy?" (the operator substrate's call) is the load-bearing seam.
Derived from EDGE-TIER-CONTRACT and Architecture §4c.

**Project-not-decide** (cockpit tier → chain): the cockpit renders
chain-anchored state; authority lives in the chain. Affordances appear
when the chain grants them and disappear when the chain withdraws them.
There is no menu cache, no static capability declaration, no cockpit-
resident authority claim. A cockpit that decides what the operator can
do has become a center. Derived from Architecture §4b and the cockpit-
projection heuristic in `CLAUDE.md`.

**Propose-not-sign** (substrate → operator artifacts): the substrate
produces candidates at scale; operators promote candidates to canonical
via signature. Cheap proposals, expensive decisions. An unsigned artifact
is a candidate; a signed artifact is an endorsement. The substrate
proposes because proposals are computational; the operator signs because
authority is sovereign. Derived from the "substrate proposes; operators
sign" heuristic in `CLAUDE.md`.

**Sign-then-act** (every tier, every privileged action): the receipt
precedes the side effect. Signing is gravity. An action that happened
in reality but not in the chain did not happen as far as the substrate
is concerned — and yet it did happen in the world. That gap is the
failure mode. Derived from Principle 1.

**Derive-not-replicate** (sovereign root tier, all tiers that use
signed material): one operator authentication ceremony per process
lifetime; every other secret is derived in memory from Genesis, not
independently stored and independently authenticated. Replication of
sovereign material across multiple credential-store entries multiplies
authentication burden linearly and weakens audit-chain authority.
Derived from `docs/SINGULAR-SOVEREIGN-ROOT-2026-05.md`.

**Verify-by-re-derivation** (verifier tier, cross-substrate peer tier):
the verifier is a parser, not a checker. It does not ask "is this state
valid?" It asks "can I re-derive this state from the productions,
starting from Genesis?" The verifier makes no network calls, holds no
authority, and emits no trust claims — only verdicts about whether the
chain is well-formed against the grammar. Derived from Architecture §4
grammar reframe.

**Witness-not-arbitrate** (substrate ↔ non-substrate boundaries): the
substrate signs its own view of any transaction with non-ZP
infrastructure — intent, gate decision, observed result, and any
counterparty attestations it can verify — without claiming authority
over what the external side is authoritative over. Three modes already
express this asymmetric coherence: outbound (a gated tool invokes an
external system; the chain anchors intent + decision + result), inbound
(the edge tier verifies external auth claims like Cloudflare Access JWTs
or OIDC tokens and converts them to canonical receipt intents), and
bilateral (both sides sign the same canonical artifact in their own
primitives; the substrate verifies and incorporates the counterparty's
signature into its receipt). The chain is honest about what crossed
from the operator's side; it does not require counterparty conformance
and does not assert facts the substrate cannot verify. This is what
makes ZeroPoint adoptable unilaterally — the operator's substrate can
integrate with the existing world without requiring the world to adopt
ZP. Derived from the asymmetric-coherence framing implicit across
`EDGE-TIER-CONTRACT-2026-06.md` (inbound conversion), `AGENT-TOOL-
CONTRACT-2026-06.md` (gated outbound action), and the External anchor
tier of this contract (outbound publication); named here so that future
"how does X integrate with non-ZP system Y?" decisions can reference
the pattern directly rather than re-deriving its shape.

**Cache-not-canon** (optional projections of canonical chain state —
derived caches, search indexes, materialized views): the chain is the
canonical source of truth; an optional cache may provide fast access
to a projection of that truth. The cache is rebuildable from canonical
records, replaceable with alternative implementations conforming to
the same interface, and gate-mediated for any operator-facing access.
Cache correctness does not affect substrate correctness — a misbehaving
cache produces degraded performance or stale projections, not
corrupted authority. The pattern lets the substrate adopt
search-optimized indexes, derived-state caches, or experimental
retrieval components (lossy compressed vector indexes, approximate-
nearest-neighbor search engines, materialized aggregates, etc.) in
carefully-bounded roles without architectural risk: nothing the cache
returns gets treated as authoritative without chain-canonical
verification; no cache operation bypasses the gate; the chain is the
source from which the cache is rebuilt whenever its contents must
change (schema migration, embedding model change, corruption,
revocation propagation). Composes with the propose-not-sign pattern
at the retrieval surface — caches propose candidates at scale; the
chain anchors any decision derived from those candidates. Surfaced
through the TurboVec adoption analysis (2026-06) as the structural
frame for incorporating an alpha-status compressed vector index under
substrate governance; generalizes to any optional cache the substrate
might choose to deploy for derived-state acceleration.

More patterns can name themselves as the empirical loop surfaces them.

---

## 7. The negative space — what ZeroPoint is not

ZeroPoint is not an agent runtime. Agents act under the substrate's
authority, not as the substrate. The Governed Agent Runtime (Architecture
§Phase 4) describes how agents run as governed tenants, with every I/O
surface mediated by the same gate machinery the substrate already uses
for tools. The substrate is the runtime for the agent's governance; it
is not the agent, and it does not inherit the agent's concerns. An
implementation that conflates substrate and agent has lost the structural
separation that makes the governance meaningful.

ZeroPoint is not a registry or a PKI. Sovereign roots are operator-held,
derived locally from Genesis, and not centrally issued. There is no
certificate authority, no registration ceremony with a platform, no
central directory of valid operators. Trust between strangers flows
through chain attestation and external anchoring, not through a common
root CA. An implementation that requires a central issuer to be reachable
in order to establish operator identity has introduced a center that the
architecture is specifically designed not to have.

ZeroPoint is not a smart-contract platform. Receipts are not contracts
in the legal or blockchain sense; the chain is not a ledger of value
transfer; constitutional rules are conservation laws about governance
structure, not executable agreements between parties. The grammar governs
what actions are well-formed; it does not adjudicate disputes, enforce
financial settlements, or manage tokenized assets. Implementations that
treat receipts as smart contracts have misread the data model.

ZeroPoint is not a SaaS. The substrate is the operator's, not the
platform's. The cockpit-OS framing in Architecture §4b is explicit: the
operator holds their own chain-anchored authority; the substrate runs on
the operator's infrastructure; verifiability flows from cryptographic
lineage rooted in the operator's Genesis key, not from a platform that
could be compromised, abandoned, or weaponized. An implementation that
routes operator authority through a platform-controlled service has
transferred sovereignty to the platform.

ZeroPoint is not a governance framework by decree. Governance is by
protocol, not by rules (whitepaper §6.1). The constitutional invariants
are enforced cryptographically, not administratively. Compliance is not
asserted by policy documents; it is demonstrated by chain derivation.
An implementation that enforces governance through configuration rather
than through structural invariants has made the governance bypassable by
anyone with filesystem access.

ZeroPoint is not an audit log. An audit log is a write-only record of
events. The receipt chain is a derivable trajectory: from Genesis, every
state is re-derivable by walking the signed, hash-linked sequence of
receipts. The distinction matters because audit logs can be selectively
appended to, can be restarted, and can be read without a validity check.
The receipt chain cannot be forked without producing a detectable
inconsistency, cannot be replayed incorrectly without signature failure,
and cannot be summarized without the summary being verifiable against the
full derivation. The chain is not a record of what happened — it is a
mathematical object from which what happened can be proven.

ZeroPoint is not a token economy. There is no native value primitive.
The substrate's value is verifiability, not exchange. Receipts carry
cryptographic proof of what was authorized; they do not carry purchasing
power, staking weight, or governance votes proportional to holdings. An
implementation that introduces a token as a governance primitive has
substituted economic incentives for cryptographic proofs, which is the
opposite of what the substrate is designed to do.

---

## Refs

In order of appearance in this document:

- `docs/EDGE-TIER-CONTRACT-2026-06.md` — the template exemplar; the
  operational complement to Architecture §4c; the empirical source of
  the Forbidden category's definition
- `docs/SURFACE-BOUNDARIES-2026-05.md` — the sibling surface-layer
  reference; named concepts and dependency direction for the surfaces
  around the substrate
- `docs/ARCHITECTURE-2026-04.md` Part I §1–§4c — the one-sentence
  statement, the four claims, the grammar reframe, the cockpit-OS
  framing, and the edge capability split
- `docs/ARCHITECTURE-2026-04.md` Part V½ — the eight design principles
  that every per-tier contract derives from
- `docs/SINGULAR-SOVEREIGN-ROOT-2026-05.md` — the complete Tier 5 spoke;
  the canonical source for the derive-not-replicate pattern
- `docs/design/quorum-sovereignty.md` — the M-of-N hardware sovereignty
  variant; extends the sovereign root tier's portability sketches
- `docs/design/governed-agent-runtime.md` — the Governed Agent Runtime
  specification; the Tier 6 spoke candidate
- `docs/SUPPLY-CHAIN-MANIFEST.md` — the partial Tier 11 spoke; currently
  covers public-site asset SRI
- `docs/whitepaper-v9.md` — the public thesis; §5 (The Governance Model —
  *"Governance in ZeroPoint is protocol, not policy. It is enforced by
  structure — evaluation order, invariant checks, cryptographic
  verification — rather than by trust in an organization"*) is the source
  for §7's governance-by-decree point. **Repointed 2026-08-14**: this cited
  `whitepaper-v2.md` §6.1, and no v2 exists — the file is v8 and v9, of
  which v9 is what the rest of the corpus cites. The section number moved
  too, so repointing to §6.1 of either extant draft would have produced a
  citation that *resolves and is wrong*, which is worse than one that
  dangles.
- `CLAUDE.md` workflow heuristics — the cockpit-projection heuristic
  (project-not-decide pattern), the propose-not-sign heuristic, and the
  singular-sovereign-root heuristic that the integration patterns
  formalize
- `crates/zp-anchor` — Tier 10 implementation; `TruthAnchor` trait,
  `AnchorCommitment`, `AnchorReceipt`, `NoOpAnchor`
- `crates/zp-verify` — Tier 8 implementation; the chain-walking parser
  that makes Claim 2 testable
- `crates/zp-mesh` — Tier 9 transport implementation; the cross-substrate
  peer protocol
