# Decentralized Transport as Substrate Implementation — Opportunity Mapping

**Document type:** Design intent / opportunity mapping. **Not** a Tier 2 canonical elaboration — it elaborates no KEEL section. It is an outside-in framing that asks where a serverless peer-to-peer network can sit *underneath* substrate contracts that already exist, and which substrate concerns must never move into it. Per A1, the negative test applies: no KEEL section is named as an elaboration target, so this is an opportunity mapping.

**Date:** 2026-07-27.

**Source:** Freenet (`freenet.org`, fetched 2026-07-27) and Ian Clarke's update talk hosted by FUTO (`youtu.be/3RBNboYUlVI`, 2026-07). Structured capture at `docs/mindmaps/freenet-no-servers-clarke-2026-07.json`. Freenet's own claims: *"Peers form a small-world network organized by location on a ring… no servers required"*; apps *"can't be taken down, don't track you, and run peer-to-peer, not on the cloud."*

**Attribution:** Freenet's architecture — contracts as WASM-governed shared state, delegates as local private state, Renegade k-NN routing — is Clarke's. The substrate mapping, the contract-by-contract reconciliation, the collisions, and the open positions are the ZeroPoint reading, drafted by Claude at the operator's request; the design decisions are Ken's. Where the two frames disagree, this document says so rather than harmonizing.

**Composes with:** `TRANSPORT-ABSTRACTION-AND-CONSTRAINED-NETWORKS-2026-07.md` (**added 2026-07-27 after it was missed on first authoring** — its message transport contract is the governing abstraction this whole mapping was written as though the corpus lacked; see the correction note below), `STORAGE-TIER-CONTRACT-2026-06.md` (§5 Forbidden #10 is the constraint that decides most of this question, and §4 Replication is the aperture it leaves open), `CROSS-SUBSTRATE-PEER-CONTRACT-2026-06.md` (the transport-agnostic peer tier a P2P network would carry, and the Forbidden list that bounds what any transport may do with content), `EXTERNAL-ANCHOR-TIER-CONTRACT-2026-06.md` (the corpus's existing, constrained answer to "publish to a third-party network" — and the refusal any artifact-publication idea collides with), `DISCOVERY-AND-BOOTSTRAP-2026-07.md` (the discovery stance, and the Non-goal that names the gap this lens is about), `MULTI-DEVICE-OPERATION-2026-07.md` Part V (the device-sync semantics a transport would carry), `QUARANTINE-PLANE-2026-07.md` (the admission ceremony any peer binary passes through), `EXTENSION-SURFACE-2026-07.md` (the capability vocabulary that turns out not to cover this shape), `CHAIN-READ-CANARY-DISCIPLINE-2026-07.md` (the detection discipline whose Non-goals name the slot a no-ack transport would need filled), `DEPENDENCY-POSTURE.md` (the `libp2p` entry, which already states the dual-path rule this document generalizes), `BACKUP-AND-RECOVERY-LANDSCAPE-2026-07.md` (Option 13 peer replication, named but undecided), `LENS-DISCIPLINE-2026-07.md` (this document's canonical form).

---

## Formal lens declaration

Per `LENS-DISCIPLINE-2026-07.md`, this document declares the following lens as its first-class canonical form. The mapping below elaborates the declaration.

- **`lens_id`**: `decentralized_transport`
- **`focus`**: whether and where a serverless peer-to-peer network can serve as an implementation beneath an existing substrate contract — and which substrate concerns must structurally never move into one
- **`dimensions`**: transport, replication, discovery, availability, censorship-resistance, content addressing, admission ceremony, observation footprint, metadata disclosure, delivery evidence, dependency posture, authority boundary
- **`keyword_composition`**: [peer-to-peer, overlay, mesh, relay, DHT, transport, replication, sync, mirror, bootstrap, rendezvous, availability, takedown, censorship, no-servers, content-addressed, gossip, where does this live, who serves this]
- **`transformation_question`**: *"is this a transport concern or an authority concern — and if transport, which existing contract already owns it?"*
- **`cross_references`**: `STORAGE-TIER-CONTRACT-2026-06.md` §4–§5, `CROSS-SUBSTRATE-PEER-CONTRACT-2026-06.md` §1, §5, §7, `EXTERNAL-ANCHOR-TIER-CONTRACT-2026-06.md` §3, §5, `DISCOVERY-AND-BOOTSTRAP-2026-07.md` Non-goals, `MULTI-DEVICE-OPERATION-2026-07.md` §5.2, §5.5, `QUARANTINE-PLANE-2026-07.md`, `EXTENSION-SURFACE-2026-07.md`, `CHAIN-READ-CANARY-DISCIPLINE-2026-07.md` Non-goals, `DEPENDENCY-POSTURE.md`, KEEL §II.13 P3 / P5 / P7 / P8, §III.18 delegable safety, §III.19 detectability, §III.24 aligned blindness, Part XIV Substrate Form

When chain-anchored as a `lens:declared:decentralized_transport` receipt, invocation semantics follow the lens discipline: any work context matching the keyword composition triggers a `lens:applied:decentralized_transport:<invocation_id>` receipt. The lens is directional **outside-in** (external network architecture → substrate composition). Silence over a long observer window means the substrate has stopped asking where its bytes live and is answering the question by habit — the specific drift this lens exists to catch, because transport decisions are usually made implicitly, at the moment a wire is first drawn, and never revisited.

`lens:composed:decentralized_transport:ai_landscape` is the expected edge — both lenses fire on the question of what infrastructure the substrate is willing to depend on, from different directions.

---

## Framing

**1. The two theses are opposites, and that is exactly why they compose.** Freenet's proudest property is the *removal* of a seat of authority. Clarke states it plainly: *"somebody could put a gun to my head and demand that I remove something from Freenet and I simply wouldn't have the ability to do it."* ZeroPoint's entire discipline is the *construction* of authority — P9, the system acts and the operator signs, and a chain that exists so "who authorized this" has a cryptographic answer. These are not competing designs; they are answers to different questions. They compose cleanly if and only if authority never moves into the transport and transport never moves into the chain. The moment either leaks, the substrate has two reasonable models over one surface — the failure mode already canonized as *when two reasonable architectural models conflict over the same surface, half-state is the failure mode*.

**2. The corpus already contains both the aperture and the refusal, and neither was written with Freenet in mind.** `STORAGE-TIER-CONTRACT-2026-06.md` §5 Forbidden #10 is the sharpest sentence in the corpus on this question:

> *"Storage backends that do not provide serializable atomic-append semantics — because they are eventually consistent, because they allow concurrent writers without serialization, or because they have no concept of transaction isolation — are not conformant for hosting the canonical chain. Replication to eventually-consistent replicas is permitted (Optional #3) provided the primary write path retains strong consistency."*

Freenet contract state is eventually consistent by construction. That single clause forecloses the canonical write path and, in the same breath, opens the replica path — §4 Replication: *"the primary chain retains single-writer semantics; replicas are read-side projections or backup artifacts, not writers."* The answer to "can Freenet hold the chain" is therefore already decided and is *no*; the answer to "can Freenet carry a replica" is already permitted and is *yes, as a non-writer*. No new invariant is needed to reach either.

**3. The corpus names this gap in its own voice.** `DISCOVERY-AND-BOOTSTRAP-2026-07.md` Non-goals contains two adjacent lines that, read together, are the reason this lens is worth declaring:

> *"**Not routing infrastructure**. Substrate uses existing internet routing; doesn't build overlay networks."*

> *"**Not censorship-resistant at the routing layer**. Using the current internet inherits its routing-layer censorship surfaces. Rendezvous signals over short-range physical channels provide some resilience; deep resistance requires additional infrastructure."*

The substrate has already declared that it will not *build* an overlay, and already declared that it therefore inherits a censorship surface it names as unsolved and needing *"additional infrastructure."* Adopting an existing overlay as one optional implementation is not the thing the first Non-goal refuses — but that reading is an interpretation, not a settled position, and it is recorded below as **Open position A** rather than assumed.

---

## Correction, 2026-07-27

This document was authored from a corpus survey that did not include `TRANSPORT-ABSTRACTION-AND-CONSTRAINED-NETWORKS-2026-07.md`, and it is wrong wherever it implies the corpus has no transport abstraction. That document is a Tier 2 canonical elaboration of KEEL §II.5, §III.20, Part VII and Part XIV; it defines a **message transport contract** with four requirements, and it was written to admit transports far more constrained than a public overlay — *"Reticulum RNS over mesh… LoRa (50-250 byte packets, minutes-to-hours latency, extreme intermittency), packet radio."*

Two consequences, both of which make the case here easier rather than harder:

- The **delivery-evidence** row below is not ownerless. The contract states *"Best-effort delivery acceptable. Transport is not required to guarantee delivery. Substrate handles retry, deduplication, and store-and-forward at the substrate layer."* The gap is that the substrate layer does not yet do this, not that no document claims it should.
- The **relay** question is already answered. Its store-and-forward discipline specifies propagation nodes — *"substrate can rely on third-party store-and-forward nodes… Substrate does not depend on propagation node integrity for content integrity (signatures verify end-to-end) but does depend on availability for eventual delivery."* That is the trust posture toward a Freenet peer, specified before Freenet was considered.

The failure was in the survey, not the reasoning: the sweep was scoped by filename guess rather than by reading the index, and a document whose title is exactly the subject was missed. Recorded here rather than silently edited, per *verify before commit*.

---

## The load-bearing structure

**The whole question reduces to one boundary: a Freenet contract may be a carrier, never a gate.**

Freenet contracts are not storage. They are shared state *plus the WASM code that decides who may change it* — Clarke: *"the contract will only allow people to add messages to the river room if those messages are cryptographically signed by an authorized member of the room."* That is an authorization engine. If substrate state lives in a contract and the contract enforces who may write it, delegation narrowing exists twice — in Rust behind the gate, and in WASM inside the contract — with two revocation stories, and Sentinel can observe only one of them. That is P8 violated at the most expensive possible layer.

The disciplined shape is to make the contract's validity rule as close to nothing as the model allows: *the signature verifies against a key the reader already trusts, and nothing else*. Authority stays in the chain; the contract carries bytes. This wastes most of what Freenet's contract model offers, and that is the correct trade — a carrier with a degenerate validity rule stays a carrier under adversarial conditions, and a gate written twice does not stay identical to itself.

Every row in the mapping below is a consequence of that one boundary.

---

## The core mapping

Classification: **Fits** (an existing contract already admits this shape, no new invariant needed) · **Needs vocabulary** (the shape is not forbidden, but no contract describes it) · **Collides** (an existing Forbidden clause or Non-goal applies) · **Refused** (structurally excluded, and correctly so).

| Substrate concern | Owning contract | Freenet's shape | Status |
|---|---|---|---|
| Canonical chain writes | Storage tier §5 | Eventually consistent, multi-writer contract state | **Refused** — Forbidden #10 is explicit and correct; nothing to negotiate |
| Chain replica / mirror for recovery | Storage tier §4 Optional | Content-addressed contract holding encrypted receipt blobs | **Fits** — "replicas are read-side projections or backup artifacts, not writers" is the exact slot |
| Device-to-device sync transport | `MULTI-DEVICE-OPERATION` §5.5 | Small-world routed message delivery | **Fits** — the doc already specifies a carrier mesh; this is one candidate carrier, not a new mechanism |
| Sovereign-to-sovereign messaging | Cross-substrate peer tier §1 | Same | **Fits** — the tier is already transport-agnostic and already names a `libp2p` adapter and Reticulum as conformant substrates |
| Discovery / bootstrap | `DISCOVERY-AND-BOOTSTRAP` | Rendezvous via a well-known contract | **Needs vocabulary** — the five specified layers are all internet/social; a sixth via overlay is not described and not refused. See Open position A |
| External anchoring | External anchor tier §5 | Publishing to a public network | **Collides** — Forbidden #5 permits only the compact commitment across that boundary; a Freenet backend would be a sixth commitment target at most, never a content store |
| Signed artifact publication | `ARTIFACT-LIBRARY-2026-05.md` | Content-addressed contract, fetchable by third parties | **Collides, arguably** — artifacts are operator-signed derived content, not receipt bodies, but the anchor tier's confidentiality logic reaches them. See Open position B |
| Authorization / delegation narrowing | Gate, chain | Contract-embedded WASM authorization | **Refused** — the load-bearing boundary above; a second gate is the collision |
| Private key custody | Vault, sovereign root | Delegates: local WASM state that signs on request | **Refused as a substitute** — architecturally similar, but no hardware anchor, no Genesis lineage, no M-of-N recovery. Adopting delegates as a vault would fracture the singular sovereign root |
| Message carriage generally | `TRANSPORT-ABSTRACTION` §"message transport contract" | Message-oriented, content-addressed, best-effort | **Fits** — all four contract requirements satisfied; see the conformance table in `FREENET-TRANSPORT-CONFORMANCE-2026-07.md` |
| Delivery evidence | `TRANSPORT-ABSTRACTION` §"store-and-forward discipline" | Best-effort adaptive routing, no acknowledgement | **Fits the spec, not the code** — the contract accepts best-effort because *"Substrate handles retry, deduplication, and store-and-forward at the substrate layer"*; that substrate layer is unbuilt. See the correction above and DT4 |
| Observation of relayed bytes | Observation plane, §III.24 | Peer stores and forwards content the host cannot inspect | **Needs vocabulary** — see DT5; this is the finding with the least prior art |
| Admission of the peer binary | Quarantine plane | A WASM/native executable artifact | **Fits** — executable surface, `delegation:admit:executable:<content_hash>`, operator ceremony, asymmetric revocation. Nothing new required |

---

## Where it composes

**P5 is the strongest fit, and it is not an analogy.** *Store-and-forward is primary* is the principle; Freenet is literally a store-and-forward network. `MULTI-DEVICE-OPERATION-2026-07.md` §5.5 already specifies that device sync rides a mesh when devices are not co-located, and §5.4 already accepts the consistency model that implies: *"The chain is not strictly totally ordered across devices, but every fork produces a merge receipt that documents the reconciliation."* A transport that delivers eventually, out of order, with no central rendezvous, is not a compromise against that design — it is the design's assumed environment.

**P7 makes the untrusted transport a non-issue.** *Contact does not commit.* A signed receipt is self-authenticating in transit; it does not matter that the carrier is a network of strangers, because nothing the carrier does can cause a commit. This is the property that makes the whole idea tractable, and it is worth stating explicitly because the instinct on first encounter is to worry about trusting the network. The substrate never trusts the network. It never has.

**P3 alignment is real and rare.** *There is no center* is Freenet's engineering thesis, not just its marketing. Most systems that describe themselves as decentralized still derive trust state from a coordinator; this one derives it locally, and its author's proudest property is his own inability to intervene.

**The dependency rule already exists and already says the right thing.** `DEPENDENCY-POSTURE.md` catalogues `libp2p` at Tier 2 and states the mitigation as a general rule: *"Architecture commits to Reticulum alongside libp2p as a parallel mesh transport option… This is the right hedge — preserve it. Neither transport should become the only path."* Its status line is equally load-bearing: *"Hedged architecturally; not yet hedged in code."* Freenet enters as a third option behind the same rule, or it does not enter.

---

## Where it collides

**External anchoring is already answered, and the answer is not this.** `EXTERNAL-ANCHOR-TIER-CONTRACT-2026-06.md` §5 Forbidden #5 is unambiguous: *"Receipt bodies, actor identifiers, claim types, policy decisions, delegation grants, and any other governed chain content must not be published to the external ledger."* Any framing of Freenet as "somewhere to put the chain" collides with this directly. The compact-commitment design exists precisely so that a chain containing sensitive governance decisions can be anchored without disclosing them, and a content-addressed P2P store is the opposite shape.

**A peer's entries never merge.** Cross-substrate peer tier §5 Forbidden #7: *"The substrate must not append a peer's receipt entries into the local `audit_entries` table as if they were local receipts — not as a performance optimization, not as a replication strategy, not as a 'unified view.'"* A shared contract that many sovereigns write to invites exactly this, and the refusal predates the temptation.

**Metadata is disclosed by construction, and Clarke says so.** He is admirably direct that room existence, message timing, approximate size and member count all leak. Translated: a chain replica published to a global network discloses the *shape* of the operator's activity — when they act, how often, in what volume — even with every byte encrypted. For a substrate whose thesis is sovereignty, that is a Form-level or delegation-level disclosure, not a default. It belongs with the §III.24 tiering, not in a config file.

---

## Frictions expected empirically

**No delivery receipt.** Renegade is best-effort adaptive routing; a request that fails to find a contract is indistinguishable from one that was never published. Against §III.19 — *silence is the enemy, not compromise* — that is the single most consequential property in this document. The canary discipline is the natural home for detection and explicitly declines the job: *"Not for external chains. Canary discipline verifies substrate-internal read paths. Peer-substrate chain reads have their own verification per peer-verification contract."* The peer-verification path is named there, and cross-Form canary is recorded as deferred. So the slot exists, is named, and is empty.

**The extension vocabulary does not describe this shape.** `EXTENSION-SURFACE-2026-07.md` declares network capability as egress only — *"Explicit endpoints, not 'network access'. Egress declarations name hosts and ports. Substrate can enforce at the network layer."* There is no ingress, listen, or bind field, and no capability category for holding third-party opaque bytes. A Freenet peer is precisely a long-running listener that stores and relays content the operator cannot inspect. This is not forbidden; it is undescribed, and undescribed is worse, because admission ceremony has nothing to put in the manifest.

**The Form question is unanswered.** Part XIV constrains observation reach per Form and, as far as this reading found, says nothing about inbound network posture. Whether a Companion-Form substrate — where the vendor holds the trust root — may run a relay at all is a question the Form spec does not currently answer.

**Maturity.** One full-time developer, two part-time, a young network, apps at alpha or pre-alpha by the author's own account. Fine to build against under the dual-path rule; not fine as a sole path for anything load-bearing. This is a statement about calendar risk, not about design quality.

---

## Verifiable outcomes (DT)

- **DT1** — A chain replica published through an external transport is fetchable and verifies against the operator's Genesis pubkey on a second device, with no substrate-operated server anywhere in the path.
- **DT2** — The transport is registered as one implementation among at least two behind whichever contract it serves, per the `DEPENDENCY-POSTURE` dual-path rule; no code path treats it as the only route.
- **DT3** — No contract, wire, or manifest grants the external network any authorization role. The validity rule on any published unit is signature verification alone, and this is checkable by reading the published unit.
- **DT4** — Publication and retrieval both emit chain-anchored evidence, such that a silent failure to propagate is detectable within a bounded window rather than discovered on next read.
- **DT5** — Any component that stores or relays third-party bytes declares that fact in its manifest, in a capability category that exists, and is admitted only by operator ceremony carrying that declaration.
- **DT6** — Metadata disclosed by publication — cadence, volume, existence — is enumerated in the delegation the operator signs, not discovered afterward.
- **DT7** — Disabling the transport entirely degrades availability and nothing else: no chain operation blocks, fails, or changes outcome.

---

## Minimum slice

**m0 adds no new substrate behavior and no new receipt type.** Export one already-signed artifact through the existing portable-export path, publish that byte-identical artifact as a single content-addressed unit on an external transport, and fetch and verify it from ARTEMIS. Nothing writes to the chain that does not already write to the chain; the transport is exercised entirely outside the substrate's own boundaries, which is what makes the slice cheap and reversible.

What m0 measures is deliberately narrow: does the signature survive a carrier the substrate does not control, and — the actually interesting question — how long does the absence of a delivery acknowledgement take to become a problem. DT4 is the outcome most likely to fail first, and failing it early on a throwaway artifact is worth more than any amount of further reasoning about it.

m0 is explicitly not a decision to adopt. It is instrumentation before remediation, per A8.

---

## Alternatives considered (tie-offs)

- **Adopt Freenet contracts as the substrate's shared-state primitive.** *Disposition: rejected.* Contracts carry their own authorization code, which makes a second gate; see the load-bearing structure. Reopens if a contract model appears whose validity rule can be pinned to signature-verification-only in a way the network enforces structurally rather than by convention.
- **Use delegates as the vault, or as a Companion-Form vault fallback.** *Disposition: rejected.* No hardware anchor, no Genesis lineage, no M-of-N recovery; adopting it fractures the singular sovereign root into two secrets with two freshness stories. Reopens if delegates gain a hardware-token binding.
- **Freenet as an external-anchor backend.** *Disposition: deferred, weak fit.* The anchor tier wants a witness that timestamps a hash — its six enumerated backends are notary and transparency-log shaped. A content-addressed store can hold a commitment but adds no independent timestamp authority, which is the property being purchased. Reopens if anchoring requirements ever widen from "timestamped witness" to "durable retrievable commitment."
- **Build the overlay ourselves rather than adopt one.** *Disposition: rejected on standing Non-goal* — *"Substrate uses existing internet routing; doesn't build overlay networks."* Recorded here because the censorship-resistance gap creates recurring pressure toward it, and the Non-goal should be the thing that answers, not each author's judgment in the moment.
- **Do nothing; treat the censorship-resistance gap as accepted.** *Disposition: live, and the honest default.* The gap is already named and already survived. Reopens on any concrete availability failure the current discovery layers cannot route around.

---

## Open positions

- **A — Does adopting an existing overlay violate the "not routing infrastructure" Non-goal?** ~~The Non-goal's wording refuses *building*; adopting is arguably outside it.~~ **RESOLVED 2026-07-27, operator ruling: no.** The Non-goal refuses *building* overlay networks; adopting an existing one as one implementation among several is outside it, and the adjacent Non-goal's *"deep resistance requires additional infrastructure"* names the gap such an adoption addresses. Freenet is targeted as a compatible transport on the same terms as Reticulum and libp2p — behind an existing trait, feature-gated, never the only path. Conformance surface, preconditions and minimum slice at `FREENET-TRANSPORT-CONFORMANCE-2026-07.md`. Positions B–F below survive the resolution and are unaffected.
- **B — Does the anchor tier's content-publication refusal reach signed artifacts?** Forbidden #5 enumerates receipt bodies, actor identifiers, claim types, policy decisions and delegation grants. A signed artifact is derived, operator-authored content — arguably not in that list, arguably within its intent. *Resolution: a ruling on whether artifact publication is governed by the anchor tier at all or belongs to `ARTIFACT-LIBRARY` with its own disclosure discipline.*
- **C — What capability category describes holding third-party opaque bytes?** The extension surface has egress endpoints and filesystem scopes, and no vocabulary for a listener that relays content the operator cannot inspect. *Resolution: either a new capability category in `EXTENSION-SURFACE`, or an explicit finding that such components are not extensions and are admitted by a different ceremony.*
- **D — Which Forms may run an inbound relay?** Part XIV constrains observation reach per Form and appears silent on inbound network posture. *Resolution: an addition to the Form matrix, or an explicit statement that inbound posture is Form-independent and governed by delegation alone.*
- **E — Who owns delivery evidence for a no-ack transport?** Canary discipline scopes itself out and names the peer-verification contract as the home; cross-Form canary is deferred there. **Amended 2026-07-27 after a read of `crates/zp-mesh/`:** this is not a property a new transport would introduce. `Interface::send` returns `MeshResult<()>` meaning the local interface accepted the bytes; `send_on_interfaces` returns `Ok(())` if any one interface accepted; no trait method distinguishes *sent* from *delivered*, and no retry or per-send timeout exists at either trait level. The substrate's transport layer is already best-effort fire-and-forget. The position stands but is substrate-wide and pre-existing, not a Freenet precondition. *Resolution: whichever document lands the peer-verification implementation takes the slot, or a separate transport-liveness discipline is declared.*
- **F — Is aligned blindness satisfied or strained by relaying opaque bytes?** Relaying content the substrate cannot see is, on one reading, §III.24 done correctly — the substrate cannot be responsible for what it structurally cannot observe. On another, it puts unaccounted bytes on the host and fails the lsof test, where every listening process and stored artifact should trace to a receipt or be explicitly out of scope. *Resolution: a §III.24 reading recorded against this specific case; the two readings cannot both stand.*

---

## What is specified vs. what is shipped

Per A11, and stated plainly because this document is otherwise easy to read as an inventory:

- **Nothing in this document is shipped.** No Freenet integration exists in `crates/`, and this reading did not check `crates/` at all — the corpus survey behind this document read `docs/` only, and any claim here about substrate behavior is a claim about a *specification*.
- The contracts cited — storage tier, peer tier, anchor tier — are contracts. This document does not assert their implementation status either way.
- `MULTI-DEVICE-OPERATION-2026-07.md` self-declares as *"Design note. Ready for iteration; many open decisions marked,"* so the device-sync mechanism this document treats as the natural carrier consumer is itself specified and not shipped.
- `BACKUP-AND-RECOVERY-LANDSCAPE-2026-07.md` Option 13 (peer chain replication) is named in an explicitly non-decisional survey — *"menu before ordering"* — and no follow-on decision note selecting it was found.
- The `DEPENDENCY-POSTURE` dual-path rule for mesh transports is *"Hedged architecturally; not yet hedged in code."*

---

## Non-goals

- **Not a recommendation to adopt Freenet.** This is a mapping of where a shape could sit and what it would collide with. Open position A gates everything.
- **Not an availability strategy.** Nothing here improves durability of the canonical chain; the canonical chain's durability is the backup-and-recovery landscape's subject and stays there.
- **Not a censorship-resistance claim.** The substrate's routing-layer exposure is named in `DISCOVERY-AND-BOOTSTRAP` Non-goals and this document does not close it. A candidate carrier is not a solved surface.
- **Not about anonymity.** Freenet's design intent includes properties the substrate does not want and could not use: a Genesis-signed receipt identifies its operator by construction, and that is the point.
- **Not a critique of Freenet.** Its trust model ends at transparency because it was built to remove authority, not to establish it. That is a coherent design for its own goal, and the divergence is what makes the two composable rather than redundant.
