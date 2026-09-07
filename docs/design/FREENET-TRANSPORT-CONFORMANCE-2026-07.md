# Freenet as a Compatible Transport — Conformance Target

**Document type:** Design note / conformance target. **Not** a Tier 2 canonical elaboration — it elaborates no KEEL section. It elaborates a Tier 2 *contract* (`CROSS-SUBSTRATE-PEER-CONTRACT-2026-06.md`) and the shipped `zp-mesh` trait surface, which per A1 makes it a design note rather than a canonical elaboration.

**Date:** 2026-07-27.

**Decision:** Freenet is targeted as a **compatible transport**, admitted the same way Reticulum and libp2p are — one implementation among several behind an existing trait, never the only path. This resolves Open position A of `DECENTRALIZED-TRANSPORT-OPPORTUNITY-MAPPING-2026-07.md` in favour of adoption-as-implementation. Operator ruling, 2026-07-27; nothing here is settled beyond that, and the conformance surface below is a target, not an agreement.

**Source:** Freenet (`freenet.org`; Clarke's FUTO talk, `youtu.be/3RBNboYUlVI`), and a direct read of `crates/zp-mesh/src/` at the current working tree. Trait definitions quoted below are verbatim from that read.

**Attribution:** The decision to target Freenet as a compatible transport is Ken's. The conformance mapping, the precondition analysis, and the open positions are drafted by Claude against the shipped code and the corpus; the design decisions remain Ken's.

**Composes with:** `TRANSPORT-ABSTRACTION-AND-CONSTRAINED-NETWORKS-2026-07.md` (**the governing Tier 2 elaboration** — its message transport contract is what Freenet conforms to, and its propagation-node discipline already anticipates third-party store-and-forward relays), `DECENTRALIZED-TRANSPORT-OPPORTUNITY-MAPPING-2026-07.md` (the lens and the boundary this document implements — a carrier is never a gate), `CROSS-SUBSTRATE-PEER-CONTRACT-2026-06.md` (§1 transport-neutrality and §5 Forbidden affordances, which bound what any transport may do with content), `STORAGE-TIER-CONTRACT-2026-06.md` (§5 Forbidden #10 — the canonical write path stays where it is; this document does not touch it), `DEPENDENCY-POSTURE.md` (the `libp2p` entry states the dual-path rule this document applies, and its own status line is the warning), `DISCOVERY-AND-BOOTSTRAP-2026-07.md` (the five specified discovery layers this adds a sixth candidate to), `QUARANTINE-PLANE-2026-07.md` (admission ceremony for the peer binary), `EXTENSION-SURFACE-2026-07.md` (the capability vocabulary that does not yet describe an inbound relay — FT5 depends on closing that).

---

## Framing

**1. "Like Reticulum" means something more specific in code than in conversation, and the difference is the whole design.** Reticulum is not a transport implementation in `zp-mesh`. It is two other things: a *wire format* that `packet.rs` implements and that every medium carries, and a *discovery backend* (`reticulum_discovery.rs`) that announces over whatever media happen to be attached. The actual media are `TcpServerInterface`, `TcpClientInterface`, `Libp2pInterface`, and `LoopbackInterface`. So "admit Freenet the way Reticulum was admitted" resolves, precisely, to: **implement `DiscoveryBackend`, and optionally `Interface`** — two separate slots, of which one is a near-exact fit and the other is a fit with caveats.

**2. The trait surface already exists and already anticipates this shape.** The `DiscoveryBackend` doc comment says so in its own words:

> *"This separation means a backend can be a dumb relay (web) or a broadcast medium (Reticulum) without knowing anything about ZeroPoint's identity model."*

A Freenet contract used as a rendezvous board is exactly a dumb relay. No new abstraction is required, no trait is widened, and the *carrier is never a gate* boundary from the opportunity mapping is enforced structurally by the trait itself — backends *"don't parse capabilities, don't verify signatures, and don't manage the peer table."*

**3. The precondition is inbound verification, and it is not a Freenet problem.** `MeshBridge` is defined in `crates/zp-pipeline/src/mesh_bridge.rs`, and its behaviour is now confirmed rather than assumed. `mesh-auth-v1` is `default = []` in both `zp-mesh` and `zp-pipeline`, and no crate in the build graph enables it — so `classify_inbound_auth` returns `AuthState::NotChecked` for every inbound payload. Its own doc table records that even with the feature on, an unsigned receipt is *"yes (v0)"* accepted, and a wrongly-signed one is rejected only when the feature is compiled in **and** a `PeerKeyStore` is attached **and** that store holds a key for the sender. **Today, an unsigned inbound receipt is accepted, and a forged one is accepted whenever the sender's key is unknown.**

This is the load-bearing finding of this document. Today's media are a TCP mesh and a gossipsub swarm of peers the operator attached, which is what makes the gap survivable. A public overlay changes the inbound population from "peers I attached" to "anyone," and attaching one first would widen an existing exposure rather than create a new one — worse, not better, because it will read as a Freenet regression when it is not. FT6 is a precondition on the substrate, not a deliverable of the transport.

---

## The conformance surface

### Slot 1 — `DiscoveryBackend` (near-exact fit, and the recommended first target)

Verbatim from `crates/zp-mesh/src/discovery.rs`:

```rust
#[async_trait]
pub trait DiscoveryBackend: Send + Sync {
    fn name(&self) -> &str;
    fn source(&self) -> DiscoverySource;
    async fn announce(&self, payload: &[u8]) -> MeshResult<()>;
    async fn poll_discoveries(&self) -> MeshResult<Vec<DiscoveredPeer>>;
    fn is_active(&self) -> bool;
    async fn shutdown(&self) -> MeshResult<()>;
}
```

The payload contract is already specified in the trait's own doc comment — *"the signed announce blob: `[combined_key(64)] + [capabilities_json] + [signature(64)]`"*, with the constraint that *"Backends transmit this blob as-is. They MUST NOT parse, log, or retain the payload beyond the minimum needed for transmission."*

A `FreenetDiscovery` implementation is mechanically obvious: `announce()` publishes the opaque blob into a well-known discovery contract; `poll_discoveries()` reads that contract's state and returns what is new. The blob is opaque to the transport by contract, which means the Freenet contract's validity rule can be the degenerate one the opportunity mapping requires — *the signature verifies, and nothing else* — and the substrate's own `DiscoveryManager` remains the only thing that interprets identity.

This slot also answers the gap `DISCOVERY-AND-BOOTSTRAP-2026-07.md` names in its Non-goals — *"deep resistance requires additional infrastructure"* — without touching that document's five existing layers. It is a sixth, optional, and it composes rather than replaces.

### Slot 2 — `Interface` (fits, with two caveats)

Verbatim from `crates/zp-mesh/src/interface.rs`:

```rust
#[async_trait]
pub trait Interface: Send + Sync + std::fmt::Debug {
    fn config(&self) -> &InterfaceConfig;
    async fn send(&self, packet: &Packet) -> MeshResult<()>;
    async fn recv(&self) -> MeshResult<Option<Packet>>;
    fn is_online(&self) -> bool;
    fn stats(&self) -> InterfaceStats;
}
```

Registration is imperative — `attach_interface(&self, interface: Arc<dyn Interface>)` — so a Freenet interface is attachable at runtime alongside TCP and libp2p with no change to `MeshNode`.

*Caveat one: latency and MTU.* `Interface` is a medium port with packet-level `send`/`recv`. Freenet's routed contract updates are not a low-latency link; a contract acting as a mailbox is a store-and-forward channel with propagation delay measured against `node_registry.rs`'s existing staleness thresholds (`DEFAULT_STALE_TIMEOUT_SECS = 90`, `DEFAULT_OFFLINE_TIMEOUT_SECS = 300`). Those give real headroom, but the interface config's MTU handling and `is_online()` semantics need explicit definitions for a medium where "online" means "the overlay is reachable," not "a socket is up."

*Caveat two: it is unicast-shaped, and Freenet is not.* `MeshNode::send_on_interfaces` fans a packet to every attached online interface and returns `Ok(())` if any one accepted it. A contract-per-destination mailbox pattern satisfies this, but publishes the *existence* of a destination pair to the overlay. That is the metadata disclosure recorded as DT6 in the opportunity mapping, and it applies to slot 2 and not to slot 1.

### What does not change

The canonical write path stays on the storage tier's single-writer semantics. No chain entry, no delegation grant, and no gate decision moves into a Freenet contract. Cross-substrate peer tier §5 Forbidden #7 continues to apply verbatim — *"The substrate must not append a peer's receipt entries into the local `audit_entries` table as if they were local receipts — not as a performance optimization, not as a replication strategy, not as a 'unified view.'"*

---

## Conformance against the message transport contract

`TRANSPORT-ABSTRACTION-AND-CONSTRAINED-NETWORKS-2026-07.md` §"The message transport contract" is the governing specification, and it was written to admit exactly this class of transport. Its four requirements, against Freenet:

| Requirement (verbatim) | Freenet |
|---|---|
| *"Message boundaries preserved. A receipt sent as one message arrives as one message (or fragmented and reassembled with fidelity)."* | Satisfied — a contract update is a discrete unit; the Tier C fragmentation discipline covers oversize |
| *"Content integrity verifiable… Transport does not need to be secure; substrate signature discipline handles integrity."* | Satisfied, and this is the clause that makes an untrusted public overlay admissible at all |
| *"Best-effort delivery acceptable. Transport is not required to guarantee delivery. Substrate handles retry, deduplication, and store-and-forward at the substrate layer."* | Satisfied by construction — and see the correction below, because the substrate layer does not currently do what this sentence says it does |
| *"Message-oriented, not stream-oriented."* | Satisfied — content-addressed state, not a byte stream |

The same document's store-and-forward discipline already anticipates the relay role: *"substrate can rely on third-party store-and-forward nodes for peers that are not currently reachable. Propagation nodes hold receipts until recipient becomes reachable. Substrate does not depend on propagation node integrity for content integrity (signatures verify end-to-end) but does depend on availability for eventual delivery."* A Freenet peer is a propagation node in that sense, and the trust posture toward it is already specified — depend on it for availability, never for integrity.

Its §"What composes from here" enumerates a Reticulum RNS adapter with LXMF composition as item 5. Freenet enters the same list.

## Delivery semantics: the honest correction

The opportunity mapping recorded "no delivery receipt" as a Freenet-specific friction against §III.19. The code read corrects that. `Interface::send` returns `MeshResult<()>`, and in `TcpServerInterface::send` a broadcast with no connected subscribers returns `Ok(())` with a debug log — *"No subscribers (no clients connected) — not an error, just no-op."* `send_on_interfaces` returns `Ok(())` when any single interface's local send succeeded. No trait method distinguishes *sent* from *delivered*; no retry loop, per-send timeout, or acknowledgement type exists at either trait level. `PacketType::Proof` is link-establishment, not a per-message receipt.

**The substrate's transport layer is already best-effort fire-and-forget with no delivery evidence.** Freenet would not introduce that property; it would inherit it. Liveness today lives one layer up, in `node_registry.rs`'s heartbeat-driven `Active` / `Stale` / `Offline` transitions, which is a membership signal rather than a delivery signal.

**And the spec is fine with best-effort — on a condition the code does not meet.** The message transport contract accepts undelivered messages precisely because *"Substrate handles retry, deduplication, and store-and-forward at the substrate layer."* No retry, no dedup, and no store-and-forward queue was found at the `Interface` or `AgentTransport` level, and `send_on_interfaces` returns `Ok(())` once any interface has locally accepted the bytes. So the transport layer is conformant by the letter — best-effort is allowed — while the substrate layer that was supposed to compensate has not been built. That is a cleaner statement of the gap than "no delivery receipt," and it belongs to `TRANSPORT-ABSTRACTION-AND-CONSTRAINED-NETWORKS`, not here.

It is also the reason a store-and-forward medium is a *better* first non-local transport than it looks: an overlay whose native mode is delayed delivery makes the missing substrate-layer retry visible immediately, where TCP on a LAN hides it.

---

## Verifiable outcomes (FT)

- **FT1** — `FreenetDiscovery` implements `DiscoveryBackend` unmodified. No trait method is widened, no new trait is introduced, and `DiscoveryManager` requires no change to consume it.
- **FT2** — The transport is feature-gated in `crates/zp-mesh/Cargo.toml` and off by default. Note the precedent to avoid: `libp2p` is currently an unconditional dependency, and `DEPENDENCY-POSTURE.md` still reads *"Hedged architecturally; not yet hedged in code."*
- **FT3** — With the feature disabled, the crate builds and every existing test passes unchanged. With it enabled but the overlay unreachable, discovery degrades to the remaining backends and no substrate operation blocks, fails, or changes outcome.
- **FT4** — The Freenet-side contract's validity rule is signature-verification-only. No capability, delegation, membership, or authorization decision is expressed in contract code — checkable by reading the published contract.
- **FT5** — The peer binary is admitted through the quarantine plane as an executable artifact with an operator-signed `delegation:admit:executable:<content_hash>`, and its manifest declares that it listens, relays third-party bytes, and stores content the operator cannot inspect. FT5 is blocked on Open position C of the opportunity mapping — that vocabulary does not exist in `EXTENSION-SURFACE-2026-07.md` today.
- **FT6** — Inbound envelopes arriving via this transport are signature-verified before dispatch, and that verification has a non-test call site. See Framing 3; this is a precondition, not a deliverable of the transport itself.
- **FT7** — Metadata the overlay discloses — announce cadence, destination-pair existence for slot 2, volume — is enumerated in the delegation the operator signs.
- **FT8** — At least one other backend remains attached and functional in every configuration where this one is enabled, per the dual-path rule.

---

## Minimum slice

**m0: `FreenetDiscovery` implementing `DiscoveryBackend`, feature-gated, announce-and-poll only.**

It adds no new substrate behavior, no new receipt type, and no new abstraction — the trait exists, its payload is already opaque-by-contract, and `DiscoveryManager` already multiplexes backends. It exercises the interesting properties immediately: does an announce blob survive a carrier the substrate does not control, how long does propagation actually take against the 90-second staleness threshold, and what does the overlay disclose about announce cadence.

It also deliberately avoids the two things that need rulings first. It carries no receipts, so cross-substrate peer tier §5 is not engaged. It is not an `Interface`, so nothing in the mesh's packet path depends on it. If m0 turns out badly, deleting the file is the entire rollback.

m0 does not satisfy FT5 or FT6, and running it locally against a self-hosted peer is the correct way to keep both out of scope until they are resolved.

---

## Sequencing

**This is not next, and the reason is not maturity — it is that the slot it plugs into is not yet connected to anything.**

`DiscoveryManager::add_backend` has no call site outside `discovery.rs`'s own test module. No production binary — not `zp-server`, not `zp-cli`, not `zp-pipeline` — constructs a `DiscoveryManager` or registers `WebDiscovery` or `ReticulumDiscovery` with one. The machinery exists and is unit-tested; it is not wired. A `FreenetDiscovery` shipped today would be a third backend for a manager nothing runs.

Neither governing roadmap contains mesh or transport work at all. `AUTONOMIC-LAYER-IMPLEMENTATION-ROADMAP-2026-07.md` runs six phases from reliability foundation through field-pilot prep with no networking item in any of them; `REGENT-SELF-BUILDOUT-TRAJECTORY-2026-07.md` runs six gates with none either. Transport is currently off the critical path, and that is a correct reading of priority rather than an oversight.

Where it *does* already appear is the empirical program, whose Coordination behavioral claims name *"Peer discovery announce propagation under adversarial spam. Never tested"* and *"Peer discovery reachability under partitioned networks. Does the mesh actually route around outages?"*, mapped to a placeholder `PEER-DISCOVERY-STRESS-INVESTIGATION` and sequenced into empirical **Phase 2 — Coordination and fleet**. That is this work's natural home: a public overlay is the most convenient adversarial-spam generator the substrate could ask for, and the stress investigation and the transport want to be one arc, not two.

### Prerequisites, in order

- **P1 — Wire `DiscoveryManager` into a running binary** with the two existing backends. Not Freenet's work, and nothing about discovery is real until it is done. Blocks m0 from being meaningful, though not from compiling.
- **P2 — Close the inbound authentication gap.** Enable `mesh-auth-v1`, attach a `PeerKeyStore`, and rule on unsigned-accepted-as-v0. Independently urgent per Open position B; hard-blocks any public medium.
- **P3 — Bound the intake path.** `DiscoveryManager::poll_all` has no cap on discoveries accepted per poll, `peer_records` has no size bound (only TTL pruning that must be called externally), and `NodeRegistry` TOFU admission has no rate limit on distinct new `node_id`s. Reputation is consulted in `MeshBridge` at the pipeline layer and nowhere on the discovery or registry intake path. All four are survivable on a mesh of attached peers and are not survivable on a public board.
- **P4 — m0.** `FreenetDiscovery` behind a feature gate, run against a self-hosted peer, as one arm of `PEER-DISCOVERY-STRESS-INVESTIGATION`.

P1 through P3 are upgrades the existing mesh needs whether or not Freenet ever lands. Freenet is the forcing function, not the cause — which is the useful part of having decided to target it now: it converts three latent gaps into named prerequisites with an order.

---

## Alternatives considered (tie-offs)

- **Implement `Interface` first, treating Freenet as a medium.** *Disposition: deferred behind m0.* It is the more powerful slot and the more expensive one — it needs MTU and `is_online()` semantics for a store-and-forward medium, and it engages the receipt path and its metadata disclosure. Reopens once m0 has produced propagation-latency evidence.
- **Implement `AgentTransport` directly, alongside `MeshNode`.** *Disposition: rejected.* `AgentTransport` is the agent-facing port that `zp-pipeline` consumes; a second implementation of it would be a second mesh, not a second transport, and it would duplicate peer-table and announce logic that `MeshNode` already owns. Reopens only if `MeshNode` is ever split.
- **Vendor or fork the Freenet peer.** *Disposition: rejected for now.* `DEPENDENCY-POSTURE.md` names trait-abstraction, feature-gating, and parallel dual-implementation as its mitigations, and does not name vendoring. The `DiscoveryBackend` trait already provides the insulation vendoring would buy. Reopens if the upstream project's release cadence becomes a practical blocker.
- **Wait for Freenet to mature before targeting it.** *Disposition: rejected by the decision above.* Targeting behind a default-off feature gate costs little and produces evidence now; the dual-path rule is what makes maturity a non-blocker.

---

## Open positions

- **A — What are `is_online()` and MTU for a store-and-forward medium?** Both trait methods assume a link. *Resolution: definitions land with the slot-2 implementation, informed by m0's measured propagation latency; not blocking m0.*
- **B — Does `MeshBridge` verify inbound envelope signatures?** **RESOLVED 2026-07-27 by direct read: no, not in any build configuration currently produced.** `MeshBridge` lives in `crates/zp-pipeline/src/mesh_bridge.rs`; `mesh-auth-v1` is off by default and enabled by no crate, so `classify_inbound_auth` returns `AuthState::NotChecked` unconditionally. With the feature on, unsigned is still accepted as legacy v0, and a bad signature is rejected only when a `PeerKeyStore` is attached and holds the sender's key. This is a finding about the current TCP and libp2p paths, not about Freenet. *Remaining work: enable the feature, attach a keystore, and rule on whether unsigned-accepted-as-v0 survives. Tracked as prerequisite P2 below.*
- **C — Which discovery contract, and who publishes it?** A rendezvous board that everyone reads is a well-known address someone has to establish first. A foundation-published contract is a center; a per-operator contract is not discoverable by strangers. *Resolution: a bootstrap ruling, which is the same unresolved question `PEER-TRUST-ANCHOR-2026-07.md` already carries as "first peer trust anchor for a fresh sovereign."*
- **D — Does the corpus want a `//! Spec:` header convention retrofitted here?** `crates/zp-mesh/src/` contains no `//! Spec:` headers at all — the A11 verification method does not work on this crate. *Resolution: an authoring-discipline ruling on whether new modules in `zp-mesh` adopt the header; a new `freenet_discovery.rs` is a natural first instance.*
- **E — Sybil exposure via an open discovery board.** `DISCOVERY-AND-BOOTSTRAP-2026-07.md` already records *"Not sybil-proof by construction"*; a public rendezvous makes announce-flooding cheaper than the existing layers do. *Resolution: measured on m0 — announce volume against a live board is the evidence.*

---

## What is specified vs. what is shipped

Per A11:

- **Specified and unit-tested but not wired:** `DiscoveryManager`. `add_backend` has no call site outside `discovery.rs`'s test module, and no production binary constructs one. Discovery, as a running capability, does not exist today — only its parts do.
- **Off in every build produced:** `mesh-auth-v1`, in both `zp-mesh` and `zp-pipeline`. Inbound payloads classify as `AuthState::NotChecked`.
- **Shipped, verified by direct read:** the `Interface`, `AgentTransport` and `DiscoveryBackend` traits; `TcpServerInterface` / `TcpClientInterface` with real socket I/O, HDLC framing and reconnect-with-backoff; `Libp2pInterface` at MVP scope (its own module doc: *"Transport: TCP only… Wire pattern: gossipsub broadcast"*); `ReticulumDiscovery` as a `DiscoveryBackend`; `LoopbackInterface`; `MeshEnvelope` sign-then-send; `verify_announce_signature` on the inbound announce path; `node_registry.rs` heartbeat lifecycle. No `todo!()` or `unimplemented!()` markers were found in the crate.
- **Not shipped:** everything in this document. No Freenet integration exists in `crates/`.
- **Unconfirmed:** inbound envelope verification downstream of `zp-mesh` (Open position B). Do not treat Framing 3 as an established vulnerability — treat it as an unverified path.
- **Contradicts a corpus claim:** `DEPENDENCY-POSTURE.md` describes libp2p and Reticulum as parallel transport options with *"Neither transport should become the only path."* In the working tree, `libp2p` is an unconditional dependency of `zp-mesh` and Reticulum is a wire format plus a discovery backend rather than a parallel medium. The hedge is real as an architecture and thinner in code than the document implies. FT2 exists so this adoption does not repeat it.

---

## Non-goals

- **Not chain storage.** The canonical write path is untouched, and `STORAGE-TIER-CONTRACT` §5 Forbidden #10 continues to exclude eventually-consistent backends from it.
- **Not an anchoring backend.** `EXTERNAL-ANCHOR-TIER-CONTRACT` §5 Forbidden #5 stands; nothing here publishes chain content.
- **Not a replacement for any existing backend.** This is an addition behind a feature gate, and FT8 requires another backend to remain functional.
- **Not anonymity.** A Genesis-signed announce identifies its operator by construction. The overlay's own anonymity properties are not being purchased and should not be claimed.
- **Not a fix for delivery evidence.** That gap is substrate-wide and pre-existing, per the correction above, and it is not this document's to close.
