# Nostr as a Compatible Transport and Discovery Backend — Conformance Target

**Document type:** Design note / conformance target. **Not** a Tier 2 canonical elaboration — it elaborates no KEEL section. It elaborates a Tier 2 *contract* (`CROSS-SUBSTRATE-PEER-CONTRACT-2026-06.md`) and the shipped `zp-mesh` trait surface, which per A1 makes it a design note rather than a canonical elaboration.

**Date:** 2026-08-14.

**Decision:** Nostr is targeted as a **compatible transport and discovery backend**, admitted the same way Reticulum, libp2p and Freenet are — one implementation among several behind an existing trait, never the only path. Operator ruling, 2026-08-14. Nothing here is settled beyond that, and the conformance surface below is a target, not an agreement.

**Third ruling, same date:** **no cross-sovereign payload persists on a third party.** Kinship-scoped traffic crossing any relay uses ephemeral kinds only. §3.2 gives the reasoning, the residuals, and what it forecloses. Operator ruling, 2026-08-14.

**Second ruling, same date:** relay classification. *"A self-hosted relay within the governed boundary is internal, while one outside oversight and protection must be considered external."* Operator ruling, 2026-08-14. §3 turns this into an operational test and a payload tier; the ruling itself is the operator's, the mechanics below are drafted.

**Source:** the Nostr protocol (NIP-01, NIP-44, NIP-59), a direct read of `block/buzz` at commit `df9e773` (Apache 2.0, Rust relay implementation, ~25.9k stars) as the most complete extant relay-plus-agent implementation, and a direct read of `crates/zp-mesh/src/` at the current working tree. Trait definitions quoted below are verbatim from that read.

**Attribution:** The decision to target Nostr, and the internal/external relay ruling, are Ken's. The conformance mapping, the retention collision, the identity-binding analysis, and the open positions are drafted by Claude against the shipped code and the corpus; the design decisions remain Ken's.

**Composes with:** `TRANSPORT-ABSTRACTION-AND-CONSTRAINED-NETWORKS-2026-07.md` (**the governing Tier 2 elaboration** — its message transport contract is what Nostr conforms to), `FREENET-TRANSPORT-CONFORMANCE-2026-07.md` (the template this follows, and whose prerequisites P1–P3 this shares verbatim), `DECENTRALIZED-TRANSPORT-OPPORTUNITY-MAPPING-2026-07.md` (the lens — a carrier is never a gate), `COMMUNITY-SURFACE-ARCHITECTURE-2026-07.md` (**the position this document revises** — see §1), `CROSS-SUBSTRATE-PEER-CONTRACT-2026-06.md` (§5 Forbidden #7), `STORAGE-TIER-CONTRACT-2026-06.md` (§5 Forbidden #10), `EXTERNAL-ANCHOR-TIER-CONTRACT` (§5 Forbidden #5 — the clause the relay ruling interacts with), `DEPENDENCY-POSTURE.md` (the dual-path rule), `PEER-TRUST-ANCHOR-2026-07.md` (the per-surface grant shape §3 reuses), `MULTI-DEVICE-OPERATION-2026-07.md` (§5.2 sync, the recommended pilot surface), `SOVEREIGN-KINSHIP-PRIMITIVES-2026-07.md` (the at-distance delivery gap), `regent-gossip-and-evolution-2026-07.md` (**the surface this document refuses** — see §9).

---

## 1. Framing — this reverses a standing position, and should say so

The corpus already assessed Nostr once. `COMMUNITY-SURFACE-ARCHITECTURE-2026-07.md:27`, verbatim:

> "**Nostr** — cryptographic identity per user, signed events published to dumb-pipe relays, clients aggregate from multiple relays, no lock-in, anyone can run a relay. The right structural shape, but with weak identity (just a key, no chain-of-authority), unclear relay economics, and no governance primitives worth speaking of."

That document then concluded: *"ZP has more infrastructure than either — chain, gate, mandate model, Cartographer, Regent — so it can build a gathering layer that's structurally stronger than either."*

The assessment stands unchanged. **The conclusion drawn from it is what changes.** The July position was *build stronger than Nostr*. This document adopts the opposite posture: *plug into Nostr and supply the strength ourselves*. The protocol's diagnosed weakness — a bare key with no chain-of-authority — is precisely the thing the substrate already has and Nostr does not. Supplying it is cheaper than reproducing relays, and the resulting artifact is interoperable with an existing network rather than adjacent to one.

Three consequences of stating the reversal plainly:

1. **The shape is the asset, not the liability.** Dumb-pipe relays, multi-relay client-side aggregation, anyone-can-run-one, no lock-in — that is what the message transport contract asks for, written by someone else and already deployed. A framing of "take the network but not the shape" would license rebuilding relays and would waste the reason for adopting at all. What is declined is the *identity thinness* and the *absence of governance primitives*, both of which the substrate supplies from above.
2. **Nostr was never assessed as a transport.** The July entry evaluated it as a community-surface comparator. It appears nowhere in `DECENTRALIZED-TRANSPORT-OPPORTUNITY-MAPPING`, `TRANSPORT-ABSTRACTION`, or `FREENET-TRANSPORT-CONFORMANCE`, all of which name-and-verdict Reticulum, libp2p, and Freenet. This is a gap in the transport survey, not a silent rejection.
3. **A carrier is never a gate.** Unchanged and load-bearing. Nothing below moves a chain write, a delegation grant, or a gate decision onto a relay.

---

## 2. Why this is a better first non-local transport than it looks

The substrate's chain supplies exactly the property Nostr lacks, and Nostr supplies exactly the distribution the substrate lacks. The composition is unusually clean:

- **Ordering lives in the payload, not the carrier.** Nostr events are individually signed with no inter-event commitment — no `prev_hash`, no sequence, verified directly against `block/buzz`'s `events` table schema, which carries `id, pubkey, created_at, kind, tags, content, sig` and nothing linking one row to another. That is a fatal weakness for a ledger and an irrelevance for a carrier, because a receipt already carries its own hash-linkage. A relay that reorders cannot corrupt sequence; a relay that drops a receipt from the middle of a run is caught by the next receipt's back-link.
- **Withholding the tail remains undetectable** without an independent liveness signal. This is not a Nostr property; it is the general store-and-forward property, and the substrate already answers it one layer up with `node_registry.rs`'s heartbeat-driven `Active`/`Stale`/`Offline` transitions.
- **Multi-relay publication makes withholding require collusion.** Client-side aggregation across N relays is the protocol's native mode, not a bolt-on.

---

## 3. The relay classification ruling, made operational

**The ruling:** a self-hosted relay within the governed boundary is internal; one outside oversight and protection must be considered external.

The ruling is correct and needs a test attached, because "within the governed boundary" is exactly the phrase that drifts. Proposed test — a relay is **internal** only if all three hold:

- **G1 — Substrate Form custody.** It runs on a Substrate Form under operator control, admitted through the readiness contract like any other governed component.
- **G2 — Governed lifecycle.** Its start, stop, and configuration changes traverse the gate and leave receipts. A relay whose config can be changed without a receipt is not inside the boundary regardless of whose hardware it sits on.
- **G3 — Closed write set.** It accepts `EVENT` only from keys in the fleet's own delegation set. A relay that accepts writes from unaffiliated npubs is external in the sense that matters, even when the operator owns the disk.

Failing any one of the three makes it external. G3 is the one that will actually bite: the temptation is to run one relay and let a kindred sovereign publish to it, which silently reclassifies it.

**Classification should be a receipt, not a config value.** `transport:relay:classified:<relay_id>:<internal|external>`, operator-signed, revocable, with the adapter selecting the payload tier mechanically from the classification rather than by convention. This is deliberately the same shape as `PEER-TRUST-ANCHOR-2026-07.md`'s per-surface anchor grants — operator-declared, chain-anchored, per-surface, never automatic — and reuses that ceremony rather than introducing a second one.

### Payload tiers that fall out of the ruling

| Relay class | May carry | May not carry |
|---|---|---|
| **Internal** (G1∧G2∧G3) | NIP-44-encrypted receipt bodies for same-sovereign fleet sync; ephemeral discovery beacons | Anything for which the fleet is not both author and audience |
| **External** (otherwise) | Compact chain-head commitments (hash + height + signature); ephemeral discovery beacons; kinship-scope payloads **only as NIP-59 ephemeral gift wrap (kind 21059)**, per §3.1, and **pending Open position C** | Receipt bodies, actor identifiers, claim types, policy decisions, delegation grants — `EXTERNAL-ANCHOR-TIER-CONTRACT` §5 Forbidden #5 stands unmodified |

**The ruling resolves the anchoring case in the right direction, and the resolution is slightly counterintuitive.** Checkpoint anchoring derives its entire value from plural *independent* custodians — independent meaning outside the operator's oversight, therefore external by this ruling. That is not a problem, because Forbidden #5 already *permits the compact commitment* across that boundary; the opportunity mapping characterises such a candidate as *"a sixth commitment target at most, never a content store."* So anchoring fits an existing contract without a new invariant. An *internal*-only anchoring deployment would be worthless — a witness you control witnesses nothing.

### 3.1 Gift wrap is the required envelope for anything kinship-scoped crossing an external relay

NIP-44 conceals content and does not conceal the social graph. A relay carrying a plain NIP-44 payload learns author, recipient, timing, cadence and volume — which is the metadata III.24 is about, and it survives the payload being unreadable.

NIP-59 gift wrap narrows that. Three layers: an **unsigned rumor** carrying the content (unsigned deliberately — a leaked rumor cannot be authenticated by whoever leaked it, which is deniability by construction); a **seal, kind 13**, being the rumor NIP-44-encrypted to the recipient and signed by the real author key, carrying no `p` tag; and a **gift wrap**, the seal encrypted again and signed by a random one-time keypair, with the recipient's `p` tag as its only required tag. The spec further recommends independent random timestamps per layer against time-analysis.

**Use kind 21059, the ephemeral gift wrap variant, not 1059.** NIP-59 defines both. 21059 falls inside the 20000–29999 ephemeral range, so sender-anonymity and non-retention compose without a custom kind and without giving up interoperability with existing Nostr tooling — which was part of the reason for adopting the protocol rather than reproducing it.

What this buys and what it does not:

- **Concealed:** content, and the author. The relay sees an event from a throwaway pubkey it has never seen before and will not see again.
- **Still disclosed:** the recipient. Routing requires the `p` tag. A relay learns that *someone* is signalling that npub, how often, and at what size. Where both sides of a kinship wrap their traffic the relay sees two unlinked streams, but volume and timing correlation on a small relay is not a hard problem.
- **Costs:** the recipient cannot filter by sender — that is the point — so it fetches everything `p`-tagged to it and attempts decryption on each, which scales with whatever junk is addressed to it. Relay-side sender-based rate limiting is defeated, which is why some relays restrict or refuse gift wraps. Per-layer timestamp randomisation makes transport-layer ordering meaningless, which is harmless here because ordering lives in the receipt chain and never in `created_at` (§2).

Gift wrap narrows the exposure from *who talks to whom* to *who is being talked to*. That is a real improvement and not a resolution. **Internal-relay-only remains the stronger answer for kinship**; gift wrap is what is reached for when a payload must cross an external relay at all.

### 3.2 Ephemerality is what keeps a relay a medium rather than a party

**Ruling: no cross-sovereign payload persists on a third party.** Kinship-scoped traffic uses ephemeral kinds only — 21059 for wrapped payloads, per §3.1. This does not constrain same-sovereign fleet sync on an internal relay, which is neither cross-sovereign nor third-party.

The reasoning matters more than the rule, because it dissolves a gap that looked like it needed new contract vocabulary.

`CROSS-SUBSTRATE-PEER-CONTRACT-2026-06.md` is transport-neutral by construction, and its §4 Optional affordances already contemplate indirect delivery: a peer registry entry may carry *"a primary endpoint, one or more fallback endpoints, **a relay path via a mutually known third peer**."* But that is a **peer** — a sovereign with a Genesis-derived key, a registry entry, and explicit operator consent per Required #4. A Nostr relay is none of those. It has no chain, no Genesis identity, and cannot hold a registry entry, so the affordance does not reach it.

That is what made the gap look real: two contracts, neither one covering an unaffiliated infrastructure intermediary holding a governed payload. `EXTERNAL-ANCHOR-TIER-CONTRACT` §5 Forbidden #5 is scoped to the `TruthAnchor::anchor()` boundary and does not reach relay-borne peer traffic at all. The peer contract governs exchange with a peer and assumes the intermediary, if any, is itself a peer.

**The question was mis-posed.** A carrier that forwards and forgets is a *medium*. A carrier that retains is a *custodian*, and a custodian is a *party*. The peer contract needs no vocabulary for media, because transport-neutrality already covers them — a wire does not get a registry entry. Durable storage is precisely the property that would convert a relay from wire into party and make new vocabulary necessary. **Ephemerality is what keeps it a wire.**

So the gap is not deferred. It is dissolved — for exactly as long as the ephemeral rule holds. If durable cross-sovereign storage is ever proposed, the relay becomes a party, the gap reopens, and it is a Tier 2 contract amendment rather than a design-note decision. Registered as such in §11.

Three residuals, stated rather than papered over:

- **Ephemerality is requested, not enforced.** NIP-01 says relays should not persist kinds 20000–29999; a dishonest relay can and will not announce it. NT2 verifies the observed behaviour of a specific relay; it constrains no hostile one. The defenses that survive a dishonest relay are the internal/external classification (§3) and gift wrap (§3.1) — not the kind number.
- **Momentary custody is not zero.** A relay holds an event in memory long enough to fan out to connected subscribers. De minimis, and it should not be described as nothing.
- **Required #6 disambiguates as a side effect.** *"Chain-anchor every cross-substrate exchange locally"* was ambiguous under store-and-forward — anchor at send, or at confirmed receipt? Ephemeral delivery reaches only currently-connected subscribers, so there is no deferred delivery to disambiguate and send-time anchoring records a determinate outcome.

**What this forecloses, and where that need goes.** `emergency_notification` cannot use this carrier. It is the one kinship scope that must reach a recipient who is not there, and ephemeral delivery by definition does not. That need is real and belongs elsewhere: to out-of-band channels the recipient already monitors and trusts, and — for the infrastructure-down case, where a relay is unreachable anyway — to LXMF store-and-forward over mesh.

Note the asymmetry that makes this the right split rather than an evasion. Peer-relayed store-and-forward is delivery through a **consented sovereign**, which the peer contract explicitly admits. Relay-stored store-and-forward is delivery through an **unaffiliated custodian**, which it does not. The same functional need lands inside the contract on one path and outside it on the other, and the difference is exactly whether the intermediary is someone the operator has consented to.

There is also a plain engineering argument for the same conclusion: routing a life-safety signal through the newest and least-proven transport in the system, behind three unbuilt prerequisites, is a worse failure mode than any privacy property it would buy.

---

## 4. The conformance surface

### Slot 1 — `DiscoveryBackend` (near-exact fit, and the recommended first target)

`crates/zp-mesh/src/discovery.rs:137`. The trait's own doc comment reads:

> "This separation means a backend can be a dumb relay (web) or a broadcast medium (Reticulum) without knowing anything about ZeroPoint's identity model."

A Nostr relay is a dumb relay in exactly that sense. `announce()` maps to publishing an event; `poll_discoveries()` maps to a `REQ` subscription drained per poll. `DiscoveryManager` requires no change to consume it, and `web_discovery.rs` and `reticulum_discovery.rs` establish the precedent of plural backends.

**But there is a hard collision, and it is the most important finding in this document.** The trait's payload contract states, verbatim:

> "Backends transmit this blob as-is. They MUST NOT parse, log, or **retain** the payload beyond the minimum needed for transmission."

Nostr relays retain events. Retention is their function. A `NostrDiscovery` publishing the signed announce blob (`[combined_key(64)] + [capabilities_json] + [signature(64)]`) to a standard relay kind violates the trait contract on the first call.

**The fix is specific and must be designed in, not discovered later:** announce over **ephemeral event kinds (20000–29999)**, which NIP-01 specifies relays do not persist. Ephemeral kinds are broadcast-to-currently-connected-subscribers only — which is precisely "the minimum needed for transmission" and nothing more. This also aligns the discovery surface with `COPRESENCE-BEACON-PROTOCOL`'s posture that a beacon is a live signal rather than a logged history.

A regular (persisted) kind would additionally turn every announce into a permanently queryable record of substrate existence, cadence, and capability set — an enumeration surface, and one that outlives any revocation.

### Slot 2 — `Interface` (fits, with the same two caveats as Freenet)

`crates/zp-mesh/src/interface.rs:133` — `config()`, `send()`, `recv()`, `is_online()`, `stats()`. A relay connection maps cleanly onto send/recv over a websocket, and `recv()` returning `Option<Packet>` matches a drained subscription buffer.

`is_online()` and MTU carry the same undefined semantics for a store-and-forward medium that `FREENET-TRANSPORT-CONFORMANCE` Open position A records. Nostr is better off than Freenet here: a websocket connection has an unambiguous liveness state, so `is_online()` is answerable. MTU is not — relays impose implementation-specific event size limits with no protocol-level negotiation, which pushes oversize handling onto the Tier C fragmentation discipline.

### What does not change

No chain entry, no delegation grant, and no gate decision moves into a relay. Cross-substrate peer tier §5 Forbidden #7 continues to apply verbatim — *"The substrate must not append a peer's receipt entries into the local `audit_entries` table as if they were local receipts — not as a performance optimization, not as a replication strategy, not as a 'unified view.'"* Storage tier §5 Forbidden #10 continues to exclude eventually-consistent backends from the canonical write path, which a relay unambiguously is.

**Note the scope of Forbidden #7 for sequencing purposes:** it governs *cross-sovereign peers*. Same-sovereign fleet sync across APOLLO / ARTEMIS / zp-playground operates on a singular chain under one Genesis and does not engage that clause. This is a substantive argument for piloting on fleet rather than kinship — fewer contracts in play.

---

## 5. Conformance against the message transport contract

| Requirement (verbatim) | Nostr |
|---|---|
| *"Message boundaries preserved. A receipt sent as one message arrives as one message (or fragmented and reassembled with fidelity)."* | Satisfied — an event is a discrete signed JSON object; oversize falls to Tier C fragmentation |
| *"Content integrity verifiable… Transport does not need to be secure; substrate signature discipline handles integrity."* | Satisfied, and doubly so — the substrate's own Ed25519 signature travels inside the payload, independent of the relay's secp256k1 envelope signature |
| *"Best-effort delivery acceptable. Transport is not required to guarantee delivery. Substrate handles retry, deduplication, and store-and-forward at the substrate layer."* | Satisfied by construction — and the same correction applies as for Freenet: the substrate layer does not currently do what this sentence says it does |
| *"Message-oriented, not stream-oriented."* | Satisfied — events, not a byte stream, despite riding a websocket |
| *"Bidirectional (or optional-reply)."* | Satisfied — `EVENT` out, `REQ`/`EVENT` in |

Nostr scores at least as well against this contract as any candidate already admitted. **This is not a recommendation on its own** — the contract's best-effort clause is conditioned on substrate-layer retry, dedup, and store-and-forward that `FREENET-TRANSPORT-CONFORMANCE` established by direct code read does not exist: *"No trait method distinguishes sent from delivered; no retry loop, per-send timeout, or acknowledgement type exists at either trait level."* That gap belongs to `TRANSPORT-ABSTRACTION`, is transport-independent, and is not this document's to close.

---

## 6. The identity binding problem

**This is the one place where adoption is not free.**

The substrate is Ed25519 throughout — `ed25519-dalek` is a workspace dependency of every signing crate, with `x25519-dalek` for ECDH. Nostr is secp256k1 Schnorr (BIP-340). The curves are not interchangeable. A Nostr identity is therefore a **second keypair**, which walks directly into singular sovereign root.

The only shape that survives:

- **Deterministic hardened derivation from Genesis** to the secp256k1 transport key, so the npub is a *projection* of the sovereign root rather than a peer of it. Same discipline as `load_sovereign_root()` — one credential, everything derived.
- **A binding receipt**, `transport:identity:bound:<npub>`, chain-anchored, making the projection auditable and revocable. Absent this, an npub is an unaccounted second identity, which is the failure the singular-root invariant exists to prevent.
- **No independent generation path for identity.** An adapter that can mint its own *identity* keypair reintroduces the problem it was designed to avoid. This does not extend to NIP-59 envelope keys, which are random, single-use, unbound by design, and assert nothing — see §3.1 and NT5. Keeping the two categories nameable in the code is the whole discipline here; an adapter that has one notion of "keypair" will get this wrong.

One incidental upside worth checking rather than assuming: secp256k1 is the curve Trezor is built around. Hardware-held signing for the transport identity may be more tractable than for the Ed25519 root, which would be an odd but real inversion. Firmware support for Nostr-style Schnorr signing needs verification before anything is designed around it.

---

## 7. Verifiable outcomes (NT)

- **NT1** — `NostrDiscovery` implements `DiscoveryBackend` unmodified. No trait method widened, no new trait introduced, `DiscoveryManager` unchanged.
- **NT2** — Announce uses an ephemeral kind in 20000–29999. Verified by publishing an announce, disconnecting, reconnecting, and issuing a `REQ` for that kind: zero results. **This is the test that the trait's MUST-NOT-retain clause is honoured, and it fails loudly if a relay implementation persists ephemeral kinds anyway** — which is worth knowing about any relay before trusting it.
- **NT3** — Feature-gated in `crates/zp-mesh/Cargo.toml`, off by default. Note the precedent to avoid: `libp2p` is currently an unconditional dependency of `zp-mesh`, and `DEPENDENCY-POSTURE.md` still reads *"Hedged architecturally; not yet hedged in code."* This is the drift this adapter is most likely to repeat.
- **NT4** — With the feature disabled the crate builds and every existing test passes. With it enabled and all relays unreachable, discovery degrades to the remaining backends and no substrate operation blocks, fails, or changes outcome.
- **NT5** — The transport npub is derived from Genesis and bound by a `transport:identity:bound` receipt. No code path generates an unbound transport **identity** keypair. **Carve-out: NIP-59 wrap keys are exempt, and must be.** A gift wrap's outer key is a random one-time envelope key whose entire purpose is to be unattributable; binding it would defeat the mitigation it exists to provide, and it asserts no identity — it signs an envelope, never a claim. The distinction the code must hold is *identity keys are derived and bound; envelope keys are random, single-use, and never persisted*. A test asserts that a wrap key is used exactly once and is not written to any keystore.
- **NT6** — Relay classification is read from a `transport:relay:classified` receipt, and the payload tier of §3 is enforced mechanically in the adapter. A test asserts that an attempt to publish a receipt body to a relay classified external returns an error rather than a warning.
- **NT7** — Metadata a relay discloses — announce cadence, subscription filters, connection times, payload volume, and recipient `p` tags — is enumerated in the delegation the operator signs. Per §3.1, kinship-scoped traffic over an external relay uses kind 21059 and the enumeration must state plainly what gift wrap does *not* conceal: the recipient, the timing, and the volume.
- **NT8** — At least one other backend remains attached and functional in every configuration where this one is enabled, per the dual-path rule.
- **NT9** — No code path publishes a cross-sovereign payload to a persisted kind. The adapter's publish surface for kinship-scoped traffic accepts ephemeral kinds only, enforced by type rather than by convention, and a test asserts that attempting kind 1059 for a kinship payload is a compile-time or construction-time failure rather than a runtime warning. Per §3.2, this is the property that keeps a relay a medium rather than a party, so it is the one that must not be a lint.

---

## 8. Minimum slice

**m0: `NostrDiscovery` implementing `DiscoveryBackend`, feature-gated, announce-and-poll only, over ephemeral kinds, against a self-hosted relay classified internal.**

It adds no new substrate behavior, no new receipt type beyond the identity binding, and no new abstraction. It exercises the interesting properties immediately: does an announce blob survive a carrier the substrate does not control, what is real propagation latency against the 90-second staleness threshold, and does the chosen relay actually decline to persist ephemeral kinds.

It avoids what needs rulings first. It carries no receipts, so cross-substrate peer tier §5 is not engaged. It is not an `Interface`, so nothing in the mesh packet path depends on it. Classified internal, so the Forbidden #5 boundary is not approached. If m0 goes badly, deleting the file is the whole rollback.

**m1, only after m0 produces latency evidence:** fleet sync over an internal relay, `MULTI-DEVICE-OPERATION` §5.2's four-step protocol with a relay as the mailbox between APOLLO and ARTEMIS. This is the first slice that carries receipt bodies, and it is deliberately confined to the case where author and audience are the same sovereign.

---

## 9. What this is not for

**The Regent gossip layer.** `regent-gossip-and-evolution-2026-07.md` requires anonymity by construction — *"No persistent gossip identities. No reputation system... Any form of persistent identity creates a fingerprinting surface that undermines the privacy properties of the gossip layer."* Every Nostr event carries an author pubkey in the signed envelope; there is no unauthored event. Ephemeral per-broadcast keys would discard the only thing relays use for rate-limiting while still not defeating timing correlation.

These are opposed requirements, not a tuning problem. **The boundary should stay sharp even under an adapter framing**, because "we already have a Nostr adapter" is exactly the argument that will later be made for routing gossip over it. Gossip is a different layer with a different transport and this document does not serve it.

**And gift wrap does not rescue it — anticipating the specific argument.** §3.1 adopts NIP-59, whose outer key is random and single-use, so it will be proposed as the anonymity mechanism gossip needs. It is not. Gift wrap conceals the author *from the relay and from third parties*; the seal is still signed by the real author key and the **recipient** can verify exactly who sent it. That is correct for kinship, where a kindred sovereign should know who is signalling them. It is fatal for gossip, whose requirement is that a finding be unattributable **to its receivers**, because attributable findings accumulate into precisely the reputation the design forbids. Gift wrap hides the sender from observers; gossip needs the sender hidden from participants. Different property, same word.

**At-distance delivery to an offline sovereign.** Per §3.2, ephemeral delivery reaches connected subscribers only. Any kinship scope whose value depends on reaching someone who is not there — `emergency_notification` above all — is out of scope for this carrier and belongs to out-of-band channels and to LXMF over mesh. This is a deliberate foreclosure, not an unimplemented feature, and it should not be quietly reopened by adding a persisted kind "just for emergencies." That is the exact change that converts the relay into a party; NT9 exists to make it fail loudly.

**Buzz the product, as distinct from Nostr the protocol.** `block/buzz` is a competent relay implementation and a useful reference, but its relay holds deployment-root authority via `RELAY_OWNER_PUBKEY`, writes authorization tables (`relay_members`, `channel_members`) through a CLI path that bypasses the event pipeline entirely, and grants admins force-delete and identity-archival powers. Its `audit_log` is genuinely hash-chained — `seq`, `prev_hash`, per-community uniqueness — and `verify_chain` has no production caller anywhere in the tree, only test-module invocations. Depending on any of that would import a center. What is borrowable is the protocol, the `nostr` Rust crate they build on, and — separately from this document — their `buzz-acp` harness and NIP-OA owner-attestation design.

---

## 10. Alternatives considered (tie-offs)

- **Implement `Interface` first, treating a relay as a medium.** *Deferred behind m0.* More powerful, more expensive, engages the receipt path and its metadata disclosure immediately. Reopens once m0 has produced propagation-latency evidence.
- **Run our own relay implementation rather than adopting one.** *Deferred, not rejected.* A minimal Nostr relay is a small Rust program and the substrate is already a Cargo workspace, which makes G1–G3 trivially satisfiable. Weigh against it only after m0 establishes whether an off-the-shelf relay honours ephemeral-kind semantics. Reopens at m1.
- **Use Nostr for the community surface as originally scoped in `COMMUNITY-SURFACE-ARCHITECTURE`.** *Out of scope here.* That document's conclusion is revised in §1 as to posture, but the community surface is a product question and this is a transport document. They should not be resolved together.
- **Wait for the ecosystem to mature.** *Rejected by the decision above.* Nostr is older and more deployed than Freenet, which was already targeted. The dual-path rule makes maturity a non-blocker.
- **Adopt NIP-26 delegation for agent identity.** *Rejected.* NIP-26 is authorship delegation — impersonation. The substrate's delegation model is narrowing and revocable and is strictly stronger. If interop is wanted, NIP-OA (Buzz's owner-attestation design, which explicitly refuses NIP-26 semantics) is the closer shape, and publishing a substrate delegation in NIP-OA form would make it legible to Nostr tooling without weakening it. Separate document.

---

## 11. Open positions

- **A — Does an off-the-shelf relay actually honour ephemeral-kind non-persistence?** NIP-01 specifies it; implementations vary. *Resolution: measured on m0. NT2 is the test. If the answer is no for the chosen relay, the "run our own" alternative promotes from deferred to required.*
- **B — Trezor Schnorr signing for the transport identity.** Would place the derived transport key behind hardware without a second custody model. *Resolution: firmware capability check, before any design depends on it.*
- **C — Which contract governs an unaffiliated intermediary holding a cross-sovereign payload? RESOLVED 2026-08-14 by operator ruling; recorded here because the reasoning is load-bearing and the resolution is conditional.**

  *The question as originally posed was wrong.* This document first asked whether kinship payloads fall under `EXTERNAL-ANCHOR-TIER-CONTRACT` §5 Forbidden #5. A direct read of that contract establishes it does not: Forbidden #5 is scoped to *"the `TruthAnchor::anchor()` boundary,"* and §5's preamble states that the entries *"name what the External anchor tier itself must not do."* A kinship payload never crosses that boundary. Citing Forbidden #5 as the governing clause was a scope error.

  *The real finding was an absence.* `CROSS-SUBSTRATE-PEER-CONTRACT` governs exchange with a peer and its §4 Optional affordances admit *"a relay path via a mutually known third peer"* — a consented sovereign with a Genesis key and a registry entry. Neither contract covers an unaffiliated infrastructure intermediary. The gap was between the two, not inside either.

  *Resolution: dissolved by the ephemeral ruling rather than closed by new vocabulary.* Per §3.2, a carrier that forwards and forgets is a medium and needs no contract vocabulary, because the peer contract is transport-neutral and a wire gets no registry entry. A carrier that retains is a custodian, and a custodian is a party. Ephemerality is what holds the relay on the medium side of that line.

  *This resolution is conditional and its condition is named.* If durable cross-sovereign relay storage is ever proposed, the relay becomes a party, C reopens, and it is a **Tier 2 contract amendment** — an `CROSS-SUBSTRATE-PEER-CONTRACT` §8 autoregressive update trigger — not a design-note decision. A design note may not admit a party to the peer boundary, and this one does not.

  *What remains genuinely open is narrower and belongs elsewhere:* the at-distance delivery need that motivated the question. `SOVEREIGN-KINSHIP-PRIMITIVES` and `COPRESENCE-BEACON-PROTOCOL` specify no transport for the non-copresence case, which is still a real gap in those documents. It is no longer this transport's gap to fill — see §3.2 and §9.
- **D — Relay economics.** The July assessment named "unclear relay economics" and nothing since has clarified them. An internal relay makes the question moot; an external one does not. *Resolution: deferred until external-relay use is actually proposed.*
- **E — Does the `//! Spec:` header convention apply?** `crates/zp-mesh/src/` contains no such headers, so the A11 verification method does not work on this crate. Same open position `FREENET-TRANSPORT-CONFORMANCE` records as D. *Resolution: an authoring-discipline ruling; a new `nostr_discovery.rs` would be a natural first instance alongside `freenet_discovery.rs`.*

---

## 12. Prerequisites, in order

**P1–P3 are shared verbatim with `FREENET-TRANSPORT-CONFORMANCE` and are not this transport's work.** They are upgrades the existing mesh needs regardless.

- **P1 — Wire `DiscoveryManager` into a running binary** with the two existing backends. `add_backend` has no call site outside `discovery.rs`'s own test module; no production binary constructs a `DiscoveryManager`. Nothing about discovery is real until this is done, and a `NostrDiscovery` shipped today would be a fourth backend for a manager nothing runs.
- **P2 — Close the inbound authentication gap.** `mesh-auth-v1` is off in every build produced; `classify_inbound_auth` returns `AuthState::NotChecked` unconditionally. Hard-blocks any public medium.
- **P3 — Bound the intake path.** `poll_all` has no cap on discoveries per poll, `peer_records` has no size bound, and `NodeRegistry` TOFU admission has no rate limit on distinct new `node_id`s. Survivable on a mesh of attached peers; not survivable on a public relay.
- **P4 — Identity binding.** Derivation and `transport:identity:bound` receipt (§6). Unlike P1–P3 this *is* specific to this transport, and it blocks m0 rather than merely preceding it.
- **P5 — m0.**

Freenet and Nostr share P1–P3 entirely. If both are targeted, the prerequisites are done once. That is an argument for treating them as one arc rather than two, and for letting whichever is easier to stand up locally be the forcing function.

---

## 13. What is specified vs. what is shipped

**Shipped and verified by direct read:** the `Interface`, `DiscoveryBackend`, `AgentTransport`, `PeerKeyStore` traits in `crates/zp-mesh/`; `tcp.rs`, `libp2p_interface.rs`, `reticulum_discovery.rs`, `web_discovery.rs` as existing implementations; `ed25519-dalek` as the workspace signing dependency.

**Designed, not shipped:** everything else in this document. No Nostr code exists in the tree. `DiscoveryManager` is unwired. `MULTI-DEVICE-OPERATION` is a self-declared design note. `PEER-TRUST-ANCHOR` is a draft. The `transport:relay:classified` and `transport:identity:bound` receipt types are proposed here and exist nowhere.

**Verified in `block/buzz` rather than in the corpus:** the absence of inter-event hash linkage in the Nostr storage model, the `audit_log` chain and its lack of a production verifier, and the relay's administrative override paths. These are properties of that implementation and of the protocol, cited to justify the carrier-not-ledger framing.

---

## 14. Non-goals

- **Not chain storage.** Storage tier §5 Forbidden #10 stands. A relay is eventually consistent and is excluded from the canonical write path.
- **Not an authorization surface.** No membership, capability, or gate decision is expressed in relay state. Buzz's model — where `relay_members` is the enforcement point and the signed event is a downstream broadcast — is the specific inversion to avoid.
- **Not a replacement for any existing backend.** Dual-path rule; NT8.
- **Not the gossip layer.** §9.
- **Not a community surface.** §10.
- **Not an identity system.** The npub is a derived projection of the sovereign root, never a peer of it.
- **Not durable custody of cross-sovereign payloads.** Operator ruling 2026-08-14; §3.2. Ephemeral kinds only across a sovereign boundary. Proposing durable storage is a Tier 2 contract amendment, not a configuration change.
- **Not an at-distance delivery path for `emergency_notification`.** Ephemeral delivery reaches only connected subscribers, by design. That need routes to out-of-band channels and to LXMF store-and-forward over mesh, where the intermediary is a consented sovereign rather than an unaffiliated custodian. §3.2.
