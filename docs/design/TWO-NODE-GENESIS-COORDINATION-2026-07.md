# Two-Node Genesis Coordination Ceremony — 2026-07

**Tier 2 canonical elaboration.** Specifies the ceremony by which two role-specialized sovereigns — a Sentinel-role node and a Regent-role node, each holding its own independent Genesis root — recognize each other as sovereign peers of the same operator, cross-reference each other's chain segments, and enter ongoing mesh-mediated coordination. Elaborates `HARDWARE-ROLE-SEPARATION-2026-07.md` (canonical two-role topology) at the ceremony layer. Does not amend KEEL.

Draft — 2026-07-27. Composes with `HARDWARE-ROLE-SEPARATION-2026-07.md` (canonical topology), `pi5-sovereign-standup-checklist-2026-07-17.md` (Sentinel-side prerequisite), `mac-mini-regent-standup-checklist-2026-07-27.md` (Regent-side prerequisite), `PEER-DISCOVERY-AS-OUTREACH-2026-07.md` (peer protocols this ceremony extends for co-sovereign framing), `PORTABLE-CHAIN-EXPORT-CEREMONY-2026-07.md` (chain segment preservation), `SUBSTRATE-BOOT-INVARIANT-CEREMONY-2026-07.md` (bright-line invariants), and the existing mesh protocol in `tools/sentinel/zp_sentinel/mesh.py` plus the AgentAnnounce envelope described in the March 2026 Sentinel v0.3 release.

## Framing

Under `HARDWARE-ROLE-SEPARATION-2026-07.md`, the sovereign node is a *pair* — a Sentinel-role hardware plus a Regent-role hardware, each with its own Genesis root, each producing its own chain segment, coordinating via the mesh protocol. This framing raises a question the earlier single-node topology did not: **how do two independently-Genesis'd nodes recognize each other as peers of the same operator, in a way that is chain-attestable, resistant to impersonation, and cheap enough to re-run when either node is rebuilt?**

The mesh protocol as of Sentinel v0.3 already handles peer discovery, capability announcement, and heartbeat. What it does not do — and what this ceremony canonicalises — is the initial *co-sovereign attestation* by which each node commits to a chain event that specifically identifies the other as a co-sovereign of the same operator. Without this commitment, the mesh treats every peer as an ordinary participant; with it, the operator can prove — from either chain segment — that these two nodes were mutually attested at a specific ceremony time, by a specific operator signature, with specific Genesis roots and chain heads. The cross-reference is the primitive that lets the Cartographer compose the two chains into one coherent substrate view without merging them, and lets a future auditor verify the pair without needing access to both nodes simultaneously.

The ceremony is small — four phases, roughly thirty minutes of wall-clock — and re-runnable: a Sentinel rebuild, a Regent rebuild, a Genesis rotation on either side all imply a re-attestation ceremony. Chain segments from before the ceremony are preserved (per `PORTABLE-CHAIN-EXPORT-CEREMONY-2026-07.md`); the ceremony establishes a *new* cross-reference for the current (Sentinel-Genesis, Regent-Genesis) pair. Historical pairs remain queryable but are no longer "the current pair" for defensive-swap coordination, mesh capability composition, or Cartographer weaving.

## Preconditions

Both nodes must be individually stood up before the coordination ceremony runs:

- **Pi 5 Sentinel** completed `pi5-sovereign-standup-checklist-2026-07-17.md` through §6.5 (Form Disclosure discipline). Sentinel-role Sovereign Form asserted, TPM 2.0-attested boot chain established, Trezor-held Genesis derivation bound, mesh subsystem active.
- **APOLLO Regent** completed `mac-mini-regent-standup-checklist-2026-07-27.md` through §5.2 (form graduation). Regent-role Sovereign Form asserted, Secure Enclave-attested boot chain, Trezor-held Genesis derivation bound (using a distinct Keychain identifier from any Companion-Form Genesis to avoid collision — see L1 empirical lesson), mesh subsystem active.
- **Network reachability**: both nodes on the same LAN segment, or with route-and-firewall-permitted TCP connectivity. Mesh WebSocket transport per `tools/sentinel/zp_sentinel/mesh.py` conventions.
- **Trezor available**: the operator's Trezor (or equivalent hardware signing device) is connected to *one* of the two nodes for the operator confirmation signature in Phase 3. The other node receives the confirmation via mesh; direct Trezor-to-both-nodes is not required.
- **Time sync**: both nodes have NTP or manual clock agreement within ~30 seconds. The ceremony's chain events include timestamps and the substrate rejects wildly divergent clocks.
- **Chain state snapshots** captured on both sides per `PORTABLE-CHAIN-EXPORT-CEREMONY-2026-07.md`, so a ceremony failure does not require restarting individual stand-ups.

## The four-phase ceremony

### Phase 1 — Discovery

The Sentinel initiates by sending its standard `AgentAnnounce` envelope to the Regent's mesh endpoint. This envelope already carries Ed25519 identity, 128-bit destination hash, capability declaration, and human-readable component name per the March 2026 release. The Regent's mesh handler recognises this as an announce from a peer it has not yet co-attested with, and responds with a `CoSovereignQuery` envelope that carries the Regent's own identity, capabilities, and a nonce.

The Sentinel receives `CoSovereignQuery`, verifies the Regent's signature, and enters attested-peer-candidate state pending Phase 2. Symmetric: either node may initiate; the substrate does not care which side goes first.

Neither side commits anything to the chain in this phase. Discovery is a mesh-layer handshake; chain writes come after attestation.

### Phase 2 — Attestation exchange

Each node presents a compact attestation chain-of-custody demonstrating its Genesis-derived identity and the trust chain reach that got it to Sovereign Form. Concretely, each side sends a `SovereignAttestation` envelope containing:

- Genesis root hash (SHA-256 of the operator's Trezor-derived Genesis material — the *hash*, never the material)
- Standing correction receipt from the node's Sovereign Form assertion (§6.6 in the Pi 5 checklist; §6.3 in the mac-mini checklist), signed by the node's Genesis-derived key
- The measured-boot receipt chain establishing hardware attestation (TPM PCRs 0+2+4+7 on Pi 5; SEP measurement on Mac Mini)
- Current chain head hash and chain segment length
- Ed25519 signature over the tuple `(peer_nonce_from_phase_1, own_genesis_root_hash, own_chain_head, timestamp)` using the Genesis-derived key

The receiving side verifies: the signature over the tuple, the standing correction receipt's own signature back to the presented Genesis root, and the measured-boot receipt chain (each PCR value is one of the small set the receiver expects to see; the specific PCR values are checked against the receiver's known-good baseline for the peer's hardware type — Pi 5 baseline for Sentinel side, Mac Mini SEP baseline for Regent side).

**Critical property**: at this point each side has cryptographic evidence that the other is (a) a Sovereign Form substrate, (b) Genesis-derived from *some* Trezor-anchored root, (c) attested to a specific chain head. Neither side has yet confirmed that the other's Genesis derives from *the same operator*. That is the point of Phase 3.

### Phase 3 — Operator confirmation

The operator confirms both nodes are theirs with a single Trezor signature. Mechanically: one node (either side, whichever holds the physical Trezor connection at ceremony time) presents the operator with a Trezor prompt via CipherKeyValue with a payload containing both nodes' Genesis root hashes and both current chain head hashes. The operator touches the Trezor to confirm.

The resulting Trezor signature is the `CoSovereignConfirmation` — cryptographic proof that a single Trezor-holding operator has attested to both Genesis roots at the same ceremony time. This signature is broadcast to both nodes over the mesh channel.

The `CoSovereignConfirmation` payload is:

```
{
  "kind": "ceremony:cosovereign:confirm",
  "sentinel": {
    "genesis_root_hash": <SHA-256>,
    "chain_head_at_ceremony": <SHA-256>,
    "component_name": "ZP Sentinel — <hardware description>",
    "role": "sentinel"
  },
  "regent": {
    "genesis_root_hash": <SHA-256>,
    "chain_head_at_ceremony": <SHA-256>,
    "component_name": "APOLLO Regent",
    "role": "regent"
  },
  "confirmed_at": <RFC3339 timestamp>,
  "trezor_signature": <Ed25519 over the above, via Trezor CipherKeyValue derivation>,
  "trezor_derivation_path": <BIP32 path used>
}
```

The Trezor signature is the only irreplaceable ingredient. Nodes present the confirmation to each other, verify the signature against the operator's Trezor public key (which both nodes already hold, because their individual Genesis derivations both descend from it), and proceed to Phase 4 if verification succeeds. If the operator does not confirm within a configurable window (default 5 minutes; extendable via `ZP_COSOVEREIGN_WAIT_SECS` per L3 empirical lesson from the APOLLO regenesis), the ceremony aborts and both nodes revert to unattested-peer status.

### Phase 4 — Cross-reference commit and verification

Each node writes a `co_sovereign:established` event to its own chain segment:

```
{
  "kind": "ceremony:cosovereign:established",
  "self_role": <sentinel | regent>,
  "peer_role": <regent | sentinel>,
  "self_genesis_root_hash": <SHA-256>,
  "peer_genesis_root_hash": <SHA-256>,
  "peer_chain_head_at_ceremony": <SHA-256>,
  "confirmation_receipt": <full CoSovereignConfirmation payload>,
  "confirmation_receipt_hash": <SHA-256>,
  "cross_reference_id": <SHA-256 of concatenated sorted genesis root hashes — same value on both sides>
}
```

The `cross_reference_id` field is the load-bearing bit. It is derived deterministically from both Genesis root hashes (sort ascending, concatenate, hash) so both nodes independently compute the same value without needing to communicate it. Any future chain event that references "the co-sovereign pair" uses this ID — defensive-swap ceremonies coordinated across nodes, officer-cadre cross-attestation, Cartographer weaving, and forward-arc peer-sync protocols all reference the pair by its `cross_reference_id` rather than by the individual chain head hashes (which advance continuously).

Each node then queries the other to verify that the peer's `co_sovereign:established` event has been committed. This verification is over the mesh; the peer responds with its own commit's event ID and the chain segment length at commit time. If either side cannot verify the other's commit within a configurable window, the ceremony reports partial completion (own side committed, peer verification pending) and the operator is prompted to investigate — either node was slow to write, the mesh transport had a temporary issue, or one side committed and the other did not, and the pair status is currently inconsistent.

Successful Phase 4 completion is the ceremony's terminal state. Both sides now hold, on their own chain segments, a chain-anchored proof that they are co-sovereigns of the same operator, referenced by a shared `cross_reference_id`.

## Attack model and mitigations

Four attack surfaces to consider:

**Rogue node claiming co-sovereign status.** An attacker's node might attempt Phase 1 discovery and Phase 2 attestation exchange, presenting a plausible-looking but adversarial Genesis root. Mitigated at Phase 3: the operator's Trezor confirmation is the only way to cross the phase boundary, and the confirmation payload explicitly includes both Genesis root hashes. An attacker would need the operator's Trezor to produce a valid `CoSovereignConfirmation`, which is precisely what the Trezor-anchored Genesis is designed to prevent.

**Man-in-the-middle during discovery or attestation exchange.** An attacker intercepts Phase 1 or Phase 2 traffic on the LAN. Mitigated by end-to-end signatures: every envelope in the ceremony carries an Ed25519 signature over a nonce-including payload; intercepted-and-replayed messages fail nonce checks; substituted messages fail signature verification. Additionally, mesh transport should be TLS-wrapped in production (though the ceremony's cryptographic proofs do not require it).

**Compromised node presenting a false Genesis.** A previously-legitimate node has been compromised post-stand-up and now presents attestation with tampered data. Mitigated at attestation exchange (Phase 2): the measured-boot receipt chain and standing correction receipt must sign back to the presented Genesis root; a compromised userland cannot fabricate a full measured-boot chain because the TPM PCR values and SEP measurements are hardware-attested and independently verifiable. If the compromise is deep enough to include the TPM's Genesis-derivation state, the ceremony has no defense — but at that point the compromise is total and the substrate as a whole is not recoverable without hardware replacement anyway.

**Chain segment tampering after ceremony.** After the ceremony completes, an attacker attempts to modify a `co_sovereign:established` event or the `cross_reference_id`. Mitigated by the standard chain-anchoring discipline: chain integrity is verified via Blake3 hash-chained SQLite ledger; modifications break the hash chain and are detectable by any verifier holding a prior chain export.

**Operator coercion / Trezor duress.** An attacker forces the operator to physically confirm on the Trezor. Not mitigated by this ceremony (it is a fundamental limit of hardware-signing-device sovereignty). Composes with any future duress-detection ceremonies at a higher layer.

## Ongoing coordination after the ceremony

Once established, the co-sovereign pair enters ongoing mesh-mediated coordination. The substrate primitives that consume the `cross_reference_id`:

- **Defensive swap coordination**: if the Sentinel's network-observer flags an anomaly and requests a Regent-side defensive adapter swap, the request references the `cross_reference_id`. The Regent verifies that its own recent chain contains a `co_sovereign:established` event with this ID before honoring the swap request. Cross-referenced swap events land on both chain segments.
- **Cartographer composite view**: the Cartographer queries both chains and weaves the composite substrate view. It uses the `cross_reference_id` to identify pair-scoped events (co-sovereign coordination, cross-attestation, joint form graduations) distinct from single-node events.
- **Officer cadre cross-attestation**: officers on either side that need to attest a claim about the pair (rather than about one node alone) use the `cross_reference_id` in their attestation, so verifiers can distinguish per-node officer claims from pair-scoped officer claims.
- **Mesh capability composition**: capability queries can now return "the pair's capabilities" (union or intersection depending on query) rather than only per-node capabilities.

Heartbeats continue via the existing mesh protocol (Ed25519 identity, 30-second intervals, WebSocket topology). If either node fails to heartbeat for the threshold window (default 3 missed heartbeats — 90 seconds), the mesh marks the pair as *degraded* rather than *dissolved*. Pair status is only dissolved by explicit ceremony (see next §).

## Re-attestation and dissolution

The `cross_reference_id` is bound to a specific (Sentinel Genesis, Regent Genesis) pair. If either Genesis rotates, a new ceremony is required to establish a new `cross_reference_id`. Concretely:

- **Genesis rotation on either side** (per KEEL §XIV.5, executed via a graduation-style ceremony on the individual node): the old `cross_reference_id` becomes historical; a new ceremony run against the rotated Genesis produces a new `cross_reference_id`. Historical events remain queryable; new pair-scoped events reference the current ID.
- **Hardware replacement** (Sentinel Pi 5 or Regent Mac Mini physically replaced): the replacement runs its own stand-up ceremony (producing a fresh chain segment on the new hardware) and then runs the coordination ceremony with the surviving peer. New `cross_reference_id` results.
- **Explicit pair dissolution** (operator decides to un-pair without immediately re-pairing): a `ceremony:cosovereign:dissolved` event is signed by the operator on both chains, referencing the current `cross_reference_id`. After dissolution, subsequent chain events do not reference the ID; the pair is not automatically re-established even if both nodes remain otherwise operational.

Dissolution is different from Genesis rotation. A dissolved pair may not want to re-pair (perhaps the operator is retiring one role or changing sovereignty architecture); a rotated Genesis expects to re-pair.

## Chain event vocabulary summary

Five chain event kinds this ceremony introduces:

- `ceremony:cosovereign:preflight` — appended by each node before the ceremony starts, records preflight verifications (own stand-up complete, mesh reachable, Trezor present)
- `ceremony:cosovereign:attest` — appended by each node after Phase 2 attestation exchange, records what it received from the peer and its verification result
- `ceremony:cosovereign:confirm` — the operator's Trezor-signed confirmation payload (identical content on both chains)
- `ceremony:cosovereign:established` — the terminal commit, includes the `cross_reference_id`
- `ceremony:cosovereign:dissolved` — the explicit un-pair, references the `cross_reference_id` being dissolved

Substrate consumers (Cartographer, officer cadre, defensive-swap coordinators) subscribe to these event kinds via the existing chain-observation surface.

## Cross-references

- `HARDWARE-ROLE-SEPARATION-2026-07.md` — canonical two-role topology (this ceremony realises the coordination between the two roles)
- `pi5-sovereign-standup-checklist-2026-07-17.md` — Sentinel-side prerequisite
- `mac-mini-regent-standup-checklist-2026-07-27.md` — Regent-side prerequisite
- `PEER-DISCOVERY-AS-OUTREACH-2026-07.md` — general peer protocols this ceremony extends for co-sovereign framing
- `PORTABLE-CHAIN-EXPORT-CEREMONY-2026-07.md` — chain preservation before and after this ceremony
- `SUBSTRATE-BOOT-INVARIANT-CEREMONY-2026-07.md` — bright-line invariants that inform this ceremony's failure modes
- `tools/sentinel/zp_sentinel/mesh.py` — existing mesh protocol (AgentAnnounce, heartbeat) this ceremony extends
- `crates/zp-officers/src/sentinel.rs` — officer-cadre Sentinel role that consumes `cross_reference_id`
- (Forthcoming) `SENTINEL-V1-MVP-2026-07.md` — Sentinel v1 spec that operationalises defensive-swap coordination against this ceremony's `cross_reference_id`

## Deferred design questions

- **Multi-node co-sovereign topologies** (three or more sovereigns of the same operator, e.g., two Regents plus one Sentinel). The `cross_reference_id` derivation (sort ascending, concatenate, hash) generalises to N Genesis roots, but the ceremony's Phase 3 confirmation payload structure needs an array field rather than fixed sentinel/regent fields. Deferred to a multi-node coordination doc when the third-node use case arises concretely.
- **Cross-operator co-sovereign topologies** (a Sentinel and a Regent belonging to different operators who want mutual attestation for shared workloads). Fundamentally different ceremony because there is no single Trezor confirmation; requires multi-signature ceremony design. Deferred.
- **Ceremony over untrusted network** (Sentinel and Regent geographically separated with no LAN, communicating over public internet). The cryptographic proofs remain valid, but network-layer availability and confidentiality require additional discipline. Deferred to a remote-pair coordination doc.

---

*Authored 2026-07-27. Two-node coordination ceremony for the Sentinel↔Regent pair. Multi-node and cross-operator topologies deferred.*
