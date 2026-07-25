# Multi-Device Operation — July 2026

**Document type:** Design note. Specifies how a single operator uses multiple devices — phone, laptop, tablet, hardware wallet — while preserving Genesis-anchored identity, chain integrity, and the singular sovereign root principle. Addresses the biggest open architectural question in the current corpus: how ZeroPoint composes with the fact that real operators are plural in devices. Composes with `BACKUP-AND-RECOVERY-LANDSCAPE-2026-07.md` (Option 10, Keybase-style per-device sigchain, was flagged as closest to what ZP naturally wants); this document formalizes that approach adapted to ZP's single-chain-per-operator invariant and adds Genesis-root architecture.

**Status:** Design note. Ready for iteration; many open decisions marked. The multi-device model this document specifies is the load-bearing gap the current corpus has been treating implicitly.

**Author:** Ken Romero, with synthesis assistance from Claude.

**Date:** 2026-07-05.

---

## Part I — The Problem

Real operators are plural in devices. A phone in the pocket, a laptop at the desk, a tablet on the couch, possibly a hardware wallet in a safe, possibly a second laptop for work vs. personal. Each device runs its own instance of the operator's substrate — chain replicas, Regent instances, cached derived state — and each needs to sign actions on the operator's behalf.

The current substrate documents implicitly assume single-device operation. Multi-device is treated as a "yes we'll handle that" without specification. This document specifies it.

### 1.1 What operators actually need across devices

- **Cryptographic identity** — the ability to sign as themselves from any authorized device.
- **Chain access** — the ability to see the substrate's history from any authorized device, without needing to physically fetch it from another device.
- **Session continuity** — starting a conversation with the Regent on a phone and continuing it on a laptop should not lose context.
- **Derived state availability** — Cartographer ontology, subscription filters, contact records, community memberships should be available on every authorized device.
- **Governance from anywhere** — flagged trajectories, acknowledgment requests, mandate approvals should be actionable from whichever device the operator is holding.
- **Loss tolerance** — losing a device should be inconvenient, not catastrophic. Identity should survive.
- **Revocation** — compromised devices should be revocable without abandoning the identity.

### 1.2 What ZP's design commitments constrain

- **One chain per operator** (invariant I-2). Multiple devices append to the same chain; there is not one-chain-per-device.
- **Genesis-derived key hierarchy** (invariant I-1). All authority derives from Genesis.
- **Singular sovereign root principle.** One authentication unlocks derived material within a session context.
- **No center.** Devices coordinate peer-to-peer; there is no central server storing device state.
- **Sovereignty preserved.** No third party can override an operator's control of their own instance regardless of which device they're on.

### 1.3 Where the tensions are

- **Genesis portability vs. exposure.** Copying Genesis to every device gives every device full authority but multiplies compromise risk. Not copying means only one device is "the real one."
- **Single chain vs. distributed writers.** All devices append to one chain; without coordination, forks occur.
- **Singular sovereign root vs. multiple devices.** Naive reading: "one authentication per operator lifetime." Realistic reading: "one authentication per session context per device." Reconciliation matters.
- **Derived state sync vs. per-device Regent.** Each device has its own Regent instance; they need shared understanding without a central coordinator.

The design that follows resolves these tensions by treating each device as a scoped delegation from Genesis, with the chain as a shared append-only structure that all devices sync toward causal consistency.

---

## Part II — Design Principles

Five principles shape the design.

**Every device signs as itself.** Each device has its own signing key. Every action the device takes is signed by that device's key. There is no "signed by the operator" ambiguity — receipts always show which specific device signed.

**Genesis authorizes; devices act.** Genesis is not used for routine signing. Genesis is used to authorize device signing keys via provisioning receipts. Once a device is provisioned, it signs its own actions without invoking Genesis. Genesis re-emerges only for high-stakes actions: provisioning new devices, revoking existing devices, key rotation ceremonies.

**The chain is singular; devices sync.** There is one operator chain. Each device maintains a local mirror. Devices sync peer-to-peer whenever they can reach each other. Conflicts (simultaneous appends from devices out of contact) are resolved via causal ordering and merge receipts.

**Compromise is per-device; revocation is chain-anchored.** A compromised device's authority extends only to what that device was authorized to do. Revocation is a chain event signed by Genesis (or by a device with revocation authority per its provisioning); post-revocation, actions signed by the revoked device are rejected by peers and by the operator's other devices.

**Singular sovereign root applies per authenticated context.** The principle is not weakened by multi-device; it is reframed. Within a single device's session, one authentication unlocks derived material for that process. Across devices, each device has been provisioned via a Genesis-level ceremony that was itself a singular sovereign root event. The principle scales cleanly; it does not require all devices to share a single authentication in real time.

---

## Part III — The Key Hierarchy Extended for Multi-Device

Multi-device requires extending the key hierarchy from `whitepaper-v9.md` §5.5.

### 3.1 The extended hierarchy

```
Genesis Root
  │
  ├─ Genesis Signing Key (Ed25519)
  │    └─ Used for: high-stakes ceremonies (device provisioning,
  │       device revocation, key rotation, sovereign delegations)
  │
  ├─ Genesis Vault Master Key (derived via HKDF)
  │    └─ Used for: sealing sensitive material that must survive
  │       device turnover (backup keys, quorum seeds)
  │
  └─ Device Provisioning Chain
       │
       ├─ Device A Signing Key ─── Provisioning Receipt A
       │    └─ Used for: routine signing on Device A
       │
       ├─ Device B Signing Key ─── Provisioning Receipt B
       │    └─ Used for: routine signing on Device B
       │
       └─ ... (per device)
```

### 3.2 Where Genesis lives

**Recommended:** Genesis root material is held on a hardware root — a hardware wallet (Trezor, YubiKey, dedicated ZP hardware token). The hardware root is offline most of the time. It is brought online only for high-stakes ceremonies.

**Alternative:** Genesis is split across an M-of-N hardware quorum via Shamir Secret Sharing. Signing Genesis-level actions requires M of N. Compromise of fewer than M devices does not compromise Genesis. This composes cleanly with the backup-and-recovery landscape's Composition A (Sovereign Purist).

**Not recommended:** Genesis held on a daily-use device. This concentrates compromise risk on the device most exposed to attack.

### 3.3 Device signing keys are device-derived

When a new device is provisioned, its signing key is generated on the device itself using the device's hardware entropy (Secure Enclave on iOS, StrongBox on Android, TPM on Linux/Windows, dedicated secure element on hardware wallets). The device signing key never leaves the device. Genesis authorizes the key; it does not generate it.

This means:
- Each device's signing key is protected by that device's own sovereignty provider.
- Compromise of one device does not expose other devices' keys.
- Devices can enroll their biometric or PIN independently.

### 3.4 Provisioning receipts

A device provisioning receipt is a chain event signed by Genesis containing:

- The device's public signing key
- Human-readable device identifier ("Ken's phone", "MacBook Pro")
- Device type (phone / laptop / hardware wallet / view-only display / etc.)
- Authorized capability scope (what this device can sign for — see §4.2)
- Time bound (optional expiration; recommended for high-security contexts)
- Sovereignty provider fingerprint (which hardware the device uses to protect its signing key)
- Genesis signature

Once published, the receipt is chain-visible. Peers who interact with any of the operator's devices can verify device authorization by walking to the provisioning receipt and checking the Genesis signature.

### 3.5 Rotation and revocation

Device signing key rotation is a chain event: the device's outgoing key signs a rotation receipt authorizing its own new key. The new key inherits the same provisioning scope. Rotation can happen without Genesis involvement because the outgoing device is authorized to rotate its own key within its provisioning scope.

Device revocation is a chain event signed by Genesis (or by another authorized device, per §4.3). The revocation receipt declares the target device's key revoked as of this receipt's timestamp. Post-revocation, actions signed by that key are rejected. Peers observe the revocation via chain sync and update their acceptance state.

---

## Part IV — Device Provisioning

The ceremony by which a new device is authorized to sign on the operator's behalf.

### 4.1 The ceremony

1. The operator brings the new device (Device N) and the Genesis hardware root together.
2. Device N generates a signing keypair using its hardware entropy. The public key is displayed.
3. The operator uses the Genesis hardware root to sign a provisioning receipt naming Device N's public key.
4. The provisioning receipt is published to the operator's chain.
5. Device N receives its chain (via sync from another device or via seed peers) and verifies the provisioning receipt from the Genesis signature.
6. Device N is now authorized.

The ceremony requires physical proximity (or verified secure channel) between the new device and the Genesis root. It is not a remote flow; it is an in-person or authenticated-remote event.

### 4.2 Capability scope per device

Not all devices need equal authority. Provisioning receipts can scope what a device is authorized to sign for:

- **Full-signing device.** Can sign any action the operator would sign, including issuing new delegations. Typical for primary laptop.
- **Communication device.** Can sign community-surface actions, personal messages, media publications. Cannot issue high-stakes delegations or approve large cloud-compute mandates. Typical for phone.
- **View-only device.** Can decrypt and view chain state but cannot sign. Typical for a display device or a device shared with a household.
- **Emergency-only device.** Can sign specific pre-authorized emergency actions but not routine ones. Typical for a hardware wallet held in a safe.
- **Working-group device.** Can sign only for specific communities or contexts, useful for role-scoped devices.

Scope is enforced structurally: the operator's other devices reject actions from Device N that exceed Device N's provisioned scope, even if Device N tries to sign them.

### 4.3 Delegation of provisioning authority

Genesis root ceremonies are inconvenient. For operators with many devices, Genesis can delegate provisioning authority to a specific device (typically the primary laptop or a dedicated management device). That device holds a delegation-issuance capability grant, chain-anchored, revocable.

The delegated device can then provision additional daily-use devices without invoking Genesis. Compromise of the delegated device is bounded — it can provision new devices but cannot exceed Genesis's own authority; Genesis can revoke the delegation at any time.

Recommended pattern: Genesis provisions one primary device with full provisioning authority; the primary device provisions others; Genesis remains offline except for revoking the primary device if needed.

### 4.4 First device (bootstrap)

The first device is the bootstrap: the operator performs Genesis on it (or on a hardware wallet connected to it). At Genesis, that first device is implicitly provisioned as a full-signing device. Subsequent devices are provisioned via the ceremony above.

If the first device is a hardware wallet, the operator needs a display device to see chain state; a view-only device can serve until a full daily-use device is provisioned.

---

## Part V — Chain Synchronization

Every device maintains a local mirror of the operator's chain. Devices sync peer-to-peer.

### 5.1 Local mirrors

Each device holds:
- Its own signing key and provisioning receipt
- A local copy of the operator's full chain (or the portion the device is authorized to see)
- Cached derived state (Cartographer ontology fragments, Regent memory, contact records)

The local mirror is authoritative for that device's own view. All read operations happen locally without network dependency. Only sync operations require peer contact.

### 5.2 Sync protocol

When two of the operator's devices come into contact (same local network, mesh reachability, or direct pairing), they sync their chain views:

1. Each device presents its chain tip hash and the timestamp of its most recent receipt.
2. Devices identify the divergence point — the last receipt both devices agree on.
3. Each device fetches receipts from the other that follow the divergence point.
4. Each device verifies the received receipts (signatures valid, hash-linked correctly, signed by an authorized device key).
5. Each device integrates the new receipts into its local chain.

Sync is idempotent — running it again produces no change if devices are already in sync. Sync is authenticated — receipts are only accepted if signed by keys authorized in provisioning receipts that both devices agree on.

### 5.3 Conflict resolution and merge receipts

If two devices sign receipts at nearly the same time while out of contact with each other, both receipts claim to succeed the same parent receipt. This is a fork.

Fork resolution:
1. When the devices sync, both forks are visible.
2. The operator's substrate creates a merge receipt: it references both forks as parents and continues the chain from there.
3. Merge receipts are signed by whichever device notices the fork first (or by a designated primary device if configured).
4. Both forks remain visible in the chain history; the merge point is where they reconcile.

Merge receipts are rare in practice because most operators are active on one device at a time. When they occur, they are chain-visible and auditable.

### 5.4 Consistency guarantees

- **Eventual consistency.** All authorized devices eventually converge on the same chain state.
- **Causal consistency.** If Device A signed receipt X and Device B later signs receipt Y, and Device B has seen X, then Y correctly links to X.
- **Fork visibility.** All forks are chain-visible; the operator can see they occurred and see the merge points.
- **No silent data loss.** No receipt is dropped in the reconciliation process; both forks remain in history.

The chain is not strictly totally ordered across devices, but every fork produces a merge receipt that documents the reconciliation.

### 5.5 Sync over mesh

The peer-discovery mesh (per `PEER-DISCOVERY-AS-OUTREACH-2026-07.md`) carries device-sync traffic between the operator's devices when they are not on the same local network. Sync traffic is authenticated (only the operator's authorized devices can sync) and encrypted (device-to-device HPKE per the encrypted storage architecture).

An operator whose phone is on cellular and laptop is at home can still sync via mesh relay — the phone's traffic reaches the laptop via any intermediate mesh peer, but the payload is encrypted such that only the target device can decrypt.

---

## Part VI — Derived State Across Devices

Chain state is one problem; derived state (Cartographer ontology, Regent memory, cached commons priors) is another.

### 6.1 Derived state is re-derivable

The Cartographer's ontology is deterministically derivable from the chain. Given the same chain state and the same Cartographer implementation, every device produces the same ontology. This means derived state does not need to be synchronized directly — it can be re-derived on each device from the synced chain.

### 6.2 Re-derivation is expensive; caching matters

Re-deriving the full ontology after a chain sync is computationally nontrivial. Devices cache derived state and invalidate the cache incrementally:

- When new receipts arrive that would affect ontology objects, only those objects re-derive.
- Most receipts affect only a few ontology objects; incremental re-derivation is fast.
- Full re-derivation is triggered only on Cartographer version changes or explicit operator request.

### 6.3 Regent memory synchronization

The Regent's session memory is ephemeral by design (per `ENCRYPTED-STORAGE-ARCHITECTURE-2026-07.md` §6.3). Cross-device Regent session continuity requires either:

**Option A: No cross-device session continuity.** Each device's Regent is independent. When the operator moves to a new device, they start a new Regent session. Session context is lost; the operator briefs the Regent on what they were doing. Simplest.

**Option B: Explicit handoff.** When the operator wants to move a session across devices, they invoke a handoff. The source device packages the session state (encrypted end-to-end using the operator's key hierarchy) and transmits it to the target device via the sync protocol. The target device's Regent picks up where the source left off.

**Option C: Continuous session sync.** Regent session state syncs continuously between devices in real time. The operator can pick up any device and continue seamlessly. Expensive in sync overhead; complex to keep consistent; may cross privacy boundaries the operator would prefer not to cross.

**Recommendation:** Option B (explicit handoff) as the default. It gives the operator control over when session state moves between devices, matches how most people actually work (they don't switch devices constantly), and is simple to implement.

### 6.4 Contact records, subscription filters, personal state

These sync alongside chain state. They live in encrypted local storage per the storage architecture and sync via the peer-to-peer device-sync channel. Small enough that continuous sync is cheap.

---

## Part VII — Regent Per Device

Each device runs its own Regent instance. The instances coordinate via the chain and via explicit handoff.

### 7.1 Independent instances

Every device with a Regent runs it locally. The Regent on the phone and the Regent on the laptop are not the same process; they are two instances of the same operator's cognitive layer, running in different execution contexts, sharing the same chain view.

This means:
- Regents on different devices can disagree in real time if they haven't synced.
- Once synced, they converge on the same understanding.
- Model choice can vary per device — the phone might run a smaller local model; the laptop might run a larger one. The operator configures per-device.

### 7.2 Cross-device presence

Multiple Regent instances raise the question of how the operator's presence is represented across devices to the outside world. When Ken is interacting with his phone's Regent, is his laptop's Regent also considered active?

Recommendation: only one Regent is the primary presence at a time. The operator designates a primary device when active on it; the Regent on the primary device represents the operator externally (responds to peer-discovery announces, handles incoming DMs, etc.). Other Regent instances are passive — they observe but don't act externally.

Primacy is transferred via handoff or explicit "become primary" action on a device. The transfer is a chain event so peers can see which device is currently primary.

### 7.3 Delegation authority per device

Devices provisioned with delegation-issuance authority can create capability grants for tools, sub-agents, and mandates. Devices without that authority cannot. This matches §4.2's capability-scope enforcement.

An operator's phone might not be authorized to issue high-stakes delegations, requiring the operator to move to the laptop for those specific operations. This is a security-usability tradeoff the operator sets at provisioning.

---

## Part VIII — Revocation and Loss

Device loss and compromise are ordinary operational events. The substrate handles them without abandoning identity.

### 8.1 Device loss scenarios

- **Physical loss without compromise.** Phone drops in a river; laptop is stolen but locked with strong biometrics. The device is lost but its signing key was not exposed. The operator revokes the device from another device (per §8.2) and continues.
- **Loss with compromise.** Device is stolen and its authentication is defeated (weak PIN, biometric compromised, sophisticated attack). The attacker can sign as the device until revoked. Revoke as soon as loss is discovered; damage is bounded by the device's provisioning scope.
- **Suspected compromise.** Malware detected on a device or the operator suspects code execution as themselves. Revoke defensively; provision a replacement device on new hardware.

### 8.2 Revocation flow

1. The operator uses another authorized device (or the Genesis root) to sign a revocation receipt naming the target device's signing key.
2. The revocation receipt is published to the chain.
3. All other devices receive the revocation via sync and update their acceptance state.
4. Post-revocation, receipts signed by the revoked key are rejected by peers and by the operator's other devices.
5. Actions in flight (already signed but not yet propagated) may or may not go through depending on timing; peers use the revocation timestamp for arbitration.

Revocation is authorized by the device's provisioning-authority chain — Genesis, or a device with delegated revocation authority.

### 8.3 What survives revocation

The operator's identity is not lost when a device is revoked. Other devices remain authorized. Chain state is preserved on all devices that have synced. Session continuity on non-revoked devices is undisturbed. Derived state is re-derivable.

What is lost:
- The specific session state on the revoked device (unless the operator had handed it off before loss).
- Chain data unique to the revoked device that hadn't yet synced elsewhere. This is why sync frequency matters — devices that go long periods without syncing risk losing recent activity if compromised.

### 8.4 If all devices are lost

If the operator loses all their daily-use devices simultaneously (fire, theft, complete infrastructure loss), they need the Genesis root plus at least one new device to recover:

1. Provision a new device from the Genesis root.
2. Sync chain from any external source — peer chain replication (per Backup and Recovery Landscape Option 13), a mesh peer they trust, a backup they made previously.
3. Once chain state is recovered, revoke the lost devices.
4. Rebuild session state, derived caches, and personal configuration.

Full recovery is possible if Genesis root survives. If Genesis root is also lost, the operator is in the backup-and-recovery scenario named in that landscape document — Composition A through E provide different paths.

---

## Part IX — Threat Model

Threats specific to multi-device operation.

### 9.1 Single device compromise

**Attack:** Adversary compromises one of the operator's devices — code execution as the operator, biometric defeat, physical access with authentication broken.

**Defense:** The device's authority is bounded by its provisioning scope. Compromise does not automatically extend to the operator's full authority. Other devices remain uncompromised. Revocation is available from any other authorized device.

**Residual risk:** For the duration between compromise and revocation, the adversary can act within the device's scope. Damage is scope-bounded but real.

### 9.2 Multi-device compromise

**Attack:** Adversary compromises multiple devices simultaneously — coordinated attack, supply chain compromise across manufacturers.

**Defense:** Genesis root is separately protected (offline, hardware wallet, potentially M-of-N quorum). Even multi-device compromise does not compromise Genesis unless the Genesis root is also compromised. Genesis can revoke all compromised devices in one ceremony.

**Residual risk:** If enough devices are compromised, and the operator does not have physical access to the Genesis root, they cannot revoke in time. This is why offline Genesis root and geographic separation matter.

### 9.3 Sync channel compromise

**Attack:** Adversary intercepts device-to-device sync traffic.

**Defense:** Sync traffic is end-to-end encrypted using HPKE against the target device's public key. Man-in-the-middle attacks fail because both endpoints authenticate via their provisioning receipts.

**Residual risk:** Metadata leakage (that the operator is syncing, at what times, at what volumes) is possible even with encrypted content.

### 9.4 Fork attack

**Attack:** Adversary controls one device and signs receipts that contradict the operator's other devices' state — trying to convince peers that the chain has moved in a different direction.

**Defense:** All authorized devices see all receipts eventually. Forks are chain-visible. If a device produces receipts that no other authorized device recognizes, the fork is anomalous and peers can flag it. Aegis and Steward would produce findings.

**Residual risk:** In the window before the fork is detected, peers may accept receipts from the compromised device. Reputation dynamics eventually correct this.

### 9.5 Provisioning-authority abuse

**Attack:** A device with delegated provisioning authority provisions unauthorized new devices.

**Defense:** Provisioning receipts are chain-visible. The operator sees all provisioning events. If unauthorized provisioning occurs, the operator revokes the abusive device via Genesis. The provisioning-authority delegation itself is revocable.

**Residual risk:** For the duration between abuse and detection, unauthorized devices exist. Their capability is bounded by the provisioning-authority's own scope, which is bounded by Genesis's delegation.

### 9.6 View-only device compromise

**Attack:** A view-only device is compromised. Adversary can read chain state but cannot sign.

**Defense:** View-only devices cannot exceed their read-only capability. Compromise exposes chain state to the adversary but does not enable actions on the operator's behalf.

**Residual risk:** Chain state exposure. Encrypted with the device's derived key hierarchy; compromise of view-only device's authentication is required to decrypt. Still, a compromise is an information disclosure.

---

## Part X — Composition with Backup and Recovery

Multi-device operation and backup/recovery are the same architectural problem viewed from different angles. This document composes with `BACKUP-AND-RECOVERY-LANDSCAPE-2026-07.md`.

### 10.1 Multi-device as natural backup

Every authorized device is a full copy of the operator's chain state. Losing any one device does not lose the identity, because other devices have the state. Multi-device operation is, incidentally, a distributed backup mechanism.

This changes the backup calculus. An operator running the Consumer Baseline composition (Landscape Composition E) actually gets more resilience than the composition alone suggests, because their multi-device setup provides implicit chain replication.

### 10.2 Composition with Shamir sharing for Genesis root

Genesis root protection can compose with Shamir Secret Sharing (Landscape Option 2). The Genesis seed is split into K-of-N shares held on different hardware roots. Signing Genesis-level actions (device provisioning, revocation) requires K of N. This adds robustness against Genesis root compromise or loss.

Practical shape:
- 2-of-3 shares: primary hardware wallet, backup hardware wallet, offline paper share in a safe.
- 3-of-5 shares: three hardware roots, two paper shares in geographically separate locations.
- Higher thresholds for high-value operators.

### 10.3 Composition with peer chain replication

Peer chain replication (Landscape Option 13) composes with device sync. An operator can replicate their chain to trusted peers in addition to syncing across their own devices. This provides recovery in the "all devices lost" scenario.

### 10.4 Composition with the Regent's guidance

The Regent surfaces device state to the operator via the compartmentalization surface (per `REGENT-COMPARTMENTALIZATION-2026-07.md`) — which devices are authorized, which are currently active, which have not synced recently, which have unusual activity patterns. Cross-device visibility is a Regent responsibility.

---

## Part XI — Composition with the Singular Sovereign Root Principle

The singular sovereign root principle needs to be reframed clearly for multi-device.

### 11.1 The principle, restated for multi-device

- **Per-session-context.** Within any single process on any single device, one authentication unlocks the derived material for that session. Multiple credential-store entries for governance material on the same device remain an anti-pattern.
- **Per-device provisioning.** Each device is provisioned via a Genesis-level ceremony that is itself a singular sovereign root event. The ceremony unlocks Genesis for a bounded action (provisioning) with a specific outcome (the new device's authorization).
- **Cross-device authentication.** Each device authenticates independently. When the operator moves from phone to laptop, they authenticate on the laptop separately. This is not "multiple sovereign roots for one session"; it is "one sovereign root per per-device session."

### 11.2 Why this preserves the principle

The principle's purpose is to prevent authentication proliferation within a single context. Every derived key within a session traces to one operator consent. Multi-device does not violate this because each device is its own context. The operator's consent on the phone (biometric unlock) authorizes the phone's session; the operator's consent on the laptop authorizes the laptop's session; each is a singular root event.

What multi-device does not do:
- Does not require the operator to authenticate on all devices simultaneously.
- Does not share unlocked vault material across devices.
- Does not treat device authentications as fungible.

Each authentication unlocks exactly the material on the device where it happened. Cross-device operations (sync, handoff) use the authentication that was already performed on each side.

### 11.3 The quorum extension

M-of-N Genesis root (§10.2) is compatible with the principle. Signing a Genesis-level action requires M authentications, all of which happen at the same ceremony. The ceremony is one singular sovereign root event in aggregate — one operator intent, expressed through M-of-N authentications.

---

## Part XII — Open Design Decisions

Extracted throughout:

1. **Genesis root architecture default.** Single hardware wallet vs. M-of-N quorum. Recommendation depends on operator persona; likely default is single with clearly-documented upgrade path.

2. **Provisioning-authority default.** Does Genesis provision every device directly, or does Genesis provision a primary device that then provisions others? Trade-off between ceremony frequency and delegation attack surface.

3. **Regent handoff mechanics.** Explicit handoff (Option B) recommended; specific handoff wire format and encryption approach need spec.

4. **Cross-device presence protocol.** How the "primary device" designation propagates and how peers know which device is currently primary.

5. **View-only device capability spec.** What exactly a view-only device can and cannot decrypt. Compartmentalization within a view-only device.

6. **Sync cadence defaults.** How often devices attempt to sync when reachable. Trade-off between currency and battery/bandwidth.

7. **Merge receipt authorship.** Which device produces merge receipts when a fork is detected. Options: whichever device first observes both forks; a designated primary device; deterministic election.

8. **Provisioning capability-scope taxonomy.** Full-signing, communication, view-only, emergency-only, working-group — is this the right taxonomy? What about custom scopes?

9. **Delegated provisioning revocation.** How the delegation-issuance capability is revoked, and whether devices provisioned by a revoked delegation-authority remain authorized or are cascade-revoked.

10. **View-only device chain visibility.** Does a view-only device see the whole chain or a filtered view? Compartmentalization considerations.

11. **First-device onboarding UX.** The Genesis ceremony is well-defined; the first-device provisioning at Genesis moment needs UX design.

12. **Emergency device.** Should an "emergency-only device" pattern be a first-class ZP primitive, with specific pre-authorized actions (initiate revocation, sound alert to peers, publish distress signal)?

---

## Part XIII — Composition with Other Design Work

- `docs/ARCHITECTURE-2026-07.md` — the singular sovereign root principle in Part I §3 that this document reframes for multi-device without weakening.
- `docs/whitepaper-v9.md` — §5.5 (Genesis and key hierarchy) is extended by this document to include the per-device provisioning layer.
- `docs/design/BACKUP-AND-RECOVERY-LANDSCAPE-2026-07.md` — Option 10 (Keybase-style per-device sigchain) was flagged as closest to what ZP naturally wants; this document formalizes that approach. Composition A through E all interact with multi-device operation.
- `docs/design/ENCRYPTED-STORAGE-ARCHITECTURE-2026-07.md` — the key hierarchy this document extends; per-device signing keys derive from the same conceptual model.
- `docs/design/PEER-DISCOVERY-AS-OUTREACH-2026-07.md` — the mesh transport that carries cross-device sync traffic when devices are not on the same local network.
- `docs/design/REGENT-COMPARTMENTALIZATION-2026-07.md` — the Regent's role in helping the operator maintain awareness of device state and cross-device compartmentalization. Multi-device Regent visibility is an open decision named in that note; this document begins to answer it.
- `docs/design/SUPERSESSION-FRAMEWORK-2026-07.md` — device provisioning, sync protocol, and revocation mechanics are all mechanisms subject to future ZEPs.
- `docs/design/TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT-2026-07.md` — Aegis and the other officers observe across device sync boundaries; his cross-device visibility is worth naming.

---

## Part XIV — Closing

Multi-device operation was the biggest architectural gap the corpus had been treating implicitly. The design here — device as scoped delegation from Genesis, per-device signing keys, chain sync via peer-to-peer with merge receipts, singular sovereign root applied per authenticated context — resolves the tensions without weakening any of the substrate's core invariants.

Every device signs as itself. Genesis authorizes; devices act. The chain remains singular. Compromise is per-device. The operator's identity survives device loss, device theft, and even Genesis-root loss (via the recovery paths in the backup and recovery landscape).

The corpus can now describe multi-device operation coherently. Where earlier documents said "yes we handle that," they can now point here.

---

*Real operators are plural in devices. ZeroPoint composes with that reality by treating each device as a scoped delegation from Genesis, provisioned via a ceremony, revocable individually, signing as itself. The chain remains singular; devices sync it. The Regent runs per device; instances coordinate via chain and explicit handoff. The singular sovereign root principle applies per authenticated context, not per operator lifetime. Every design commitment survives; every device is honestly what it is.*
