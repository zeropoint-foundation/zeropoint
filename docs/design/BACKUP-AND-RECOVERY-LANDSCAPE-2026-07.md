# Backup and Recovery Landscape — July 2026

**Document type:** Research survey. Not a decision doc; not a recommendation. This document maps the current landscape of backup and recovery approaches from crypto wallets, sovereign identity systems, secure messaging protocols, and adjacent domains, and evaluates each against ZeroPoint's sovereignty-first design principles. Purpose: menu before ordering. When a decision is made, a follow-on design note will specify the chosen approach.

**Status:** Survey. Complete-enough for Ken to evaluate the option space.

**Author:** Ken Romero, with synthesis assistance from Claude.

**Date:** 2026-07-05.

---

## Part I — What We're Actually Backing Up

Before evaluating options, name the three distinct problems that "backup and recovery" collapses in ordinary conversation:

**1. The Genesis identity secret.** The 32-byte Ed25519 seed from which all trust in the deployment derives. Losing this is losing the operator's identity in the strong sense — every capability grant, every attestation, every historical action was anchored to it. Not recoverable from anywhere except a copy of the secret itself.

**2. The chain state.** The sequence of signed receipts that constitutes the operator's history. Chain state is derivable from Genesis given all receipts — but if the receipts themselves are lost, the operator's history is lost. Peers who saw those receipts may hold copies, but there's no central place to fetch from.

**3. The derived state.** The Cartographer's ontology (Trajectories, Decisions, Insights, Artifacts, Frictions), the Regent's session memory, subscription filter configurations, cached commons priors, learned attention patterns. All computable from chain state given time and compute, but the compute is nontrivial and the immediate operator experience depends on this state being warm.

These three are separable problems with different constraints. A backup approach can address one, two, or all three. Approaches that only address (1) leave (2) and (3) as separate concerns. Approaches that try to address all three at once make different trade-offs than approaches that focus.

Most of the survey below is about (1) — because that's the hardest problem and the one where most existing approaches focus. (2) is a peer-replication problem discussed briefly. (3) is a derived-state re-derivation problem discussed briefly.

---

## Part II — ZP's Constraints (the filter every option passes through)

Every option below is evaluated against six ZP-specific properties. An option that violates any of these introduces a fundamental compromise with ZP's philosophy; whether that's acceptable is a judgment call, but the compromise should be visible.

**Sovereignty preservation.** No third party — including the Foundation — should be able to recover an operator's identity without the operator's explicit prior authorization. If a third party can recover, they can also be compelled to recover, which means they hold the identity in practice.

**No center.** Recovery mechanisms should not require a Foundation-run service to function. A Foundation service can *support* recovery (as a convenience, as a peer among many), but the substrate should work without it.

**Singular sovereign root.** One operator authentication should unlock the derived material for a process. Recovery mechanisms that require multiple simultaneous authentications (each with its own credential store) violate this principle.

**Chain-anchored.** Recovery events themselves should be chain receipts. "I recovered my identity on this date via this mechanism with these witnesses" should be a chain-visible event, verifiable by peers, subject to normal governance.

**Append-only compatible.** The chain cannot be rewound. Recovery cannot mean "restore chain to a prior state"; it must mean "re-anchor identity forward from wherever the chain currently is." This constrains what "backup" of chain state can even mean.

**Structural, not policy.** Defenses that rely on organizations behaving well ("we promise not to abuse the recovery key we hold") are weaker than defenses that make bad behavior structurally impossible. Where the option requires trust, name it explicitly.

---

## Part III — The Menu

Each option below has: what it is, reference implementations, how it composes with the six ZP constraints, what it introduces as trade-offs, and a summary line.

### Option 1: Seed phrases (BIP-39 style)

**What it is.** The Genesis secret is encoded as a mnemonic sequence of words (typically 12 or 24 words drawn from a 2048-word list). The operator writes down or memorizes the phrase; recovery means re-entering the phrase to reconstruct the secret.

**Reference implementations.** Nearly every crypto wallet — Bitcoin (BIP-39), Ethereum, Solana, Cosmos, most hardware wallets (Ledger, Trezor's default). BIP-39 is the dominant standard.

**Composition with ZP constraints:**
- **Sovereignty preservation:** ✓ The phrase is held only by the operator. No third party knows it.
- **No center:** ✓ Fully offline.
- **Singular sovereign root:** ✓ One authentication (typing the phrase) unlocks everything.
- **Chain-anchored:** Partial. The recovery event can be a chain receipt, but the phrase itself is not chain-derived — it's the raw secret.
- **Append-only compatible:** ✓ Recovery re-derives keys but doesn't rewind chain.
- **Structural, not policy:** ✓ No trust in others required.

**Trade-offs introduced.**
- **Single point of failure at the operator side.** Loss of the phrase means loss of the identity, period.
- **Theft equals total compromise.** Anyone who acquires the phrase acquires the identity.
- **Storage burden falls entirely on operator.** Paper, metal seed backup plates, safe deposit boxes, splitting for paranoid storage.
- **User experience is terrible in one specific way:** the phrase has to be *written down correctly* and *stored durably* immediately after Genesis. Many operators skip or defer this and lose their identity later.
- **No inheritance mechanism.** If the operator dies without arranging phrase disclosure, the identity is unrecoverable.

**Summary:** The purest sovereign-aligned approach. Also the most operator-hostile for people who aren't already crypto-literate. Everything depends on the operator not losing a piece of paper.

---

### Option 2: Shamir Secret Sharing (SLIP-39)

**What it is.** Split the Genesis secret into N shares such that any K of them can reconstruct it (K-of-N threshold). Below the threshold, shares reveal nothing about the secret. Store shares in separate locations; a single share can be lost without losing the identity, a single share can be stolen without exposing the identity.

**Reference implementations.** SLIP-39 (Trezor's standard). Supported natively by Trezor Model T, Trezor Safe 3, Trezor Safe 5, Keystone 3 Pro, SeedSigner. Not supported by Ledger. Vault12 Guard uses a variant. Uses a distinct 1024-word list from BIP-39 to prevent confusion between formats.

**Composition with ZP constraints:**
- **Sovereignty preservation:** ✓ Shares held only by the operator (or by parties the operator delegates to hold shares).
- **No center:** ✓ Fully offline; no central service.
- **Singular sovereign root:** ✓ Recovery reconstructs the single Genesis secret.
- **Chain-anchored:** Partial. Share generation and recovery events can be chain-receipted.
- **Append-only compatible:** ✓ Same as seed phrase.
- **Structural, not policy:** ✓ K-of-N is mathematical, not trust-based. Below threshold shares reveal nothing.

**Trade-offs introduced.**
- **Better than raw seed against partial loss.** Losing one share doesn't lose the identity.
- **Better than raw seed against partial theft.** Stealing one share doesn't compromise the identity (below threshold).
- **Substantially more complex.** Multiple shares to manage, distribute, retrieve. Cognitive burden higher.
- **Coordinated attacks still possible.** Adversary who compromises K shares owns the identity.
- **Share generation ceremony matters.** Bad randomness at share generation compromises the scheme.
- **Reshare when a share is lost.** Best practice says regenerate shares after any share is lost or unaccounted for — because the missing share could be in adversary hands. This creates operational burden.

**Summary:** Cryptographically clean upgrade to seed phrases. Real improvement against single-point-of-failure scenarios. More complexity for the operator. Compositionally sovereign — no trust in third parties required.

---

### Option 3: M-of-N Social Recovery (Guardians)

**What it is.** Designate a set of trusted parties (friends, family, hardware devices, institutional custodians) as guardians. Any M of N guardians can collectively authorize a key rotation, allowing the operator to recover from a lost primary credential. Guardians don't hold shares of the identity secret — they hold authorization to attest that a new key should replace the old one.

**Reference implementations.** Argent (Ethereum smart contract wallet; guardians can approve key rotations). Loopring. Safe (formerly Gnosis Safe) with multisig guardian patterns. ERC-4337 account-abstraction wallets often bake this in as a native affordance. DID methods for self-sovereign identity commonly propose social-recovery patterns for lost keys.

**Composition with ZP constraints:**
- **Sovereignty preservation:** ⚠ Partial. Guardians can collectively rotate the operator's key without operator consent (if M guardians collude). The operator's sovereignty is contingent on guardian honesty.
- **No center:** ✓ Guardians can be independent peers; no central service required.
- **Singular sovereign root:** ⚠ Recovery is a distributed authentication involving M guardians, which conflicts with the principle. But normal operation retains singular root.
- **Chain-anchored:** ✓ Guardian designation, revocation, and recovery events are all chain receipts.
- **Append-only compatible:** ✓ Recovery is key rotation forward, not chain rewind.
- **Structural, not policy:** ⚠ M-of-N is structural (below threshold guardians can't act) but requires trust that guardians won't collude against the operator.

**Trade-offs introduced.**
- **Recovers from lost primary credential without seed phrase burden.** The operator doesn't have to store a piece of paper.
- **Guardian collusion risk.** M colluding guardians can seize the identity. In practice this requires guardians who know each other, motivated to collude, coordinating to attack. Real but bounded risk.
- **Guardian coercion risk.** Guardians can be pressured (legal, physical, social) to authorize a recovery the operator doesn't want.
- **Guardian availability risk.** Guardians die, become unavailable, lose their own keys. The operator must maintain a healthy guardian set over time.
- **Guardian selection is a UX problem.** New users don't know who to trust; wrong initial choices can be hard to undo.
- **Real social dynamics matter.** Making your ex-partner a guardian is a decision you might later regret.

**Summary:** Substantially better user experience than seed phrases. Real sovereignty compromise: the operator's identity is only as safe as their guardians. Suitable for operators who have trustworthy social/institutional relationships; problematic for operators who don't.

---

### Option 4: MPC / Threshold Signatures with Provider Server

**What it is.** The Genesis secret is split across two or more parties using Multi-Party Computation. The operator's device holds one share; a provider server holds another. Signing requires cooperation between them — neither can sign alone. Recovery involves re-establishing the client share via biometric or backup mechanism; the server share persists.

**Reference implementations.** ZenGo (client + ZenGo server with 3-factor recovery: email, cloud, 3D FaceLock). Coinbase Wallet. Portal. Many "no seed phrase" wallets marketed to non-technical users.

**Composition with ZP constraints:**
- **Sovereignty preservation:** ✗ The provider holds signing authority. They can be compelled by legal process, hacked, or drift toward extraction over time.
- **No center:** ✗ The provider IS the center.
- **Singular sovereign root:** Partial. Normal operation feels single-authentication (biometric on device) but authority is actually distributed.
- **Chain-anchored:** N/A. Recovery is an out-of-band process with the provider.
- **Append-only compatible:** ✓ In terms of chain semantics, sure — but the sovereignty issue dominates.
- **Structural, not policy:** ✗ The operator's sovereignty depends on the provider not doing bad things.

**Trade-offs introduced.**
- **Great UX.** No seed phrase to lose. Biometric authentication. Recovery via forgot-password-like flow.
- **Not sovereign.** The operator does not fully hold their identity. This is disqualifying for ZP.
- **Provider becomes a subpoena/hack target.** All users' identities are compromisable via provider compromise.

**Summary:** Excellent UX for centralized services. Fundamentally incompatible with ZP's sovereignty principle. Off the table for ZP proper; potentially useful as a *reference* for what ZP is deliberately not doing.

---

### Option 5: MPC / Threshold Signatures Fully Client-Side

**What it is.** MPC/TSS applied across multiple operator-controlled devices or shares, with no provider party. The operator holds all shares themselves (across phone, laptop, hardware wallet, etc.). Any K of N devices can sign; no single device compromise reveals the identity.

**Reference implementations.** Some enterprise deployments of Fireblocks in customer-controlled mode. Threshold wallets used in institutional custody where the institution doesn't want a third-party MPC provider. ZenGo's Recovery Kit exports a client-only recovery bundle.

**Composition with ZP constraints:**
- **Sovereignty preservation:** ✓ All shares held by the operator.
- **No center:** ✓ No provider party.
- **Singular sovereign root:** ⚠ Multi-device signing conflicts with singular root at signing time. Practical operations may cache session keys after multi-device authentication, restoring singular root for the session.
- **Chain-anchored:** ✓ Device provisioning and share regeneration events are chain receipts.
- **Append-only compatible:** ✓
- **Structural, not policy:** ✓ Fully cryptographic.

**Trade-offs introduced.**
- **Requires multiple operator devices.** New operators with one device can't use this pattern.
- **Complex UX for cross-device signing.** Coordinating M devices for every signature is friction. Session caching helps but introduces other trade-offs.
- **Device loss requires ceremony.** If N-K+1 devices are lost, identity is unrecoverable. If fewer, share regeneration must happen before more losses.
- **Share regeneration is chain-anchored ceremony.** Not casual.
- **Interacts with multi-device operation problem.** These are actually the same problem in different framings.

**Summary:** Sovereignty-preserving. Real user experience burden. Solves multi-device operation and backup as one composed problem, which is elegant. Compositional complexity.

---

### Option 6: Hardware Key Backup (YubiKey, Trezor, Ledger)

**What it is.** The Genesis secret lives in a hardware security module — a dedicated device that produces signatures without exposing the private key. Backup means either duplicating the hardware (initializing multiple hardware devices with the same seed) or using seed-phrase / Shamir backup of the underlying seed.

**Reference implementations.** YubiKey (FIDO2/WebAuthn keys), Trezor (Model T, Safe 3, Safe 5), Ledger (Nano X, Nano S Plus, Stax), Passport, Coldcard. Also enterprise HSMs (Thales, YubiHSM).

**Composition with ZP constraints:**
- **Sovereignty preservation:** ✓ Operator holds the hardware.
- **No center:** ✓ No third party involved.
- **Singular sovereign root:** ✓ One authentication (biometric or PIN to hardware device) signs.
- **Chain-anchored:** ✓ Device provisioning is a chain event.
- **Append-only compatible:** ✓
- **Structural, not policy:** ✓ Hardware security is structural.

**Trade-offs introduced.**
- **Hardware device required.** Adds cost ($50-$300+) and physical possession requirement.
- **Backup is still a problem.** The hardware itself can be lost, damaged, stolen. Solutions include: seed-phrase backup (Option 1) of the hardware's underlying secret; duplicating the hardware; Shamir backup (Option 2) of the underlying secret.
- **Hardware supply chain risk.** Compromised hardware from adversarial manufacturer or interception in shipping. Real for high-value targets; usually not for ordinary operators.
- **Vendor lock-in patterns.** Some hardware (Ledger Recover, 2023 controversy) has added features that partially compromise the "keys never leave the device" property.
- **Great for high-value / high-security operators.** Less appropriate for casual mass-market adoption.

**Summary:** Strong option for operators who care about security enough to buy hardware. Backup of the hardware itself is a separate problem that composes with Options 1 or 2. Compositional with other options rather than complete solution.

---

### Option 7: Passkey / WebAuthn with Sync

**What it is.** Cryptographic credentials created and stored by the operating system (iCloud Keychain, Google Password Manager) or a third-party password manager (1Password, Bitwarden, Dashlane). Passkeys sync across the operator's devices via the storage provider. As of 2026, the Credential Exchange Format (CXF) and Credential Exchange Protocol (CXP) allow moving passkeys between providers.

**Reference implementations.** Apple's iCloud Keychain (iOS 26 supports CXF import/export). Google Password Manager. Microsoft (Passkey Profiles and Synced Passkeys reaching GA March 2026). 1Password, Bitwarden, Dashlane all support passkey storage. The CXP standard is under active development by all major players.

**Composition with ZP constraints:**
- **Sovereignty preservation:** ⚠ Depends on the passkey storage provider. Apple/Google/Microsoft could in principle access the passkeys they store (subject to their claimed encryption of at-rest data). Third-party password managers similarly. Not as compromising as MPC-with-server, but not fully sovereign.
- **No center:** ⚠ The passkey storage provider is a center.
- **Singular sovereign root:** ✓ Operator authenticates once to the storage provider.
- **Chain-anchored:** N/A. Passkeys are not chain-native.
- **Append-only compatible:** ✓ In principle.
- **Structural, not policy:** ⚠ Storage providers make security claims that are policy statements as much as structural.

**Trade-offs introduced.**
- **Great UX.** Sync just works across devices. Backup handled by storage provider.
- **Not fully sovereign.** Storage provider is a trust dependency.
- **Portable across providers via CXF/CXP.** Reduces lock-in.
- **Phishing-resistant compared to passwords.** Real security improvement over prior standards.
- **Doesn't fit ZP's chain-native identity model naturally.** Passkeys are for authenticating to services, not for being an autonomous identity that signs actions on your own chain.

**Summary:** Excellent for authenticating to services; awkward fit for ZP's identity model, which is more like a personal PGP key than a login credential. Might be useful as an auxiliary authentication factor for unlocking Genesis material on a specific device, not as the Genesis identity itself.

---

### Option 8: Biometric-Derived / Fuzzy Extractors

**What it is.** Derive a cryptographic key from biometric data (fingerprint, iris, face) directly. Fuzzy extractors are the cryptographic primitive: they generate a stable key from noisy biometric input using error-correcting codes, with public "helper data" enabling reconstruction while (in theory) revealing nothing about the biometric.

**Reference implementations.** Academic research (Dodis, Fuller, and others). No large-scale production deployment. Widely used biometric authentication (Touch ID, Face ID) uses biometric-unlocked keys, NOT biometric-derived keys — the biometric unlocks a key stored in the secure enclave, and this distinction is crucial.

**Composition with ZP constraints:**
- **Sovereignty preservation:** ✓ In principle.
- **No center:** ✓ Fully offline.
- **Singular sovereign root:** ✓ One biometric presentation.
- **Chain-anchored:** ⚠ N/A for the derivation itself.
- **Append-only compatible:** ✓
- **Structural, not policy:** ⚠ Depends on fuzzy extractor security guarantees, which are limited in practice.

**Trade-offs introduced.**
- **Compelling UX in principle.** Your face is your key. No phrase to remember.
- **Biometric compromise is permanent.** You can't rotate your fingerprint. Once biometric data is exposed (data breach elsewhere, coerced enrollment), the derived key is compromised forever.
- **Fuzzy extractor practicality is limited.** Helper data can be enormous (research reports helper data ranging from 33GB to 19TB for realistic error rates). Multi-enrollment doesn't work — using the same biometric with a second system breaks security guarantees. No security guarantees against real biometric sources beyond narrow lab conditions.
- **Coercion resistance is worse than knowledge-based secrets.** You can be physically compelled to present your biometric. You cannot be physically compelled to remember a phrase you refuse to.
- **Practical biometric systems use biometrics as unlock, not as key material.** Touch ID/Face ID unlock a key stored in secure hardware. This is actually a different problem than biometric-derived keys.

**Summary:** Attractive in principle, problematic in practice for identity-level keys. Biometric-unlocked keys (Touch ID/Face ID unlocking secure enclave) are a fine convenience for accessing already-stored material. Biometric-derived keys as the identity itself have serious cryptographic and coercion limitations. Recommend against for Genesis; consider for device-unlock UX.

---

### Option 9: Signal-Style Encrypted Backup with Recovery Key

**What it is.** Content (messages, keys, state) is backed up in encrypted form to a location — either a server the operator doesn't trust with plaintext, or their own storage. A recovery key (64-character random string, or similar) is required to decrypt. The operator is responsible for holding the recovery key.

**Reference implementations.** Signal's Secure Backups. WhatsApp's end-to-end encrypted backup (using their key vault). Some 1Password/Bitwarden features. Most modern "we can't read your data" services follow this pattern.

**Composition with ZP constraints:**
- **Sovereignty preservation:** ✓ The backup provider cannot decrypt without the key.
- **No center:** ⚠ Signal uses their own storage; the pattern generalizes to peer-hosted or self-hosted storage.
- **Singular sovereign root:** ✓ One authentication (the recovery key) unlocks the backup.
- **Chain-anchored:** ⚠ Backup creation and restoration can be chain-anchored.
- **Append-only compatible:** ✓ Backup is a snapshot; restoration is a re-derivation event on the chain.
- **Structural, not policy:** ✓ Cryptographic encryption is structural.

**Trade-offs introduced.**
- **Two problems now: keep the recovery key, and keep the encrypted backup.** If either is lost, recovery fails.
- **Recovery key is a seed phrase in disguise.** Same storage/loss risks as Option 1.
- **June 2026 phishing attack (Signal, per FBI/CISA advisory) demonstrates:** even sophisticated users can be tricked into revealing recovery keys. Human factor remains the weak link.
- **Backup content can be substantial.** Chain state grows over time; incremental backup design matters.

**Summary:** Solves the "backup the derived state" problem well. Doesn't solve the "backup the identity secret" problem beyond the recovery key itself. Composes naturally with a chain-replication strategy for chain state. Recovery key is another thing to lose.

---

### Option 10: Keybase-Style Per-Device Sigchain with Paper Key

**What it is.** Each of the operator's devices has its own device key. The operator's identity is a per-user sigchain that includes announcements of active device keys. Losing a device means the operator (from another device) publishes a revocation to their sigchain. A "paper key" acts as a special device key that exists as printed text — it's a backup device you can provision from later. New devices are added by the operator (from an existing device) via chain events.

**Reference implementations.** Keybase's pre-Zoom implementation (widely respected for its cryptographic design). Some concepts survive in the newer sigsum/transparency-log space. Not widely adopted post-Zoom acquisition.

**Composition with ZP constraints:**
- **Sovereignty preservation:** ✓ Device keys held by operator on hardware they control.
- **No center:** ⚠ Keybase's original implementation used their server for sigchain publication. The pattern generalizes to peer-published sigchains.
- **Singular sovereign root:** ⚠ Multi-device pattern conflicts with singular root at signing time (each device signs with its own key). Session caching mitigates.
- **Chain-anchored:** ✓ This IS chain-anchored — the sigchain is the record.
- **Append-only compatible:** ✓ Sigchain is append-only by design.
- **Structural, not policy:** ✓ Fully cryptographic.

**Trade-offs introduced.**
- **Multi-device model is well-suited to real operator lifestyles.** Operators use multiple devices; each holds its own key; recovery from device loss is native to the model.
- **Paper key handles worst-case (all devices lost).** Same storage burden as Option 1.
- **Chain-native design.** The paradigm fits ZP's substrate philosophy naturally.
- **Per-user-key (PUK) architecture.** Keybase's PUK — encrypted for all active devices, rotated on device revocation — is a proven pattern for keeping user-level material available across devices without requiring all devices to hold the master key.

**Summary:** Probably the closest existing pattern to what ZP naturally wants. Combines multi-device operation with backup via paper key. Chain-native. The main gap is that Keybase's implementation relied on a central sigchain server; ZP's design would need to distribute sigchain publication. This is compatible with our peer-discovery mechanism.

---

### Option 11: DID-Style Social Recovery with Quorum

**What it is.** Self-sovereign identity systems built on W3C DID standards use social recovery patterns similar to Option 3 but with quorum-based key rotation embedded in the DID method. A group of guardians can collectively update the DID document to associate a new key with the identity. The identity itself (the DID) persists across key rotations.

**Reference implementations.** DID methods that support recovery: did:web with guardians, did:ion with recovery keys, did:ethr with delegate-based recovery. Various SSI wallets (Trinsic, Serto, Veres One) implement DID-native social recovery. W3C DID v1.1 (Candidate Recommendation, March 2026) formalizes recovery mechanisms in the DID Rubric.

**Composition with ZP constraints:**
- **Sovereignty preservation:** ⚠ Same as Option 3 — guardians can collude.
- **No center:** ✓ DID methods are designed to be centerless.
- **Singular sovereign root:** ⚠ Recovery is distributed.
- **Chain-anchored:** ✓ DID document updates are chain events on whatever ledger the DID method uses.
- **Append-only compatible:** ✓ DID documents grow monotonically.
- **Structural, not policy:** ⚠ Same as Option 3.

**Trade-offs introduced.**
- **Standardized approach with growing ecosystem support.** Interoperability benefits.
- **DID persists across key rotations.** The identity is stable even as keys change. Composable with ZP if Genesis is treated as a DID.
- **Same guardian dynamics as Option 3.** All the same trade-offs.
- **Adds an abstraction layer.** ZP would be committing to a specific DID method or defining its own.

**Summary:** Essentially Option 3 with W3C standards formalism. Adds interoperability with the broader SSI ecosystem. Same fundamental trade-offs on sovereignty vs. usability. Worth considering if interop matters; otherwise a native ZP design may be simpler.

---

### Option 12: Time-Locked / Dead-Man's Switch Recovery

**What it is.** A pre-authorized recovery path activates automatically after a period of inactivity from the operator. Typical form: a second key (held by heir or trusted party) can sign after N months of no activity from the primary key. Activation is enforced by the substrate itself, not by any third party.

**Reference implementations.** Bitcoin OP_CHECKLOCKTIMEVERIFY (OP_CLTV) for time-locked spending paths. Sarcophagus (Ethereum + Arweave decentralized dead-man switch). Ethereum smart contracts with heartbeat mechanisms. Cited as increasingly relevant in 2026 with an estimated $60-80B in cryptocurrency permanently lost to owner incapacitation.

**Composition with ZP constraints:**
- **Sovereignty preservation:** ⚠ The recovery party can activate after the timeout without operator consent (indeed, the operator is presumably deceased or incapacitated). This is the point.
- **No center:** ✓ Enforcement is by substrate, not by service.
- **Singular sovereign root:** ✓ Normal operation is single root; timeout activates a separate path.
- **Chain-anchored:** ✓ Timeout activation is a chain event; heartbeat signals are chain events.
- **Append-only compatible:** ✓
- **Structural, not policy:** ✓ Timeout is enforced by substrate rules.

**Trade-offs introduced.**
- **Solves inheritance and long-term-availability problem elegantly.** Real problem underserved by other options.
- **False triggers.** Operator on vacation, in hospital, incarcerated but not deceased — the timeout may trigger unwanted recovery. Design must include easy heartbeat refresh with adequate margin.
- **Heir must actually claim after timeout.** If heir doesn't know about the arrangement or has lost their own key, the recovery path is inert.
- **Composable with other options.** A dead-man's switch can be added on top of any primary recovery scheme.

**Summary:** Addresses a real problem (long-term availability, inheritance) that most other options ignore. Composable as an add-on rather than as primary recovery. Should probably be in the recommended stack regardless of what else is chosen.

---

### Option 13: Chain Replication Among Trusted Peers

**What it is.** Backup of chain state (Problem 2, per Part I) via peer replication. The operator grants selected peers scoped, revocable capability to hold encrypted copies of their chain receipts. If the operator's local chain is lost, peers can supply the encrypted receipts, which the operator decrypts and reconstructs their local chain from.

**Reference implementations.** Bitcoin's UTXO set is peer-replicated by design. Some enterprise blockchain systems formalize peer chain replication. Not a common pattern for identity chains specifically, but the technical primitives exist.

**Composition with ZP constraints:**
- **Sovereignty preservation:** ✓ Peers hold encrypted copies they can't decrypt.
- **No center:** ✓ Peer-to-peer.
- **Singular sovereign root:** ✓ Restoration is unlocking encrypted receipts with the operator's key.
- **Chain-anchored:** ✓ Replication grants and restoration events are chain-native.
- **Append-only compatible:** ✓ Only backs up receipts, not derived state.
- **Structural, not policy:** ✓ Peers can only supply what they were given, encrypted.

**Trade-offs introduced.**
- **Addresses Problem 2 (chain state backup).** Distinct from Problems 1 (identity secret) and 3 (derived state).
- **Peer availability matters.** If the operator's peers are also offline when recovery is needed, restoration fails. Choose peers with independent failure modes.
- **Encrypted-at-rest metadata may leak information.** Sizes of receipts, timing patterns, aggregate volume. Peers know that this operator has this many receipts, at these times. Some information leak is unavoidable.
- **Revocation is straightforward.** The operator can revoke replication capability at any time.

**Summary:** Solves a specific problem (chain state backup) that Options 1-12 mostly ignore. Composable with any Option 1-12 as the primary identity-recovery mechanism.

---

## Part IV — Cross-Cutting Concerns

### The chain state problem, again

Most options above address Problem 1 (identity secret). Only Options 9 (encrypted backup), 10 (Keybase pattern), and 13 (peer replication) directly address Problem 2 (chain state). A complete backup strategy has to address Problem 2 explicitly. Options that address only identity leave the operator with a valid identity but no history — which is a partial-recovery scenario worth designing for but not the full solution.

### The derived state problem

Problem 3 (Cartographer ontology, Regent memory, learned patterns) is theoretically re-derivable from chain state given time and compute. Re-derivation may be slow (minutes to hours depending on chain size). Options for handling:

- **Accept re-derivation.** After recovery, the operator's Regent is temporarily less capable while the Cartographer rebuilds. Explicit expectation-setting to the operator.
- **Backup derived state alongside chain state.** More data to protect but faster recovery. Composable with Options 9 or 13.
- **Rolling snapshots.** Cartographer produces snapshot receipts periodically that allow fast rebuild from the most recent snapshot forward.

### Cross-device operation composability

Options that support multi-device natively — 5 (client-side MPC), 10 (Keybase pattern), and 7 (Passkey sync) — solve backup and multi-device as one composed problem. Options that don't (1, 2, 6) leave multi-device operation as a separate design problem. Solving them together via Option 5 or 10 may be architecturally cleaner than solving them separately.

### Attack surfaces to weigh

Each option has a distinctive attack surface:

- **Options 1, 2:** Storage of physical secrets. Loss, theft, coercion.
- **Options 3, 11:** Guardian collusion, guardian coercion, guardian unavailability.
- **Option 4:** Provider compromise (out for ZP).
- **Option 5:** Multi-device coordination attacks; share-regeneration ceremony failures.
- **Option 6:** Hardware supply chain, physical device attacks.
- **Option 7:** Storage provider compromise.
- **Option 8:** Biometric compromise (permanent), coercion.
- **Option 9:** Recovery-key phishing (per Signal's June 2026 incident), storage provider compromise if backup is hosted.
- **Option 10:** Chain publication availability.
- **Option 12:** False-timeout activation, heir key loss.
- **Option 13:** Peer availability, metadata leak.

None of these is uniformly best. The attack surface an operator can defend against depends on their threat model, technical sophistication, and social/institutional environment.

---

## Part V — Compatibility Matrix

Rough summary of each option against the six ZP constraints. ✓ = clean fit; ⚠ = partial or conditional; ✗ = fundamental conflict.

| Option | Sovereignty | No center | Singular root | Chain-anchored | Append-only | Structural |
|--------|-------------|-----------|---------------|----------------|-------------|------------|
| 1. Seed phrase | ✓ | ✓ | ✓ | ⚠ | ✓ | ✓ |
| 2. Shamir (SLIP-39) | ✓ | ✓ | ✓ | ⚠ | ✓ | ✓ |
| 3. Social recovery (guardians) | ⚠ | ✓ | ⚠ | ✓ | ✓ | ⚠ |
| 4. MPC with server | ✗ | ✗ | ⚠ | N/A | ✓ | ✗ |
| 5. MPC client-side | ✓ | ✓ | ⚠ | ✓ | ✓ | ✓ |
| 6. Hardware key | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 7. Passkey sync | ⚠ | ⚠ | ✓ | N/A | ✓ | ⚠ |
| 8. Biometric-derived | ✓ | ✓ | ✓ | ⚠ | ✓ | ⚠ |
| 9. Encrypted backup + recovery key | ✓ | ⚠ | ✓ | ⚠ | ✓ | ✓ |
| 10. Keybase per-device sigchain | ✓ | ⚠ | ⚠ | ✓ | ✓ | ✓ |
| 11. DID social recovery | ⚠ | ✓ | ⚠ | ✓ | ✓ | ⚠ |
| 12. Time-locked / dead-man | ⚠ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 13. Peer chain replication | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

Matrix caveats:
- ⚠ in "Sovereignty" often means "conditional on parties behaving well" rather than "structurally compromised."
- The matrix collapses nuance. Option 3's ⚠ is different from Option 12's ⚠ in kind, not just severity.
- The matrix doesn't reflect UX cost, which is a real design constraint that isn't a ZP-principle constraint.

---

## Part VI — Composable Combinations

Options aren't mutually exclusive. Some natural compositions:

**Composition A: Sovereign Purist.** Options 2 (Shamir) + 6 (hardware) + 13 (peer chain replication) + 12 (dead-man switch). No trust in any external party for identity. Shamir shares split across geography; hardware devices protect the working key material; peer replication for chain state; dead-man switch for long-term availability. Maximum sovereignty, maximum operator burden.

**Composition B: Practical Balance.** Options 10 (Keybase-style per-device sigchain) + 13 (peer replication) + 12 (dead-man switch) + 1 (paper key backup). Multi-device operation as first-class, so daily use is convenient. Paper key exists as ultimate fallback. Peer replication handles chain state. Dead-man switch handles inheritance. Sovereignty preserved with reasonable UX.

**Composition C: Guardian-Assisted.** Options 3 (social recovery with guardians) + 6 (hardware for primary) + 13 (peer replication) + 12 (dead-man switch). Guardians handle recovery from lost primary key; hardware protects daily-use key; peers handle chain state; dead-man switch for inheritance. Trades sovereignty (guardian collusion risk) for UX (no paper phrase to lose).

**Composition D: Enterprise Ready.** Options 5 (MPC client-side) + 6 (hardware) + 13 (peer replication) + 12 (dead-man switch). Multi-device MPC with hardware devices as MPC parties; peer replication; dead-man switch. Suitable for institutional deployments where operators are technically sophisticated and multi-device operation is native.

**Composition E: Consumer Baseline.** Options 7 (Passkey sync, with heavy caveats) + 3 (social recovery) + 13 (peer replication) + 12 (dead-man switch). Everything the least-technical operator can be walked through. Sovereignty compromise: real but bounded. Suitable for casual adoption, not high-value operators.

Each composition serves a different operator persona. ZP could support multiple compositions and let the operator choose at Genesis time, with the Regent explaining trade-offs.

---

## Part VII — What's Off the Table

Some options can be named as structurally incompatible with ZP's principles:

- **MPC with provider server (Option 4) as primary identity architecture.** The provider becomes the trust dependency; there is no scenario where this fits ZP.
- **Any recovery mechanism that requires Foundation to hold recovery material.** Even the Foundation is not privileged. Foundation-run services can *support* recovery (as one peer among many, per the peer-discovery / commons pattern) but never be *required* for it.
- **Any recovery mechanism that requires phoning home on activation.** Recovery must be usable when the operator has no network access to any specific service.
- **Biometric-derived keys as Genesis identity.** Coercion resistance and unrecoverability-on-compromise make this unsuitable.

These are not close calls. Options that structurally require these compromises should not be under active consideration.

---

## Part VIII — Open Questions Not Answered Here

Deliberate scope limits of this survey:

- **Which composition is best for ZP's actual operator personas.** That's a follow-on decision doc, not this survey.
- **Detailed cryptographic parameter choices.** K-of-N ratios, timeout durations, share sizes — all follow after the composition is chosen.
- **UX design of the recovery flow.** Recovery ceremonies need careful design; not scoped here.
- **Legal jurisdictional considerations for guardians and heirs.** Real concern, especially for cross-border deployments. Follow-on work.
- **Integration with the Regent's role in guiding backup decisions.** The Regent should help operators make informed choices; that surface is not designed here.
- **Backup of the pattern-sharing keys and bounded-space identities.** These derive from the Genesis identity but have their own lifecycle; how they interact with backup is a distinct design question.

---

## Part IX — Companion Documents

- `docs/ARCHITECTURE-2026-07.md` — canonical architecture record. The singular sovereign root principle discussed here is grounded in Part I §3.6 there.
- `docs/design/PEER-DISCOVERY-AS-OUTREACH-2026-07.md` — peer discovery provides transport primitives for Option 10 and Option 13.
- `docs/design/DISTRIBUTED-KNOWLEDGE-COMMONS-2026-07.md` — pattern-sharing key derivation ceremony is relevant for backup scope questions.
- `docs/whitepaper-v9.md` — public thesis. Section 5.6 discusses the singular sovereign root that constrains this design space.

---

## Sources

- [Account Abstraction & ERC-4337 (Hacken)](https://hacken.io/discover/erc-4337-account-abstraction/)
- [ERC-4337 Social Recovery (Eco Support)](https://eco.com/support/en/articles/12014843-what-is-account-abstraction-a-2026-guide)
- [Shamir's Secret Sharing / SLIP-39 (Blofin)](https://blofin.com/academy/education/shamirs-secret-sharing)
- [SLIP-39 Hardware Wallet Guide (Keystone)](https://blog.keyst.one/how-shamir-backups-slip-39-safeguard-your-crypto-a-complete-guide)
- [Vault12 Quantum-Safe Data Storage](https://quantumzeitgeist.com/vault12-quantum-safe-data-storage/)
- [Credential Exchange Protocol / Format (Corbado)](https://www.corbado.com/blog/credential-exchange-protocol-cxp-credential-exchange-format-cxf)
- [Passkey Sync Explained (Security Boulevard)](https://securityboulevard.com/2026/05/cross-device-passkey-sync-explained-icloud-keychain-google-password-manager-and-1password/)
- [W3C DID v1.1 Specification](https://www.w3.org/TR/did-1.1/)
- [W3C DID Update (Biometric Update)](https://www.biometricupdate.com/202603/w3c-releases-updated-decentralized-identifiers-spec-for-comment)
- [Top MPC Wallets 2026 (CoinsDo)](https://www.coinsdo.com/en/blog/top-5-mpc-wallets-in-2026)
- [Fireblocks Backup and Recovery Docs](https://developers.fireblocks.com/docs/embedded-wallet-backup-and-recovery)
- [ZenGo MPC Wallet Overview](https://zengo.com/mpc-wallet/)
- [Signal Secure Backups Support](https://support.signal.org/hc/en-us/articles/9708267671322-Signal-Secure-Backups)
- [Signal Backup Phishing Attack Analysis (Aardwolf Security)](https://aardwolfsecurity.com/signal-backup-recovery-key-security/)
- [Signal Phishing Attack Wave (Cybersecurity News)](https://cybersecuritynews.com/hackers-attacking-signal-users/)
- [Fuzzy Extractors Original Paper (SIAM)](https://epubs.siam.org/doi/10.1137/060651380)
- [Fuzzy Extractor Limitations (Hindawi)](https://www.hindawi.com/journals/scn/2018/6107912/)
- [Crypto Inheritance and Dead-Man Switch (Nexus Crypto)](https://nexuscryptopro.net/dead-mans-switch-automatic-crypto-inheritance-triggers/)
- [Bitcoin OP_CSV Inheritance (In Bitcoin We Trust)](https://inbitcoinwetrust.substack.com/p/the-dead-mans-switch-how-to-program)
- [Sarcophagus Decentralized Dead-Man Switch](https://sarcophagus.io/)
- [Keybase Book: Per-User Keys](https://book.keybase.io/docs/teams/puk)
- [Keybase Protocol Security Review (NCC Group)](https://keybase.io/docs-assets/blog/NCC_Group_Keybase_KB2018_Public_Report_2019-02-27_v1.3.pdf)
- [Keybase Key Exchange Protocol](https://book.keybase.io/docs/crypto/key-exchange)
