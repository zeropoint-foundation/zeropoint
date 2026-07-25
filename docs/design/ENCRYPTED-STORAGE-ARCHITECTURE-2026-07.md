# Encrypted Storage Architecture — July 2026

**Document type:** Technical design note. Specifies ZeroPoint's end-to-end encryption architecture for at-rest storage, in-transit sharing, key derivation from Genesis, and the composition with the append-only chain. Retires the hand-wavy "it's encrypted" formulations elsewhere in the docs. Every mention of encrypted storage in `ARCHITECTURE-2026-07.md` and `whitepaper-v9.md` should ultimately point here for the specifics.

**Status:** Design specification. Concrete enough to implement; open decision points marked explicitly.

**Author:** Ken Romero, with synthesis assistance from Claude.

**Date:** 2026-07-05.

**Companion:** Sits alongside `docs/design/BACKUP-AND-RECOVERY-LANDSCAPE-2026-07.md` — that document covers *what happens when the operator loses their Genesis material*; this document covers *how the material and the state it protects are actually cryptographically structured*.

---

## Part I — What Encryption Actually Needs To Protect

Before specifying schemes, name the categories of state ZP holds and what threats apply to each. This scoping matters because different categories warrant different treatment.

**1. Genesis identity material.** The Ed25519 seed. Highest sensitivity. Compromise = total identity loss. Must survive: device theft, cold-boot attack, coerced or seized device with authentication refused, malicious peer with limited software access.

**2. Signing keys derived from Genesis.** Chain-signing key, delegation-issuance key, pattern-sharing keys. Must be usable at runtime without exposing Genesis to memory beyond the ceremony. High sensitivity.

**3. Chain receipts (bulk).** Signed, hash-linked. The plaintext content of receipts is often sensitive (governance actions, community messages, cognitive-layer outputs). Sensitivity varies by receipt type.

**4. Derived cognitive-layer state.** Cartographer ontology (Trajectories, Decisions, Insights, Artifacts, Frictions). Regent memory (session context, learned preferences, attention patterns). Officer state (in-session domain context). Extremely sensitive — this is where interpretation of the operator's private life lives.

**5. Delegated capability grants and mandates.** Both issued (grants the operator gave others) and received (grants others gave the operator). Signature-bearing, some contain scope details that reveal what the operator has authorized.

**6. Session state.** Current authentication state, cached decryption keys, current session context. Ephemeral by design but memory-resident during runtime.

**7. Real-time session content.** Voice/video call content, locked-door meeting content. Latency-sensitive; encryption architecture differs from chain at-rest.

**8. Captured media.** Photos, video, audio, files. Larger and more numerous than chain receipts; storage architecture must handle bulk.

**9. Peer-shared state.** Chain segments the operator has shared with peers for backup replication, research mandate queries, community context propagation.

Each of these has distinct storage, access, and threat characteristics. A single flat "encrypt everything with one key" would be architecturally lazy and expose real weaknesses.

---

## Part II — Threat Model, Concretely

Six threats the storage architecture must defend against. Each is specified with the assumed adversary capability and the defense posture.

### 2.1 Device theft

**Adversary capability:** Physical possession of an operator's powered-off device. Cannot authenticate as the operator. Access to disk contents, standard forensic tools.

**Defense posture:** All state at rest must be encrypted such that decryption requires operator authentication. Genesis material sealed by sovereignty provider (Secure Enclave, TPM, hardware wallet, biometric). No unlock keys stored on disk in accessible form. Even if the attacker mounts the disk on another system, the ciphertext reveals nothing beyond metadata that we allow to leak.

### 2.2 Cold-boot / running-device seizure

**Adversary capability:** Physical possession of an operator's running device with vault potentially unlocked. Memory dump possible. Access to session keys and derived material currently in RAM.

**Defense posture:** Session keys and derived key material minimized in RAM. Where possible, cryptographic operations offloaded to TEE/Secure Enclave so signing/decryption happens without private key touching main memory. Explicit lock timeouts. Panic-lock via hardware button or hotkey. Memory scrubbing after use (best-effort — memory forensics defeats scrubbing in some cases).

### 2.3 Cloud backup exposure

**Adversary capability:** Access to any cloud storage the operator has used for backup. Cloud provider itself may be adversary. Operator's account credentials to cloud may be compromised.

**Defense posture:** Backup encryption occurs at the operator's device before upload. Cloud provider sees ciphertext with metadata bounded to size and timing. Backup encryption key is independent of the operator's device authentication — it is derived from Genesis (per backup design) or from a separate passphrase the operator holds. Cloud provider never has any material that could decrypt the backup.

### 2.4 Compromised peer

**Adversary capability:** Peer that the operator has shared data with (chain segments, research query responses, community context, session participation) is fully compromised. All state that peer received is in adversary hands.

**Defense posture:** Capability-scoped decryption. Each peer receives only the specific keys required for their specific relationship — never the operator's master keys. Compromise of a peer exposes only what that peer had legitimate access to, not the operator's broader state. Revocation is straightforward: rotate the shared key; peer loses forward access even if they hold prior material.

### 2.5 Law enforcement seizure with compelled authentication

**Adversary capability:** Legal authority to compel the operator's authentication. Device seized in operating state or operator physically present. Varies by jurisdiction (US 5th Amendment has been interpreted variously; UK RIPA compels disclosure; other jurisdictions vary).

**Defense posture:** This threat is jurisdiction-dependent and cannot be defended against structurally in all cases. Architectural affordances that help:

- **Compartmentalization by CEK:** an operator compelled to unlock the general vault does not thereby expose every context. Different contexts (bounded spaces, specific communities, sensitive categories) have separate CEKs; unlocking one does not decrypt the others.
- **Duress-response patterns:** operator can pre-configure duress authentication that opens a reduced vault view (containing only public-safe material) while triggering a chain-anchored duress signal that peers can observe. Sophisticated legal authority may test for this; not perfect.
- **Deniable existence:** for the most sensitive categories, plausible deniability that the encrypted blob exists at all can be constructed via hidden volume patterns. Complex; not a first-tier feature.
- **Chain-anchored refusal:** the operator can publish an authenticated refusal-to-decrypt receipt. Doesn't prevent seizure but creates auditable record.

### 2.6 Malicious software on the operator's device

**Adversary capability:** Software running with the operator's user privileges. Can observe keystrokes, wait for authentication events, replay authenticated actions.

**Defense posture:** This threat is largely undefendable at the storage-encryption layer — if the attacker has code execution as the operator, they wait for authentication and act as the operator once it occurs. Mitigations at the storage layer:

- **TEE-mediated signing:** keys never leave the secure enclave; even code execution as the operator cannot exfiltrate the private key material.
- **Per-operation authentication:** high-stakes operations (constitutional modifications, mass delegations, backup export) require explicit authentication each time, not just an unlocked vault.
- **Chain-anchored anomaly detection:** the Cartographer flags operations that don't fit the operator's normal patterns; the Regent surfaces suspected compromises to the operator.

Storage-layer defense is best-effort against this threat. The primary defense is at the runtime attestation layer (see `PEER-DISCOVERY-AS-OUTREACH-2026-07.md` on software integrity attestation).

---

## Part III — Key Hierarchy from Genesis Down

All key material derives from the Genesis seed via a formally specified hierarchy. The hierarchy is the singular-sovereign-root principle made concrete.

```
Genesis Seed (32 bytes, Ed25519 seed)
│
├── Chain Signing Key (Ed25519 keypair, derived by HKDF)
│    └── Used for: signing all chain receipts
│
├── Delegation Issuance Key (Ed25519 keypair, derived by HKDF)
│    └── Used for: signing capability grants and mandates
│
├── Vault Master Key (32 bytes, derived by HKDF-SHA256)
│    │
│    └── Vault Content Encryption Keys (per category)
│         ├── VCEK-vault-general    (personal secrets, contact keys)
│         ├── VCEK-vault-community-N  (per-community persistent state)
│         ├── VCEK-vault-mandate-M    (per-mandate scoped state)
│         └── ...
│
├── Content Encryption Key Base (derived by HKDF-SHA256)
│    │
│    └── Content Encryption Keys (per category, per epoch)
│         ├── CEK-chain-general-e1     (general chain receipts, epoch 1)
│         ├── CEK-chain-general-e2     (general chain receipts, epoch 2, after rotation)
│         ├── CEK-chain-community-X-e1 (community X receipts)
│         ├── CEK-chain-mandate-Y-e1   (mandate Y receipts)
│         └── ...
│
├── Derived State Key (32 bytes, derived by HKDF-SHA256)
│    │
│    ├── DSK-ontology              (Cartographer ontology at rest)
│    ├── DSK-regent-persistent     (Regent long-term memory)
│    ├── DSK-regent-session        (Regent per-session, ephemeral)
│    ├── DSK-officer-{name}        (per-officer in-session state)
│    └── DSK-cache-{purpose}       (derived caches, priors from commons)
│
├── Pattern-Sharing Root (derived by HKDF-SHA256)
│    │
│    ├── PSK-commons                (identity for commons emission)
│    ├── PSK-bounded-{space}        (per-bounded-space identity)
│    └── PSK-purpose-{context}      (purpose-scoped identity)
│
├── Backup Encryption Key (32 bytes, derived by HKDF-SHA256)
│    └── Used for: at-rest encryption of exported backups
│
└── Session Ephemeral Key Base (32 bytes, derived by HKDF-SHA256)
     │
     └── Session Ephemeral Keys (per real-time session)
          ├── SEK-{session-id}       (locked-door meeting, voice call, etc.)
          └── ...
```

### 3.1 Derivation function

All non-Ed25519 keys derived by HKDF-SHA256, with:
- **Salt:** a chain-anchored derivation salt receipt. Not secret; simply distinguishes ZP's derivation namespace from others.
- **IKM (input keying material):** the Genesis seed (for top-level derivations) or a parent-level key (for hierarchical derivations).
- **Info:** a purpose string uniquely identifying the derivation. E.g., `"zp/vault-master-key/v1"`, `"zp/cek-base/v1"`, `"zp/backup-encryption-key/v1"`.

The hierarchy is fixed at Genesis-ceremony time. New categories emerging at runtime derive their specific keys from the appropriate base with a category identifier as additional info: e.g., `CEK-chain-community-X-e1 = HKDF(CEK-base, "community-X/epoch-1")`.

### 3.2 Ed25519 keys derived from Genesis

The chain-signing key and delegation-issuance key are Ed25519 keypairs. They are derived deterministically from Genesis using a well-specified scheme (BIP32-Ed25519 or similar chain-code derivation). Given the Genesis seed, these keys can be re-derived; they are not stored separately from Genesis. This means the vault does not need to persistently store signing keys — it holds Genesis material sealed by the sovereignty provider, and derives signing keys on demand.

### 3.3 Which keys live where

- **Genesis seed:** sealed by sovereignty provider (Secure Enclave, TPM, hardware wallet). Never in plaintext on disk. Unlockable only via operator authentication ceremony.
- **Derived signing keys:** in TEE where supported (signing happens without material leaving TEE). In memory during signing sessions only. Not persisted.
- **Vault master key:** derived from Genesis at session start. Held in memory during authenticated session. Cleared on lock.
- **CEKs:** persisted (encrypted under vault master key) in the vault. Retrieved as needed. Cached in memory during use with configurable timeout.
- **Session ephemeral keys:** in memory only. Destroyed at session end for ephemeral sessions; persisted encrypted under vault master key for persistent sessions.
- **Backup encryption key:** derived from Genesis at backup-export time. Not persisted.
- **Pattern-sharing keys:** derived from Genesis; the specific derivation for a bounded-space key is chain-anchored (the separation ceremony receipt is what makes the key valid).

---

## Part IV — The Vault

The vault is the sealed container for material that must persist across sessions but must never be exposed without operator authentication.

### 4.1 What the vault contains

- Genesis seed (or a wrapping key that unlocks Genesis stored in sovereignty provider)
- CEK index (map from context to encrypted CEK)
- Capability grants (issued and received)
- Pattern-sharing keys (or their derivation state)
- Sovereignty provider bindings (which providers are authorized)
- Vault version metadata, format identifier, salt

### 4.2 Vault format decision

**Decision required: vault format.**

Options:
- **A. Encrypted SQLite.** SQLCipher-style. Structured queries possible after unlock. Well-tested.
- **B. Encrypted append-log.** Simple, auditable, immutable-history-native. Aligns with chain philosophy.
- **C. Custom sealed-JSON.** Simple, human-inspectable when unlocked, easy to migrate.

Recommendation for further design: **B** aligns most cleanly with the append-only chain philosophy — the vault becomes a specialized chain segment. Concretely: vault operations (add key, revoke grant, rotate CEK) become chain receipts on a private vault chain. Advantages: full auditability of vault mutations; ability to reconstruct vault state from chain if needed; philosophical coherence. Trade-off: more complex to implement than SQLite.

**Open decision.**

### 4.3 Vault sealing and unlocking

The vault is sealed by the sovereignty provider. Sovereignty providers ZP supports:

- **Secure Enclave (macOS/iOS).** Touch ID or Face ID unlocks a key that decrypts the vault.
- **StrongBox / TrustZone (Android).** Biometric or PIN unlocks a key that decrypts the vault.
- **TPM (Windows/Linux).** Platform authentication unlocks a key that decrypts the vault.
- **Hardware wallet (YubiKey, Trezor, Ledger).** External hardware holds the wrapping key; touch confirms unlock.
- **Passphrase (fallback).** Argon2id-derived key from a passphrase. Weakest option; last resort.
- **M-of-N sovereign quorum (future).** Multiple sovereignty providers combined.

The vault format binds to a specific sovereignty provider at ceremony time. Migration between providers is a chain-anchored ceremony (re-seal with new provider; new vault format tagged with the transition).

### 4.4 Vault unlock semantics

Once unlocked, the vault master key is held in memory. Duration decisions:

- **Session lifetime.** Vault stays unlocked until process exits.
- **Timeout.** Vault re-locks after N minutes of no vault access.
- **Idle timeout.** Vault re-locks after N minutes of no user activity.
- **Explicit lock.** Operator manually locks.

**Decision required: default unlock semantics.**

Recommendation: idle timeout with configurable duration (default 15 minutes), explicit lock always available, session lifetime as opt-in for continuous operation (e.g., the Regent running as a service).

---

## Part V — Chain Encryption (The Hard Part)

The chain is append-only, signed, hash-linked. Adding encryption without breaking these properties requires care.

### 5.1 What's plaintext vs. encrypted in a receipt

A receipt has two distinct payloads:

**Plaintext (always accessible without decryption):**
- Receipt ID (`id`)
- Receipt type (`rt`): execution, intent, approval, delegation, verification, refusal, cognitive_step, etc.
- Status (`st`)
- Trust grade (`tg`)
- Timestamp (`ts`)
- Parent receipt ID (`pr`)
- Policy decision (`pd`)
- Category tag (`cat`): community-general, community-X, mandate-Y, etc.
- Content hash (`ch`): Blake3 of the plaintext content
- Signature (`sg`): over all of the above plus the content hash

**Encrypted (requires appropriate CEK):**
- Content payload (`ct`): the actual receipt content
- Rationale text (`ra` may be encrypted if sensitive)
- Extensions (`ex` may contain encrypted fields)

The design property this achieves: **chain integrity is verifiable without decryption.** A peer can verify signatures, walk hash links, and check chain structure without holding any CEK. The peer knows a receipt exists in some category at some time, and it's a valid link in the chain. They don't know what the receipt says.

### 5.2 The signature covers the content hash, not the ciphertext

Critical detail: the signature is computed over the content hash (`ch`), which is a hash of the *plaintext content*. This ensures:

- The signature commits to what actually happened, not to a possibly-manipulable ciphertext.
- Chain integrity is meaningful — the operator signed the truth of the content.
- Peers verifying without decryption confirm signature validity and chain-link validity but cannot verify the plaintext-hash without decrypting.
- Operators with the CEK can verify: decrypt content, hash it, compare to the signed `ch`. Any tampering during transit or storage is detected.

The associated data (AAD) in the AEAD encryption includes the plaintext receipt metadata. This binds the ciphertext to the specific receipt context — an attacker cannot swap ciphertexts between receipts.

### 5.3 CEK derivation per category

Content Encryption Keys are per-category and per-epoch:

```
CEK-{category}-e{n} = HKDF(CEK-base, "chain-content/{category}/epoch/{n}")
```

Where:
- `category` is the receipt category tag
- `n` is the epoch counter, incremented on rotation

The vault holds the epoch counter and CEKs for all past epochs (so historical receipts can be decrypted). A CEK is used for all receipts in its category-epoch until rotation.

### 5.4 CEK rotation

Rotation is a chain-anchored event. When the operator rotates the CEK for a category:

1. New CEK derived: `CEK-{category}-e{n+1}`
2. Rotation receipt written to chain, category `system:cek-rotation`, encrypted under the vault master key (not any CEK, since this is meta), containing the new CEK's derivation info.
3. Subsequent receipts in that category use the new CEK.
4. Old CEK remains in vault; old receipts decrypt with old CEK.

Rotation is triggered by:
- **Time-based:** rotation every N months as hygiene.
- **Event-based:** operator suspects compromise; rotates immediately.
- **Structural:** e.g., pattern-sharing key rotation for a bounded space triggers CEK rotation for that space's receipts.
- **Automatic:** e.g., session key rotation on locked-door session convening.

### 5.5 Storage layout for chain

**Decision required: chain storage medium.**

Options:
- **A. Single SQLite database.** Receipts as rows; encrypted content as BLOB column. Efficient queries, one file.
- **B. Log-structured file (append-only receipt file).** Simple, aligns with append-only chain semantics, easy to replicate.
- **C. Content-addressed store.** Receipts written as individual files named by their hash. Enables deduplication, simple peer replication.

Recommendation for further design: **A for the working substrate, with B or C for backup/replication.** SQLite gives us efficient chain queries (walk chain, filter by category, look up by ID). Backups can serialize to log-structured or content-addressed format for replication and long-term storage.

**Open decision.**

### 5.6 Metadata leakage acknowledged

Even with encrypted content, the plaintext parts leak information:

- **Timing:** when receipts are emitted reveals when the operator is active.
- **Volume:** how many receipts, of what types, at what cadence, reveals activity patterns.
- **Categories:** which categories are receiving receipts reveals what the operator is engaged with.
- **Chain hash values:** deterministic function of content; correlations across chains may leak.

Mitigations:
- **Padding:** pad ciphertext to fixed size buckets to hide content length. Trade-off: storage overhead.
- **Dummy receipts:** emit noise receipts under an inactive-decoy category to mask activity patterns. Trade-off: complexity, wasted storage.
- **Category obfuscation:** categories could be encrypted tokens rather than plaintext labels, resolvable only by the operator. Trade-off: complexity, breaks easy peer-side chain filtering.

**Decision required: metadata protection level.**

Recommendation for further design: baseline padding (all receipt ciphertexts padded to one of a small set of size buckets); categories as plaintext (efficiency and peer-verification friendliness); no dummy receipts in v1 (add later if threat model warrants).

---

## Part VI — Derived Cognitive State

### 6.1 What lives here

- **Cartographer ontology.** Trajectories, Decisions, Insights, Artifacts, Frictions. Persisted between sessions; regenerable from chain given time.
- **Regent persistent memory.** Long-term learned patterns, operator preferences, cross-session context.
- **Regent session memory.** Current session's working context, active reasoning state.
- **Officer state.** Per-officer in-session context, accumulated understanding.

### 6.2 Encryption architecture

Derived state has its own dedicated encryption keys under `DSK-*` (per key hierarchy). Distinct from CEKs to allow:

- Different rotation cadences (ontology may rotate on schedule; Regent session memory rotates per session).
- Different access patterns (ontology is queried heavily; Regent session is streamed).
- Separate compromise blast radius (a leaked CEK for one community doesn't leak the entire ontology).

### 6.3 Ephemerality by design

Regent session memory is ephemeral by default. Session key `DSK-regent-session` is derived per session with an ephemeral input (session identifier, plus current time nonce). At session end:

- Session key destroyed
- Session memory ciphertext optionally retained (encrypted under a rotation of the vault master key that's now gone)
- Effectively unrecoverable

This is a deliberate design choice: **the Regent forgets sessions by default.** Long-term memory requires explicit consolidation (a receipt on the chain records what the Regent learned from this session, decrypted-and-re-encrypted under the persistent memory key).

### 6.4 Ontology encryption granularity

The Cartographer ontology contains typed objects (Trajectories, Decisions, etc.). Should each object type have its own key?

**Decision required: ontology encryption granularity.**

Options:
- **A. Single key for all ontology.** Simplest. Compromise exposes everything.
- **B. Per-type keys.** Rotate independently. Compromise of one type doesn't expose others.
- **C. Per-Trajectory keys.** Finest granularity. Substantial key-management overhead.

Recommendation: **B for v1.** Balances compromise-compartmentalization with key-management sanity.

---

## Part VII — Peer Sharing and Capability-Scoped Decryption

### 7.1 The general pattern

When the operator shares chain state or ontology material with a peer (for research query, replication backup, community context, etc.), the sharing must:

- Give the peer exactly what they need, no more
- Be revocable (peer loses forward access)
- Be auditable (chain records the share)
- Not compromise the operator's master keys

The pattern: **envelope encryption via HPKE (Hybrid Public Key Encryption, RFC 9180).**

### 7.2 Envelope encryption workflow

To share receipts of category X with peer P:

1. Operator identifies the target receipts.
2. Operator generates an ephemeral sharing key K_share.
3. Operator wraps K_share for peer P using HPKE with P's public key: producing `enc_wrap = HPKE.Encrypt(P.pubkey, K_share)`.
4. For each receipt to share:
   - Get the underlying CEK from vault.
   - Decrypt receipt content with CEK.
   - Re-encrypt content with K_share (or leave underlying encryption intact if sharing the CEK is acceptable).
5. Package: `{enc_wrap, [receipt-ids, wire format]}` and send to P via mesh.
6. P decrypts K_share using HPKE with their private key: `K_share = HPKE.Decrypt(P.privkey, enc_wrap)`.
7. P decrypts receipt contents using K_share.

The operator's master CEKs never leave their device. K_share is scoped to this specific share to this specific peer for this specific purpose. If P is compromised, only what was shared is exposed.

### 7.3 Revocation

To revoke a peer's access to a specific ongoing share (e.g., a research mandate that had rolling access):

- Operator emits a revocation receipt.
- Operator rotates K_share for future receipts (so past K_share'd receipts are still decryptable by P, but future ones use a new key P doesn't have).
- If revocation must retroactively deny access, that's not possible — data P has already received is data P has. Sovereignty is one-way here.

### 7.4 Bulk chain replication (backup)

For peer-based chain replication (per Backup Landscape Option 13):

- Operator wraps their vault master key or a scoped replication key using HPKE for the peer.
- Peer receives encrypted chain state + wrapped decryption material.
- Peer stores blindly (cannot decrypt without their own private key + revocation status check).
- On recovery: operator authenticates to peer, peer transmits encrypted chain, operator decrypts on their new device.

Revocation: operator publishes a revocation receipt; peer is expected to delete the material. Compliance with revocation is a trust-and-reputation concern, not a structural guarantee — but the peer benefits little from retaining revoked material.

### 7.5 Multi-peer replication with quorum

For robustness, operator can shard chain state across multiple peers using Shamir Secret Sharing (per Backup Landscape Option 2 applied to the wrapping key). No single peer can decrypt; K-of-N reconstruction required. This makes peer-based backup robust to a fraction of peer compromises.

---

## Part VIII — Real-Time Session Content

Locked-door meetings, voice calls, live sessions all need real-time encryption with different properties than at-rest chain encryption.

### 8.1 Session key derivation

Session keys are derived via group Diffie-Hellman over the attendance manifest at session convening:

1. Convener issues the manifest (chain-anchored, per Locked-Door Sessions design).
2. Each participant contributes an ephemeral X25519 keypair.
3. Group DH ceremony produces a shared session key SEK.
4. SEK is used for AEAD encryption (XChaCha20-Poly1305) of session content in real time.

### 8.2 Forward secrecy

For ephemeral sessions:
- SEK is destroyed at session end.
- Session content transcripts (if any) are destroyed alongside SEK.
- Even if a participant's long-term key is compromised later, the session key cannot be reconstructed. Session content is unrecoverable.

For persistent sessions:
- SEK is encrypted under each participant's persistent memory key.
- Each participant retains session content encrypted with SEK on their own chain.
- Compromise of a participant's long-term key exposes their retained session content (they were always going to have this exposure).

### 8.3 Ratcheting for long-lived sessions

For long-duration real-time sessions (extended voice calls, multi-day working meetings), the SEK is ratcheted periodically (every N minutes or after M messages, using a symmetric ratchet like Signal's Double Ratchet). This provides forward secrecy even within the session — earlier session content is undecryptable if the current SEK is compromised.

### 8.4 Composition with non-recording attestation

Non-recording attestation (per `PEER-DISCOVERY-AS-OUTREACH-2026-07.md` on runtime integrity) composes: participants attest their nodes are not recording; SEK is the key that would need to be captured for recording to be useful; SEK is destroyed at session end for ephemeral sessions. The two mechanisms combine to give strong ephemerality guarantees.

---

## Part IX — Media at Rest

Captured media (photos, video, audio, files) has different characteristics than receipts: larger, more numerous, potentially long-lived, sometimes shared publicly.

### 9.1 Storage separation

Media is stored separately from the chain to avoid inflating the chain with large blobs. Chain receipts reference media by content hash; media itself lives in a dedicated media store:

```
~/ZeroPoint/media/
├── originals/       (per-media encrypted files, content-addressed)
├── thumbnails/      (encrypted preview versions)
└── shared/          (media re-encrypted for specific shares)
```

### 9.2 Encryption architecture

Each media file is encrypted with its own Media Encryption Key (MEK):
- MEK is unique per media file (derived from a media base key plus content identifier).
- MEK is stored in the vault under the operator's control.
- Content-addressed storage: filename is a hash of encrypted content, enabling deduplication across contexts.

### 9.3 Provenance metadata

Media provenance receipts (per `docs/design/PEER-DISCOVERY-AS-OUTREACH-2026-07.md` — actually, media provenance was discussed in-conversation and deserves its own design note not yet written) are chain receipts. They point to media by content hash. The provenance chain itself is chain-anchored; the media content is separately encrypted.

### 9.4 Sharing to communities

When media is shared to a community:
- Operator identifies the media
- Operator re-encrypts the media under the community's context key (or under a per-share key using HPKE, as in §7)
- Publication receipt references the re-encrypted media
- Recipients in the community decrypt using the community context key
- Media in `shared/` is the re-encrypted copy; original in `originals/` remains encrypted under MEK

---

## Part X — Backup Encryption

Backup is covered in `BACKUP-AND-RECOVERY-LANDSCAPE-2026-07.md` from the recovery angle. Here the cryptographic architecture.

### 10.1 Backup encryption key

Backup Encryption Key (BEK) derived from Genesis via HKDF with info `"zp/backup-encryption-key/v1"`. BEK is not persisted between backup operations — it's re-derived from Genesis each time a backup is created or restored.

**Alternative:** BEK derived from a separate backup passphrase. Advantage: backup accessible without Genesis (recovery scenario). Disadvantage: another secret for the operator to manage.

**Decision required: BEK derivation source.**

Recommendation: **support both, operator chooses at backup export time.** Fast path (Genesis-derived BEK, backup only recoverable if Genesis is recoverable). Recovery path (passphrase-derived BEK, backup recoverable independent of Genesis for disaster scenarios).

### 10.2 Backup content

Backup export includes:
- Chain receipts (with content still encrypted under CEKs)
- CEK index (encrypted under BEK)
- Vault contents (encrypted under BEK)
- Derived state (optional; encrypted under BEK)
- Backup metadata (backup timestamp, chain tip hash, format version)

The backup is a self-contained blob that can be restored on a new device given Genesis (or the backup passphrase).

### 10.3 Backup segmentation and Shamir

For distributed backup (per Landscape Option 2 or 13), the BEK itself can be Shamir-split. Each shard holds encrypted backup content; K-of-N shards allow reconstruction. Each shard on its own reveals nothing.

---

## Part XI — Cryptographic Primitives Selected

### 11.1 Symmetric AEAD

**Primary choice: XChaCha20-Poly1305** (RFC 8439 + extended nonce).

Rationale:
- Extended nonce (192 bits) allows random nonce generation without collision concerns.
- Software performance comparable to AES-GCM on hardware without AES-NI.
- No side-channel concerns from cache-timing attacks (constant-time construction).
- Widely supported in modern libraries (libsodium, ring, openssl).

**Fallback: AES-256-GCM** for hardware acceleration on modern CPUs. Runtime detection can choose per-platform. Both are supported in the file format.

### 11.2 Asymmetric encryption

**Primary choice: HPKE (RFC 9180) with X25519 + HKDF-SHA256 + XChaCha20-Poly1305.**

Rationale:
- Modern standardized construction.
- Well-analyzed security properties.
- Composable with the Ed25519/X25519 keys already in use.
- Enables single-message encryption (fire-and-forget peer sharing) and multi-message contexts.

### 11.3 Key derivation

**Choice: HKDF-SHA256** for structured derivation from Genesis and from parent keys.

**Choice: Argon2id** for password-based derivation (backup passphrase, fallback vault sealing).

Argon2id parameters (initial recommendation, subject to threat-model tuning):
- Memory: 256 MB
- Iterations: 3
- Parallelism: 4 lanes

### 11.4 Signing

**Existing: Ed25519** (already used for chain signatures).

### 11.5 Hashing

**Existing: Blake3** (already used for chain hash-linking).

### 11.6 Random number generation

Cryptographically secure PRNG from operating system:
- macOS/iOS: SecRandomCopyBytes
- Android: java.security.SecureRandom (which delegates to /dev/urandom)
- Linux: getrandom(2)
- Windows: BCryptGenRandom

Do not use language-level random generators for cryptographic material. Explicit check in code for correct source.

---

## Part XII — Storage Layout

Concrete filesystem layout for the operator's ZP runtime home.

```
~/ZeroPoint/
├── genesis/
│   ├── sealed.enc              # Genesis material sealed by sovereignty provider
│   ├── sovereignty.toml        # Which provider (Secure Enclave, TPM, hardware wallet)
│   └── ceremony.receipt        # Signed Genesis ceremony receipt (chain-verifiable)
│
├── vault/
│   ├── format.toml             # Vault format version, encryption scheme
│   ├── vault.enc               # Encrypted vault content (per Part IV)
│   └── vault.chain             # If append-log format (per §4.2 Option B): chain of vault mutations
│
├── chain/
│   ├── audit.db                # SQLite database (working store)
│   │                           # Rows: receipts with encrypted content column
│   └── epochs/                 # Sealed epoch archives after compaction
│       ├── epoch-{N}.enc       # Encrypted epoch archive
│       └── epoch-{N}.merkle    # Merkle inclusion proof anchor
│
├── ontology/
│   ├── trajectories.enc        # Encrypted Trajectory store
│   ├── decisions.enc           # Encrypted Decision store
│   ├── insights.enc            # Encrypted Insight store
│   ├── artifacts.enc           # Encrypted Artifact index
│   ├── frictions.enc           # Encrypted Friction store
│   └── index.enc               # Cross-object index for query performance
│
├── regent/
│   ├── persistent.enc          # Long-term memory (encrypted under DSK-regent-persistent)
│   └── sessions/               # Per-session ephemeral state
│       └── {session-id}.enc    # Destroyed at session end
│
├── officers/
│   ├── steward.enc             # Per-officer state
│   ├── sentinel.enc
│   ├── forge.enc
│   └── cleo.enc
│
├── media/
│   ├── originals/              # Content-addressed encrypted media
│   │   ├── {hash-prefix}/
│   │   │   └── {hash}.enc
│   ├── thumbnails/             # Preview versions
│   │   └── ...
│   └── shared/                 # Re-encrypted for specific shares
│       └── ...
│
├── mandates/
│   ├── issued.enc              # Grants I've given (encrypted)
│   └── received.enc            # Grants I hold (encrypted)
│
├── subscriptions/
│   └── filters.enc             # Local subscription filter state
│
├── backups/
│   ├── {timestamp}.zpbak       # Self-contained backup blob
│   └── manifest.enc            # Backup manifest with metadata
│
└── logs/
    ├── system.log              # Non-sensitive operational logs
    └── audit.log               # Access audit log (encrypted)
```

### 12.1 What's NOT stored on disk

- Genesis seed in plaintext.
- Vault master key.
- CEKs in plaintext (they're stored encrypted under vault master key).
- Session ephemeral keys after session end.
- Derived signing keys.

### 12.2 Directory permissions

Standard practice: `~/ZeroPoint/` and children set to `0700` (owner-only). Enforced at ZP startup; refuse to run if permissions are wrong. Additional OS-level protection: keychain-integrated backup exclusion where possible (avoid Time Machine including Genesis material).

---

## Part XIII — End-to-End Walkthrough

Concrete example: Ken publishes a message to `community:general`.

**1. Authentication (per session start).**
- Ken opens ZP client.
- Client prompts for authentication via sovereignty provider (Touch ID).
- Ken authenticates.
- Sovereignty provider unwraps Genesis material into secure enclave.
- Vault master key derived (via HKDF from Genesis).
- Vault opened; CEK index decrypted into memory.

**2. Compose message.**
- Ken types "Just shipped v8 of the whitepaper — feedback welcome."
- Regent captures content, decides to publish.

**3. Prepare receipt.**
- Payload serialized: `{"type": "message", "text": "Just shipped v8...", "attachments": []}`
- Category: `community:general`
- Look up CEK for current epoch: `CEK-community-general-e1` retrieved from vault.
- Encrypt content: `ct = XChaCha20-Poly1305.encrypt(CEK, nonce, payload, AAD)` where AAD is the plaintext receipt structure.
- Content hash: `ch = Blake3(payload)`.
- Timestamp: current time.
- Parent receipt: previous chain-tip receipt ID.

**4. Sign.**
- Assemble signable structure: `{id, rt, st, tg, ts, pr, pd, cat, ch}`.
- Sign with chain signing key (derived from Genesis, held in secure enclave): `sg = Ed25519.sign(structure)`.

**5. Write to chain.**
- Insert row into audit.db with plaintext structure + ciphertext + signature.
- Update chain tip.

**6. Publish via mesh announce.**
- Announce receipt to `community:general` destination hash.
- Announce packet contains: plaintext receipt structure + ciphertext + signature.

**7. Peer receives.**
- Peer's substrate receives announce.
- Peer verifies signature against Ken's known chain signing key.
- Peer verifies chain link (pr matches expected previous receipt).
- Peer checks if they hold `CEK-community-general-e1`.
- If yes: decrypt content, present via Regent.
- If no: receipt is a valid chain entry they can verify exists, but content is not accessible.

**8. Ken locks vault.**
- After idle timeout, vault re-locks.
- CEK index cleared from memory.
- Vault master key destroyed.
- Genesis material returned to sovereignty provider seal.

**9. Ken returns hours later.**
- Authenticates again.
- Vault reopens.
- Historical receipts remain fully decryptable (CEKs are in vault).

This is the end-to-end flow. Nothing is hand-waved.

---

## Part XIV — Open Design Decisions

Decisions that need to be made before implementation, extracted from throughout this document:

1. **Vault format** (§4.2): SQLite (A), append-log (B), or sealed-JSON (C). Recommendation: B for philosophical coherence with chain.

2. **Vault unlock semantics** (§4.4): default idle timeout duration; explicit lock affordances; continuous-session opt-in.

3. **Chain storage medium** (§5.5): SQLite (A) primary + log-structured (B) or content-addressed (C) for backup/replication.

4. **Metadata protection level** (§5.6): baseline padding; category plaintext vs. encrypted; dummy receipts.

5. **Ontology encryption granularity** (§6.4): single key (A), per-type keys (B), per-Trajectory keys (C). Recommendation: B.

6. **BEK derivation source** (§10.1): Genesis-derived only; passphrase-derived only; both (operator choice). Recommendation: both.

7. **Sovereignty provider set at launch** (§4.3): which providers to support in v1. Recommendation: Secure Enclave (macOS/iOS), StrongBox (Android), TPM (Linux/Windows), passphrase fallback. Hardware wallet (YubiKey/Trezor) as v1.1.

8. **Argon2id parameters** (§11.3): memory / iterations / parallelism. Initial values proposed; needs threat-model tuning.

9. **Duress-response affordances** (§2.5): duress authentication that opens reduced view; chain-anchored refusal receipt; deniable-existence hidden volumes. Which to include in v1?

10. **Chain-anchored anomaly detection integration** (§2.6): how deeply the Regent watches for compromise indicators.

---

## Part XV — Companion Documents

- `docs/ARCHITECTURE-2026-07.md` — canonical architecture. Part I §3.6 establishes singular sovereign root that this document operationalizes.
- `docs/design/BACKUP-AND-RECOVERY-LANDSCAPE-2026-07.md` — recovery options that this document's key hierarchy must support.
- `docs/design/PEER-DISCOVERY-AS-OUTREACH-2026-07.md` — peer transport, and the software integrity attestation pattern that composes with encryption to defend against runtime compromise.
- `docs/design/DISTRIBUTED-KNOWLEDGE-COMMONS-2026-07.md` — pattern-sharing key derivation; this document formalizes the derivation hierarchy those keys sit within.
- `docs/PERSONALITY-ADAPTATION-VALIDATION-PROTOCOL-2026-07.md` — mandate-scoped queries against chain state require the capability-scoped decryption architecture specified here (§VII).
- `docs/whitepaper-v9.md` — public thesis. Section 3.6 (singular sovereign root) and Section 6.2 (inference governance) both depend on the concrete architecture this document specifies.

---

## Part XVI — What This Document Doesn't Cover

Deliberate scope limits:

- **Multi-device operation and synchronization.** How the same operator running on multiple devices maintains synchronized state. Composes with backup and recovery. Separate design note.
- **Recovery ceremony UX.** The user experience of vault unlock, backup export, disaster recovery. Separate design work.
- **Migration between vault formats.** When the format changes across versions, how existing operators migrate. Operational concern.
- **Post-quantum considerations.** Ed25519 and X25519 are not quantum-resistant. When PQ transition matters is a separate risk assessment.
- **Formal security proof.** This document is design specification; formal analysis of the composition is a separate exercise.
- **Compliance frameworks.** How this architecture maps to specific regulatory requirements (GDPR, HIPAA, etc.) is jurisdiction-dependent.

---

*Nothing hand-waved. Every "encrypted at rest" mention elsewhere in the ZP corpus should now resolve to a specific mechanism specified here — the vault architecture (§IV), chain content encryption (§V), derived-state encryption (§VI), peer sharing via HPKE (§VII), realtime session keys (§VIII), media at rest (§IX), or backup encryption (§X). The key hierarchy (§III) makes explicit what derives from what. The storage layout (§XII) makes explicit where things live. The threat model (§II) makes explicit what we're defending against and what we're not.*
