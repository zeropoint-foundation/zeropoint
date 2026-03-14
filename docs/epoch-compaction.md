# Epoch-Based Chain Compaction

## Architecture Specification — ZeroPoint Receipt & Audit Chains

**Status:** Proposed
**Author:** Ken Romero, ThinkStream Labs
**Date:** March 2026

---

## The Problem

ZeroPoint's receipt and audit chains are append-only, hash-linked sequences. Every entry references the previous entry's hash, making the chain tamper-evident. This is the core integrity guarantee: remove an entry and the chain breaks; modify an entry and the hashes stop matching.

But append-only means unbounded growth. An agent performing 1,000 actions per day produces 1,000 receipts per day. Over a year, that is 365,000 entries. A fleet of 100 agents produces 36.5 million. The chain's integrity guarantee — every entry depends on every previous entry — is also its scaling constraint. You cannot simply drop old entries because downstream hashes depend on them.

The current implementation reflects this honestly: `ReceiptChain` is an in-memory `Vec<ChainEntry>` with no size limit, and the SQLite audit store has no pruning, retention, or compaction logic. Integrity first, optimization second. The integrity is proven (699 tests). Now we need the optimization.

---

## Design Constraints

Any solution must preserve these properties:

1. **Tamper evidence.** Modifying any entry in the chain must be detectable.
2. **Independent verifiability.** Any peer with the actor's public key can verify the chain without the actor's cooperation.
3. **Mesh compatibility.** Verification data must fit within Reticulum's 500-byte MTU (465 bytes payload after headers).
4. **No central coordinator.** No trusted third party holds the "real" chain. Every node is sovereign.
5. **Tenet III compliance.** "If it is not in the chain, it did not happen." Compaction must not destroy evidence — only reorganize how it is stored and verified.

---

## The Mechanism: Epochs and Seals

### Core Concept

The chain is divided into **epochs** — fixed-size segments that, once complete, are summarized by a signed **EpochSeal** and become eligible for archival. The seal preserves the cryptographic integrity of the epoch's contents in a compact form, allowing verification without holding every individual entry.

Think of it like a notarized ledger. You write entries on pages. When a page is full, a notary stamps it with a summary that covers everything on the page. You can file the page in a cabinet, but the stamp stays in the active ledger. Anyone who wants to verify a specific entry on the filed page can retrieve it and check it against the stamp. The stamp chain — the sequence of stamps in the active ledger — is itself a verifiable history of the entire ledger.

### Epoch Boundaries

An epoch closes when either condition is met:

- **Entry count:** The epoch contains `EPOCH_MAX_ENTRIES` entries (default: 8,192 — chosen as a power of 2 for clean Merkle tree construction)
- **Time window:** The epoch has been open for `EPOCH_MAX_DURATION` (default: 7 days)

Whichever threshold is reached first triggers the seal. This ensures that both high-throughput agents (hitting entry limits quickly) and low-throughput agents (hitting time limits slowly) produce regular seals.

The current epoch — the one still accepting new entries — is always held in full in the active store. Only sealed epochs are eligible for archival.

### The Merkle Tree

When an epoch closes, a Merkle tree is computed over its entries.

Each leaf of the tree is the `entry_hash` (Blake3) of one chain entry. Leaves are ordered by sequence number — the same order they appear in the chain. The tree is constructed bottom-up: pairs of hashes are concatenated and hashed together, producing parent nodes, until a single root hash remains.

```
                    Merkle Root
                   /            \
              H(0-3)            H(4-7)
             /      \          /      \
         H(0-1)   H(2-3)  H(4-5)   H(6-7)
         /   \    /   \    /   \    /   \
        E0   E1  E2   E3  E4   E5  E6   E7
```

For an epoch of 8,192 entries, the tree has 13 levels. The Merkle root is a single 32-byte Blake3 hash that cryptographically commits to every entry in the epoch. Change any entry and the root changes.

**Odd-count handling:** If the entry count is not a power of 2, the last entry at each level is promoted without pairing. This is standard Merkle tree behavior — no duplication of the last leaf.

**Hash function:** Blake3, matching the existing chain hash function. The concatenation format is: `blake3(left_hash || right_hash)` where `||` is byte concatenation.

### The EpochSeal

The EpochSeal is a receipt — it joins the chain like any other entry. It is the first entry of the *next* epoch, linking the sealed epoch to the ongoing chain.

```rust
struct EpochSeal {
    // ── Identity ──
    epoch_number: u64,           // Monotonic, starting from 0
    seal_id: String,             // Receipt ID, prefixed "seal-"

    // ── Chain Linkage ──
    prev_seal_id: Option<String>,   // None for epoch 0's seal
    prev_seal_hash: Option<String>, // None for epoch 0's seal
    chain_prev_hash: String,        // Hash of the last entry in the sealed epoch
                                    // (standard chain linkage — this IS a chain entry)

    // ── Epoch Summary ──
    entry_count: u64,            // Number of entries in this epoch
    first_entry_hash: String,    // Hash of epoch's first entry
    last_entry_hash: String,     // Hash of epoch's last entry
    first_sequence: u64,         // Global sequence number of first entry
    last_sequence: u64,          // Global sequence number of last entry

    // ── Integrity ──
    merkle_root: String,         // Blake3 Merkle root over all entry_hashes in order
    merkle_depth: u8,            // Tree depth (for verification)

    // ── Metadata ──
    epoch_opened_at: DateTime<Utc>,
    epoch_sealed_at: DateTime<Utc>,

    // ── Signing ──
    signature: String,           // Ed25519 signature over canonical JSON of all above fields
    signer_public_key: String,   // The node's signing key
}
```

The seal is signed by the same key that signs the node's regular chain entries. This means a peer verifying the seal chain gets the same cryptographic assurance as verifying individual entries: the seal was produced by the claimed actor and has not been modified.

### How the Seal Joins the Chain

The seal is a chain entry. It has a `chain_prev_hash` that references the last entry of the epoch it is sealing. The next regular entry after the seal references the seal's own hash as its `prev_hash`. The chain is continuous — the seal does not break the hash linkage.

```
... → Entry 8190 → Entry 8191 → [EpochSeal #0] → Entry 8192 → Entry 8193 → ...
                                  ↑                 ↑
                          seals entries 0–8191    first entry of epoch 1
                          merkle_root covers       prev_hash = seal's hash
                          all 8192 entries
```

### The Seal Chain

The seals form their own verifiable sequence via `prev_seal_id` and `prev_seal_hash`. This is a lightweight chain-of-chains:

```
[Seal #0] → [Seal #1] → [Seal #2] → [Seal #3] → ... → [Seal #N] → [current epoch]
   ↓            ↓            ↓            ↓                  ↓
 Epoch 0     Epoch 1     Epoch 2     Epoch 3            Epoch N
 (archived)  (archived)  (archived)  (archived)         (archived)
```

To verify the entire history of a node, a peer needs only the seal chain (N seals, each a few hundred bytes) plus the current epoch's entries. This is O(N) in epochs, not O(M) in entries. For an agent that has produced 1 million entries across 122 epochs, verification requires checking 122 seals instead of walking 1 million entries.

---

## Verification Modes

The epoch/seal architecture supports four verification modes, each appropriate for different situations:

### Mode 1: Current Epoch — Full Walk

For the current (unsealed) epoch, verification is the same as today: walk the entries, check each `prev_hash`, verify signatures. This is what peers do when challenging recent activity. The current epoch is bounded by `EPOCH_MAX_ENTRIES`, so the maximum walk is 8,192 entries.

### Mode 2: Seal Chain — History Overview

To verify the broad integrity of a node's history, walk the seal chain: check that each seal's `prev_seal_hash` matches the previous seal's hash, verify each seal's signature, and confirm the sequence numbers and entry counts are consistent (no gaps, no overlaps). This proves the node claims a specific history of epochs without examining individual entries.

**Cost:** One seal is approximately 400–500 bytes serialized. The full seal chain for a year of weekly epochs is ~52 seals ≈ 25 KB. Fits in roughly 50 mesh packets.

### Mode 3: Epoch Spot-Check — Merkle Proof

To verify that a specific entry belongs to a specific sealed epoch, request a **Merkle proof** — the path from the entry's leaf to the epoch's Merkle root. The proof consists of the sibling hashes at each level of the tree.

For an epoch of 8,192 entries (depth 13), a Merkle proof is 13 hashes × 32 bytes = 416 bytes. This fits in a single mesh packet. The verifier:

1. Takes the entry's `entry_hash` as the leaf
2. Hashes it with each sibling in the proof path, bottom-up
3. Compares the result to the `merkle_root` in the signed seal

If it matches, the entry is proven to be part of the sealed epoch. No other entries need to be examined.

### Mode 4: Epoch Full Verification — Reconstruct and Compare

For maximum assurance (or forensic investigation), request all entries in a sealed epoch from the archive, reconstruct the Merkle tree locally, and compare the computed root against the seal's `merkle_root`. This is expensive but definitive. It is not expected to be routine — it's the "audit the auditor" mode.

---

## Storage Architecture

### Active Store (SQLite)

The active store holds:

- **Current epoch entries:** All entries in the unsealed current epoch (max 8,192)
- **Seal chain:** All EpochSeals ever produced (lightweight, grows by ~1 entry/week)
- **Seal index:** Epoch number → seal ID mapping for fast lookup

```sql
-- Current epoch entries (same schema as today)
CREATE TABLE active_entries (
    id TEXT PRIMARY KEY,
    sequence INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    conversation_id TEXT NOT NULL,
    policy_decision TEXT NOT NULL,
    policy_module TEXT NOT NULL,
    receipt TEXT,
    signature TEXT
);

-- Seal chain
CREATE TABLE epoch_seals (
    epoch_number INTEGER PRIMARY KEY,
    seal_id TEXT NOT NULL UNIQUE,
    seal_hash TEXT NOT NULL,
    prev_seal_hash TEXT,
    merkle_root TEXT NOT NULL,
    merkle_depth INTEGER NOT NULL,
    entry_count INTEGER NOT NULL,
    first_sequence INTEGER NOT NULL,
    last_sequence INTEGER NOT NULL,
    first_entry_hash TEXT NOT NULL,
    last_entry_hash TEXT NOT NULL,
    epoch_opened_at TEXT NOT NULL,
    epoch_sealed_at TEXT NOT NULL,
    signature TEXT NOT NULL,
    signer_public_key TEXT NOT NULL,
    -- Full canonical JSON for re-verification
    canonical_json TEXT NOT NULL
);

CREATE INDEX idx_active_sequence ON active_entries(sequence);
CREATE INDEX idx_active_conversation ON active_entries(conversation_id);
CREATE INDEX idx_seal_hash ON epoch_seals(seal_hash);
```

When an epoch is sealed:
1. Compute Merkle tree over active entries
2. Create and sign EpochSeal
3. Insert seal into `epoch_seals`
4. Export active entries to archive
5. Clear `active_entries`
6. Insert the seal as the first entry of the new epoch in `active_entries`

### Archive Store

Sealed epoch entries are exported to compressed archive files:

```
archives/
  epoch-000000.zst    # Zstandard-compressed, canonical JSON lines
  epoch-000001.zst
  epoch-000002.zst
  ...
```

Each archive file contains one JSON object per line (entry), ordered by sequence number. The file is compressed with Zstandard (zstd) for ~5:1 compression on JSON data. A typical 8,192-entry epoch at ~500 bytes per entry is ~4 MB uncompressed, ~800 KB compressed.

Archive files are immutable once written. They are never modified, only read (for spot-check verification or forensic retrieval).

**Retention policy** is a deployment configuration, not a protocol decision:

```rust
struct RetentionPolicy {
    /// Keep archives locally for this duration. After expiry,
    /// the archive may be deleted — the seal still proves the
    /// epoch's integrity, but individual entries cannot be retrieved
    /// locally. Peers or archival nodes may still hold copies.
    local_retention: Duration,      // e.g., 90 days

    /// Optional: replicate archives to external storage before
    /// local expiry. Deployment-specific (S3, IPFS, NAS, etc.)
    external_replication: Option<ReplicationConfig>,
}
```

### In-Memory State

The `ReceiptChain` struct changes from holding the full chain to holding only the working set:

```rust
pub struct ReceiptChain {
    chain_id: String,

    // Current epoch (unsealed, accepting entries)
    current_epoch: EpochBuffer,

    // Chain tip (hash of most recent entry)
    head_hash: String,

    // Epoch counter
    current_epoch_number: u64,

    // Reference to most recent seal (for seal chain linkage)
    last_seal: Option<EpochSeal>,
}

struct EpochBuffer {
    entries: Vec<ChainEntry>,     // Bounded by EPOCH_MAX_ENTRIES
    opened_at: DateTime<Utc>,
    epoch_number: u64,
}
```

Memory usage is now bounded: at most `EPOCH_MAX_ENTRIES` entries in memory (8,192 × ~500 bytes ≈ 4 MB), plus the most recent seal (~500 bytes). Independent of total chain length.

---

## Mesh Protocol Integration

### Challenge/Response with Epochs

The existing `AuditChallenge` and `AuditResponse` protocol extends naturally:

**New challenge types:**

```rust
enum ChallengeRange {
    // Existing
    Recent(usize),              // Most recent N entries
    SinceHash(String),          // Entries since a known hash

    // New
    SealChain,                  // Request the full seal chain
    EpochEntries(u64),          // Request all entries for epoch N
    MerkleProof {               // Request proof for a specific entry
        epoch: u64,
        entry_hash: String,
    },
}
```

**Response sizes:**

| Challenge Type | Response Size | Packets (500B MTU) |
|---|---|---|
| Recent(10) | ~3 compact entries/packet | 4 packets |
| SealChain (52 epochs) | ~1 seal/packet | 52 packets |
| MerkleProof (depth 13) | 416 bytes | 1 packet |
| EpochEntries (8,192) | 3 entries/packet | 2,731 packets |

The common verification path — request seal chain, spot-check a few entries with Merkle proofs — requires roughly 55 packets for a year's history. This is practical over mesh, even at constrained bandwidths.

### Attestation with Seals

The existing `PeerAuditAttestation` gains epoch awareness:

```rust
struct PeerAuditAttestation {
    // Existing fields...
    peer: String,
    oldest_hash: String,
    newest_hash: String,
    entries_verified: usize,
    chain_valid: bool,
    signatures_valid: usize,

    // New fields
    seals_verified: usize,           // How many seals were checked
    epochs_spot_checked: Vec<u64>,   // Which epochs had entries verified
    merkle_proofs_valid: usize,      // How many Merkle proofs passed
}
```

This gives the attestation more granularity: "I verified 52 seals covering 365,000 entries, spot-checked 5 epochs with Merkle proofs, and everything checks out" is a much stronger statement than "I verified the last 3 entries."

---

## Scaling Analysis

### Storage

| Duration | Entries | Epochs | Active Store | Archive (compressed) | Seal Chain |
|---|---|---|---|---|---|
| 1 day | 1,000 | 0 (open) | 500 KB | — | — |
| 1 week | 7,000 | 0 (open) | 3.5 MB | — | — |
| 1 month | 30,000 | 3 | 4 MB | 2.4 MB | 1.5 KB |
| 1 year | 365,000 | 44 | 4 MB | 35 MB | 22 KB |
| 5 years | 1,825,000 | 222 | 4 MB | 175 MB | 111 KB |

Active store is bounded at ~4 MB regardless of total history. Archive grows linearly but compresses well and can be offloaded per retention policy. Seal chain is negligible.

### Verification

| Scenario | Without Epochs | With Epochs |
|---|---|---|
| Verify 1 year history | Walk 365,000 entries | Check 44 seals + spot-check |
| Verify single entry | Walk from genesis | 1 Merkle proof (416 bytes) |
| Peer attestation over mesh | 121,667 packets | ~50 packets (seals) + ~5 packets (spot-checks) |
| Memory usage | 182 MB (unbounded) | ~4 MB (bounded) |

### Computational Cost

Sealing an epoch of 8,192 entries requires:
- 8,192 leaf hashes (already computed as `entry_hash`) — **zero additional cost**
- ~8,191 internal Merkle tree hashes — Blake3 is ~4 GB/s on modern hardware, so hashing 8,191 × 64 bytes ≈ 512 KB takes **< 1 ms**
- 1 Ed25519 signature — **< 1 ms**
- 1 SQLite insert + 1 archive write — **< 10 ms**

Total sealing cost: **under 15 milliseconds.** Negligible for an operation that happens at most once per 8,192 actions or once per week.

---

## What This Does Not Solve

**Disaster recovery.** If archived entries are lost and no peer holds copies, the seal proves they *existed* with a specific Merkle root, but cannot reconstruct their content. Durability requires replication, which is a deployment decision. ZeroPoint does not mandate replication because mandating infrastructure contradicts mesh sovereignty.

**Malicious epoch creation.** A compromised node could produce a valid seal over fabricated entries. The seal proves internal consistency, not truthfulness. This is inherent to any self-attested system. The defense is peer attestation: if peers regularly spot-check entries against their own records of interactions with the node, fabrication is detectable.

**Retroactive auditing of pruned epochs.** If local retention expires and external archives are unavailable, the detailed entries are gone. The seal chain still proves the *structure* of history (entry counts, time ranges, Merkle roots), but individual actions cannot be examined. This is the deployment operator's tradeoff: storage cost vs. audit depth. The protocol does not make this choice for them.

---

## Implementation Sequence

### Phase 1: Merkle Tree and Seals
- Implement `MerkleTree` struct with Blake3 leaf/internal hashing
- Implement `EpochSeal` struct and signing
- Add `seal_epoch()` method to `ReceiptChain`
- Migrate `ReceiptChain` from unbounded `Vec` to `EpochBuffer` + seal reference
- Tests: tree construction, proof generation, proof verification, seal signing/verification

### Phase 2: Storage
- Add `epoch_seals` table to SQLite schema
- Implement archive export (zstd-compressed JSON lines)
- Implement seal chain queries (`get_seal_chain()`, `get_seal_by_epoch()`)
- Add epoch boundary detection (entry count + time window triggers)
- Tests: seal persistence, archive round-trip, boundary triggers

### Phase 3: Verification Protocol
- Extend `AuditChallenge` with `SealChain`, `EpochEntries`, `MerkleProof` variants
- Extend `AuditResponse` with seal chain and Merkle proof payloads
- Implement Merkle proof generation from archived entries
- Update `PeerAuditAttestation` with epoch-aware fields
- Tests: challenge/response round-trip over mesh, attestation with spot-checks

### Phase 4: Retention
- Implement `RetentionPolicy` configuration
- Add background task for expired archive cleanup
- Add metrics: entries per epoch, seal chain length, archive sizes
- Tests: retention enforcement, cleanup correctness

---

## Constants

```rust
/// Maximum entries per epoch. Power of 2 for clean Merkle trees.
pub const EPOCH_MAX_ENTRIES: usize = 8_192;

/// Maximum duration of an open epoch before forced seal.
pub const EPOCH_MAX_DURATION: Duration = Duration::from_secs(7 * 24 * 60 * 60); // 7 days

/// Maximum Merkle proof depth (log2 of EPOCH_MAX_ENTRIES).
pub const MAX_MERKLE_DEPTH: u8 = 13;

/// Maximum seals per mesh response (fits in MTU).
pub const MAX_SEALS_PER_RESPONSE: usize = 1;

/// Maximum Merkle proof nodes per mesh response.
pub const MAX_PROOF_NODES_PER_RESPONSE: usize = 13; // Full proof fits in one packet
```
