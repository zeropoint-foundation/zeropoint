# zp-audit

Hash-chained, always-on audit trail for ZeroPoint v2 with collective verification.

A cryptographically-verified, append-only audit log using SQLite and Blake3. Every governance action creates an immutable, hash-chained entry. The audit system also supports distributed verification — peers can challenge each other's chains and produce signed attestations of integrity.

## Architecture

The audit system has two layers: local persistence (AuditStore + ChainBuilder) and collective verification (peer challenges, responses, and attestations).

### Local Audit Trail

**AuditStore** (`src/store.rs`) opens or creates an SQLite database, manages append-only insertion, provides query by conversation ID, and implements hash chain verification. The genesis hash (Blake3 of empty string) anchors the chain root.

**ChainBuilder** (`src/chain.rs`) constructs audit entries with deterministic hashing. `build_entry()` takes an explicit previous hash; `build_entry_from_genesis()` creates the first entry.

### Collective Audit (`src/collective_audit.rs`)

Distributed audit trail verification spanning multiple agents.

**AuditChallenge** — A peer requests recent audit entries from another peer, either by count (`recent(count)`) or since a known hash (`since_hash(hash)`). Challenges carry the challenger's address and a nonce.

**AuditResponse** — The challenged peer responds with a chain of `CompactAuditEntry` records. Each compact entry contains the entry hash, previous hash, timestamp, actor, action summary, and optional signature — enough to verify chain linkage without transmitting full audit data.

**PeerAuditAttestation** — After verifying a response, the verifier produces a signed attestation recording the peer's address, whether the chain was valid, the chain length, the time range covered, and the verifier's signature. Attestations are stored locally and can be broadcast to the mesh.

`verify_peer_chain()` validates a chain segment: checks that each entry's `prev_hash` matches the previous entry's `entry_hash`, and that all hashes are non-empty. Returns true only if the entire chain is intact.

### Chain Verifier (`src/verifier.rs`)

`ChainVerifier` provides comprehensive chain validation beyond basic linkage. It checks genesis hash correctness, hash chain integrity, optional signature verification (Ed25519), and produces a detailed `VerificationReport` with per-entry results, hash validity ratio, and an overall pass/fail determination.

## Database Schema

```sql
CREATE TABLE audit_entries (
    id TEXT PRIMARY KEY,
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
```

Indexes on `conversation_id` and `timestamp` for efficient queries.

## API

### AuditStore

```rust
impl AuditStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self>
    pub fn append(&self, entry: AuditEntry) -> Result<()>
    pub fn get_latest_hash(&self) -> Result<String>
    pub fn get_entries(&self, conversation_id: &ConversationId, limit: usize) -> Result<Vec<AuditEntry>>
    pub fn verify_chain(&self) -> Result<bool>
    pub fn export_chain(&self) -> Result<Vec<AuditEntry>>
}
```

### Collective Audit

```rust
// Challenge a peer's audit chain
let challenge = AuditChallenge::recent(10);

// Build a response from local entries
let response = AuditResponse::from_entries(&entries);

// Verify the response chain
let valid = verify_peer_chain(&response.entries);

// Produce an attestation
let attestation = PeerAuditAttestation::new(peer_hash, valid, chain_length, time_range, signature);
```

## Design Decisions

1. **Synchronous SQLite**: Not async — SQLite is fast enough for audit logging and avoids complexity.
2. **JSON serialization for hashing**: Deterministic JSON (stable key ordering via serde_json) ensures reproducible hashes across rebuilds.
3. **Genesis hash**: Blake3 of empty string as chain root makes the first entry's `prev_hash` predictable and verifiable.
4. **Compact entries for mesh**: Full audit entries are too large for the 465-byte mesh packet MTU. `CompactAuditEntry` carries only the fields needed for chain verification.

## Dependencies

All inherited from workspace: `rusqlite` (bundled SQLite), `blake3` (hashing), `chrono` (timestamps), `serde`/`serde_json` (serialization), `thiserror` (errors), `tracing` (logging), `uuid` (identifiers), `ed25519-dalek` (signatures), `zp-core` (shared types).

## Testing

33 tests covering chain linkage, genesis hashing, compact entry serialization, audit challenge/response roundtrips, peer chain verification (valid, broken, empty chains), attestation creation and signing, and chain export.

```bash
cargo test -p zp-audit
```
