# RFC: Mesh Inbound Authentication v1

**Status:** Draft
**Author:** ZeroPoint core (sweep 5 scoping)
**Date:** 2026-04-07
**Tracks:** R1 (mesh inbound revalidation)

## 1. Problem

`MeshBridge::handle_inbound_receipt` (`crates/zp-pipeline/src/mesh_bridge.rs:291`)
and `MeshBridge::handle_inbound_delegation` (same file, line 415) accept
`CompactReceipt` / `CompactDelegation` payloads from peers and store them
after validating only structural fields (non-empty `id`, valid `status`).

Neither path performs cryptographic verification of the payload:

- `CompactReceipt` carries `ch` (content hash) and an optional `sg`
  (ed25519 signature over `ch`). The bridge currently ignores `sg`.
- `CompactDelegation` strips signature material entirely by design — there
  is no field on the wire that would let a receiver verify it.

A malicious or buggy peer can therefore:

1. Inject a receipt with arbitrary `ch` and have it stored in
   `received_receipts`, polluting downstream reputation and audit views.
2. Inject delegation grants the receiver cannot verify came from the
   purported grantor.

## 2. Constraints

- The 465-byte mesh MTU must not be exceeded by the wire format. CompactReceipt
  is already ~150–300 bytes; CompactDelegation has no headroom for a 64-byte
  signature plus a key id.
- Existing peers in the field already speak the v0 wire format. A v1 must
  either be backwards-compatible (optional fields, version negotiation) or
  gated behind an explicit handshake.
- The canonical `AuditStore` is *not* affected — this RFC concerns only the
  mesh bridge and its in-memory `received_receipts` / delegation paths.

## 3. Proposal

### 3.1 PeerKeyStore

Introduce a trait in `zp-mesh`:

```rust
pub trait PeerKeyStore: Send + Sync {
    /// Returns the ed25519 verifying key for a peer, if known.
    fn verifying_key(&self, peer_hash: &[u8; 16]) -> Option<ed25519_dalek::VerifyingKey>;
}
```

`MeshNode` already tracks peer identity; it gains a method
`fn key_store(&self) -> Arc<dyn PeerKeyStore>` returning a handle to a
keystore populated during peer link establishment (the existing
negotiation handshake exchanges identity material).

`MeshBridge::new` accepts the keystore alongside `MeshNode`.

### 3.2 CompactReceipt verification

Add to `zp-mesh::envelope`:

```rust
impl CompactReceipt {
    /// Verify ed25519 signature over `ch` using the supplied verifying key.
    /// Returns Ok(true) if signed and valid, Ok(false) if `sg` is None,
    /// Err if signature parse or verification fails.
    pub fn verify_signature(
        &self,
        key: &ed25519_dalek::VerifyingKey,
    ) -> Result<bool, MeshError> { ... }
}
```

Wire `handle_inbound_receipt` to call this when `sg.is_some()` and the
keystore returns a key for `sender_hash`. Policy table:

| `sg` present | key known | result |
| --- | --- | --- |
| yes | yes, valid | accept (full trust) |
| yes | yes, invalid | reject + negative reputation |
| yes | no | accept with `unverified` flag, log warn |
| no | — | accept with `unsigned` flag, log warn |

Add `unverified: bool` to `ReceivedReceipt` so downstream consumers can
distinguish authenticated from anonymous payloads.

### 3.3 CompactDelegation v1

CompactDelegation has no signature field. Two options:

**Option A — Inline signature (preferred).** Add `sg: Option<String>` (64
bytes hex, optional for back-compat). Recompute the canonical preimage
locally as `(ct, sc, tl, gr, ge, tt, ts, ri, pi, dd, md, ex)` ordered
JSON, blake3-hash, and ed25519-verify. ~80 bytes overhead, fits within
the MTU budget.

**Option B — Out-of-band envelope signature.** Have `MeshEnvelope`
itself carry an ed25519 signature over its inner payload bytes. Smaller
delta to CompactDelegation, but couples envelope routing concerns to
payload authenticity.

Option A is recommended for symmetry with CompactReceipt and explicit
per-payload provenance.

### 3.4 Wire version negotiation

Bump `MeshEnvelope::version` from 1 → 2. Peers advertise supported
versions during link negotiation. v1↔v2 peers fall back to v1 (unsigned
delegations, optional receipt signatures unchecked) but log a `warn` so
operators can track upgrade status.

## 4. Test plan

- Unit: `CompactReceipt::verify_signature` with valid, tampered, wrong-key,
  parse-error cases.
- Unit: `CompactDelegation::verify_signature` parallel cases.
- Integration: `handle_inbound_receipt` honors all four cells of the
  policy table from §3.2.
- Integration: `handle_inbound_delegation` rejects v1 grant when the
  bridge is configured `require_signed_delegations = true`.
- Multinode integration: two `MeshBridge` instances exchange a signed
  receipt + delegation end-to-end and reach the same trust verdict.

## 5. Migration

- Sweep 5 (this milestone): land RFC, no code changes.
- Sweep 6: implement §3.1 PeerKeyStore + §3.2 CompactReceipt verification
  behind a feature flag (`mesh-auth-v1`); leave default behavior unchanged.
- Sweep 7: implement §3.3 CompactDelegation v1 (Option A); flip the
  feature flag on by default; emit deprecation warning when a v0 peer
  link is established.
- Sweep 8: remove v0 fallback after one release cycle.

## 6. Open questions

- How does the keystore get bootstrapped before the first peer link is
  fully established? (Likely: trust-on-first-use with the link's
  ephemeral key, then pin.)
- Should `unverified` inbound receipts contribute to reputation at all,
  or only the audited portion? Current proposal: yes, but at half weight.
- Do we need replay protection on top of signatures? (Existing `ts` field
  + dedup-by-id may be sufficient; document explicitly.)

## 7. Out of scope

- Canonical `AuditStore` chain integrity — already covered by AUDIT-03
  recanonicalization and Sweeps 1–4.
- Pedagogical `zp-receipt::ReceiptChain` and `zp-receipt::epoch` — see
  `docs/audit-architecture.md` §6 and the crate-level doc guard added in
  Sweep 2.
