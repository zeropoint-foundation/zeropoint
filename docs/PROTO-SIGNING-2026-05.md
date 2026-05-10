# Proto Message Signing — Phase 2b Design

*Drafted 2026-05-09. Resolves task #78. Companion to AGENTIC-SURFACE-2026-05.md
(II.14) and ARCHITECTURE-2026-05.md II.7 (verb-set schema layer).*

## The question

Several gRPC verbs return *signed envelopes* (Architecture VII.3) — proto
messages with a `signature: common.Signature` field that the issuer
populates and consumers verify. Examples on `NodeStatus`:
`SignedIdentity`, `SignedSecurityPosture`, `SignedTopologyEnvelope`,
`SignedBlastRadiusEnvelope`, `SignedFleetNodeEnvelope`. Many more across
`Guard`, `Delegation`, `Audit`, etc.

How does a gRPC handler sign a proto-generated message?

## The constraint

The substrate already has a *single canonical form* for signed material —
"ZP-canonical-v1" — defined in `zp_receipt::canonical` (Seam 17) and
exposed through the `Signable` trait (Seam 20). The discipline doc on
`canonical.rs` is explicit:

> there is one canonical form, defined once, used everywhere. Per-domain
> hand-rolled preimages are forbidden because they're how subtle
> inconsistencies creep in.

The verification side is locked down by discipline pin
`no_direct_verify_strict_outside_helper` — every signature check goes
through `zp_receipt::verify::verify_signature`.

Any proto-signing approach must honor both: one canonical form, one
verification primitive.

## Three paths considered

**(A) Sign prost's deterministic encoding directly.** Hash the proto
wire bytes, sign the hash. Self-contained, uses prost's existing
deterministic encoding rules.

*Rejected.* Adopting proto-bytes-as-canonical introduces a *second*
canonical form alongside ZP-canonical-v1, splitting the discipline that
Seam 17/20 just unified. Schema evolution rules now bind on proto field
numbering (renumbering breaks signatures), and debugging requires
hexdump of binary preimages instead of inspectable JSON. The discipline
doc forbids this exact pattern.

**(B) Add serde derives to generated proto types via tonic-build config,
then implement `Signable` for each signed envelope.** Single canonical
form preserved; existing Signable infrastructure works as-is.

*Rejected.* Adding global `#[derive(Serialize, Deserialize)]` to *every*
generated message has wide blast radius for a narrow need (only
envelopes with signature fields actually need this). Excluding the
signature field requires `#[serde(skip_serializing_if = ...)]` injected
via `tonic_build::Builder::field_attribute`, which is fragile to schema
churn. Per-message hand-rolled preimage gives more explicit control and
matches how `Receipt`, `CapabilityGrant`, etc. already work.

**(C) Hand-rolled preimage per signed verb, signed via existing
canonical machinery.** In each handler, build a `serde_json::Value` that
mirrors the proto message's fields *minus the signature*, sign with
`canonical_bytes` + `Signer::sign`, populate the proto's signature
field. Each handler explicitly owns its preimage rule, matching the
`Signable` trait's discipline.

***Selected.*** Single canonical form preserved. Signing primitive
(`SigningKey::sign`) and verification primitive
(`zp_receipt::verify::verify_signature`) both unchanged. Per-handler
preimage construction is explicit and auditable. Discipline pins
already in place catch verification deviations.

## Which key signs

`ServerIdentity.signing_key` — the **Operator key** from the
Genesis→Operator certificate hierarchy. Already publicly accessible at
`state.0.identity.signing_key` in any handler.

This is *not* the same key as `AuditSigner`. The two coexist by design:

| Surface | Key | Why |
|---------|-----|-----|
| Audit chain entries | `AuditSigner` (derived from Genesis via `derive_audit_signer_seed`) | Purpose-built for chain entry signing, scoped to `AuditStore::append` |
| Node-level envelopes | `ServerIdentity.signing_key` (Operator key) | "This server's identity" — what `SignedIdentity` etc. attest to |
| Receipts (chain-bound) | `AuditSigner`, via `AuditStore::append` | Same as audit entries — receipts ARE chain entries |

Both keys descend from Genesis (Architecture II.6 — identity is a key,
not a location), so a verifier with knowledge of the Genesis hierarchy
can validate either. The separation is operational: rotating one
shouldn't invalidate the other.

## The cross-language verification cost

Signing canonical JSON means external gRPC clients (Python, TypeScript,
Go, etc.) need to implement "ZP-canonical-v1" in their language to
verify substrate envelopes — same lexicographic-key + serde_json-bytes
rules.

This is a documentation cost the substrate already pays for the audit
chain (Seam 22 audit-doc captures it). Extending the same cost to
node-level envelopes is consistent. The alternative (proto-bytes
signing per Path A) would have made client verification slightly
easier at the cost of splitting the substrate's canonical discipline —
a bad trade.

The cost mitigates with adoption: once `zp-mcp` (task #72) and
`zp-agui` (task #73) ship, most agentic clients will go through MCP
servers that handle verification on the substrate side, and clients
just consume already-verified data. Direct gRPC clients are the
minority case and can be expected to do the canonical-form work.

A future task should land "ZP-canonical-v1 reference implementation
in TypeScript and Python" alongside the SDK content rewrite (#56).

## The implementation template

Every signed-envelope verb follows this shape:

```rust
async fn get_identity(
    &self,
    _request: Request<GetIdentityRequest>,
) -> Result<Response<SignedIdentity>, Status> {
    let identity = &self.state.0.identity;
    let now = chrono::Utc::now();

    // 1. Read substrate state needed for the envelope's body fields.
    let (genesis_pos, genesis_hash_hex) = read_genesis_anchor(&self.state)?;
    let node_name = read_node_name(&self.state)?;

    // 2. Build the canonical preimage as a serde_json::Value.
    //    Mirror the proto message field names. EXCLUDE the signature field.
    let preimage = serde_json::json!({
        "public_key": identity.public_key_hex,
        "node_id": identity.destination_hash,
        "node_name": node_name,
        "genesis_chain_position": genesis_pos,
        "genesis_receipt_hash": {
            "hex": genesis_hash_hex,
            "algorithm": "blake3",
        },
        "identity_as_of": now.to_rfc3339(),
    });

    // 3. Sign the canonical hash via the Operator key.
    let hash = zp_receipt::canonical::canonical_hash_bytes(&preimage);
    use ed25519_dalek::Signer;
    let sig_bytes = identity.signing_key.sign(&hash).to_bytes();

    // 4. Construct the proto message with the signature populated.
    Ok(Response::new(SignedIdentity {
        public_key: identity.public_key_hex.clone(),
        node_id: identity.destination_hash.clone(),
        node_name,
        genesis_chain_position: genesis_pos,
        genesis_receipt_hash: Some(zp_verbs::common::ContentHash {
            hex: genesis_hash_hex,
            algorithm: zp_verbs::common::HashAlgorithm::Blake3 as i32,
        }),
        identity_as_of: Some(datetime_to_timestamp(&now)),
        signature: Some(zp_verbs::common::Signature {
            public_key: identity.public_key_hex.clone(),
            signature: hex::encode(sig_bytes),
            algorithm: zp_verbs::common::SignatureAlgorithm::Ed25519 as i32,
        }),
    }))
}
```

## Discipline considerations

- **Hash-then-sign**: preimage is built with no signature field present;
  hash is computed; signature is computed over the hash; signature is
  written to the proto message. The proto's signature field never feeds
  back into the hash. Matches the existing receipt discipline.

- **Single verification primitive**: verifiers (`verify_signature` from
  `zp_receipt::verify`) never appear in adapter code; the discipline
  pin already enforces this for any code path.

- **Helper function candidate**: as the third or fourth signed verb
  lands, the preimage→sign→Signature pattern in step 3 is worth
  factoring into a small helper:
  ```rust
  fn sign_envelope(signing_key: &SigningKey, public_key_hex: &str,
                   preimage: &serde_json::Value) -> common::Signature
  ```
  Defer until pattern repeats; premature extraction is its own anti-
  discipline. The receipt code does the same — each Signable impl owns
  its preimage construction explicitly.

- **Future discipline pin candidate**: `signed_envelope_excludes_sig`
  — scan handler code for `serde_json::json!{}` blocks that build
  preimages and confirm they don't include `signature` fields. Adds
  defense-in-depth against a footgun future contributors might hit.

## What this unblocks

The five signed-envelope verbs on NodeStatus:

1. `GetIdentity` → `SignedIdentity`
2. `GetSecurityPosture` → `SignedSecurityPosture`
3. `GetTopology` → `SignedTopologyEnvelope`
4. `GetBlastRadius` → `SignedBlastRadiusEnvelope`
5. `GetFleetNode` → `SignedFleetNodeEnvelope`

Each becomes a focused per-verb commit following the template above.
GetIdentity should land first as the canonical example; subsequent
verbs reference it.

The signed-envelope verbs across other services (Guard.GetPolicyRules /
GetPolicyVersion, Audit's signed read variants, etc.) follow the same
template once their services are migrated.

The receipt-issuance verbs (RegisterBlastRadius, ReportCompromise,
DeregisterFleetNode) are *not* covered by this design — they go through
`AuditStore::append` which uses `AuditSigner`, not the Operator key.
Receipt-issuance design is its own follow-up sub-question and probably
needs less new design work since `append` already exists.

## Status

Design selected: Path C, hand-rolled preimage per verb, Operator key
signs, canonical_bytes_of preserves the single canonical form.

Implementation queued: `GetIdentity` next, as the template-establishing
verb. Other four signed envelopes follow.
