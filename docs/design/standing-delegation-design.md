# Standing Delegation and Revocation Architecture

## Design Principles

1. **Build for today's topology (tree), design for tomorrow's (hierarchy, federation).** Every primitive must work in a flat tree with 4 nodes. No primitive may assume that topology is permanent.
2. **Revocation is the default state.** Delegated authority expires. Continuation requires active renewal. The kill-switch isn't a special mechanism — it's what happens when renewal stops.
3. **Sovereignty is non-negotiable.** Each zone has exactly one genesis authority. Cross-zone trust is bilateral and severable.
4. **Extend, don't duplicate.** Standing delegation extends `zp-core::CapabilityGrant` — not a parallel type system.

---

## Relationship to Existing Types

### What Already Exists (zp-core)

**`CapabilityGrant`** (capability_grant.rs, 2072 lines) provides:
- Grant identity, grantor/grantee, capability type, constraints
- `parent_grant_id` and `delegation_depth` / `max_delegation_depth`
- `expires_at: Option<DateTime<Utc>>` (fixed wall-clock, no renewal)
- `provenance: GrantProvenance` (OperatorIssued, Delegated, SystemGenerated)
- Ed25519 signature and verification
- `delegate()` method with scope narrowing and depth checking
- Builder pattern with `with_*()` methods

**`DelegationChain`** (delegation_chain.rs, 544 lines) provides:
- Ordered chain of grants from root to leaf
- `verify()` enforcing: parent linkage, depth monotonicity, scope containment, grantor-grantee matching, expiration inheritance, signature validity
- Comprehensive error types for each invariant violation

**`ZpDelegationPolicy`** (delegation_bridge.rs, 225 lines) provides:
- Agent-bridge type mapping (agent-zp → zp-core)
- Authorization and chain validation
- `revoke()` — currently a stub (no-op)

### What Standing Delegation Adds

Standing delegation does NOT replace CapabilityGrant. It extends it with:

1. **Lease semantics** — grants that expect periodic renewal rather than fixed expiration
2. **Revocation authority** — who can revoke, separate from who can exercise
3. **Renewal authority** — who can extend the lease, as capability references not node IDs
4. **Failure modes** — what happens when a lease expires (halt, degrade, flag)
5. **Active revocation** — RevocationClaim as a first-class chain receipt, not a stub

### Extension Strategy

Add new fields to `CapabilityGrant`:

```rust
// New fields on CapabilityGrant
pub lease_policy: Option<LeasePolicy>,          // None = fixed expiration (backward compatible)
pub renewal_authorities: Vec<AuthorityRef>,     // Who can renew (empty = non-renewable)
pub revocable_by: Vec<AuthorityRef>,            // Who can revoke (empty = only issuer)
pub redelegation: RedelegationPolicy,           // Whether subject can re-delegate
pub revocation_anchor: Option<String>,          // Future: anchor layer ref for bypass verification
pub last_renewed_at: Option<DateTime<Utc>>,     // Tracking field, updated on renewal
pub renewal_count: u32,                         // How many times this grant has been renewed
```

When `lease_policy` is `None`, the grant behaves exactly as it does today — fixed `expires_at`, no renewal expectation. This ensures full backward compatibility. Existing grants, tests, and code paths are unaffected.

When `lease_policy` is `Some(...)`, the grant is a standing delegation with lease semantics. `expires_at` is rewritten on each renewal. `renewal_authorities` determines who can perform the renewal.

Add new type alongside CapabilityGrant:

```rust
// New type — NOT a replacement for CapabilityGrant
pub struct RevocationClaim { ... }
```

Add new variant to GrantProvenance:

```rust
pub enum GrantProvenance {
    OperatorIssued,
    Delegated,
    SystemGenerated,
    Standing,           // New: long-lived grant with lease renewal expectation
}
```

---

## New Types

### LeasePolicy

```rust
pub struct LeasePolicy {
    pub lease_duration: Duration,               // How long each renewal extends the grant
    pub grace_period: Duration,                 // Buffer after expiry before hard action
    pub renewal_interval: Duration,             // How often the subject should request renewal
    pub failure_mode: LeaseFailureMode,
    pub max_consecutive_failures: u32,
}

pub enum LeaseFailureMode {
    HaltOnExpiry,           // Stop exercising capabilities (default, safe)
    DegradeOnExpiry,        // Drop to T0 read-only
    ContinueWithFlag,       // Continue but emit chain warning (requires explicit opt-in)
}
```

### AuthorityRef

Topology-independent reference to an authority. Does not name nodes — names capabilities.

```rust
pub struct AuthorityRef {
    pub ref_type: AuthorityRefType,
    pub grant_id: Option<String>,               // Specific grant, or None for genesis
    pub capability_required: GrantedCapability,  // What capability the authority must hold
}

pub enum AuthorityRefType {
    Genesis,            // The zone's genesis node (always valid)
    GrantHolder,        // Any node holding the referenced grant with required capability
    AnchorVerified,     // Verified via anchor layer (future, activates with HCS)
}
```

### RedelegationPolicy

```rust
pub enum RedelegationPolicy {
    Forbidden,                                  // Subject cannot re-delegate
    Allowed { max_subtree_depth: u32 },         // Subject can delegate up to N levels deep
    RequiresApproval,                           // Future: re-delegation queued for issuer review
}
```

### RevocationClaim

```rust
pub struct RevocationClaim {
    pub revocation_id: String,                  // "revoke-{uuid}"
    pub target_grant_id: String,
    pub cascade: CascadePolicy,
    pub issued_by: Vec<u8>,                     // Issuer public key (matches existing grantor format)
    pub authority_chain: Vec<String>,           // Grant IDs proving revocation authority
    pub reason: RevocationReason,
    pub issued_at: DateTime<Utc>,
    pub anchor_commitment: Option<String>,      // Future: anchor ref
    pub signature: Vec<u8>,
}

pub enum CascadePolicy {
    GrantOnly,          // Revoke this grant; children must re-validate
    SubtreeHalt,        // Revoke this grant and all derived grants
    SubtreeReroot,      // Future: revoke grant, re-parent children to revoker
}

pub enum RevocationReason {
    OperatorRequested,
    LeaseExpired,
    CompromiseDetected,
    PolicyViolation,
    Superseded { new_grant_id: String },
}
```

---

## Invariants

These hold across all topologies, current and future:

1. **Authority monotonicity.** A grant at depth N cannot issue capabilities broader than its own scope, tiers higher than its own ceiling, or delegation deeper than its remaining depth budget. (Already enforced by `DelegationChain::verify()` — no changes needed.)

2. **Revocation asymmetry.** Any single authority in `revocable_by` can revoke unilaterally. Renewal requires a valid authority from `renewal_authorities`. The bar to stop is always lower than the bar to continue.

3. **Expiry is revocation.** An unrenewed grant is a revoked grant. The system does not distinguish between "deliberately revoked" and "failed to renew" at the enforcement layer. Both result in capability cessation.

4. **Revocation permanence within epoch.** A revoked grant cannot be un-revoked. A new grant must be issued. This prevents race conditions where revocation and renewal compete.

5. **Chain provenance.** Every grant and every revocation is a receipt in the audit chain. The authority chain is verifiable by any party with access to the chain.

6. **Anchor independence.** If an anchor backend is configured, anchor-layer revocation supersedes relay-layer renewal. (Future — no-op until HCS ships.)

---

## Initial Topology: The Tree

```
APOLLO (genesis, depth 0, T4 Council)
├── SENTINEL (depth 1, T3 Core, revocation + lease renewal + device governance)
│   └── [future: network devices governed by Sentinel]
├── ARTEMIS (depth 1, T2 Verified, tool execution + credential access)
└── ZP-PLAYGROUND (depth 1, T1 Sandbox, tool execution only)
```

### Grant Configuration

| Grant | Capabilities | Tier | Lease | Renewal | Revocable By | Re-delegate |
|-------|-------------|------|-------|---------|--------------|-------------|
| APOLLO → Sentinel | RevocationAuthority, LeaseRenewal, DeviceGovernance | T3 | 24h / 6h refresh | APOLLO | APOLLO only | Allowed (depth 2) |
| APOLLO → ARTEMIS | ToolExecution, CredentialAccess | T2 | 8h / 2h refresh | APOLLO, Sentinel | APOLLO, Sentinel | Forbidden |
| APOLLO → Playground | ToolExecution | T1 | 4h / 1h refresh | APOLLO, Sentinel | APOLLO, Sentinel | Forbidden |

Lease durations are operator-configurable per grant. The values above are starting points. Setting lease_duration to effectively permanent (e.g., 10 years) disables the dead man's switch for that grant — revocation then depends entirely on active delivery.

### Kill-Switch Scenarios

**Sentinel goes down:** ARTEMIS and playground renew from APOLLO directly. Sentinel's subtree (network devices) halts. Fleet continues.

**APOLLO goes down:** Sentinel continues renewing ARTEMIS and playground. Sentinel's own grant decays over 24h. If APOLLO returns within 24h, no disruption. If not, progressive fleet halt — playground (4h), ARTEMIS (8h), Sentinel (24h).

**Compromised ARTEMIS:** APOLLO or Sentinel issues RevocationClaim. ARTEMIS halts on receipt or on lease expiry. Blast radius: one node.

**Compromised Sentinel:** Only APOLLO can revoke Sentinel. APOLLO issues RevocationClaim with `SubtreeHalt`. Sentinel and any network devices halt. ARTEMIS and playground are unaffected (sibling grants, not in Sentinel's subtree).

---

## Evolution Path

### Stage 1: Tree (Current)
Single genesis, flat delegation, two renewal authorities per leaf. Kill-switch is lease expiry + active revocation. All primitives built, topology is configuration.

### Stage 2: Hierarchy
Intermediate nodes with `RedelegationPolicy::Allowed` manage subtrees. Regional revocation authorities. `renewal_authorities` lists expand to include intermediates. No primitive changes — deployment configuration only.

### Stage 3: Federation with Anchor Bypass
Multiple sovereign zones with bilateral trust. `revocation_anchor` activates. Nodes verify revocation status against public ledger independently of relay hierarchy. Compromised intermediates bypassed via anchor side channel. No primitive changes — field activation only.

---

## Implementation Sequence

### Phase 1: Type Extensions + Chain Integration
- Add lease/renewal/revocation fields to CapabilityGrant (backward compatible via Option)
- Add LeasePolicy, AuthorityRef, RedelegationPolicy, RevocationClaim types to zp-core
- Add Standing variant to GrantProvenance
- Emit delegation:granted/renewed/revoked/expired receipts to audit chain
- Add delegation:revoked to Merkle anchoring trigger list
- CLI: `zp delegate`, `zp revoke`, `zp grants`, `zp grants --check`
- Compile, test (existing tests must still pass unchanged)

### Phase 2: Lease Engine
- POST /api/v1/lease/renew endpoint
- Lease validation in governance gate (prerequisite check before policy evaluation)
- Background heartbeat client for delegate nodes
- HaltOnExpiry / DegradeOnExpiry enforcement

### Phase 3: Operational Deployment
- Issue standing grants from APOLLO to fleet
- Configure heartbeat clients
- Verify kill-switch scenarios
- Cockpit: "Fleet Grants" tile
