# CLIC01 Brief — P4: Standing Delegation Primitives

## Prerequisites

P3 complete. Chain at 502 entries, Merkle anchoring live.

**Read first:** `docs/design/standing-delegation-design.md` in the ZeroPoint repo. It contains the full rationale, type relationships, invariants, and evolution path. This brief covers implementation only.

---

## Critical: Extend, Don't Duplicate

There is already substantial delegation infrastructure in `zp-core`:
- `capability_grant.rs` (2072 lines) — CapabilityGrant with delegation depth, parent_grant_id, expiration, signatures, scope narrowing
- `delegation_chain.rs` (544 lines) — DelegationChain with full invariant verification
- `delegation_bridge.rs` (225 lines) — Agent bridge type mapping
- `zp-keys/blast_radius.rs` — Indexes capability grants for compromise scoping

**Do NOT create a parallel type system.** Standing delegation extends `CapabilityGrant` with new fields. All new fields are `Option` or have defaults for backward compatibility. Existing tests must pass unchanged.

---

## Phase 1: Type Extensions + Chain Integration

### 1A: Add New Types to `zp-core`

**New file: `crates/zp-core/src/lease.rs`**

```rust
pub struct LeasePolicy {
    pub lease_duration: Duration,
    pub grace_period: Duration,
    pub renewal_interval: Duration,
    pub failure_mode: LeaseFailureMode,
    pub max_consecutive_failures: u32,
}

pub enum LeaseFailureMode {
    HaltOnExpiry,
    DegradeOnExpiry,
    ContinueWithFlag,
}
```

**New file: `crates/zp-core/src/authority_ref.rs`**

```rust
pub struct AuthorityRef {
    pub ref_type: AuthorityRefType,
    pub grant_id: Option<String>,
    pub capability_required: GrantedCapability,
}

pub enum AuthorityRefType {
    Genesis,
    GrantHolder,
    AnchorVerified,
}
```

**New file: `crates/zp-core/src/revocation.rs`**

```rust
pub struct RevocationClaim {
    pub revocation_id: String,
    pub target_grant_id: String,
    pub cascade: CascadePolicy,
    pub issued_by: Vec<u8>,              // Public key, matches existing grantor format
    pub authority_chain: Vec<String>,
    pub reason: RevocationReason,
    pub issued_at: DateTime<Utc>,
    pub anchor_commitment: Option<String>,
    pub signature: Vec<u8>,
}

pub enum CascadePolicy {
    GrantOnly,
    SubtreeHalt,
    SubtreeReroot,
}

pub enum RevocationReason {
    OperatorRequested,
    LeaseExpired,
    CompromiseDetected,
    PolicyViolation,
    Superseded { new_grant_id: String },
}
```

**New enum variant: `crates/zp-core/src/capability_grant.rs`**

Add to existing `RedelegationPolicy` (or create if it doesn't exist):
```rust
pub enum RedelegationPolicy {
    Forbidden,
    Allowed { max_subtree_depth: u32 },
    RequiresApproval,
}
```

Add to existing `GrantProvenance`:
```rust
Standing,  // Long-lived grant with lease renewal expectation
```

### 1B: Extend CapabilityGrant

Add these fields to the existing `CapabilityGrant` struct in `capability_grant.rs`:

```rust
// Standing delegation extensions — all Option for backward compatibility
pub lease_policy: Option<LeasePolicy>,
pub renewal_authorities: Vec<AuthorityRef>,     // Default: empty vec
pub revocable_by: Vec<AuthorityRef>,            // Default: empty vec
pub redelegation: RedelegationPolicy,           // Default: Forbidden
pub revocation_anchor: Option<String>,
pub last_renewed_at: Option<DateTime<Utc>>,
pub renewal_count: u32,                         // Default: 0
```

**Backward compatibility rules:**
- `lease_policy: None` → grant behaves exactly as today (fixed expiration)
- `renewal_authorities: []` → non-renewable (existing behavior)
- `revocable_by: []` → only issuer can revoke (existing behavior)
- `redelegation: Forbidden` → existing default
- Existing `delegate()` method must continue to work unchanged
- Existing `DelegationChain::verify()` must pass with or without these fields

Update `delegate()` to propagate lease policy when present:
- Child inherits parent's `lease_policy` (can't upgrade lease terms)
- Child's `renewal_authorities` must be ⊆ parent's
- Child cannot add itself to `revocable_by`

Update `DelegationChain::verify()` to validate lease fields when present:
- If parent has lease_policy, child must also have lease_policy
- Child lease_duration ≤ parent lease_duration
- Child renewal_authorities ⊆ parent renewal_authorities

### 1C: Wire `revoke()` in delegation_bridge.rs

Replace the existing stub with actual implementation:
1. Create RevocationClaim with appropriate cascade policy
2. Walk authority_chain to verify issuer has revocation authority
3. Emit revocation receipt to audit chain
4. If `SubtreeHalt`: enumerate child grants and mark revoked

### 1D: Emit Delegation Receipts to Chain

In `zp-server/src/tool_chain.rs`, add:

```rust
pub fn emit_delegation_receipt(store, grant) -> Result<Option<String>>
pub fn emit_revocation_receipt(store, claim) -> Result<Option<String>>
```

Event types (these are chain entries, same format as existing tool lifecycle events):
- `delegation:granted:{subject_id}`
- `delegation:renewed:{subject_id}`
- `delegation:revoked:{subject_id}`
- `delegation:expired:{subject_id}`

**Anchor pipeline update:** Add `delegation:revoked:*` and `delegation:granted:*` to the trigger list in `anchor_pipeline.rs`. Trust boundary changes should trigger Merkle epoch sealing.

### 1E: CLI Commands

Add to `zp-cli/src/main.rs`:

**`zp delegate`** — Issue a standing grant:
```bash
zp --data-dir ~/ZeroPoint/data delegate \
    --subject artemis \
    --capabilities tool-execution,credential-access \
    --tier-ceiling 2 \
    --lease-duration 8h \
    --renewal-interval 2h \
    --renewal-authorities genesis,sentinel \
    --revocable-by genesis,sentinel \
    --max-depth 0
```

**`zp revoke`** — Revoke a grant:
```bash
zp --data-dir ~/ZeroPoint/data revoke \
    --grant-id grant-abc123 \
    --cascade subtree-halt \
    --reason operator-requested
```

**`zp grants`** — List active grants with lease status:
```bash
zp --data-dir ~/ZeroPoint/data grants
zp --data-dir ~/ZeroPoint/data grants --check  # Validate invariants
```

### 1F: Tests

1. Existing CapabilityGrant tests pass unchanged (backward compat)
2. Existing DelegationChain tests pass unchanged
3. New: Standing grant creation with lease policy
4. New: Authority monotonicity rejection (lease escalation, renewal authority broadening)
5. New: RevocationClaim creation and chain validation
6. New: Cascade policy enforcement (GrantOnly vs SubtreeHalt)
7. New: Expired grant rejection on renewal attempt
8. New: Revoked grant rejection on renewal attempt
9. New: `zp grants --check` validates clean state
10. New: `zp grants --check` catches violated invariants

Exit criterion: `cargo test` passes (all existing + new). `zp delegate` and `zp revoke` emit chain receipts. `zp verify` ACCEPT. Zero regressions in existing grant/chain tests.

---

## Phase 2: Lease Engine

### 2A: Lease Renewal Endpoint

Add to `zp-server/src/lib.rs`:

```
POST /api/v1/lease/renew
```

Handler logic:
1. Look up grant in chain (walk delegation:granted/renewed receipts)
2. Check not revoked (walk delegation:revoked receipts)
3. Check not expired (current time < expires_at + grace_period)
4. Verify requesting node's signature
5. Verify THIS node has renewal authority (its own grant includes LeaseRenewal capability with scope covering target)
6. If anchor configured: check for anchor-layer revocation (no-op for now)
7. Emit `delegation:renewed:{subject}` with new `expires_at`
8. Return `{ renewed: true, new_expires_at: ... }`

### 2B: Lease Validation in Gate

Add to existing `gate_tool_call_handler` as a prerequisite check:

Before deny-list evaluation, check requesting agent's node has a valid (non-expired, non-revoked) standing grant with appropriate capabilities. If no valid grant: deny with `"no_valid_delegation"`.

**Additive only** — existing gate logic (deny-list, policy) still applies after lease check passes.

### 2C: Heartbeat Client

New: `crates/zp-server/src/lease_heartbeat.rs`

On server startup, if node has a standing delegation configured:
1. Read grant from local config or chain
2. Spawn background task at `renewal_interval`
3. POST to each `renewal_authority` in order until one succeeds
4. Track consecutive failures → grace period → failure_mode execution

Only active on delegate nodes. Genesis doesn't heartbeat.

### 2D: Tests

1. Renewal succeeds for valid grant
2. Renewal rejected for expired / revoked grant
3. Renewal rejected from unauthorized node
4. Gate rejects tool call with no valid delegation
5. Heartbeat enters grace period after consecutive failures
6. HaltOnExpiry / DegradeOnExpiry enforcement

Exit criterion: Full lease lifecycle end-to-end. Gate enforces delegation. `zp verify` ACCEPT.

---

## Key Files

| File | Action | Purpose |
|------|--------|---------|
| `zp-core/src/lease.rs` | **Create** | LeasePolicy, LeaseFailureMode |
| `zp-core/src/authority_ref.rs` | **Create** | AuthorityRef, AuthorityRefType |
| `zp-core/src/revocation.rs` | **Create** | RevocationClaim, CascadePolicy, RevocationReason |
| `zp-core/src/capability_grant.rs` | **Modify** | Add lease/renewal/revocation fields, extend delegate() and verify() |
| `zp-core/src/delegation_chain.rs` | **Modify** | Validate lease fields in verify() |
| `zp-agent-bridge/src/delegation_bridge.rs` | **Modify** | Implement revoke() (currently stub) |
| `zp-server/src/tool_chain.rs` | **Modify** | Add emit_delegation_receipt, emit_revocation_receipt |
| `zp-server/src/anchor_pipeline.rs` | **Modify** | Add delegation events to trigger list |
| `zp-server/src/lib.rs` | **Modify** | Add /api/v1/lease/renew, lease check in gate |
| `zp-server/src/lease_heartbeat.rs` | **Create** | Background lease renewal client |
| `zp-cli/src/main.rs` | **Modify** | Add delegate, revoke, grants subcommands |
