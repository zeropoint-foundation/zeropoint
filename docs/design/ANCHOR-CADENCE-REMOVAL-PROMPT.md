# CLIC Prompt: Remove Cadence Scheduler from zp-anchor, Replace with Event-Driven Model

## Context

`crates/zp-anchor/src/lib.rs` contains an `AnchoringConfig` struct (lines 228–269) that models truth anchoring as a cadence-based scheduler: "anchor every 100 receipts or every 15 minutes, whichever comes first." This is wrong. The chain doesn't get "more true" by being witnessed on a timer.

The correct model is **event-driven and opportunistic**:

- **Situational:** Anchoring happens when there's a reason — an audit, a cross-mesh introduction, a compliance checkpoint, a dispute, an operator request.
- **Opportunistic:** When a blockchain transaction is already happening for another reason, piggyback the chain head as metadata. Zero marginal cost.
- **Never cadence-based.** No timers, no receipt-count triggers. The chain's internal integrity is self-contained via hash-linking. External witnessing is for specific trust events, not periodic reaffirmation.

The `AnchoringConfig` struct and its defaults are not referenced anywhere outside this crate (confirmed by grep). Removing them is safe with no downstream breakage.

## Task

Remove the cadence-based scheduler configuration from `zp-anchor` and replace it with an `AnchorTrigger` enum that represents the actual reasons anchoring occurs. Update doc comments to reflect the event-driven model.

## Exact Changes

### 1. Remove `AnchoringConfig` and its default functions (lines 223–269)

Delete the entire block from `// Anchoring Scheduler Configuration` through the `impl Default for AnchoringConfig` closing brace. This includes:

- The section comment `// Anchoring Scheduler Configuration`
- The `AnchoringConfig` struct (lines 228–246)
- `fn default_cadence_receipts()` (lines 248–250)
- `fn default_cadence_minutes()` (lines 251–253)
- `fn default_max_cost_usd()` (lines 254–256)
- `fn default_enabled()` (lines 257–259)
- `impl Default for AnchoringConfig` (lines 261–269)

### 2. Replace with `AnchorTrigger` enum

In the same location (after the trait, before the NoOpAnchor), add:

```rust
// ============================================================================
// Anchor Triggers
// ============================================================================

/// Why an anchoring operation was initiated.
///
/// Truth anchoring is event-driven, not cadence-based. The chain's internal
/// integrity is self-contained via hash-linking — external witnessing adds
/// verifiability for specific trust events, not periodic reaffirmation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorTrigger {
    /// The operator explicitly requested an anchor (CLI, API, or UI).
    OperatorRequested,

    /// A cross-mesh introduction: two meshes exchanging trust require
    /// each to anchor their current chain head so the other can verify.
    CrossMeshIntroduction {
        /// Identifier of the remote mesh being introduced.
        remote_mesh_id: String,
    },

    /// A compliance or audit checkpoint (e.g., before generating an
    /// audit export, before a scheduled compliance review).
    ComplianceCheckpoint {
        /// Human-readable reason for the checkpoint.
        reason: String,
    },

    /// A dispute or investigation requires a timestamped anchor to
    /// establish chain state at a specific point.
    DisputeEvidence {
        /// Reference to the dispute or investigation.
        reference: String,
    },

    /// Opportunistic: a blockchain transaction is already happening for
    /// another reason; embed the chain head as metadata at zero marginal cost.
    Opportunistic {
        /// What triggered the existing transaction (e.g., "token_transfer",
        /// "contract_call", "nft_mint").
        piggyback_on: String,
    },

    /// Governance lifecycle event: a significant state change (capability
    /// revocation, constitutional rule update, trust tier change) that
    /// warrants external witnessing.
    GovernanceEvent {
        /// The event type that triggered anchoring.
        event_type: String,
    },
}
```

### 3. Update the `AnchorCommitment` struct

Add a `trigger` field so every commitment records *why* it was anchored:

```rust
    /// What triggered this anchoring operation.
    pub trigger: AnchorTrigger,
```

Add this field after `chain_type: ChainType,` in the `AnchorCommitment` struct.

### 4. Update the doc comment on the `TruthAnchor` trait (lines 176–187)

Replace the entire doc comment block (from `/// Pluggable interface` through the `/// fields. If no backend is configured, anchoring is silently skipped.` line) with:

```rust
/// Pluggable interface for external truth anchoring.
///
/// Any DLT backend (Hedera, Ethereum, Bitcoin, Ceramic, HTTPS timestamp
/// authority) implements this trait. Anchoring is event-driven: callers
/// invoke `anchor()` in response to specific trust events (see
/// [`AnchorTrigger`]), not on a timer or receipt-count cadence.
///
/// If no backend is configured, the [`NoOpAnchor`] implementation
/// returns `NotAvailable` errors, and the system operates without
/// external verification. Local chain integrity is unaffected.
```

### 5. Update the module-level doc comment (lines 1–45)

In the `//! ## Design Principles` section, replace principle 2:

**Find:**
```
//! 2. **Optional enrichment.** If no anchor is configured, ZeroPoint operates
//!    without external verification. Local chain integrity remains fully
//!    functional. DLT adds external verifiability — it doesn't replace
//!    internal verification.
```

**Replace with:**
```
//! 2. **Optional enrichment, event-driven.** If no anchor is configured,
//!    ZeroPoint operates without external verification. Local chain integrity
//!    remains fully functional. When anchoring is configured, it is triggered
//!    by specific trust events (audits, cross-mesh introductions, disputes,
//!    operator requests) or opportunistically when a blockchain transaction
//!    is already in flight. There is no timer or cadence — the chain doesn't
//!    get "more true" by being witnessed more often.
```

### 6. Update the usage example (lines 29–45)

Replace the usage example to show the trigger:

```rust
//! ```rust,ignore
//! use zp_anchor::{TruthAnchor, AnchorCommitment, AnchorTrigger, ChainType};
//!
//! async fn anchor_for_audit(anchor: &dyn TruthAnchor, head_hash: &str) {
//!     let commitment = AnchorCommitment {
//!         chain_head_hash: head_hash.to_string(),
//!         chain_sequence: 42,
//!         prev_anchor_hash: None,
//!         operator_signature: "deadbeef".to_string(),
//!         chain_type: ChainType::AuditChain,
//!         trigger: AnchorTrigger::ComplianceCheckpoint {
//!             reason: "quarterly audit export".to_string(),
//!         },
//!     };
//!     let receipt = anchor.anchor(commitment).await.unwrap();
//!     println!("Anchored at: {}", receipt.consensus_timestamp);
//! }
//! ```
```

### 7. Remove `BudgetExhausted` error variant

The `BudgetExhausted` variant (lines 74–75) only existed to support the cadence scheduler's cost-limiting logic. Remove it:

```rust
    /// Budget exhausted for anchoring operations.
    #[error("Anchor budget exhausted: {reason}")]
    BudgetExhausted { reason: String },
```

Budget concerns are the operator's responsibility at the backend-implementation level, not a trait-level concept.

## Verification

After making changes:

1. `cargo check --workspace` must pass (no downstream references to `AnchoringConfig` or `BudgetExhausted`)
2. `cargo test --workspace` must pass
3. `grep -r "AnchoringConfig" crates/` returns zero results
4. `grep -r "cadence" crates/zp-anchor/` returns zero results
5. `grep -r "BudgetExhausted" crates/` returns zero results (or only in unrelated error-handling code)
6. The new `AnchorTrigger` enum compiles and is visible in the public API

## Commit Message

```
refactor(zp-anchor): replace cadence scheduler with event-driven anchor triggers

The AnchoringConfig assumed anchoring should happen on a timer (every
100 receipts or 15 minutes). This is wrong — the chain's integrity is
self-contained via hash-linking; external witnessing serves specific
trust events, not periodic reaffirmation.

Remove AnchoringConfig, its default functions, and the BudgetExhausted
error variant. Replace with AnchorTrigger enum representing actual
reasons to anchor: operator request, cross-mesh introduction,
compliance checkpoint, dispute evidence, opportunistic piggyback,
and governance lifecycle events. Add trigger field to AnchorCommitment
so every anchor records why it was created.
```

## Do NOT

- Do not remove or modify the `TruthAnchor` trait methods (`anchor`, `verify`, `query_range`, `backend_name`, `is_available`) — those are correct
- Do not remove or modify `AnchorCommitment`, `AnchorReceipt`, `AnchorVerification`, or `ChainType` (except adding the `trigger` field to `AnchorCommitment`)
- Do not remove or modify the `NoOpAnchor` implementation
- Do not remove the other `AnchorError` variants — only `BudgetExhausted`
- Do not add any timer, scheduler, or periodic-execution logic — that's the entire point of this change
- Do not add new crate dependencies — everything needed is already available
