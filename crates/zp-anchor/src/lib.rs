//! # ZeroPoint Truth Anchor
//!
//! Pluggable abstraction for external truth anchoring via distributed ledgers.
//!
//! This crate defines the `TruthAnchor` trait — the interface that any external
//! ledger backend must implement to serve as a truth anchor for ZeroPoint's
//! audit chain. The trait is intentionally minimal: publish a commitment, verify
//! a commitment, query commitments by time range.
//!
//! **No DLT dependency lives here.** This crate depends only on standard Rust
//! types (chrono, serde, async-trait). Concrete implementations live in their
//! own crates (e.g., `zp-hedera` for Hedera Hashgraph HCS anchoring).
//!
//! ## Design Principles
//!
//! 1. **DLT-agnostic.** The trait works with Hedera HCS, Ethereum L2 calldata,
//!    Bitcoin OpenTimestamps, Ceramic streams, or a simple HTTPS timestamp
//!    authority. ZP never depends on a single external infrastructure.
//!
//! 2. **Optional enrichment, event-driven.** If no anchor is configured,
//!    ZeroPoint operates without external verification. Local chain integrity
//!    remains fully functional. When anchoring is configured, it is triggered
//!    by specific trust events (audits, cross-mesh introductions, disputes,
//!    operator requests) or opportunistically when a blockchain transaction
//!    is already in flight. There is no timer or cadence — the chain doesn't
//!    get "more true" by being witnessed more often.
//!
//! 3. **Operator sovereignty.** The operator chooses their anchor backend.
//!    Cross-mesh trust is established by exchanging anchor identifiers
//!    (e.g., HCS topic IDs), not by mandating a specific ledger.
//!
//! ## Usage
//!
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

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ============================================================================
// Errors
// ============================================================================

/// Errors that can occur during anchor operations.
#[derive(Debug, thiserror::Error)]
pub enum AnchorError {
    /// The external ledger rejected the commitment.
    #[error("Anchor rejected: {reason}")]
    Rejected { reason: String },

    /// Network or connectivity error reaching the external ledger.
    #[error("Anchor network error: {0}")]
    Network(String),

    /// The anchor receipt failed verification.
    #[error("Anchor verification failed: {reason}")]
    VerificationFailed { reason: String },

    /// The anchor backend is not configured or unavailable.
    #[error("Anchor not available: {reason}")]
    NotAvailable { reason: String },

    /// Generic internal error.
    #[error("Anchor internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, AnchorError>;

// ============================================================================
// Core Types
// ============================================================================

/// Which chain is being anchored.
///
/// ZeroPoint maintains up to three hash chains (Phase 4 introduces the
/// observation and reflection chains alongside the existing audit chain).
/// Each chain head is anchored independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainType {
    /// The primary audit trail (actions, policy decisions, receipts).
    AuditChain,
    /// The observation chain (Phase 4: observer agent recordings).
    ObservationChain,
    /// The reflection chain (Phase 4: reflector agent syntheses).
    ReflectionChain,
}

/// A commitment to be published to an external ledger.
///
/// This is what gets anchored: the hash of the chain head at a given sequence
/// number, signed by the operator. The anchor backend wraps this in whatever
/// transaction format its ledger requires.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorCommitment {
    /// BLAKE3 hash of the current chain head.
    pub chain_head_hash: String,

    /// Monotonically increasing sequence number in the chain.
    pub chain_sequence: u64,

    /// Hash of the previous anchor commitment (links anchor history).
    /// None for the first anchor in the series.
    pub prev_anchor_hash: Option<String>,

    /// Ed25519 signature by the operator key over this commitment.
    pub operator_signature: String,

    /// Which chain this commitment covers.
    pub chain_type: ChainType,

    /// What triggered this anchoring operation.
    pub trigger: AnchorTrigger,
}

/// A receipt from the external ledger proving that a commitment was published.
///
/// This is what comes back: the ledger's own transaction ID, its consensus
/// timestamp (from the ledger's clock, not the local clock), and the original
/// commitment. The `ledger_proof` field carries opaque ledger-specific
/// verification data (e.g., HCS sequence number + running hash for Hedera).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorReceipt {
    /// Ledger-specific transaction or message ID.
    pub external_id: String,

    /// Consensus timestamp from the external ledger (not local clock).
    pub consensus_timestamp: DateTime<Utc>,

    /// The commitment that was anchored.
    pub commitment: AnchorCommitment,

    /// Opaque ledger-specific verification data.
    /// For Hedera: HCS sequence number + running hash.
    /// For Ethereum: block number + tx hash.
    /// For OpenTimestamps: OTS proof bytes.
    pub ledger_proof: Vec<u8>,

    /// Which anchor backend produced this receipt.
    pub backend: String,
}

/// Result of verifying a local chain state against a previously published anchor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorVerification {
    /// Whether the local chain matches the anchored commitment.
    pub chain_matches: bool,

    /// Whether the anchor receipt itself is valid on the external ledger.
    pub anchor_valid: bool,

    /// Time difference between local chain state and anchor timestamp.
    /// Negative means the local state is older than the anchor.
    pub drift: chrono::Duration,

    /// Human-readable summary of the verification result.
    pub summary: String,
}

// ============================================================================
// The Trait
// ============================================================================

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
#[async_trait::async_trait]
pub trait TruthAnchor: Send + Sync {
    /// Publish a chain-head commitment to the external ledger.
    ///
    /// Returns an `AnchorReceipt` containing the ledger's own transaction ID
    /// and consensus timestamp. The receipt should be stored locally for
    /// later verification.
    async fn anchor(&self, commitment: AnchorCommitment) -> Result<AnchorReceipt>;

    /// Verify a local chain state against a previously published anchor.
    ///
    /// Checks that the commitment in the receipt matches the local chain head
    /// at the given sequence, and that the receipt is valid on the external
    /// ledger (i.e., the transaction actually exists with the claimed content).
    async fn verify(&self, receipt: &AnchorReceipt) -> Result<AnchorVerification>;

    /// Query the external ledger for all anchors in a time range.
    ///
    /// Returns anchor receipts in chronological order. This enables
    /// cross-mesh trust verification: two peers exchange their anchor
    /// backend identifiers and each independently queries the other's
    /// anchor history.
    async fn query_range(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<AnchorReceipt>>;

    /// Human-readable name of this anchor backend (e.g., "hedera-hcs", "ethereum-l2").
    fn backend_name(&self) -> &str;

    /// Whether this backend is currently configured and reachable.
    async fn is_available(&self) -> bool;
}

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

// ============================================================================
// No-op implementation for when no backend is configured
// ============================================================================

/// A no-op anchor that silently succeeds without external verification.
///
/// Used when the operator has not configured a DLT backend. All operations
/// return errors indicating that no backend is available.
pub struct NoOpAnchor;

#[async_trait::async_trait]
impl TruthAnchor for NoOpAnchor {
    async fn anchor(&self, _commitment: AnchorCommitment) -> Result<AnchorReceipt> {
        Err(AnchorError::NotAvailable {
            reason: "No DLT backend configured. Run onboarding to provision one.".to_string(),
        })
    }

    async fn verify(&self, _receipt: &AnchorReceipt) -> Result<AnchorVerification> {
        Err(AnchorError::NotAvailable {
            reason: "No DLT backend configured.".to_string(),
        })
    }

    async fn query_range(
        &self,
        _from: DateTime<Utc>,
        _to: DateTime<Utc>,
    ) -> Result<Vec<AnchorReceipt>> {
        Err(AnchorError::NotAvailable {
            reason: "No DLT backend configured.".to_string(),
        })
    }

    fn backend_name(&self) -> &str {
        "none"
    }

    async fn is_available(&self) -> bool {
        false
    }
}
