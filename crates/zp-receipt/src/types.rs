//! Core types matching the receipt.schema.json specification.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Version of the receipt schema.
pub const RECEIPT_SCHEMA_VERSION: &str = "1.0.0";

// ============================================================================
// Receipt — the top-level type
// ============================================================================

/// Portable, cryptographically verifiable proof of execution.
///
/// This is the fundamental trust primitive of the ZeroPoint protocol.
/// Every action — code execution, API call, payment, content access — produces
/// a Receipt that can be independently verified by any party.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    /// Unique identifier (prefixed: rcpt-, intn-, dsgn-, appr-)
    pub id: String,

    /// Schema version for forward compatibility
    pub version: String,

    /// Stage in the provenance chain
    pub receipt_type: ReceiptType,

    /// Parent receipt in the provenance chain (None for intent receipts)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_receipt_id: Option<String>,

    /// Outcome of the action
    pub status: Status,

    /// Blake3 hash of the canonical JSON body (all fields except signature)
    pub content_hash: String,

    /// **Legacy single-signature field.** Pre-F8 receipts carry a
    /// single Ed25519 signature here as base64. Post-F8 receipts leave
    /// this `None` and use [`Receipt::signatures`] instead. Kept on the
    /// wire for round-trip identity with the existing chain — see
    /// [`Receipt::is_signed`] and [`Receipt::signature_blocks`] for
    /// version-agnostic accessors.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,

    /// **Legacy companion to [`Receipt::signature`].** Pre-F8 receipts
    /// carry the Ed25519 signer's public key (hex) here. Post-F8
    /// receipts use [`SignatureBlock::key_id`] inside
    /// [`Receipt::signatures`] instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_public_key: Option<String>,

    /// **F8 algorithm-agile signatures.** Zero or more
    /// [`SignatureBlock`]s, one per algorithm + signer pair. The
    /// canonical form is sorted by `(algorithm_name, key_id)` so the
    /// serialized JSON is deterministic regardless of insertion order
    /// — required for the chain entry hash to be stable.
    ///
    /// Empty on pre-F8 receipts; in that case [`Receipt::signature`]
    /// carries the lone Ed25519 signature instead. Post-F8 receipts
    /// produced by [`crate::Signer::sign`] populate this field and
    /// leave the legacy fields at `None`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<SignatureBlock>,

    /// Assurance level
    pub trust_grade: TrustGrade,

    /// When this receipt was created
    pub created_at: DateTime<Utc>,

    /// Who performed the action
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executor: Option<Executor>,

    /// What was done
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<Action>,

    /// Timing information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timing: Option<Timing>,

    /// Resource consumption
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<Resources>,

    /// Artifacts produced
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outputs: Option<Vec<OutputArtifact>>,

    /// I/O stream hashes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_hashes: Option<IoHashes>,

    /// Policy evaluation result
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyDecision>,

    /// Error details (if failed/denied/timeout)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorDetail>,

    /// Redacted fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redactions: Option<Vec<Redaction>>,

    /// Hash-chain linkage metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain: Option<ChainMetadata>,

    /// Vendor/domain extensions (reverse-domain keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<HashMap<String, serde_json::Value>>,

    /// When this receipt expires (None = no expiry).
    /// Execution claims default to 90 days. Memory promotion claims persist indefinitely.
    /// Delegation claims expire with the capability grant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    /// Type-specific claim metadata.
    /// Each claim type carries metadata appropriate to its semantics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_metadata: Option<ClaimMetadata>,

    /// The epistemic semantics of the signature on this receipt.
    /// Defaults to AuthorshipProof (I made this) for backward compatibility.
    #[serde(default = "default_claim_semantics")]
    pub claim_semantics: ClaimSemantics,

    /// Receipt IDs this receipt supersedes (forward reference).
    /// The superseded receipts remain in the chain but are no longer
    /// the current authority for whatever they claimed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supersedes: Vec<String>,

    /// Receipt IDs this receipt explicitly revokes (forward reference).
    /// Revoked receipts are treated as void — any downstream claims
    /// that depend on them are also invalidated.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revokes: Vec<String>,

    /// ID of the receipt that supersedes this one (backward reference,
    /// set on the *old* receipt after supersession).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub superseded_by: Option<String>,

    /// Timestamp when this receipt was revoked (backward reference,
    /// set on the *old* receipt after revocation).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

impl Receipt {
    /// Start building an execution receipt.
    pub fn execution(executor_id: &str) -> crate::ReceiptBuilder {
        crate::ReceiptBuilder::new(ReceiptType::Execution, executor_id)
    }

    /// Start building an intent receipt (root of chain).
    pub fn intent(executor_id: &str) -> crate::ReceiptBuilder {
        crate::ReceiptBuilder::new(ReceiptType::Intent, executor_id)
    }

    /// Start building a design receipt.
    pub fn design(executor_id: &str) -> crate::ReceiptBuilder {
        crate::ReceiptBuilder::new(ReceiptType::Design, executor_id)
    }

    /// Start building an approval receipt.
    pub fn approval(executor_id: &str) -> crate::ReceiptBuilder {
        crate::ReceiptBuilder::new(ReceiptType::Approval, executor_id)
    }

    /// Start building a payment receipt.
    pub fn payment(executor_id: &str) -> crate::ReceiptBuilder {
        crate::ReceiptBuilder::new(ReceiptType::Payment, executor_id)
    }

    /// Start building an access receipt.
    pub fn access(executor_id: &str) -> crate::ReceiptBuilder {
        crate::ReceiptBuilder::new(ReceiptType::Access, executor_id)
    }

    /// Start building an observation claim receipt.
    pub fn observation(executor_id: &str) -> crate::ReceiptBuilder {
        crate::ReceiptBuilder::new(ReceiptType::ObservationClaim, executor_id)
    }

    /// Start building a policy claim receipt.
    pub fn policy_claim(executor_id: &str) -> crate::ReceiptBuilder {
        crate::ReceiptBuilder::new(ReceiptType::PolicyClaim, executor_id)
    }

    /// Start building an authorization claim receipt.
    pub fn authorization(executor_id: &str) -> crate::ReceiptBuilder {
        crate::ReceiptBuilder::new(ReceiptType::AuthorizationClaim, executor_id)
    }

    /// Start building a memory promotion claim receipt.
    pub fn memory_promotion(executor_id: &str) -> crate::ReceiptBuilder {
        crate::ReceiptBuilder::new(ReceiptType::MemoryPromotionClaim, executor_id)
    }

    /// Start building a delegation claim receipt.
    pub fn delegation(executor_id: &str) -> crate::ReceiptBuilder {
        crate::ReceiptBuilder::new(ReceiptType::DelegationClaim, executor_id)
    }

    /// Start building a narrative synthesis claim receipt.
    pub fn narrative_synthesis(executor_id: &str) -> crate::ReceiptBuilder {
        crate::ReceiptBuilder::new(ReceiptType::NarrativeSynthesisClaim, executor_id)
    }

    /// Start building a reflection claim receipt.
    pub fn reflection(executor_id: &str) -> crate::ReceiptBuilder {
        crate::ReceiptBuilder::new(ReceiptType::ReflectionClaim, executor_id)
    }

    /// Start building a revocation claim receipt.
    pub fn revocation(executor_id: &str) -> crate::ReceiptBuilder {
        crate::ReceiptBuilder::new(ReceiptType::RevocationClaim, executor_id)
    }

    /// Start building a configuration claim receipt.
    pub fn configuration(executor_id: &str) -> crate::ReceiptBuilder {
        crate::ReceiptBuilder::new(ReceiptType::ConfigurationClaim, executor_id)
    }

    /// Start building a canonicalization claim receipt (bead zero).
    pub fn canonicalized(executor_id: &str) -> crate::ReceiptBuilder {
        crate::ReceiptBuilder::new(ReceiptType::CanonicalizedClaim, executor_id)
    }

    /// Verify the content_hash matches the receipt body.
    pub fn verify_hash(&self) -> bool {
        let computed = crate::canonical_hash(self);
        computed == self.content_hash
    }

    /// Check if this receipt has expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at.is_some_and(|exp| Utc::now() > exp)
    }

    /// Check if this receipt is still active (not revoked, superseded, or expired).
    pub fn is_active(&self) -> bool {
        !self.is_expired() && self.revoked_at.is_none() && self.superseded_by.is_none()
    }

    /// Mark this receipt as superseded by another receipt.
    /// The original claim still exists for auditability but `is_active()` returns false.
    pub fn supersede(&mut self, new_receipt_id: &str) {
        self.superseded_by = Some(new_receipt_id.to_string());
    }

    /// Revoke this receipt. Returns a RevocationClaim receipt builder that
    /// should be finalized and appended to the chain as proof of revocation.
    ///
    /// Sets both the backward reference (`revoked_at` on this receipt) and
    /// the forward reference (`revokes` on the new revocation receipt).
    pub fn revoke(&mut self, revoker_id: &str, reason: &str) -> crate::ReceiptBuilder {
        self.revoked_at = Some(Utc::now());

        Receipt::revocation(revoker_id)
            .parent(&self.id)
            .revokes_receipt(&self.id)
            .claim_metadata(ClaimMetadata::Revocation {
                revoked_receipt_id: self.id.clone(),
                reason: reason.to_string(),
                revoker_id: revoker_id.to_string(),
            })
    }

    /// Verify the Ed25519 signature.
    #[cfg(feature = "signing")]
    pub fn verify_signature(&self, public_key: &[u8; 32]) -> Result<bool, String> {
        crate::Signer::verify_receipt(self, public_key)
    }

    /// Check if this receipt is the root of a chain.
    pub fn is_root(&self) -> bool {
        self.receipt_type == ReceiptType::Intent && self.parent_receipt_id.is_none()
    }

    /// Check if the action succeeded.
    pub fn is_success(&self) -> bool {
        self.status == Status::Success
    }

    // ── F8 algorithm-agile signature accessors ─────────────────────────

    /// Whether this receipt carries any signature, F8-style or legacy.
    ///
    /// Use this in preference to `receipt.signature.is_some()` — that
    /// only checks the legacy field and reports `false` on F8 receipts.
    pub fn is_signed(&self) -> bool {
        !self.signatures.is_empty() || self.signature.is_some()
    }

    /// Return a synthetic vec of [`SignatureBlock`]s covering this
    /// receipt regardless of which format it was produced in.
    ///
    /// * F8 receipt → returns the populated [`Receipt::signatures`] vec.
    /// * Pre-F8 receipt → synthesizes a one-entry vec by promoting the
    ///   legacy [`Receipt::signature`] / [`Receipt::signer_public_key`]
    ///   pair into an [`SignatureAlgorithm::Ed25519`] block.
    /// * Unsigned receipt → returns an empty vec.
    ///
    /// The returned vec is owned (clone), so callers can mutate it
    /// without affecting the receipt.
    pub fn signature_blocks(&self) -> Vec<SignatureBlock> {
        if !self.signatures.is_empty() {
            return self.signatures.clone();
        }
        match (&self.signature, &self.signer_public_key) {
            (Some(sig_b64), Some(pk_hex)) => vec![SignatureBlock {
                algorithm: SignatureAlgorithm::Ed25519,
                key_id: pk_hex.clone(),
                signature_b64: sig_b64.clone(),
            }],
            (Some(sig_b64), None) => vec![SignatureBlock {
                algorithm: SignatureAlgorithm::Ed25519,
                // Pre-F8 receipts that signed without recording a public
                // key are exotic but possible; preserve the signature
                // and let verifiers discover the missing key separately.
                key_id: String::new(),
                signature_b64: sig_b64.clone(),
            }],
            _ => Vec::new(),
        }
    }

    /// Distinct algorithm names present in this receipt's signatures,
    /// sorted alphabetically. Includes the implicit `"ed25519"` entry
    /// when only the legacy [`Receipt::signature`] field is set.
    ///
    /// Stable string form so callers can compare against e.g.
    /// `"ed25519"` or `"ML-DSA-65"` without importing the enum.
    pub fn algorithm_ids(&self) -> Vec<String> {
        let blocks = self.signature_blocks();
        let mut ids: Vec<String> = blocks
            .iter()
            .map(|b| b.algorithm.as_str().to_string())
            .collect();
        ids.sort();
        ids.dedup();
        ids
    }

    /// Whether this receipt carries a signature using `alg`.
    pub fn has_algorithm(&self, alg: &SignatureAlgorithm) -> bool {
        self.signature_blocks()
            .iter()
            .any(|b| b.algorithm == *alg)
    }
}

// ============================================================================
// F8 algorithm-agile signature types
// ============================================================================

/// A single signature on a receipt, identified by algorithm and key.
///
/// Pre-F8 the receipt held one Ed25519 signature in the legacy
/// `signature` field. Post-F8 the receipt holds zero or more of these,
/// allowing hybrid signing (e.g. Ed25519 + ML-DSA-65) to slot in
/// without a chain-format migration. The chain entry hash already
/// covers the `signatures` array via JSON serialization, so tampering
/// with any block breaks chain continuity.
///
/// Canonical ordering: callers MUST keep [`Receipt::signatures`] sorted
/// by `(algorithm.as_str(), key_id)` ascending so the JSON form (and
/// therefore the entry hash) is deterministic. [`crate::Signer::sign`]
/// preserves this invariant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureBlock {
    /// The signature algorithm. The named [`SignatureAlgorithm::Ed25519`]
    /// variant is the only one ZP currently produces; everything else
    /// is carried as [`SignatureAlgorithm::Experimental`] so older
    /// verifiers can still parse the block.
    pub algorithm: SignatureAlgorithm,

    /// Stable identifier for the signing key. For Ed25519 this is the
    /// hex-encoded 32-byte public key (the same string that lived in
    /// the legacy `signer_public_key` field). For Experimental
    /// algorithms, the format is algorithm-defined — the SDK only
    /// requires it be a non-empty UTF-8 string.
    pub key_id: String,

    /// The raw signature bytes encoded as base64 (standard alphabet,
    /// padded). Base64 keeps the on-wire format JSON-clean and the
    /// `String` type matches the legacy `signature` field — useful
    /// for tools that round-trip via plain text.
    #[serde(rename = "signature")]
    pub signature_b64: String,
}

impl SignatureBlock {
    /// Convenience: build an Ed25519 block from a hex-encoded public
    /// key and a base64-encoded signature, the formats produced by the
    /// existing [`crate::Signer`].
    pub fn ed25519(public_key_hex: &str, signature_b64: &str) -> Self {
        Self {
            algorithm: SignatureAlgorithm::Ed25519,
            key_id: public_key_hex.to_string(),
            signature_b64: signature_b64.to_string(),
        }
    }

    /// The cmp key used for canonical ordering: `(alg_name, key_id)`.
    /// Exposed as a method so call sites that need to sort an external
    /// Vec stay in lock-step with [`Receipt::signatures`].
    pub fn canonical_sort_key(&self) -> (&str, &str) {
        (self.algorithm.as_str(), self.key_id.as_str())
    }
}

/// Signature algorithm identifier.
///
/// `Ed25519` is the only named variant for now — everything else
/// (ML-DSA-65, SLH-DSA-SHA2-128s, future PQ candidates) is carried
/// as `Experimental(String)`. This keeps older verifiers forward-
/// compatible: they parse the block, recognize the algorithm as
/// unknown, and skip verification with a warning rather than failing.
///
/// The wire form is a tagged enum:
///   `{"type": "ed25519"}`
///   `{"type": "experimental", "name": "ML-DSA-65"}`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SignatureAlgorithm {
    /// Classical Ed25519 (RFC 8032). The format ZP currently signs with.
    Ed25519,

    /// A future algorithm not yet recognized by this version of the
    /// SDK. The string is the algorithm's stable identifier (e.g.
    /// `"ML-DSA-65"`, `"SLH-DSA-SHA2-128s"`).
    Experimental {
        /// Algorithm identifier as published by the producing signer.
        name: String,
    },
}

impl SignatureAlgorithm {
    /// Stable string form used in canonical sort keys, receipt claims,
    /// and verifier output. `Ed25519` ↔ `"ed25519"`, `Experimental`
    /// returns the carried `name` verbatim.
    pub fn as_str(&self) -> &str {
        match self {
            SignatureAlgorithm::Ed25519 => "ed25519",
            SignatureAlgorithm::Experimental { name } => name.as_str(),
        }
    }

    /// Convenience constructor for an experimental algorithm.
    pub fn experimental(name: impl Into<String>) -> Self {
        SignatureAlgorithm::Experimental { name: name.into() }
    }
}

// ============================================================================
// Enums
// ============================================================================

/// The stage in the provenance chain.
///
/// Phase 2.1 adds typed claim variants beyond the original provenance chain.
/// The new claim types carry explicit semantics and type-specific metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptType {
    // --- Original provenance chain types ---
    /// User's original request (root of chain)
    Intent,
    /// Plan created to fulfill the intent
    Design,
    /// Authorization decision
    Approval,
    /// Actual execution and results
    Execution,
    /// Financial transaction (agent web extension)
    Payment,
    /// Content/API access (agent web extension)
    Access,

    // --- Phase 2.1: Typed claim extensions ---
    /// An observation recorded by an observer agent
    ObservationClaim,
    /// A policy evaluation or constitutional rule invocation
    PolicyClaim,
    /// An authorization decision with explicit scope and constraints
    AuthorizationClaim,
    /// Promotion of knowledge from working memory to long-term memory
    MemoryPromotionClaim,
    /// Delegation of a capability from one agent to another
    DelegationClaim,
    /// Synthesis of multiple observations into a narrative summary
    NarrativeSynthesisClaim,
    /// Revocation of a previously issued receipt
    RevocationClaim,
    /// Configuration of a tool's capabilities with specific values
    ConfigurationClaim,

    // --- Phase 4.1: Cognition plane receipt types ---
    /// A reflection (consolidation pass) over observations by a reflector agent
    ReflectionClaim,

    // --- Phase 7: Canonicalization (bead zero) ---
    /// First-known-state receipt that anchors a domain wire on the abacus.
    /// Emitted once per domain entity (provider, tool, node) to establish
    /// the canonical starting point from which all subsequent state is derived.
    CanonicalizedClaim,

    // --- T1: Chain-Derived Role ---
    /// Delegate node records its acceptance of the delegation relationship.
    /// This is the cryptographic proof that the node is a delegate.
    NodeDelegationAccepted,
    /// Genesis node records that it has granted delegation to a downstream node.
    /// This is the complement to node:delegation:accepted.
    NodeDelegationGranted,

    // --- T2: Role Transitions ---
    /// Node role transition receipt — emitted when the node's derived role changes.
    /// Records the before/after state, the reason for change, and cryptographic
    /// boundary information (chain seal hash for genesis→delegate transitions).
    NodeRoleTransition,

    // --- T4: Fleet Membership Attestation ---
    /// Genesis node records that it has admitted a node to the fleet.
    /// This is the cryptographic proof of fleet membership.
    FleetMembershipGranted,
    /// Joining node records its acceptance of fleet membership.
    /// Complements FleetMembershipGranted on the member's chain.
    FleetMembershipAccepted,

    // --- T7: External Anchoring ---
    /// Records that the local chain state was anchored to an external
    /// settlement layer (e.g., Hedera Consensus Service). Creates an
    /// externally verifiable timestamp proving the chain existed in its
    /// current state at a specific time.
    ExternalAnchor,

    // --- T7 Phase 2: Financial Capability ---
    /// Records a financial capability grant — the binding between a
    /// delegation chain and financial constraints. When a human grants
    /// an agent authority to operate with money, this receipt type carries
    /// the settlement-layer-consumable constraints: spending ceilings,
    /// asset types, counterparty restrictions, approval thresholds, and
    /// escrow requirements.
    FinancialCapabilityGrant,
}

impl ReceiptType {
    /// Returns the ID prefix for this receipt type.
    pub fn id_prefix(&self) -> &'static str {
        match self {
            ReceiptType::Intent => "intn",
            ReceiptType::Design => "dsgn",
            ReceiptType::Approval => "appr",
            ReceiptType::Execution => "rcpt",
            ReceiptType::Payment => "pymt",
            ReceiptType::Access => "accs",
            ReceiptType::ObservationClaim => "obsv",
            ReceiptType::PolicyClaim => "plcy",
            ReceiptType::AuthorizationClaim => "auth",
            ReceiptType::MemoryPromotionClaim => "mpro",
            ReceiptType::DelegationClaim => "dlgt",
            ReceiptType::NarrativeSynthesisClaim => "nrtv",
            ReceiptType::RevocationClaim => "revk",
            ReceiptType::ReflectionClaim => "rflt",
            ReceiptType::ConfigurationClaim => "cfgr",
            ReceiptType::CanonicalizedClaim => "cano",
            ReceiptType::NodeDelegationAccepted => "ndac",
            ReceiptType::NodeDelegationGranted => "ndgr",
            ReceiptType::NodeRoleTransition => "nrtr",
            ReceiptType::FleetMembershipGranted => "fmgr",
            ReceiptType::FleetMembershipAccepted => "fmac",
            ReceiptType::ExternalAnchor => "xanc",
            ReceiptType::FinancialCapabilityGrant => "fcap",
        }
    }

    /// Returns the expected parent type in a standard chain.
    ///
    /// The original six types form a strict provenance chain.
    /// The new claim types are more flexible — they can attach to any
    /// existing receipt as context. Returns None when the parent type
    /// is unconstrained (caller must supply a valid parent_receipt_id).
    pub fn expected_parent(&self) -> Option<ReceiptType> {
        match self {
            ReceiptType::Intent => None,
            ReceiptType::Design => Some(ReceiptType::Intent),
            ReceiptType::Approval => Some(ReceiptType::Design),
            ReceiptType::Execution => Some(ReceiptType::Approval),
            ReceiptType::Payment => Some(ReceiptType::Execution),
            ReceiptType::Access => Some(ReceiptType::Approval),
            // Typed claims can reference any receipt as parent
            ReceiptType::ObservationClaim => None,
            ReceiptType::PolicyClaim => None,
            ReceiptType::AuthorizationClaim => None,
            ReceiptType::MemoryPromotionClaim => None,
            ReceiptType::DelegationClaim => None,
            ReceiptType::NarrativeSynthesisClaim => None,
            ReceiptType::RevocationClaim => None,
            ReceiptType::ReflectionClaim => None,
            ReceiptType::ConfigurationClaim => None,
            ReceiptType::CanonicalizedClaim => None,
            // Node delegation receipts are root claims (no fixed parent)
            ReceiptType::NodeDelegationAccepted => None,
            ReceiptType::NodeDelegationGranted => None,
            // Node role transition is a root claim (no fixed parent)
            ReceiptType::NodeRoleTransition => None,
            // Fleet membership receipts are root claims (no fixed parent)
            ReceiptType::FleetMembershipGranted => None,
            ReceiptType::FleetMembershipAccepted => None,
            // External anchors reference the chain head they anchor
            ReceiptType::ExternalAnchor => None,
            // Financial capability grants reference a delegation receipt
            ReceiptType::FinancialCapabilityGrant => None,
        }
    }

    /// Returns the default expiration duration for this receipt type.
    /// None means the receipt never expires.
    pub fn default_expiry(&self) -> Option<chrono::Duration> {
        match self {
            ReceiptType::Execution => Some(chrono::Duration::days(90)),
            ReceiptType::DelegationClaim => Some(chrono::Duration::days(30)),
            ReceiptType::AuthorizationClaim => Some(chrono::Duration::days(30)),
            // Memory promotion and narrative synthesis persist indefinitely
            ReceiptType::MemoryPromotionClaim => None,
            ReceiptType::NarrativeSynthesisClaim => None,
            // Node delegation receipts persist indefinitely
            // (revocation is a separate receipt type)
            ReceiptType::NodeDelegationAccepted => None,
            ReceiptType::NodeDelegationGranted => None,
            // Node role transitions persist indefinitely
            ReceiptType::NodeRoleTransition => None,
            // Fleet membership receipts persist indefinitely (revocation is separate)
            ReceiptType::FleetMembershipGranted => None,
            ReceiptType::FleetMembershipAccepted => None,
            // External anchors persist indefinitely (they are evidence)
            ReceiptType::ExternalAnchor => None,
            // Financial capability grants persist until revoked or delegation expires
            ReceiptType::FinancialCapabilityGrant => None,
            // Everything else: no default expiry
            _ => None,
        }
    }

    /// Whether this is one of the original provenance chain types.
    pub fn is_provenance_type(&self) -> bool {
        matches!(
            self,
            ReceiptType::Intent
                | ReceiptType::Design
                | ReceiptType::Approval
                | ReceiptType::Execution
                | ReceiptType::Payment
                | ReceiptType::Access
        )
    }

    /// Whether this is a typed claim extension (Phase 2.1+).
    pub fn is_claim_type(&self) -> bool {
        !self.is_provenance_type()
    }
}

impl std::fmt::Display for ReceiptType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReceiptType::Intent => write!(f, "intent"),
            ReceiptType::Design => write!(f, "design"),
            ReceiptType::Approval => write!(f, "approval"),
            ReceiptType::Execution => write!(f, "execution"),
            ReceiptType::Payment => write!(f, "payment"),
            ReceiptType::Access => write!(f, "access"),
            ReceiptType::ObservationClaim => write!(f, "observation_claim"),
            ReceiptType::PolicyClaim => write!(f, "policy_claim"),
            ReceiptType::AuthorizationClaim => write!(f, "authorization_claim"),
            ReceiptType::MemoryPromotionClaim => write!(f, "memory_promotion_claim"),
            ReceiptType::DelegationClaim => write!(f, "delegation_claim"),
            ReceiptType::NarrativeSynthesisClaim => write!(f, "narrative_synthesis_claim"),
            ReceiptType::RevocationClaim => write!(f, "revocation_claim"),
            ReceiptType::ReflectionClaim => write!(f, "reflection_claim"),
            ReceiptType::ConfigurationClaim => write!(f, "configuration_claim"),
            ReceiptType::CanonicalizedClaim => write!(f, "canonicalized_claim"),
            ReceiptType::NodeDelegationAccepted => write!(f, "node_delegation_accepted"),
            ReceiptType::NodeDelegationGranted => write!(f, "node_delegation_granted"),
            ReceiptType::NodeRoleTransition => write!(f, "node_role_transition"),
            ReceiptType::FleetMembershipGranted => write!(f, "fleet_membership_granted"),
            ReceiptType::FleetMembershipAccepted => write!(f, "fleet_membership_accepted"),
            ReceiptType::ExternalAnchor => write!(f, "external_anchor"),
            ReceiptType::FinancialCapabilityGrant => write!(f, "financial_capability_grant"),
        }
    }
}

/// The epistemic meaning of the signature on a receipt.
///
/// This is a critical semantic distinction introduced in Phase 2.3.
/// Signing a receipt with `AuthorshipProof` semantics proves who created it
/// but does NOT assert that the content is true. Only `TruthAssertion`
/// semantics can be used for memory promotion (Phase 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ClaimSemantics {
    /// "I made this." Proves authorship/origin. Default for all existing receipts.
    #[default]
    AuthorshipProof,
    /// "This hasn't changed." Proves content integrity since a prior state.
    IntegrityAttestation,
    /// "I believe this is true." Required for memory promotion and knowledge claims.
    TruthAssertion,
    /// "I permit this." Used for authorization grants and delegation claims.
    AuthorizationGrant,
}

fn default_claim_semantics() -> ClaimSemantics {
    ClaimSemantics::default()
}

/// Outcome status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Success,
    Partial,
    Failed,
    Denied,
    Timeout,
    Pending,
}

/// Assurance level.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrustGrade {
    /// Signed receipt only
    #[default]
    D,
    /// Sandboxed execution (container/VM/jail)
    C,
    /// Hardware key + OS integrity
    B,
    /// TEE with hardware root of trust
    A,
}

/// Type of executor entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExecutorType {
    Agent,
    Human,
    Service,
    Pipeline,
    Role,
}

/// Category of action performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    CodeExecution,
    ShellCommand,
    ToolCall,
    ApiRequest,
    FileOperation,
    Payment,
    ContentAccess,
    Delegation,
    PolicyEvaluation,
    PlanCreation,
    ApprovalDecision,
}

/// Policy evaluation decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
    Escalate,
    AuditOnly,
}

/// Trust tier for policy evaluation.
///
/// **Sync note.** This enum mirrors `zp_core::policy::TrustTier`. The two
/// definitions are kept in lockstep by hand because `zp-core` already
/// depends on `zp-receipt`, so a clean re-export would require breaking
/// that dep first (extracting the tier type into its own crate). When
/// extending: extend BOTH and keep variant order identical so the derived
/// `Ord` lines up. Wire-format note: this enum uses `lowercase` rename
/// while zp-core's uses default (`Tier0`) — they intentionally serialize
/// differently because they appear in different JSON schemas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustTier {
    Tier0,
    Tier1,
    Tier2,
    Tier3,
    Tier4,
    Tier5,
}

/// Type of redaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionType {
    Credential,
    Pii,
    Secret,
    SensitiveOutput,
}

// ============================================================================
// Nested structs
// ============================================================================

/// Identity of the entity that performed the action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Executor {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executor_type: Option<ExecutorType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,
}

/// Description of the action performed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    #[serde(rename = "type")]
    pub action_type: ActionType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

impl Action {
    /// Convenience: code execution action.
    pub fn code_execution(runtime: &str, exit_code: i32) -> Self {
        Self {
            action_type: ActionType::CodeExecution,
            name: Some(runtime.to_string()),
            input_hash: None,
            output_hash: None,
            exit_code: Some(exit_code),
            detail: None,
        }
    }

    /// Convenience: shell command action.
    pub fn shell_command(command_hash: &str, exit_code: i32) -> Self {
        Self {
            action_type: ActionType::ShellCommand,
            name: Some("shell".to_string()),
            input_hash: Some(command_hash.to_string()),
            output_hash: None,
            exit_code: Some(exit_code),
            detail: None,
        }
    }

    /// Convenience: tool call action.
    pub fn tool_call(tool_name: &str) -> Self {
        Self {
            action_type: ActionType::ToolCall,
            name: Some(tool_name.to_string()),
            input_hash: None,
            output_hash: None,
            exit_code: None,
            detail: None,
        }
    }

    /// Convenience: payment action.
    pub fn payment(amount_usd: f64, recipient: &str) -> Self {
        Self {
            action_type: ActionType::Payment,
            name: Some("payment".to_string()),
            input_hash: None,
            output_hash: None,
            exit_code: None,
            detail: Some(serde_json::json!({
                "amount_usd": amount_usd,
                "recipient": recipient,
            })),
        }
    }

    /// Convenience: API access action.
    pub fn api_request(endpoint: &str, method: &str) -> Self {
        Self {
            action_type: ActionType::ApiRequest,
            name: Some(endpoint.to_string()),
            input_hash: None,
            output_hash: None,
            exit_code: None,
            detail: Some(serde_json::json!({ "method": method })),
        }
    }
}

/// Timing information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timing {
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queued_ms: Option<u64>,
}

/// Resource consumption.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Resources {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_seconds: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_peak_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_written_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_bytes_sent: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_bytes_received: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens_input: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens_output: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,
}

/// Output artifact with integrity hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputArtifact {
    pub path: String,
    pub hash: String,
    pub size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// Hashes of I/O streams.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoHashes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdin_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr_size: Option<u64>,
}

/// Policy evaluation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub decision: Decision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_tier: Option<TrustTier>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
}

/// Error details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub recoverable: bool,
}

/// Redaction record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Redaction {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redaction_type: Option<RedactionType>,
    pub target: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_hash: Option<String>,
}

/// Hash-chain linkage metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,
}

// ============================================================================
// Phase 2.1: Typed Claim Metadata
// ============================================================================

/// Type-specific metadata carried by claim receipts.
///
/// Each claim type has distinct validation requirements and semantics.
/// The variant must match the `receipt_type` — e.g. an `ObservationClaim`
/// receipt must carry `ClaimMetadata::Observation`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "claim_type")]
pub enum ClaimMetadata {
    /// Metadata for an observation recorded by an observer agent.
    Observation {
        /// What was observed (e.g., "tool_invocation", "policy_violation")
        observation_type: String,
        /// The agent or system that produced the observation
        observer_id: String,
        /// Confidence level (0.0 - 1.0)
        #[serde(skip_serializing_if = "Option::is_none")]
        confidence: Option<f64>,
        /// Tags for categorization
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        tags: Vec<String>,
    },

    /// Metadata for a policy evaluation claim.
    Policy {
        /// The policy rule that was evaluated
        rule_id: String,
        /// The constitutional principle, if any
        #[serde(skip_serializing_if = "Option::is_none")]
        principle: Option<String>,
        /// Whether the policy was satisfied
        satisfied: bool,
        /// Explanation of the evaluation
        #[serde(skip_serializing_if = "Option::is_none")]
        rationale: Option<String>,
    },

    /// Metadata for an authorization claim.
    Authorization {
        /// Scope of the authorization (e.g., "tool:launch", "proxy:openai")
        scope: String,
        /// Who granted the authorization
        grantor_id: String,
        /// Constraints on the authorization (e.g., rate limits, time bounds)
        #[serde(default, skip_serializing_if = "HashMap::is_empty")]
        constraints: HashMap<String, serde_json::Value>,
    },

    /// Metadata for a memory promotion claim.
    MemoryPromotion {
        /// Where the knowledge came from (e.g., "working_memory", "observation")
        source_stage: String,
        /// Where it was promoted to (e.g., "episodic", "semantic", "procedural")
        target_stage: String,
        /// Evidence supporting the promotion
        promotion_evidence: String,
        /// Who reviewed and approved the promotion
        #[serde(skip_serializing_if = "Option::is_none")]
        reviewer: Option<String>,
    },

    /// Metadata for a delegation claim.
    Delegation {
        /// The capability being delegated
        capability_id: String,
        /// Who is delegating
        delegator_id: String,
        /// Who receives the delegation
        delegate_id: String,
        /// Maximum depth of re-delegation allowed (0 = no re-delegation)
        #[serde(default)]
        max_depth: u32,
    },

    /// Metadata for a narrative synthesis claim.
    NarrativeSynthesis {
        /// The observation receipt IDs that were synthesized
        source_observation_ids: Vec<String>,
        /// The synthesis method (e.g., "temporal_summary", "anomaly_report")
        synthesis_method: String,
        /// The agent that performed the synthesis
        synthesizer_id: String,
    },

    /// Metadata for a reflection (consolidation) claim.
    /// Produced by the Reflector agent when it merges/upgrades/downgrades/drops observations.
    Reflection {
        /// IDs of observations consumed (merged, upgraded, downgraded, completed)
        consumed_observation_ids: Vec<String>,
        /// IDs of new observations produced by the consolidation
        produced_observation_ids: Vec<String>,
        /// IDs of observations dropped (pruned entirely)
        dropped_observation_ids: Vec<String>,
        /// Total observation tokens before reflection
        tokens_before: usize,
        /// Total observation tokens after reflection
        tokens_after: usize,
        /// Compression ratio (tokens_after / tokens_before)
        compression_ratio: f64,
        /// The reflector agent that performed the consolidation
        reflector_id: String,
    },

    /// Metadata for a revocation claim.
    Revocation {
        /// The receipt ID being revoked
        revoked_receipt_id: String,
        /// Why it was revoked
        reason: String,
        /// Who authorized the revocation
        revoker_id: String,
    },

    /// Metadata for a tool capability configuration claim.
    /// Emitted when a tool's configurable parameters are set or changed.
    Configuration {
        /// The tool being configured
        tool_id: String,
        /// Parameter name (e.g., "max_tokens", "temperature", "model")
        parameter: String,
        /// The configured value (serialized)
        value: serde_json::Value,
        /// Whether this is a default from the manifest or an operator override
        source: ConfigurationSource,
        /// The previous value, if this is a reconfiguration
        #[serde(skip_serializing_if = "Option::is_none")]
        previous_value: Option<serde_json::Value>,
    },

    /// Metadata for a canonicalization claim (bead zero).
    /// Captures the first-known-state of a domain entity, anchoring
    /// the wire from which all subsequent state transitions are derived.
    Canonicalization {
        /// The domain being canonicalized: "system", "provider", "tool", "node"
        domain: CanonicalDomain,
        /// The entity name within that domain (e.g., "anthropic", "ironclaw")
        entity_id: String,
        /// Parent domain entity this was canonicalized under
        /// (e.g., tool "ironclaw" under provider "anthropic")
        #[serde(skip_serializing_if = "Option::is_none")]
        parent_entity: Option<String>,
        /// Snapshot of the entity's state at canonicalization time
        /// (e.g., vault keys present, provider fields set)
        initial_state: serde_json::Value,
        /// Who triggered the canonicalization
        canonicalized_by: String,
        /// F3 pre-canon content scanner verdict ("clean" | "flagged" | "blocked").
        /// Absent on legacy or system/provider canonicalizations that didn't
        /// pass through the scanner.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scan_verdict: Option<String>,
        /// Number of findings recorded by the F3 scanner.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scan_findings_count: Option<u32>,
        /// RFC3339 timestamp at which the F3 scan ran.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scan_timestamp: Option<String>,
        /// F5 reversibility declared by the tool's manifest at canonicalization time.
        /// One of "reversible" | "partial" | "irreversible" | "unknown". Absent on
        /// pre-F5 chains and on system/provider canonicalizations.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reversibility: Option<String>,
    },

    /// Metadata for a tool lifecycle state transition (beads after bead zero).
    /// Each variant maps to a distinct event on a tool's abacus wire:
    /// configured, preflight passed/failed, launched, setup complete,
    /// providers resolved, capability verified/degraded/failed.
    Lifecycle {
        /// The tool this lifecycle event belongs to
        tool_id: String,
        /// The lifecycle event type (e.g., "configured", "preflight:passed",
        /// "launched", "setup:complete", "providers:resolved",
        /// "capability:verified", "capability:degraded", "capability:failed")
        event_type: String,
        /// Optional detail (e.g., capability name, failure reason)
        #[serde(skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },

    /// Metadata for node:delegation:accepted — delegate records its acceptance.
    /// This is the cryptographic proof that the node is a delegate (T1).
    NodeDelegationAccepted {
        /// The upstream genesis server address (e.g., "192.168.1.152:17770")
        upstream_addr: String,
        /// The upstream node's genesis public key (ed25519:...)
        upstream_genesis_pubkey: String,
        /// The upstream node's ID for reference
        #[serde(skip_serializing_if = "Option::is_none")]
        upstream_node_id: Option<String>,
        /// When the delegation was accepted
        accepted_at: String,
        /// The config hint role at acceptance time (for audit trail)
        #[serde(skip_serializing_if = "Option::is_none")]
        config_hint_role: Option<String>,
    },

    /// Metadata for node:delegation:granted — genesis records the grant.
    /// This is the complement to node:delegation:accepted (T1).
    NodeDelegationGranted {
        /// The delegate node's ID
        delegate_node_id: String,
        /// The delegate node's public key for future verification
        #[serde(skip_serializing_if = "Option::is_none")]
        delegate_pubkey: Option<String>,
        /// The delegate node's address (e.g., "192.168.1.199:17770")
        #[serde(skip_serializing_if = "Option::is_none")]
        delegate_addr: Option<String>,
        /// When the delegation was granted
        granted_at: String,
    },

    /// Metadata for a node role transition (T2).
    /// Emitted when the node's derived role changes (e.g., Genesis→Delegate,
    /// Delegate→Standalone, or Delegate with different upstream).
    NodeRoleTransition {
        /// What the node was before (e.g., "Genesis", "Delegate(192.168.1.152:17770)", "Standalone")
        previous_role: String,
        /// What the node is now
        new_role: String,
        /// Why the transition happened
        /// Standard values: "delegation_accepted", "delegation_revoked", "redelegation", "genesis_performed", "operator_initiated"
        trigger: String,
        /// Hash of the chain at transition time — cryptographic boundary between eras.
        /// Present when the transition requires sealing (genesis→delegate).
        #[serde(skip_serializing_if = "Option::is_none")]
        sealed_chain_hash: Option<String>,
        /// The receipt ID being superseded (e.g., old ndac being replaced)
        #[serde(skip_serializing_if = "Option::is_none")]
        superseded_receipt_id: Option<String>,
        /// When the transition occurred
        transition_at: String,
    },

    /// Metadata for fleet:membership:granted — genesis admits a node to the fleet (T4).
    FleetMembershipGranted {
        /// The admitted node's ID
        member_node_id: String,
        /// The admitted node's public key (for future verification)
        member_pubkey: String,
        /// The admitted node's network endpoint
        member_endpoint: String,
        /// Trust tier assigned at admission
        assigned_trust_tier: u8,
        /// Capabilities granted to this member
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        capabilities: Vec<String>,
        /// When the membership was granted
        granted_at: String,
    },

    /// Metadata for fleet:membership:accepted — joining node records acceptance (T4).
    FleetMembershipAccepted {
        /// The genesis node's ID (fleet authority)
        fleet_authority_id: String,
        /// The genesis node's public key
        fleet_authority_pubkey: String,
        /// Receipt ID of the FleetMembershipGranted receipt
        grant_receipt_id: String,
        /// When the membership was accepted
        accepted_at: String,
    },

    /// Metadata for a financial capability grant (T7 Phase 2).
    /// Binds financial constraints to a delegation chain so that
    /// settlement layers can consume and enforce spending limits.
    /// This is the bridge between ZeroPoint's trust substrate and
    /// the financial settlement layer.
    FinancialCapability {
        /// The delegation receipt this enriches (links to the capability grant)
        delegation_receipt_id: String,
        /// The agent receiving financial authority
        agent_id: String,
        /// The human principal granting authority
        principal_id: String,
        /// Maximum spend amount per period
        ceiling_amount: f64,
        /// Currency of the spending ceiling (e.g., "USD", "HBAR")
        ceiling_currency: String,
        /// Period over which the ceiling applies: "daily", "weekly", "monthly", "total"
        ceiling_period: String,
        /// Asset types the agent may spend (empty = ceiling currency only)
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        asset_types: Vec<String>,
        /// Counterparties the agent may pay (empty = unrestricted)
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        counterparty_allowlist: Vec<String>,
        /// Counterparties the agent may NOT pay (empty = no denylist)
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        counterparty_denylist: Vec<String>,
        /// Amount above which human confirmation is required (None = no threshold)
        #[serde(skip_serializing_if = "Option::is_none")]
        approval_threshold: Option<f64>,
        /// Whether funds must be pre-committed to escrow before the agent can spend
        #[serde(default)]
        escrow_required: bool,
        /// When this financial capability was granted
        granted_at: String,
    },

    /// Metadata for an external anchor (T7).
    /// Records that the local chain state was anchored to an external
    /// settlement layer, creating an externally verifiable timestamp.
    ExternalAnchor {
        /// The settlement layer used (e.g., "hedera_hcs", "ethereum", "bitcoin")
        settlement_layer: String,
        /// Blake3 hash of the local chain head at anchor time
        chain_head_hash: String,
        /// Number of receipts in the local chain at anchor time
        chain_length: u64,
        /// What triggered the anchor (e.g., "role_transition", "delegation",
        /// "settlement", "heartbeat", "fleet_membership")
        anchor_trigger: String,
        /// External reference — settlement-layer-specific identifier
        /// (e.g., HCS topic ID + sequence number, Ethereum tx hash)
        #[serde(skip_serializing_if = "Option::is_none")]
        external_ref: Option<String>,
        /// Consensus timestamp from the settlement layer (if available)
        /// This is the externally attested timestamp, not the local clock.
        #[serde(skip_serializing_if = "Option::is_none")]
        consensus_timestamp: Option<String>,
        /// Reference to the previous anchor receipt (local chain linkage)
        #[serde(skip_serializing_if = "Option::is_none")]
        previous_anchor_id: Option<String>,
        /// When the anchor was submitted
        anchored_at: String,
    },
}

/// Source of a configuration value.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigurationSource {
    /// Default from the tool manifest
    ManifestDefault,
    /// Explicitly set by the operator
    OperatorOverride,
    /// Set during initial onboarding/configure
    InitialSetup,
    /// Changed at runtime via reconfiguration
    RuntimeChange,
}

/// Domain of a canonicalization event — which wire on the abacus.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalDomain {
    /// The system itself (genesis is bead zero on this wire)
    System,
    /// A credential provider (e.g., "anthropic", "openai")
    Provider,
    /// A governed tool (e.g., "ironclaw", "shannon")
    Tool,
    /// A fleet node in a multi-node deployment
    Node,
}
