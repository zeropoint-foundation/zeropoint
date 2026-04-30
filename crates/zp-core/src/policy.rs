//! Policy types — the vocabulary of the WASM policy engine.
//!
//! PolicyDecision is the graduated severity model inspired by IronClaw:
//! Allow / Block / Warn / Review / Sanitize.

use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::types::{Channel, ConversationId};

/// Trust tier configuration. The runtime enforces whatever tier is
/// configured — the LLM never knows.
///
/// The tier ladder is structural, not just a label: each rung carries an
/// invariant that the rest of the substrate enforces. The variant order
/// matters — `PartialOrd`/`Ord` on this enum derives the
/// "ceiling-comparison" used by the gate, the delegation chain, and the
/// blast-radius tracker.
///
/// **The Ceremony invariant.** Tier 5 is the ZeroPoint "cold floor": a
/// running node can hold a Tier ≤ 4 grant under lease, but no live
/// process is ever permitted to issue or hold a Tier 5 capability.
/// `CapabilityGrant::delegate()` rejects re-delegation of T5; T5
/// authority is exercised only during a genesis ceremony with the
/// hardware-secured operator key offline. This is what keeps the very
/// top of the substrate from being reachable by code paths.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrustTier {
    /// **Sandbox.** No signing. Modules load from local filesystem. Trust =
    /// you control the machine. Default.
    #[default]
    Tier0,
    /// **Verified.** Local key signs modules. Tamper detection via hash
    /// verification.
    Tier1,
    /// **Operational.** Genesis root key, delegation chain, all modules
    /// signed. Full provenance.
    Tier2,
    /// **Core.** High-privilege operational authority — can manage tools,
    /// renew leases, reach the network. The "team-lead" rung; granted to
    /// trusted automation like Sentinel.
    Tier3,
    /// **Council.** Governance authority. Can issue and revoke standing
    /// delegations across the fleet. Genesis-rooted.
    Tier4,
    /// **Ceremony.** Cold storage / hardware-secured / never online.
    /// Structural invariant: no running node can hold or issue a Tier 5
    /// capability — the delegate() path rejects it. T5 is exercised only
    /// during a genesis ceremony with the operator key physically present.
    Tier5,
}

impl TrustTier {
    /// Map a 0–5 numeric tier to the enum. Returns `None` for 6+.
    /// Used by CLI / config parsers to surface "tier_ceiling out of range"
    /// errors rather than silently capping.
    pub fn from_u8(n: u8) -> Option<Self> {
        match n {
            0 => Some(TrustTier::Tier0),
            1 => Some(TrustTier::Tier1),
            2 => Some(TrustTier::Tier2),
            3 => Some(TrustTier::Tier3),
            4 => Some(TrustTier::Tier4),
            5 => Some(TrustTier::Tier5),
            _ => None,
        }
    }

    /// Numeric rung. Inverse of `from_u8` for valid tiers.
    pub fn as_u8(&self) -> u8 {
        match self {
            TrustTier::Tier0 => 0,
            TrustTier::Tier1 => 1,
            TrustTier::Tier2 => 2,
            TrustTier::Tier3 => 3,
            TrustTier::Tier4 => 4,
            TrustTier::Tier5 => 5,
        }
    }

    /// `true` iff this tier is the Ceremony rung that no running node may
    /// issue or hold. `delegate()` rejects when this is true.
    pub fn is_ceremony(&self) -> bool {
        matches!(self, TrustTier::Tier5)
    }
}

/// The context provided to a WASM policy module for evaluation.
/// Pure structured data — no LLM state, no prompt content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyContext {
    /// The action being requested
    pub action: ActionType,
    /// Active trust tier
    pub trust_tier: TrustTier,
    /// Channel the request came from
    pub channel: Channel,
    /// Conversation context
    pub conversation_id: ConversationId,
    /// Which skills are being invoked
    pub skill_ids: Vec<String>,
    /// Which tools would be activated
    pub tool_names: Vec<String>,
    /// Optional mesh peer context for reputation-gated policy decisions (Phase 4).
    /// Present when the action involves a mesh peer interaction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh_context: Option<MeshPeerContext>,
}

/// Context about a mesh peer involved in the current action.
///
/// Carried inside `PolicyContext` so that the `ReputationGateRule` can
/// make reputation-aware policy decisions without the policy engine
/// needing a direct dependency on `zp-mesh`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshPeerContext {
    /// The peer's mesh address (hex-encoded destination hash).
    pub peer_address: String,
    /// The peer's reputation grade, if known.
    pub reputation_grade: Option<String>,
    /// The peer's reputation score (0.0–1.0), if known.
    pub reputation_score: Option<f64>,
    /// What mesh action is being requested with this peer.
    pub mesh_action: MeshAction,
}

/// Types of mesh actions subject to reputation gating.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MeshAction {
    /// Forward a receipt to this peer.
    ForwardReceipt,
    /// Accept a receipt from this peer.
    AcceptReceipt,
    /// Share policy modules with this peer.
    SharePolicy,
    /// Accept policy modules from this peer.
    AcceptPolicy,
    /// Delegate capabilities to this peer.
    DelegateCapability,
    /// Accept delegated capabilities from this peer.
    AcceptDelegation,
}

/// Categorized action types for policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionType {
    /// Pure conversation — no tool use
    Chat,
    /// Read-only data access
    Read { target: String },
    /// Data modification
    Write { target: String },
    /// External API call
    ApiCall { endpoint: String },
    /// Code execution
    Execute { language: String },
    /// File system operation
    FileOp { op: FileOperation, path: String },
    /// Credential access
    CredentialAccess { credential_ref: String },
    /// System configuration change
    ConfigChange { setting: String },
    /// Key delegation — issuing a child certificate in the key hierarchy.
    ///
    /// Governed by the policy engine so that operators can control when and
    /// how trust is extended. The mechanism (signing) is unconditional;
    /// the *decision* to delegate is policy-gated.
    KeyDelegation {
        /// Role being delegated to (e.g., "operator", "agent").
        target_role: String,
        /// Subject name of the key being certified.
        target_subject: String,
        /// Genesis public key fingerprint (first 16 hex chars).
        genesis_fingerprint: String,
    },
    /// Peer introduction — establishing trust with a new remote node.
    ///
    /// Triggered when a node presents its certificate chain and requests
    /// a trust relationship. The policy engine decides whether to accept.
    PeerIntroduction {
        /// The remote peer's mesh address.
        peer_address: String,
        /// The role of the peer's leaf certificate.
        peer_role: String,
        /// The genesis fingerprint the peer's chain traces back to.
        peer_genesis_fingerprint: String,
        /// Whether the peer's genesis matches our own.
        same_genesis: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileOperation {
    Read,
    Write,
    Delete,
    Create,
    List,
}

/// Graduated policy decision — the heart of the safety layer.
///
/// Replaces binary Allow/Deny with nuanced responses that give operators
/// graduated control over agent behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyDecision {
    /// Action is permitted. Proceed normally.
    Allow {
        #[serde(default)]
        conditions: Vec<String>,
    },

    /// Action is blocked. Cannot proceed under any circumstances.
    Block {
        reason: String,
        policy_module: String,
    },

    /// Action is permitted but flagged. User is warned before execution.
    Warn {
        message: String,
        /// Does the user need to explicitly acknowledge before proceeding?
        require_ack: bool,
    },

    /// Action requires human review before execution.
    Review {
        summary: String,
        /// Who needs to review
        reviewer: ReviewTarget,
        /// How long to wait before auto-denying
        #[serde(with = "optional_duration_serde")]
        timeout: Option<Duration>,
    },

    /// Action is permitted but output must be sanitized.
    Sanitize {
        /// What patterns to redact in the output
        patterns: Vec<SanitizePattern>,
    },
}

impl PolicyDecision {
    /// Quick check: does this decision allow the action to proceed
    /// (possibly with conditions)?
    pub fn is_allowed(&self) -> bool {
        matches!(
            self,
            PolicyDecision::Allow { .. } | PolicyDecision::Sanitize { .. }
        )
    }

    /// Quick check: is this a hard block?
    pub fn is_blocked(&self) -> bool {
        matches!(self, PolicyDecision::Block { .. })
    }

    /// Quick check: does this need user interaction before proceeding?
    pub fn needs_interaction(&self) -> bool {
        matches!(
            self,
            PolicyDecision::Warn {
                require_ack: true,
                ..
            } | PolicyDecision::Review { .. }
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReviewTarget {
    /// Current user in the conversation
    CurrentUser,
    /// A specific user by identifier
    User(String),
}

/// A pattern to redact from output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizePattern {
    /// Human-readable name for what's being redacted
    pub name: String,
    /// Regex pattern to match
    pub pattern: String,
    /// What to replace with
    pub replacement: String,
}

/// Risk level assessment for model routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    /// Assess risk level from an action type.
    pub fn from_action(action: &ActionType) -> Self {
        match action {
            ActionType::Chat => RiskLevel::Low,
            ActionType::Read { .. } => RiskLevel::Low,
            ActionType::Write { .. } => RiskLevel::Medium,
            ActionType::ApiCall { .. } => RiskLevel::High,
            ActionType::Execute { .. } => RiskLevel::High,
            ActionType::FileOp {
                op: FileOperation::Delete,
                ..
            } => RiskLevel::High,
            ActionType::FileOp {
                op: FileOperation::Write,
                ..
            } => RiskLevel::Medium,
            ActionType::FileOp { .. } => RiskLevel::Low,
            ActionType::CredentialAccess { .. } => RiskLevel::Critical,
            ActionType::ConfigChange { .. } => RiskLevel::High,
            ActionType::KeyDelegation { .. } => RiskLevel::Critical,
            ActionType::PeerIntroduction {
                same_genesis: true, ..
            } => RiskLevel::High,
            ActionType::PeerIntroduction {
                same_genesis: false,
                ..
            } => RiskLevel::Critical,
        }
    }
}

/// Metadata about a policy module (for audit trail).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMetadata {
    pub module_id: String,
    pub version: String,
    pub description: String,
    pub signature: Option<String>,
}

// Serde helper for Option<Duration>
mod optional_duration_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match duration {
            Some(d) => d.as_secs().serialize(serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<u64> = Option::deserialize(deserializer)?;
        Ok(opt.map(Duration::from_secs))
    }
}
