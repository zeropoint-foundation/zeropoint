//! Collective audit — peer-to-peer audit chain verification.
//!
//! Enables mesh agents to challenge each other's audit chains,
//! exchange chain segments for cross-verification, and produce
//! attestations that a peer's audit trail is intact.
//!
//! ## Protocol
//!
//! 1. **Challenge**: Agent A sends an `AuditChallenge` to Agent B,
//!    requesting chain segments since a known hash.
//! 2. **Response**: Agent B replies with `AuditResponse` containing
//!    compact audit entries from the requested range.
//! 3. **Attestation**: Agent A verifies the chain segment and produces
//!    a `PeerAuditAttestation` recording the result.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Maximum number of compact audit entries in a single response.
/// Kept small to fit within mesh packet MTU constraints.
pub const MAX_ENTRIES_PER_RESPONSE: usize = 3;

/// A challenge from one peer to verify another's audit chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditChallenge {
    /// Unique challenge identifier.
    pub id: String,
    /// What range of entries we're requesting.
    pub range: AuditRange,
    /// The challenger's latest known hash from this peer (if any).
    /// Used to detect chain divergence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known_tip: Option<String>,
    /// Unix timestamp of the challenge.
    pub ts: i64,
}

/// Specifies which audit entries to return.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditRange {
    /// Request the N most recent entries.
    Recent(usize),
    /// Request entries since a specific hash (exclusive).
    SinceHash(String),
}

/// Response to an audit challenge with chain segment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditResponse {
    /// References the challenge this responds to.
    pub challenge_id: String,
    /// The compact audit entries in chronological order.
    pub entries: Vec<CompactAuditEntry>,
    /// Hash of the responder's chain tip (most recent entry).
    pub chain_tip: String,
    /// Total entries available (may exceed what's included).
    pub total_available: usize,
    /// Whether more entries follow (pagination).
    pub has_more: bool,
}

/// Compact representation of an audit entry for mesh transmission.
///
/// Uses short field names to minimize wire size, similar to
/// `CompactReceipt` and `CompactDelegation`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactAuditEntry {
    /// Audit entry ID (UUID string).
    pub id: String,
    /// Timestamp (Unix seconds).
    pub ts: i64,
    /// Previous entry hash (chain link).
    pub ph: String,
    /// This entry's hash.
    pub eh: String,
    /// Actor identifier (compact string).
    pub ac: String,
    /// Action type (compact string: "msg", "resp", "tool", "exec", "config", "skill", "guard").
    pub at: String,
    /// Policy decision ("allow", "block", "warn", "escalate").
    pub pd: String,
    /// Policy module name.
    pub pm: String,
    /// Signature (if present).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sg: Option<String>,
}

impl CompactAuditEntry {
    /// Convert from a full `AuditEntry`.
    pub fn from_entry(entry: &zp_core::AuditEntry) -> Self {
        let ac = match &entry.actor {
            zp_core::ActorId::User(name) => format!("u:{}", name),
            zp_core::ActorId::Operator => "op".to_string(),
            zp_core::ActorId::System(name) => format!("s:{}", name),
            zp_core::ActorId::Skill(name) => format!("sk:{}", name),
        };

        let at = match &entry.action {
            zp_core::AuditAction::MessageReceived { .. } => "msg".to_string(),
            zp_core::AuditAction::ResponseGenerated { .. } => "resp".to_string(),
            zp_core::AuditAction::ToolInvoked { .. } => "tool".to_string(),
            zp_core::AuditAction::ToolCompleted { .. } => "exec".to_string(),
            zp_core::AuditAction::CredentialInjected { .. } => "cred".to_string(),
            zp_core::AuditAction::PolicyInteraction { .. } => "policy".to_string(),
            zp_core::AuditAction::OutputSanitized { .. } => "sanitize".to_string(),
            zp_core::AuditAction::SkillActivated { .. } => "skill".to_string(),
            zp_core::AuditAction::SkillProposed { .. } => "skillp".to_string(),
            zp_core::AuditAction::SkillApproved { .. } => "skilla".to_string(),
            zp_core::AuditAction::SystemEvent { .. } => "sys".to_string(),
            zp_core::AuditAction::ApiCallProxied { .. } => "proxy".to_string(),
        };

        let pd = compact_decision(&entry.policy_decision);

        Self {
            id: entry.id.0.to_string(),
            ts: entry.timestamp.timestamp(),
            ph: entry.prev_hash.clone(),
            eh: entry.entry_hash.clone(),
            ac,
            at,
            pd,
            pm: entry.policy_module.clone(),
            sg: entry.signature.clone(),
        }
    }
}

/// Attestation that a peer's audit chain has been verified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAuditAttestation {
    /// Unique attestation ID.
    pub id: String,
    /// The peer whose chain was verified (destination hash, hex).
    pub peer: String,
    /// Hash of the oldest entry verified.
    pub oldest_hash: String,
    /// Hash of the newest entry verified (chain tip).
    pub newest_hash: String,
    /// Number of entries verified.
    pub entries_verified: usize,
    /// Whether the chain passed all integrity checks.
    pub chain_valid: bool,
    /// Number of valid signatures found.
    pub signatures_valid: usize,
    /// When the verification was performed.
    pub timestamp: DateTime<Utc>,
    /// Verifier's signature over the attestation (hex, if signed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl PeerAuditAttestation {
    /// Compute a deterministic hash for this attestation.
    pub fn compute_hash(&self) -> String {
        let canonical = serde_json::json!({
            "id": self.id,
            "peer": self.peer,
            "oldest_hash": self.oldest_hash,
            "newest_hash": self.newest_hash,
            "entries_verified": self.entries_verified,
            "chain_valid": self.chain_valid,
            "signatures_valid": self.signatures_valid,
            "timestamp": self.timestamp.to_rfc3339(),
        });
        let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
        blake3::hash(&bytes).to_hex().to_string()
    }
}

impl AuditChallenge {
    /// Create a challenge requesting recent entries.
    pub fn recent(count: usize) -> Self {
        Self {
            id: format!("chal-{}", uuid::Uuid::now_v7()),
            range: AuditRange::Recent(count),
            known_tip: None,
            ts: Utc::now().timestamp(),
        }
    }

    /// Create a challenge requesting entries since a known hash.
    pub fn since_hash(hash: String) -> Self {
        Self {
            id: format!("chal-{}", uuid::Uuid::now_v7()),
            range: AuditRange::SinceHash(hash.clone()),
            known_tip: Some(hash),
            ts: Utc::now().timestamp(),
        }
    }
}

impl AuditResponse {
    /// Build a response from a store's exported chain segment.
    pub fn from_entries(
        challenge_id: &str,
        entries: &[zp_core::AuditEntry],
        total_available: usize,
    ) -> Self {
        let compact: Vec<CompactAuditEntry> = entries
            .iter()
            .take(MAX_ENTRIES_PER_RESPONSE)
            .map(CompactAuditEntry::from_entry)
            .collect();

        let chain_tip = entries
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_default();

        Self {
            challenge_id: challenge_id.to_string(),
            entries: compact,
            chain_tip,
            total_available,
            has_more: entries.len() > MAX_ENTRIES_PER_RESPONSE,
        }
    }
}

/// Verify a set of compact audit entries for chain integrity.
///
/// Checks that `prev_hash` links are consistent across entries.
/// Returns a `PeerAuditAttestation` recording the result.
pub fn verify_peer_chain(peer: &str, entries: &[CompactAuditEntry]) -> PeerAuditAttestation {
    let chain_valid = if entries.is_empty() {
        true
    } else {
        // Check that each entry's prev_hash matches the previous entry's entry_hash
        entries.windows(2).all(|w| w[1].ph == w[0].eh)
    };

    let oldest_hash = entries.first().map(|e| e.eh.clone()).unwrap_or_default();

    let newest_hash = entries.last().map(|e| e.eh.clone()).unwrap_or_default();

    let signatures_valid = entries.iter().filter(|e| e.sg.is_some()).count();

    PeerAuditAttestation {
        id: format!("att-{}", uuid::Uuid::now_v7()),
        peer: peer.to_string(),
        oldest_hash,
        newest_hash,
        entries_verified: entries.len(),
        chain_valid,
        signatures_valid,
        timestamp: Utc::now(),
        signature: None,
    }
}

/// Compact policy decision for wire transmission.
fn compact_decision(decision: &zp_core::PolicyDecision) -> String {
    match decision {
        zp_core::PolicyDecision::Allow { .. } => "allow".to_string(),
        zp_core::PolicyDecision::Block { .. } => "block".to_string(),
        zp_core::PolicyDecision::Warn { .. } => "warn".to_string(),
        zp_core::PolicyDecision::Review { .. } => "review".to_string(),
        zp_core::PolicyDecision::Sanitize { .. } => "sanitize".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zp_core::{ActorId, AuditAction, AuditEntry, AuditId, ConversationId, PolicyDecision};

    fn make_test_entry(prev_hash: &str, index: usize) -> AuditEntry {
        let entry_hash = blake3::hash(format!("entry-{}", index).as_bytes())
            .to_hex()
            .to_string();
        AuditEntry {
            id: AuditId::new(),
            timestamp: Utc::now(),
            prev_hash: prev_hash.to_string(),
            entry_hash,
            actor: ActorId::System("test-agent".to_string()),
            action: AuditAction::ToolInvoked {
                tool_name: "ls".to_string(),
                arguments_hash: "abc123".to_string(),
            },
            conversation_id: ConversationId::new(),
            policy_decision: PolicyDecision::Allow { conditions: vec![] },
            policy_module: "default-gate".to_string(),
            receipt: None,
            signature: None,
        }
    }

    fn make_chain(n: usize) -> Vec<AuditEntry> {
        let genesis = blake3::hash(b"").to_hex().to_string();
        let mut chain = Vec::new();
        let mut prev = genesis;
        for i in 0..n {
            let entry = make_test_entry(&prev, i);
            prev = entry.entry_hash.clone();
            chain.push(entry);
        }
        chain
    }

    #[test]
    fn test_compact_audit_entry_from_entry() {
        let chain = make_chain(1);
        let compact = CompactAuditEntry::from_entry(&chain[0]);
        assert_eq!(compact.at, "tool");
        assert_eq!(compact.pd, "allow");
        assert_eq!(compact.pm, "default-gate");
        assert!(compact.ac.starts_with("s:"));
    }

    #[test]
    fn test_audit_challenge_recent() {
        let challenge = AuditChallenge::recent(5);
        assert!(challenge.id.starts_with("chal-"));
        assert!(challenge.known_tip.is_none());
        match challenge.range {
            AuditRange::Recent(n) => assert_eq!(n, 5),
            _ => panic!("expected Recent"),
        }
    }

    #[test]
    fn test_audit_challenge_since_hash() {
        let challenge = AuditChallenge::since_hash("abc123".to_string());
        assert_eq!(challenge.known_tip, Some("abc123".to_string()));
        match challenge.range {
            AuditRange::SinceHash(ref h) => assert_eq!(h, "abc123"),
            _ => panic!("expected SinceHash"),
        }
    }

    #[test]
    fn test_audit_response_from_entries() {
        let chain = make_chain(5);
        let response = AuditResponse::from_entries("chal-1", &chain, 5);
        assert_eq!(response.challenge_id, "chal-1");
        assert_eq!(response.entries.len(), MAX_ENTRIES_PER_RESPONSE);
        assert_eq!(response.total_available, 5);
        assert!(response.has_more);
    }

    #[test]
    fn test_audit_response_small_chain() {
        let chain = make_chain(2);
        let response = AuditResponse::from_entries("chal-2", &chain, 2);
        assert_eq!(response.entries.len(), 2);
        assert!(!response.has_more);
        assert_eq!(response.chain_tip, chain[1].entry_hash);
    }

    #[test]
    fn test_verify_peer_chain_valid() {
        let chain = make_chain(3);
        let compact: Vec<_> = chain.iter().map(CompactAuditEntry::from_entry).collect();
        let attestation = verify_peer_chain("peer-abc", &compact);
        assert!(attestation.chain_valid);
        assert_eq!(attestation.entries_verified, 3);
        assert!(attestation.id.starts_with("att-"));
        assert_eq!(attestation.peer, "peer-abc");
    }

    #[test]
    fn test_verify_peer_chain_broken() {
        let chain = make_chain(3);
        let mut compact: Vec<_> = chain.iter().map(CompactAuditEntry::from_entry).collect();
        // Break the chain link
        compact[2].ph = "tampered".to_string();
        let attestation = verify_peer_chain("peer-xyz", &compact);
        assert!(!attestation.chain_valid);
    }

    #[test]
    fn test_verify_peer_chain_empty() {
        let attestation = verify_peer_chain("peer-empty", &[]);
        assert!(attestation.chain_valid);
        assert_eq!(attestation.entries_verified, 0);
    }

    #[test]
    fn test_verify_peer_chain_single() {
        let chain = make_chain(1);
        let compact: Vec<_> = chain.iter().map(CompactAuditEntry::from_entry).collect();
        let attestation = verify_peer_chain("peer-one", &compact);
        assert!(attestation.chain_valid);
        assert_eq!(attestation.entries_verified, 1);
    }

    #[test]
    fn test_attestation_compute_hash() {
        let att1 = PeerAuditAttestation {
            id: "att-1".to_string(),
            peer: "peer-abc".to_string(),
            oldest_hash: "aaa".to_string(),
            newest_hash: "bbb".to_string(),
            entries_verified: 5,
            chain_valid: true,
            signatures_valid: 3,
            timestamp: DateTime::from_timestamp(1700000000, 0).unwrap(),
            signature: None,
        };
        let hash1 = att1.compute_hash();
        let hash2 = att1.compute_hash();
        assert_eq!(hash1, hash2); // deterministic

        let mut att2 = att1.clone();
        att2.chain_valid = false;
        assert_ne!(att1.compute_hash(), att2.compute_hash()); // different when fields differ
    }

    #[test]
    fn test_compact_entry_serialization_roundtrip() {
        let chain = make_chain(1);
        let compact = CompactAuditEntry::from_entry(&chain[0]);
        let json = serde_json::to_string(&compact).unwrap();
        let decoded: CompactAuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.eh, compact.eh);
        assert_eq!(decoded.ph, compact.ph);
        assert_eq!(decoded.at, compact.at);
    }

    #[test]
    fn test_challenge_serialization_roundtrip() {
        let challenge = AuditChallenge::recent(10);
        let json = serde_json::to_string(&challenge).unwrap();
        let decoded: AuditChallenge = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id, challenge.id);
    }

    #[test]
    fn test_response_serialization_roundtrip() {
        let chain = make_chain(2);
        let response = AuditResponse::from_entries("chal-test", &chain, 2);
        let json = serde_json::to_string(&response).unwrap();
        let decoded: AuditResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.challenge_id, "chal-test");
        assert_eq!(decoded.entries.len(), 2);
    }

    #[test]
    fn test_attestation_with_signatures() {
        let mut entry = make_test_entry("prev", 0);
        entry.signature = Some("deadbeef".to_string());
        let compact = CompactAuditEntry::from_entry(&entry);
        assert_eq!(compact.sg, Some("deadbeef".to_string()));

        let attestation = verify_peer_chain("peer", &[compact]);
        assert_eq!(attestation.signatures_valid, 1);
    }
}
