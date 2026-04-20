//! Blast radius model — scoping the impact of key compromise.
//!
//! Phase 3 (R6-1): When a key is compromised, the system must know exactly
//! which trust relationships, capability grants, and memories are affected.
//!
//! The blast radius model operates on in-memory indices that track:
//! - Which receipts were signed by which key
//! - Which delegation chains include which keys
//! - Which capability grants were authorized through which delegations
//! - Which memories were promoted using which receipts as evidence
//!
//! ## Usage
//!
//! ```rust,ignore
//! let mut tracker = BlastRadiusTracker::new();
//!
//! // Register relationships as they occur
//! tracker.register_signed_receipt("key-abc", "rcpt-1");
//! tracker.register_delegation("parent-key", "child-key", "deleg-1");
//! tracker.register_grant("deleg-1", "grant-1");
//! tracker.register_memory_evidence("rcpt-1", "mem-1");
//!
//! // When compromise detected, compute the blast radius
//! let radius = tracker.compute("key-abc");
//! ```

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tracing::{info, warn};

// ============================================================================
// Blast radius result
// ============================================================================

/// The computed blast radius of a compromised key.
///
/// Contains every entity whose trust chain passes through the compromised key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastRadius {
    /// The compromised public key (hex-encoded).
    pub compromised_key: String,

    /// Receipt IDs signed directly by the compromised key.
    pub signed_receipts: Vec<String>,

    /// Keys that were delegated from the compromised key
    /// (includes transitive delegations).
    pub affected_delegations: Vec<DelegationEdge>,

    /// All keys in the compromise cone: the compromised key plus
    /// all transitively delegated keys.
    pub affected_keys: Vec<String>,

    /// Capability grant IDs authorized through affected delegation chains.
    pub affected_grants: Vec<String>,

    /// Memory IDs promoted using affected receipts as evidence.
    pub affected_memories: Vec<String>,
}

impl BlastRadius {
    /// Total number of entities affected by this compromise.
    pub fn total_affected(&self) -> usize {
        self.signed_receipts.len()
            + self.affected_delegations.len()
            + self.affected_grants.len()
            + self.affected_memories.len()
    }

    /// Whether this compromise has any impact at all.
    pub fn is_empty(&self) -> bool {
        self.signed_receipts.is_empty()
            && self.affected_delegations.is_empty()
            && self.affected_grants.is_empty()
            && self.affected_memories.is_empty()
    }
}

/// A delegation edge in the trust graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationEdge {
    /// The parent key that delegated.
    pub parent_key: String,
    /// The child key that received delegation.
    pub child_key: String,
    /// The delegation record ID.
    pub delegation_id: String,
}

// ============================================================================
// Response actions
// ============================================================================

/// Recommended response actions for each category of blast radius impact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompromiseResponse {
    /// Receipt IDs that should be revoked (emit RevocationClaim for each).
    pub receipts_to_revoke: Vec<String>,
    /// Delegation IDs to revoke and re-issue from clean parent.
    pub delegations_to_revoke: Vec<String>,
    /// Grant IDs to revoke and re-grant through clean chain.
    pub grants_to_revoke: Vec<String>,
    /// Memory IDs to quarantine pending re-evaluation.
    pub memories_to_quarantine: Vec<String>,
    /// Keys to rotate (the compromised key + all transitive delegations).
    pub keys_to_rotate: Vec<String>,
}

impl BlastRadius {
    /// Generate the recommended response actions from this blast radius.
    pub fn response_actions(&self) -> CompromiseResponse {
        CompromiseResponse {
            receipts_to_revoke: self.signed_receipts.clone(),
            delegations_to_revoke: self
                .affected_delegations
                .iter()
                .map(|d| d.delegation_id.clone())
                .collect(),
            grants_to_revoke: self.affected_grants.clone(),
            memories_to_quarantine: self.affected_memories.clone(),
            keys_to_rotate: self.affected_keys.clone(),
        }
    }
}

// ============================================================================
// Blast radius tracker
// ============================================================================

/// In-memory tracker that maintains the relationship indices needed
/// to compute blast radius on key compromise.
///
/// In production, these indices would be maintained by the receipt chain
/// and delegation store. This tracker provides the computation model.
#[derive(Debug, Default)]
pub struct BlastRadiusTracker {
    /// Index: signer public key (hex) → receipt IDs signed by that key.
    key_to_receipts: HashMap<String, Vec<String>>,

    /// Index: parent key → child keys delegated to.
    delegation_graph: HashMap<String, Vec<(String, String)>>, // (child_key, delegation_id)

    /// Index: delegation ID → grant IDs authorized through it.
    delegation_to_grants: HashMap<String, Vec<String>>,

    /// Index: receipt ID → memory IDs that use this receipt as evidence.
    receipt_to_memories: HashMap<String, Vec<String>>,
}

impl BlastRadiusTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register that a receipt was signed by a specific key.
    pub fn register_signed_receipt(&mut self, signer_key: &str, receipt_id: &str) {
        self.key_to_receipts
            .entry(signer_key.to_string())
            .or_default()
            .push(receipt_id.to_string());
    }

    /// Register a delegation from parent key to child key.
    pub fn register_delegation(
        &mut self,
        parent_key: &str,
        child_key: &str,
        delegation_id: &str,
    ) {
        self.delegation_graph
            .entry(parent_key.to_string())
            .or_default()
            .push((child_key.to_string(), delegation_id.to_string()));
    }

    /// Register that a capability grant was authorized through a delegation.
    pub fn register_grant(&mut self, delegation_id: &str, grant_id: &str) {
        self.delegation_to_grants
            .entry(delegation_id.to_string())
            .or_default()
            .push(grant_id.to_string());
    }

    /// Register that a memory was promoted using a receipt as evidence.
    pub fn register_memory_evidence(&mut self, receipt_id: &str, memory_id: &str) {
        self.receipt_to_memories
            .entry(receipt_id.to_string())
            .or_default()
            .push(memory_id.to_string());
    }

    /// Compute the blast radius for a compromised key.
    ///
    /// Walks the delegation graph transitively to find all affected keys,
    /// then collects all receipts, grants, and memories that depend on
    /// any key in the compromise cone.
    pub fn compute(&self, compromised_key: &str) -> BlastRadius {
        // Step 1: Find all keys in the compromise cone (transitive delegations).
        let mut affected_keys = HashSet::new();
        let mut affected_delegations = Vec::new();
        affected_keys.insert(compromised_key.to_string());

        self.walk_delegations(compromised_key, &mut affected_keys, &mut affected_delegations);

        // Step 2: Collect all receipts signed by any affected key.
        let mut signed_receipts = Vec::new();
        let mut receipt_set = HashSet::new();
        for key in &affected_keys {
            if let Some(receipts) = self.key_to_receipts.get(key) {
                for r in receipts {
                    if receipt_set.insert(r.clone()) {
                        signed_receipts.push(r.clone());
                    }
                }
            }
        }

        // Step 3: Collect all grants authorized through affected delegations.
        let mut affected_grants = Vec::new();
        let mut grant_set = HashSet::new();
        for deleg in &affected_delegations {
            if let Some(grants) = self.delegation_to_grants.get(&deleg.delegation_id) {
                for g in grants {
                    if grant_set.insert(g.clone()) {
                        affected_grants.push(g.clone());
                    }
                }
            }
        }

        // Step 4: Collect all memories whose evidence includes affected receipts.
        let mut affected_memories = Vec::new();
        let mut memory_set = HashSet::new();
        for receipt_id in &signed_receipts {
            if let Some(memories) = self.receipt_to_memories.get(receipt_id) {
                for m in memories {
                    if memory_set.insert(m.clone()) {
                        affected_memories.push(m.clone());
                    }
                }
            }
        }

        let affected_keys_vec: Vec<String> = affected_keys.into_iter().collect();

        info!(
            compromised_key = %compromised_key,
            affected_keys = affected_keys_vec.len(),
            signed_receipts = signed_receipts.len(),
            affected_delegations = affected_delegations.len(),
            affected_grants = affected_grants.len(),
            affected_memories = affected_memories.len(),
            "Blast radius computed"
        );

        BlastRadius {
            compromised_key: compromised_key.to_string(),
            signed_receipts,
            affected_delegations,
            affected_keys: affected_keys_vec,
            affected_grants,
            affected_memories,
        }
    }

    /// Recursively walk the delegation graph to find all transitive
    /// delegations from a compromised key.
    fn walk_delegations(
        &self,
        key: &str,
        visited: &mut HashSet<String>,
        delegations: &mut Vec<DelegationEdge>,
    ) {
        if let Some(children) = self.delegation_graph.get(key) {
            for (child_key, delegation_id) in children {
                delegations.push(DelegationEdge {
                    parent_key: key.to_string(),
                    child_key: child_key.clone(),
                    delegation_id: delegation_id.clone(),
                });

                // Only recurse if we haven't visited this child yet
                // (prevents cycles in the delegation graph).
                if visited.insert(child_key.clone()) {
                    self.walk_delegations(child_key, visited, delegations);
                } else {
                    warn!(
                        parent = %key,
                        child = %child_key,
                        "Cycle detected in delegation graph — skipping"
                    );
                }
            }
        }
    }

    /// Get all receipt IDs signed by a specific key (direct, non-transitive).
    pub fn receipts_by_key(&self, key: &str) -> Vec<String> {
        self.key_to_receipts
            .get(key)
            .cloned()
            .unwrap_or_default()
    }

    /// Get all direct delegations from a key.
    pub fn delegations_from(&self, key: &str) -> Vec<(&str, &str)> {
        self.delegation_graph
            .get(key)
            .map(|children| {
                children
                    .iter()
                    .map(|(k, d)| (k.as_str(), d.as_str()))
                    .collect()
            })
            .unwrap_or_default()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_blast_radius_for_unknown_key() {
        let tracker = BlastRadiusTracker::new();
        let radius = tracker.compute("unknown-key");

        assert!(radius.is_empty());
        assert_eq!(radius.total_affected(), 0);
        assert_eq!(radius.affected_keys.len(), 1); // Just the compromised key itself
    }

    #[test]
    fn direct_receipt_impact() {
        let mut tracker = BlastRadiusTracker::new();

        tracker.register_signed_receipt("key-A", "rcpt-1");
        tracker.register_signed_receipt("key-A", "rcpt-2");
        tracker.register_signed_receipt("key-B", "rcpt-3"); // Different key

        let radius = tracker.compute("key-A");

        assert_eq!(radius.signed_receipts.len(), 2);
        assert!(radius.signed_receipts.contains(&"rcpt-1".to_string()));
        assert!(radius.signed_receipts.contains(&"rcpt-2".to_string()));
        assert!(!radius.signed_receipts.contains(&"rcpt-3".to_string()));
    }

    #[test]
    fn transitive_delegation_impact() {
        let mut tracker = BlastRadiusTracker::new();

        // Genesis → Operator → Agent chain
        tracker.register_delegation("genesis", "operator", "deleg-1");
        tracker.register_delegation("operator", "agent-1", "deleg-2");
        tracker.register_delegation("operator", "agent-2", "deleg-3");

        // Receipts signed by each level
        tracker.register_signed_receipt("genesis", "rcpt-genesis");
        tracker.register_signed_receipt("operator", "rcpt-op");
        tracker.register_signed_receipt("agent-1", "rcpt-a1");
        tracker.register_signed_receipt("agent-2", "rcpt-a2");

        // Compromise the operator — should affect operator + both agents
        let radius = tracker.compute("operator");

        assert_eq!(radius.affected_keys.len(), 3); // operator + agent-1 + agent-2
        assert_eq!(radius.affected_delegations.len(), 2); // deleg-2, deleg-3
        assert_eq!(radius.signed_receipts.len(), 3); // rcpt-op + rcpt-a1 + rcpt-a2

        // Genesis receipts NOT affected
        assert!(!radius.signed_receipts.contains(&"rcpt-genesis".to_string()));
    }

    #[test]
    fn genesis_compromise_cascades_fully() {
        let mut tracker = BlastRadiusTracker::new();

        tracker.register_delegation("genesis", "op-1", "d1");
        tracker.register_delegation("genesis", "op-2", "d2");
        tracker.register_delegation("op-1", "agent-1a", "d3");
        tracker.register_delegation("op-2", "agent-2a", "d4");

        tracker.register_signed_receipt("agent-1a", "r1");
        tracker.register_signed_receipt("agent-2a", "r2");

        let radius = tracker.compute("genesis");

        // All keys affected: genesis + op-1 + op-2 + agent-1a + agent-2a
        assert_eq!(radius.affected_keys.len(), 5);
        assert_eq!(radius.signed_receipts.len(), 2);
        assert_eq!(radius.affected_delegations.len(), 4);
    }

    #[test]
    fn grants_through_delegations() {
        let mut tracker = BlastRadiusTracker::new();

        tracker.register_delegation("operator", "agent-1", "deleg-1");
        tracker.register_grant("deleg-1", "grant-A");
        tracker.register_grant("deleg-1", "grant-B");

        // Unrelated grant through unrelated delegation
        tracker.register_delegation("other-operator", "other-agent", "deleg-other");
        tracker.register_grant("deleg-other", "grant-C");

        let radius = tracker.compute("operator");

        assert_eq!(radius.affected_grants.len(), 2);
        assert!(radius.affected_grants.contains(&"grant-A".to_string()));
        assert!(radius.affected_grants.contains(&"grant-B".to_string()));
        assert!(!radius.affected_grants.contains(&"grant-C".to_string()));
    }

    #[test]
    fn memory_evidence_impact() {
        let mut tracker = BlastRadiusTracker::new();

        tracker.register_signed_receipt("agent-key", "rcpt-1");
        tracker.register_signed_receipt("agent-key", "rcpt-2");

        tracker.register_memory_evidence("rcpt-1", "mem-A");
        tracker.register_memory_evidence("rcpt-1", "mem-B");
        tracker.register_memory_evidence("rcpt-2", "mem-C");
        tracker.register_memory_evidence("rcpt-other", "mem-D"); // Unrelated

        let radius = tracker.compute("agent-key");

        assert_eq!(radius.affected_memories.len(), 3);
        assert!(radius.affected_memories.contains(&"mem-A".to_string()));
        assert!(radius.affected_memories.contains(&"mem-B".to_string()));
        assert!(radius.affected_memories.contains(&"mem-C".to_string()));
        assert!(!radius.affected_memories.contains(&"mem-D".to_string()));
    }

    #[test]
    fn response_actions_from_blast_radius() {
        let mut tracker = BlastRadiusTracker::new();

        tracker.register_delegation("operator", "agent", "deleg-1");
        tracker.register_signed_receipt("agent", "rcpt-1");
        tracker.register_grant("deleg-1", "grant-1");
        tracker.register_memory_evidence("rcpt-1", "mem-1");

        let radius = tracker.compute("operator");
        let response = radius.response_actions();

        assert_eq!(response.receipts_to_revoke.len(), 1);
        assert_eq!(response.delegations_to_revoke.len(), 1);
        assert_eq!(response.grants_to_revoke.len(), 1);
        assert_eq!(response.memories_to_quarantine.len(), 1);
        assert!(response.keys_to_rotate.len() >= 2); // operator + agent
    }

    #[test]
    fn no_duplicate_receipts_across_keys() {
        let mut tracker = BlastRadiusTracker::new();

        // Same receipt registered under two keys in the same chain
        tracker.register_delegation("parent", "child", "d1");
        tracker.register_signed_receipt("parent", "shared-rcpt");
        tracker.register_signed_receipt("child", "shared-rcpt");

        let radius = tracker.compute("parent");

        // shared-rcpt should appear only once
        let count = radius
            .signed_receipts
            .iter()
            .filter(|r| *r == "shared-rcpt")
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn cycle_in_delegation_graph_handled() {
        let mut tracker = BlastRadiusTracker::new();

        // Create a cycle: A → B → C → A
        tracker.register_delegation("A", "B", "d1");
        tracker.register_delegation("B", "C", "d2");
        tracker.register_delegation("C", "A", "d3"); // cycle

        tracker.register_signed_receipt("A", "r1");
        tracker.register_signed_receipt("B", "r2");
        tracker.register_signed_receipt("C", "r3");

        // Should not infinite loop — cycle detection prevents it
        let radius = tracker.compute("A");

        assert_eq!(radius.affected_keys.len(), 3); // A, B, C
        assert_eq!(radius.signed_receipts.len(), 3);
    }

    #[test]
    fn leaf_key_compromise_is_contained() {
        let mut tracker = BlastRadiusTracker::new();

        tracker.register_delegation("genesis", "operator", "d1");
        tracker.register_delegation("operator", "agent-leaf", "d2");

        tracker.register_signed_receipt("genesis", "r1");
        tracker.register_signed_receipt("operator", "r2");
        tracker.register_signed_receipt("agent-leaf", "r3");

        // Compromising a leaf should only affect that leaf
        let radius = tracker.compute("agent-leaf");

        assert_eq!(radius.affected_keys.len(), 1); // Just agent-leaf
        assert_eq!(radius.signed_receipts.len(), 1); // Just r3
        assert!(radius.affected_delegations.is_empty());
    }
}
