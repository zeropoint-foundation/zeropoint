use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use zp_core::{ActorId, AuditAction, AuditEntry, AuditId, ConversationId, PolicyDecision, Receipt};

/// ChainBuilder constructs audit entries with deterministic hash chains.
pub struct ChainBuilder;

impl ChainBuilder {
    /// Builds an audit entry with a computed hash based on all fields.
    /// The entry_hash is computed deterministically from a JSON serialization
    /// of all entry fields in a stable order.
    #[allow(clippy::too_many_arguments)]
    pub fn build_entry(
        prev_hash: &str,
        actor: ActorId,
        action: AuditAction,
        conversation_id: ConversationId,
        policy_decision: PolicyDecision,
        policy_module: String,
        receipt: Option<Receipt>,
        signature: Option<String>,
    ) -> AuditEntry {
        let id = AuditId(Uuid::now_v7());
        let timestamp = Utc::now();

        // Build a deterministic JSON representation of the entry (without the hash fields themselves)
        // This ensures the hash computation is reproducible.
        let entry_data = json!({
            "id": format!("{:?}", id.0),
            "timestamp": timestamp.to_rfc3339(),
            "prev_hash": prev_hash,
            "actor": format!("{:?}", actor),
            "action": serde_json::to_value(&action).unwrap_or(json!(null)),
            "conversation_id": format!("{:?}", conversation_id.0),
            "policy_decision": serde_json::to_value(&policy_decision).unwrap_or(json!(null)),
            "policy_module": policy_module,
            "receipt": receipt.as_ref().map(|r| serde_json::to_value(r).unwrap_or(json!(null))),
            "signature": signature,
        });

        // Serialize to JSON bytes and hash with blake3
        let entry_bytes = serde_json::to_vec(&entry_data).unwrap_or_default();
        let entry_hash = blake3::hash(&entry_bytes).to_hex().to_string();

        AuditEntry {
            id,
            timestamp,
            prev_hash: prev_hash.to_string(),
            entry_hash,
            actor,
            action,
            conversation_id,
            policy_decision,
            policy_module,
            receipt,
            signature,
        }
    }

    /// Convenience method: builds an entry starting from the genesis hash.
    pub fn build_entry_from_genesis(
        actor: ActorId,
        action: AuditAction,
        conversation_id: ConversationId,
        policy_decision: PolicyDecision,
        policy_module: String,
        receipt: Option<Receipt>,
        signature: Option<String>,
    ) -> AuditEntry {
        let genesis = blake3::hash(b"").to_hex().to_string();
        Self::build_entry(
            &genesis,
            actor,
            action,
            conversation_id,
            policy_decision,
            policy_module,
            receipt,
            signature,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_linkage() {
        let actor = ActorId::System("test-actor".to_string());
        let action = AuditAction::SystemEvent {
            event: "test".to_string(),
        };
        let conversation_id = ConversationId(Uuid::now_v7());
        let policy_decision = PolicyDecision::Allow { conditions: vec![] };

        let entry1 = ChainBuilder::build_entry_from_genesis(
            actor.clone(),
            action.clone(),
            conversation_id.clone(),
            policy_decision.clone(),
            "module1".to_string(),
            None,
            None,
        );

        let entry2 = ChainBuilder::build_entry(
            &entry1.entry_hash,
            actor.clone(),
            action.clone(),
            conversation_id.clone(),
            policy_decision.clone(),
            "module2".to_string(),
            None,
            None,
        );

        let entry3 = ChainBuilder::build_entry(
            &entry2.entry_hash,
            actor,
            action,
            conversation_id,
            policy_decision,
            "module3".to_string(),
            None,
            None,
        );

        // Verify the chain is properly linked
        assert_eq!(entry2.prev_hash, entry1.entry_hash);
        assert_eq!(entry3.prev_hash, entry2.entry_hash);
    }
}
