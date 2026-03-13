//! Lab 8: The Audit Trail
//!
//! Persisted audit trail with chain verification
//! Run: cargo run --example lab08_audit_trail -p course-examples

use zp_audit::{AuditStore, ChainBuilder, ChainVerifier};
use zp_core::audit::{ActorId, AuditAction};
use zp_core::policy::PolicyDecision;
use zp_core::types::ConversationId;

fn main() {
    let store = AuditStore::open("./lab-audit.db")
        .expect("Should open audit store");
    let conv_id = ConversationId::new();

    // Build genesis entry (first in chain)
    let entry1 = ChainBuilder::build_entry_from_genesis(
        ActorId::User("alice".into()),
        AuditAction::MessageReceived {
            content_hash: "abc123".into(),
        },
        conv_id.clone(),
        PolicyDecision::Allow { conditions: vec![] },
        "default-allow".into(),
        None, None,
    );
    println!("Entry 1: {:?} (genesis)", entry1.id);
    store.append(entry1.clone()).expect("Should append");

    // Build second entry (chained to first)
    let entry2 = ChainBuilder::build_entry(
        &entry1.entry_hash,
        ActorId::Operator,
        AuditAction::ResponseGenerated {
            model: "claude-3".into(),
            content_hash: "def456".into(),
        },
        conv_id.clone(),
        PolicyDecision::Allow { conditions: vec![] },
        "default-allow".into(),
        None, None,
    );
    println!("Entry 2: {:?} (prev={}...)", entry2.id, &entry2.prev_hash[..8]);
    store.append(entry2.clone()).expect("Should append");

    // Build third entry
    let entry3 = ChainBuilder::build_entry(
        &entry2.entry_hash,
        ActorId::Skill("code-executor".into()),
        AuditAction::ToolInvoked {
            tool_name: "python".into(),
            arguments_hash: "ghi789".into(),
        },
        conv_id.clone(),
        PolicyDecision::Warn {
            message: "High-risk execution".into(),
            require_ack: true,
        },
        "catastrophic-action-rule".into(),
        None, None,
    );
    store.append(entry3).expect("Should append");

    // Retrieve and verify
    let entries = store.get_entries(&conv_id, 100)
        .expect("Should retrieve");
    println!("\nRetrieved {} entries", entries.len());

    let verifier = ChainVerifier::new();
    let report = verifier.verify(&entries, None);
    println!("Chain valid: {}", report.chain_valid);
    println!("✓ Audit chain verified");
}
