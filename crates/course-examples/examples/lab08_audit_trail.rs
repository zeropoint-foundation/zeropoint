//! Lab 8: The Audit Trail
//!
//! Persisted audit trail with chain verification.
//!
//! Updated for the post-AUDIT-03 store API: callers construct
//! `UnsealedEntry` and let the store seal each entry atomically inside
//! a `BEGIN IMMEDIATE` transaction. Callers no longer compute `prev_hash`.
//!
//! Run: cargo run --example lab08_audit_trail -p course-examples

use zp_audit::{AuditStore, ChainVerifier, UnsealedEntry};
use zp_core::audit::{ActorId, AuditAction};
use zp_core::policy::PolicyDecision;
use zp_core::types::ConversationId;

fn main() {
    let mut store = AuditStore::open("./lab-audit.db").expect("Should open audit store");
    let conv_id = ConversationId::new();

    // Genesis entry (first in chain)
    let entry1 = store
        .append(UnsealedEntry::new(
            ActorId::User("alice".into()),
            AuditAction::MessageReceived {
                content_hash: "abc123".into(),
            },
            conv_id.clone(),
            PolicyDecision::Allow { conditions: vec![] },
            "default-allow",
        ))
        .expect("Should append");
    println!("Entry 1: {:?} (genesis)", entry1.id);

    // Second entry — store handles linkage automatically
    let entry2 = store
        .append(UnsealedEntry::new(
            ActorId::Operator,
            AuditAction::ResponseGenerated {
                model: "claude-3".into(),
                content_hash: "def456".into(),
            },
            conv_id.clone(),
            PolicyDecision::Allow { conditions: vec![] },
            "default-allow",
        ))
        .expect("Should append");
    println!(
        "Entry 2: {:?} (prev={}...)",
        entry2.id,
        &entry2.prev_hash[..8]
    );

    // Third entry
    store
        .append(UnsealedEntry::new(
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
            "catastrophic-action-rule",
        ))
        .expect("Should append");

    // Retrieve and verify
    let entries = store.get_entries(&conv_id, 100).expect("Should retrieve");
    println!("\nRetrieved {} entries", entries.len());

    let verifier = ChainVerifier::new();
    let report = verifier.verify(&entries, None);
    println!("Chain valid: {}", report.chain_valid);
    println!("✓ Audit chain verified");
}
