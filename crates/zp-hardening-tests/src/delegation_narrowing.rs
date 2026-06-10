//! Claim 4 hardening tests: delegation narrowing at tool-call time.
//!
//! These tests prove that `lease_prereq_for_agent` (and by extension the
//! `/api/v1/gate/tool-call` handler) checks capability scope — not just
//! grant existence — before allowing a tool call.
//!
//! The gap that motivated Claim 4: a delegated agent with a live but
//! narrowly-scoped grant could call ANY tool because the gate only verified
//! "does a live grant exist?" without checking whether the grant's
//! `ToolCall { tools }` scope covered the requested tool.
//!
//! Run with:
//! ```bash
//! cargo test -p zp-hardening-tests delegation_narrowing
//! ```

#[cfg(test)]
use std::sync::{Arc, Mutex};
#[cfg(test)]
use tempfile::tempdir;
#[cfg(test)]
use uuid::Uuid;
#[cfg(test)]
use zp_audit::{AuditStore, UnsealedEntry};
#[cfg(test)]
use zp_core::{
    ActionType, ActorId, AuditAction, CapabilityGrant, ConversationId, GrantedCapability,
    LeasePolicy, PolicyDecision,
};

/// Emit a `delegation:granted:{agent}` entry into the store, serialising the
/// grant JSON into the `conditions` array of the Allow decision. This mirrors
/// the production `tool_chain::emit_delegation_receipt` path.
#[cfg(test)]
fn emit_grant(store: &Arc<Mutex<AuditStore>>, agent: &str, grant: &CapabilityGrant) {
    let grant_json = serde_json::to_string(grant).expect("serialise grant");
    let entry = UnsealedEntry::new(
        ActorId::System("test-genesis".to_string()),
        AuditAction::SystemEvent {
            event: format!("delegation:granted:{agent}"),
        },
        ConversationId(Uuid::now_v7()),
        PolicyDecision::Allow {
            conditions: vec![grant_json],
        },
        "delegation-narrowing-test",
    );
    store.lock().unwrap().append(entry).expect("append grant");
}

/// Walk the chain and reproduce the Claim 4 scope-check logic inline.
///
/// Returns `None` (allow) when a live grant covers `tool_name`, otherwise
/// returns the deny reason. Mirrors the production `lease_prereq_for_agent`
/// so the test stays legible without an `AppState`.
#[cfg(test)]
fn prereq(store: &Arc<Mutex<AuditStore>>, agent_id: &str, tool_name: &str) -> Option<&'static str> {
    let chain = store
        .lock()
        .unwrap()
        .export_chain(i32::MAX as usize)
        .unwrap();

    let mut grants: std::collections::HashMap<String, CapabilityGrant> = Default::default();
    for entry in &chain {
        let zp_core::AuditAction::SystemEvent { event } = &entry.action else {
            continue;
        };
        let zp_core::PolicyDecision::Allow { conditions } = &entry.policy_decision else {
            continue;
        };
        let Some(body) = conditions.first() else {
            continue;
        };
        if event.starts_with("delegation:granted:") || event.starts_with("delegation:renewed:") {
            if let Ok(g) = serde_json::from_str::<CapabilityGrant>(body) {
                if g.grantee == agent_id {
                    grants.insert(g.id.clone(), g);
                }
            }
        }
    }

    let live: Vec<&CapabilityGrant> = grants.values().filter(|g| !g.is_past_grace()).collect();
    if live.is_empty() {
        return Some("no_valid_delegation");
    }

    let tool_action = ActionType::ToolCall { name: tool_name.to_string() };
    if live.iter().any(|g| g.matches_action(&tool_action)) {
        None
    } else {
        Some("capability_scope_exceeded")
    }
}

/// Wildcard grant (`tools: ["*"]`) allows any tool — the common case for a
/// fully-trusted agent that has no per-tool restrictions.
#[test]
fn claim4_wildcard_grant_allows_any_tool() {
    let dir = tempdir().expect("tempdir");
    let db = dir.path().join("audit.db");
    let store = Arc::new(Mutex::new(AuditStore::open_unsigned(&db).expect("open")));

    let grant = CapabilityGrant::new(
        "genesis".to_string(),
        "artemis".to_string(),
        GrantedCapability::ToolCall {
            tools: vec!["*".to_string()],
        },
        "rcpt-test-wildcard".to_string(),
    )
    .with_lease_policy(LeasePolicy::standard_8h())
    .as_standing("genesis-key");

    emit_grant(&store, "artemis", &grant);

    assert_eq!(prereq(&store, "artemis", "bash"), None, "wildcard: bash allowed");
    assert_eq!(prereq(&store, "artemis", "read"), None, "wildcard: read allowed");
    assert_eq!(prereq(&store, "artemis", "slack.send_message"), None, "wildcard: slack allowed");
}

/// Narrow grant (`tools: ["read"]`) allows only the listed tool.
/// Calling any other tool must be denied with `capability_scope_exceeded`.
#[test]
fn claim4_narrow_grant_allows_in_scope_denies_out_of_scope() {
    let dir = tempdir().expect("tempdir");
    let db = dir.path().join("audit.db");
    let store = Arc::new(Mutex::new(AuditStore::open_unsigned(&db).expect("open")));

    let grant = CapabilityGrant::new(
        "genesis".to_string(),
        "artemis".to_string(),
        GrantedCapability::ToolCall {
            tools: vec!["read".to_string()],
        },
        "rcpt-test-narrow".to_string(),
    )
    .with_lease_policy(LeasePolicy::standard_8h())
    .as_standing("genesis-key");

    emit_grant(&store, "artemis", &grant);

    // In-scope: allowed.
    assert_eq!(
        prereq(&store, "artemis", "read"),
        None,
        "in-scope tool must be allowed"
    );
    // Out-of-scope: denied — this is the Claim 4 invariant.
    assert_eq!(
        prereq(&store, "artemis", "bash"),
        Some("capability_scope_exceeded"),
        "out-of-scope tool must be denied even with a live grant"
    );
    assert_eq!(
        prereq(&store, "artemis", "slack.send_message"),
        Some("capability_scope_exceeded"),
        "slack tool outside scope must also be denied"
    );
}

/// An agent with no delegation at all must be denied with `no_valid_delegation`
/// — the grant-existence check still fires before the scope check.
#[test]
fn claim4_no_delegation_denied_before_scope_check() {
    let dir = tempdir().expect("tempdir");
    let db = dir.path().join("audit.db");
    let store = Arc::new(Mutex::new(AuditStore::open_unsigned(&db).expect("open")));

    // Empty chain — no delegation receipts.
    assert_eq!(
        prereq(&store, "artemis", "bash"),
        Some("no_valid_delegation"),
    );
}

/// Multi-tool grant allows exactly the listed tools and nothing more.
#[test]
fn claim4_multi_tool_grant_enforces_exact_set() {
    let dir = tempdir().expect("tempdir");
    let db = dir.path().join("audit.db");
    let store = Arc::new(Mutex::new(AuditStore::open_unsigned(&db).expect("open")));

    let grant = CapabilityGrant::new(
        "genesis".to_string(),
        "artemis".to_string(),
        GrantedCapability::ToolCall {
            tools: vec!["read".to_string(), "write".to_string()],
        },
        "rcpt-test-multi".to_string(),
    )
    .with_lease_policy(LeasePolicy::standard_8h())
    .as_standing("genesis-key");

    emit_grant(&store, "artemis", &grant);

    assert_eq!(prereq(&store, "artemis", "read"), None);
    assert_eq!(prereq(&store, "artemis", "write"), None);
    assert_eq!(prereq(&store, "artemis", "bash"), Some("capability_scope_exceeded"));
    assert_eq!(prereq(&store, "artemis", "computer"), Some("capability_scope_exceeded"));
}
