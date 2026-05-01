//! Node role derivation from chain state.
//!
//! The node's role is derived from cryptographic evidence in the chain,
//! not from config.toml (which is treated as a "bootstrap hint").

use crate::schema::NodeRole;
use std::path::Path;

/// Information about a detected role transition.
#[derive(Debug, Clone)]
pub struct TransitionInfo {
    /// What the node was before (e.g., "Genesis", "Delegate(192.168.1.152:17770)", "Standalone")
    pub previous_role: String,
    /// What the node is now
    pub new_role: String,
    /// Why the transition happened (e.g., "delegation_accepted", "delegation_revoked", "redelegation")
    pub trigger: String,
}

/// Derive the node's role from chain state (genesis.json).
///
/// This is the basic version that checks only for genesis.json.
/// A more complete version that also checks the audit chain for delegation
/// receipts would live in zp-cli where both zp-config and zp-receipt are available.
///
/// Priority:
///   1. If genesis.json exists with valid transcript → Genesis
///   2. Otherwise → Standalone
///
/// Note: Delegation receipt checking will be added in a later step when the
/// receipt types are defined and a full delegation handshake is implemented.
pub fn derive_node_role(home: &Path) -> NodeRole {
    // Check for genesis ceremony evidence
    let genesis_path = home.join("genesis.json");
    if genesis_path.exists() {
        // TODO: Optionally verify the signed transcript here (T1 phase 2)
        return NodeRole::Genesis;
    }

    NodeRole::Standalone
}

/// Convert a config string hint to a NodeRole.
///
/// This is used for bootstrapping and for warning when config disagrees with
/// chain-derived role. The config hint is never authoritative after the chain
/// has recorded the node's actual role.
pub fn config_hint_role(role_str: &str) -> NodeRole {
    match role_str {
        "genesis" => NodeRole::Genesis,
        "delegate" => NodeRole::Delegate {
            // Placeholder values — the actual upstream binding comes from
            // the delegation receipt in the chain, not config.
            upstream_addr: String::new(),
            upstream_genesis_pubkey: String::new(),
        },
        _ => NodeRole::Standalone,
    }
}

/// Format a NodeRole as a display string for transition metadata.
fn role_to_string(role: &NodeRole) -> String {
    match role {
        NodeRole::Genesis => "Genesis".to_string(),
        NodeRole::Delegate {
            upstream_addr,
            upstream_genesis_pubkey: _,
        } => format!("Delegate({})", upstream_addr),
        NodeRole::Standalone => "Standalone".to_string(),
    }
}

/// Detect whether a role transition has occurred by comparing the current
/// derived role against the previously recorded role.
///
/// Returns `Some(TransitionInfo)` if the roles differ (including upstream
/// changes for Delegate→Delegate re-delegation).
///
/// Returns `None` if roles are identical (same variant AND same field values for Delegate).
pub fn detect_role_transition(current: &NodeRole, previous: &NodeRole) -> Option<TransitionInfo> {
    // Check if roles are identical
    if current == previous {
        return None;
    }

    // Determine trigger based on role transition pattern
    let trigger = match (previous, current) {
        // Genesis → Delegate: delegation was accepted
        (NodeRole::Genesis, NodeRole::Delegate { .. }) => "delegation_accepted",
        // Genesis → Standalone: should not happen in normal operation
        (NodeRole::Genesis, NodeRole::Standalone) => "genesis_reverted",
        // Delegate → Genesis: should not happen in normal operation
        (NodeRole::Delegate { .. }, NodeRole::Genesis) => "delegate_to_genesis",
        // Delegate → Delegate with different upstream: re-delegation
        (
            NodeRole::Delegate {
                upstream_addr: prev_addr,
                upstream_genesis_pubkey: _,
            },
            NodeRole::Delegate {
                upstream_addr: curr_addr,
                upstream_genesis_pubkey: _,
            },
        ) if prev_addr != curr_addr => "redelegation",
        // Delegate → Standalone: delegation was revoked
        (NodeRole::Delegate { .. }, NodeRole::Standalone) => "delegation_revoked",
        // Standalone → Genesis: genesis was performed
        (NodeRole::Standalone, NodeRole::Genesis) => "genesis_performed",
        // Standalone → Delegate: first delegation accepted (or bootstrapped state)
        (NodeRole::Standalone, NodeRole::Delegate { .. }) => "delegation_accepted",
        // Catch-all for any other transition
        _ => "operator_initiated",
    };

    Some(TransitionInfo {
        previous_role: role_to_string(previous),
        new_role: role_to_string(current),
        trigger: trigger.to_string(),
    })
}
