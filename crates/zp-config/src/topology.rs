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

/// Derive the node's role from chain state and config hint.
///
/// The config hint is used to disambiguate between a genesis node (which
/// created genesis.json) and a delegate node (which holds a copy of its
/// upstream's genesis.json for verification).
///
/// Priority:
///   1. If genesis.json exists AND config says "delegate" with an upstream
///      → Delegate (holding upstream's certificate for verification)
///   2. If genesis.json exists AND config says "genesis" or is absent
///      → Genesis (this node performed the ceremony)
///   3. No genesis.json → Standalone
///
/// A future pass will also check the audit chain for delegation receipts,
/// which would make the config hint unnecessary for delegates that have
/// completed the attestation ceremony.
pub fn derive_node_role(home: &Path) -> NodeRole {
    derive_node_role_with_hint(home, None, None)
}

/// Derive node role using the config hint to disambiguate delegate vs genesis.
///
/// When a delegate node holds a copy of its upstream's genesis.json, the
/// config hint (role = "delegate", upstream = "addr:port") tells us this
/// node is a delegate, not a second genesis.
pub fn derive_node_role_with_hint(
    home: &Path,
    config_role_hint: Option<&str>,
    config_upstream: Option<&str>,
) -> NodeRole {
    let genesis_path = home.join("genesis.json");

    if genesis_path.exists() {
        // Config says "delegate" with an upstream address → this node holds
        // its upstream's genesis certificate, not its own.
        if config_role_hint == Some("delegate") {
            let upstream_addr = config_upstream.unwrap_or("").to_string();
            // Extract the genesis pubkey from the certificate for binding verification
            let upstream_genesis_pubkey = extract_genesis_pubkey(&genesis_path)
                .unwrap_or_default();
            return NodeRole::Delegate {
                upstream_addr,
                upstream_genesis_pubkey,
            };
        }
        return NodeRole::Genesis;
    }

    // Config says delegate but no genesis.json yet — standalone until
    // the upstream's certificate is received.
    NodeRole::Standalone
}

/// Extract the genesis public key from a genesis.json certificate.
fn extract_genesis_pubkey(genesis_path: &Path) -> Option<String> {
    let data = std::fs::read_to_string(genesis_path).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&data).ok()?;
    parsed["genesis_pubkey"]
        .as_str()
        .or_else(|| parsed["public_key"].as_str())
        .or_else(|| parsed["pubkey"].as_str())
        .map(|s| s.to_string())
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
