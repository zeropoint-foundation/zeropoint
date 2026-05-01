//! Node role derivation from chain state.
//!
//! The node's role is derived from cryptographic evidence in the chain,
//! not from config.toml (which is treated as a "bootstrap hint").

use crate::schema::NodeRole;
use std::path::Path;

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
