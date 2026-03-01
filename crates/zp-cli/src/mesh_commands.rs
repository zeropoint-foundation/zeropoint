//! CLI handlers for mesh networking subcommands.
//!
//! Implements: `zp mesh status`, `zp mesh peers`, `zp mesh challenge`,
//! `zp mesh grant`, and `zp mesh save`.

use anyhow::{bail, Result};
use zp_mesh::transport::AgentTransport;
use zp_pipeline::Pipeline;

/// `zp mesh status` — print local identity, interface count, runtime stats,
/// and persistent store status.
pub async fn status(pipeline: &Pipeline) -> Result<()> {
    let bridge = match pipeline.mesh_bridge() {
        Some(b) => b,
        None => bail!("Mesh is not initialized. Use --mesh to enable."),
    };

    let node = bridge.node();
    let identity = node.identity();

    println!();
    println!("Mesh Node Status");
    println!("{}", "=".repeat(60));
    println!("Address:         {}", identity.address());
    println!(
        "Public Key:      {}",
        hex::encode(identity.signing_public_key())
    );
    println!(
        "Interfaces:      {}",
        node.interfaces_snapshot().await.len()
    );

    // Peer count
    let peers = node.known_peers().await;
    println!("Known Peers:     {}", peers.len());

    let linked = peers.iter().filter(|p| p.has_link).count();
    println!("Active Links:    {}", linked);

    // Runtime stats
    if let Some(rt) = pipeline.mesh_runtime() {
        let stats = rt.stats().await;
        println!();
        println!("Runtime");
        println!("{}", "-".repeat(40));
        println!("Running:              {}", rt.is_running());
        println!("Packets received:     {}", stats.packets_received);
        println!("Envelopes dispatched: {}", stats.envelopes_dispatched);
        println!("Deserialize errors:   {}", stats.deserialize_errors);
        println!("Announces seen:       {}", stats.announces_seen);
        println!("Packets skipped:      {}", stats.packets_skipped);
    } else {
        println!("Runtime:         not started");
    }

    // Store status
    if pipeline.mesh_store().is_some() {
        println!();
        println!("Store:           connected (SQLite)");
    } else {
        println!();
        println!("Store:           none");
    }

    println!();
    Ok(())
}

/// `zp mesh peers` — list known peers with address, link status, capabilities,
/// and reputation grade.
pub async fn peers(pipeline: &Pipeline) -> Result<()> {
    let bridge = match pipeline.mesh_bridge() {
        Some(b) => b,
        None => bail!("Mesh is not initialized. Use --mesh to enable."),
    };

    let node = bridge.node();
    let peers = node.known_peers().await;
    let reputations = node.all_peer_reputations().await;

    println!();
    if peers.is_empty() {
        println!("No known peers.");
        println!();
        return Ok(());
    }

    println!(
        "{:<36} {:<6} {:<8} {:<10} {:<12} Agent",
        "Address", "Hops", "Link", "Grade", "Signals"
    );
    println!("{}", "-".repeat(90));

    for peer in &peers {
        // Look up pre-computed reputation score for this peer
        let dest_hash = hex_to_dest_hash(&peer.address);
        let (grade, signals) =
            if let Some(score) = dest_hash.as_ref().and_then(|h| reputations.get(h)) {
                (
                    format!("{}", score.grade),
                    format!("+{} -{}", score.positive_signals, score.negative_signals),
                )
            } else {
                ("Unknown".to_string(), "-".to_string())
            };

        let link_str = if peer.has_link { "yes" } else { "no" };
        let agent_name = peer
            .capabilities
            .as_ref()
            .map(|c| c.name.as_str())
            .unwrap_or("-");

        // Truncate address for display
        let addr_display = if peer.address.len() > 34 {
            format!("{}…", &peer.address[..34])
        } else {
            peer.address.clone()
        };

        println!(
            "{:<36} {:<6} {:<8} {:<10} {:<12} {}",
            addr_display, peer.hops, link_str, grade, signals, agent_name
        );
    }

    println!();
    println!("{} peer(s) total", peers.len());
    println!();
    Ok(())
}

/// `zp mesh challenge <peer>` — send an audit challenge to a peer.
pub async fn challenge(
    pipeline: &Pipeline,
    peer_address: &str,
    since_hash: Option<&str>,
) -> Result<()> {
    let bridge = match pipeline.mesh_bridge() {
        Some(b) => b,
        None => bail!("Mesh is not initialized. Use --mesh to enable."),
    };

    let peer_hash = hex_to_dest_hash(peer_address)
        .ok_or_else(|| anyhow::anyhow!("Invalid peer address: {}", peer_address))?;

    println!();
    println!("Challenging peer audit trail...");
    println!("Peer:  {}", peer_address);

    let result = if let Some(hash) = since_hash {
        println!("Since: {}", hash);
        bridge
            .challenge_peer_audit_since(&peer_hash, hash.to_string())
            .await
    } else {
        // Request the 100 most recent entries
        bridge.challenge_peer_audit(&peer_hash, 100).await
    };

    match result {
        Ok(challenge) => {
            println!();
            println!("Challenge sent successfully.");
            println!("Challenge ID: {}", challenge.id);
            println!("Waiting for response from the peer...");
            println!("(Responses are processed asynchronously by the runtime.)");
        }
        Err(e) => {
            println!();
            println!("Failed to send challenge: {}", e);
        }
    }

    println!();
    Ok(())
}

/// `zp mesh grant <peer>` — grant a capability to a peer via delegation.
pub async fn grant(
    pipeline: &Pipeline,
    peer_address: &str,
    capability_type: &str,
    scope: &str,
) -> Result<()> {
    let bridge = match pipeline.mesh_bridge() {
        Some(b) => b,
        None => bail!("Mesh is not initialized. Use --mesh to enable."),
    };

    let peer_hash = hex_to_dest_hash(peer_address)
        .ok_or_else(|| anyhow::anyhow!("Invalid peer address: {}", peer_address))?;

    let scope_vec: Vec<String> = scope.split(',').map(|s| s.trim().to_string()).collect();

    let capability = match capability_type {
        "read" => zp_core::GrantedCapability::Read { scope: scope_vec },
        "write" => zp_core::GrantedCapability::Write { scope: scope_vec },
        "execute" => zp_core::GrantedCapability::Execute {
            languages: scope_vec,
        },
        "api" => zp_core::GrantedCapability::ApiCall {
            endpoints: scope_vec,
        },
        "mesh-send" => zp_core::GrantedCapability::MeshSend {
            destinations: scope_vec,
        },
        "config" => zp_core::GrantedCapability::ConfigChange {
            settings: scope_vec,
        },
        _ => bail!(
            "Unknown capability type '{}'. Use: read, write, execute, api, mesh-send, or config.",
            capability_type
        ),
    };

    println!();
    println!("Granting Capability");
    println!("{}", "=".repeat(60));
    println!("From:       {}", bridge.address());
    println!("To:         {}", peer_address);
    println!("Capability: {:?}", &capability);

    let grant = zp_core::CapabilityGrant::new(
        bridge.address(),
        peer_address.to_string(),
        capability,
        uuid::Uuid::new_v4().to_string(),
    );
    println!("Grant ID:   {}", grant.id);

    match bridge.send_delegation_to(&peer_hash, &grant).await {
        Ok(()) => {
            println!();
            println!("Delegation sent successfully.");
        }
        Err(e) => {
            println!();
            println!("Failed to send delegation: {}", e);
        }
    }

    println!();
    Ok(())
}

/// `zp mesh save` — persist current mesh state to the SQLite store.
pub async fn save(pipeline: &Pipeline) -> Result<()> {
    if !pipeline.has_mesh() {
        bail!("Mesh is not initialized. Use --mesh to enable.");
    }

    println!();
    println!("Saving mesh state...");

    match pipeline.save_mesh_state().await {
        Ok(()) => {
            println!("Mesh state saved successfully.");
        }
        Err(e) => {
            println!("Failed to save mesh state: {}", e);
        }
    }

    println!();
    Ok(())
}

/// Parse a hex peer address into a 16-byte destination hash.
fn hex_to_dest_hash(hex_addr: &str) -> Option<[u8; 16]> {
    let bytes = hex::decode(hex_addr).ok()?;
    if bytes.len() >= 16 {
        let mut hash = [0u8; 16];
        hash.copy_from_slice(&bytes[..16]);
        Some(hash)
    } else {
        None
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_to_dest_hash_valid() {
        let hex = "0102030405060708090a0b0c0d0e0f10";
        let hash = hex_to_dest_hash(hex).unwrap();
        assert_eq!(
            hash,
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        );
    }

    #[test]
    fn test_hex_to_dest_hash_too_short() {
        let hex = "0102030405";
        assert!(hex_to_dest_hash(hex).is_none());
    }

    #[test]
    fn test_hex_to_dest_hash_invalid_hex() {
        let hex = "not-a-hex-string";
        assert!(hex_to_dest_hash(hex).is_none());
    }

    #[test]
    fn test_hex_to_dest_hash_longer_than_16() {
        let hex = "0102030405060708090a0b0c0d0e0f101112131415";
        let hash = hex_to_dest_hash(hex).unwrap();
        assert_eq!(
            hash,
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        );
    }
}
