//! Lab 10: The Presence Plane
//!
//! Dual-backend presence plane
//! Run: cargo run --example lab10_presence_plane -p course-examples

use zp_mesh::discovery::DiscoveryManager;
use zp_mesh::web_discovery::WebDiscovery;
use zp_mesh::reticulum_discovery::ReticulumDiscovery;
use zp_mesh::identity::MeshIdentity;
use zp_mesh::transport::AgentCapabilities;
use zp_mesh::interface::LoopbackInterface;
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() {
    let identity = MeshIdentity::generate();
    println!("Agent address: {}", identity.address());

    let caps = AgentCapabilities {
        name: "presence-lab-agent".into(),
        version: "1.0.0".into(),
        receipt_types: vec!["execution".into()],
        skills: vec!["data-processing".into()],
        actor_type: "agent".into(),
        trust_tier: "tier1".into(),
    };

    let payload = DiscoveryManager::build_announce_payload(&identity, &caps)
        .expect("Should build announce payload");
    println!("Announce payload: {} bytes", payload.len());
    println!("  Combined key: 64 bytes");
    println!("  Capabilities JSON: {} bytes", payload.len() - 128);
    println!("  Ed25519 signature: 64 bytes");

    let manager = DiscoveryManager::new(Duration::from_secs(900));

    let web = WebDiscovery::with_relay("wss://relay.zeropoint.global/discover");
    web.start().await.unwrap();
    manager.add_backend(Box::new(web)).await;

    let ret = ReticulumDiscovery::new();
    let lo = Arc::new(LoopbackInterface::new());
    ret.add_interface(lo.clone()).await;
    manager.add_backend(Box::new(ret)).await;

    println!("\nBackends: {:?}", manager.active_backends().await);

    manager.announce_all(&identity, &caps).await.unwrap();
    println!("✓ Announced on all backends");

    let peer_identity = MeshIdentity::generate();
    let peer_caps = AgentCapabilities {
        name: "peer-agent".into(),
        version: "1.0.0".into(),
        receipt_types: vec!["intent".into()],
        skills: vec!["negotiation".into()],
        actor_type: "agent".into(),
        trust_tier: "tier2".into(),
    };
    let peer_payload = DiscoveryManager::build_announce_payload(
        &peer_identity, &peer_caps
    ).unwrap();

    println!("\nPeer payload built: {} bytes", peer_payload.len());
    println!("Peer address: {}", peer_identity.address());

    let validated = manager.poll_all().await;
    println!("\nValidated discoveries: {}", validated.len());
    println!("Known peers: {}", manager.peer_count().await);

    let pruned = manager.prune_expired().await;
    println!("Pruned: {} (none expected — all fresh)", pruned);

    manager.shutdown().await;
    println!("\n✓ Presence Plane: dual-backend discovery with unified peer table");
}
