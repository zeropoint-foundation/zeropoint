//! Lab 9: Discovery
//!
//! Mesh discovery with loopback interfaces
//! Run: cargo run --example lab09_discovery -p course-examples

use std::sync::Arc;
use std::time::Duration;
use zp_mesh::interface::LoopbackInterface;
use zp_mesh::transport::{AgentCapabilities, AgentTransport};
use zp_mesh::{MeshNode, MeshRuntime, RuntimeConfig};
use zp_trust::Signer;

#[tokio::main]
async fn main() {
    let signer_a = Signer::generate();
    let signer_b = Signer::generate();

    let node_a = Arc::new(MeshNode::from_signer(&signer_a).unwrap());
    let node_b = Arc::new(MeshNode::from_signer(&signer_b).unwrap());

    let lo = Arc::new(LoopbackInterface::new());
    node_a.attach_interface(lo.clone()).await;
    node_b.attach_interface(lo.clone()).await;

    let mut runtime_b = MeshRuntime::start(
        node_b.clone(),
        RuntimeConfig {
            poll_interval: Duration::from_millis(10),
            ..Default::default()
        },
    );
    let _inbound = runtime_b.take_inbound_rx();

    let caps = AgentCapabilities {
        name: "agent-alpha".into(),
        version: "1.0.0".into(),
        receipt_types: vec!["execution".into(), "intent".into()],
        skills: vec!["python".into(), "shell".into()],
        actor_type: "agent".into(),
        trust_tier: "tier1".into(),
    };
    node_a.announce(&caps).await.unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;

    let stats = runtime_b.stats().await;
    println!("Announces seen: {}", stats.announces_seen);
    println!("Peers discovered: {}", stats.peers_discovered);

    let peers: Vec<_> = node_b.known_peers().await;
    println!("Known peers: {}", peers.len());
    for peer in &peers {
        println!(
            "  {} — {:?}",
            peer.address,
            peer.capabilities.as_ref().map(|c| &c.name)
        );
    }

    runtime_b.shutdown();
    println!("\n✓ Discovery complete: A announced → B auto-registered A as peer");
}
