//! Load test for zp-mesh — concurrent agent receipt exchange.
//!
//! Simulates N agents on a shared loopback mesh, each generating and
//! exchanging receipts at high throughput. Validates:
//!
//! - Identity generation at scale (1000+ agents)
//! - Destination hash uniqueness
//! - Concurrent receipt serialization (compact + envelope + packet)
//! - Link handshake under load
//! - Receipt roundtrip integrity
//! - Throughput measurement

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use zp_mesh::destination::DestinationHash;
use zp_mesh::envelope::{CompactReceipt, MeshEnvelope};
use zp_mesh::identity::{MeshIdentity, PeerIdentity};
use zp_mesh::interface::LoopbackInterface;
use zp_mesh::link::Link;
use zp_mesh::packet::{Packet, PacketContext, MAX_DATA_TYPE1};
use zp_mesh::*;

// ============================================================================
// Identity stress tests
// ============================================================================

#[test]
fn load_identity_generation_1000() {
    let start = Instant::now();
    let mut addresses = HashSet::new();

    for _ in 0..1000 {
        let id = MeshIdentity::generate();
        let addr = id.address();
        assert!(
            addresses.insert(addr.clone()),
            "Duplicate address generated: {}",
            addr
        );
    }

    let elapsed = start.elapsed();
    println!(
        "Generated 1000 unique identities in {:?} ({:.0} identities/sec)",
        elapsed,
        1000.0 / elapsed.as_secs_f64()
    );
}

#[test]
fn load_identity_from_secret_determinism() {
    // Verify that 1000 different secrets produce 1000 different addresses
    // AND that each secret is deterministic
    let mut addresses = HashSet::new();

    for i in 0u32..1000 {
        let mut secret = [0u8; 32];
        secret[..4].copy_from_slice(&i.to_be_bytes());

        let id1 = MeshIdentity::from_ed25519_secret(&secret).unwrap();
        let id2 = MeshIdentity::from_ed25519_secret(&secret).unwrap();

        // Deterministic
        assert_eq!(id1.address(), id2.address());
        assert_eq!(id1.signing_public_key(), id2.signing_public_key());
        assert_eq!(id1.encryption_public_key(), id2.encryption_public_key());

        // Unique
        addresses.insert(id1.address());
    }

    assert_eq!(
        addresses.len(),
        1000,
        "All 1000 secrets should produce unique addresses"
    );
}

// ============================================================================
// Signing throughput
// ============================================================================

#[test]
fn load_signing_throughput() {
    let id = MeshIdentity::generate();
    let data = b"receipt content hash to sign for mesh transport verification";

    let iterations = 10_000;
    let start = Instant::now();

    for _ in 0..iterations {
        let sig = id.sign(data);
        assert_eq!(sig.len(), 64);
    }

    let elapsed = start.elapsed();
    println!(
        "Signed {} messages in {:?} ({:.0} signs/sec)",
        iterations,
        elapsed,
        iterations as f64 / elapsed.as_secs_f64()
    );
}

#[test]
fn load_verification_throughput() {
    let id = MeshIdentity::generate();
    let data = b"receipt content hash to verify";
    let sig = id.sign(data);

    let iterations = 10_000;
    let start = Instant::now();

    for _ in 0..iterations {
        assert!(id.verify(data, &sig));
    }

    let elapsed = start.elapsed();
    println!(
        "Verified {} signatures in {:?} ({:.0} verifications/sec)",
        iterations,
        elapsed,
        iterations as f64 / elapsed.as_secs_f64()
    );
}

// ============================================================================
// Key exchange throughput
// ============================================================================

#[test]
fn load_key_exchange_throughput() {
    let alice = MeshIdentity::generate();
    let bob = MeshIdentity::generate();
    let bob_pub = bob.encryption_public_key();

    let iterations = 5_000;
    let start = Instant::now();

    for _ in 0..iterations {
        let shared = alice.key_exchange(&bob_pub);
        assert_eq!(shared.len(), 32);
    }

    let elapsed = start.elapsed();
    println!(
        "Performed {} key exchanges in {:?} ({:.0} exchanges/sec)",
        iterations,
        elapsed,
        iterations as f64 / elapsed.as_secs_f64()
    );
}

// ============================================================================
// Link handshake under load
// ============================================================================

#[test]
fn load_link_handshakes_100() {
    let start = Instant::now();
    let mut successful = 0;

    for _ in 0..100 {
        let alice = MeshIdentity::generate();
        let bob = MeshIdentity::generate();
        let bob_dest = DestinationHash::from_public_key(&bob.combined_public_key());

        // Full 3-step handshake
        let (mut alice_link, request) = Link::initiate(&alice, bob_dest);
        let (_bob_link, proof, bob_keys) = Link::accept(&bob, &request).unwrap();
        let alice_keys = alice_link
            .complete_handshake(&alice, &proof, &request)
            .unwrap();

        // Verify session key agreement
        assert_eq!(alice_keys.encrypt_key, bob_keys.decrypt_key);
        assert_eq!(alice_keys.decrypt_key, bob_keys.encrypt_key);
        assert!(alice_link.is_active());
        successful += 1;
    }

    let elapsed = start.elapsed();
    println!(
        "Completed {} link handshakes in {:?} ({:.0} handshakes/sec)",
        successful,
        elapsed,
        successful as f64 / elapsed.as_secs_f64()
    );
    assert_eq!(successful, 100);
}

// ============================================================================
// Receipt serialization throughput
// ============================================================================

fn make_receipt(i: u64) -> zp_receipt::Receipt {
    zp_receipt::Receipt::execution(&format!("agent-{}", i))
        .status(zp_receipt::Status::Success)
        .trust_grade(zp_receipt::TrustGrade::C)
        .executor_type(zp_receipt::ExecutorType::Agent)
        .runtime("shell")
        .action(zp_receipt::Action::shell_command(&format!("task-{}", i), 0))
        .policy_full(zp_receipt::PolicyDecision {
            decision: zp_receipt::Decision::Allow,
            policy_id: Some("zp-guard-v2".into()),
            trust_tier: None,
            rationale: Some(format!("Automated task {}", i)),
        })
        .finalize()
}

#[test]
fn load_compact_receipt_serialization_10k() {
    let start = Instant::now();
    let mut total_bytes = 0usize;
    let mut max_size = 0usize;

    for i in 0..10_000 {
        let receipt = make_receipt(i);
        let compact = CompactReceipt::from_receipt(&receipt);
        let encoded = compact.to_msgpack().unwrap();

        total_bytes += encoded.len();
        if encoded.len() > max_size {
            max_size = encoded.len();
        }

        // Roundtrip verify
        let decoded = CompactReceipt::from_msgpack(&encoded).unwrap();
        assert_eq!(decoded.id, compact.id);
    }

    let elapsed = start.elapsed();
    let avg_size = total_bytes / 10_000;
    println!("Serialized 10,000 compact receipts in {:?}", elapsed);
    println!(
        "  Avg size: {} bytes, Max size: {} bytes, Total: {} KB",
        avg_size,
        max_size,
        total_bytes / 1024
    );
    println!(
        "  Throughput: {:.0} receipts/sec, {:.1} MB/sec",
        10_000.0 / elapsed.as_secs_f64(),
        total_bytes as f64 / elapsed.as_secs_f64() / 1_048_576.0
    );

    // Verify all fit in mesh MTU
    assert!(
        max_size <= MAX_DATA_TYPE1,
        "Largest receipt ({} bytes) exceeds mesh MTU ({})",
        max_size,
        MAX_DATA_TYPE1
    );
}

// ============================================================================
// Envelope sign + verify throughput
// ============================================================================

#[test]
fn load_envelope_sign_verify_1k() {
    let identity = MeshIdentity::generate();
    let pub_key = identity.signing_public_key();

    let start = Instant::now();
    let mut total_wire_bytes = 0usize;

    for i in 0..1_000u64 {
        let receipt = make_receipt(i);
        let compact = CompactReceipt::from_receipt(&receipt);
        let envelope = MeshEnvelope::receipt(&identity, &compact, i).unwrap();

        // Verify signature
        assert!(envelope.verify(&pub_key).unwrap());

        // Verify roundtrip
        let wire = envelope.to_msgpack().unwrap();
        total_wire_bytes += wire.len();
        let decoded = MeshEnvelope::from_msgpack(&wire).unwrap();
        assert!(decoded.verify(&pub_key).unwrap());

        let extracted = decoded.extract_receipt().unwrap();
        assert_eq!(extracted.id, compact.id);
    }

    let elapsed = start.elapsed();
    println!(
        "Signed, verified, and roundtripped 1,000 envelopes in {:?}",
        elapsed
    );
    println!(
        "  Throughput: {:.0} envelopes/sec",
        1000.0 / elapsed.as_secs_f64()
    );
    println!(
        "  Avg envelope wire size: {} bytes",
        total_wire_bytes / 1000
    );
}

// ============================================================================
// Packet encode/decode throughput
// ============================================================================

#[test]
fn load_packet_codec_50k() {
    let id = MeshIdentity::generate();
    let dest = DestinationHash::from_public_key(&id.combined_public_key());
    let payload = vec![0xAB; 200]; // Typical receipt-sized payload

    let start = Instant::now();

    for _ in 0..50_000 {
        let pkt = Packet::data(dest, payload.clone(), PacketContext::Receipt).unwrap();
        let wire = pkt.to_bytes();
        let decoded = Packet::from_bytes(&wire).unwrap();
        assert_eq!(decoded.data, payload);
    }

    let elapsed = start.elapsed();
    println!(
        "Encoded/decoded 50,000 packets in {:?} ({:.0} packets/sec)",
        elapsed,
        50_000.0 / elapsed.as_secs_f64()
    );
}

// ============================================================================
// Multi-agent mesh simulation
// ============================================================================

#[tokio::test]
async fn load_multi_agent_mesh_10_agents() {
    let num_agents = 10;
    let receipts_per_agent = 100;

    // Create N agents, each with their own MeshNode and loopback interface
    let mut nodes: Vec<Arc<MeshNode>> = Vec::new();
    let mut identities: Vec<MeshIdentity> = Vec::new();

    for _ in 0..num_agents {
        let id = MeshIdentity::generate();
        let node = MeshNode::new(MeshIdentity::from_ed25519_secret(&id.signing_secret()).unwrap());
        let lo = Arc::new(LoopbackInterface::new());
        node.attach_interface(lo).await;
        identities.push(id);
        nodes.push(Arc::new(node));
    }

    // Register all peers with each other
    for i in 0..num_agents {
        for j in 0..num_agents {
            if i != j {
                let peer = PeerIdentity::from_combined_key(&identities[j].combined_public_key(), 1)
                    .unwrap();
                nodes[i].register_peer(peer, None).await;
            }
        }
    }

    // Each agent sends receipts_per_agent receipts to a random peer
    let start = Instant::now();
    let mut total_sent = 0u64;

    for i in 0..num_agents {
        let target_idx = (i + 1) % num_agents;
        let target_addr = identities[target_idx].address();

        for r in 0..receipts_per_agent {
            let receipt = make_receipt((i * receipts_per_agent + r) as u64);
            nodes[i].send_receipt(&target_addr, &receipt).await.unwrap();
            total_sent += 1;
        }
    }

    let elapsed = start.elapsed();
    println!(
        "Multi-agent mesh: {} agents sent {} receipts in {:?}",
        num_agents, total_sent, elapsed
    );
    println!(
        "  Throughput: {:.0} receipts/sec across mesh",
        total_sent as f64 / elapsed.as_secs_f64()
    );

    // Verify all nodes report correct peer count
    for node in &nodes {
        let peers = node.known_peers().await;
        assert_eq!(
            peers.len(),
            num_agents - 1,
            "Each node should know {} peers",
            num_agents - 1
        );
    }
}

#[tokio::test]
async fn load_broadcast_storm() {
    // 20 agents, each broadcasting a receipt to all peers simultaneously
    let num_agents = 20;

    let mut nodes: Vec<Arc<MeshNode>> = Vec::new();
    let mut identities: Vec<MeshIdentity> = Vec::new();

    for _ in 0..num_agents {
        let id = MeshIdentity::generate();
        let node = MeshNode::new(MeshIdentity::from_ed25519_secret(&id.signing_secret()).unwrap());
        let lo = Arc::new(LoopbackInterface::new());
        node.attach_interface(lo).await;
        identities.push(id);
        nodes.push(Arc::new(node));
    }

    // Full mesh peer registration
    for i in 0..num_agents {
        for j in 0..num_agents {
            if i != j {
                let peer = PeerIdentity::from_combined_key(&identities[j].combined_public_key(), 1)
                    .unwrap();
                nodes[i].register_peer(peer, None).await;
            }
        }
    }

    // Broadcast storm: every agent broadcasts simultaneously
    let start = Instant::now();
    let mut handles = Vec::new();

    for (i, node) in nodes.iter().enumerate() {
        let node = node.clone();
        let handle = tokio::spawn(async move {
            let receipt = make_receipt(i as u64);
            node.broadcast_receipt(&receipt).await.unwrap();
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }

    let elapsed = start.elapsed();
    let total_messages = num_agents * (num_agents - 1); // each broadcasts to N-1 peers
    println!(
        "Broadcast storm: {} agents, {} total messages in {:?}",
        num_agents, total_messages, elapsed
    );
    println!(
        "  Throughput: {:.0} messages/sec",
        total_messages as f64 / elapsed.as_secs_f64()
    );
}

// ============================================================================
// Receipt chain integrity
// ============================================================================

#[test]
fn load_receipt_chain_integrity() {
    // Build a chain of 100 receipts (intent → design → approval → execution × 25)
    // Verify each compact receipt preserves the parent linkage
    let identity = MeshIdentity::generate();

    let mut chain: Vec<CompactReceipt> = Vec::new();
    let mut parent_id: Option<String> = None;

    let types = ["intent", "design", "approval", "execution"];

    for i in 0..100 {
        let receipt_type = types[i % 4];
        let mut builder = match receipt_type {
            "intent" => zp_receipt::Receipt::intent("chain-agent"),
            "design" => zp_receipt::Receipt::design("chain-agent"),
            "approval" => zp_receipt::Receipt::approval("chain-agent"),
            _ => zp_receipt::Receipt::execution("chain-agent"),
        };

        builder = builder
            .status(zp_receipt::Status::Success)
            .trust_grade(zp_receipt::TrustGrade::C);

        if let Some(ref pid) = parent_id {
            builder = builder.parent(pid);
        }

        let receipt = builder.finalize();
        parent_id = Some(receipt.id.clone());

        let compact = CompactReceipt::from_receipt(&receipt);

        // Sign and verify the envelope
        let envelope = MeshEnvelope::receipt(&identity, &compact, i as u64).unwrap();
        assert!(envelope.verify(&identity.signing_public_key()).unwrap());

        // Extract and verify chain linkage
        let extracted = envelope.extract_receipt().unwrap();
        if i > 0 {
            assert!(extracted.pr.is_some(), "Receipt {} should have parent", i);
            assert_eq!(
                extracted.pr.as_ref().unwrap(),
                &chain[i - 1].id,
                "Receipt {} parent should be receipt {}",
                i,
                i - 1
            );
        }

        chain.push(extracted);
    }

    println!(
        "Verified chain of {} receipts with intact parent linkage",
        chain.len()
    );
}
