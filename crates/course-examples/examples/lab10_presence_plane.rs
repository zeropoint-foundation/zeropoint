//! Lab 10: The Presence Plane
//!
//! Dual-backend discovery architecture — conceptual walkthrough
//! Run: cargo run --example lab10_presence_plane -p course-examples

use zp_mesh::identity::MeshIdentity;
use zp_mesh::transport::AgentCapabilities;

fn main() {
    println!("LAB 10: The Presence Plane");
    println!("══════════════════════════\n");

    // 1. Generate an agent identity (Ed25519 + X25519 keypair)
    let identity = MeshIdentity::generate();
    println!("Agent identity generated");
    println!("  Address: {}", identity.address());
    println!("  Public key: {} bytes", identity.signing_public_key().len());

    // 2. Declare capabilities
    let caps = AgentCapabilities {
        name: "presence-lab-agent".into(),
        version: "1.0.0".into(),
        receipt_types: vec!["execution".into(), "intent".into()],
        skills: vec!["data-processing".into(), "negotiation".into()],
        actor_type: "agent".into(),
        trust_tier: "tier1".into(),
    };
    println!("\nCapabilities declared:");
    println!("  Name: {}", caps.name);
    println!("  Skills: {:?}", caps.skills);
    println!("  Receipt types: {:?}", caps.receipt_types);

    // 3. Announce payload structure
    //    The Presence Plane uses a unified announce format:
    //    [32B signing key | 32B exchange key | JSON capabilities | 64B signature]
    let signing_key = identity.signing_public_key();
    let encryption_key = identity.encryption_public_key();
    let caps_json = serde_json::to_vec(&caps).unwrap();

    let total_size = signing_key.len() + encryption_key.len() + caps_json.len() + 64;
    println!("\nAnnounce payload layout:");
    println!("  Signing key:    {} bytes (Ed25519)", signing_key.len());
    println!("  Encryption key: {} bytes (X25519)", encryption_key.len());
    println!("  Capabilities:   {} bytes (JSON)", caps_json.len());
    println!("  Signature:      64 bytes (Ed25519)");
    println!("  Total:          {} bytes", total_size);

    // 4. Dual-backend architecture
    println!("\n┌──────────────────────────────────────────────────┐");
    println!("│  DiscoveryManager                                 │");
    println!("│                                                   │");
    println!("│  ┌─────────────────┐  ┌────────────────────────┐ │");
    println!("│  │  WebDiscovery    │  │  ReticulumDiscovery    │ │");
    println!("│  │  (pub/sub relay) │  │  (broadcast announces) │ │");
    println!("│  └────────┬────────┘  └───────────┬────────────┘ │");
    println!("│           │                        │              │");
    println!("│           └───────────┬────────────┘              │");
    println!("│                       ▼                           │");
    println!("│              Unified Peer Table                   │");
    println!("│         (same PeerIdentity, same hash)            │");
    println!("└──────────────────────────────────────────────────┘");

    // 5. Peer generation and identity verification
    let peer = MeshIdentity::generate();
    println!("\nPeer identity generated:");
    println!("  Address: {}", peer.address());

    // 6. Key exchange (X25519 Diffie-Hellman)
    let shared_secret = identity.key_exchange(&peer.encryption_public_key());
    println!("\nX25519 key exchange:");
    println!("  Shared secret: {} bytes", shared_secret.len());

    // Derive session keys from shared secret
    let (encrypt, decrypt, hmac) =
        MeshIdentity::derive_session_keys(&shared_secret, true).unwrap();
    println!("  Encrypt key:  {} bytes", encrypt.len());
    println!("  Decrypt key:  {} bytes", decrypt.len());
    println!("  HMAC key:     {} bytes", hmac.len());

    // 7. Discovery properties
    println!("\nPresence Plane properties:");
    println!("  ✓ Privacy-preserving: relay is structurally amnesic");
    println!("  ✓ Dual-backend: web relay + Reticulum mesh");
    println!("  ✓ Unified identity: same peer hash across backends");
    println!("  ✓ Signature-verified: all announces are Ed25519-signed");
    println!("  ✓ TTL-based: expired peers are pruned automatically");

    println!("\n✓ Presence Plane architecture demonstrated");
}
