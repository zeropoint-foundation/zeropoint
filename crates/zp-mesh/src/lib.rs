//! # ZeroPoint Mesh — Sovereign Agent Transport
//!
//! Reticulum-compatible cryptographic mesh networking for autonomous agents.
//!
//! This crate provides the physical transport layer for the ZeroPoint agent web,
//! enabling agents to discover each other, establish encrypted channels, and
//! exchange receipted work over any physical medium — LoRa, WiFi, HaLow, Ethernet,
//! serial, or even Morse code.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │  ZeroPoint Agent                             │
//! │  ┌────────────┐  ┌──────────┐  ┌──────────┐│
//! │  │ zp-pipeline │  │ zp-trust │  │zp-receipt││
//! │  └─────┬──────┘  └────┬─────┘  └────┬─────┘│
//! │        │              │              │       │
//! │  ┌─────┴──────────────┴──────────────┴─────┐│
//! │  │            zp-mesh (this crate)          ││
//! │  │                                          ││
//! │  │  MeshIdentity ←→ Ed25519 + X25519 keys  ││
//! │  │  Destination  ←→ 128-bit address hash    ││
//! │  │  Link         ←→ Encrypted channel       ││
//! │  │  Packet       ←→ Wire-format datagrams   ││
//! │  │  Envelope     ←→ Receipt-in-mesh carrier ││
//! │  └─────────────────────┬────────────────────┘│
//! │                        │                      │
//! └────────────────────────┼──────────────────────┘
//!                          │
//!            ┌─────────────┼─────────────┐
//!            │             │             │
//!        ┌───┴───┐   ┌────┴────┐   ┌────┴────┐
//!        │ LoRa  │   │  WiFi   │   │ Serial  │
//!        │ RNode │   │  HaLow  │   │ Ethernet│
//!        └───────┘   └─────────┘   └─────────┘
//! ```
//!
//! ## Design Principles
//!
//! 1. **Sovereign**: No dependency on DNS, CAs, ISPs, or cloud infrastructure
//! 2. **Identity = Keypair**: Agent addresses derive from Ed25519 public keys
//! 3. **Encrypted by Default**: All traffic is encrypted; origin is obscured
//! 4. **Medium-Agnostic**: Same semantics over LoRa at 300 baud or fiber at 1 Gbps
//! 5. **Receipt-Native**: Every exchange produces a verifiable receipt
//! 6. **Reticulum-Compatible**: Wire format matches the Reticulum network stack
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use zp_mesh::{MeshIdentity, MeshNode, Interface};
//!
//! // Create an agent identity (or derive from existing zp-trust Signer)
//! let identity = MeshIdentity::generate();
//!
//! // Create a mesh node with one or more interfaces
//! let node = MeshNode::new(identity);
//!
//! // The node can now discover peers, establish links, and exchange receipts
//! // over any attached interface — LoRa, WiFi, serial, etc.
//! ```

pub mod capability_exchange;
pub mod consensus;
pub mod destination;
pub mod discovery;
pub mod envelope;
pub mod error;
pub mod identity;
pub mod interface;
pub mod link;
pub mod node_registry;
pub mod packet;
pub mod policy_distributor;
pub mod peer_keystore;
pub mod policy_sync;
pub mod reputation;
pub mod reticulum_discovery;
pub mod runtime;
pub mod store;
pub mod tcp;
pub mod transport;
pub mod web_discovery;

// Re-export primary types
pub use capability_exchange::{
    CapabilityPolicy, CapabilityRequest, CapabilityResponse, NegotiationResult,
};
pub use consensus::{ConsensusCoordinator, ConsensusOutcome, Proposal, Vote};
pub use destination::{Destination, DestinationHash, DestinationType};
pub use envelope::{CompactDelegation, CompactReceipt, MeshEnvelope};
pub use error::MeshError;
pub use identity::MeshIdentity;
pub use interface::{Interface, InterfaceType};
pub use link::{Link, LinkState, SessionKeys};
pub use packet::{Packet, PacketHeader, PacketType, PropagationType};
pub use policy_sync::{
    PolicyAdvertisement, PolicyAgreement, PolicyChunk, PolicyDenial, PolicyModuleInfo,
    PolicyProposal, PolicyPullRequest, PolicyPullResponse, PolicyVote, TransferState,
};
pub use reputation::{
    CompactReputationSummary, PeerReputation, ReputationGrade, ReputationScore, ReputationSignal,
    ReputationWeights, SignalCategory, SignalPolarity,
};
pub use node_registry::{FleetNode, FleetSummary, NodeHeartbeat, NodeRegistry, NodeStatus};
pub use policy_distributor::{PolicyDistributor, PolicyRollout, RolloutSummary};
pub use runtime::{InboundEnvelope, MeshRuntime, RuntimeConfig, RuntimeStats};
pub use store::MeshStore;
pub use tcp::{TcpClientInterface, TcpServerInterface};
pub use transport::{AgentTransport, MeshNode};

// Discovery system
pub use discovery::{
    DiscoveredPeer, DiscoveryBackend, DiscoveryConfig, DiscoveryManager, DiscoverySource,
    ValidatedDiscovery,
};
pub use reticulum_discovery::ReticulumDiscovery;
pub use web_discovery::{
    ConnectionBehavior, RelayConnection, WebDiscovery, WebDiscoveryConfig, WebRelayServer,
};
