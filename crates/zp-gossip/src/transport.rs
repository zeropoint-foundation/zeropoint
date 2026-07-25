//! Gossip transport — how findings move between substrates.
//!
//! Store-and-forward, not live. Composes with Principle 5
//! (store-and-forward is primary) and Principle 3 (there is no center).

use crate::finding::GossipFinding;

/// Error during gossip transport.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("transport unavailable: {0}")]
    Unavailable(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("I/O error: {0}")]
    Io(String),
}

/// Gossip transport trait — abstracts over network, file, or null.
///
/// Implementations:
/// - `NullTransport` — gossip disabled, local findings only.
/// - Future: `MeshTransport` (via zp-mesh), `FileTransport` (air-gapped).
pub trait GossipTransport: Send + Sync {
    /// Broadcast a finding to available peers.
    fn broadcast(&self, finding: &GossipFinding) -> Result<(), TransportError>;

    /// Receive pending findings from peers.
    fn receive(&self) -> Result<Vec<GossipFinding>, TransportError>;

    /// Transport name for logging/receipts.
    fn name(&self) -> &str;
}

/// Null transport — gossip disabled. The Regent produces local findings
/// but doesn't share them. Receives nothing.
pub struct NullTransport;

impl GossipTransport for NullTransport {
    fn broadcast(&self, _finding: &GossipFinding) -> Result<(), TransportError> {
        // Silently succeed — the finding stays local.
        Ok(())
    }

    fn receive(&self) -> Result<Vec<GossipFinding>, TransportError> {
        Ok(Vec::new())
    }

    fn name(&self) -> &str {
        "none"
    }
}
