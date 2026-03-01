//! Pipeline configuration structures and defaults.

use std::path::PathBuf;
use zp_core::OperatorIdentity;
use zp_core::TrustTier;

/// Configuration for the ZeroPoint Pipeline.
///
/// Controls operator identity, trust levels, and persistent storage locations.
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// The operator identity for this pipeline instance
    pub operator_identity: OperatorIdentity,

    /// Trust tier for this pipeline
    pub trust_tier: TrustTier,

    /// Directory where databases and persistent state are stored
    pub data_dir: PathBuf,

    /// Optional mesh network configuration.
    /// When set, the pipeline will initialize mesh networking on startup.
    pub mesh: Option<MeshConfig>,
}

/// Configuration for mesh network integration.
#[derive(Debug, Clone)]
pub struct MeshConfig {
    /// Secret key material for deterministic identity generation.
    /// If None, a random identity is generated each time.
    pub identity_secret: Option<[u8; 32]>,
    /// Whether to forward receipts to mesh peers after each request.
    pub forward_receipts: bool,
    /// Whether to forward audit entries to mesh peers.
    pub forward_audit: bool,
    /// Maximum peers to forward to (0 = all).
    pub max_forward_peers: usize,
    /// TCP listen address for mesh peers (e.g., "0.0.0.0:4242").
    /// If None, no TCP listener is started.
    pub tcp_listen: Option<String>,
    /// TCP peers to connect to on startup (e.g., ["192.168.1.10:4242"]).
    pub tcp_peers: Vec<String>,
    /// Runtime poll interval in milliseconds.
    pub poll_interval_ms: u64,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            identity_secret: None,
            forward_receipts: true,
            forward_audit: true,
            max_forward_peers: 0,
            tcp_listen: None,
            tcp_peers: Vec::new(),
            poll_interval_ms: 50,
        }
    }
}

impl PipelineConfig {
    /// Create a new pipeline configuration with custom settings.
    pub fn new(
        operator_identity: OperatorIdentity,
        trust_tier: TrustTier,
        data_dir: PathBuf,
    ) -> Self {
        Self {
            operator_identity,
            trust_tier,
            data_dir,
            mesh: None,
        }
    }
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            operator_identity: OperatorIdentity::default(),
            trust_tier: TrustTier::default(),
            data_dir: PathBuf::from("./data/zeropoint"),
            mesh: None,
        }
    }
}
