//! Fleet node registry — tracks fleet-wide node status, health, and capabilities.
//!
//! The `NodeRegistry` maintains a live view of all known ZeroPoint nodes in a fleet,
//! tracking heartbeat timestamps, trust tiers, policy versions, and online/offline
//! status. Nodes register via heartbeat and are marked stale after a configurable
//! timeout.
//!
//! ## Design
//!
//! ```text
//! ┌──────────────────────────────────────────┐
//! │  NodeRegistry                             │
//! │                                           │
//! │  node_id → FleetNode {                    │
//! │    status: Online | Stale | Offline,      │
//! │    trust_tier, policy_version,            │
//! │    last_heartbeat, capabilities,          │
//! │    endpoint                               │
//! │  }                                        │
//! │                                           │
//! │  heartbeat() → register / refresh         │
//! │  sweep()     → mark stale / offline       │
//! │  summary()   → fleet-wide status          │
//! └──────────────────────────────────────────┘
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// How long before a node is considered stale (no heartbeat received).
pub const DEFAULT_STALE_TIMEOUT_SECS: u64 = 90;

/// How long after going stale before a node is marked offline.
pub const DEFAULT_OFFLINE_TIMEOUT_SECS: u64 = 300;

/// Node operational status within the fleet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeStatus {
    /// Actively sending heartbeats.
    Online,
    /// Heartbeat overdue but within offline threshold.
    Stale,
    /// No heartbeat for extended period — assumed down.
    Offline,
}

impl std::fmt::Display for NodeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeStatus::Online => write!(f, "online"),
            NodeStatus::Stale => write!(f, "stale"),
            NodeStatus::Offline => write!(f, "offline"),
        }
    }
}

/// A node in the fleet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetNode {
    /// Unique node identifier (hex-encoded destination hash).
    pub node_id: String,
    /// Human-readable node name.
    pub name: String,
    /// Current operational status.
    pub status: NodeStatus,
    /// Trust tier the node operates at.
    pub trust_tier: u8,
    /// Policy version hash the node is running.
    pub policy_version: String,
    /// Network endpoint (e.g., "10.0.1.5:9473" or mesh destination hash).
    pub endpoint: String,
    /// Node capabilities (e.g., ["receipts", "delegation", "policy-sync"]).
    pub capabilities: Vec<String>,
    /// When this node first registered.
    pub registered_at: DateTime<Utc>,
    /// Last heartbeat timestamp.
    pub last_heartbeat: DateTime<Utc>,
    /// Number of heartbeats received since registration.
    pub heartbeat_count: u64,
}

/// Heartbeat payload sent by fleet nodes to register or refresh.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeHeartbeat {
    /// Unique node identifier.
    pub node_id: String,
    /// Human-readable name.
    pub name: String,
    /// Trust tier.
    pub trust_tier: u8,
    /// Policy version hash.
    pub policy_version: String,
    /// Reachable endpoint.
    pub endpoint: String,
    /// Node capabilities.
    pub capabilities: Vec<String>,
}

/// Fleet-wide summary statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetSummary {
    /// Total registered nodes.
    pub total_nodes: usize,
    /// Currently online.
    pub online: usize,
    /// Heartbeat overdue.
    pub stale: usize,
    /// Assumed offline.
    pub offline: usize,
    /// Distinct policy versions in fleet.
    pub policy_versions: Vec<String>,
    /// Timestamp of this summary.
    pub timestamp: String,
}

/// Configuration for the node registry.
#[derive(Debug, Clone)]
pub struct RegistryConfig {
    /// Seconds without heartbeat before marking stale.
    pub stale_timeout: Duration,
    /// Seconds without heartbeat before marking offline.
    pub offline_timeout: Duration,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            stale_timeout: Duration::from_secs(DEFAULT_STALE_TIMEOUT_SECS),
            offline_timeout: Duration::from_secs(DEFAULT_OFFLINE_TIMEOUT_SECS),
        }
    }
}

/// Fleet node registry — maintains live view of all nodes.
#[derive(Debug, Clone)]
pub struct NodeRegistry {
    nodes: Arc<RwLock<HashMap<String, FleetNode>>>,
    config: RegistryConfig,
}

impl NodeRegistry {
    /// Create a new empty registry with default config.
    pub fn new() -> Self {
        Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
            config: RegistryConfig::default(),
        }
    }

    /// Create a registry with custom timeouts.
    pub fn with_config(config: RegistryConfig) -> Self {
        Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Process a heartbeat — registers new nodes or refreshes existing ones.
    pub async fn heartbeat(&self, hb: NodeHeartbeat) {
        let mut nodes = self.nodes.write().await;
        let now = Utc::now();

        if let Some(node) = nodes.get_mut(&hb.node_id) {
            // Refresh existing node
            node.status = NodeStatus::Online;
            node.trust_tier = hb.trust_tier;
            node.policy_version = hb.policy_version;
            node.endpoint = hb.endpoint;
            node.capabilities = hb.capabilities;
            node.last_heartbeat = now;
            node.heartbeat_count += 1;
            debug!(node_id = %node.node_id, count = node.heartbeat_count, "node heartbeat refreshed");
        } else {
            // Register new node
            let node = FleetNode {
                node_id: hb.node_id.clone(),
                name: hb.name,
                status: NodeStatus::Online,
                trust_tier: hb.trust_tier,
                policy_version: hb.policy_version,
                endpoint: hb.endpoint,
                capabilities: hb.capabilities,
                registered_at: now,
                last_heartbeat: now,
                heartbeat_count: 1,
            };
            info!(node_id = %node.node_id, name = %node.name, "new fleet node registered");
            nodes.insert(node.node_id.clone(), node);
        }
    }

    /// Sweep all nodes — mark stale or offline based on heartbeat age.
    pub async fn sweep(&self) {
        let mut nodes = self.nodes.write().await;
        let now = Utc::now();

        for node in nodes.values_mut() {
            let age = now
                .signed_duration_since(node.last_heartbeat)
                .to_std()
                .unwrap_or(Duration::ZERO);

            if age >= self.config.offline_timeout {
                if node.status != NodeStatus::Offline {
                    warn!(node_id = %node.node_id, age_secs = age.as_secs(), "node marked offline");
                    node.status = NodeStatus::Offline;
                }
            } else if age >= self.config.stale_timeout {
                if node.status != NodeStatus::Stale {
                    warn!(node_id = %node.node_id, age_secs = age.as_secs(), "node marked stale");
                    node.status = NodeStatus::Stale;
                }
            }
        }
    }

    /// Get a snapshot of all nodes.
    pub async fn list_nodes(&self) -> Vec<FleetNode> {
        let nodes = self.nodes.read().await;
        nodes.values().cloned().collect()
    }

    /// Get a single node by ID.
    pub async fn get_node(&self, node_id: &str) -> Option<FleetNode> {
        let nodes = self.nodes.read().await;
        nodes.get(node_id).cloned()
    }

    /// Get online nodes only.
    pub async fn online_nodes(&self) -> Vec<FleetNode> {
        let nodes = self.nodes.read().await;
        nodes
            .values()
            .filter(|n| n.status == NodeStatus::Online)
            .cloned()
            .collect()
    }

    /// Get nodes running a specific policy version.
    pub async fn nodes_with_policy(&self, version: &str) -> Vec<FleetNode> {
        let nodes = self.nodes.read().await;
        nodes
            .values()
            .filter(|n| n.policy_version == version)
            .cloned()
            .collect()
    }

    /// Remove a node from the registry.
    pub async fn deregister(&self, node_id: &str) -> bool {
        let mut nodes = self.nodes.write().await;
        let removed = nodes.remove(node_id).is_some();
        if removed {
            info!(node_id = %node_id, "node deregistered from fleet");
        }
        removed
    }

    /// Generate fleet-wide summary statistics.
    pub async fn summary(&self) -> FleetSummary {
        let nodes = self.nodes.read().await;
        let mut online = 0;
        let mut stale = 0;
        let mut offline = 0;
        let mut versions = std::collections::HashSet::new();

        for node in nodes.values() {
            match node.status {
                NodeStatus::Online => online += 1,
                NodeStatus::Stale => stale += 1,
                NodeStatus::Offline => offline += 1,
            }
            versions.insert(node.policy_version.clone());
        }

        FleetSummary {
            total_nodes: nodes.len(),
            online,
            stale,
            offline,
            policy_versions: versions.into_iter().collect(),
            timestamp: Utc::now().to_rfc3339(),
        }
    }
}

impl Default for NodeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_heartbeat(id: &str, name: &str) -> NodeHeartbeat {
        NodeHeartbeat {
            node_id: id.to_string(),
            name: name.to_string(),
            trust_tier: 1,
            policy_version: "v3.0.0-abc123".to_string(),
            endpoint: format!("10.0.1.{}:9473", id),
            capabilities: vec!["receipts".to_string(), "delegation".to_string()],
        }
    }

    #[tokio::test]
    async fn heartbeat_registers_new_node() {
        let registry = NodeRegistry::new();
        registry.heartbeat(test_heartbeat("node-1", "Alpha")).await;

        let nodes = registry.list_nodes().await;
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].node_id, "node-1");
        assert_eq!(nodes[0].name, "Alpha");
        assert_eq!(nodes[0].status, NodeStatus::Online);
        assert_eq!(nodes[0].heartbeat_count, 1);
    }

    #[tokio::test]
    async fn heartbeat_refreshes_existing_node() {
        let registry = NodeRegistry::new();
        registry.heartbeat(test_heartbeat("node-1", "Alpha")).await;
        registry.heartbeat(test_heartbeat("node-1", "Alpha")).await;

        let node = registry.get_node("node-1").await.unwrap();
        assert_eq!(node.heartbeat_count, 2);
        assert_eq!(node.status, NodeStatus::Online);
    }

    #[tokio::test]
    async fn sweep_marks_stale_and_offline() {
        let config = RegistryConfig {
            stale_timeout: Duration::from_secs(0), // immediate for testing
            offline_timeout: Duration::from_secs(0),
        };
        let registry = NodeRegistry::with_config(config);
        registry.heartbeat(test_heartbeat("node-1", "Alpha")).await;

        // After sweep with zero timeouts, node should be offline
        registry.sweep().await;
        let node = registry.get_node("node-1").await.unwrap();
        assert_eq!(node.status, NodeStatus::Offline);
    }

    #[tokio::test]
    async fn deregister_removes_node() {
        let registry = NodeRegistry::new();
        registry.heartbeat(test_heartbeat("node-1", "Alpha")).await;
        assert!(registry.deregister("node-1").await);
        assert!(registry.get_node("node-1").await.is_none());
        assert!(!registry.deregister("node-1").await); // already gone
    }

    #[tokio::test]
    async fn summary_counts_by_status() {
        let registry = NodeRegistry::new();
        registry.heartbeat(test_heartbeat("n1", "A")).await;
        registry.heartbeat(test_heartbeat("n2", "B")).await;
        registry.heartbeat(test_heartbeat("n3", "C")).await;

        let summary = registry.summary().await;
        assert_eq!(summary.total_nodes, 3);
        assert_eq!(summary.online, 3);
        assert_eq!(summary.stale, 0);
        assert_eq!(summary.offline, 0);
    }

    #[tokio::test]
    async fn online_nodes_filters_correctly() {
        let config = RegistryConfig {
            stale_timeout: Duration::from_secs(0),
            offline_timeout: Duration::from_secs(9999),
        };
        let registry = NodeRegistry::with_config(config);
        registry.heartbeat(test_heartbeat("n1", "A")).await;

        // Sweep makes it stale (not offline since offline_timeout is large)
        registry.sweep().await;

        // Now add a fresh node
        registry.heartbeat(test_heartbeat("n2", "B")).await;

        let online = registry.online_nodes().await;
        assert_eq!(online.len(), 1);
        assert_eq!(online[0].node_id, "n2");
    }

    #[tokio::test]
    async fn nodes_with_policy_filters_by_version() {
        let registry = NodeRegistry::new();
        registry.heartbeat(test_heartbeat("n1", "A")).await;

        let mut hb2 = test_heartbeat("n2", "B");
        hb2.policy_version = "v2.9.0-old".to_string();
        registry.heartbeat(hb2).await;

        let v3_nodes = registry.nodes_with_policy("v3.0.0-abc123").await;
        assert_eq!(v3_nodes.len(), 1);
        assert_eq!(v3_nodes[0].node_id, "n1");
    }
}
