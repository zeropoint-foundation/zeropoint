//! Bridges `agent_zp::MeshTransport` → `zp_mesh::MeshNode` + `AgentTransport`.
//!
//! Maps agent-zp's mesh types to ZP's native mesh node, enabling agent sessions
//! to participate in the ZP peer network for receipt forwarding, capability
//! negotiation, and peer discovery.

use async_trait::async_trait;
use std::sync::Arc;

use agent_zp::{
    ExecutionReceipt,
};
use agent_zp::mesh::{
    AgentCapabilities as AgentCaps, MeshCapability, MeshError, MeshPeerInfo, MeshTransport,
    NegotiationResult as AgentNegResult,
};

use zp_mesh::transport::{
    AgentCapabilities as ZpCaps, AgentTransport, MeshNode, PeerInfo,
};
use zp_mesh::capability_exchange::CapabilityPolicy;
use zp_core::GrantedCapability;

/// Concrete `MeshTransport` backed by ZP's `MeshNode`.
///
/// Wraps an existing `MeshNode` to provide agent sessions with mesh
/// connectivity for receipt forwarding and peer discovery.
pub struct ZpMeshTransport {
    node: Arc<MeshNode>,
    capability_policy: CapabilityPolicy,
}

impl ZpMeshTransport {
    pub fn new(node: Arc<MeshNode>) -> Self {
        Self {
            node,
            capability_policy: CapabilityPolicy::deny_all(),
        }
    }

    pub fn with_capability_policy(mut self, policy: CapabilityPolicy) -> Self {
        self.capability_policy = policy;
        self
    }

    /// Map agent-zp capabilities → ZP capabilities for announcement.
    fn map_capabilities(caps: &AgentCaps) -> ZpCaps {
        ZpCaps {
            name: caps.name.clone(),
            version: caps.version.clone(),
            receipt_types: caps.receipt_types.clone(),
            skills: caps.skills.clone(),
            actor_type: caps.actor_type.clone(),
            trust_tier: caps.trust_tier.clone(),
        }
    }

    /// Map ZP peer info → agent-zp peer info.
    fn map_peer_info(peer: &PeerInfo) -> MeshPeerInfo {
        MeshPeerInfo {
            address: peer.address.clone(),
            hops: peer.hops,
            last_seen: peer.last_seen,
            capabilities: peer.capabilities.as_ref().map(|c| AgentCaps {
                name: c.name.clone(),
                version: c.version.clone(),
                receipt_types: c.receipt_types.clone(),
                skills: c.skills.clone(),
                actor_type: c.actor_type.clone(),
                trust_tier: c.trust_tier.clone(),
            }),
            has_link: peer.has_link,
        }
    }

    /// Map agent-zp mesh capability → ZP granted capability.
    fn map_mesh_cap(cap: &MeshCapability) -> GrantedCapability {
        GrantedCapability::Custom {
            name: cap.capability_type.clone(),
            parameters: serde_json::json!({
                "scope": cap.scope,
                "constraints": cap.constraints,
            }),
        }
    }

    /// Build a receipt suitable for mesh forwarding from an agent-zp receipt.
    fn build_zp_receipt(receipt: &ExecutionReceipt) -> zp_receipt::Receipt {
        use zp_receipt::{
            Action, ActionType, ExecutorType, ReceiptBuilder, ReceiptType, Status,
            TrustGrade,
        };

        let status = if receipt.success {
            Status::Success
        } else {
            Status::Failed
        };

        let started_at = receipt.completed_at
            - chrono::Duration::milliseconds(receipt.timing.wall_ms as i64);

        ReceiptBuilder::new(ReceiptType::Execution, &receipt.agent_id)
            .status(status)
            .trust_grade(TrustGrade::C)
            .executor_type(ExecutorType::Agent)
            .runtime(&receipt.runtime)
            .action(Action {
                action_type: ActionType::ToolCall,
                name: Some(receipt.runtime.clone()),
                input_hash: Some(receipt.input_hash.clone()),
                output_hash: Some(receipt.output_hash.clone()),
                exit_code: Some(receipt.exit_code),
                detail: None,
            })
            .timing(started_at, receipt.completed_at)
            .finalize()
    }
}

#[async_trait]
impl MeshTransport for ZpMeshTransport {
    fn address(&self) -> String {
        self.node.identity().address()
    }

    async fn announce(&self, capabilities: &AgentCaps) -> Result<(), MeshError> {
        let zp_caps = Self::map_capabilities(capabilities);
        self.node
            .announce(&zp_caps)
            .await
            .map_err(|e| MeshError::Other(e.to_string()))
    }

    async fn discover_peers(&self) -> Result<Vec<MeshPeerInfo>, MeshError> {
        let peers = self.node.known_peers().await;
        Ok(peers.iter().map(Self::map_peer_info).collect())
    }

    async fn establish_link(
        &self,
        peer_address: &str,
        our_capabilities: &[MeshCapability],
        requested_capabilities: &[MeshCapability],
    ) -> Result<AgentNegResult, MeshError> {
        use zp_mesh::capability_exchange::CapabilityRequest;

        // Build capability requests from the agent-zp mesh capabilities
        let our_request = CapabilityRequest {
            requested: requested_capabilities
                .iter()
                .map(Self::map_mesh_cap)
                .collect(),
            offered: our_capabilities
                .iter()
                .map(Self::map_mesh_cap)
                .collect(),
            claimed_tier: zp_core::TrustTier::Tier1,
        };
        let their_request = CapabilityRequest {
            requested: our_capabilities
                .iter()
                .map(Self::map_mesh_cap)
                .collect(),
            offered: requested_capabilities
                .iter()
                .map(Self::map_mesh_cap)
                .collect(),
            claimed_tier: zp_core::TrustTier::Tier1,
        };

        // Establish link via MeshNode — resolves peer by address from registry
        let result = self
            .node
            .establish_link_by_address(
                peer_address,
                &self.capability_policy,
                &our_request,
                &their_request,
            )
            .await
            .map_err(|e| MeshError::LinkFailed(e.to_string()))?;

        // Map ZP negotiation result → agent-zp result
        Ok(AgentNegResult {
            granted_to_us: result
                .initiator_grants
                .iter()
                .map(|g| MeshCapability {
                    capability_type: format!("{:?}", g.capability),
                    scope: vec![],
                    constraints: vec![],
                })
                .collect(),
            granted_to_peer: result
                .responder_grants
                .iter()
                .map(|g| MeshCapability {
                    capability_type: format!("{:?}", g.capability),
                    scope: vec![],
                    constraints: vec![],
                })
                .collect(),
            denied: result
                .denied
                .iter()
                .map(|d| {
                    (
                        MeshCapability {
                            capability_type: format!("{:?}", d.capability),
                            scope: vec![],
                            constraints: vec![],
                        },
                        d.reason.clone(),
                    )
                })
                .collect(),
            effective_tier: format!("{:?}", result.effective_tier),
        })
    }

    async fn forward_receipt(
        &self,
        peer_address: &str,
        receipt: &ExecutionReceipt,
    ) -> Result<(), MeshError> {
        let zp_receipt = Self::build_zp_receipt(receipt);
        self.node
            .send_receipt(peer_address, &zp_receipt)
            .await
            .map_err(|e| MeshError::ForwardFailed(e.to_string()))
    }

    async fn broadcast_receipt(&self, receipt: &ExecutionReceipt) -> Result<(), MeshError> {
        let zp_receipt = Self::build_zp_receipt(receipt);
        self.node
            .broadcast_receipt(&zp_receipt)
            .await
            .map_err(|e| MeshError::ForwardFailed(e.to_string()))
    }

    async fn is_reachable(&self, peer_address: &str) -> bool {
        self.node.is_reachable(peer_address).await
    }

    async fn known_peers(&self) -> Vec<MeshPeerInfo> {
        let peers = self.node.known_peers().await;
        peers.iter().map(Self::map_peer_info).collect()
    }
}
