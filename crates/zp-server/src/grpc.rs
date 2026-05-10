//! gRPC service handlers — Phase 2b foothold (NodeStatus pilot).
//!
//! Per Architecture II.13 (pure gRPC, HTTP/JSON deprecated), this module
//! is the new outer surface for zp-server. Service handlers translate
//! between the gRPC verb set (`zp_verbs::*`) and the substrate's internal
//! types (`AppState`, `AuditStore`, etc.).
//!
//! Per Architecture II.0 (contracts singular, implementations plural),
//! this is an adapter: it imports the verb-set *port* (`zp_verbs`) and
//! adapts substrate state to it. The contract lives in `proto/v1/`; the
//! adapter does not.
//!
//! Phase 2b lands one service at a time. NodeStatus is the pilot — small
//! verb count, mostly read-only, validates the architectural shape:
//!   - `tonic::transport::Server` runs alongside `axum::serve` on a
//!     separate listener (axum on `port`, gRPC on `port + 1`)
//!   - Handlers access `AppState` via `Arc` clone (same pattern as axum)
//!   - Request/response types come from the codegen target (`zp_verbs`)
//!
//! Only `GetNodeStats` is implemented in this commit. The other nine
//! NodeStatus verbs return `Status::unimplemented(...)`. Each will land
//! as a focused follow-up commit:
//!
//!   - `GetIdentity`            — needs node signing (SignedIdentity)
//!   - `GetSecurityPosture`     — needs signing + posture engine wiring
//!   - `GetTopology`            — needs signing + mesh topology view
//!   - `RegisterBlastRadius`    — needs receipt issuance + chain append
//!   - `GetBlastRadius`         — needs signing + tracker query
//!   - `ReportCompromise`       — needs receipt issuance + chain append
//!   - `ListFleetNodes`         — pagination + node_registry query
//!   - `GetFleetNode`           — needs signing + node_registry query
//!   - `DeregisterFleetNode`    — needs receipt issuance + chain append

use std::time::SystemTime;

use prost_types::Timestamp;
use tonic::{Request, Response, Status};

use zp_verbs::nodestatus::node_status_server::NodeStatus;
use zp_verbs::nodestatus::{
    BlastRadiusReceipt, CompromiseReceipt, DeregisterFleetNodeRequest, FleetNodesEnvelope,
    GetBlastRadiusRequest, GetFleetNodeRequest, GetIdentityRequest, GetNodeStatsRequest,
    GetSecurityPostureRequest, GetTopologyRequest, ListFleetNodesRequest,
    NodeDeregistrationReceipt, NodeStatsEnvelope, RegisterBlastRadiusRequest,
    ReportCompromiseRequest, SignedBlastRadiusEnvelope, SignedFleetNodeEnvelope,
    SignedIdentity, SignedSecurityPosture, SignedTopologyEnvelope,
};

use crate::AppState;

/// gRPC handler for the `NodeStatus` service.
///
/// Holds a clone of [`AppState`]. Cloning is cheap (`Arc<AppStateInner>`
/// under the hood); every invocation observes the same shared state as
/// the axum handlers, with no separate synchronization needed.
#[derive(Clone)]
pub struct NodeStatusHandler {
    state: AppState,
}

impl NodeStatusHandler {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl NodeStatus for NodeStatusHandler {
    /// Return runtime statistics for this node.
    ///
    /// Plain envelope (no signature) — fast-polling observation, does not
    /// drive trust-critical decisions.
    async fn get_node_stats(
        &self,
        _request: Request<GetNodeStatsRequest>,
    ) -> Result<Response<NodeStatsEnvelope>, Status> {
        // Audit chain length. Mirrors the existing HTTP `stats_handler`
        // (lib.rs:2463) for behavioral equivalence — including its
        // truncation at 10_000 entries. Replacing this with an O(1)
        // chain_head().chain_position lookup is a follow-up.
        let chain_length = {
            let store = self
                .state
                .0
                .audit_store
                .lock()
                .map_err(|_| Status::internal("audit_store mutex poisoned"))?;
            store.export_chain(10_000).map(|v| v.len()).unwrap_or(0) as u64
        };

        // Active capabilities = grants currently held in memory.
        let active_capabilities = self
            .state
            .0
            .grants
            .lock()
            .map_err(|_| Status::internal("grants mutex poisoned"))?
            .len() as u32;

        Ok(Response::new(NodeStatsEnvelope {
            // `receipts_issued` and `chain_length` are equivalent in v1
            // (every chain entry is a receipt). Phase 3 may differentiate
            // when compensating receipts land — issued counts compensations,
            // length stays the chain head position.
            receipts_issued: chain_length,
            chain_length,
            // TODO: track server start instant on AppStateInner and
            // compute uptime here. Default 0 for the pilot.
            uptime_seconds: 0,
            // TODO: query node_registry for currently-reachable peers.
            // Default 0 for the pilot.
            active_peers: 0,
            active_capabilities,
            stats_at: Some(now_timestamp()),
        }))
    }

    // ── Verbs deferred to Phase 2b follow-up commits ────────────────────

    async fn get_identity(
        &self,
        _request: Request<GetIdentityRequest>,
    ) -> Result<Response<SignedIdentity>, Status> {
        Err(Status::unimplemented(
            "NodeStatus.GetIdentity — Phase 2b follow-up (needs node signing)",
        ))
    }

    async fn get_security_posture(
        &self,
        _request: Request<GetSecurityPostureRequest>,
    ) -> Result<Response<SignedSecurityPosture>, Status> {
        Err(Status::unimplemented(
            "NodeStatus.GetSecurityPosture — Phase 2b follow-up (needs signing + posture engine)",
        ))
    }

    async fn get_topology(
        &self,
        _request: Request<GetTopologyRequest>,
    ) -> Result<Response<SignedTopologyEnvelope>, Status> {
        Err(Status::unimplemented(
            "NodeStatus.GetTopology — Phase 2b follow-up (needs signing + mesh topology)",
        ))
    }

    async fn register_blast_radius(
        &self,
        _request: Request<RegisterBlastRadiusRequest>,
    ) -> Result<Response<BlastRadiusReceipt>, Status> {
        Err(Status::unimplemented(
            "NodeStatus.RegisterBlastRadius — Phase 2b follow-up (needs receipt issuance)",
        ))
    }

    async fn get_blast_radius(
        &self,
        _request: Request<GetBlastRadiusRequest>,
    ) -> Result<Response<SignedBlastRadiusEnvelope>, Status> {
        Err(Status::unimplemented(
            "NodeStatus.GetBlastRadius — Phase 2b follow-up (needs signing + tracker query)",
        ))
    }

    async fn report_compromise(
        &self,
        _request: Request<ReportCompromiseRequest>,
    ) -> Result<Response<CompromiseReceipt>, Status> {
        Err(Status::unimplemented(
            "NodeStatus.ReportCompromise — Phase 2b follow-up (needs receipt issuance)",
        ))
    }

    async fn list_fleet_nodes(
        &self,
        _request: Request<ListFleetNodesRequest>,
    ) -> Result<Response<FleetNodesEnvelope>, Status> {
        Err(Status::unimplemented(
            "NodeStatus.ListFleetNodes — Phase 2b follow-up (needs node_registry pagination)",
        ))
    }

    async fn get_fleet_node(
        &self,
        _request: Request<GetFleetNodeRequest>,
    ) -> Result<Response<SignedFleetNodeEnvelope>, Status> {
        Err(Status::unimplemented(
            "NodeStatus.GetFleetNode — Phase 2b follow-up (needs signing + node_registry query)",
        ))
    }

    async fn deregister_fleet_node(
        &self,
        _request: Request<DeregisterFleetNodeRequest>,
    ) -> Result<Response<NodeDeregistrationReceipt>, Status> {
        Err(Status::unimplemented(
            "NodeStatus.DeregisterFleetNode — Phase 2b follow-up (needs receipt issuance)",
        ))
    }
}

/// Convert `SystemTime::now()` to `prost_types::Timestamp`.
fn now_timestamp() -> Timestamp {
    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    Timestamp {
        seconds: dur.as_secs() as i64,
        nanos: dur.subsec_nanos() as i32,
    }
}
