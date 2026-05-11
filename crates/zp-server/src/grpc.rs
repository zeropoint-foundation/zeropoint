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

use chrono::{DateTime, Utc};
use prost_types::Timestamp;
use tonic::{Request, Response, Status};

use zp_verbs::common::PageInfo;
use zp_verbs::nodestatus::node_status_server::NodeStatus;
use zp_verbs::nodestatus::{
    BlastRadiusReceipt, CompromiseReceipt, DeregisterFleetNodeRequest, FleetNodeSummary,
    FleetNodesEnvelope, GetBlastRadiusRequest, GetFleetNodeRequest, GetIdentityRequest,
    GetNodeStatsRequest, GetSecurityPostureRequest, GetTopologyRequest, ListFleetNodesRequest,
    NodeDeregistrationReceipt, NodeStatsEnvelope, RegisterBlastRadiusRequest,
    ReportCompromiseRequest, SignedBlastRadiusEnvelope, SignedFleetNodeEnvelope, SignedIdentity,
    SignedSecurityPosture, SignedTopologyEnvelope,
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

    /// List fleet nodes registered with this node, with optional status
    /// filtering and offset-based pagination.
    ///
    /// Plain envelope (no signature) — observation-only list, may be
    /// polled by dashboards.
    async fn list_fleet_nodes(
        &self,
        request: Request<ListFleetNodesRequest>,
    ) -> Result<Response<FleetNodesEnvelope>, Status> {
        let req = request.into_inner();

        // Snapshot the registry. `list_nodes()` clones under an `RwLock`
        // read, so the returned Vec is independent of subsequent mutations.
        let mut all_nodes = self.state.0.node_registry.list_nodes().await;

        // Status filter — empty string means "no filter, return all".
        // Matches the lowercase Display strings: "online" / "stale" / "offline".
        if !req.status_filter.is_empty() {
            all_nodes.retain(|n| n.status.to_string() == req.status_filter);
        }

        let total = all_nodes.len() as u64;

        // Offset pagination. `page_token` carries the start index as a
        // decimal string; empty token = first page. `page_size` of 0 means
        // "server default" (100, per common.proto convention).
        //
        // TODO: cursor-based pagination once we need stability across
        // mutations. Offset pagination is fine for v1 — the registry only
        // mutates on heartbeat receipt, and dashboards re-poll often
        // enough that consistency-on-page-boundary is not load-bearing.
        let page_request = req.page.unwrap_or_default();
        let page_size = if page_request.page_size == 0 {
            100
        } else {
            page_request.page_size as usize
        };
        let start: usize = if page_request.page_token.is_empty() {
            0
        } else {
            page_request.page_token.parse().map_err(|_| {
                Status::invalid_argument(format!(
                    "page_token must be a non-negative integer, got: {:?}",
                    page_request.page_token
                ))
            })?
        };

        let end = start.saturating_add(page_size).min(all_nodes.len());
        let nodes: Vec<FleetNodeSummary> = if start < all_nodes.len() {
            all_nodes[start..end]
                .iter()
                .map(|n| FleetNodeSummary {
                    node_id: n.node_id.clone(),
                    node_name: n.name.clone(),
                    public_key: n.public_key.clone(),
                    status: n.status.to_string(),
                    last_heartbeat: Some(datetime_to_timestamp(&n.last_heartbeat)),
                })
                .collect()
        } else {
            Vec::new()
        };

        let next_page_token = if end < all_nodes.len() {
            end.to_string()
        } else {
            String::new()
        };

        Ok(Response::new(FleetNodesEnvelope {
            nodes,
            page: Some(PageInfo {
                next_page_token,
                total_size: total,
            }),
        }))
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

/// Convert a `chrono::DateTime<Utc>` to `prost_types::Timestamp`.
///
/// Used wherever the substrate's internal time type (chrono) meets the
/// proto wire type (prost_types). Sub-second precision preserved.
fn datetime_to_timestamp(dt: &DateTime<Utc>) -> Timestamp {
    Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    }
}
