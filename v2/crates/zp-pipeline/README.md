# zp-pipeline

Central orchestrator for ZeroPoint v2 — wires policy evaluation, LLM interaction, skill matching, audit logging, and mesh networking into a single request-handling flow.

## Overview

The Pipeline is where everything comes together. A request enters, gets policy-evaluated by the GovernanceGate, matched to skills, routed to an LLM provider, executed with tool calls, audit-logged, and optionally forwarded to mesh peers as a receipt. The `MeshBridge` connects the pipeline to the mesh transport layer for cross-agent governance.

## Modules

### pipeline.rs — Request Handler

`Pipeline::handle()` implements the core 14-step flow:

1. Build `PolicyContext` from request action, trust tier, channel, and conversation
2. Evaluate policy via `PolicyEngine` → `PolicyDecision`
3. Check for blocks — return error if policy blocks the action
4. Match skills to request content via `SkillMatcher`
5. Build capabilities for matched skills at the current trust tier
6. Select LLM model class based on risk level
7. Build prompt with conversation history and active capabilities
8. Select LLM provider from pool
9. Get initial LLM completion
10. Tool invocation loop (up to 10 iterations): execute tools, collect results and receipts, request LLM continuation
11. Build response with all tool calls and results
12. Audit-log the response
13. Store conversation history
14. Forward receipt to mesh peers (if mesh is configured)

### mesh_bridge.rs — Pipeline ↔ Mesh Bridge

`MeshBridge` wraps an `Arc<MeshNode>` and provides the pipeline-level interface to the mesh network.

**Receipt handling.** `forward_receipt()` broadcasts receipts to all known peers. `handle_inbound_receipt()` validates incoming receipts (non-empty ID, valid status), checks sender reputation (Poor peers are rejected), stores the receipt, and records a reputation signal. `received_receipts()`, `accepted_receipts()`, and `receipts_from_peer()` query stored receipts.

**Delegation chain verification.** `handle_inbound_delegation()` validates inbound delegations, checks sender reputation (Fair threshold), reconstructs the grant chain by looking up parent grants, verifies the full chain via `DelegationChain::verify()` (8 invariants), stores verified chains, and records reputation signals. `verify_delegation_chain()` validates arbitrary grant chains. `check_grant_authorization()` verifies a grant covers a specific action with all constraints satisfied.

**Audit verification.** `challenge_peer_audit()` sends an audit challenge requesting recent entries. `handle_audit_response()` verifies the returned chain segment, stores an attestation, and records a reputation signal based on chain validity. `respond_to_audit_challenge()` builds and sends a response from local audit entries.

**Capability negotiation.** `establish_peer_link()` performs the 3-packet handshake and runs bilateral capability negotiation. `peer_authorizes_action()` checks if a peer's grants cover a specific action.

**Multi-dimensional reputation.** `peer_reputation()` returns the composite score for a peer. `peer_trust_snapshot()` aggregates all dimensions (audit, delegation, policy, receipt scores plus link state and attestation count) into a `PeerTrustSnapshot`. `build_peer_context_for_receipt()` constructs the `MeshPeerContext` that the `ReputationGateRule` consumes for policy decisions. Individual signal recording methods: `record_receipt_reputation()`, `record_delegation_reputation()`, `record_audit_reputation()`, `record_policy_compliance()`.

### config.rs — Configuration

`PipelineConfig` specifies operator identity, trust tier, data directory, and optional `MeshConfig`. `MeshConfig` controls identity secret (for deterministic identity), receipt/audit forwarding flags, TCP listen address, TCP peer addresses, and poll interval.

## Mesh Initialization

`Pipeline::init_mesh()` wires the full mesh lifecycle:

1. Create `MeshIdentity` (deterministic from secret or random)
2. Create `MeshNode` and load persistent state from SQLite
3. Bind TCP listener and connect to configured peers
4. Create `MeshBridge` with forwarding configuration
5. Start `MeshRuntime` (background Tokio task polling interfaces)
6. Spawn inbound envelope processor (routes receipts, delegations, audit messages, and announcements from the runtime channel through the bridge)

`shutdown_mesh()` stops the runtime and `save_mesh_state()` persists all mesh state to SQLite.

## Integration Tests

The crate includes 59 integration tests covering receipt exchange, delegation chain verification, audit challenge/response, capability negotiation, multi-dimensional reputation, policy evaluation with mesh context, runtime dispatch, SQLite persistence, multi-node scenarios (2-node and 3-node), and persist-and-restore across node restarts. These tests exercise the full governance flow across crate boundaries.
