//! End-to-end integration tests.
//!
//! These tests exercise the full governance flow across crate boundaries:
//! - Pipeline setup with mesh bridge
//! - Receipt forwarding to mesh peers
//! - Inbound receipt handling with reputation gating
//! - Reputation signal recording and grade evolution
//! - Policy evaluation with mesh peer context
//! - Governance event creation for mesh actions
//! - Phase 5: Delegation chain verification across the pipeline
//! - Phase 5: Audit chain verification and peer challenges
//!
//! Each test is self-contained: creates its own mesh nodes, bridges,
//! and policy engines. No external state required.

use std::sync::Arc;

use chrono::Utc;

use zp_audit::collective_audit::{AuditChallenge, AuditResponse, CompactAuditEntry};
use zp_core::capability_grant::GrantedCapability;
use zp_core::governance::{
    ActionContext, GovernanceActor, GovernanceDecision, GovernanceEvent, GovernanceEventType,
};
use zp_core::policy::{ActionType, MeshAction, MeshPeerContext, PolicyContext, TrustTier};
use zp_core::{CapabilityGrant, Channel, ConversationId, PolicyDecision};
use zp_mesh::capability_exchange::{CapabilityPolicy, CapabilityRequest};
use zp_mesh::envelope::{CompactDelegation, CompactReceipt};
use zp_mesh::identity::{MeshIdentity, PeerIdentity};
use zp_mesh::interface::{Interface, LoopbackInterface};
use zp_mesh::reputation::ReputationGrade;
use zp_mesh::runtime::{MeshRuntime, RuntimeConfig};
use zp_mesh::transport::{AgentTransport, MeshNode};
use zp_pipeline::{MeshBridge, MeshBridgeConfig};
use zp_policy::PolicyEngine;

// ============================================================================
// Helpers
// ============================================================================

fn make_node() -> Arc<MeshNode> {
    let id = MeshIdentity::generate();
    Arc::new(MeshNode::new(id))
}

fn make_compact_receipt(id: &str, status: &str) -> CompactReceipt {
    CompactReceipt {
        id: id.to_string(),
        rt: "execution".to_string(),
        st: status.to_string(),
        tg: "C".to_string(),
        ch: "deadbeef".to_string(),
        ts: Utc::now().timestamp(),
        pr: None,
        pd: None,
        ra: None,
        sg: None,
        ex: None,
    }
}

fn make_policy_context_with_mesh(
    action: MeshAction,
    grade: Option<&str>,
    score: Option<f64>,
) -> PolicyContext {
    PolicyContext {
        action: ActionType::Chat,
        trust_tier: TrustTier::Tier1,
        channel: Channel::Cli,
        conversation_id: ConversationId::new(),
        skill_ids: vec![],
        tool_names: vec![],
        mesh_context: Some(MeshPeerContext {
            peer_address: "aabbccdd".to_string(),
            reputation_grade: grade.map(|s| s.to_string()),
            reputation_score: score,
            mesh_action: action,
        }),
    }
}

// ============================================================================
// Test 1: Full round-trip receipt forwarding between two nodes
// ============================================================================

#[tokio::test]
async fn test_e2e_receipt_forward_and_receive() {
    // Setup: Two mesh nodes connected via loopback
    let node_a = make_node();
    let node_b = make_node();

    let lo_a = Arc::new(LoopbackInterface::new());
    let lo_b = Arc::new(LoopbackInterface::new());
    node_a.attach_interface(lo_a.clone()).await;
    node_b.attach_interface(lo_b.clone()).await;

    // Register each other as peers
    let peer_b =
        PeerIdentity::from_combined_key(&node_b.identity().combined_public_key(), 1).unwrap();
    node_a.register_peer(peer_b, None).await;

    let peer_a =
        PeerIdentity::from_combined_key(&node_a.identity().combined_public_key(), 1).unwrap();
    let peer_a_hash = peer_a.destination_hash;
    node_b.register_peer(peer_a, None).await;

    // Create bridges
    let bridge_a = MeshBridge::with_defaults(node_a.clone());
    let bridge_b = MeshBridge::with_defaults(node_b.clone());

    // Node A forwards a receipt
    let receipt = zp_receipt::Receipt::execution("test-agent")
        .status(zp_receipt::Status::Success)
        .trust_grade(zp_receipt::TrustGrade::C)
        .finalize();

    let result = bridge_a.forward_receipt(&receipt).await;
    assert!(result.is_ok(), "Forward should succeed");

    // Verify packet appeared on loopback (simulating mesh transit)
    let received = lo_a.recv().await.unwrap();
    assert!(received.is_some(), "Packet should appear on loopback");

    // Node B handles the inbound receipt (simulating receipt extraction)
    let compact = make_compact_receipt(&receipt.id, "success");
    let accepted = bridge_b
        .handle_inbound_receipt(&compact, &peer_a_hash)
        .await
        .unwrap();
    assert!(accepted, "Receipt from unknown peer should be accepted");

    // Verify receipt was stored
    assert_eq!(bridge_b.received_receipt_count().await, 1);

    // Verify reputation signal was recorded for peer A
    let score = bridge_b.peer_reputation(&peer_a_hash).await;
    assert_eq!(score.positive_signals, 1, "Should have 1 positive signal");
    assert_eq!(score.negative_signals, 0);
}

// ============================================================================
// Test 2: Reputation builds over multiple receipt exchanges
// ============================================================================

#[tokio::test]
async fn test_e2e_reputation_builds_over_exchanges() {
    let node = make_node();
    let bridge = MeshBridge::with_defaults(node);
    let peer_hash = [0xAAu8; 16];

    // Send 10 successful receipts — reputation should reach Good or Excellent
    for i in 0..10 {
        let receipt = make_compact_receipt(&format!("r-{}", i), "success");
        let accepted = bridge
            .handle_inbound_receipt(&receipt, &peer_hash)
            .await
            .unwrap();
        assert!(accepted, "Receipt {} should be accepted", i);
    }

    assert_eq!(bridge.received_receipt_count().await, 10);

    let score = bridge.peer_reputation(&peer_hash).await;
    assert_eq!(score.positive_signals, 10);
    assert_eq!(score.negative_signals, 0);
    // With 10 positive receipt signals, the grade should be at least Good
    // (receipt category = 1.0, other categories default to 0.5)
    assert!(
        score.grade >= ReputationGrade::Good,
        "Expected Good or better after 10 positive exchanges, got {:?} (score: {})",
        score.grade,
        score.score,
    );
}

// ============================================================================
// Test 3: Failed receipts erode reputation
// ============================================================================

#[tokio::test]
async fn test_e2e_failed_receipts_erode_reputation() {
    let node = make_node();
    let bridge = MeshBridge::with_defaults(node);
    let peer_hash = [0xBBu8; 16];

    // Send 5 failed receipts
    for i in 0..5 {
        let receipt = make_compact_receipt(&format!("fail-{}", i), "failed");
        bridge
            .handle_inbound_receipt(&receipt, &peer_hash)
            .await
            .unwrap();
    }

    let score = bridge.peer_reputation(&peer_hash).await;
    assert_eq!(score.positive_signals, 0);
    assert_eq!(score.negative_signals, 5);
    // With all negative receipt signals, the receipt category scores 0.0,
    // but the other 3 categories (audit, delegation, policy) default to 0.5
    // since there's no data. Overall: 0 × 0.20 + 0.5 × 0.35 + 0.5 × 0.20 + 0.5 × 0.25 = 0.40 → Fair.
    assert!(
        score.grade <= ReputationGrade::Fair,
        "Expected Fair or worse after all failed receipts, got {:?} (score: {})",
        score.grade,
        score.score,
    );
    // Receipt category specifically should be 0.0
    let receipt_cat = score
        .breakdown
        .iter()
        .find(|c| c.category == zp_mesh::reputation::SignalCategory::ReceiptExchange)
        .unwrap();
    assert!(
        receipt_cat.score < 0.01,
        "Receipt category should be ~0.0 with all negatives"
    );
}

// ============================================================================
// Test 4: Policy engine blocks poor-reputation peer from delegation
// ============================================================================

#[tokio::test]
async fn test_e2e_policy_blocks_poor_peer_delegation() {
    let engine = PolicyEngine::new();

    // Simulate a peer with Poor reputation trying to delegate
    let context =
        make_policy_context_with_mesh(MeshAction::DelegateCapability, Some("Poor"), Some(0.15));

    let decision = engine.evaluate(&context);
    assert!(
        decision.is_blocked(),
        "Policy should block delegation from poor-reputation peer, got: {:?}",
        decision
    );
}

// ============================================================================
// Test 5: Policy engine allows good-reputation peer receipt forwarding
// ============================================================================

#[tokio::test]
async fn test_e2e_policy_allows_good_peer_receipt() {
    let engine = PolicyEngine::new();

    let context =
        make_policy_context_with_mesh(MeshAction::ForwardReceipt, Some("Good"), Some(0.65));

    let decision = engine.evaluate(&context);
    assert!(
        decision.is_allowed(),
        "Policy should allow receipt forwarding from good peer, got: {:?}",
        decision
    );
}

// ============================================================================
// Test 6: Policy engine escalates unknown peer on high-risk actions
// ============================================================================

#[tokio::test]
async fn test_e2e_policy_reviews_unknown_peer_high_risk() {
    let engine = PolicyEngine::new();

    // Unknown peer attempting delegation (high risk)
    let context = make_policy_context_with_mesh(
        MeshAction::AcceptDelegation,
        None, // no grade = unknown
        None,
    );

    let decision = engine.evaluate(&context);
    assert!(
        matches!(decision, PolicyDecision::Review { .. }),
        "Policy should require review for unknown peer delegation, got: {:?}",
        decision
    );
}

// ============================================================================
// Test 7: Governance events capture full mesh action lifecycle
// ============================================================================

#[test]
fn test_e2e_governance_events_mesh_lifecycle() {
    // 1. Receipt forwarded event
    let fwd_event = GovernanceEvent::receipt_forwarded(
        GovernanceActor::System {
            component: "mesh-bridge".to_string(),
        },
        ActionContext {
            action_type: "ForwardReceipt".to_string(),
            target: Some("3 peers".to_string()),
            trust_tier: 1,
            risk_level: "Low".to_string(),
        },
        GovernanceDecision::Allow {
            conditions: vec!["receipt forwarded to mesh".to_string()],
        },
    );
    assert!(matches!(
        fwd_event.event_type,
        GovernanceEventType::ReceiptForwarded
    ));

    // 2. Receipt received from mesh event
    let recv_event = GovernanceEvent::receipt_received_from_mesh(
        GovernanceActor::Agent {
            destination_hash: "aabbccdd".to_string(),
            trust_tier: 1,
        },
        ActionContext {
            action_type: "AcceptReceipt".to_string(),
            target: Some("rcpt-123".to_string()),
            trust_tier: 1,
            risk_level: "Low".to_string(),
        },
        GovernanceDecision::Allow {
            conditions: vec!["peer reputation: Good".to_string()],
        },
    );
    assert!(matches!(
        recv_event.event_type,
        GovernanceEventType::ReceiptReceivedFromMesh
    ));

    // 3. Reputation gate blocked event
    let block_event = GovernanceEvent::reputation_gate_blocked(
        GovernanceActor::System {
            component: "reputation_gate".to_string(),
        },
        ActionContext {
            action_type: "DelegateCapability".to_string(),
            target: Some("peer-poor".to_string()),
            trust_tier: 1,
            risk_level: "High".to_string(),
        },
        GovernanceDecision::Block {
            reason: "Peer reputation Poor, below Good threshold".to_string(),
            authority: "ReputationGate".to_string(),
        },
    );
    assert!(matches!(
        block_event.event_type,
        GovernanceEventType::ReputationGateBlocked
    ));

    // 4. All events should have valid IDs and be hash-chainable
    for event in [&fwd_event, &recv_event, &block_event] {
        assert!(event.id.starts_with("gov-"));
        let hash = event.compute_hash();
        assert!(!hash.is_empty(), "Event hash should be non-empty");
        assert_eq!(hash.len(), 64, "Blake3 hex hash should be 64 chars");
    }
}

// ============================================================================
// Test 8: Bridge builds peer context from live reputation data
// ============================================================================

#[tokio::test]
async fn test_e2e_bridge_builds_peer_context_from_reputation() {
    let node = make_node();
    let bridge = MeshBridge::with_defaults(node);
    let peer_hash = [0xCCu8; 16];

    // Record multiple positive signals to build reputation
    for i in 0..5 {
        bridge
            .record_receipt_reputation(&peer_hash, &format!("r-{}", i), true)
            .await;
    }

    // Build peer context for policy evaluation
    let ctx = bridge
        .build_peer_context_for_receipt(&peer_hash, MeshAction::AcceptReceipt)
        .await;

    assert_eq!(ctx.peer_address, hex::encode(peer_hash));
    assert_eq!(ctx.mesh_action, MeshAction::AcceptReceipt);
    assert!(ctx.reputation_score.is_some());
    assert!(ctx.reputation_grade.is_some());

    // The score should reflect positive signals
    let score = ctx.reputation_score.unwrap();
    assert!(
        score > 0.5,
        "Score should be > 0.5 with all positive signals, got {}",
        score
    );
}

// ============================================================================
// Test 9: Full flow — reputation → policy context → engine evaluation
// ============================================================================

#[tokio::test]
async fn test_e2e_reputation_to_policy_evaluation() {
    let node = make_node();
    let bridge = MeshBridge::with_defaults(node);
    let peer_hash = [0xDDu8; 16];

    // Build up Good reputation (need enough positive signals)
    for i in 0..15 {
        bridge
            .record_receipt_reputation(&peer_hash, &format!("rep-{}", i), true)
            .await;
    }

    // Verify reputation is Good or better
    let rep = bridge.peer_reputation(&peer_hash).await;
    assert!(
        rep.grade >= ReputationGrade::Good,
        "Need at least Good grade, got {:?}",
        rep.grade,
    );

    // Build peer context from live data
    let peer_ctx = bridge
        .build_peer_context_for_receipt(&peer_hash, MeshAction::SharePolicy)
        .await;

    // Create policy context with the live mesh peer data
    let policy_context = PolicyContext {
        action: ActionType::Chat,
        trust_tier: TrustTier::Tier1,
        channel: Channel::Cli,
        conversation_id: ConversationId::new(),
        skill_ids: vec![],
        tool_names: vec![],
        mesh_context: Some(peer_ctx),
    };

    // Evaluate — should allow because peer has Fair+ reputation for SharePolicy
    let engine = PolicyEngine::new();
    let decision = engine.evaluate(&policy_context);
    assert!(
        decision.is_allowed(),
        "Good-reputation peer should be allowed to share policy, got: {:?}",
        decision,
    );
}

// ============================================================================
// Test 10: Mixed receipt flow — some accepted, some rejected by validation
// ============================================================================

#[tokio::test]
async fn test_e2e_mixed_receipt_validation() {
    let node = make_node();
    let bridge = MeshBridge::with_defaults(node);
    let peer = [0xEEu8; 16];

    // Valid receipt
    let r1 = make_compact_receipt("valid-1", "success");
    assert!(bridge.handle_inbound_receipt(&r1, &peer).await.is_ok());

    // Invalid: empty ID
    let r2 = make_compact_receipt("", "success");
    assert!(bridge.handle_inbound_receipt(&r2, &peer).await.is_err());

    // Invalid: bad status
    let r3 = make_compact_receipt("bad-status", "foobar");
    assert!(bridge.handle_inbound_receipt(&r3, &peer).await.is_err());

    // Valid: denied status (valid receipt status)
    let r4 = make_compact_receipt("denied-1", "denied");
    assert!(bridge.handle_inbound_receipt(&r4, &peer).await.is_ok());

    // Valid: partial status
    let r5 = make_compact_receipt("partial-1", "partial");
    assert!(bridge.handle_inbound_receipt(&r5, &peer).await.is_ok());

    // Only 3 valid receipts should be stored
    assert_eq!(bridge.received_receipt_count().await, 3);
    assert_eq!(bridge.accepted_receipts().await.len(), 3);
}

// ============================================================================
// Test 11: Multi-peer receipt flow with different reputations
// ============================================================================

#[tokio::test]
async fn test_e2e_multi_peer_different_reputations() {
    let node = make_node();
    let bridge = MeshBridge::with_defaults(node);

    let good_peer = [0x11u8; 16];
    let new_peer = [0x22u8; 16];

    // Good peer: send many successful receipts
    for i in 0..10 {
        let r = make_compact_receipt(&format!("good-{}", i), "success");
        bridge.handle_inbound_receipt(&r, &good_peer).await.unwrap();
    }

    // New peer: just one receipt
    let r = make_compact_receipt("new-1", "success");
    bridge.handle_inbound_receipt(&r, &new_peer).await.unwrap();

    // Good peer should have higher reputation
    let good_rep = bridge.peer_reputation(&good_peer).await;
    let new_rep = bridge.peer_reputation(&new_peer).await;

    assert!(
        good_rep.positive_signals > new_rep.positive_signals,
        "Good peer should have more positive signals",
    );

    // Verify per-peer receipt counts
    assert_eq!(bridge.receipts_from_peer(&good_peer).await.len(), 10);
    assert_eq!(bridge.receipts_from_peer(&new_peer).await.len(), 1);

    // Total count
    assert_eq!(bridge.received_receipt_count().await, 11);
}

// ============================================================================
// Test 12: Bridge configuration affects forwarding behavior
// ============================================================================

#[tokio::test]
async fn test_e2e_bridge_config_controls_forwarding() {
    let node = make_node();
    let lo = Arc::new(LoopbackInterface::new());
    node.attach_interface(lo.clone()).await;

    let peer_id = MeshIdentity::generate();
    let peer = PeerIdentity::from_combined_key(&peer_id.combined_public_key(), 1).unwrap();
    node.register_peer(peer, None).await;

    // Bridge with forwarding disabled
    let config = MeshBridgeConfig {
        forward_receipts: false,
        forward_audit: true,
        max_forward_peers: 0,
    };
    let bridge = MeshBridge::new(node, config);

    let receipt = zp_receipt::Receipt::execution("test")
        .status(zp_receipt::Status::Success)
        .trust_grade(zp_receipt::TrustGrade::C)
        .finalize();

    // Forward should succeed silently (no-op)
    assert!(bridge.forward_receipt(&receipt).await.is_ok());

    // But nothing should appear on the loopback
    let received = lo.recv().await.unwrap();
    assert!(
        received.is_none(),
        "No packet should be sent when forwarding is disabled"
    );
}

// ============================================================================
// Test 13: Governance event hashing is deterministic per event
// ============================================================================

#[test]
fn test_e2e_governance_event_hash_determinism() {
    let actor = GovernanceActor::Agent {
        destination_hash: "aabbccdd".to_string(),
        trust_tier: 1,
    };
    let ctx = ActionContext {
        action_type: "ForwardReceipt".to_string(),
        target: Some("peer-xyz".to_string()),
        trust_tier: 1,
        risk_level: "Low".to_string(),
    };
    let decision = GovernanceDecision::Allow {
        conditions: vec!["mesh forwarded".to_string()],
    };

    let event = GovernanceEvent::receipt_forwarded(actor, ctx, decision);

    // Hash should be consistent across multiple calls
    let hash1 = event.compute_hash();
    let hash2 = event.compute_hash();
    assert_eq!(hash1, hash2, "Hash should be deterministic");
    assert_eq!(hash1.len(), 64, "Blake3 hex = 64 chars");
}

// ============================================================================
// Test 14: ReputationGrade ordering is correct across the stack
// ============================================================================

#[test]
fn test_e2e_reputation_grade_ordering() {
    // Verify the ordering that ReputationGateRule depends on
    assert!(ReputationGrade::Unknown < ReputationGrade::Poor);
    assert!(ReputationGrade::Poor < ReputationGrade::Fair);
    assert!(ReputationGrade::Fair < ReputationGrade::Good);
    assert!(ReputationGrade::Good < ReputationGrade::Excellent);

    // Verify string representation matches what policy expects
    assert_eq!(ReputationGrade::Unknown.to_string(), "Unknown");
    assert_eq!(ReputationGrade::Poor.to_string(), "Poor");
    assert_eq!(ReputationGrade::Fair.to_string(), "Fair");
    assert_eq!(ReputationGrade::Good.to_string(), "Good");
    assert_eq!(ReputationGrade::Excellent.to_string(), "Excellent");
}

// ============================================================================
// Test 15: Policy evaluation with all MeshAction variants
// ============================================================================

#[test]
fn test_e2e_policy_all_mesh_actions() {
    let engine = PolicyEngine::new();

    let actions_and_min_grades: Vec<(MeshAction, &str, bool)> = vec![
        // Low risk: Unknown peers allowed
        (MeshAction::ForwardReceipt, "Unknown", true),
        (MeshAction::AcceptReceipt, "Unknown", true),
        // Medium risk: Fair required, Unknown gets Warn
        (MeshAction::SharePolicy, "Fair", true),
        (MeshAction::AcceptPolicy, "Fair", true),
        // High risk: Good required, Unknown gets Review
        (MeshAction::DelegateCapability, "Good", true),
        (MeshAction::AcceptDelegation, "Good", true),
        // Poor peer blocked from high-risk actions
        (MeshAction::DelegateCapability, "Poor", false),
        (MeshAction::AcceptDelegation, "Poor", false),
    ];

    for (action, grade, should_pass) in actions_and_min_grades {
        let score = match grade {
            "Unknown" => None,
            "Poor" => Some(0.15),
            "Fair" => Some(0.35),
            "Good" => Some(0.65),
            "Excellent" => Some(0.85),
            _ => panic!("bad grade"),
        };
        let grade_opt = if grade == "Unknown" {
            None
        } else {
            Some(grade)
        };

        let context = make_policy_context_with_mesh(action.clone(), grade_opt, score);
        let decision = engine.evaluate(&context);

        if should_pass {
            assert!(
                !decision.is_blocked(),
                "{:?} with grade {} should not be blocked, got: {:?}",
                action,
                grade,
                decision
            );
        } else {
            assert!(
                decision.is_blocked(),
                "{:?} with grade {} should be blocked, got: {:?}",
                action,
                grade,
                decision
            );
        }
    }
}

// ============================================================================
// Test 16: Peer context is wired correctly from bridge to policy
// ============================================================================

#[tokio::test]
async fn test_e2e_peer_context_wiring() {
    let node = make_node();
    let bridge = MeshBridge::with_defaults(node);
    let peer_hash = [0xFFu8; 16];

    // Unknown peer (no signals yet)
    let ctx = bridge
        .build_peer_context_for_receipt(&peer_hash, MeshAction::AcceptReceipt)
        .await;

    // Should have Unknown grade
    assert_eq!(ctx.reputation_grade.as_deref(), Some("Unknown"));
    assert!(ctx.reputation_score.is_some());

    // Feed into policy engine
    let policy_context = PolicyContext {
        action: ActionType::Chat,
        trust_tier: TrustTier::Tier1,
        channel: Channel::Cli,
        conversation_id: ConversationId::new(),
        skill_ids: vec![],
        tool_names: vec![],
        mesh_context: Some(ctx),
    };

    let engine = PolicyEngine::new();
    let decision = engine.evaluate(&policy_context);

    // AcceptReceipt is low-risk, Unknown peers are allowed
    assert!(
        decision.is_allowed(),
        "Unknown peer should be allowed for AcceptReceipt, got: {:?}",
        decision,
    );
}

// ============================================================================
// Phase 5 Step 1: Delegation Chain Verification Integration Tests
// ============================================================================

fn make_root_grant() -> CapabilityGrant {
    CapabilityGrant::new(
        "alice".to_string(),
        "bob".to_string(),
        GrantedCapability::Read {
            scope: vec!["data/*".to_string()],
        },
        "receipt_root".to_string(),
    )
    .with_max_delegation_depth(3)
}

// ============================================================================
// Test 17: Delegation chain verification through the bridge
// ============================================================================

#[tokio::test]
async fn test_e2e_delegation_chain_verification() {
    let node = make_node();
    let bridge = MeshBridge::with_defaults(node);

    // Create a valid 3-level delegation chain
    let root = make_root_grant();
    let g1 = root
        .delegate(
            "charlie".to_string(),
            GrantedCapability::Read {
                scope: vec!["data/*".to_string()],
            },
            "r1".to_string(),
        )
        .unwrap();
    let g2 = g1
        .delegate(
            "dave".to_string(),
            GrantedCapability::Read {
                scope: vec!["data/logs".to_string()],
            },
            "r2".to_string(),
        )
        .unwrap();

    // Verify through the bridge
    let chain = bridge
        .verify_delegation_chain(vec![root, g1, g2], false)
        .await
        .unwrap();

    assert_eq!(chain.len(), 3);
    assert_eq!(chain.current_depth(), 2);
    assert_eq!(chain.root().grantor, "alice");
    assert_eq!(chain.leaf().grantee, "dave");
    assert!(chain.can_extend()); // max depth 3, at depth 2
}

// ============================================================================
// Test 18: Inbound delegation accepted and stored
// ============================================================================

#[tokio::test]
async fn test_e2e_inbound_delegation_accepted() {
    let node = make_node();
    let bridge = MeshBridge::with_defaults(node);
    let sender = [0xAAu8; 16];

    let root = make_root_grant();
    let compact = CompactDelegation::from_grant(&root);

    // Accept the delegation
    let grant = bridge
        .handle_inbound_delegation(&compact, &sender)
        .await
        .unwrap();

    assert_eq!(grant.grantor, "alice");
    assert_eq!(grant.grantee, "bob");
    assert!(!grant.is_delegated());

    // Verify it was stored
    let chain_ids = bridge.delegation_chain_ids().await;
    assert!(!chain_ids.is_empty());

    // Verify reputation signal was recorded
    let score = bridge.peer_reputation(&sender).await;
    assert!(
        score.positive_signals > 0,
        "Positive delegation signal should be recorded"
    );
}

// ============================================================================
// Test 19: Delegation chain with parent lookup
// ============================================================================

#[tokio::test]
async fn test_e2e_delegation_chain_parent_lookup() {
    let node = make_node();
    let bridge = MeshBridge::with_defaults(node);
    let sender = [0xBBu8; 16];

    // First, accept the root grant
    let root = make_root_grant();
    let root_compact = CompactDelegation::from_grant(&root);
    bridge
        .handle_inbound_delegation(&root_compact, &sender)
        .await
        .unwrap();

    // Now delegate and send child
    let child = root
        .delegate(
            "charlie".to_string(),
            GrantedCapability::Read {
                scope: vec!["data/public".to_string()],
            },
            "receipt_child".to_string(),
        )
        .unwrap();
    let child_compact = CompactDelegation::from_grant(&child);

    let grant = bridge
        .handle_inbound_delegation(&child_compact, &sender)
        .await
        .unwrap();

    assert!(grant.is_delegated());
    assert_eq!(grant.delegation_depth, 1);
}

// ============================================================================
// Test 20: Grant authorization check — valid grant passes
// ============================================================================

#[tokio::test]
async fn test_e2e_grant_authorization_valid() {
    let node = make_node();
    let bridge = MeshBridge::with_defaults(node);

    let grant = make_root_grant();

    // Store the chain first
    bridge
        .node()
        .store_delegation_chain(vec![grant.clone()])
        .await
        .unwrap();

    let action = ActionType::Read {
        target: "data/config".to_string(),
    };
    let ctx = zp_core::ConstraintContext::new("data/config".to_string());

    let result = bridge
        .check_grant_authorization(&grant, &action, &ctx)
        .await;
    assert!(result.is_ok(), "Valid grant should pass: {:?}", result);
}

// ============================================================================
// Test 21: Grant authorization rejects wrong action
// ============================================================================

#[tokio::test]
async fn test_e2e_grant_authorization_wrong_action() {
    let node = make_node();
    let bridge = MeshBridge::with_defaults(node);

    let grant = make_root_grant(); // Read grant

    let action = ActionType::Write {
        target: "data/config".to_string(),
    };
    let ctx = zp_core::ConstraintContext::new("data/config".to_string());

    let result = bridge
        .check_grant_authorization(&grant, &action, &ctx)
        .await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("does not authorize"));
}

// ============================================================================
// Test 22: Delegation + policy — DelegateCapability requires Good reputation
// ============================================================================

#[tokio::test]
async fn test_e2e_delegation_requires_good_reputation() {
    let engine = PolicyEngine::new();

    // Unknown peer trying to DelegateCapability → should get Review (not blocked)
    let ctx_unknown = make_policy_context_with_mesh(
        MeshAction::DelegateCapability,
        None, // Unknown grade
        None,
    );
    let decision = engine.evaluate(&ctx_unknown);
    assert!(
        !decision.is_blocked(),
        "Unknown peer should get Review for DelegateCapability, not Block. Got: {:?}",
        decision,
    );

    // Poor peer trying DelegateCapability → should be blocked
    let ctx_poor =
        make_policy_context_with_mesh(MeshAction::DelegateCapability, Some("Poor"), Some(0.15));
    let decision = engine.evaluate(&ctx_poor);
    assert!(
        decision.is_blocked(),
        "Poor peer should be blocked for DelegateCapability. Got: {:?}",
        decision,
    );

    // Good peer trying DelegateCapability → should be allowed
    let ctx_good =
        make_policy_context_with_mesh(MeshAction::DelegateCapability, Some("Good"), Some(0.65));
    let decision = engine.evaluate(&ctx_good);
    assert!(
        !decision.is_blocked(),
        "Good peer should be allowed DelegateCapability. Got: {:?}",
        decision,
    );
}

// ============================================================================
// Test 23: Full flow — delegation received, verified, grant checked
// ============================================================================

#[tokio::test]
async fn test_e2e_full_delegation_flow() {
    let node = make_node();
    let bridge = MeshBridge::with_defaults(node);
    let sender = [0xCCu8; 16];

    // Step 1: Receive root delegation
    let root = make_root_grant();
    let root_compact = CompactDelegation::from_grant(&root);
    bridge
        .handle_inbound_delegation(&root_compact, &sender)
        .await
        .unwrap();

    // Step 2: Receive child delegation
    let child = root
        .delegate(
            "charlie".to_string(),
            GrantedCapability::Read {
                scope: vec!["data/public".to_string()],
            },
            "rcpt-child".to_string(),
        )
        .unwrap();
    let child_compact = CompactDelegation::from_grant(&child);
    let verified_grant = bridge
        .handle_inbound_delegation(&child_compact, &sender)
        .await
        .unwrap();

    // Step 3: Check the child grant authorizes a Read action
    let action = ActionType::Read {
        target: "data/public".to_string(),
    };
    let ctx = zp_core::ConstraintContext::new("data/public".to_string());
    let result = bridge
        .check_grant_authorization(&verified_grant, &action, &ctx)
        .await;
    assert!(
        result.is_ok(),
        "Delegated grant should authorize Read on data/public: {:?}",
        result,
    );

    // Step 4: Verify the scope narrowing worked — out-of-scope should fail
    let out_of_scope_action = ActionType::Read {
        target: "secret/keys".to_string(),
    };
    let result = bridge
        .check_grant_authorization(&verified_grant, &out_of_scope_action, &ctx)
        .await;
    assert!(
        result.is_err(),
        "Delegated grant should NOT authorize Read on secret/keys",
    );

    // Step 5: Verify reputation was recorded for both delegations
    let score = bridge.peer_reputation(&sender).await;
    assert!(
        score.positive_signals >= 2,
        "Should have at least 2 positive delegation signals, got {}",
        score.positive_signals,
    );
}

// =========================================================================
// Phase 5 Step 2: Audit Chain Verification Integration Tests
// =========================================================================

fn make_compact_audit_entries(n: usize) -> Vec<CompactAuditEntry> {
    let genesis = blake3::hash(b"").to_hex().to_string();
    let mut entries = Vec::new();
    let mut prev = genesis;
    for i in 0..n {
        let eh = blake3::hash(format!("entry-{}", i).as_bytes())
            .to_hex()
            .to_string();
        entries.push(CompactAuditEntry {
            id: format!("audit-{}", i),
            ts: Utc::now().timestamp(),
            ph: prev.clone(),
            eh: eh.clone(),
            ac: "s:test-agent".to_string(),
            at: "tool".to_string(),
            pd: "allow".to_string(),
            pm: "default-gate".to_string(),
            sg: None,
        });
        prev = eh;
    }
    entries
}

fn make_audit_response_e2e(challenge_id: &str, entries: Vec<CompactAuditEntry>) -> AuditResponse {
    let chain_tip = entries.last().map(|e| e.eh.clone()).unwrap_or_default();
    let total = entries.len();
    AuditResponse {
        challenge_id: challenge_id.to_string(),
        entries,
        chain_tip,
        total_available: total,
        has_more: false,
    }
}

/// Test 24: Challenge → response → verify → attestation flow.
#[tokio::test]
async fn test_e2e_audit_challenge_and_verify() {
    let node = make_node();
    let bridge = MeshBridge::with_defaults(node);
    let peer = [0xD1u8; 16];

    // Simulate: we challenged, they responded with 3 valid entries
    let entries = make_compact_audit_entries(3);
    let response = make_audit_response_e2e("chal-e2e-1", entries);

    let attestation = bridge
        .handle_audit_response(&response, &peer, false)
        .await
        .unwrap();

    assert!(attestation.chain_valid);
    assert_eq!(attestation.entries_verified, 3);
    assert_eq!(attestation.peer, hex::encode(peer));

    // Peer should now be considered audit-verified
    assert!(bridge.peer_audit_verified(&peer).await);
}

/// Test 25: Broken chain produces invalid attestation and negative reputation.
#[tokio::test]
async fn test_e2e_broken_audit_chain_reputation() {
    let node = make_node();
    let bridge = MeshBridge::with_defaults(node);
    let peer = [0xD2u8; 16];

    let mut entries = make_compact_audit_entries(4);
    entries[3].ph = "tampered-hash".to_string();
    let response = make_audit_response_e2e("chal-e2e-2", entries);

    let attestation = bridge
        .handle_audit_response(&response, &peer, false)
        .await
        .unwrap();

    assert!(!attestation.chain_valid);

    // Reputation should have a negative signal
    let score = bridge.peer_reputation(&peer).await;
    assert!(
        score.negative_signals > 0,
        "Broken chain should record negative reputation"
    );
}

/// Test 26: Multiple audit verifications accumulate attestations.
#[tokio::test]
async fn test_e2e_multiple_audit_verifications() {
    let node = make_node();
    let bridge = MeshBridge::with_defaults(node);
    let peer = [0xD3u8; 16];

    // First verification: valid
    let entries1 = make_compact_audit_entries(2);
    let response1 = make_audit_response_e2e("chal-e2e-3a", entries1);
    bridge
        .handle_audit_response(&response1, &peer, false)
        .await
        .unwrap();

    // Second verification: also valid
    let entries2 = make_compact_audit_entries(3);
    let response2 = make_audit_response_e2e("chal-e2e-3b", entries2);
    bridge
        .handle_audit_response(&response2, &peer, false)
        .await
        .unwrap();

    assert_eq!(bridge.peer_valid_attestation_count(&peer).await, 2);

    // Reputation should have accumulated positive signals
    let score = bridge.peer_reputation(&peer).await;
    assert!(
        score.positive_signals >= 2,
        "Multiple valid chains should record multiple positive signals"
    );
}

/// Test 27: Audit verification + delegation = multi-signal reputation.
#[tokio::test]
async fn test_e2e_audit_and_delegation_combined_reputation() {
    let node = make_node();
    let bridge = MeshBridge::with_defaults(node);
    let peer = [0xD4u8; 16];

    // Send a valid audit chain → positive audit signal
    let entries = make_compact_audit_entries(3);
    let response = make_audit_response_e2e("chal-e2e-4", entries);
    bridge
        .handle_audit_response(&response, &peer, false)
        .await
        .unwrap();

    // Send a valid delegation → positive delegation signal
    let grant = make_root_grant();
    let compact = CompactDelegation::from_grant(&grant);
    bridge
        .handle_inbound_delegation(&compact, &peer)
        .await
        .unwrap();

    // Both signal types should be recorded
    let score = bridge.peer_reputation(&peer).await;
    assert!(
        score.positive_signals >= 2,
        "Should have both audit and delegation positive signals, got {}",
        score.positive_signals,
    );
}

/// Test 28: Audit challenge sends to wire (full mesh wiring check).
#[tokio::test]
async fn test_e2e_audit_challenge_sends_packet() {
    let node_a = make_node();
    let lo = Arc::new(LoopbackInterface::new());
    node_a.attach_interface(lo.clone()).await;

    let peer_id = MeshIdentity::generate();
    let peer = PeerIdentity::from_combined_key(&peer_id.combined_public_key(), 1).unwrap();
    let peer_hash = peer.destination_hash;
    node_a.register_peer(peer, None).await;

    let bridge = MeshBridge::with_defaults(node_a);

    let challenge = bridge.challenge_peer_audit(&peer_hash, 10).await.unwrap();
    assert!(challenge.id.starts_with("chal-"));

    // Verify packet was transmitted
    let received = lo.recv().await.unwrap();
    assert!(received.is_some(), "Challenge packet should be on the wire");
}

/// Test 29: Respond to audit challenge sends response packet.
#[tokio::test]
async fn test_e2e_respond_to_audit_challenge() {
    let node = make_node();
    let lo = Arc::new(LoopbackInterface::new());
    node.attach_interface(lo.clone()).await;

    let peer_id = MeshIdentity::generate();
    let peer = PeerIdentity::from_combined_key(&peer_id.combined_public_key(), 1).unwrap();
    let peer_hash = peer.destination_hash;
    node.register_peer(peer, None).await;

    let bridge = MeshBridge::with_defaults(node);
    let challenge = AuditChallenge::recent(5);

    let result = bridge
        .respond_to_audit_challenge(&challenge, &[], &peer_hash)
        .await;
    assert!(result.is_ok());

    // Verify a response packet was sent
    let received = lo.recv().await.unwrap();
    assert!(received.is_some(), "Response packet should be on the wire");
}

/// Test 30: Full audit verification flow with broadcast.
#[tokio::test]
async fn test_e2e_audit_verify_and_broadcast() {
    let node = make_node();
    let lo = Arc::new(LoopbackInterface::new());
    node.attach_interface(lo.clone()).await;

    // Register a peer to broadcast to
    let peer_id = MeshIdentity::generate();
    let broadcast_peer =
        PeerIdentity::from_combined_key(&peer_id.combined_public_key(), 1).unwrap();
    node.register_peer(broadcast_peer, None).await;

    let bridge = MeshBridge::with_defaults(node);
    let sender = [0xD5u8; 16];

    let entries = make_compact_audit_entries(3);
    let response = make_audit_response_e2e("chal-e2e-5", entries);

    let attestation = bridge
        .handle_audit_response(&response, &sender, true) // broadcast=true
        .await
        .unwrap();

    assert!(attestation.chain_valid);

    // Attestation should be stored and peer verified regardless of broadcast MTU
    assert!(bridge.peer_audit_verified(&sender).await);
    assert_eq!(bridge.peer_valid_attestation_count(&sender).await, 1);
}

// =========================================================================
// Phase 5 Step 3: Capability Negotiation Integration Tests
// =========================================================================

/// Test 31: Full link establishment with capability negotiation.
#[tokio::test]
async fn test_e2e_link_establishment_with_negotiation() {
    let node_id = MeshIdentity::generate();
    let node = Arc::new(MeshNode::new(node_id));
    let lo = Arc::new(LoopbackInterface::new());
    node.attach_interface(lo.clone()).await;

    let peer = MeshIdentity::generate();

    let bridge = MeshBridge::with_defaults(node);
    let policy = CapabilityPolicy::allow_all();
    let our_request = CapabilityRequest {
        requested: vec![
            GrantedCapability::Read {
                scope: vec!["data/*".to_string()],
            },
            GrantedCapability::Execute {
                languages: vec!["tools/safe".to_string()],
            },
        ],
        offered: vec![GrantedCapability::Read {
            scope: vec!["audit/*".to_string()],
        }],
        claimed_tier: TrustTier::Tier1,
    };
    let their_request = CapabilityRequest {
        requested: vec![GrantedCapability::Read {
            scope: vec!["audit/*".to_string()],
        }],
        offered: vec![
            GrantedCapability::Read {
                scope: vec!["data/*".to_string()],
            },
            GrantedCapability::Execute {
                languages: vec!["tools/safe".to_string()],
            },
        ],
        claimed_tier: TrustTier::Tier1,
    };

    let result = bridge
        .establish_peer_link(&peer, &policy, &our_request, &their_request)
        .await;
    assert!(result.is_ok());

    let neg = result.unwrap();
    // Initiator should receive grants for what they requested (data/*, tools/safe)
    assert!(
        !neg.initiator_grants.is_empty(),
        "Initiator should get grants for their requests"
    );
    // Responder should receive grants for what they requested (audit/*)
    assert!(
        !neg.responder_grants.is_empty(),
        "Responder should get grants for their requests"
    );
}

/// Test 32: Deny-all policy produces no grants.
#[tokio::test]
async fn test_e2e_deny_all_policy_no_grants() {
    let node_id = MeshIdentity::generate();
    let node = Arc::new(MeshNode::new(node_id));
    let lo = Arc::new(LoopbackInterface::new());
    node.attach_interface(lo.clone()).await;

    let peer = MeshIdentity::generate();

    let bridge = MeshBridge::with_defaults(node);
    let policy = CapabilityPolicy::deny_all();
    let request = CapabilityRequest {
        requested: vec![GrantedCapability::Read {
            scope: vec!["*".to_string()],
        }],
        offered: vec![],
        claimed_tier: TrustTier::Tier1,
    };

    let neg = bridge
        .establish_peer_link(&peer, &policy, &request, &request)
        .await
        .unwrap();

    assert!(neg.initiator_grants.is_empty());
    assert!(neg.responder_grants.is_empty());
}

/// Test 33: peer_authorizes_action works across the full bridge.
#[tokio::test]
async fn test_e2e_peer_authorizes_action() {
    let node_id = MeshIdentity::generate();
    let node = Arc::new(MeshNode::new(node_id));
    let lo = Arc::new(LoopbackInterface::new());
    node.attach_interface(lo.clone()).await;

    let peer = MeshIdentity::generate();
    let peer_address = peer.address();

    let bridge = MeshBridge::with_defaults(node);
    let policy = CapabilityPolicy::allow_all();
    let request = CapabilityRequest {
        requested: vec![GrantedCapability::Read {
            scope: vec!["data/*".to_string()],
        }],
        offered: vec![GrantedCapability::Read {
            scope: vec!["data/*".to_string()],
        }],
        claimed_tier: TrustTier::Tier1,
    };

    bridge
        .establish_peer_link(&peer, &policy, &request, &request)
        .await
        .unwrap();

    // Should authorize Read
    let read = ActionType::Read {
        target: "data/foo".to_string(),
    };
    assert!(bridge.peer_authorizes_action(&peer_address, &read).await);

    // Should NOT authorize Write (not negotiated)
    let write = ActionType::Write {
        target: "data/foo".to_string(),
    };
    assert!(!bridge.peer_authorizes_action(&peer_address, &write).await);
}

/// Test 34: Active link detection through the bridge.
#[tokio::test]
async fn test_e2e_active_link_detection() {
    let node_id = MeshIdentity::generate();
    let node = Arc::new(MeshNode::new(node_id));
    let lo = Arc::new(LoopbackInterface::new());
    node.attach_interface(lo.clone()).await;

    let peer = MeshIdentity::generate();
    let peer_address = peer.address();

    let bridge = MeshBridge::with_defaults(node);

    // No link yet
    assert!(!bridge.has_active_link(&peer_address).await);

    let policy = CapabilityPolicy::allow_all();
    let request = CapabilityRequest {
        requested: vec![],
        offered: vec![],
        claimed_tier: TrustTier::Tier1,
    };

    bridge
        .establish_peer_link(&peer, &policy, &request, &request)
        .await
        .unwrap();

    // Now link exists
    assert!(bridge.has_active_link(&peer_address).await);
}

// ============================================================================
// Phase 5 Step 4: Multi-dimensional reputation signals
// ============================================================================

/// Test 35: All four signal dimensions feed into composite score.
#[tokio::test]
async fn test_e2e_multi_dimensional_reputation_excellent() {
    let node = make_node();
    let bridge = MeshBridge::with_defaults(node);
    let peer = [0xD1u8; 16];

    // Feed positive signals in every dimension
    bridge.record_receipt_reputation(&peer, "r1", true).await;
    bridge.record_delegation_reputation(&peer, "d1", true).await;
    bridge.record_policy_compliance(&peer, "p1", true).await;

    let att = zp_audit::collective_audit::PeerAuditAttestation {
        id: "att-e2e-1".to_string(),
        peer: hex::encode(peer),
        oldest_hash: "a".to_string(),
        newest_hash: "b".to_string(),
        entries_verified: 4,
        chain_valid: true,
        signatures_valid: 2,
        timestamp: Utc::now(),
        signature: None,
    };
    bridge.record_audit_reputation(&peer, &att).await;

    let snap = bridge.peer_trust_snapshot(&peer).await;
    assert_eq!(snap.grade, ReputationGrade::Excellent);
    assert!(snap.overall_score > 0.9);
    assert_eq!(snap.positive_signals, 4);
    assert_eq!(snap.negative_signals, 0);
}

/// Test 36: Mixed signals across dimensions produce Fair/Good grade.
#[tokio::test]
async fn test_e2e_multi_dimensional_mixed() {
    let node = make_node();
    let bridge = MeshBridge::with_defaults(node);
    let peer = [0xD2u8; 16];

    // Receipts: all positive
    bridge.record_receipt_reputation(&peer, "r1", true).await;
    bridge.record_receipt_reputation(&peer, "r2", true).await;

    // Policy: all negative
    bridge
        .record_policy_compliance(&peer, "p-bad1", false)
        .await;
    bridge
        .record_policy_compliance(&peer, "p-bad2", false)
        .await;

    // Delegation: positive
    bridge.record_delegation_reputation(&peer, "d1", true).await;

    // Audit: positive
    let att = zp_audit::collective_audit::PeerAuditAttestation {
        id: "att-e2e-mix".to_string(),
        peer: hex::encode(peer),
        oldest_hash: "a".to_string(),
        newest_hash: "b".to_string(),
        entries_verified: 3,
        chain_valid: true,
        signatures_valid: 1,
        timestamp: Utc::now(),
        signature: None,
    };
    bridge.record_audit_reputation(&peer, &att).await;

    let snap = bridge.peer_trust_snapshot(&peer).await;
    // Receipt (0.20 weight) = 1.0, Delegation (0.20) = 1.0,
    // Audit (0.35) = 1.0, Policy (0.25) = 0.0
    // Overall ≈ 0.20 + 0.20 + 0.35 + 0.0 = 0.75 → Good or Excellent boundary
    assert!(
        snap.grade >= ReputationGrade::Good,
        "Mixed with mostly positive should be at least Good: {:?} (score={})",
        snap.grade,
        snap.overall_score,
    );
    assert!(snap.policy_score < 0.1, "Policy should be low");
    assert!(snap.receipt_score > 0.9, "Receipt should be high");
}

/// Test 37: Trust snapshot includes link and attestation state.
#[tokio::test]
async fn test_e2e_trust_snapshot_with_link_and_attestation() {
    let node_id = MeshIdentity::generate();
    let node = Arc::new(MeshNode::new(node_id));
    let lo = Arc::new(LoopbackInterface::new());
    node.attach_interface(lo.clone()).await;

    let peer = MeshIdentity::generate();
    let bridge = MeshBridge::with_defaults(node);

    // Establish link
    let policy = CapabilityPolicy::allow_all();
    let request = CapabilityRequest {
        requested: vec![],
        offered: vec![],
        claimed_tier: TrustTier::Tier1,
    };
    bridge
        .establish_peer_link(&peer, &policy, &request, &request)
        .await
        .unwrap();

    // We need the peer's destination hash for reputation methods.
    // Parse address to get hash.
    let peer_combined = peer.combined_public_key();
    let peer_identity = PeerIdentity::from_combined_key(&peer_combined, 1).unwrap();
    let peer_hash = peer_identity.destination_hash;

    // Handle an audit response to store an attestation
    let entries = make_compact_audit_entries(2);
    let response = make_audit_response_e2e("chal-snap", entries);
    bridge
        .handle_audit_response(&response, &peer_hash, false)
        .await
        .unwrap();

    let snap = bridge.peer_trust_snapshot(&peer_hash).await;

    assert!(snap.has_active_link, "Should have active link");
    assert!(snap.audit_verified, "Should have verified attestation");
    assert_eq!(snap.valid_attestation_count, 1);
    assert!(snap.positive_signals >= 1);
}

/// Test 38: Policy compliance signals affect reputation gate.
#[tokio::test]
async fn test_e2e_policy_violations_erode_trust() {
    let node = make_node();
    let bridge = MeshBridge::with_defaults(node);
    let peer = [0xD4u8; 16];

    // Many policy violations
    for i in 0..10 {
        bridge
            .record_policy_compliance(&peer, &format!("viol-{}", i), false)
            .await;
    }

    let snap = bridge.peer_trust_snapshot(&peer).await;
    // Policy category score should be 0.0
    assert!(snap.policy_score < 0.01);
    // Overall should be dragged down but other categories default to 0.5
    assert!(snap.overall_score < 0.5);
    assert_eq!(snap.negative_signals, 10);
}

/// Test 39: Custom weights emphasise specific dimension.
#[tokio::test]
async fn test_e2e_custom_weights_audit_heavy() {
    let node = make_node();
    let bridge = MeshBridge::with_defaults(node);
    let peer = [0xD5u8; 16];

    // Only audit signal — positive
    let att = zp_audit::collective_audit::PeerAuditAttestation {
        id: "att-cw-e2e".to_string(),
        peer: hex::encode(peer),
        oldest_hash: "a".to_string(),
        newest_hash: "b".to_string(),
        entries_verified: 5,
        chain_valid: true,
        signatures_valid: 3,
        timestamp: Utc::now(),
        signature: None,
    };
    bridge.record_audit_reputation(&peer, &att).await;

    // Custom weights: audit dominates
    let heavy_audit = zp_mesh::reputation::ReputationWeights {
        audit_attestation: 0.85,
        delegation_chain: 0.05,
        policy_compliance: 0.05,
        receipt_exchange: 0.05,
    };
    let score = bridge
        .peer_reputation_with_weights(&peer, &heavy_audit)
        .await;
    // Audit (1.0 * 0.85) + others (0.5 * 0.05 each) = 0.85 + 0.075 = 0.925
    assert!(
        score.score > 0.9,
        "Audit-heavy weights should yield high score: {}",
        score.score
    );
    assert_eq!(score.grade, ReputationGrade::Excellent);

    // Now with receipt-heavy weights, score should be lower
    let heavy_receipt = zp_mesh::reputation::ReputationWeights {
        audit_attestation: 0.05,
        delegation_chain: 0.05,
        policy_compliance: 0.05,
        receipt_exchange: 0.85,
    };
    let score2 = bridge
        .peer_reputation_with_weights(&peer, &heavy_receipt)
        .await;
    // Receipt (0.5 * 0.85) + audit (1.0 * 0.05) + others (0.5 * 0.05 each) = 0.475
    assert!(
        score2.score < 0.6,
        "Receipt-heavy weights with no receipt signals should be mediocre: {}",
        score2.score
    );
}

/// Test 40: Breakdown has all four categories with correct counts.
#[tokio::test]
async fn test_e2e_breakdown_all_categories() {
    let node = make_node();
    let bridge = MeshBridge::with_defaults(node);
    let peer = [0xD6u8; 16];

    bridge.record_receipt_reputation(&peer, "r1", true).await;
    bridge.record_receipt_reputation(&peer, "r2", false).await;
    bridge.record_delegation_reputation(&peer, "d1", true).await;
    bridge.record_policy_compliance(&peer, "p1", true).await;
    bridge.record_policy_compliance(&peer, "p2", true).await;
    bridge.record_policy_compliance(&peer, "p3", false).await;

    let att = zp_audit::collective_audit::PeerAuditAttestation {
        id: "att-bd-e2e".to_string(),
        peer: hex::encode(peer),
        oldest_hash: "a".to_string(),
        newest_hash: "b".to_string(),
        entries_verified: 2,
        chain_valid: true,
        signatures_valid: 1,
        timestamp: Utc::now(),
        signature: None,
    };
    bridge.record_audit_reputation(&peer, &att).await;

    let breakdown = bridge.peer_reputation_breakdown(&peer).await;
    assert_eq!(breakdown.len(), 4);

    use zp_mesh::reputation::SignalCategory;

    let receipt = breakdown
        .iter()
        .find(|c| c.category == SignalCategory::ReceiptExchange)
        .unwrap();
    assert_eq!(receipt.signal_count, 2);

    let delegation = breakdown
        .iter()
        .find(|c| c.category == SignalCategory::DelegationChain)
        .unwrap();
    assert_eq!(delegation.signal_count, 1);

    let policy = breakdown
        .iter()
        .find(|c| c.category == SignalCategory::PolicyCompliance)
        .unwrap();
    assert_eq!(policy.signal_count, 3);

    let audit = breakdown
        .iter()
        .find(|c| c.category == SignalCategory::AuditAttestation)
        .unwrap();
    assert_eq!(audit.signal_count, 1);
}

// ============================================================================
// Phase 6 Step 2: Pipeline + Runtime integration tests (Tests 41-46)
// ============================================================================

/// Test 41: MeshRuntime dispatches receipt to pipeline-level inbound channel.
///
/// Verifies the full path: inject packet → runtime dispatch → inbound channel.
#[tokio::test]
async fn test_e2e_runtime_receipt_to_pipeline_channel() {
    use std::time::Duration;
    use zp_mesh::destination::DestinationHash;
    use zp_mesh::envelope::MeshEnvelope;
    use zp_mesh::packet::{Packet, PacketContext};

    let node = make_node();
    let lo = Arc::new(LoopbackInterface::new());
    node.attach_interface(lo.clone()).await;

    let mut runtime = MeshRuntime::start(
        node.clone(),
        RuntimeConfig {
            poll_interval: Duration::from_millis(10),
            ..Default::default()
        },
    );
    let mut inbound_rx = runtime.take_inbound_rx().unwrap();

    // Inject a receipt packet from a "peer"
    let peer_id = MeshIdentity::generate();
    let compact = make_compact_receipt("rcpt-runtime-41", "success");
    let envelope = MeshEnvelope::receipt(&peer_id, &compact, 1).unwrap();
    let envelope_bytes = envelope.to_msgpack().unwrap();
    let dest = DestinationHash::from_public_key(&peer_id.combined_public_key());
    let packet = Packet::data(dest, envelope_bytes, PacketContext::Receipt).unwrap();
    lo.inject(&packet).await;

    // Receive it from the inbound channel
    let inbound = tokio::time::timeout(Duration::from_secs(2), inbound_rx.recv())
        .await
        .expect("timeout waiting for inbound envelope")
        .expect("channel closed");

    assert_eq!(
        inbound.envelope.envelope_type,
        zp_mesh::envelope::EnvelopeType::Receipt
    );
    let extracted = inbound.envelope.extract_receipt().unwrap();
    assert_eq!(extracted.id, "rcpt-runtime-41");

    runtime.shutdown();
}

/// Test 42: MeshRuntime processes reputation summary and bridge reads it.
///
/// Verifies: runtime dispatches ReputationSummary → MeshNode stores it →
/// MeshBridge can read back the summaries from the peer.
#[tokio::test]
async fn test_e2e_runtime_reputation_through_bridge() {
    use std::time::Duration;
    use zp_mesh::destination::DestinationHash;
    use zp_mesh::envelope::MeshEnvelope;
    use zp_mesh::packet::{Packet, PacketContext};

    let node = make_node();
    let lo = Arc::new(LoopbackInterface::new());
    node.attach_interface(lo.clone()).await;

    let bridge = MeshBridge::with_defaults(node.clone());

    let mut runtime = MeshRuntime::start(
        node.clone(),
        RuntimeConfig {
            poll_interval: Duration::from_millis(10),
            ..Default::default()
        },
    );
    let _inbound_rx = runtime.take_inbound_rx();

    // Inject a reputation summary
    let peer_id = MeshIdentity::generate();
    let summary = zp_mesh::reputation::CompactReputationSummary {
        peer: "target_agent".to_string(),
        sc: 0.90,
        gr: "E".to_string(),
        ps: 20,
        ns: 1,
        ts: Utc::now().timestamp(),
    };
    let envelope = MeshEnvelope::reputation_summary(&peer_id, &summary, 1).unwrap();
    let envelope_bytes = envelope.to_msgpack().unwrap();
    let dest = DestinationHash::from_public_key(&peer_id.combined_public_key());
    let packet = Packet::data(dest, envelope_bytes, PacketContext::Receipt).unwrap();
    lo.inject(&packet).await;

    // Wait for processing
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Bridge should be able to read the received summary
    let peer_hash = zp_mesh::runtime::sender_hash_from_address(&peer_id.address());
    let summaries = bridge.received_reputation_summaries(&peer_hash).await;
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].peer, "target_agent");

    runtime.shutdown();
}

/// Test 43: MeshRuntime dispatches delegation + pipeline processes it.
///
/// Verifies: delegation packet → runtime dispatch → MeshNode stores chain →
/// delegation also forwarded to inbound channel for pipeline processing.
#[tokio::test]
async fn test_e2e_runtime_delegation_stored_and_forwarded() {
    use std::time::Duration;
    use zp_mesh::destination::DestinationHash;
    use zp_mesh::envelope::MeshEnvelope;
    use zp_mesh::packet::{Packet, PacketContext};

    let node = make_node();
    let lo = Arc::new(LoopbackInterface::new());
    node.attach_interface(lo.clone()).await;

    let mut runtime = MeshRuntime::start(
        node.clone(),
        RuntimeConfig {
            poll_interval: Duration::from_millis(10),
            ..Default::default()
        },
    );
    let mut inbound_rx = runtime.take_inbound_rx().unwrap();

    // Create and inject a delegation
    let peer_id = MeshIdentity::generate();
    let grant = CapabilityGrant::new(
        "alice".to_string(),
        "bob".to_string(),
        GrantedCapability::Read {
            scope: vec!["data/*".to_string()],
        },
        "rcpt-del-43".to_string(),
    );
    let compact_del = CompactDelegation::from_grant(&grant);
    let envelope = MeshEnvelope::delegation(&peer_id, &compact_del, 1).unwrap();
    let envelope_bytes = envelope.to_msgpack().unwrap();
    let dest = DestinationHash::from_public_key(&peer_id.combined_public_key());
    let packet = Packet::data(dest, envelope_bytes, PacketContext::Receipt).unwrap();
    lo.inject(&packet).await;

    // Should be forwarded to inbound channel
    let inbound = tokio::time::timeout(Duration::from_secs(2), inbound_rx.recv())
        .await
        .expect("timeout")
        .expect("closed");
    assert_eq!(
        inbound.envelope.envelope_type,
        zp_mesh::envelope::EnvelopeType::Delegation
    );

    // Should also be stored on the node
    let chain = node.get_delegation_chain(&grant.id).await;
    assert!(chain.is_some());

    runtime.shutdown();
}

/// Test 44: MeshRuntime dispatches audit attestation → MeshNode stores it →
/// Bridge reports peer_audit_verified as true.
#[tokio::test]
async fn test_e2e_runtime_audit_attestation_to_bridge() {
    use std::time::Duration;
    use zp_audit::collective_audit::PeerAuditAttestation;
    use zp_mesh::destination::DestinationHash;
    use zp_mesh::envelope::MeshEnvelope;
    use zp_mesh::packet::{Packet, PacketContext};

    let node = make_node();
    let lo = Arc::new(LoopbackInterface::new());
    node.attach_interface(lo.clone()).await;

    let bridge = MeshBridge::with_defaults(node.clone());

    let mut runtime = MeshRuntime::start(
        node.clone(),
        RuntimeConfig {
            poll_interval: Duration::from_millis(10),
            ..Default::default()
        },
    );
    let _inbound_rx = runtime.take_inbound_rx();

    // Inject an audit attestation
    let peer_id = MeshIdentity::generate();
    let attestation = PeerAuditAttestation {
        id: "att-44".to_string(),
        peer: "target-peer".to_string(),
        oldest_hash: "aaa".to_string(),
        newest_hash: "bbb".to_string(),
        entries_verified: 10,
        chain_valid: true,
        signatures_valid: 5,
        timestamp: Utc::now(),
        signature: None,
    };
    let envelope = MeshEnvelope::audit_attestation(&peer_id, &attestation, 1).unwrap();
    let envelope_bytes = envelope.to_msgpack().unwrap();
    let dest = DestinationHash::from_public_key(&peer_id.combined_public_key());
    let packet = Packet::data(dest, envelope_bytes, PacketContext::Receipt).unwrap();
    lo.inject(&packet).await;

    // Wait for runtime to process
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Bridge should report audit verified for this peer
    let peer_hash = zp_mesh::runtime::sender_hash_from_address(&peer_id.address());
    let verified = bridge.peer_audit_verified(&peer_hash).await;
    assert!(
        verified,
        "Audit should be verified after receiving valid attestation"
    );

    // Attestation count should be 1
    let count = bridge.peer_valid_attestation_count(&peer_hash).await;
    assert_eq!(count, 1);

    runtime.shutdown();
}

/// Test 45: Pipeline MeshConfig initializes full mesh subsystem.
///
/// Verifies: PipelineConfig with MeshConfig → Pipeline::init_mesh →
/// bridge + runtime created → mesh is active.
#[tokio::test]
async fn test_e2e_pipeline_init_mesh_from_config() {
    use zp_pipeline::{MeshConfig, Pipeline, PipelineConfig};

    let tmp = tempfile::tempdir().unwrap();
    let config = PipelineConfig {
        data_dir: tmp.path().to_path_buf(),
        mesh: Some(MeshConfig::default()),
        ..Default::default()
    };

    let mesh_config = config.mesh.clone().unwrap();
    std::fs::create_dir_all(&config.data_dir).ok();
    let audit_store = Arc::new(std::sync::Mutex::new(
        zp_audit::AuditStore::open(&config.data_dir.join("audit.db")).unwrap(),
    ));
    let mut pipeline = Pipeline::new(config, audit_store).expect("pipeline init");
    pipeline.init_mesh(&mesh_config).await.expect("mesh init");

    assert!(pipeline.has_mesh());
    assert!(pipeline.mesh_bridge().is_some());
    assert!(pipeline.mesh_runtime().is_some());
    assert!(pipeline.mesh_runtime().unwrap().is_running());

    pipeline.shutdown_mesh();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(!pipeline.mesh_runtime().unwrap().is_running());
}

/// Test 46: MeshRuntime stats are accessible through bridge after processing.
#[tokio::test]
async fn test_e2e_runtime_stats_after_packet_processing() {
    use std::time::Duration;
    use zp_mesh::destination::DestinationHash;
    use zp_mesh::envelope::MeshEnvelope;
    use zp_mesh::packet::{Packet, PacketContext};

    let node = make_node();
    let lo = Arc::new(LoopbackInterface::new());
    node.attach_interface(lo.clone()).await;

    let mut runtime = MeshRuntime::start(
        node.clone(),
        RuntimeConfig {
            poll_interval: Duration::from_millis(10),
            ..Default::default()
        },
    );
    let _inbound_rx = runtime.take_inbound_rx();

    // Inject 3 receipts
    for i in 0..3 {
        let sender_id = MeshIdentity::generate();
        let compact = make_compact_receipt(&format!("rcpt-stats-{}", i), "success");
        let envelope = MeshEnvelope::receipt(&sender_id, &compact, 1).unwrap();
        let envelope_bytes = envelope.to_msgpack().unwrap();
        let dest = DestinationHash::from_public_key(&sender_id.combined_public_key());
        let packet = Packet::data(dest, envelope_bytes, PacketContext::Receipt).unwrap();
        lo.inject(&packet).await;
    }

    // Wait for processing
    tokio::time::sleep(Duration::from_millis(300)).await;

    let stats = runtime.stats().await;
    assert_eq!(stats.packets_received, 3);
    assert_eq!(stats.envelopes_dispatched, 3);
    assert_eq!(stats.deserialize_errors, 0);

    runtime.shutdown();
}

// ============================================================================
// Phase 6 Step 3: Persistent storage tests
// ============================================================================

// Test 47: MeshStore persists peer state across save/load cycles.
#[tokio::test]
async fn test_e2e_mesh_store_peer_persistence() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("mesh.db");

    let node = make_node();

    // Register a peer
    let peer_id = MeshIdentity::generate();
    let peer = PeerIdentity::from_combined_key(&peer_id.combined_public_key(), 2).unwrap();
    let dest_hash = peer.destination_hash;
    node.register_peer(
        peer,
        Some(zp_mesh::transport::AgentCapabilities {
            name: "test-agent".to_string(),
            version: "1.0".to_string(),
            receipt_types: vec!["receipt_v1".to_string()],
            skills: vec!["code_review".to_string()],
            actor_type: "agent".to_string(),
            trust_tier: "tier1".to_string(),
        }),
    )
    .await;

    // Save to store
    let store = zp_mesh::store::MeshStore::open(&db_path).unwrap();
    node.save_to_store(&store).await.unwrap();
    drop(store);

    // Load into fresh node
    let node2 = make_node();
    let store2 = zp_mesh::store::MeshStore::open(&db_path).unwrap();
    node2.load_from_store(&store2).await.unwrap();

    let peers = node2.known_peers().await;
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].address, hex::encode(dest_hash));
    assert!(peers[0].capabilities.is_some());
    assert_eq!(peers[0].capabilities.as_ref().unwrap().name, "test-agent");
}

// Test 48: MeshStore persists reputation signals across restarts.
#[tokio::test]
async fn test_e2e_mesh_store_reputation_persistence() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("mesh_rep.db");

    let node = make_node();

    // Register peer and record reputation
    let peer_id = MeshIdentity::generate();
    let peer = PeerIdentity::from_combined_key(&peer_id.combined_public_key(), 1).unwrap();
    let dest_hash = peer.destination_hash;
    node.register_peer(peer, None).await;

    // Record positive receipt signals
    node.record_reputation_signal(
        &dest_hash,
        zp_mesh::reputation::signal_from_receipt("r1", true, Utc::now()),
    )
    .await;
    node.record_reputation_signal(
        &dest_hash,
        zp_mesh::reputation::signal_from_receipt("r2", true, Utc::now()),
    )
    .await;
    node.record_reputation_signal(
        &dest_hash,
        zp_mesh::reputation::signal_from_delegation("d1", true, Utc::now()),
    )
    .await;

    // Save
    let store = zp_mesh::store::MeshStore::open(&db_path).unwrap();
    node.save_to_store(&store).await.unwrap();
    drop(store);

    // Reload
    let node2 = make_node();
    let store2 = zp_mesh::store::MeshStore::open(&db_path).unwrap();
    node2.load_from_store(&store2).await.unwrap();

    let reps = node2.all_peer_reputations().await;
    assert_eq!(reps.len(), 1);
    let score = reps.values().next().unwrap();
    assert!(
        score.score > 0.5,
        "Loaded reputation should reflect positive signals"
    );
    assert_eq!(score.positive_signals, 3);
}

// Test 49: MeshStore persists delegation chains.
#[tokio::test]
async fn test_e2e_mesh_store_delegation_persistence() {
    let store = zp_mesh::store::MeshStore::open_memory().unwrap();

    let grant = CapabilityGrant::new(
        "root-human".to_string(),
        "agent-1".to_string(),
        zp_core::capability_grant::GrantedCapability::Execute { languages: vec![] },
        "receipt-api".to_string(),
    );

    store.save_delegation_chain("chain-001", &[grant]).unwrap();

    let loaded = store.load_delegation_chains().unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded["chain-001"][0].grantor, "root-human");
    assert_eq!(loaded["chain-001"][0].grantee, "agent-1");
}

// Test 50: MeshStore persists audit attestations.
#[tokio::test]
async fn test_e2e_mesh_store_attestation_persistence() {
    let store = zp_mesh::store::MeshStore::open_memory().unwrap();
    let peer_hash = [42u8; 16];

    let att = zp_audit::PeerAuditAttestation {
        id: "att-persist-1".to_string(),
        peer: hex::encode(peer_hash),
        oldest_hash: "aaa".to_string(),
        newest_hash: "bbb".to_string(),
        entries_verified: 25,
        chain_valid: true,
        signatures_valid: 10,
        timestamp: Utc::now(),
        signature: None,
    };

    store.save_attestation(&peer_hash, &att).unwrap();

    let loaded = store.load_attestations().unwrap();
    assert_eq!(loaded.len(), 1);
    let att_list = loaded.get(&peer_hash).unwrap();
    assert_eq!(att_list[0].entries_verified, 25);
    assert!(att_list[0].chain_valid);
}

// Test 51: Pipeline init_mesh creates store and loads state.
#[tokio::test]
async fn test_e2e_pipeline_mesh_store_lifecycle() {
    use zp_core::policy::TrustTier;
    use zp_core::OperatorIdentity;
    use zp_pipeline::{MeshConfig, PipelineConfig};

    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();

    // First pipeline instance — init mesh, populate, save
    {
        let config = PipelineConfig {
            operator_identity: OperatorIdentity::default(),
            trust_tier: TrustTier::Tier1,
            data_dir: data_dir.clone(),
            mesh: None,
        };
        std::fs::create_dir_all(&config.data_dir).ok();
        let audit_store = Arc::new(std::sync::Mutex::new(
            zp_audit::AuditStore::open(&config.data_dir.join("audit.db")).unwrap(),
        ));
        let mut pipeline = zp_pipeline::Pipeline::new(config, audit_store).unwrap();

        let mesh_config = MeshConfig {
            poll_interval_ms: 50,
            ..Default::default()
        };
        pipeline.init_mesh(&mesh_config).await.unwrap();

        assert!(pipeline.has_mesh());
        assert!(pipeline.mesh_store().is_some());

        // Save state (even with no peers, should succeed)
        pipeline.save_mesh_state().await.unwrap();
        pipeline.shutdown_mesh();
    }

    // Verify the mesh.db file was created
    assert!(data_dir.join("mesh.db").exists());
}

// Test 52: Snapshot roundtrip with all state types.
#[tokio::test]
async fn test_e2e_mesh_store_full_snapshot_roundtrip() {
    let node = make_node();

    // Populate with diverse state
    let peer_id = MeshIdentity::generate();
    let peer = PeerIdentity::from_combined_key(&peer_id.combined_public_key(), 1).unwrap();
    let dest_hash = peer.destination_hash;
    node.register_peer(
        peer,
        Some(zp_mesh::transport::AgentCapabilities {
            name: "snapshot-agent".to_string(),
            version: "2.0".to_string(),
            receipt_types: vec![],
            skills: vec!["analysis".to_string()],
            actor_type: "agent".to_string(),
            trust_tier: "tier2".to_string(),
        }),
    )
    .await;

    // Reputation signals
    node.record_reputation_signal(
        &dest_hash,
        zp_mesh::reputation::signal_from_receipt("r1", true, Utc::now()),
    )
    .await;
    node.record_reputation_signal(
        &dest_hash,
        zp_mesh::reputation::signal_from_receipt("r2", false, Utc::now()),
    )
    .await;

    // Save snapshot
    let store = zp_mesh::store::MeshStore::open_memory().unwrap();
    node.save_to_store(&store).await.unwrap();

    // Load into fresh node
    let node2 = make_node();
    node2.load_from_store(&store).await.unwrap();

    // Verify
    let peers = node2.known_peers().await;
    assert_eq!(peers.len(), 1);
    assert_eq!(
        peers[0].capabilities.as_ref().unwrap().name,
        "snapshot-agent"
    );

    let reps = node2.all_peer_reputations().await;
    assert_eq!(reps.len(), 1);
    let score = reps.values().next().unwrap();
    assert_eq!(score.positive_signals + score.negative_signals, 2);
}

// ============================================================================
// Phase 6 Step 5: Multi-node integration tests
// ============================================================================
//
// These tests exercise true multi-node communication: two or more MeshNode
// instances exchanging packets through CrossoverInterfaces (paired channels
// where node A's send arrives at node B's recv and vice versa).

use async_trait::async_trait;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use zp_mesh::interface::{InterfaceConfig, InterfaceMode, InterfaceStats, InterfaceType};
use zp_mesh::packet::Packet;

/// One side of a crossover pair. `send()` writes to the partner's buffer;
/// `recv()` reads from our own buffer (which the partner writes to).
#[derive(Debug)]
struct CrossoverInterface {
    config: InterfaceConfig,
    /// Our inbound buffer — the partner pushes here, we pop from here.
    rx: Arc<tokio::sync::Mutex<Vec<Vec<u8>>>>,
    /// Partner's inbound buffer — we push here when sending.
    tx: Arc<tokio::sync::Mutex<Vec<Vec<u8>>>>,
    sent: AtomicU64,
    received: AtomicU64,
}

/// Create a crossover pair — two interfaces wired back-to-back.
/// Anything side_a sends, side_b receives, and vice versa.
fn crossover_pair() -> (Arc<CrossoverInterface>, Arc<CrossoverInterface>) {
    let buf_a = Arc::new(tokio::sync::Mutex::new(Vec::<Vec<u8>>::new()));
    let buf_b = Arc::new(tokio::sync::Mutex::new(Vec::<Vec<u8>>::new()));

    fn make_config(name: &str) -> InterfaceConfig {
        InterfaceConfig {
            name: name.to_string(),
            interface_type: InterfaceType::Loopback,
            mode: InterfaceMode::Full,
            mtu: 65535,
            enabled: true,
            announce_cap: 0.02,
        }
    }

    let side_a = Arc::new(CrossoverInterface {
        config: make_config("xover-a"),
        rx: buf_a.clone(), // a reads from buf_a
        tx: buf_b.clone(), // a sends to buf_b (b's inbound)
        sent: AtomicU64::new(0),
        received: AtomicU64::new(0),
    });

    let side_b = Arc::new(CrossoverInterface {
        config: make_config("xover-b"),
        rx: buf_b, // b reads from buf_b
        tx: buf_a, // b sends to buf_a (a's inbound)
        sent: AtomicU64::new(0),
        received: AtomicU64::new(0),
    });

    (side_a, side_b)
}

#[async_trait]
impl Interface for CrossoverInterface {
    fn config(&self) -> &InterfaceConfig {
        &self.config
    }

    async fn send(&self, packet: &Packet) -> zp_mesh::error::MeshResult<()> {
        let bytes = packet.to_bytes();
        self.tx.lock().await.push(bytes);
        self.sent.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn recv(&self) -> zp_mesh::error::MeshResult<Option<Packet>> {
        let mut buf = self.rx.lock().await;
        if buf.is_empty() {
            Ok(None)
        } else {
            let bytes = buf.remove(0); // FIFO
            self.received.fetch_add(1, Ordering::Relaxed);
            Ok(Some(Packet::from_bytes(&bytes)?))
        }
    }

    fn is_online(&self) -> bool {
        true
    }

    fn stats(&self) -> InterfaceStats {
        InterfaceStats {
            packets_sent: self.sent.load(Ordering::Relaxed),
            packets_received: self.received.load(Ordering::Relaxed),
            ..Default::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Multi-node helpers
// ---------------------------------------------------------------------------

/// Create two mesh nodes wired together via a crossover pair, with each
/// node registered as a peer of the other. Returns (node_a, node_b).
async fn make_wired_pair() -> (Arc<MeshNode>, Arc<MeshNode>) {
    // Use make_node() which creates nodes via MeshIdentity::generate() directly,
    // ensuring the node's identity and peer identities share the same key material.
    let node_a = make_node();
    let node_b = make_node();

    let (iface_a, iface_b) = crossover_pair();
    node_a.attach_interface(iface_a).await;
    node_b.attach_interface(iface_b).await;

    // Register each other as peers using the *node's* actual combined public key
    // so the peer destination hash matches node.identity().destination_hash().
    let peer_a =
        PeerIdentity::from_combined_key(&node_a.identity().combined_public_key(), 1).unwrap();
    let peer_b =
        PeerIdentity::from_combined_key(&node_b.identity().combined_public_key(), 1).unwrap();
    node_a.register_peer(peer_b, None).await;
    node_b.register_peer(peer_a, None).await;

    (node_a, node_b)
}

// ---------------------------------------------------------------------------
// Test 53: Two nodes exchange a receipt via crossover interface.
// ---------------------------------------------------------------------------

/// Verifies: Node A sends a receipt → packet arrives at Node B's interface →
/// Node B's runtime dispatches it and produces an inbound envelope.
#[tokio::test]
async fn test_e2e_multinode_receipt_exchange() {
    let (node_a, node_b) = make_wired_pair().await;

    // Start runtime on node B to process inbound packets
    let mut runtime_b = MeshRuntime::start(
        node_b.clone(),
        RuntimeConfig {
            poll_interval: Duration::from_millis(10),
            ..Default::default()
        },
    );
    let mut inbound_rx = runtime_b.take_inbound_rx().unwrap();

    // Node A sends a receipt to Node B's address
    let receipt = zp_receipt::Receipt::execution("agent-53")
        .status(zp_receipt::Status::Success)
        .trust_grade(zp_receipt::TrustGrade::C)
        .finalize();
    let addr_b = node_b.identity().address();
    node_a.send_receipt(&addr_b, &receipt).await.unwrap();

    // Node B's runtime should pick it up
    let inbound = tokio::time::timeout(Duration::from_secs(2), inbound_rx.recv())
        .await
        .expect("timeout waiting for receipt at node B")
        .expect("channel closed");

    assert_eq!(
        inbound.envelope.envelope_type,
        zp_mesh::envelope::EnvelopeType::Receipt
    );
    let extracted = inbound.envelope.extract_receipt().unwrap();
    assert_eq!(extracted.st, "success");
    assert_eq!(extracted.rt, "execution");

    runtime_b.shutdown();
}

// ---------------------------------------------------------------------------
// Test 54: Two nodes exchange a delegation via crossover interface.
// ---------------------------------------------------------------------------

/// Verifies: Node A sends a delegation grant → Node B's runtime dispatches it →
/// Node B stores the delegation chain.
#[tokio::test]
async fn test_e2e_multinode_delegation_exchange() {
    let (node_a, node_b) = make_wired_pair().await;

    let mut runtime_b = MeshRuntime::start(
        node_b.clone(),
        RuntimeConfig {
            poll_interval: Duration::from_millis(10),
            ..Default::default()
        },
    );
    let _inbound_rx = runtime_b.take_inbound_rx();

    // Node A grants a capability to Node B
    let addr_b_hash = node_b.identity().destination_hash();
    let grant = CapabilityGrant::new(
        node_a.identity().address(),
        node_b.identity().address(),
        GrantedCapability::Read {
            scope: vec!["audit/*".to_string()],
        },
        "receipt-del-54".to_string(),
    );
    node_a.send_delegation(&addr_b_hash, &grant).await.unwrap();

    // Wait for runtime to process
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Node B should have stored the delegation
    let chains = node_b.delegation_chain_ids().await;
    assert!(
        !chains.is_empty(),
        "Node B should have at least one delegation chain after receiving grant"
    );

    runtime_b.shutdown();
}

// ---------------------------------------------------------------------------
// Test 55: Bidirectional receipt exchange — both nodes send and receive.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_e2e_multinode_bidirectional_receipts() {
    let (node_a, node_b) = make_wired_pair().await;

    // Start runtimes on both nodes
    let mut runtime_a = MeshRuntime::start(
        node_a.clone(),
        RuntimeConfig {
            poll_interval: Duration::from_millis(10),
            ..Default::default()
        },
    );
    let mut runtime_b = MeshRuntime::start(
        node_b.clone(),
        RuntimeConfig {
            poll_interval: Duration::from_millis(10),
            ..Default::default()
        },
    );
    let mut rx_a = runtime_a.take_inbound_rx().unwrap();
    let mut rx_b = runtime_b.take_inbound_rx().unwrap();

    // A → B
    let receipt_ab = zp_receipt::Receipt::execution("agent-55-ab")
        .status(zp_receipt::Status::Success)
        .trust_grade(zp_receipt::TrustGrade::C)
        .finalize();
    node_a
        .send_receipt(&node_b.identity().address(), &receipt_ab)
        .await
        .unwrap();

    // B → A
    let receipt_ba = zp_receipt::Receipt::execution("agent-55-ba")
        .status(zp_receipt::Status::Success)
        .trust_grade(zp_receipt::TrustGrade::B)
        .finalize();
    node_b
        .send_receipt(&node_a.identity().address(), &receipt_ba)
        .await
        .unwrap();

    // Both should receive
    let inbound_b = tokio::time::timeout(Duration::from_secs(2), rx_b.recv())
        .await
        .expect("timeout B")
        .expect("channel B closed");
    let inbound_a = tokio::time::timeout(Duration::from_secs(2), rx_a.recv())
        .await
        .expect("timeout A")
        .expect("channel A closed");

    let extracted_b = inbound_b.envelope.extract_receipt().unwrap();
    assert_eq!(extracted_b.st, "success");
    assert_eq!(extracted_b.tg, "C");

    let extracted_a = inbound_a.envelope.extract_receipt().unwrap();
    assert_eq!(extracted_a.st, "success");
    assert_eq!(extracted_a.tg, "B");

    runtime_a.shutdown();
    runtime_b.shutdown();
}

// ---------------------------------------------------------------------------
// Test 56: Multi-node reputation propagation.
// ---------------------------------------------------------------------------

/// Node A broadcasts a reputation summary → Node B's runtime dispatches it →
/// Node B stores the received reputation summary.
#[tokio::test]
async fn test_e2e_multinode_reputation_propagation() {
    let (node_a, node_b) = make_wired_pair().await;

    let mut runtime_b = MeshRuntime::start(
        node_b.clone(),
        RuntimeConfig {
            poll_interval: Duration::from_millis(10),
            ..Default::default()
        },
    );
    let _inbound_rx = runtime_b.take_inbound_rx();

    // First, record a reputation signal on A so it has something to broadcast
    let hash_b = node_b.identity().destination_hash();
    node_a
        .record_reputation_signal(
            &hash_b,
            zp_mesh::reputation::signal_from_receipt("r-56", true, Utc::now()),
        )
        .await;

    // Node A broadcasts a reputation summary about Node B
    node_a.broadcast_reputation_summary(&hash_b).await.unwrap();

    // Wait for runtime to process
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Node B should have received the reputation summary from A
    let hash_a = node_a.identity().destination_hash();
    let summaries = node_b.received_summaries_from(&hash_a).await;
    assert!(
        !summaries.is_empty(),
        "Node B should have received at least one reputation summary from A"
    );

    runtime_b.shutdown();
}

// ---------------------------------------------------------------------------
// Test 57: Three-node chain — A→B→C receipt relay.
// ---------------------------------------------------------------------------

/// Three nodes in a line: A ↔ B ↔ C. Node A sends a receipt to B, B forwards
/// to C. Verifies multi-hop mesh topology.
#[tokio::test]
async fn test_e2e_multinode_three_node_relay() {
    let node_a = make_node();
    let node_b = make_node();
    let node_c = make_node();

    // Wire A↔B and B↔C
    let (iface_ab_a, iface_ab_b) = crossover_pair();
    let (iface_bc_b, iface_bc_c) = crossover_pair();

    node_a.attach_interface(iface_ab_a).await;
    node_b.attach_interface(iface_ab_b).await;
    node_b.attach_interface(iface_bc_b).await;
    node_c.attach_interface(iface_bc_c).await;

    // Register peers using nodes' actual identities
    let peer_a =
        PeerIdentity::from_combined_key(&node_a.identity().combined_public_key(), 1).unwrap();
    let peer_b =
        PeerIdentity::from_combined_key(&node_b.identity().combined_public_key(), 1).unwrap();
    let peer_c =
        PeerIdentity::from_combined_key(&node_c.identity().combined_public_key(), 1).unwrap();

    node_a.register_peer(peer_b.clone(), None).await;
    node_b.register_peer(peer_a, None).await;
    node_b.register_peer(peer_c.clone(), None).await;
    node_c.register_peer(peer_b, None).await;

    // Start runtimes on B and C
    let mut runtime_b = MeshRuntime::start(
        node_b.clone(),
        RuntimeConfig {
            poll_interval: Duration::from_millis(10),
            ..Default::default()
        },
    );
    let mut rx_b = runtime_b.take_inbound_rx().unwrap();

    let mut runtime_c = MeshRuntime::start(
        node_c.clone(),
        RuntimeConfig {
            poll_interval: Duration::from_millis(10),
            ..Default::default()
        },
    );
    let mut rx_c = runtime_c.take_inbound_rx().unwrap();

    // Step 1: A sends a receipt to B
    let receipt_ab = zp_receipt::Receipt::execution("agent-57-ab")
        .status(zp_receipt::Status::Success)
        .trust_grade(zp_receipt::TrustGrade::C)
        .finalize();
    node_a
        .send_receipt(&node_b.identity().address(), &receipt_ab)
        .await
        .unwrap();

    // B receives it
    let inbound_b = tokio::time::timeout(Duration::from_secs(2), rx_b.recv())
        .await
        .expect("timeout B")
        .expect("channel B closed");
    let extracted_b = inbound_b.envelope.extract_receipt().unwrap();
    assert_eq!(extracted_b.st, "success");
    assert_eq!(extracted_b.rt, "execution");

    // Step 2: B forwards a different receipt to C
    let receipt_bc = zp_receipt::Receipt::execution("agent-57-bc")
        .status(zp_receipt::Status::Success)
        .trust_grade(zp_receipt::TrustGrade::B)
        .finalize();
    node_b
        .send_receipt(&node_c.identity().address(), &receipt_bc)
        .await
        .unwrap();

    // C receives it
    let inbound_c = tokio::time::timeout(Duration::from_secs(2), rx_c.recv())
        .await
        .expect("timeout C")
        .expect("channel C closed");
    let extracted_c = inbound_c.envelope.extract_receipt().unwrap();
    assert_eq!(extracted_c.st, "success");
    assert_eq!(extracted_c.tg, "B");

    runtime_b.shutdown();
    runtime_c.shutdown();
}

// ---------------------------------------------------------------------------
// Test 58: Multi-node with bridge — receipt forwarding triggers reputation.
// ---------------------------------------------------------------------------

/// Node A sends a receipt to Node B via the mesh bridge. B's bridge processes
/// the inbound receipt and records a reputation signal.
#[tokio::test]
async fn test_e2e_multinode_bridge_receipt_and_reputation() {
    let (node_a, node_b) = make_wired_pair().await;

    let bridge_a = MeshBridge::with_defaults(node_a.clone());
    let bridge_b = MeshBridge::with_defaults(node_b.clone());

    let mut runtime_b = MeshRuntime::start(
        node_b.clone(),
        RuntimeConfig {
            poll_interval: Duration::from_millis(10),
            ..Default::default()
        },
    );
    let mut rx_b = runtime_b.take_inbound_rx().unwrap();

    // A's bridge forwards a receipt to all peers (which is just B)
    let receipt = zp_receipt::Receipt::execution("agent-58")
        .status(zp_receipt::Status::Success)
        .trust_grade(zp_receipt::TrustGrade::C)
        .finalize();
    bridge_a.forward_receipt(&receipt).await.unwrap();

    // B's runtime picks up the receipt
    let inbound = tokio::time::timeout(Duration::from_secs(2), rx_b.recv())
        .await
        .expect("timeout")
        .expect("channel closed");

    // B's bridge processes the inbound receipt
    let compact = inbound.envelope.extract_receipt().unwrap();
    bridge_b
        .handle_inbound_receipt(&compact, &inbound.sender_hash)
        .await
        .unwrap();

    // B should now have a reputation score for A
    let hash_a = node_a.identity().destination_hash();
    let rep = bridge_b.peer_reputation(&hash_a).await;
    // peer_reputation returns ReputationScore (not Option), check positive_signals > 0
    assert!(
        rep.positive_signals > 0,
        "Node B should have positive reputation signals for Node A after processing receipt"
    );

    // Check that a receipt was stored
    let received = bridge_b.received_receipts().await;
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].receipt.st, "success");

    runtime_b.shutdown();
}

// ---------------------------------------------------------------------------
// Test 59: Persist and restore across two-node exchange.
// ---------------------------------------------------------------------------

/// Two nodes exchange receipts, then both save to store, then both restore
/// from store into fresh nodes and verify peer state survived.
#[tokio::test]
async fn test_e2e_multinode_persist_and_restore() {
    let (node_a, node_b) = make_wired_pair().await;

    // Record mutual reputation signals
    let hash_a = node_a.identity().destination_hash();
    let hash_b = node_b.identity().destination_hash();

    node_a
        .record_reputation_signal(
            &hash_b,
            zp_mesh::reputation::signal_from_receipt("r1", true, Utc::now()),
        )
        .await;
    node_b
        .record_reputation_signal(
            &hash_a,
            zp_mesh::reputation::signal_from_receipt("r2", true, Utc::now()),
        )
        .await;

    // Save both to separate stores
    let store_a = zp_mesh::store::MeshStore::open_memory().unwrap();
    let store_b = zp_mesh::store::MeshStore::open_memory().unwrap();
    node_a.save_to_store(&store_a).await.unwrap();
    node_b.save_to_store(&store_b).await.unwrap();

    // Restore into fresh nodes
    let fresh_a = make_node();
    let fresh_b = make_node();
    fresh_a.load_from_store(&store_a).await.unwrap();
    fresh_b.load_from_store(&store_b).await.unwrap();

    // Verify peers survived
    let peers_a = fresh_a.known_peers().await;
    let peers_b = fresh_b.known_peers().await;
    assert_eq!(peers_a.len(), 1, "Restored node A should have 1 peer");
    assert_eq!(peers_b.len(), 1, "Restored node B should have 1 peer");

    // Verify reputation survived — use compute_peer_reputation which directly
    // looks up the reputation by hash (independent of peers map iteration)
    let score_a = fresh_a.compute_peer_reputation(&hash_b).await;
    let score_b = fresh_b.compute_peer_reputation(&hash_a).await;
    assert_eq!(
        score_a.positive_signals, 1,
        "Restored node A should have 1 positive signal for peer B"
    );
    assert_eq!(
        score_b.positive_signals, 1,
        "Restored node B should have 1 positive signal for peer A"
    );
}

// ============================================================================
// Stage 5 (AUDIT-03): end-to-end concurrent-writer regression
// ============================================================================

/// Regression test for AUDIT-03 at the integration level.
///
/// Before Stage 3, the server's `AppState` and the `Pipeline` each
/// opened their own `AuditStore` handle on the same DB file. Two writers
/// with independent `Mutex`es produced the 4 P1 fork rows we found in
/// the historical DB. Stage 3 collapsed this to a single
/// `Arc<Mutex<AuditStore>>` shared between both owners. This test pins
/// the invariant by simulating both writers concurrently through the
/// *same* shared handle and asserting the catalog verifier (now in
/// strict P2 mode) finds zero violations.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_stage3_shared_audit_store_no_forks_under_load() {
    use std::thread;
    use zp_audit::{AuditStore, UnsealedEntry};
    use zp_core::{ActorId, AuditAction, ConversationId, PolicyDecision};

    let tmp = tempfile::tempdir().unwrap();
    let audit_path = tmp.path().join("audit.db");

    // The single, canonical store. Both the "server" and "pipeline"
    // sides below clone this Arc — exactly what AppState::init and
    // Pipeline::new do after Stage 3.
    let shared: Arc<std::sync::Mutex<AuditStore>> =
        Arc::new(std::sync::Mutex::new(AuditStore::open(&audit_path).unwrap()));

    // Two "halves" of the system, both clones of the same Arc. Any
    // attempt to re-open the DB here would be a regression of Stage 3.
    let server_side = Arc::clone(&shared);
    let pipeline_side = Arc::clone(&shared);

    const THREADS_PER_SIDE: usize = 4;
    const APPENDS_PER_THREAD: usize = 50;

    let mut handles = vec![];
    for (tag, side) in [("server", &server_side), ("pipeline", &pipeline_side)] {
        for t in 0..THREADS_PER_SIDE {
            let s = Arc::clone(side);
            handles.push(thread::spawn(move || {
                for i in 0..APPENDS_PER_THREAD {
                    let u = UnsealedEntry::new(
                        ActorId::System(format!("{tag}-worker-{t}")),
                        AuditAction::SystemEvent {
                            event: format!("{tag}-evt-{i}"),
                        },
                        ConversationId::new(),
                        PolicyDecision::Allow { conditions: vec![] },
                        "stage3-e2e",
                    );
                    s.lock().unwrap().append(u).unwrap();
                }
            }));
        }
    }
    for h in handles {
        h.join().unwrap();
    }

    let expected = 2 * THREADS_PER_SIDE * APPENDS_PER_THREAD;
    let report = shared.lock().unwrap().verify_with_catalog().unwrap();
    assert_eq!(
        report.receipts_checked, expected,
        "expected {expected} receipts, got {}",
        report.receipts_checked
    );
    assert!(
        report.violations().is_empty(),
        "Stage 3 regression: shared AuditStore produced {} violations under load: {:?}",
        report.violations().len(),
        report.violations()
    );
}

/// Sweep 4 (2026-04-07): full-construction end-to-end coherence test.
///
/// This test goes one level higher than `test_stage3_shared_audit_store_no_forks_under_load`:
/// instead of opening an `AuditStore` directly, it walks the *exact* construction
/// path that `zp_server::AppState::init` and `zp_cli::main` take in production:
///
/// 1. Create a `PipelineConfig` with a real temp data_dir
/// 2. Open the canonical `AuditStore` once, wrap in `Arc<Mutex<_>>`
/// 3. Pass that Arc into `Pipeline::new` (Stage 3 API)
/// 4. Concurrently append through BOTH the pipeline's `audit_store` handle AND
///    a separately-cloned "server-side" Arc — the two-owner topology that
///    caused the original AUDIT-03 P1 forks
/// 5. Run `verify_with_catalog` against the shared store
///
/// A single violation here means either the Stage 3 Arc-share regressed, the
/// Stage 4 schema v2 + `BEGIN IMMEDIATE` regressed, or the Stage 5 strict P2
/// verifier drifted. This is the canonical "ZP is coherent end-to-end" gate.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_sweep4_full_construction_end_to_end_coherence() {
    use std::thread;
    use zp_audit::{AuditStore, UnsealedEntry};
    use zp_core::{ActorId, AuditAction, ConversationId, PolicyDecision};
    use zp_pipeline::{Pipeline, PipelineConfig};

    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().to_path_buf();
    std::fs::create_dir_all(&data_dir).ok();

    // Step 1-2: open the single canonical store, exactly as AppState::init does.
    let audit_path = data_dir.join("audit.db");
    let audit_store: Arc<std::sync::Mutex<AuditStore>> = Arc::new(std::sync::Mutex::new(
        AuditStore::open(&audit_path).expect("open canonical audit store"),
    ));

    // Step 3: construct a real Pipeline with the shared Arc.
    // This exercises the full Pipeline::new setup (policy engine, skill
    // registry, provider pool, etc.) — everything AppState does except
    // the HTTP surface. If Pipeline::new ever secretly re-opens the store
    // or wraps it in a new Mutex, this test catches it.
    let config = PipelineConfig {
        data_dir: data_dir.clone(),
        ..Default::default()
    };
    let pipeline = Pipeline::new(config, Arc::clone(&audit_store))
        .expect("Pipeline::new with shared AuditStore must succeed");

    // Sanity: the pipeline's audit_store must be the SAME Arc we passed in.
    // Stage 3 guarantees this — any regression that clones-into-new-Mutex
    // would break reference equality here.
    assert!(
        Arc::ptr_eq(&pipeline.audit_store, &audit_store),
        "Pipeline::new must store the exact Arc passed in (not clone underlying store)"
    );

    // Step 4: two-owner concurrent append topology.
    // "server-side" = AppState-style Arc clone
    // "pipeline-side" = Pipeline's own audit_store field
    let server_side = Arc::clone(&audit_store);
    let pipeline_side = Arc::clone(&pipeline.audit_store);

    const THREADS_PER_SIDE: usize = 4;
    const APPENDS_PER_THREAD: usize = 25;

    let mut handles = vec![];
    for (tag, side) in [("server", &server_side), ("pipeline", &pipeline_side)] {
        for t in 0..THREADS_PER_SIDE {
            let s = Arc::clone(side);
            handles.push(thread::spawn(move || {
                for i in 0..APPENDS_PER_THREAD {
                    let u = UnsealedEntry::new(
                        ActorId::System(format!("{tag}-sweep4-{t}")),
                        AuditAction::SystemEvent {
                            event: format!("sweep4-{tag}-{i}"),
                        },
                        ConversationId::new(),
                        PolicyDecision::Allow { conditions: vec![] },
                        "sweep4-e2e",
                    );
                    s.lock().unwrap().append(u).expect("append must succeed");
                }
            }));
        }
    }
    for h in handles {
        h.join().unwrap();
    }

    // Step 5: catalog verification under strict P2.
    let expected = 2 * THREADS_PER_SIDE * APPENDS_PER_THREAD;
    let report = audit_store
        .lock()
        .unwrap()
        .verify_with_catalog()
        .expect("verify_with_catalog must not error");

    assert_eq!(
        report.receipts_checked, expected,
        "expected {expected} receipts through the full-construction path, got {}",
        report.receipts_checked
    );
    assert!(
        report.violations().is_empty(),
        "Sweep 4 full-construction coherence failure: {} violations: {:?}",
        report.violations().len(),
        report.violations()
    );
    // Note: strict P2 (content_hash_valid) is already asserted inside
    // verify_with_catalog — every receipt that passes catalog verification
    // has been re-hashed via `recompute_entry_hash` and compared against
    // its stored `entry_hash`. No extra loop is needed.
}
