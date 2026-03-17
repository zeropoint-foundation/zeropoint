//! Lab 16: Capstone — Portable Trust
//!
//! Full integration
//! Run: cargo run --example lab16_capstone -p course-examples

use chrono::{Duration, Utc};
use std::time::Duration as StdDuration;
use zp_audit::{AuditStore, ChainBuilder, ChainVerifier};
use zp_core::audit::ActorId;
use zp_core::capability_grant::{CapabilityGrant, Constraint, GrantedCapability};
use zp_core::delegation_chain::DelegationChain;
use zp_core::governance::ConsensusThreshold;
use zp_core::policy::{ActionType, PolicyContext, TrustTier};
use zp_core::ConversationId;
use zp_keys::{AgentKey, GenesisKey, OperatorKey};
use zp_mesh::consensus::{ConsensusCoordinator, ConsensusOutcome, Proposal, Vote};
use zp_mesh::reputation::{
    PeerReputation, ReputationSignal, ReputationWeights, SignalCategory, SignalPolarity,
};
use zp_policy::gate::Guard;
use zp_policy::{GovernanceGate, PolicyEngine};
use zp_receipt::{Receipt, ReceiptChain, Status, TrustGrade};

fn main() {
    println!("FLEET SUMMARY");
    println!("─────────────");

    // 1. Key hierarchy: genesis → 2 operators → 5 agents
    let genesis = GenesisKey::generate("fleet-command");
    let op_east =
        OperatorKey::generate("ops-east", &genesis, Some(Utc::now() + Duration::days(365)));
    let op_west =
        OperatorKey::generate("ops-west", &genesis, Some(Utc::now() + Duration::days(365)));

    let agents: Vec<AgentKey> = (0..3)
        .map(|i| {
            AgentKey::generate(
                &format!("agent-east-{}", i),
                &op_east,
                Some(Utc::now() + Duration::days(30)),
            )
        })
        .chain((0..2).map(|i| {
            AgentKey::generate(
                &format!("agent-west-{}", i),
                &op_west,
                Some(Utc::now() + Duration::days(30)),
            )
        }))
        .collect();

    // Sub-agent delegation
    let sub_agent = AgentKey::generate(
        "sub-agent-east-0",
        &op_east,
        Some(Utc::now() + Duration::days(7)),
    );

    println!("Genesis: fleet-command");
    println!("Operators: 2");
    println!("Agents: {} (+ 1 sub-agent)", agents.len());

    // 2. Capability grants with delegation
    let root_grant = CapabilityGrant::new(
        hex::encode(genesis.public_key()),
        hex::encode(op_east.public_key()),
        GrantedCapability::Read {
            scope: vec!["data/**".into()],
        },
        "receipt-root".to_string(),
    )
    .with_trust_tier(TrustTier::Tier2)
    .with_expiration(Utc::now() + Duration::days(365))
    .with_max_delegation_depth(3);

    let agent_grant = CapabilityGrant::new(
        hex::encode(op_east.public_key()),
        hex::encode(agents[0].public_key()),
        GrantedCapability::Read {
            scope: vec!["data/reports/**".into()],
        },
        "receipt-agent".to_string(),
    )
    .with_trust_tier(TrustTier::Tier2)
    .with_expiration(Utc::now() + Duration::days(90))
    .with_constraint(Constraint::RequireReceipt);

    let sub_grant = CapabilityGrant::new(
        hex::encode(agents[0].public_key()),
        hex::encode(sub_agent.public_key()),
        GrantedCapability::Read {
            scope: vec!["data/reports/billing/*".into()],
        },
        "receipt-sub".to_string(),
    )
    .with_trust_tier(TrustTier::Tier2)
    .with_expiration(Utc::now() + Duration::days(7))
    .with_constraint(Constraint::RequireReceipt)
    .with_constraint(Constraint::TimeWindow {
        start_hour: 9,
        end_hour: 17,
    });

    match DelegationChain::verify(vec![root_grant, agent_grant, sub_grant], true) {
        Ok(_) => println!("Delegation chains: verified ✓"),
        Err(e) => println!("Delegation chains: FAILED {:?}", e),
    }

    // 3. GovernanceGate
    println!("\nGOVERNANCE");
    println!("─────────");
    let guard = Guard::with_config(100, StdDuration::from_secs(60), TrustTier::Tier0);
    guard.block_actor(&format!("{:?}", ActorId::User("malicious".into())));
    let gate = GovernanceGate::with_guard("fleet-gate", PolicyEngine::new(), guard);

    let mut allowed = 0;
    let mut warned = 0;
    let mut blocked = 0;

    let actions = vec![
        ActionType::Chat,
        ActionType::Chat,
        ActionType::Read {
            target: "file.txt".into(),
        },
        ActionType::Write {
            target: "output.txt".into(),
        },
        ActionType::Execute {
            language: "python".into(),
        },
        ActionType::CredentialAccess {
            credential_ref: "api-key".into(),
        },
    ];

    let mut receipt_chain = ReceiptChain::new("fleet-receipts");

    for (i, action) in actions.iter().enumerate() {
        let ctx = PolicyContext {
            action: action.clone(),
            trust_tier: TrustTier::Tier1,
            channel: zp_core::Channel::Cli,
            conversation_id: ConversationId::new(),
            skill_ids: vec![],
            tool_names: vec![],
            mesh_context: None,
        };
        let result = gate.evaluate(&ctx, ActorId::User(format!("agent-{}", i % 5)));

        if result.is_allowed() {
            allowed += 1;
        } else if result.is_blocked() {
            blocked += 1;
        } else {
            warned += 1;
        }

        // Receipt for each action
        let mut receipt = Receipt::execution(&format!("agent-{}", i % 5))
            .status(if result.is_allowed() {
                Status::Success
            } else {
                Status::Denied
            })
            .trust_grade(TrustGrade::B)
            .finalize();
        receipt_chain.append(&mut receipt).unwrap();
    }

    println!("Guard: active (blocklist + rate limiting)");
    println!("Actions evaluated: {}", actions.len());
    println!(
        "  Allowed: {}  Warned: {}  Blocked: {}",
        allowed, warned, blocked
    );
    receipt_chain.verify_integrity().unwrap();
    println!("Receipts: {} (chain verified ✓)", receipt_chain.len());

    // 4. Audit trail
    println!("\nAUDIT");
    println!("─────");
    let store = AuditStore::open("./capstone-audit.db").expect("Should open audit store");
    let conv_id = ConversationId::new();

    let entry = ChainBuilder::build_entry_from_genesis(
        ActorId::User("alice".into()),
        zp_core::audit::AuditAction::MessageReceived {
            content_hash: "abc".into(),
        },
        conv_id.clone(),
        zp_core::policy::PolicyDecision::Allow { conditions: vec![] },
        "default-allow".into(),
        None,
        None,
    );
    store.append(entry).expect("Should append");

    let entries = store.get_entries(&conv_id, 100).expect("Should retrieve");
    println!("Entries: {}", entries.len());

    let verifier = ChainVerifier::new();
    let report = verifier.verify(&entries, None);
    println!(
        "Chain integrity: {} ✓",
        if report.chain_valid {
            "verified"
        } else {
            "FAILED"
        }
    );
    println!("SQLite store: ./capstone-audit.db");

    // 5. Reputation
    println!("\nMESH");
    println!("────");
    let mut rep = PeerReputation::new();
    rep.record(ReputationSignal {
        category: SignalCategory::AuditAttestation,
        polarity: SignalPolarity::Positive,
        timestamp: Utc::now(),
        evidence_id: "att-001".into(),
        detail: Some("chain verified".into()),
    });
    rep.record(ReputationSignal {
        category: SignalCategory::ReceiptExchange,
        polarity: SignalPolarity::Positive,
        timestamp: Utc::now(),
        evidence_id: "rcpt-001".into(),
        detail: None,
    });

    let weights = ReputationWeights::default();
    let score = rep.compute_score("node-a", &weights, Utc::now());
    println!(
        "Reputation: Node A scored {:.2} ({}) ✓",
        score.score, score.grade
    );

    // 6. Consensus
    let mut coordinator = ConsensusCoordinator::new();
    let proposal = Proposal::new(
        "rcpt-hash-capstone".into(),
        "agent-east-0".into(),
        "Approve fleet expansion".into(),
        ConsensusThreshold::Unanimous,
        vec!["agent-east-1".into(), "agent-west-0".into()],
        Some(3600),
    );
    let prop_id = coordinator.propose(proposal);
    coordinator.vote(Vote::accept(&prop_id, "agent-east-1"));
    coordinator.vote(Vote::accept(&prop_id, "agent-west-0"));
    let round = coordinator.round(&prop_id).unwrap();
    println!(
        "Consensus: Proposal {} ({}/2 unanimous) ✓",
        if matches!(round.outcome, ConsensusOutcome::Accepted) {
            "accepted"
        } else {
            "rejected"
        },
        round.accepts()
    );

    println!("\nAll systems operational. You are a ZeroPoint Builder.");
}
