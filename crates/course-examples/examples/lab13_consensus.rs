//! Lab 13: Consensus
//!
//! Receipt-based consensus
//! Run: cargo run --example lab13_consensus -p course-examples

use zp_mesh::consensus::{
    ConsensusCoordinator, ConsensusOutcome, Proposal, Vote,
};
use zp_core::governance::ConsensusThreshold;

fn main() {
    let mut coordinator = ConsensusCoordinator::new();

    let proposal = Proposal::new(
        "rcpt-hash-abc".into(),
        "agent-alpha".into(),
        "Approve capability grant for data-processing".into(),
        ConsensusThreshold::Unanimous,
        vec!["agent-beta".into(), "agent-gamma".into()],
        Some(3600),
    );
    let prop_id = coordinator.propose(proposal);
    println!("Proposal created: {}", prop_id);

    coordinator.vote(Vote::accept(&prop_id, "agent-beta"));

    let round = coordinator.round(&prop_id).unwrap();
    println!("After 1 vote: {:?} ({} accepts, {} rejects)",
        round.outcome, round.accepts(), round.rejects());

    coordinator.vote(Vote::accept(&prop_id, "agent-gamma"));

    let round = coordinator.round(&prop_id).unwrap();
    println!("After 2 votes: {:?}", round.outcome);
    assert!(matches!(round.outcome, ConsensusOutcome::Accepted));

    let proposal2 = Proposal::new(
        "rcpt-hash-def".into(),
        "agent-alpha".into(),
        "Approve cross-fleet audit exchange".into(),
        ConsensusThreshold::Majority,
        vec!["agent-beta".into(), "agent-gamma".into(), "agent-delta".into()],
        None,
    );
    let prop2_id = coordinator.propose(proposal2);

    coordinator.vote(Vote::accept(&prop2_id, "agent-beta"));
    coordinator.vote(Vote::reject(&prop2_id, "agent-gamma", "Insufficient evidence"));
    coordinator.vote(Vote::accept(&prop2_id, "agent-delta"));

    let round2 = coordinator.round(&prop2_id).unwrap();
    println!("Majority vote: {:?} ({} accepts, {} rejects)",
        round2.outcome, round2.accepts(), round2.rejects());
    assert!(matches!(round2.outcome, ConsensusOutcome::Accepted));

    let proposal3 = Proposal::new(
        "rcpt-hash-ghi".into(),
        "agent-alpha".into(),
        "Critical governance change".into(),
        ConsensusThreshold::Threshold { required: 3, total: 4 },
        vec!["a".into(), "b".into(), "c".into(), "d".into()],
        None,
    );
    let prop3_id = coordinator.propose(proposal3);

    coordinator.vote(Vote::accept(&prop3_id, "a"));
    coordinator.vote(Vote::reject(&prop3_id, "b", "Disagree with scope"));
    coordinator.vote(Vote::reject(&prop3_id, "c", "Too risky"));

    let round3 = coordinator.round(&prop3_id).unwrap();
    println!("k-of-n vote: {:?}", round3.outcome);
    assert!(matches!(round3.outcome, ConsensusOutcome::Rejected));

    println!("\n✓ Consensus: proposals, votes, thresholds (unanimous + majority + k-of-n)");
}
