//! Lab 12: Reputation and Trust Tiers
//!
//! Reputation scoring with time decay
//! Run: cargo run --example lab12_reputation -p course-examples

use chrono::Utc;
use zp_mesh::reputation::{
    PeerReputation, ReputationSignal, ReputationWeights, SignalCategory, SignalPolarity,
};

fn main() {
    let mut rep = PeerReputation::new();

    rep.record(ReputationSignal {
        category: SignalCategory::AuditAttestation,
        polarity: SignalPolarity::Positive,
        timestamp: Utc::now(),
        evidence_id: "att-001".into(),
        detail: Some("chain verified, 5 entries".into()),
    });
    rep.record(ReputationSignal {
        category: SignalCategory::ReceiptExchange,
        polarity: SignalPolarity::Positive,
        timestamp: Utc::now(),
        evidence_id: "rcpt-001".into(),
        detail: None,
    });
    rep.record(ReputationSignal {
        category: SignalCategory::PolicyCompliance,
        polarity: SignalPolarity::Positive,
        timestamp: Utc::now(),
        evidence_id: "policy-pass-001".into(),
        detail: Some("honoured data-sharing agreement".into()),
    });

    let weights = ReputationWeights::default();
    let score = rep.compute_score("peer-abc", &weights, Utc::now());

    println!("Peer: {}", score.peer);
    println!("Score: {:.2} (grade: {})", score.score, score.grade);
    println!("Positive signals: {}", score.positive_signals);
    println!("Negative signals: {}", score.negative_signals);

    for cat in &score.breakdown {
        println!(
            "  {:?}: {:.2} (weight {:.2}, weighted {:.2}, {} signals)",
            cat.category, cat.score, cat.weight, cat.weighted_score, cat.signal_count
        );
    }

    rep.record(ReputationSignal {
        category: SignalCategory::PolicyCompliance,
        polarity: SignalPolarity::Negative,
        timestamp: Utc::now(),
        evidence_id: "policy-fail-001".into(),
        detail: Some("violated rate limit agreement".into()),
    });

    let updated = rep.compute_score("peer-abc", &weights, Utc::now());
    println!("\nAfter negative signal:");
    println!("Score: {:.2} (grade: {})", updated.score, updated.grade);
    assert!(
        updated.score < score.score,
        "Negative signal should lower score"
    );

    println!("\n✓ Reputation: signals → time-decayed scores → grades");
}
