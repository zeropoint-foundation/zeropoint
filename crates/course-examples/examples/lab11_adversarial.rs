//! Lab 11: Presence Plane — Adversarial Model
//!
//! Relay reciprocity and reputation signals from behavioral analysis
//! Run: cargo run --example lab11_adversarial -p course-examples

use chrono::Utc;
use zp_mesh::reputation::{
    PeerReputation, ReputationSignal, ReputationWeights, SignalCategory, SignalPolarity,
};

fn main() {
    println!("LAB 11: Adversarial Model");
    println!("═════════════════════════\n");

    // The relay enforces reciprocity: agents must announce before receiving.
    // This prevents passive scanning — you must reveal yourself to observe others.
    //
    // Behavioral model:
    //   1. Connect → try_receive → BLOCKED (must announce first)
    //   2. publish_announce → try_receive → ALLOWED (reciprocity gate passed)
    //   3. Connect → wait past grace period → TERMINATED (scanner pattern)

    println!("Reciprocity gate rules:");
    println!("  1. New connections cannot receive until they announce");
    println!("  2. A grace period allows time to announce after connecting");
    println!("  3. If grace period expires without announcing → connection terminated");
    println!("  4. Announcing grants access to the peer announce stream\n");

    // Simulate legitimate agent behavior
    let legit_announced = true;
    let legit_publishes = 3;
    let legit_reciprocity_violation = false;

    println!("Legitimate agent:");
    println!("  Announced: {}", legit_announced);
    println!("  Publishes: {}", legit_publishes);
    println!("  Reciprocity violation: {}", legit_reciprocity_violation);

    // Simulate scanner behavior
    let scanner_announced = false;
    let scanner_publishes = 0;
    let scanner_reciprocity_violation = true;

    println!("\nPassive scanner:");
    println!("  Announced: {}", scanner_announced);
    println!("  Publishes: {}", scanner_publishes);
    println!("  Reciprocity violation: {}", scanner_reciprocity_violation);

    // Convert behavioral signals into reputation
    println!("\n─── Reputation from behavior ───\n");

    let mut rep = PeerReputation::new();

    // Legitimate agent: positive policy compliance
    rep.record(ReputationSignal {
        category: SignalCategory::PolicyCompliance,
        polarity: SignalPolarity::Positive,
        timestamp: Utc::now(),
        evidence_id: "relay-session-legit".into(),
        detail: Some(format!(
            "announced={}, published={}, violation={}",
            legit_announced, legit_publishes, legit_reciprocity_violation
        )),
    });

    // Legitimate agent: positive receipt exchange (participated)
    rep.record(ReputationSignal {
        category: SignalCategory::ReceiptExchange,
        polarity: SignalPolarity::Positive,
        timestamp: Utc::now(),
        evidence_id: "relay-receipts-legit".into(),
        detail: Some("3 announces, active participant".into()),
    });

    // Scanner: negative policy compliance
    rep.record(ReputationSignal {
        category: SignalCategory::PolicyCompliance,
        polarity: SignalPolarity::Negative,
        timestamp: Utc::now(),
        evidence_id: "relay-session-scanner".into(),
        detail: Some(format!(
            "announced={}, published={}, violation={}",
            scanner_announced, scanner_publishes, scanner_reciprocity_violation
        )),
    });

    let weights = ReputationWeights::default();
    let score = rep.compute_score("relay-participants", &weights, Utc::now());

    println!("Combined relay reputation:");
    println!("  Score: {:.2}", score.score);
    println!("  Grade: {}", score.grade);
    println!("  Positive signals: {}", score.positive_signals);
    println!("  Negative signals: {}", score.negative_signals);

    // Show how reputation gates future actions
    println!("\n─── Reputation-gated actions ───\n");

    let mut good_peer = PeerReputation::new();
    for i in 0..5 {
        good_peer.record(ReputationSignal {
            category: SignalCategory::PolicyCompliance,
            polarity: SignalPolarity::Positive,
            timestamp: Utc::now(),
            evidence_id: format!("session-{}", i),
            detail: None,
        });
    }
    let good_score = good_peer.compute_score("good-agent", &weights, Utc::now());
    println!(
        "Good peer: {:.2} ({}) — can delegate, share policies",
        good_score.score, good_score.grade
    );

    let mut bad_peer = PeerReputation::new();
    for i in 0..5 {
        bad_peer.record(ReputationSignal {
            category: SignalCategory::PolicyCompliance,
            polarity: SignalPolarity::Negative,
            timestamp: Utc::now(),
            evidence_id: format!("violation-{}", i),
            detail: None,
        });
    }
    let bad_score = bad_peer.compute_score("scanner-agent", &weights, Utc::now());
    println!(
        "Bad peer:  {:.2} ({}) — blocked from delegation, policy exchange",
        bad_score.score, bad_score.grade
    );

    println!("\n✓ Adversarial model: reciprocity gate + behavioral signals + reputation gating");
}
