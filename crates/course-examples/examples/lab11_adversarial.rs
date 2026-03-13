//! Lab 11: Presence Plane — Adversarial Model
//!
//! Relay reciprocity and reputation signals
//! Run: cargo run --example lab11_adversarial -p course-examples

use zp_mesh::web_discovery::WebRelayServer;
use zp_mesh::reputation::{
    PeerReputation, ReputationSignal, ReputationWeights,
    SignalCategory, SignalPolarity,
};
use std::time::Duration;
use chrono::Utc;

fn main() {
    let relay = WebRelayServer::with_grace_period(64, Duration::from_secs(1));

    let mut legit = relay.connect();
    assert!(!legit.has_announced(), "Should not have announced yet");

    let result = legit.try_receive();
    assert!(result.is_err(), "Should be blocked before announcing");
    println!("✓ Reciprocity gate: receive blocked before announce");

    let payload = vec![0xAA; 200];
    legit.publish_announce(&relay, payload).unwrap();
    assert!(legit.has_announced(), "Should have announced");
    println!("✓ Agent announced: reciprocity gate passed");
    println!("Announces published by legit: {}", legit.announces_published());

    let mut scanner = relay.connect();
    let result = scanner.try_receive();
    assert!(result.is_err());
    println!("\n✓ Scanner blocked: must announce first");

    std::thread::sleep(Duration::from_secs(2));

    assert!(scanner.grace_period_expired(), "Grace period should be expired");
    let result = scanner.try_receive();
    assert!(result.is_err());
    println!("✓ Scanner grace period expired: connection should be terminated");

    let legit_behavior = relay.disconnect_with_behavior(&legit);
    let scanner_behavior = relay.disconnect_with_behavior(&scanner);

    println!("\nLegitimate agent behavior:");
    println!("  Announced: {}", legit_behavior.announced);
    println!("  Announces published: {}", legit_behavior.announces_published);
    println!("  Duration: {:?}", legit_behavior.duration);
    println!("  Reciprocity violation: {}", legit_behavior.reciprocity_violation);

    println!("\nScanner behavior:");
    println!("  Announced: {}", scanner_behavior.announced);
    println!("  Announces published: {}", scanner_behavior.announces_published);
    println!("  Duration: {:?}", scanner_behavior.duration);
    println!("  Reciprocity violation: {}", scanner_behavior.reciprocity_violation);

    let mut rep = PeerReputation::new();

    rep.record(ReputationSignal {
        category: SignalCategory::PolicyCompliance,
        polarity: SignalPolarity::Positive,
        timestamp: Utc::now(),
        evidence_id: "relay-session-001".into(),
        detail: Some(format!(
            "announced={}, published={}, duration={:?}",
            legit_behavior.announced,
            legit_behavior.announces_published,
            legit_behavior.duration
        )),
    });

    rep.record(ReputationSignal {
        category: SignalCategory::PolicyCompliance,
        polarity: SignalPolarity::Negative,
        timestamp: Utc::now(),
        evidence_id: "relay-session-002".into(),
        detail: Some(format!(
            "reciprocity_violation={}, announced={}, duration={:?}",
            scanner_behavior.reciprocity_violation,
            scanner_behavior.announced,
            scanner_behavior.duration
        )),
    });

    let weights = ReputationWeights::default();
    let score = rep.compute_score("relay-participants", &weights, Utc::now());
    println!("\nRelay reputation impact:");
    println!("  Score: {:.2} (grade: {})", score.score, score.grade);
    println!("  Positive: {}, Negative: {}", score.positive_signals, score.negative_signals);

    println!("\nRelay stats:");
    println!("  Announces relayed: {}", relay.announces_relayed());
    println!("  Reciprocity rejections: {}", relay.reciprocity_rejections());

    relay.shutdown();
    println!("\n✓ Adversarial model: reciprocity gate + behavioral signals + reputation");
}
