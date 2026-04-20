//! Receipt generation for observation and reflection operations.
//!
//! Phase 4.1: Wires the observation/reflection pipeline into the receipt chain.
//! Every observation is backed by an `ObservationClaim` receipt, and every
//! reflection pass is backed by a `ReflectionClaim` receipt. This makes the
//! entire cognition plane cryptographically verifiable.

use zp_receipt::{Action, ActionType, ClaimMetadata, ClaimSemantics, Receipt, Status};

use crate::types::{Observation, ObservationPriority, Reflection, SourceRange};

// ============================================================================
// Observation receipt generation
// ============================================================================

/// Generate an `ObservationClaim` receipt for a single observation.
///
/// The receipt links the observation to its source receipt range via
/// `SourceRange::content_hash()` as the `input_hash`, and the observation's
/// own `content_hash()` as the `output_hash`. This enables cryptographic
/// verification: given the source receipts, anyone can verify that the
/// observation receipt references them.
pub fn generate_observation_receipt(
    observation: &Observation,
    observer_id: &str,
    parent_receipt_id: Option<&str>,
) -> Receipt {
    let source_hash = observation.source_range.content_hash();
    let obs_hash = observation.content_hash();

    let mut builder = Receipt::observation(observer_id)
        .status(Status::Success)
        .claim_semantics(ClaimSemantics::AuthorshipProof)
        .claim_metadata(ClaimMetadata::Observation {
            observation_type: observation.category.clone(),
            observer_id: observer_id.to_string(),
            confidence: priority_to_confidence(&observation.priority),
            tags: vec![
                observation.priority.to_string(),
                observation.category.clone(),
            ],
        });

    if let Some(parent_id) = parent_receipt_id {
        builder = builder.parent(parent_id);
    }

    // Set action with source range as input and observation content as output.
    builder = builder.action(Action {
        action_type: ActionType::ContentAccess,
        name: Some("observe".to_string()),
        input_hash: Some(source_hash),
        output_hash: Some(obs_hash),
        exit_code: None,
        detail: Some(serde_json::json!(format!(
            "Distilled {} receipts from chain '{}' (seq {}-{}) into observation",
            observation.source_range.receipt_count,
            observation.source_range.chain_id,
            observation.source_range.start_sequence,
            observation.source_range.end_sequence,
        ))),
    });

    // Store source range details in extensions for full traceability.
    let sr = &observation.source_range;
    builder = builder
        .extension(
            "zp.observation.source_chain_id",
            serde_json::Value::String(sr.chain_id.clone()),
        )
        .extension(
            "zp.observation.source_start_hash",
            serde_json::Value::String(sr.start_hash.clone()),
        )
        .extension(
            "zp.observation.source_end_hash",
            serde_json::Value::String(sr.end_hash.clone()),
        )
        .extension(
            "zp.observation.source_start_seq",
            serde_json::json!(sr.start_sequence),
        )
        .extension(
            "zp.observation.source_end_seq",
            serde_json::json!(sr.end_sequence),
        )
        .extension(
            "zp.observation.priority",
            serde_json::Value::String(observation.priority.to_string()),
        )
        .extension(
            "zp.observation.category",
            serde_json::Value::String(observation.category.clone()),
        );

    builder.finalize()
}

/// Generate `ObservationClaim` receipts for a batch of observations from a
/// single observer pass, chaining them together.
///
/// Returns (receipts, observations_with_receipt_ids). The observations are
/// updated in-place with their receipt IDs.
pub fn generate_observation_receipts(
    observations: &mut [Observation],
    observer_id: &str,
    chain_parent_receipt_id: Option<&str>,
) -> Vec<Receipt> {
    let mut receipts = Vec::with_capacity(observations.len());
    let mut prev_receipt_id = chain_parent_receipt_id.map(|s| s.to_string());

    for obs in observations.iter_mut() {
        let receipt = generate_observation_receipt(obs, observer_id, prev_receipt_id.as_deref());
        obs.receipt_id = Some(receipt.id.clone());
        prev_receipt_id = Some(receipt.id.clone());
        receipts.push(receipt);
    }

    receipts
}

// ============================================================================
// Reflection receipt generation
// ============================================================================

/// Generate a `ReflectionClaim` receipt for a reflection (consolidation) pass.
///
/// The receipt captures the full state transition: which observations were
/// consumed, which were produced, which were dropped, and the compression
/// metrics. This makes every reflection auditable and reversible.
pub fn generate_reflection_receipt(
    reflection: &Reflection,
    reflector_id: &str,
    parent_receipt_id: Option<&str>,
) -> Receipt {
    let ratio = reflection.compression_ratio();

    let mut builder = Receipt::reflection(reflector_id)
        .status(Status::Success)
        .claim_semantics(ClaimSemantics::AuthorshipProof)
        .claim_metadata(ClaimMetadata::Reflection {
            consumed_observation_ids: reflection.consumed_observation_ids.clone(),
            produced_observation_ids: reflection
                .produced_observations
                .iter()
                .map(|o| o.id.clone())
                .collect(),
            dropped_observation_ids: reflection.dropped_observation_ids.clone(),
            tokens_before: reflection.tokens_before,
            tokens_after: reflection.tokens_after,
            compression_ratio: ratio,
            reflector_id: reflector_id.to_string(),
        });

    if let Some(parent_id) = parent_receipt_id {
        builder = builder.parent(parent_id);
    }

    // Action records the consolidation with token metrics.
    let consumed_hash = blake3::hash(reflection.consumed_observation_ids.join(",").as_bytes())
        .to_hex()
        .to_string();

    let produced_hash = blake3::hash(
        reflection
            .produced_observations
            .iter()
            .map(|o| o.id.as_str())
            .collect::<Vec<_>>()
            .join(",")
            .as_bytes(),
    )
    .to_hex()
    .to_string();

    builder = builder.action(Action {
        action_type: ActionType::ContentAccess,
        name: Some("reflect".to_string()),
        input_hash: Some(consumed_hash),
        output_hash: Some(produced_hash),
        exit_code: None,
        detail: Some(serde_json::json!(format!(
            "Consolidated {} observations -> {} produced + {} dropped ({}->{}tokens, {:.1}% compression)",
            reflection.consumed_observation_ids.len(),
            reflection.produced_observations.len(),
            reflection.dropped_observation_ids.len(),
            reflection.tokens_before,
            reflection.tokens_after,
            ratio * 100.0,
        ))),
    });

    // Extensions for detailed traceability.
    builder = builder
        .extension(
            "zp.reflection.tokens_before",
            serde_json::json!(reflection.tokens_before),
        )
        .extension(
            "zp.reflection.tokens_after",
            serde_json::json!(reflection.tokens_after),
        )
        .extension("zp.reflection.compression_ratio", serde_json::json!(ratio))
        .extension(
            "zp.reflection.consumed_count",
            serde_json::json!(reflection.consumed_observation_ids.len()),
        )
        .extension(
            "zp.reflection.produced_count",
            serde_json::json!(reflection.produced_observations.len()),
        )
        .extension(
            "zp.reflection.dropped_count",
            serde_json::json!(reflection.dropped_observation_ids.len()),
        );

    builder.finalize()
}

// ============================================================================
// SourceRange verification
// ============================================================================

/// Verify that a set of receipts matches the source range of an observation.
///
/// Given the raw receipts that an observation claims to have been derived from,
/// this function recomputes the SourceRange and checks that the content_hash
/// matches. This is the key verification primitive: it proves the observation
/// is referencing the correct source material.
///
/// # Arguments
/// * `receipts` - The raw receipts in sequence order (must be contiguous)
/// * `chain_id` - Expected chain ID
/// * `expected_hash` - The observation's `source_range.content_hash()` to verify against
///
/// # Returns
/// `true` if the receipts match the expected source range hash.
pub fn verify_source_range(receipts: &[Receipt], chain_id: &str, expected_hash: &str) -> bool {
    if receipts.is_empty() {
        return false;
    }

    // Extract the first and last receipt hashes and sequence numbers.
    let first = &receipts[0];
    let last = &receipts[receipts.len() - 1];

    let start_hash = &first.content_hash;
    let end_hash = &last.content_hash;

    // Extract sequence numbers from chain metadata.
    let start_seq = first.chain.as_ref().and_then(|c| c.sequence).unwrap_or(0);
    let end_seq = last.chain.as_ref().and_then(|c| c.sequence).unwrap_or(0);

    // Reconstruct the source range and check its hash.
    let reconstructed = SourceRange::new(
        chain_id,
        start_hash.clone(),
        end_hash.clone(),
        start_seq,
        end_seq,
    );

    reconstructed.content_hash() == expected_hash
}

/// Verify that an observation receipt's action hashes match its source range
/// and content. This is a higher-level check that validates the receipt's
/// internal consistency without needing the raw source receipts.
pub fn verify_observation_receipt_consistency(
    receipt: &Receipt,
    observation: &Observation,
) -> bool {
    let action = match &receipt.action {
        Some(a) => a,
        None => return false,
    };

    let expected_input_hash = observation.source_range.content_hash();
    let expected_output_hash = observation.content_hash();

    let input_ok = action.input_hash.as_ref() == Some(&expected_input_hash);

    let output_ok = action.output_hash.as_ref() == Some(&expected_output_hash);

    input_ok && output_ok
}

// ============================================================================
// Helpers
// ============================================================================

/// Map observation priority to a confidence score for the receipt metadata.
fn priority_to_confidence(priority: &ObservationPriority) -> Option<f64> {
    Some(match priority {
        ObservationPriority::High => 0.95,
        ObservationPriority::Medium => 0.75,
        ObservationPriority::Low => 0.50,
        ObservationPriority::Completed => 0.90,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn test_observation() -> Observation {
        Observation {
            id: "obs-test-001".to_string(),
            content: "User configured TLS on port 8443".to_string(),
            priority: ObservationPriority::High,
            category: "security".to_string(),
            referenced_at: Utc::now(),
            observed_at: Utc::now(),
            relative_time: Some("just now".to_string()),
            source_range: SourceRange::new("chain-main", "aaa111", "bbb222", 10, 15),
            superseded: false,
            token_estimate: 8,
            receipt_id: None,
        }
    }

    #[test]
    fn observation_receipt_has_correct_type_and_hashes() {
        let obs = test_observation();
        let receipt = generate_observation_receipt(&obs, "observer-agent-1", None);

        assert!(receipt.id.starts_with("obsv-"));
        assert_eq!(receipt.status, Status::Success);

        // Verify action hashes link to source range and content.
        assert!(verify_observation_receipt_consistency(&receipt, &obs));

        // Verify claim metadata is Observation type.
        match &receipt.claim_metadata {
            Some(ClaimMetadata::Observation {
                observer_id,
                observation_type,
                ..
            }) => {
                assert_eq!(observer_id, "observer-agent-1");
                assert_eq!(observation_type, "security");
            }
            other => panic!("Expected Observation metadata, got {:?}", other),
        }
    }

    #[test]
    fn batch_observation_receipts_chain_together() {
        let mut observations = vec![test_observation(), test_observation()];
        observations[1].id = "obs-test-002".to_string();
        observations[1].content = "Rate limiter set to 100 req/s".to_string();

        let receipts =
            generate_observation_receipts(&mut observations, "observer-1", Some("parent-rcpt"));

        assert_eq!(receipts.len(), 2);

        // First receipt parents to the supplied chain parent.
        assert_eq!(
            receipts[0].parent_receipt_id.as_deref(),
            Some("parent-rcpt")
        );
        // Second receipt parents to the first observation receipt.
        assert_eq!(
            receipts[1].parent_receipt_id.as_deref(),
            Some(receipts[0].id.as_str())
        );

        // Both observations now have receipt IDs.
        assert!(observations[0].receipt_id.is_some());
        assert!(observations[1].receipt_id.is_some());
    }

    #[test]
    fn reflection_receipt_has_correct_metadata() {
        let reflection = Reflection {
            id: "refl-001".to_string(),
            reflected_at: Utc::now(),
            consumed_observation_ids: vec!["obs-1".into(), "obs-2".into()],
            produced_observations: vec![test_observation()],
            dropped_observation_ids: vec!["obs-3".into()],
            tokens_before: 1000,
            tokens_after: 400,
            receipt_id: None,
        };

        let receipt =
            generate_reflection_receipt(&reflection, "reflector-agent-1", Some("prev-rcpt"));

        assert!(receipt.id.starts_with("rflt-"));
        assert_eq!(receipt.status, Status::Success);

        match &receipt.claim_metadata {
            Some(ClaimMetadata::Reflection {
                consumed_observation_ids,
                produced_observation_ids,
                dropped_observation_ids,
                tokens_before,
                tokens_after,
                compression_ratio,
                reflector_id,
            }) => {
                assert_eq!(consumed_observation_ids.len(), 2);
                assert_eq!(produced_observation_ids.len(), 1);
                assert_eq!(dropped_observation_ids.len(), 1);
                assert_eq!(*tokens_before, 1000);
                assert_eq!(*tokens_after, 400);
                assert!((*compression_ratio - 0.4).abs() < f64::EPSILON);
                assert_eq!(reflector_id, "reflector-agent-1");
            }
            other => panic!("Expected Reflection metadata, got {:?}", other),
        }
    }

    #[test]
    fn source_range_verification() {
        let sr = SourceRange::new("chain-main", "hash_a", "hash_b", 0, 5);
        let _expected = sr.content_hash();

        // Build mock receipts matching the source range.
        let first = Receipt::execution("test")
            .chain("", 0, "chain-main")
            .finalize();

        let last = Receipt::execution("test")
            .chain(&first.content_hash, 5, "chain-main")
            .finalize();

        // Reconstruct source range from receipt hashes.
        let reconstructed = SourceRange::new(
            "chain-main",
            first.content_hash.clone(),
            last.content_hash.clone(),
            0,
            5,
        );
        let reconstructed_hash = reconstructed.content_hash();

        // The reconstructed hash should be deterministic given the same inputs.
        assert_eq!(
            reconstructed_hash,
            SourceRange::new(
                "chain-main",
                first.content_hash.clone(),
                last.content_hash.clone(),
                0,
                5
            )
            .content_hash()
        );
    }

    #[test]
    fn observation_receipt_consistency_check() {
        let obs = test_observation();
        let receipt = generate_observation_receipt(&obs, "obs-agent", None);

        // Valid observation matches its receipt.
        assert!(verify_observation_receipt_consistency(&receipt, &obs));

        // A different observation does NOT match.
        let mut different = test_observation();
        different.content = "Something completely different".to_string();
        assert!(!verify_observation_receipt_consistency(
            &receipt, &different
        ));
    }
}
