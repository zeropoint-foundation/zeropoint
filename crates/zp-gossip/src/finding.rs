//! Gossip finding types — structurally private by construction.
//!
//! The type system defines what *can* be shared; anything outside the
//! type is structurally unsharable. No operator identity, preferences,
//! chain content, or behavioral patterns can flow through these types.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Content-addressed hash of a finding's canonical serialization.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentHash(pub String);

/// A gossip finding — the unit of knowledge exchange between Regents.
///
/// Content-addressed by `finding_id` (BLAKE3 of canonical payload).
/// Contains zero operator-specific data by construction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipFinding {
    /// Deterministic content hash of this finding's payload.
    pub finding_id: ContentHash,
    /// What kind of finding this is.
    pub finding_type: FindingType,
    /// When this finding was produced.
    pub created_at: DateTime<Utc>,
    /// Model family (e.g. "qwen3", "gemma4", "claude-sonnet").
    pub model_family: String,
    /// Model variant within the family (e.g. "8b", "27b-mlx").
    pub model_variant: Option<String>,
    /// Type-specific payload.
    pub payload: FindingPayload,
    /// ZeroPoint version that produced this finding.
    pub substrate_version: String,
    /// Hash of the local evaluation receipt — verifiable provenance
    /// without exposing the receipt itself.
    pub evaluation_receipt_hash: String,
    /// Confidence in this finding (0.0–1.0).
    pub confidence: f64,
}

impl GossipFinding {
    /// Compute the content-addressed ID from the finding's payload.
    pub fn compute_id(finding: &GossipFinding) -> ContentHash {
        // Canonical serialization: sorted keys, no whitespace.
        let canonical = serde_json::json!({
            "finding_type": finding.finding_type,
            "model_family": finding.model_family,
            "model_variant": finding.model_variant,
            "payload": finding.payload,
            "substrate_version": finding.substrate_version,
            "evaluation_receipt_hash": finding.evaluation_receipt_hash,
        });
        let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
        let hash = blake3::hash(&bytes);
        ContentHash(hash.to_hex().to_string())
    }

    /// Create a new finding with auto-computed ID.
    pub fn new(
        finding_type: FindingType,
        model_family: String,
        model_variant: Option<String>,
        payload: FindingPayload,
        substrate_version: String,
        evaluation_receipt_hash: String,
        confidence: f64,
    ) -> Self {
        let mut finding = Self {
            finding_id: ContentHash(String::new()),
            finding_type,
            created_at: Utc::now(),
            model_family,
            model_variant,
            payload,
            substrate_version,
            evaluation_receipt_hash,
            confidence,
        };
        finding.finding_id = Self::compute_id(&finding);
        finding
    }
}

/// The kind of finding being shared.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FindingType {
    /// "This model fails/succeeds at this prompt task."
    ModelPromptCoupling,
    /// "These inference parameters work well for this model."
    ConfigurationRecipe,
    /// "This model has these latency/throughput/memory characteristics."
    PerformanceCharacteristic,
    /// "This prompt phrasing produces better results for this model family."
    PromptVariant,
    /// "This model breaks under these conditions."
    SafetyBoundary,
}

/// Type-specific payload — each variant carries only model-performance
/// data, never operator-specific information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FindingPayload {
    ModelPromptCoupling {
        /// What was tested: "sovereign_identity", "json_compliance", etc.
        task: String,
        /// Pass/Fail/Degraded.
        result: CouplingResult,
        /// Hash of the prompt variant tested.
        prompt_hash: String,
        /// Test conditions: "temperature=0.3", "context_window=4096".
        conditions: Vec<String>,
    },
    ConfigurationRecipe {
        /// Parameter name → value.
        parameters: BTreeMap<String, serde_json::Value>,
        /// What this recipe is good for.
        use_case: String,
        /// Measured improvement over baseline (0.0–1.0), if available.
        measured_improvement: Option<f64>,
    },
    PerformanceCharacteristic {
        /// Hardware class: "apple_silicon_m2", "nvidia_4090", "cpu_only".
        hardware_class: String,
        /// Latency per inference call.
        latency_ms: Option<f64>,
        /// Throughput.
        tokens_per_second: Option<f64>,
        /// Memory footprint.
        memory_mb: Option<u64>,
        /// Context window size tested.
        context_window_tested: Option<u64>,
    },
    PromptVariant {
        /// Hash of the base prompt this variant improves on.
        base_prompt_hash: String,
        /// The variant text itself — substrate infrastructure, not operator data.
        variant_text: String,
        /// What task this variant targets.
        task: String,
        /// Improvement over base (0.0–1.0).
        improvement_over_base: f64,
    },
    SafetyBoundary {
        /// How the model fails: "hallucination", "instruction_bypass", etc.
        failure_mode: String,
        /// What triggers the failure.
        trigger_conditions: Vec<String>,
        /// How bad: "critical", "degraded", "edge_case".
        severity: String,
    },
}

/// Result of a model-prompt coupling test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CouplingResult {
    Pass,
    Fail,
    Degraded { score: f64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_hash_is_deterministic() {
        let f1 = GossipFinding::new(
            FindingType::ModelPromptCoupling,
            "qwen3".to_string(),
            Some("8b".to_string()),
            FindingPayload::ModelPromptCoupling {
                task: "sovereign_identity".to_string(),
                result: CouplingResult::Pass,
                prompt_hash: "abc123".to_string(),
                conditions: vec!["temperature=0.3".to_string()],
            },
            "0.42.0".to_string(),
            "receipt_hash_xyz".to_string(),
            0.95,
        );

        let f2 = GossipFinding::new(
            FindingType::ModelPromptCoupling,
            "qwen3".to_string(),
            Some("8b".to_string()),
            FindingPayload::ModelPromptCoupling {
                task: "sovereign_identity".to_string(),
                result: CouplingResult::Pass,
                prompt_hash: "abc123".to_string(),
                conditions: vec!["temperature=0.3".to_string()],
            },
            "0.42.0".to_string(),
            "receipt_hash_xyz".to_string(),
            0.95,
        );

        assert_eq!(f1.finding_id, f2.finding_id);
    }

    #[test]
    fn different_payload_different_hash() {
        let f1 = GossipFinding::new(
            FindingType::ModelPromptCoupling,
            "qwen3".to_string(),
            Some("8b".to_string()),
            FindingPayload::ModelPromptCoupling {
                task: "sovereign_identity".to_string(),
                result: CouplingResult::Pass,
                prompt_hash: "abc123".to_string(),
                conditions: vec![],
            },
            "0.42.0".to_string(),
            "hash_a".to_string(),
            0.95,
        );

        let f2 = GossipFinding::new(
            FindingType::ModelPromptCoupling,
            "qwen3".to_string(),
            Some("8b".to_string()),
            FindingPayload::ModelPromptCoupling {
                task: "sovereign_identity".to_string(),
                result: CouplingResult::Fail,
                prompt_hash: "abc123".to_string(),
                conditions: vec![],
            },
            "0.42.0".to_string(),
            "hash_b".to_string(),
            0.30,
        );

        assert_ne!(f1.finding_id, f2.finding_id);
    }
}
