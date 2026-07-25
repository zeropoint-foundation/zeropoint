//! Evolution zone classification.
//!
//! Zone 1 (Autonomous) — operational tuning within validated ranges.
//! Zone 2 (Proposal) — structural changes requiring operator approval.
//! Zone 3 (Constitutional) — invariants requiring amendment ceremony.

use serde::{Deserialize, Serialize};

use crate::finding::{FindingPayload, GossipFinding};

/// Evolution zone for a proposed change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Zone {
    /// Operational tuning — Regent acts autonomously (with precedent).
    Autonomous,
    /// Structural proposal — requires operator approval.
    Proposal,
    /// Constitutional invariant — requires amendment ceremony.
    Constitutional,
}

/// Classify a finding's influence zone based on what it would change.
///
/// Conservative by default — when in doubt, classify as Proposal.
/// The Regent can downgrade Proposal → Autonomous if she has established
/// precedent for that specific pattern on the local chain.
pub fn classify_finding(finding: &GossipFinding) -> Zone {
    match &finding.payload {
        FindingPayload::ConfigurationRecipe { parameters, .. } => {
            if parameters.keys().all(|k| is_zone1_param(k)) {
                Zone::Autonomous
            } else {
                Zone::Proposal
            }
        }
        // Prompt variants are Zone 2 by default (introducing new prompt text).
        // The Regent can downgrade to Autonomous if she has precedent for
        // this prompt task's variant selection.
        FindingPayload::PromptVariant { .. } => Zone::Proposal,

        // Informational findings influence Zone 1 decisions but don't
        // require direct action.
        FindingPayload::ModelPromptCoupling { .. }
        | FindingPayload::PerformanceCharacteristic { .. } => Zone::Autonomous,

        // Safety findings may trigger Zone 2 proposals (e.g., "stop using
        // this model"). Conservative default.
        FindingPayload::SafetyBoundary { .. } => Zone::Proposal,
    }
}

/// Zone 1 inference parameters — adjustable within validated ranges.
fn is_zone1_param(key: &str) -> bool {
    matches!(
        key,
        "temperature"
            | "top_p"
            | "top_k"
            | "repeat_penalty"
            | "context_window"
            | "keep_alive"
            | "num_predict"
            | "seed"
            | "mirostat"
            | "mirostat_tau"
            | "mirostat_eta"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::*;
    use std::collections::BTreeMap;

    #[test]
    fn zone1_config_recipe() {
        let mut params = BTreeMap::new();
        params.insert("temperature".to_string(), serde_json::json!(0.3));
        params.insert("top_p".to_string(), serde_json::json!(0.9));

        let f = GossipFinding::new(
            FindingType::ConfigurationRecipe,
            "qwen3".to_string(),
            None,
            FindingPayload::ConfigurationRecipe {
                parameters: params,
                use_case: "structured_output".to_string(),
                measured_improvement: Some(0.15),
            },
            "0.42.0".to_string(),
            "hash".to_string(),
            0.8,
        );
        assert_eq!(classify_finding(&f), Zone::Autonomous);
    }

    #[test]
    fn zone2_config_recipe_with_non_zone1_param() {
        let mut params = BTreeMap::new();
        params.insert("temperature".to_string(), serde_json::json!(0.3));
        params.insert("model_name".to_string(), serde_json::json!("gemma4:27b"));

        let f = GossipFinding::new(
            FindingType::ConfigurationRecipe,
            "gemma4".to_string(),
            None,
            FindingPayload::ConfigurationRecipe {
                parameters: params,
                use_case: "conversation".to_string(),
                measured_improvement: None,
            },
            "0.42.0".to_string(),
            "hash".to_string(),
            0.7,
        );
        assert_eq!(classify_finding(&f), Zone::Proposal);
    }

    #[test]
    fn safety_boundary_is_proposal() {
        let f = GossipFinding::new(
            FindingType::SafetyBoundary,
            "qwen3".to_string(),
            Some("8b".to_string()),
            FindingPayload::SafetyBoundary {
                failure_mode: "hallucination".to_string(),
                trigger_conditions: vec!["long_context".to_string()],
                severity: "degraded".to_string(),
            },
            "0.42.0".to_string(),
            "hash".to_string(),
            0.6,
        );
        assert_eq!(classify_finding(&f), Zone::Proposal);
    }
}
