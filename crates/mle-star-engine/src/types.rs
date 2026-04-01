//! Core types for MLE STAR Engine
//!
//! This module defines the fundamental data structures used throughout
//! the expertise pre-learning engine.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Error types for MLE STAR operations
#[derive(Debug, Error)]
pub enum MLEStarError {
    #[error("Insufficient observations: need at least {required}, have {actual}")]
    InsufficientObservations { required: usize, actual: usize },

    #[error("Target not found: {0}")]
    TargetNotFound(String),

    #[error("Estimation failed: {0}")]
    EstimationFailed(String),

    #[error("Invalid confidence: {0} (must be between 0 and 1)")]
    InvalidConfidence(f64),

    #[error("Pre-learning failed: {0}")]
    PreLearningFailed(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    #[error("Storage error: {0}")]
    StorageError(String),
}

pub type MLEStarResult<T> = Result<T, MLEStarError>;

/// An observation recorded from tool/capability execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    /// Unique identifier for this observation
    pub id: String,
    /// Target tool/capability being observed
    pub target_id: String,
    /// Task category (e.g., "code_generation", "search", "analysis")
    pub task_category: String,
    /// Input features/context for this execution
    pub input_features: HashMap<String, f64>,
    /// Output metrics (success, latency, quality, etc.)
    pub output_metrics: HashMap<String, f64>,
    /// Whether the execution was successful
    pub success: bool,
    /// Optional quality score (0.0 - 1.0)
    pub quality_score: Option<f64>,
    /// Execution duration in milliseconds
    pub duration_ms: u64,
    /// When this observation was recorded
    pub timestamp: DateTime<Utc>,
    /// Optional additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

impl Observation {
    pub fn new(target_id: impl Into<String>, task_category: impl Into<String>) -> Self {
        Self {
            id: generate_id(),
            target_id: target_id.into(),
            task_category: task_category.into(),
            input_features: HashMap::new(),
            output_metrics: HashMap::new(),
            success: true,
            quality_score: None,
            duration_ms: 0,
            timestamp: Utc::now(),
            metadata: HashMap::new(),
        }
    }

    pub fn with_success(mut self, success: bool) -> Self {
        self.success = success;
        self
    }

    pub fn with_quality(mut self, score: f64) -> Self {
        self.quality_score = Some(score.clamp(0.0, 1.0));
        self
    }

    pub fn with_duration(mut self, ms: u64) -> Self {
        self.duration_ms = ms;
        self
    }

    pub fn with_input_feature(mut self, name: impl Into<String>, value: f64) -> Self {
        self.input_features.insert(name.into(), value);
        self
    }

    pub fn with_output_metric(mut self, name: impl Into<String>, value: f64) -> Self {
        self.output_metrics.insert(name.into(), value);
        self
    }
}

/// Maximum Likelihood Estimate for a capability parameter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityEstimate {
    /// Name of the capability being estimated
    pub name: String,
    /// MLE estimate value
    pub estimate: f64,
    /// Standard error of the estimate
    pub standard_error: f64,
    /// Confidence interval (lower, upper)
    pub confidence_interval: (f64, f64),
    /// Log-likelihood of the estimate
    pub log_likelihood: f64,
    /// Number of observations used
    pub observation_count: usize,
}

/// Task affinity - how well suited a target is for a task type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskAffinity {
    /// Task category
    pub task_category: String,
    /// Affinity score (0.0 - 1.0, higher = more suited)
    pub affinity_score: f64,
    /// Success rate for this task type
    pub success_rate: f64,
    /// Average quality for this task type
    pub average_quality: f64,
    /// Number of observations for this task type
    pub observation_count: usize,
    /// Confidence in this affinity estimate
    pub confidence: f64,
}

/// Parameter sensitivity analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterSensitivity {
    /// Parameter name
    pub parameter: String,
    /// Sensitivity coefficient (how much output changes per unit input)
    pub sensitivity: f64,
    /// Direction of effect (positive or negative)
    pub direction: SensitivityDirection,
    /// Confidence in this sensitivity estimate
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SensitivityDirection {
    Positive,  // Higher input -> higher output
    Negative,  // Higher input -> lower output
    NonLinear, // Complex relationship
    Unknown,   // Insufficient data
}

/// Observed performance pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformancePattern {
    /// Pattern identifier
    pub id: String,
    /// Description of when this pattern applies
    pub condition: String,
    /// Expected performance when pattern applies
    pub expected_performance: f64,
    /// Variance in performance
    pub variance: f64,
    /// How often this pattern is observed
    pub frequency: f64,
    /// Confidence in this pattern
    pub confidence: f64,
}

/// Complete expertise profile for a tool/capability ("mental model")
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpertiseProfile {
    /// Target identifier (tool/capability ID)
    pub target_id: String,
    /// Human-readable name
    pub target_name: String,
    /// Capability estimates
    pub capability_estimates: HashMap<String, CapabilityEstimate>,
    /// Task affinities
    pub task_affinities: HashMap<String, TaskAffinity>,
    /// Parameter sensitivities
    pub parameter_sensitivities: Vec<ParameterSensitivity>,
    /// Observed performance patterns
    pub performance_patterns: Vec<PerformancePattern>,
    /// Overall success rate
    pub overall_success_rate: f64,
    /// Overall quality score
    pub overall_quality: f64,
    /// Total number of observations
    pub observation_count: usize,
    /// Confidence in this profile (0.0 - 1.0)
    pub profile_confidence: f64,
    /// When profile was created
    pub created_at: DateTime<Utc>,
    /// When profile was last updated
    pub last_updated: DateTime<Utc>,
}

impl ExpertiseProfile {
    pub fn new(target_id: impl Into<String>, target_name: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            target_id: target_id.into(),
            target_name: target_name.into(),
            capability_estimates: HashMap::new(),
            task_affinities: HashMap::new(),
            parameter_sensitivities: Vec::new(),
            performance_patterns: Vec::new(),
            overall_success_rate: 0.0,
            overall_quality: 0.0,
            observation_count: 0,
            profile_confidence: 0.0,
            created_at: now,
            last_updated: now,
        }
    }

    /// Get affinity for a specific task category
    pub fn get_task_affinity(&self, category: &str) -> Option<&TaskAffinity> {
        self.task_affinities.get(category)
    }

    /// Check if profile has sufficient data for a given confidence threshold
    pub fn is_confident(&self, threshold: f64) -> bool {
        self.profile_confidence >= threshold
    }
}

/// Readiness assessment for production use
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadinessAssessment {
    /// Readiness score (0.0 - 1.0)
    pub score: f64,
    /// Whether ready for production use
    pub production_ready: bool,
    /// Identified data gaps
    pub data_gaps: Vec<String>,
    /// Recommended tests before production
    pub recommended_tests: Vec<String>,
    /// Warnings about potential issues
    pub warnings: Vec<String>,
    /// Minimum observations needed for confidence
    pub min_observations_needed: usize,
}

impl ReadinessAssessment {
    pub fn ready(score: f64) -> Self {
        Self {
            score: score.clamp(0.0, 1.0),
            production_ready: score >= 0.7,
            data_gaps: Vec::new(),
            recommended_tests: Vec::new(),
            warnings: Vec::new(),
            min_observations_needed: 0,
        }
    }

    pub fn not_ready(reason: impl Into<String>) -> Self {
        Self {
            score: 0.0,
            production_ready: false,
            data_gaps: vec![reason.into()],
            recommended_tests: Vec::new(),
            warnings: Vec::new(),
            min_observations_needed: 10,
        }
    }
}

/// A hypothesis generated from expertise
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hypothesis {
    /// Unique identifier
    pub id: String,
    /// Type of hypothesis
    pub hypothesis_type: HypothesisType,
    /// Human-readable statement
    pub statement: String,
    /// Predicted effect
    pub predicted_effect: PredictedEffect,
    /// Confidence in this hypothesis (0.0 - 1.0)
    pub confidence: f64,
    /// Supporting evidence
    pub supporting_evidence: Vec<String>,
    /// How to test this hypothesis
    pub test_procedure: Option<String>,
    /// When hypothesis was generated
    pub generated_at: DateTime<Utc>,
}

impl Hypothesis {
    pub fn new(
        hypothesis_type: HypothesisType,
        statement: impl Into<String>,
        predicted_effect: PredictedEffect,
        confidence: f64,
    ) -> Self {
        Self {
            id: generate_id(),
            hypothesis_type,
            statement: statement.into(),
            predicted_effect,
            confidence: confidence.clamp(0.0, 1.0),
            supporting_evidence: Vec::new(),
            test_procedure: None,
            generated_at: Utc::now(),
        }
    }

    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.supporting_evidence.push(evidence.into());
        self
    }

    pub fn with_test_procedure(mut self, procedure: impl Into<String>) -> Self {
        self.test_procedure = Some(procedure.into());
        self
    }
}

/// Type of hypothesis
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HypothesisType {
    /// Performance improvement hypothesis
    Performance,
    /// Quality improvement hypothesis
    Quality,
    /// Capability expansion hypothesis
    Capability,
    /// Task affinity hypothesis
    TaskAffinity,
    /// Parameter optimization hypothesis
    ParameterOptimization,
    /// Risk reduction hypothesis
    RiskReduction,
}

/// Predicted effect of a hypothesis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredictedEffect {
    /// Metric being affected
    pub metric: String,
    /// Direction of expected change
    pub direction: EffectDirection,
    /// Magnitude of expected change (percentage)
    pub magnitude: f64,
    /// Confidence interval for magnitude
    pub magnitude_ci: (f64, f64),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EffectDirection {
    Increase,
    Decrease,
    NoChange,
    Unknown,
}

/// Result of pre-learning process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreLearningResult {
    /// Target that was pre-learned
    pub target_id: String,
    /// Built expertise profile
    pub expertise: ExpertiseProfile,
    /// Readiness assessment
    pub readiness: ReadinessAssessment,
    /// Generated hypotheses
    pub hypotheses: Vec<Hypothesis>,
    /// Recommendations for optimal use
    pub recommendations: Vec<String>,
    /// Warnings about potential issues
    pub warnings: Vec<String>,
    /// Pre-learning duration in milliseconds
    pub duration_ms: u64,
    /// When pre-learning completed
    pub completed_at: DateTime<Utc>,
}

/// Learning context for pre-learning
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LearningContext {
    /// Task categories to focus on
    pub focus_categories: Vec<String>,
    /// Minimum confidence threshold
    pub confidence_threshold: f64,
    /// Whether to generate hypotheses
    pub generate_hypotheses: bool,
    /// Maximum observations to consider
    pub max_observations: Option<usize>,
    /// Time window for observations (in seconds)
    pub time_window_seconds: Option<u64>,
}

impl LearningContext {
    pub fn new() -> Self {
        Self {
            focus_categories: Vec::new(),
            confidence_threshold: 0.7,
            generate_hypotheses: true,
            max_observations: None,
            time_window_seconds: None,
        }
    }

    pub fn with_focus(mut self, category: impl Into<String>) -> Self {
        self.focus_categories.push(category.into());
        self
    }

    pub fn with_confidence_threshold(mut self, threshold: f64) -> Self {
        self.confidence_threshold = threshold.clamp(0.0, 1.0);
        self
    }

    pub fn with_hypothesis_generation(mut self, enabled: bool) -> Self {
        self.generate_hypotheses = enabled;
        self
    }
}

/// Generate a simple unique ID
fn generate_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 8] = rng.gen();
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_observation_builder() {
        let obs = Observation::new("tool_1", "code_generation")
            .with_success(true)
            .with_quality(0.85)
            .with_duration(150)
            .with_input_feature("complexity", 0.7)
            .with_output_metric("tokens", 500.0);

        assert_eq!(obs.target_id, "tool_1");
        assert_eq!(obs.task_category, "code_generation");
        assert!(obs.success);
        assert_eq!(obs.quality_score, Some(0.85));
        assert_eq!(obs.duration_ms, 150);
        assert_eq!(obs.input_features.get("complexity"), Some(&0.7));
        assert_eq!(obs.output_metrics.get("tokens"), Some(&500.0));
    }

    #[test]
    fn test_hypothesis_builder() {
        let hyp = Hypothesis::new(
            HypothesisType::Performance,
            "Using batch processing will improve throughput",
            PredictedEffect {
                metric: "throughput".to_string(),
                direction: EffectDirection::Increase,
                magnitude: 25.0,
                magnitude_ci: (15.0, 35.0),
            },
            0.8,
        )
        .with_evidence("Observed 30% improvement in similar systems")
        .with_test_procedure("Run A/B test with batch size 10 vs 1");

        assert_eq!(hyp.hypothesis_type, HypothesisType::Performance);
        assert_eq!(hyp.confidence, 0.8);
        assert_eq!(hyp.supporting_evidence.len(), 1);
        assert!(hyp.test_procedure.is_some());
    }

    #[test]
    fn test_expertise_profile() {
        let profile = ExpertiseProfile::new("tool_1", "Code Generator");
        assert_eq!(profile.target_id, "tool_1");
        assert_eq!(profile.observation_count, 0);
        assert!(!profile.is_confident(0.5));
    }

    #[test]
    fn test_readiness_assessment() {
        let ready = ReadinessAssessment::ready(0.85);
        assert!(ready.production_ready);
        assert_eq!(ready.score, 0.85);

        let not_ready = ReadinessAssessment::not_ready("Insufficient data");
        assert!(!not_ready.production_ready);
        assert_eq!(not_ready.data_gaps.len(), 1);
    }

    #[test]
    fn test_learning_context() {
        let ctx = LearningContext::new()
            .with_focus("code_generation")
            .with_focus("analysis")
            .with_confidence_threshold(0.8)
            .with_hypothesis_generation(true);

        assert_eq!(ctx.focus_categories.len(), 2);
        assert_eq!(ctx.confidence_threshold, 0.8);
        assert!(ctx.generate_hypotheses);
    }
}
