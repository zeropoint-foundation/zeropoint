//! Extensible traits for MLE STAR Engine
//!
//! These traits allow custom implementations to be plugged into the engine:
//! - MLEstimator: How parameters are estimated from observations
//! - HypothesisGenerator: How hypotheses are generated from expertise
//! - ObservationStore: How observations are stored and retrieved
//! - ExpertiseStore: How expertise profiles are stored and retrieved

use crate::types::{
    CapabilityEstimate, ExpertiseProfile, Hypothesis, LearningContext, Observation,
    ParameterSensitivity, TaskAffinity,
};
use async_trait::async_trait;
use std::fmt::Debug;

/// Estimator for Maximum Likelihood parameters
///
/// Different estimators can use different statistical methods:
/// - Basic: Simple sample statistics
/// - Bayesian: Posterior estimation with priors
/// - Robust: Outlier-resistant estimation
pub trait MLEstimator: Send + Sync + Debug {
    /// Estimate capability parameters from observations
    ///
    /// # Arguments
    /// * `observations` - Historical observations for the target
    /// * `capability_name` - Name of capability to estimate
    ///
    /// # Returns
    /// Capability estimate with confidence intervals
    fn estimate_capability(
        &self,
        observations: &[Observation],
        capability_name: &str,
    ) -> Option<CapabilityEstimate>;

    /// Estimate task affinity from observations
    fn estimate_task_affinity(
        &self,
        observations: &[Observation],
        task_category: &str,
    ) -> Option<TaskAffinity>;

    /// Estimate parameter sensitivities
    fn estimate_sensitivities(&self, observations: &[Observation]) -> Vec<ParameterSensitivity>;

    /// Name of this estimator (for logging/debugging)
    fn name(&self) -> &'static str;
}

/// Generator for hypotheses from expertise profiles
///
/// Different generators can produce different types of hypotheses:
/// - Performance: Throughput and latency improvements
/// - Quality: Output quality improvements
/// - Capability: New capability suggestions
pub trait HypothesisGenerator: Send + Sync + Debug {
    /// Generate hypotheses from an expertise profile
    ///
    /// # Arguments
    /// * `profile` - Current expertise profile
    /// * `context` - Learning context with constraints
    ///
    /// # Returns
    /// List of generated hypotheses
    fn generate(&self, profile: &ExpertiseProfile, context: &LearningContext) -> Vec<Hypothesis>;

    /// Name of this generator (for logging/debugging)
    fn name(&self) -> &'static str;
}

/// Store for observations
#[async_trait]
pub trait ObservationStore: Send + Sync + Debug {
    /// Store a new observation
    async fn store(&self, observation: Observation) -> Result<(), String>;

    /// Get all observations for a target
    async fn get_for_target(&self, target_id: &str) -> Vec<Observation>;

    /// Get observations filtered by category
    async fn get_by_category(&self, target_id: &str, category: &str) -> Vec<Observation>;

    /// Get observations within a time window
    async fn get_recent(&self, target_id: &str, since_seconds: u64) -> Vec<Observation>;

    /// Count observations for a target
    async fn count(&self, target_id: &str) -> usize;

    /// Clear all observations for a target
    async fn clear(&self, target_id: &str) -> Result<(), String>;

    /// Name of this store (for logging/debugging)
    fn name(&self) -> &'static str;
}

/// Store for expertise profiles
#[async_trait]
pub trait ExpertiseStore: Send + Sync + Debug {
    /// Store or update an expertise profile
    async fn store(&self, profile: ExpertiseProfile) -> Result<(), String>;

    /// Get expertise profile for a target
    async fn get(&self, target_id: &str) -> Option<ExpertiseProfile>;

    /// List all stored target IDs
    async fn list_targets(&self) -> Vec<String>;

    /// Check if profile exists for target
    async fn exists(&self, target_id: &str) -> bool;

    /// Delete profile for a target
    async fn delete(&self, target_id: &str) -> Result<(), String>;

    /// Name of this store (for logging/debugging)
    fn name(&self) -> &'static str;
}

/// Calculator for profile confidence scores
pub trait ConfidenceCalculator: Send + Sync + Debug {
    /// Calculate overall confidence for a profile
    ///
    /// # Arguments
    /// * `observations` - Observations used to build profile
    /// * `profile` - Current profile state
    ///
    /// # Returns
    /// Confidence score (0.0 - 1.0)
    fn calculate_confidence(&self, observations: &[Observation], profile: &ExpertiseProfile)
        -> f64;

    /// Calculate confidence for a specific capability estimate
    fn calculate_capability_confidence(
        &self,
        observations: &[Observation],
        capability_name: &str,
    ) -> f64;

    /// Name of this calculator (for logging/debugging)
    fn name(&self) -> &'static str;
}

/// Pattern detector for identifying performance patterns
pub trait PatternDetector: Send + Sync + Debug {
    /// Detect patterns in observations
    ///
    /// # Arguments
    /// * `observations` - Historical observations
    ///
    /// # Returns
    /// Detected performance patterns
    fn detect_patterns(
        &self,
        observations: &[Observation],
    ) -> Vec<crate::types::PerformancePattern>;

    /// Name of this detector (for logging/debugging)
    fn name(&self) -> &'static str;
}
