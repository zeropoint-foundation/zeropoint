//! Extensible traits for Monte Carlo simulation
//!
//! These traits allow custom implementations to be plugged into the engine:
//! - SamplingStrategy: How parameters are sampled (Random, Latin Hypercube, Sobol)
//! - DistributionEstimator: How outcome distributions are estimated
//! - RiskAssessor: How risk is assessed from distributions
//! - OutcomeEvaluator: How individual simulation outcomes are evaluated

use crate::types::{
    ConfidenceIntervals, OutcomeDistribution, ParameterBounds, RiskAssessment, SampledParameters,
    SignificanceResult,
};
use std::fmt::Debug;

/// Strategy for sampling parameter space
///
/// Different sampling strategies offer different trade-offs:
/// - Random: Simple but may miss regions of parameter space
/// - Latin Hypercube: Better coverage with fewer samples
/// - Sobol: Deterministic, excellent coverage (quasi-Monte Carlo)
pub trait SamplingStrategy: Send + Sync + Debug {
    /// Sample n points from parameter space defined by bounds
    ///
    /// # Arguments
    /// * `n_samples` - Number of samples to generate
    /// * `bounds` - Parameter bounds as (name, min, max) tuples
    ///
    /// # Returns
    /// Vector of sampled parameter sets
    fn sample(&self, n_samples: usize, bounds: &[ParameterBounds]) -> Vec<SampledParameters>;

    /// Name of this sampling strategy (for logging/debugging)
    fn name(&self) -> &'static str;
}

/// Estimator for outcome distributions
///
/// Takes raw outcome samples and estimates the underlying distribution.
pub trait DistributionEstimator: Send + Sync + Debug {
    /// Estimate distribution from samples
    ///
    /// # Arguments
    /// * `samples` - Raw outcome values from simulation runs
    ///
    /// # Returns
    /// Estimated distribution with statistics
    fn estimate(&self, samples: &[f64]) -> OutcomeDistribution;

    /// Name of this estimator (for logging/debugging)
    fn name(&self) -> &'static str;
}

/// Assessor for risk metrics
///
/// Compares baseline and experimental distributions to assess risk.
pub trait RiskAssessor: Send + Sync + Debug {
    /// Assess risk from comparing two distributions
    ///
    /// # Arguments
    /// * `baseline` - Distribution of baseline/control outcomes
    /// * `experimental` - Distribution of experimental/treatment outcomes
    /// * `confidence_level` - Confidence level for VaR calculations (e.g., 0.95)
    ///
    /// # Returns
    /// Risk assessment with VaR, CVaR, and other metrics
    fn assess(
        &self,
        baseline: &OutcomeDistribution,
        experimental: &OutcomeDistribution,
        confidence_level: f64,
    ) -> RiskAssessment;

    /// Name of this assessor (for logging/debugging)
    fn name(&self) -> &'static str;
}

/// Calculator for statistical significance
///
/// Tests whether the difference between two samples is statistically significant.
pub trait SignificanceCalculator: Send + Sync + Debug {
    /// Calculate statistical significance between two sample sets
    ///
    /// # Arguments
    /// * `baseline_samples` - Outcome samples from baseline/control
    /// * `experimental_samples` - Outcome samples from experimental/treatment
    ///
    /// # Returns
    /// Significance result with p-value, effect size, and test details
    fn calculate(
        &self,
        baseline_samples: &[f64],
        experimental_samples: &[f64],
    ) -> SignificanceResult;

    /// Name of this calculator (for logging/debugging)
    fn name(&self) -> &'static str;
}

/// Calculator for confidence intervals
///
/// Computes confidence intervals for distribution parameters.
pub trait ConfidenceIntervalCalculator: Send + Sync + Debug {
    /// Calculate confidence intervals for a distribution
    ///
    /// # Arguments
    /// * `samples` - Raw outcome samples
    /// * `confidence_level` - Desired confidence level (e.g., 0.95 for 95% CI)
    ///
    /// # Returns
    /// Confidence intervals for mean, median, and effect
    fn calculate(&self, samples: &[f64], confidence_level: f64) -> ConfidenceIntervals;

    /// Name of this calculator (for logging/debugging)
    fn name(&self) -> &'static str;
}
