//! Core types for Monte Carlo simulation
//!
//! This module defines the fundamental data structures used throughout
//! the Monte Carlo engine.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Error types for Monte Carlo operations
#[derive(Debug, Error)]
pub enum MonteCarloError {
    #[error("Insufficient samples: need at least {required}, have {actual}")]
    InsufficientSamples { required: usize, actual: usize },

    #[error("Invalid parameter bounds: {parameter} min ({min}) >= max ({max})")]
    InvalidBounds {
        parameter: String,
        min: f64,
        max: f64,
    },

    #[error("Simulation failed: {0}")]
    SimulationFailed(String),

    #[error("Invalid confidence level: {0} (must be between 0 and 1)")]
    InvalidConfidenceLevel(f64),

    #[error("Convergence not achieved after {iterations} iterations")]
    ConvergenceNotAchieved { iterations: usize },

    #[error("Configuration error: {0}")]
    ConfigurationError(String),
}

pub type MonteCarloResult<T> = Result<T, MonteCarloError>;

/// Parameter bounds for sampling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterBounds {
    pub name: String,
    pub min: f64,
    pub max: f64,
    pub distribution_hint: Option<DistributionHint>,
}

impl ParameterBounds {
    pub fn new(name: impl Into<String>, min: f64, max: f64) -> Self {
        Self {
            name: name.into(),
            min,
            max,
            distribution_hint: None,
        }
    }

    pub fn with_distribution(mut self, hint: DistributionHint) -> Self {
        self.distribution_hint = Some(hint);
        self
    }

    pub fn validate(&self) -> MonteCarloResult<()> {
        if self.min >= self.max {
            return Err(MonteCarloError::InvalidBounds {
                parameter: self.name.clone(),
                min: self.min,
                max: self.max,
            });
        }
        Ok(())
    }
}

/// Hint for parameter distribution (used by advanced samplers)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DistributionHint {
    Uniform,
    Normal { mean: f64, std_dev: f64 },
    LogNormal { mu: f64, sigma: f64 },
    Beta { alpha: f64, beta: f64 },
    Triangular { mode: f64 },
}

/// A set of sampled parameter values
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampledParameters {
    pub values: HashMap<String, f64>,
}

impl SampledParameters {
    pub fn new() -> Self {
        Self {
            values: HashMap::new(),
        }
    }

    pub fn get(&self, name: &str) -> Option<f64> {
        self.values.get(name).copied()
    }

    pub fn insert(&mut self, name: impl Into<String>, value: f64) {
        self.values.insert(name.into(), value);
    }
}

impl Default for SampledParameters {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a single simulation run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationRun {
    pub run_id: usize,
    pub parameters: SampledParameters,
    pub outcome: f64,
    pub metadata: HashMap<String, serde_json::Value>,
    pub execution_time_us: u64,
}

/// Outcome distribution statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutcomeDistribution {
    /// Sample mean
    pub mean: f64,
    /// Sample median (p50)
    pub median: f64,
    /// Sample standard deviation
    pub std_dev: f64,
    /// Sample variance
    pub variance: f64,
    /// Skewness (0 = symmetric, >0 = right-skewed, <0 = left-skewed)
    pub skewness: f64,
    /// Excess kurtosis (0 = normal, >0 = heavy tails, <0 = light tails)
    pub kurtosis: f64,
    /// Minimum value
    pub min: f64,
    /// Maximum value
    pub max: f64,
    /// Percentiles (p5, p10, p25, p50, p75, p90, p95, p99)
    pub percentiles: HashMap<String, f64>,
    /// Number of samples
    pub sample_count: usize,
}

impl OutcomeDistribution {
    /// Get a specific percentile value
    pub fn percentile(&self, p: &str) -> Option<f64> {
        self.percentiles.get(p).copied()
    }

    /// Get interquartile range (p75 - p25)
    pub fn iqr(&self) -> Option<f64> {
        let p25 = self.percentiles.get("p25")?;
        let p75 = self.percentiles.get("p75")?;
        Some(p75 - p25)
    }
}

/// Confidence intervals for distribution parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceIntervals {
    /// Confidence interval for the mean (lower, upper)
    pub mean_ci: (f64, f64),
    /// Confidence interval for the median (lower, upper)
    pub median_ci: (f64, f64),
    /// Confidence interval for the effect size (lower, upper)
    pub effect_ci: (f64, f64),
    /// The confidence level used (e.g., 0.95 for 95% CI)
    pub confidence_level: f64,
}

/// Risk assessment comparing baseline and experimental outcomes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    /// Probability of the experimental outcome being worse than baseline
    pub probability_of_loss: f64,
    /// Value at Risk at the given confidence level
    /// (worst expected outcome at confidence level)
    pub value_at_risk: f64,
    /// Conditional VaR (expected shortfall)
    /// (expected loss given that loss exceeds VaR)
    pub conditional_var: f64,
    /// Maximum observed loss (worst case in simulation)
    pub max_drawdown: f64,
    /// Risk-adjusted score (similar to Sharpe ratio)
    /// (expected improvement / std dev of improvement)
    pub risk_adjusted_score: f64,
    /// Confidence level used for VaR calculation
    pub confidence_level: f64,
}

/// Result of statistical significance testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignificanceResult {
    /// p-value (probability of observing this difference by chance)
    pub p_value: f64,
    /// Whether the result is statistically significant at common thresholds
    pub is_significant_at_05: bool,
    pub is_significant_at_01: bool,
    pub is_significant_at_001: bool,
    /// Effect size (Cohen's d)
    pub effect_size: f64,
    /// Effect size interpretation
    pub effect_interpretation: EffectSizeInterpretation,
    /// Statistical test used
    pub test_name: String,
    /// Test statistic value
    pub test_statistic: f64,
    /// Degrees of freedom (if applicable)
    pub degrees_of_freedom: Option<f64>,
}

/// Interpretation of effect size (Cohen's d)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EffectSizeInterpretation {
    Negligible, // |d| < 0.2
    Small,      // 0.2 <= |d| < 0.5
    Medium,     // 0.5 <= |d| < 0.8
    Large,      // |d| >= 0.8
}

impl EffectSizeInterpretation {
    pub fn from_cohens_d(d: f64) -> Self {
        let abs_d = d.abs();
        if abs_d < 0.2 {
            Self::Negligible
        } else if abs_d < 0.5 {
            Self::Small
        } else if abs_d < 0.8 {
            Self::Medium
        } else {
            Self::Large
        }
    }
}

/// Complete results from a Monte Carlo simulation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResults {
    /// Unique identifier for this simulation
    pub simulation_id: String,
    /// Configuration used
    pub config_summary: String,
    /// Individual simulation runs (may be sampled if too many)
    pub runs: Vec<SimulationRun>,
    /// Total number of runs performed
    pub total_runs: usize,
    /// Number of successful runs
    pub successful_runs: usize,
    /// Number of failed runs
    pub failed_runs: usize,
    /// Outcome distribution for baseline (if comparing)
    pub baseline_distribution: Option<OutcomeDistribution>,
    /// Outcome distribution for experimental
    pub experimental_distribution: OutcomeDistribution,
    /// Confidence intervals
    pub confidence_intervals: ConfidenceIntervals,
    /// Risk assessment (if comparing baseline/experimental)
    pub risk_assessment: Option<RiskAssessment>,
    /// Statistical significance (if comparing)
    pub significance: Option<SignificanceResult>,
    /// When simulation started
    pub started_at: DateTime<Utc>,
    /// When simulation completed
    pub completed_at: DateTime<Utc>,
    /// Total execution time in milliseconds
    pub execution_time_ms: u64,
    /// Whether early stopping was triggered
    pub early_stopped: bool,
    /// Convergence info (if tracked)
    pub convergence_info: Option<ConvergenceInfo>,
}

/// Information about simulation convergence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConvergenceInfo {
    /// Did the simulation converge?
    pub converged: bool,
    /// Number of iterations to convergence (or total if not converged)
    pub iterations: usize,
    /// Final variance of the mean estimate
    pub final_variance: f64,
    /// Threshold that was used
    pub threshold: f64,
}
