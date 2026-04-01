//! Configuration for Monte Carlo simulation
//!
//! This module provides the configuration structure for running simulations,
//! including sample count, parallelism, convergence criteria, and reproducibility.

use serde::{Deserialize, Serialize};

/// Configuration for a Monte Carlo simulation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonteCarloConfig {
    /// Number of simulation iterations to run
    /// Default: 10,000
    pub num_simulations: usize,

    /// Confidence level for statistical calculations (0.0 - 1.0)
    /// Default: 0.95 (95% confidence)
    pub confidence_level: f64,

    /// Optional seed for reproducible results
    /// If None, uses system entropy
    pub seed: Option<u64>,

    /// Maximum parallelism (number of concurrent simulation tasks)
    /// Default: number of CPU cores
    pub max_parallelism: usize,

    /// Optional convergence threshold for early stopping
    /// If Some(t), simulation stops when variance of mean estimate < t
    pub convergence_threshold: Option<f64>,

    /// Minimum samples before checking convergence
    /// Default: 1000
    pub min_samples_for_convergence: usize,

    /// Whether to store all individual runs (can be memory-intensive)
    /// Default: false (only stores summary statistics)
    pub store_all_runs: bool,

    /// Maximum runs to store if store_all_runs is true
    /// Default: 10,000
    pub max_stored_runs: usize,

    /// Sampling strategy name (for logging/debugging)
    /// Options: "random", "latin_hypercube", "sobol"
    pub sampling_strategy: String,
}

impl Default for MonteCarloConfig {
    fn default() -> Self {
        Self {
            num_simulations: 10_000,
            confidence_level: 0.95,
            seed: None,
            max_parallelism: num_cpus::get(),
            convergence_threshold: None,
            min_samples_for_convergence: 1000,
            store_all_runs: false,
            max_stored_runs: 10_000,
            sampling_strategy: "latin_hypercube".to_string(),
        }
    }
}

impl MonteCarloConfig {
    /// Create a new configuration with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder method: set number of simulations
    pub fn with_num_simulations(mut self, n: usize) -> Self {
        self.num_simulations = n;
        self
    }

    /// Builder method: set confidence level
    pub fn with_confidence_level(mut self, level: f64) -> Self {
        self.confidence_level = level.clamp(0.0, 1.0);
        self
    }

    /// Builder method: set seed for reproducibility
    pub fn with_seed(mut self, seed: u64) -> Self {
        self.seed = Some(seed);
        self
    }

    /// Builder method: set max parallelism
    pub fn with_max_parallelism(mut self, n: usize) -> Self {
        self.max_parallelism = n.max(1);
        self
    }

    /// Builder method: enable convergence-based early stopping
    pub fn with_convergence_threshold(mut self, threshold: f64) -> Self {
        self.convergence_threshold = Some(threshold);
        self
    }

    /// Builder method: enable storing all runs
    pub fn with_store_all_runs(mut self, store: bool) -> Self {
        self.store_all_runs = store;
        self
    }

    /// Builder method: set sampling strategy
    pub fn with_sampling_strategy(mut self, strategy: impl Into<String>) -> Self {
        self.sampling_strategy = strategy.into();
        self
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.num_simulations == 0 {
            return Err("num_simulations must be > 0".to_string());
        }
        if self.confidence_level <= 0.0 || self.confidence_level >= 1.0 {
            return Err("confidence_level must be between 0 and 1 (exclusive)".to_string());
        }
        if self.max_parallelism == 0 {
            return Err("max_parallelism must be > 0".to_string());
        }
        if let Some(threshold) = self.convergence_threshold {
            if threshold <= 0.0 {
                return Err("convergence_threshold must be > 0".to_string());
            }
        }
        Ok(())
    }
}

/// Preset configurations for common use cases
impl MonteCarloConfig {
    /// Quick simulation for development/testing
    pub fn quick() -> Self {
        Self::default()
            .with_num_simulations(1_000)
            .with_max_parallelism(4)
    }

    /// Standard simulation for production use
    pub fn standard() -> Self {
        Self::default().with_num_simulations(10_000)
    }

    /// High-precision simulation for critical decisions
    pub fn high_precision() -> Self {
        Self::default()
            .with_num_simulations(100_000)
            .with_convergence_threshold(1e-6)
    }

    /// Reproducible simulation with fixed seed
    pub fn reproducible(seed: u64) -> Self {
        Self::default().with_seed(seed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = MonteCarloConfig::default();
        assert_eq!(config.num_simulations, 10_000);
        assert_eq!(config.confidence_level, 0.95);
        assert!(config.seed.is_none());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_builder_pattern() {
        let config = MonteCarloConfig::new()
            .with_num_simulations(5000)
            .with_confidence_level(0.99)
            .with_seed(42)
            .with_sampling_strategy("sobol");

        assert_eq!(config.num_simulations, 5000);
        assert_eq!(config.confidence_level, 0.99);
        assert_eq!(config.seed, Some(42));
        assert_eq!(config.sampling_strategy, "sobol");
    }

    #[test]
    fn test_validation() {
        let invalid_confidence = MonteCarloConfig::default().with_confidence_level(1.5);
        assert!(invalid_confidence.validate().is_err());

        let zero_sims = MonteCarloConfig {
            num_simulations: 0,
            ..Default::default()
        };
        assert!(zero_sims.validate().is_err());
    }

    #[test]
    fn test_presets() {
        let quick = MonteCarloConfig::quick();
        assert_eq!(quick.num_simulations, 1_000);

        let high = MonteCarloConfig::high_precision();
        assert_eq!(high.num_simulations, 100_000);
        assert!(high.convergence_threshold.is_some());
    }
}
