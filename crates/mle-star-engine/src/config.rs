//! Configuration for MLE STAR Engine
//!
//! This module provides configuration options for the pre-learning engine,
//! including thresholds, generation settings, and storage options.

use serde::{Deserialize, Serialize};

/// Configuration for the MLE STAR Engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLEStarConfig {
    /// Minimum observations before building a profile
    /// Default: 10
    pub min_observations: usize,

    /// Confidence threshold for profile validity
    /// Default: 0.7
    pub confidence_threshold: f64,

    /// Automatically refresh profiles when new observations arrive
    /// Default: true
    pub auto_refresh: bool,

    /// Enable hypothesis generation during pre-learning
    /// Default: true
    pub hypothesis_generation: bool,

    /// Maximum hypotheses to generate per profile
    /// Default: 10
    pub max_hypotheses: usize,

    /// Enable pattern detection
    /// Default: true
    pub pattern_detection: bool,

    /// Maximum patterns to detect per profile
    /// Default: 20
    pub max_patterns: usize,

    /// Minimum observations for task affinity calculation
    /// Default: 5
    pub min_task_observations: usize,

    /// Confidence level for statistical estimates
    /// Default: 0.95
    pub confidence_level: f64,

    /// Maximum age of observations to consider (seconds)
    /// None = no age limit
    pub max_observation_age_seconds: Option<u64>,

    /// Enable sensitivity analysis
    /// Default: true
    pub sensitivity_analysis: bool,

    /// Minimum correlation for sensitivity detection
    /// Default: 0.3
    pub min_sensitivity_correlation: f64,
}

impl Default for MLEStarConfig {
    fn default() -> Self {
        Self {
            min_observations: 10,
            confidence_threshold: 0.7,
            auto_refresh: true,
            hypothesis_generation: true,
            max_hypotheses: 10,
            pattern_detection: true,
            max_patterns: 20,
            min_task_observations: 5,
            confidence_level: 0.95,
            max_observation_age_seconds: None,
            sensitivity_analysis: true,
            min_sensitivity_correlation: 0.3,
        }
    }
}

impl MLEStarConfig {
    /// Create a new configuration with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: set minimum observations
    pub fn with_min_observations(mut self, n: usize) -> Self {
        self.min_observations = n.max(1);
        self
    }

    /// Builder: set confidence threshold
    pub fn with_confidence_threshold(mut self, threshold: f64) -> Self {
        self.confidence_threshold = threshold.clamp(0.0, 1.0);
        self
    }

    /// Builder: set auto-refresh
    pub fn with_auto_refresh(mut self, enabled: bool) -> Self {
        self.auto_refresh = enabled;
        self
    }

    /// Builder: set hypothesis generation
    pub fn with_hypothesis_generation(mut self, enabled: bool) -> Self {
        self.hypothesis_generation = enabled;
        self
    }

    /// Builder: set pattern detection
    pub fn with_pattern_detection(mut self, enabled: bool) -> Self {
        self.pattern_detection = enabled;
        self
    }

    /// Builder: set maximum observation age
    pub fn with_max_observation_age(mut self, seconds: u64) -> Self {
        self.max_observation_age_seconds = Some(seconds);
        self
    }

    /// Builder: set sensitivity analysis
    pub fn with_sensitivity_analysis(mut self, enabled: bool) -> Self {
        self.sensitivity_analysis = enabled;
        self
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.min_observations == 0 {
            return Err("min_observations must be > 0".to_string());
        }
        if self.confidence_threshold <= 0.0 || self.confidence_threshold > 1.0 {
            return Err("confidence_threshold must be between 0 and 1".to_string());
        }
        if self.confidence_level <= 0.0 || self.confidence_level >= 1.0 {
            return Err("confidence_level must be between 0 and 1 (exclusive)".to_string());
        }
        Ok(())
    }
}

/// Preset configurations for common use cases
impl MLEStarConfig {
    /// Quick configuration for development/testing
    pub fn quick() -> Self {
        Self::default()
            .with_min_observations(5)
            .with_hypothesis_generation(false)
            .with_pattern_detection(false)
    }

    /// Standard configuration for production use
    pub fn standard() -> Self {
        Self::default()
    }

    /// Thorough configuration for critical decisions
    pub fn thorough() -> Self {
        Self::default()
            .with_min_observations(50)
            .with_confidence_threshold(0.85)
    }

    /// Minimal configuration without hypothesis generation
    pub fn minimal() -> Self {
        Self::default()
            .with_hypothesis_generation(false)
            .with_pattern_detection(false)
            .with_sensitivity_analysis(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = MLEStarConfig::default();
        assert_eq!(config.min_observations, 10);
        assert_eq!(config.confidence_threshold, 0.7);
        assert!(config.auto_refresh);
        assert!(config.hypothesis_generation);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_builder_pattern() {
        let config = MLEStarConfig::new()
            .with_min_observations(20)
            .with_confidence_threshold(0.8)
            .with_auto_refresh(false)
            .with_hypothesis_generation(false);

        assert_eq!(config.min_observations, 20);
        assert_eq!(config.confidence_threshold, 0.8);
        assert!(!config.auto_refresh);
        assert!(!config.hypothesis_generation);
    }

    #[test]
    fn test_validation() {
        let invalid = MLEStarConfig {
            min_observations: 0,
            ..Default::default()
        };
        assert!(invalid.validate().is_err());

        // Test invalid confidence by directly setting the field
        let invalid_confidence = MLEStarConfig {
            confidence_threshold: 1.5,
            ..Default::default()
        };
        assert!(invalid_confidence.validate().is_err());
    }

    #[test]
    fn test_presets() {
        let quick = MLEStarConfig::quick();
        assert_eq!(quick.min_observations, 5);
        assert!(!quick.hypothesis_generation);

        let thorough = MLEStarConfig::thorough();
        assert_eq!(thorough.min_observations, 50);
        assert_eq!(thorough.confidence_threshold, 0.85);
    }
}
