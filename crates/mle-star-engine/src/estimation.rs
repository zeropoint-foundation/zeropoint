//! Maximum Likelihood Estimation implementations
//!
//! This module provides estimators for inferring capability parameters
//! from historical observations.

use crate::traits::MLEstimator;
use crate::types::{
    CapabilityEstimate, Observation, ParameterSensitivity, SensitivityDirection, TaskAffinity,
};
use statrs::distribution::{ContinuousCDF, StudentsT};

/// Basic MLE estimator using sample statistics
#[derive(Debug, Clone, Default)]
pub struct BasicEstimator {
    confidence_level: f64,
}

impl BasicEstimator {
    pub fn new() -> Self {
        Self {
            confidence_level: 0.95,
        }
    }

    pub fn with_confidence_level(mut self, level: f64) -> Self {
        self.confidence_level = level.clamp(0.5, 0.99);
        self
    }

    /// Calculate t-critical value for confidence interval
    fn t_critical(&self, df: f64) -> f64 {
        let alpha = 1.0 - self.confidence_level;
        let t_dist =
            StudentsT::new(0.0, 1.0, df).unwrap_or(StudentsT::new(0.0, 1.0, 30.0).unwrap());
        t_dist.inverse_cdf(1.0 - alpha / 2.0)
    }
}

impl MLEstimator for BasicEstimator {
    fn estimate_capability(
        &self,
        observations: &[Observation],
        capability_name: &str,
    ) -> Option<CapabilityEstimate> {
        if observations.is_empty() {
            return None;
        }

        // Extract values for this capability from observations
        let values: Vec<f64> = match capability_name {
            "success_rate" => observations
                .iter()
                .map(|o| if o.success { 1.0 } else { 0.0 })
                .collect(),
            "quality" => observations
                .iter()
                .filter_map(|o| o.quality_score)
                .collect(),
            "latency" => observations.iter().map(|o| o.duration_ms as f64).collect(),
            _ => {
                // Try to find in output metrics
                observations
                    .iter()
                    .filter_map(|o| o.output_metrics.get(capability_name).copied())
                    .collect()
            }
        };

        if values.is_empty() {
            return None;
        }

        let n = values.len() as f64;
        let mean = values.iter().sum::<f64>() / n;

        let variance = if n > 1.0 {
            values.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0)
        } else {
            0.0
        };

        let std_error = if n > 1.0 { (variance / n).sqrt() } else { 0.0 };

        // Confidence interval
        let df = (n - 1.0).max(1.0);
        let t_crit = self.t_critical(df);
        let margin = t_crit * std_error;

        // Log-likelihood (assuming normal distribution)
        let log_likelihood = if variance > 0.0 {
            -0.5 * n * (2.0 * std::f64::consts::PI * variance).ln()
                - 0.5 * values.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / variance
        } else {
            0.0
        };

        Some(CapabilityEstimate {
            name: capability_name.to_string(),
            estimate: mean,
            standard_error: std_error,
            confidence_interval: (mean - margin, mean + margin),
            log_likelihood,
            observation_count: values.len(),
        })
    }

    fn estimate_task_affinity(
        &self,
        observations: &[Observation],
        task_category: &str,
    ) -> Option<TaskAffinity> {
        let task_obs: Vec<&Observation> = observations
            .iter()
            .filter(|o| o.task_category == task_category)
            .collect();

        if task_obs.is_empty() {
            return None;
        }

        let n = task_obs.len() as f64;

        // Success rate
        let successes = task_obs.iter().filter(|o| o.success).count() as f64;
        let success_rate = successes / n;

        // Average quality
        let qualities: Vec<f64> = task_obs.iter().filter_map(|o| o.quality_score).collect();
        let average_quality = if !qualities.is_empty() {
            qualities.iter().sum::<f64>() / qualities.len() as f64
        } else {
            success_rate // Fallback to success rate if no quality scores
        };

        // Affinity score combines success rate and quality
        let affinity_score = 0.6 * success_rate + 0.4 * average_quality;

        // Confidence based on observation count
        let confidence = 1.0 - 1.0 / (n + 1.0).sqrt();

        Some(TaskAffinity {
            task_category: task_category.to_string(),
            affinity_score,
            success_rate,
            average_quality,
            observation_count: task_obs.len(),
            confidence,
        })
    }

    fn estimate_sensitivities(&self, observations: &[Observation]) -> Vec<ParameterSensitivity> {
        if observations.len() < 5 {
            return Vec::new();
        }

        let mut sensitivities = Vec::new();

        // Collect all input feature names
        let feature_names: Vec<String> = observations
            .iter()
            .flat_map(|o| o.input_features.keys().cloned())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        // For each feature, calculate correlation with success/quality
        for feature in feature_names {
            let pairs: Vec<(f64, f64)> = observations
                .iter()
                .filter_map(|o| {
                    let input = o.input_features.get(&feature)?;
                    let output = o.quality_score.unwrap_or(if o.success { 1.0 } else { 0.0 });
                    Some((*input, output))
                })
                .collect();

            if pairs.len() < 5 {
                continue;
            }

            let correlation = calculate_correlation(&pairs);
            let sensitivity = correlation.abs();

            if sensitivity > 0.2 {
                // Minimum threshold
                let direction = if correlation > 0.1 {
                    SensitivityDirection::Positive
                } else if correlation < -0.1 {
                    SensitivityDirection::Negative
                } else {
                    SensitivityDirection::Unknown
                };

                // Confidence based on sample size and correlation strength
                let confidence = (pairs.len() as f64 / 50.0).min(1.0) * sensitivity;

                sensitivities.push(ParameterSensitivity {
                    parameter: feature,
                    sensitivity,
                    direction,
                    confidence,
                });
            }
        }

        // Sort by sensitivity (highest first)
        sensitivities.sort_by(|a, b| {
            b.sensitivity
                .partial_cmp(&a.sensitivity)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        sensitivities
    }

    fn name(&self) -> &'static str {
        "Basic MLE"
    }
}

/// Calculate Pearson correlation coefficient
fn calculate_correlation(pairs: &[(f64, f64)]) -> f64 {
    if pairs.len() < 2 {
        return 0.0;
    }

    let n = pairs.len() as f64;
    let (sum_x, sum_y): (f64, f64) = pairs
        .iter()
        .fold((0.0, 0.0), |(sx, sy), (x, y)| (sx + x, sy + y));
    let mean_x = sum_x / n;
    let mean_y = sum_y / n;

    let mut cov = 0.0;
    let mut var_x = 0.0;
    let mut var_y = 0.0;

    for (x, y) in pairs {
        let dx = x - mean_x;
        let dy = y - mean_y;
        cov += dx * dy;
        var_x += dx * dx;
        var_y += dy * dy;
    }

    if var_x == 0.0 || var_y == 0.0 {
        return 0.0;
    }

    cov / (var_x * var_y).sqrt()
}

/// Bayesian estimator with prior beliefs
#[derive(Debug, Clone)]
pub struct BayesianEstimator {
    /// Prior mean for success rate
    prior_success_mean: f64,
    /// Prior strength (equivalent sample size)
    prior_strength: f64,
    confidence_level: f64,
}

impl BayesianEstimator {
    pub fn new() -> Self {
        Self {
            prior_success_mean: 0.5, // Uninformative prior
            prior_strength: 2.0,     // Weak prior (2 pseudo-observations)
            confidence_level: 0.95,
        }
    }

    pub fn with_prior(mut self, mean: f64, strength: f64) -> Self {
        self.prior_success_mean = mean.clamp(0.0, 1.0);
        self.prior_strength = strength.max(0.1);
        self
    }
}

impl Default for BayesianEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl MLEstimator for BayesianEstimator {
    fn estimate_capability(
        &self,
        observations: &[Observation],
        capability_name: &str,
    ) -> Option<CapabilityEstimate> {
        if observations.is_empty() {
            return None;
        }

        // Extract values
        let values: Vec<f64> = match capability_name {
            "success_rate" => observations
                .iter()
                .map(|o| if o.success { 1.0 } else { 0.0 })
                .collect(),
            "quality" => observations
                .iter()
                .filter_map(|o| o.quality_score)
                .collect(),
            _ => observations
                .iter()
                .filter_map(|o| o.output_metrics.get(capability_name).copied())
                .collect(),
        };

        if values.is_empty() {
            return None;
        }

        let n = values.len() as f64;
        let sample_mean = values.iter().sum::<f64>() / n;

        // Bayesian update: combine prior with sample
        let posterior_mean = (self.prior_strength * self.prior_success_mean + n * sample_mean)
            / (self.prior_strength + n);

        // Variance estimate
        let sample_variance = if n > 1.0 {
            values
                .iter()
                .map(|x| (x - sample_mean).powi(2))
                .sum::<f64>()
                / (n - 1.0)
        } else {
            0.25 // Default variance for single observation
        };

        // Posterior variance (simplified)
        let posterior_variance = sample_variance / (self.prior_strength + n);
        let std_error = posterior_variance.sqrt();

        // Credible interval (using normal approximation)
        use statrs::distribution::Normal;
        let z = Normal::new(0.0, 1.0)
            .unwrap()
            .inverse_cdf(1.0 - (1.0 - self.confidence_level) / 2.0);
        let margin = z * std_error;

        Some(CapabilityEstimate {
            name: capability_name.to_string(),
            estimate: posterior_mean,
            standard_error: std_error,
            confidence_interval: (posterior_mean - margin, posterior_mean + margin),
            log_likelihood: 0.0, // Not computed for Bayesian
            observation_count: values.len(),
        })
    }

    fn estimate_task_affinity(
        &self,
        observations: &[Observation],
        task_category: &str,
    ) -> Option<TaskAffinity> {
        // Delegate to basic estimator with Bayesian adjustment
        let basic = BasicEstimator::new().with_confidence_level(self.confidence_level);
        let mut affinity = basic.estimate_task_affinity(observations, task_category)?;

        // Apply Bayesian shrinkage toward prior
        let n = affinity.observation_count as f64;
        let shrinkage = n / (n + self.prior_strength);
        affinity.affinity_score =
            shrinkage * affinity.affinity_score + (1.0 - shrinkage) * self.prior_success_mean;

        Some(affinity)
    }

    fn estimate_sensitivities(&self, observations: &[Observation]) -> Vec<ParameterSensitivity> {
        // Use basic estimator for sensitivities
        BasicEstimator::new().estimate_sensitivities(observations)
    }

    fn name(&self) -> &'static str {
        "Bayesian MLE"
    }
}

/// Factory function to create estimator by name
pub fn create_estimator(name: &str) -> Box<dyn MLEstimator> {
    match name.to_lowercase().as_str() {
        "basic" | "mle" | "frequentist" => Box::new(BasicEstimator::new()),
        "bayesian" | "bayes" => Box::new(BayesianEstimator::new()),
        _ => Box::new(BasicEstimator::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_observations(n: usize, success_rate: f64, quality: f64) -> Vec<Observation> {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        (0..n)
            .map(|_| {
                let success = rng.gen::<f64>() < success_rate;
                Observation::new("test_tool", "test_category")
                    .with_success(success)
                    .with_quality(quality + rng.gen::<f64>() * 0.1 - 0.05)
                    .with_duration(100 + (rng.gen::<u64>() % 50))
                    .with_input_feature("complexity", rng.gen::<f64>())
            })
            .collect()
    }

    #[test]
    fn test_basic_estimator_success_rate() {
        let observations = create_test_observations(100, 0.8, 0.75);
        let estimator = BasicEstimator::new();

        let estimate = estimator
            .estimate_capability(&observations, "success_rate")
            .unwrap();

        // Should be close to 0.8
        assert!(estimate.estimate > 0.6 && estimate.estimate < 1.0);
        assert_eq!(estimate.observation_count, 100);
    }

    #[test]
    fn test_basic_estimator_task_affinity() {
        let observations = create_test_observations(50, 0.9, 0.85);
        let estimator = BasicEstimator::new();

        let affinity = estimator
            .estimate_task_affinity(&observations, "test_category")
            .unwrap();

        assert!(affinity.success_rate > 0.7);
        assert_eq!(affinity.observation_count, 50);
    }

    #[test]
    fn test_basic_estimator_sensitivities() {
        // Create observations with correlation between complexity and success
        let observations: Vec<Observation> = (0..100)
            .map(|i| {
                let complexity = (i as f64) / 100.0;
                let success = complexity < 0.5; // Low complexity = success
                Observation::new("test_tool", "test_category")
                    .with_success(success)
                    .with_quality(if success { 0.9 } else { 0.3 })
                    .with_input_feature("complexity", complexity)
            })
            .collect();

        let estimator = BasicEstimator::new();
        let sensitivities = estimator.estimate_sensitivities(&observations);

        // Should detect complexity sensitivity
        assert!(!sensitivities.is_empty());
        let complexity_sens = sensitivities.iter().find(|s| s.parameter == "complexity");
        assert!(complexity_sens.is_some());
    }

    #[test]
    fn test_bayesian_estimator() {
        let observations = create_test_observations(20, 0.8, 0.75);
        let estimator = BayesianEstimator::new().with_prior(0.5, 5.0);

        let estimate = estimator
            .estimate_capability(&observations, "success_rate")
            .unwrap();

        // With shrinkage toward 0.5 prior, estimate should be between 0.5 and sample mean
        assert!(estimate.estimate > 0.5);
        assert!(estimate.estimate < 0.9);
    }

    #[test]
    fn test_empty_observations() {
        let estimator = BasicEstimator::new();
        let result = estimator.estimate_capability(&[], "success_rate");
        assert!(result.is_none());
    }

    #[test]
    fn test_factory() {
        let basic = create_estimator("basic");
        assert_eq!(basic.name(), "Basic MLE");

        let bayesian = create_estimator("bayesian");
        assert_eq!(bayesian.name(), "Bayesian MLE");
    }
}
