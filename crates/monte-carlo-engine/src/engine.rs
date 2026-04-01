//! Monte Carlo Engine - Main simulation orchestrator
//!
//! This module provides the main `MonteCarloEngine` struct that coordinates
//! sampling, simulation, distribution estimation, and risk assessment.

use crate::confidence::{create_ci_calculator, mean_difference_ci};
use crate::config::MonteCarloConfig;
use crate::distribution::create_estimator;
use crate::risk::create_risk_assessor;
use crate::sampling::create_sampler;
use crate::significance::create_significance_calculator;
use crate::traits::{
    ConfidenceIntervalCalculator, DistributionEstimator, RiskAssessor, SamplingStrategy,
    SignificanceCalculator,
};
use crate::types::{
    ConfidenceIntervals, ConvergenceInfo, MonteCarloError, MonteCarloResult, OutcomeDistribution,
    ParameterBounds, RiskAssessment, SampledParameters, SignificanceResult, SimulationResults,
    SimulationRun,
};
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

/// Monte Carlo simulation engine
///
/// Provides a flexible, extensible framework for running Monte Carlo simulations
/// with pluggable sampling strategies, distribution estimators, and risk assessors.
pub struct MonteCarloEngine {
    config: MonteCarloConfig,
    sampler: Arc<RwLock<Box<dyn SamplingStrategy>>>,
    estimator: Arc<RwLock<Box<dyn DistributionEstimator>>>,
    risk_assessor: Arc<RwLock<Box<dyn RiskAssessor>>>,
    significance_calc: Arc<RwLock<Box<dyn SignificanceCalculator>>>,
    ci_calculator: Arc<RwLock<Box<dyn ConfidenceIntervalCalculator>>>,
}

impl MonteCarloEngine {
    /// Create a new Monte Carlo engine with default configuration
    pub fn new() -> Self {
        Self::with_config(MonteCarloConfig::default())
    }

    /// Create a new Monte Carlo engine with custom configuration
    pub fn with_config(config: MonteCarloConfig) -> Self {
        let sampler = create_sampler(&config.sampling_strategy, config.seed);
        let estimator = create_estimator("empirical");
        let risk_assessor = create_risk_assessor("standard");
        let significance_calc = create_significance_calculator("welch", None);
        let ci_calculator = create_ci_calculator("standard", None);

        Self {
            config,
            sampler: Arc::new(RwLock::new(sampler)),
            estimator: Arc::new(RwLock::new(estimator)),
            risk_assessor: Arc::new(RwLock::new(risk_assessor)),
            significance_calc: Arc::new(RwLock::new(significance_calc)),
            ci_calculator: Arc::new(RwLock::new(ci_calculator)),
        }
    }

    /// Builder: set custom sampling strategy
    pub fn with_sampler(mut self, sampler: Box<dyn SamplingStrategy>) -> Self {
        self.sampler = Arc::new(RwLock::new(sampler));
        self
    }

    /// Builder: set custom distribution estimator
    pub fn with_estimator(mut self, estimator: Box<dyn DistributionEstimator>) -> Self {
        self.estimator = Arc::new(RwLock::new(estimator));
        self
    }

    /// Builder: set custom risk assessor
    pub fn with_risk_assessor(mut self, assessor: Box<dyn RiskAssessor>) -> Self {
        self.risk_assessor = Arc::new(RwLock::new(assessor));
        self
    }

    /// Builder: set custom significance calculator
    pub fn with_significance_calculator(mut self, calc: Box<dyn SignificanceCalculator>) -> Self {
        self.significance_calc = Arc::new(RwLock::new(calc));
        self
    }

    /// Builder: set custom confidence interval calculator
    pub fn with_ci_calculator(mut self, calc: Box<dyn ConfidenceIntervalCalculator>) -> Self {
        self.ci_calculator = Arc::new(RwLock::new(calc));
        self
    }

    /// Get current configuration
    pub fn config(&self) -> &MonteCarloConfig {
        &self.config
    }

    /// Run a Monte Carlo simulation with a custom evaluation function
    ///
    /// # Arguments
    /// * `bounds` - Parameter bounds defining the search space
    /// * `eval_fn` - Function that takes sampled parameters and returns an outcome
    ///
    /// # Returns
    /// Simulation results with distribution statistics and confidence intervals
    pub async fn simulate<F>(
        &self,
        bounds: &[ParameterBounds],
        eval_fn: F,
    ) -> MonteCarloResult<SimulationResults>
    where
        F: Fn(&SampledParameters) -> f64 + Send + Sync,
    {
        // Validate bounds
        for bound in bounds {
            bound.validate()?;
        }

        let started_at = Utc::now();
        let start_time = Instant::now();

        // Generate samples
        let sampler = self.sampler.read().await;
        let samples = sampler.sample(self.config.num_simulations, bounds);
        drop(sampler);

        // Run simulations
        let mut runs = Vec::with_capacity(samples.len());
        let mut outcomes = Vec::with_capacity(samples.len());
        let mut running_mean = 0.0;
        let mut running_m2 = 0.0;
        let mut converged = false;
        let mut convergence_iteration = 0;

        for (run_id, params) in samples.into_iter().enumerate() {
            let run_start = Instant::now();
            let outcome = eval_fn(&params);
            let execution_time_us = run_start.elapsed().as_micros() as u64;

            outcomes.push(outcome);

            // Update running statistics (Welford's algorithm)
            let n = (run_id + 1) as f64;
            let delta = outcome - running_mean;
            running_mean += delta / n;
            let delta2 = outcome - running_mean;
            running_m2 += delta * delta2;

            // Check convergence if enabled
            if let Some(threshold) = self.config.convergence_threshold {
                if run_id >= self.config.min_samples_for_convergence {
                    let variance_of_mean = running_m2 / (n * (n - 1.0));
                    if variance_of_mean < threshold {
                        converged = true;
                        convergence_iteration = run_id + 1;
                        break;
                    }
                }
            }

            // Store run if configured
            if self.config.store_all_runs && runs.len() < self.config.max_stored_runs {
                runs.push(SimulationRun {
                    run_id,
                    parameters: params,
                    outcome,
                    metadata: HashMap::new(),
                    execution_time_us,
                });
            }
        }

        let completed_at = Utc::now();
        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        // Estimate distribution
        let estimator = self.estimator.read().await;
        let distribution = estimator.estimate(&outcomes);
        drop(estimator);

        // Calculate confidence intervals
        let ci_calc = self.ci_calculator.read().await;
        let confidence_intervals = ci_calc.calculate(&outcomes, self.config.confidence_level);
        drop(ci_calc);

        // Build results
        let total_runs = outcomes.len();
        let successful_runs = total_runs;
        let failed_runs = 0;

        let convergence_info = if let Some(threshold) = self.config.convergence_threshold {
            let n = total_runs as f64;
            let final_variance = if n > 1.0 {
                running_m2 / (n * (n - 1.0))
            } else {
                f64::INFINITY
            };
            Some(ConvergenceInfo {
                converged,
                iterations: if converged {
                    convergence_iteration
                } else {
                    total_runs
                },
                final_variance,
                threshold,
            })
        } else {
            None
        };

        Ok(SimulationResults {
            simulation_id: uuid_v4(),
            config_summary: format!(
                "n={}, strategy={}, confidence={}",
                total_runs, self.config.sampling_strategy, self.config.confidence_level
            ),
            runs,
            total_runs,
            successful_runs,
            failed_runs,
            baseline_distribution: None,
            experimental_distribution: distribution,
            confidence_intervals,
            risk_assessment: None,
            significance: None,
            started_at,
            completed_at,
            execution_time_ms,
            early_stopped: converged,
            convergence_info,
        })
    }

    /// Compare two sets of outcomes (baseline vs experimental)
    ///
    /// # Arguments
    /// * `baseline` - Baseline/control outcome samples
    /// * `experimental` - Experimental/treatment outcome samples
    ///
    /// # Returns
    /// Full comparison results with significance, effect size, and risk assessment
    pub async fn compare(
        &self,
        baseline: &[f64],
        experimental: &[f64],
    ) -> MonteCarloResult<SimulationResults> {
        if baseline.len() < 2 {
            return Err(MonteCarloError::InsufficientSamples {
                required: 2,
                actual: baseline.len(),
            });
        }
        if experimental.len() < 2 {
            return Err(MonteCarloError::InsufficientSamples {
                required: 2,
                actual: experimental.len(),
            });
        }

        let started_at = Utc::now();
        let start_time = Instant::now();

        // Estimate distributions
        let estimator = self.estimator.read().await;
        let baseline_dist = estimator.estimate(baseline);
        let experimental_dist = estimator.estimate(experimental);
        drop(estimator);

        // Calculate significance
        let sig_calc = self.significance_calc.read().await;
        let significance = sig_calc.calculate(baseline, experimental);
        drop(sig_calc);

        // Assess risk
        let risk_assessor = self.risk_assessor.read().await;
        let risk_assessment = risk_assessor.assess(
            &baseline_dist,
            &experimental_dist,
            self.config.confidence_level,
        );
        drop(risk_assessor);

        // Calculate confidence intervals for the difference
        let effect_ci = mean_difference_ci(baseline, experimental, self.config.confidence_level);
        let ci_calc = self.ci_calculator.read().await;
        let exp_ci = ci_calc.calculate(experimental, self.config.confidence_level);
        drop(ci_calc);

        let confidence_intervals = ConfidenceIntervals {
            mean_ci: exp_ci.mean_ci,
            median_ci: exp_ci.median_ci,
            effect_ci,
            confidence_level: self.config.confidence_level,
        };

        let completed_at = Utc::now();
        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        Ok(SimulationResults {
            simulation_id: uuid_v4(),
            config_summary: format!(
                "comparison: baseline_n={}, experimental_n={}, confidence={}",
                baseline.len(),
                experimental.len(),
                self.config.confidence_level
            ),
            runs: Vec::new(),
            total_runs: baseline.len() + experimental.len(),
            successful_runs: baseline.len() + experimental.len(),
            failed_runs: 0,
            baseline_distribution: Some(baseline_dist),
            experimental_distribution: experimental_dist,
            confidence_intervals,
            risk_assessment: Some(risk_assessment),
            significance: Some(significance),
            started_at,
            completed_at,
            execution_time_ms,
            early_stopped: false,
            convergence_info: None,
        })
    }

    /// Quick significance test between two samples
    pub async fn significance_test(
        &self,
        baseline: &[f64],
        experimental: &[f64],
    ) -> SignificanceResult {
        let sig_calc = self.significance_calc.read().await;
        sig_calc.calculate(baseline, experimental)
    }

    /// Quick risk assessment between two distributions
    pub async fn assess_risk(
        &self,
        baseline: &[f64],
        experimental: &[f64],
    ) -> MonteCarloResult<RiskAssessment> {
        if baseline.len() < 2 || experimental.len() < 2 {
            return Err(MonteCarloError::InsufficientSamples {
                required: 2,
                actual: baseline.len().min(experimental.len()),
            });
        }

        let estimator = self.estimator.read().await;
        let baseline_dist = estimator.estimate(baseline);
        let experimental_dist = estimator.estimate(experimental);
        drop(estimator);

        let risk_assessor = self.risk_assessor.read().await;
        Ok(risk_assessor.assess(
            &baseline_dist,
            &experimental_dist,
            self.config.confidence_level,
        ))
    }

    /// Estimate distribution from samples
    pub async fn estimate_distribution(&self, samples: &[f64]) -> OutcomeDistribution {
        let estimator = self.estimator.read().await;
        estimator.estimate(samples)
    }

    /// Calculate confidence intervals for samples
    pub async fn confidence_intervals(&self, samples: &[f64]) -> ConfidenceIntervals {
        let ci_calc = self.ci_calculator.read().await;
        ci_calc.calculate(samples, self.config.confidence_level)
    }
}

impl Default for MonteCarloEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a simple UUID v4
fn uuid_v4() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 16] = rng.gen();

    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        (bytes[6] & 0x0f) | 0x40, bytes[7],
        (bytes[8] & 0x3f) | 0x80, bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_basic_simulation() {
        let engine = MonteCarloEngine::with_config(
            MonteCarloConfig::default()
                .with_num_simulations(100)
                .with_seed(42),
        );

        let bounds = vec![
            ParameterBounds::new("x", 0.0, 10.0),
            ParameterBounds::new("y", -5.0, 5.0),
        ];

        let results = engine
            .simulate(&bounds, |params| {
                let x = params.get("x").unwrap_or(0.0);
                let y = params.get("y").unwrap_or(0.0);
                x + y
            })
            .await
            .unwrap();

        assert_eq!(results.total_runs, 100);
        assert_eq!(results.successful_runs, 100);
        assert!(!results.early_stopped);
    }

    #[tokio::test]
    async fn test_simulation_with_convergence() {
        let engine = MonteCarloEngine::with_config(
            MonteCarloConfig::default()
                .with_num_simulations(10000)
                .with_convergence_threshold(1e-4)
                .with_seed(42),
        );

        let bounds = vec![ParameterBounds::new("x", 0.0, 1.0)];

        let results = engine
            .simulate(&bounds, |params| params.get("x").unwrap_or(0.5))
            .await
            .unwrap();

        // Should have converged before 10000 iterations
        assert!(results.convergence_info.is_some());
        // May or may not have early stopped depending on convergence
    }

    #[tokio::test]
    async fn test_compare_samples() {
        let engine = MonteCarloEngine::new();

        let baseline: Vec<f64> = (0..100).map(|x| x as f64).collect();
        let experimental: Vec<f64> = (10..110).map(|x| x as f64).collect();

        let results = engine.compare(&baseline, &experimental).await.unwrap();

        assert!(results.baseline_distribution.is_some());
        assert!(results.significance.is_some());
        assert!(results.risk_assessment.is_some());

        // Should be statistically significant (shifted by 10)
        let sig = results.significance.unwrap();
        assert!(sig.is_significant_at_05);
    }

    #[tokio::test]
    async fn test_significance_test() {
        let engine = MonteCarloEngine::new();

        let a: Vec<f64> = (0..50).map(|x| x as f64).collect();
        let b: Vec<f64> = (25..75).map(|x| x as f64).collect();

        let result = engine.significance_test(&a, &b).await;

        assert!(result.is_significant_at_05);
        assert!(result.effect_size > 0.0);
    }

    #[tokio::test]
    async fn test_risk_assessment() {
        let engine = MonteCarloEngine::new();

        let baseline: Vec<f64> = (0..100).map(|x| x as f64).collect();
        let experimental: Vec<f64> = (5..105).map(|x| x as f64).collect();

        let risk = engine.assess_risk(&baseline, &experimental).await.unwrap();

        // Experimental is slightly better, so probability of loss should be < 0.5
        assert!(risk.probability_of_loss < 0.5);
    }

    #[tokio::test]
    async fn test_invalid_bounds() {
        let engine = MonteCarloEngine::new();

        let bounds = vec![ParameterBounds::new("x", 10.0, 0.0)]; // min > max

        let result = engine.simulate(&bounds, |_| 0.0).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_insufficient_samples() {
        let engine = MonteCarloEngine::new();

        let result = engine.compare(&[1.0], &[2.0, 3.0]).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_distribution_estimation() {
        let engine = MonteCarloEngine::new();

        let samples: Vec<f64> = (0..100).map(|x| x as f64).collect();
        let dist = engine.estimate_distribution(&samples).await;

        assert!((dist.mean - 49.5).abs() < 1.0);
        assert_eq!(dist.sample_count, 100);
    }

    #[tokio::test]
    async fn test_confidence_intervals() {
        let engine = MonteCarloEngine::new();

        let samples: Vec<f64> = (0..100).map(|x| x as f64).collect();
        let ci = engine.confidence_intervals(&samples).await;

        // Mean CI should contain the true mean (~49.5)
        assert!(ci.mean_ci.0 < 49.5);
        assert!(ci.mean_ci.1 > 49.5);
        assert_eq!(ci.confidence_level, 0.95);
    }
}
