//! Confidence interval calculations for Monte Carlo simulations
//!
//! This module provides methods for computing confidence intervals
//! for distribution parameters (mean, median, effect sizes).

use crate::traits::ConfidenceIntervalCalculator;
use crate::types::ConfidenceIntervals;
use statrs::distribution::{ContinuousCDF, StudentsT};

/// Standard confidence interval calculator using t-distribution
#[derive(Debug, Clone, Default)]
pub struct StandardCICalculator;

impl StandardCICalculator {
    pub fn new() -> Self {
        Self
    }

    /// Calculate t-critical value for given confidence level and degrees of freedom
    fn t_critical(confidence_level: f64, df: f64) -> f64 {
        let alpha = 1.0 - confidence_level;
        let t_dist =
            StudentsT::new(0.0, 1.0, df).unwrap_or(StudentsT::new(0.0, 1.0, 30.0).unwrap());
        t_dist.inverse_cdf(1.0 - alpha / 2.0)
    }
}

impl ConfidenceIntervalCalculator for StandardCICalculator {
    fn calculate(&self, samples: &[f64], confidence_level: f64) -> ConfidenceIntervals {
        let n = samples.len();

        if n < 2 {
            return ConfidenceIntervals {
                mean_ci: (f64::NEG_INFINITY, f64::INFINITY),
                median_ci: (f64::NEG_INFINITY, f64::INFINITY),
                effect_ci: (f64::NEG_INFINITY, f64::INFINITY),
                confidence_level,
            };
        }

        let mean = samples.iter().sum::<f64>() / n as f64;
        let variance = samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1) as f64;
        let std_dev = variance.sqrt();
        let std_error = std_dev / (n as f64).sqrt();

        let df = (n - 1) as f64;
        let t_crit = Self::t_critical(confidence_level, df);

        // Mean CI
        let mean_margin = t_crit * std_error;
        let mean_ci = (mean - mean_margin, mean + mean_margin);

        // Median CI (using order statistics approximation)
        let median_ci = calculate_median_ci(samples, confidence_level);

        // Effect CI (treating mean as effect size relative to 0)
        // For single sample, this is same as mean CI
        let effect_ci = mean_ci;

        ConfidenceIntervals {
            mean_ci,
            median_ci,
            effect_ci,
            confidence_level,
        }
    }

    fn name(&self) -> &'static str {
        "Standard (t-distribution)"
    }
}

/// Bootstrap confidence interval calculator
/// More robust for non-normal distributions
#[derive(Debug, Clone)]
pub struct BootstrapCICalculator {
    n_bootstrap: usize,
    seed: Option<u64>,
}

impl BootstrapCICalculator {
    pub fn new(n_bootstrap: usize) -> Self {
        Self {
            n_bootstrap,
            seed: None,
        }
    }

    pub fn with_seed(mut self, seed: u64) -> Self {
        self.seed = Some(seed);
        self
    }

    fn bootstrap_statistic<F>(
        &self,
        samples: &[f64],
        statistic: F,
        confidence_level: f64,
    ) -> (f64, f64)
    where
        F: Fn(&[f64]) -> f64,
    {
        use rand::prelude::*;
        use rand::SeedableRng;

        let mut rng = match self.seed {
            Some(s) => rand::rngs::StdRng::seed_from_u64(s),
            None => rand::rngs::StdRng::from_entropy(),
        };

        let n = samples.len();
        let mut bootstrap_stats = Vec::with_capacity(self.n_bootstrap);

        for _ in 0..self.n_bootstrap {
            // Resample with replacement
            let resampled: Vec<f64> = (0..n).map(|_| samples[rng.gen_range(0..n)]).collect();
            bootstrap_stats.push(statistic(&resampled));
        }

        // Sort for percentile calculation
        bootstrap_stats.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let alpha = 1.0 - confidence_level;
        let lower_idx = (alpha / 2.0 * self.n_bootstrap as f64) as usize;
        let upper_idx = ((1.0 - alpha / 2.0) * self.n_bootstrap as f64) as usize;

        let lower = bootstrap_stats
            .get(lower_idx)
            .copied()
            .unwrap_or(f64::NEG_INFINITY);
        let upper = bootstrap_stats
            .get(upper_idx.min(self.n_bootstrap - 1))
            .copied()
            .unwrap_or(f64::INFINITY);

        (lower, upper)
    }
}

impl Default for BootstrapCICalculator {
    fn default() -> Self {
        Self::new(10000)
    }
}

impl ConfidenceIntervalCalculator for BootstrapCICalculator {
    fn calculate(&self, samples: &[f64], confidence_level: f64) -> ConfidenceIntervals {
        if samples.len() < 2 {
            return ConfidenceIntervals {
                mean_ci: (f64::NEG_INFINITY, f64::INFINITY),
                median_ci: (f64::NEG_INFINITY, f64::INFINITY),
                effect_ci: (f64::NEG_INFINITY, f64::INFINITY),
                confidence_level,
            };
        }

        // Bootstrap CI for mean
        let mean_ci = self.bootstrap_statistic(
            samples,
            |s| s.iter().sum::<f64>() / s.len() as f64,
            confidence_level,
        );

        // Bootstrap CI for median
        let median_ci = self.bootstrap_statistic(
            samples,
            |s| {
                let mut sorted = s.to_vec();
                sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                let mid = sorted.len() / 2;
                if sorted.len() % 2 == 0 {
                    (sorted[mid - 1] + sorted[mid]) / 2.0
                } else {
                    sorted[mid]
                }
            },
            confidence_level,
        );

        // Effect CI same as mean CI for single sample
        let effect_ci = mean_ci;

        ConfidenceIntervals {
            mean_ci,
            median_ci,
            effect_ci,
            confidence_level,
        }
    }

    fn name(&self) -> &'static str {
        "Bootstrap"
    }
}

/// Calculate median confidence interval using order statistics
fn calculate_median_ci(samples: &[f64], confidence_level: f64) -> (f64, f64) {
    let n = samples.len();
    if n < 2 {
        return (f64::NEG_INFINITY, f64::INFINITY);
    }

    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    // Use normal approximation for large n
    // CI indices for median: n/2 +/- z * sqrt(n)/2
    let z = z_critical(confidence_level);
    let half_width = z * (n as f64).sqrt() / 2.0;
    let mid = n as f64 / 2.0;

    let lower_idx = ((mid - half_width).floor() as usize).max(0);
    let upper_idx = ((mid + half_width).ceil() as usize).min(n - 1);

    (sorted[lower_idx], sorted[upper_idx])
}

/// Z-critical value for given confidence level (standard normal)
fn z_critical(confidence_level: f64) -> f64 {
    use statrs::distribution::Normal;
    let alpha = 1.0 - confidence_level;
    let normal = Normal::new(0.0, 1.0).unwrap();
    normal.inverse_cdf(1.0 - alpha / 2.0)
}

/// Calculate confidence interval for the difference between two means
pub fn mean_difference_ci(
    samples_a: &[f64],
    samples_b: &[f64],
    confidence_level: f64,
) -> (f64, f64) {
    let n_a = samples_a.len() as f64;
    let n_b = samples_b.len() as f64;

    if n_a < 2.0 || n_b < 2.0 {
        return (f64::NEG_INFINITY, f64::INFINITY);
    }

    let mean_a = samples_a.iter().sum::<f64>() / n_a;
    let mean_b = samples_b.iter().sum::<f64>() / n_b;
    let diff = mean_b - mean_a;

    let var_a = samples_a.iter().map(|x| (x - mean_a).powi(2)).sum::<f64>() / (n_a - 1.0);
    let var_b = samples_b.iter().map(|x| (x - mean_b).powi(2)).sum::<f64>() / (n_b - 1.0);

    // Welch's t-test degrees of freedom
    let se = (var_a / n_a + var_b / n_b).sqrt();
    let df = welch_df(var_a, n_a, var_b, n_b);

    let t_crit = StandardCICalculator::t_critical(confidence_level, df);
    let margin = t_crit * se;

    (diff - margin, diff + margin)
}

/// Welch-Satterthwaite degrees of freedom approximation
fn welch_df(var_a: f64, n_a: f64, var_b: f64, n_b: f64) -> f64 {
    let sa = var_a / n_a;
    let sb = var_b / n_b;
    let numerator = (sa + sb).powi(2);
    let denominator = sa.powi(2) / (n_a - 1.0) + sb.powi(2) / (n_b - 1.0);

    if denominator == 0.0 {
        (n_a + n_b - 2.0).max(1.0)
    } else {
        (numerator / denominator).max(1.0)
    }
}

/// Factory function to create CI calculator by name
pub fn create_ci_calculator(
    name: &str,
    n_bootstrap: Option<usize>,
) -> Box<dyn ConfidenceIntervalCalculator> {
    match name.to_lowercase().as_str() {
        "standard" | "t" | "parametric" => Box::new(StandardCICalculator::new()),
        "bootstrap" | "nonparametric" => {
            Box::new(BootstrapCICalculator::new(n_bootstrap.unwrap_or(10000)))
        }
        _ => Box::new(StandardCICalculator::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_ci_basic() {
        // Known distribution: standard normal samples
        let samples: Vec<f64> = vec![
            0.1, -0.2, 0.3, 0.1, -0.1, 0.2, 0.0, 0.1, -0.1, 0.2, 0.1, 0.0, -0.1, 0.2, 0.1, 0.0,
            -0.1, 0.1, 0.0, 0.1,
        ];

        let calculator = StandardCICalculator::new();
        let ci = calculator.calculate(&samples, 0.95);

        // Mean should be close to 0, CI should contain 0
        assert!(ci.mean_ci.0 < 0.1);
        assert!(ci.mean_ci.1 > -0.1);
        assert_eq!(ci.confidence_level, 0.95);
    }

    #[test]
    fn test_ci_width_increases_with_confidence() {
        let samples: Vec<f64> = (0..100).map(|x| x as f64).collect();
        let calculator = StandardCICalculator::new();

        let ci_90 = calculator.calculate(&samples, 0.90);
        let ci_95 = calculator.calculate(&samples, 0.95);
        let ci_99 = calculator.calculate(&samples, 0.99);

        let width_90 = ci_90.mean_ci.1 - ci_90.mean_ci.0;
        let width_95 = ci_95.mean_ci.1 - ci_95.mean_ci.0;
        let width_99 = ci_99.mean_ci.1 - ci_99.mean_ci.0;

        assert!(width_90 < width_95);
        assert!(width_95 < width_99);
    }

    #[test]
    fn test_ci_narrows_with_more_samples() {
        let calculator = StandardCICalculator::new();

        let small: Vec<f64> = (0..10).map(|x| x as f64).collect();
        let large: Vec<f64> = (0..1000).map(|x| (x % 10) as f64).collect();

        let ci_small = calculator.calculate(&small, 0.95);
        let ci_large = calculator.calculate(&large, 0.95);

        let width_small = ci_small.mean_ci.1 - ci_small.mean_ci.0;
        let width_large = ci_large.mean_ci.1 - ci_large.mean_ci.0;

        assert!(width_large < width_small);
    }

    #[test]
    fn test_bootstrap_ci() {
        let samples: Vec<f64> = (0..100).map(|x| x as f64).collect();
        let calculator = BootstrapCICalculator::new(1000).with_seed(42);
        let ci = calculator.calculate(&samples, 0.95);

        // Mean should be ~49.5, CI should contain it
        let mean = 49.5;
        assert!(ci.mean_ci.0 < mean);
        assert!(ci.mean_ci.1 > mean);
    }

    #[test]
    fn test_mean_difference_ci() {
        let a: Vec<f64> = (0..50).map(|x| x as f64).collect();
        let b: Vec<f64> = (10..60).map(|x| x as f64).collect(); // Shifted by 10

        let ci = mean_difference_ci(&a, &b, 0.95);

        // Difference should be ~10, CI should contain it
        assert!(ci.0 < 10.0);
        assert!(ci.1 > 10.0);
    }

    #[test]
    fn test_empty_samples() {
        let calculator = StandardCICalculator::new();
        let ci = calculator.calculate(&[], 0.95);

        assert!(ci.mean_ci.0.is_infinite());
        assert!(ci.mean_ci.1.is_infinite());
    }

    #[test]
    fn test_single_sample() {
        let calculator = StandardCICalculator::new();
        let ci = calculator.calculate(&[42.0], 0.95);

        // With single sample, CI is infinite
        assert!(ci.mean_ci.0.is_infinite());
        assert!(ci.mean_ci.1.is_infinite());
    }

    #[test]
    fn test_factory() {
        let standard = create_ci_calculator("standard", None);
        assert_eq!(standard.name(), "Standard (t-distribution)");

        let bootstrap = create_ci_calculator("bootstrap", Some(5000));
        assert_eq!(bootstrap.name(), "Bootstrap");
    }
}
