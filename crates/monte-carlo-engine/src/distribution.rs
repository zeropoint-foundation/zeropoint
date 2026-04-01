//! Distribution estimation for Monte Carlo outcomes
//!
//! This module provides estimators for analyzing simulation outcomes
//! and computing distribution statistics.

use crate::traits::DistributionEstimator;
use crate::types::OutcomeDistribution;
use std::collections::HashMap;

/// Empirical distribution estimator using sample statistics
#[derive(Debug, Clone, Default)]
pub struct EmpiricalEstimator;

impl EmpiricalEstimator {
    pub fn new() -> Self {
        Self
    }
}

impl DistributionEstimator for EmpiricalEstimator {
    fn estimate(&self, samples: &[f64]) -> OutcomeDistribution {
        if samples.is_empty() {
            return OutcomeDistribution {
                mean: 0.0,
                median: 0.0,
                std_dev: 0.0,
                variance: 0.0,
                skewness: 0.0,
                kurtosis: 0.0,
                min: 0.0,
                max: 0.0,
                percentiles: HashMap::new(),
                sample_count: 0,
            };
        }

        let n = samples.len() as f64;

        // Sort for percentile calculations
        let mut sorted = samples.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        // Basic statistics
        let mean = samples.iter().sum::<f64>() / n;
        let min = sorted[0];
        let max = sorted[sorted.len() - 1];

        // Variance and std dev
        let variance = samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0).max(1.0);
        let std_dev = variance.sqrt();

        // Skewness (Fisher's definition)
        let skewness = if std_dev > 0.0 {
            let m3 = samples.iter().map(|x| (x - mean).powi(3)).sum::<f64>() / n;
            m3 / std_dev.powi(3)
        } else {
            0.0
        };

        // Excess kurtosis (Fisher's definition)
        let kurtosis = if std_dev > 0.0 {
            let m4 = samples.iter().map(|x| (x - mean).powi(4)).sum::<f64>() / n;
            (m4 / std_dev.powi(4)) - 3.0
        } else {
            0.0
        };

        // Percentiles
        let percentiles = calculate_percentiles(&sorted);

        // Median (p50)
        let median = *percentiles.get("p50").unwrap_or(&mean);

        OutcomeDistribution {
            mean,
            median,
            std_dev,
            variance,
            skewness,
            kurtosis,
            min,
            max,
            percentiles,
            sample_count: samples.len(),
        }
    }

    fn name(&self) -> &'static str {
        "Empirical"
    }
}

/// Calculate standard percentiles from sorted samples
fn calculate_percentiles(sorted: &[f64]) -> HashMap<String, f64> {
    let percentile_points = [
        ("p1", 0.01),
        ("p5", 0.05),
        ("p10", 0.10),
        ("p25", 0.25),
        ("p50", 0.50),
        ("p75", 0.75),
        ("p90", 0.90),
        ("p95", 0.95),
        ("p99", 0.99),
    ];

    let mut percentiles = HashMap::new();
    let n = sorted.len();

    if n == 0 {
        return percentiles;
    }

    for (name, p) in percentile_points {
        let value = percentile_linear_interpolation(sorted, p);
        percentiles.insert(name.to_string(), value);
    }

    percentiles
}

/// Linear interpolation percentile calculation (similar to numpy's default)
fn percentile_linear_interpolation(sorted: &[f64], p: f64) -> f64 {
    let n = sorted.len();
    if n == 0 {
        return 0.0;
    }
    if n == 1 {
        return sorted[0];
    }

    let index = p * (n - 1) as f64;
    let lower = index.floor() as usize;
    let upper = index.ceil() as usize;
    let fraction = index - lower as f64;

    if lower == upper {
        sorted[lower]
    } else {
        sorted[lower] * (1.0 - fraction) + sorted[upper] * fraction
    }
}

/// Kernel Density Estimation (KDE) based distribution estimator
/// More sophisticated but computationally more expensive
#[derive(Debug, Clone)]
pub struct KernelDensityEstimator {
    bandwidth: Option<f64>,
}

impl KernelDensityEstimator {
    pub fn new() -> Self {
        Self { bandwidth: None }
    }

    pub fn with_bandwidth(bandwidth: f64) -> Self {
        Self {
            bandwidth: Some(bandwidth),
        }
    }

    /// Silverman's rule of thumb for bandwidth selection
    fn optimal_bandwidth(samples: &[f64]) -> f64 {
        let n = samples.len() as f64;
        if n < 2.0 {
            return 1.0;
        }

        let mean = samples.iter().sum::<f64>() / n;
        let variance = samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0);
        let std_dev = variance.sqrt();

        // Silverman's rule
        1.06 * std_dev * n.powf(-0.2)
    }

    /// Gaussian kernel
    fn gaussian_kernel(x: f64) -> f64 {
        const INV_SQRT_2PI: f64 = 0.3989422804014327;
        INV_SQRT_2PI * (-0.5 * x * x).exp()
    }

    /// Estimate density at a point
    fn density_at(&self, x: f64, samples: &[f64], bandwidth: f64) -> f64 {
        let n = samples.len() as f64;
        let sum: f64 = samples
            .iter()
            .map(|&xi| Self::gaussian_kernel((x - xi) / bandwidth))
            .sum();
        sum / (n * bandwidth)
    }
}

impl Default for KernelDensityEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl DistributionEstimator for KernelDensityEstimator {
    fn estimate(&self, samples: &[f64]) -> OutcomeDistribution {
        // Start with empirical estimates
        let empirical = EmpiricalEstimator::new();
        let mut dist = empirical.estimate(samples);

        if samples.is_empty() {
            return dist;
        }

        // Calculate bandwidth
        let bandwidth = self
            .bandwidth
            .unwrap_or_else(|| Self::optimal_bandwidth(samples));

        // For KDE, we can refine the mode estimation
        // Find mode by evaluating density at sample points
        let mode = samples
            .iter()
            .max_by(|&&a, &&b| {
                let da = self.density_at(a, samples, bandwidth);
                let db = self.density_at(b, samples, bandwidth);
                da.partial_cmp(&db).unwrap_or(std::cmp::Ordering::Equal)
            })
            .copied()
            .unwrap_or(dist.mean);

        // Add mode to percentiles
        dist.percentiles.insert("mode".to_string(), mode);

        dist
    }

    fn name(&self) -> &'static str {
        "Kernel Density"
    }
}

/// Robust estimator using median-based statistics
/// Less sensitive to outliers
#[derive(Debug, Clone, Default)]
pub struct RobustEstimator;

impl RobustEstimator {
    pub fn new() -> Self {
        Self
    }
}

impl DistributionEstimator for RobustEstimator {
    fn estimate(&self, samples: &[f64]) -> OutcomeDistribution {
        // Get base empirical estimates
        let empirical = EmpiricalEstimator::new();
        let mut dist = empirical.estimate(samples);

        if samples.len() < 2 {
            return dist;
        }

        // Replace std_dev with MAD (Median Absolute Deviation)
        let median = dist.median;
        let mut deviations: Vec<f64> = samples.iter().map(|x| (x - median).abs()).collect();
        deviations.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let mad = percentile_linear_interpolation(&deviations, 0.5);

        // Scale MAD to be comparable to std dev (for normal distributions)
        let robust_std = mad * 1.4826;
        dist.percentiles.insert("mad".to_string(), mad);
        dist.percentiles
            .insert("robust_std".to_string(), robust_std);

        // Winsorized mean (trim extreme values)
        let mut sorted = samples.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let n = sorted.len();
        let trim = (n as f64 * 0.05).ceil() as usize; // 5% trim
        if n > 2 * trim {
            let trimmed: Vec<f64> = sorted[trim..n - trim].to_vec();
            let trimmed_mean = trimmed.iter().sum::<f64>() / trimmed.len() as f64;
            dist.percentiles
                .insert("trimmed_mean".to_string(), trimmed_mean);
        }

        dist
    }

    fn name(&self) -> &'static str {
        "Robust"
    }
}

/// Factory function to create estimator by name
pub fn create_estimator(name: &str) -> Box<dyn DistributionEstimator> {
    match name.to_lowercase().as_str() {
        "empirical" | "sample" => Box::new(EmpiricalEstimator::new()),
        "kde" | "kernel" | "kernel_density" => Box::new(KernelDensityEstimator::new()),
        "robust" | "mad" => Box::new(RobustEstimator::new()),
        _ => Box::new(EmpiricalEstimator::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empirical_basic_stats() {
        let samples = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let estimator = EmpiricalEstimator::new();
        let dist = estimator.estimate(&samples);

        assert!((dist.mean - 3.0).abs() < 1e-10);
        assert!((dist.median - 3.0).abs() < 1e-10);
        assert_eq!(dist.min, 1.0);
        assert_eq!(dist.max, 5.0);
        assert_eq!(dist.sample_count, 5);
    }

    #[test]
    fn test_empirical_variance() {
        let samples = vec![2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0];
        let estimator = EmpiricalEstimator::new();
        let dist = estimator.estimate(&samples);

        // Sample variance should be 4.571... (using n-1 denominator)
        assert!((dist.variance - 4.571428571).abs() < 0.01);
    }

    #[test]
    fn test_percentiles() {
        let samples: Vec<f64> = (1..=100).map(|x| x as f64).collect();
        let estimator = EmpiricalEstimator::new();
        let dist = estimator.estimate(&samples);

        // p50 should be close to 50.5
        let p50 = dist.percentile("p50").unwrap();
        assert!((p50 - 50.5).abs() < 1.0);

        // p25 should be close to 25.75
        let p25 = dist.percentile("p25").unwrap();
        assert!((p25 - 25.75).abs() < 1.0);
    }

    #[test]
    fn test_iqr() {
        let samples: Vec<f64> = (1..=100).map(|x| x as f64).collect();
        let estimator = EmpiricalEstimator::new();
        let dist = estimator.estimate(&samples);

        let iqr = dist.iqr().unwrap();
        // IQR should be approximately 50 (75.25 - 25.75)
        assert!((iqr - 49.5).abs() < 1.0);
    }

    #[test]
    fn test_empty_samples() {
        let samples: Vec<f64> = vec![];
        let estimator = EmpiricalEstimator::new();
        let dist = estimator.estimate(&samples);

        assert_eq!(dist.sample_count, 0);
        assert_eq!(dist.mean, 0.0);
    }

    #[test]
    fn test_single_sample() {
        let samples = vec![42.0];
        let estimator = EmpiricalEstimator::new();
        let dist = estimator.estimate(&samples);

        assert_eq!(dist.mean, 42.0);
        assert_eq!(dist.median, 42.0);
        assert_eq!(dist.min, 42.0);
        assert_eq!(dist.max, 42.0);
    }

    #[test]
    fn test_skewness_symmetric() {
        // Symmetric distribution should have ~0 skewness
        let samples: Vec<f64> = (-50..=50).map(|x| x as f64).collect();
        let estimator = EmpiricalEstimator::new();
        let dist = estimator.estimate(&samples);

        assert!(dist.skewness.abs() < 0.1);
    }

    #[test]
    fn test_kde_estimator() {
        let samples: Vec<f64> = (0..100).map(|x| x as f64).collect();
        let estimator = KernelDensityEstimator::new();
        let dist = estimator.estimate(&samples);

        // Should have mode in percentiles
        assert!(dist.percentiles.contains_key("mode"));
    }

    #[test]
    fn test_robust_estimator() {
        let mut samples: Vec<f64> = (0..100).map(|x| x as f64).collect();
        // Add outliers
        samples.push(10000.0);
        samples.push(-10000.0);

        let estimator = RobustEstimator::new();
        let dist = estimator.estimate(&samples);

        // Should have MAD and robust_std
        assert!(dist.percentiles.contains_key("mad"));
        assert!(dist.percentiles.contains_key("robust_std"));
    }

    #[test]
    fn test_factory() {
        let emp = create_estimator("empirical");
        assert_eq!(emp.name(), "Empirical");

        let kde = create_estimator("kde");
        assert_eq!(kde.name(), "Kernel Density");

        let robust = create_estimator("robust");
        assert_eq!(robust.name(), "Robust");
    }
}
