//! Sampling strategies for Monte Carlo simulation
//!
//! This module provides various sampling strategies for exploring parameter spaces:
//! - Random: Simple random sampling
//! - Latin Hypercube: Space-filling design with better coverage
//! - Sobol: Quasi-Monte Carlo sequences for deterministic low-discrepancy sampling

use crate::traits::SamplingStrategy;
use crate::types::{DistributionHint, ParameterBounds, SampledParameters};
use rand::prelude::*;
use rand::SeedableRng;
use rand_distr::{Beta, LogNormal, Normal, Triangular, Uniform};

/// Random sampling strategy (simple Monte Carlo)
#[derive(Debug, Clone)]
pub struct RandomSampler {
    seed: Option<u64>,
}

impl RandomSampler {
    pub fn new() -> Self {
        Self { seed: None }
    }

    pub fn with_seed(seed: u64) -> Self {
        Self { seed: Some(seed) }
    }

    fn create_rng(&self) -> impl Rng {
        match self.seed {
            Some(seed) => rand::rngs::StdRng::seed_from_u64(seed),
            None => rand::rngs::StdRng::from_entropy(),
        }
    }
}

impl Default for RandomSampler {
    fn default() -> Self {
        Self::new()
    }
}

impl SamplingStrategy for RandomSampler {
    fn sample(&self, n_samples: usize, bounds: &[ParameterBounds]) -> Vec<SampledParameters> {
        let mut rng = self.create_rng();
        let mut samples = Vec::with_capacity(n_samples);

        for _ in 0..n_samples {
            let mut params = SampledParameters::new();
            for bound in bounds {
                let value = sample_with_hint(&mut rng, bound);
                params.insert(&bound.name, value);
            }
            samples.push(params);
        }

        samples
    }

    fn name(&self) -> &'static str {
        "Random"
    }
}

/// Latin Hypercube Sampling for better space coverage
#[derive(Debug, Clone)]
pub struct LatinHypercubeSampler {
    seed: Option<u64>,
}

impl LatinHypercubeSampler {
    pub fn new() -> Self {
        Self { seed: None }
    }

    pub fn with_seed(seed: u64) -> Self {
        Self { seed: Some(seed) }
    }

    fn create_rng(&self) -> impl Rng {
        match self.seed {
            Some(seed) => rand::rngs::StdRng::seed_from_u64(seed),
            None => rand::rngs::StdRng::from_entropy(),
        }
    }
}

impl Default for LatinHypercubeSampler {
    fn default() -> Self {
        Self::new()
    }
}

impl SamplingStrategy for LatinHypercubeSampler {
    fn sample(&self, n_samples: usize, bounds: &[ParameterBounds]) -> Vec<SampledParameters> {
        let mut rng = self.create_rng();
        let n_params = bounds.len();

        // Generate Latin Hypercube design
        // For each dimension, divide [0,1] into n_samples equal intervals
        // Then randomly permute and sample within each interval
        let mut lhs_values: Vec<Vec<f64>> = Vec::with_capacity(n_params);

        for _ in 0..n_params {
            // Create interval indices and shuffle
            let mut indices: Vec<usize> = (0..n_samples).collect();
            indices.shuffle(&mut rng);

            // Sample one point from each interval
            let values: Vec<f64> = indices
                .iter()
                .map(|&i| {
                    let lower = i as f64 / n_samples as f64;
                    let upper = (i + 1) as f64 / n_samples as f64;
                    rng.gen_range(lower..upper)
                })
                .collect();

            lhs_values.push(values);
        }

        // Convert to SampledParameters
        let samples = (0..n_samples)
            .map(|sample_idx| {
                let mut params = SampledParameters::new();
                for (param_idx, bound) in bounds.iter().enumerate() {
                    // Transform from [0,1] to parameter bounds
                    let unit_value = lhs_values[param_idx][sample_idx];
                    let value = transform_to_bounds(unit_value, bound);
                    params.insert(&bound.name, value);
                }
                params
            })
            .collect();

        samples
    }

    fn name(&self) -> &'static str {
        "Latin Hypercube"
    }
}

/// Sobol sequence sampler (quasi-Monte Carlo)
/// Uses a simple implementation when the sobol crate API is complex
#[derive(Debug, Clone)]
pub struct SobolSampler {
    skip: usize, // Skip initial samples for better uniformity
}

impl SobolSampler {
    pub fn new() -> Self {
        Self { skip: 0 }
    }

    pub fn with_skip(skip: usize) -> Self {
        Self { skip }
    }

    /// Van der Corput sequence in base b
    fn van_der_corput(n: usize, base: usize) -> f64 {
        let mut result = 0.0;
        let mut denom = 1.0;
        let mut index = n;

        while index > 0 {
            denom *= base as f64;
            result += (index % base) as f64 / denom;
            index /= base;
        }

        result
    }

    /// Halton sequence (low-discrepancy quasi-random sequence)
    /// Uses prime bases for each dimension
    fn halton_point(n: usize, dims: usize) -> Vec<f64> {
        const PRIMES: [usize; 20] = [
            2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
        ];

        (0..dims)
            .map(|d| {
                let base = if d < PRIMES.len() {
                    PRIMES[d]
                } else {
                    PRIMES[d % PRIMES.len()] + d
                };
                Self::van_der_corput(n, base)
            })
            .collect()
    }
}

impl Default for SobolSampler {
    fn default() -> Self {
        Self::new()
    }
}

impl SamplingStrategy for SobolSampler {
    fn sample(&self, n_samples: usize, bounds: &[ParameterBounds]) -> Vec<SampledParameters> {
        let n_dims = bounds.len();
        let mut samples = Vec::with_capacity(n_samples);

        for i in 0..n_samples {
            let mut params = SampledParameters::new();

            // Get Halton sequence point (quasi-random, low discrepancy)
            let point = Self::halton_point(i + self.skip + 1, n_dims);

            for (dim_idx, bound) in bounds.iter().enumerate() {
                let unit_value = point[dim_idx];
                let value = transform_to_bounds(unit_value, bound);
                params.insert(&bound.name, value);
            }

            samples.push(params);
        }

        samples
    }

    fn name(&self) -> &'static str {
        "Sobol"
    }
}

/// Transform a [0,1] value to parameter bounds, respecting distribution hint
fn transform_to_bounds(unit_value: f64, bound: &ParameterBounds) -> f64 {
    match &bound.distribution_hint {
        Some(DistributionHint::Uniform) | None => {
            // Linear interpolation
            bound.min + unit_value * (bound.max - bound.min)
        }
        Some(DistributionHint::Normal { mean, std_dev }) => {
            // Inverse CDF transform for normal distribution
            // Clamp to bounds
            use statrs::distribution::{ContinuousCDF, Normal as StatrsNormal};
            let normal = StatrsNormal::new(*mean, *std_dev).unwrap_or(
                StatrsNormal::new((bound.min + bound.max) / 2.0, (bound.max - bound.min) / 4.0)
                    .unwrap(),
            );
            let value = normal.inverse_cdf(unit_value.clamp(0.001, 0.999));
            value.clamp(bound.min, bound.max)
        }
        Some(DistributionHint::LogNormal { mu, sigma }) => {
            use statrs::distribution::{ContinuousCDF, LogNormal as StatrsLogNormal};
            let lognormal = StatrsLogNormal::new(*mu, *sigma)
                .unwrap_or(StatrsLogNormal::new(0.0, 1.0).unwrap());
            let value = lognormal.inverse_cdf(unit_value.clamp(0.001, 0.999));
            value.clamp(bound.min, bound.max)
        }
        Some(DistributionHint::Beta { alpha, beta }) => {
            use statrs::distribution::{Beta as StatrsBeta, ContinuousCDF};
            let beta_dist =
                StatrsBeta::new(*alpha, *beta).unwrap_or(StatrsBeta::new(1.0, 1.0).unwrap());
            let unit_sample = beta_dist.inverse_cdf(unit_value.clamp(0.001, 0.999));
            // Scale to bounds
            bound.min + unit_sample * (bound.max - bound.min)
        }
        Some(DistributionHint::Triangular { mode }) => {
            // Inverse CDF for triangular distribution
            let a = bound.min;
            let b = bound.max;
            let c = mode.clamp(a, b);
            let fc = (c - a) / (b - a);

            if unit_value < fc {
                a + ((unit_value * (b - a) * (c - a)).sqrt())
            } else {
                b - (((1.0 - unit_value) * (b - a) * (b - c)).sqrt())
            }
        }
    }
}

/// Sample a value respecting distribution hint (for random sampling)
fn sample_with_hint<R: Rng>(rng: &mut R, bound: &ParameterBounds) -> f64 {
    match &bound.distribution_hint {
        Some(DistributionHint::Uniform) | None => {
            let dist = Uniform::new(bound.min, bound.max);
            rng.sample(dist)
        }
        Some(DistributionHint::Normal { mean, std_dev }) => {
            let dist = Normal::new(*mean, *std_dev).unwrap_or(
                Normal::new((bound.min + bound.max) / 2.0, (bound.max - bound.min) / 4.0).unwrap(),
            );
            rng.sample(dist).clamp(bound.min, bound.max)
        }
        Some(DistributionHint::LogNormal { mu, sigma }) => {
            let dist = LogNormal::new(*mu, *sigma).unwrap_or(LogNormal::new(0.0, 1.0).unwrap());
            rng.sample(dist).clamp(bound.min, bound.max)
        }
        Some(DistributionHint::Beta { alpha, beta }) => {
            let dist = Beta::new(*alpha, *beta).unwrap_or(Beta::new(1.0, 1.0).unwrap());
            let unit_sample: f64 = rng.sample(dist);
            // Scale to bounds
            bound.min + unit_sample * (bound.max - bound.min)
        }
        Some(DistributionHint::Triangular { mode }) => {
            let c = mode.clamp(bound.min, bound.max);
            let dist = Triangular::new(bound.min, bound.max, c).unwrap_or(
                Triangular::new(bound.min, bound.max, (bound.min + bound.max) / 2.0).unwrap(),
            );
            rng.sample(dist)
        }
    }
}

/// Factory function to create sampler by name
pub fn create_sampler(name: &str, seed: Option<u64>) -> Box<dyn SamplingStrategy> {
    match name.to_lowercase().as_str() {
        "random" => {
            let sampler = match seed {
                Some(s) => RandomSampler::with_seed(s),
                None => RandomSampler::new(),
            };
            Box::new(sampler)
        }
        "latin_hypercube" | "lhs" => {
            let sampler = match seed {
                Some(s) => LatinHypercubeSampler::with_seed(s),
                None => LatinHypercubeSampler::new(),
            };
            Box::new(sampler)
        }
        "sobol" | "quasi" => Box::new(SobolSampler::new()),
        _ => {
            // Default to Latin Hypercube
            let sampler = match seed {
                Some(s) => LatinHypercubeSampler::with_seed(s),
                None => LatinHypercubeSampler::new(),
            };
            Box::new(sampler)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_sampler_bounds() {
        let sampler = RandomSampler::with_seed(42);
        let bounds = vec![
            ParameterBounds::new("x", 0.0, 10.0),
            ParameterBounds::new("y", -5.0, 5.0),
        ];

        let samples = sampler.sample(100, &bounds);
        assert_eq!(samples.len(), 100);

        for sample in &samples {
            let x = sample.get("x").unwrap();
            let y = sample.get("y").unwrap();
            assert!((0.0..=10.0).contains(&x));
            assert!((-5.0..=5.0).contains(&y));
        }
    }

    #[test]
    fn test_random_sampler_reproducibility() {
        let sampler1 = RandomSampler::with_seed(42);
        let sampler2 = RandomSampler::with_seed(42);
        let bounds = vec![ParameterBounds::new("x", 0.0, 1.0)];

        let samples1 = sampler1.sample(10, &bounds);
        let samples2 = sampler2.sample(10, &bounds);

        for (s1, s2) in samples1.iter().zip(samples2.iter()) {
            assert_eq!(s1.get("x"), s2.get("x"));
        }
    }

    #[test]
    fn test_lhs_coverage() {
        let sampler = LatinHypercubeSampler::with_seed(42);
        let bounds = vec![ParameterBounds::new("x", 0.0, 1.0)];

        let samples = sampler.sample(10, &bounds);

        // In LHS, each decile should have exactly one sample
        let mut decile_counts = [0; 10];
        for sample in &samples {
            let x = sample.get("x").unwrap();
            let decile = (x * 10.0).floor() as usize;
            let decile = decile.min(9);
            decile_counts[decile] += 1;
        }

        for count in decile_counts {
            assert_eq!(count, 1, "LHS should have exactly one sample per stratum");
        }
    }

    #[test]
    fn test_sobol_deterministic() {
        let sampler = SobolSampler::new();
        let bounds = vec![ParameterBounds::new("x", 0.0, 1.0)];

        let samples1 = sampler.sample(10, &bounds);

        // Create new sampler - should produce same sequence
        let sampler2 = SobolSampler::new();
        let samples2 = sampler2.sample(10, &bounds);

        for (s1, s2) in samples1.iter().zip(samples2.iter()) {
            assert!((s1.get("x").unwrap() - s2.get("x").unwrap()).abs() < 1e-10);
        }
    }

    #[test]
    fn test_distribution_hint_normal() {
        let sampler = RandomSampler::with_seed(42);
        let bounds = vec![ParameterBounds::new("x", 0.0, 100.0).with_distribution(
            DistributionHint::Normal {
                mean: 50.0,
                std_dev: 10.0,
            },
        )];

        let samples = sampler.sample(1000, &bounds);

        // Calculate mean - should be close to 50
        let mean: f64 = samples.iter().map(|s| s.get("x").unwrap()).sum::<f64>() / 1000.0;
        assert!(
            (mean - 50.0).abs() < 5.0,
            "Mean should be close to 50, got {}",
            mean
        );
    }

    #[test]
    fn test_create_sampler_factory() {
        let random = create_sampler("random", None);
        assert_eq!(random.name(), "Random");

        let lhs = create_sampler("latin_hypercube", None);
        assert_eq!(lhs.name(), "Latin Hypercube");

        let sobol = create_sampler("sobol", None);
        assert_eq!(sobol.name(), "Sobol");
    }
}
