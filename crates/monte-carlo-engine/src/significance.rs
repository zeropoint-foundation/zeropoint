//! Statistical significance testing for Monte Carlo simulations
//!
//! This module provides tests for statistical significance including:
//! - Two-sample t-tests (Welch's t-test)
//! - Mann-Whitney U test (non-parametric)
//! - Effect size calculations (Cohen's d)

use crate::traits::SignificanceCalculator;
use crate::types::{EffectSizeInterpretation, SignificanceResult};
use statrs::distribution::{ContinuousCDF, Normal, StudentsT};

/// Welch's t-test for significance (parametric)
#[derive(Debug, Clone, Default)]
pub struct WelchTTest;

impl WelchTTest {
    pub fn new() -> Self {
        Self
    }
}

impl SignificanceCalculator for WelchTTest {
    fn calculate(
        &self,
        baseline_samples: &[f64],
        experimental_samples: &[f64],
    ) -> SignificanceResult {
        let n1 = baseline_samples.len() as f64;
        let n2 = experimental_samples.len() as f64;

        if n1 < 2.0 || n2 < 2.0 {
            return SignificanceResult {
                p_value: 1.0,
                is_significant_at_05: false,
                is_significant_at_01: false,
                is_significant_at_001: false,
                effect_size: 0.0,
                effect_interpretation: EffectSizeInterpretation::Negligible,
                test_name: "Welch's t-test".to_string(),
                test_statistic: 0.0,
                degrees_of_freedom: Some(0.0),
            };
        }

        // Calculate means
        let mean1 = baseline_samples.iter().sum::<f64>() / n1;
        let mean2 = experimental_samples.iter().sum::<f64>() / n2;

        // Calculate variances
        let var1 = baseline_samples
            .iter()
            .map(|x| (x - mean1).powi(2))
            .sum::<f64>()
            / (n1 - 1.0);
        let var2 = experimental_samples
            .iter()
            .map(|x| (x - mean2).powi(2))
            .sum::<f64>()
            / (n2 - 1.0);

        // Welch's t-statistic
        let se = (var1 / n1 + var2 / n2).sqrt();
        let t_stat = if se > 0.0 { (mean2 - mean1) / se } else { 0.0 };

        // Welch-Satterthwaite degrees of freedom
        let df = welch_df(var1, n1, var2, n2);

        // Two-tailed p-value
        let t_dist =
            StudentsT::new(0.0, 1.0, df).unwrap_or(StudentsT::new(0.0, 1.0, 30.0).unwrap());
        let p_value = 2.0 * (1.0 - t_dist.cdf(t_stat.abs()));

        // Cohen's d effect size
        let pooled_std = ((var1 + var2) / 2.0).sqrt();
        let effect_size = if pooled_std > 0.0 {
            (mean2 - mean1) / pooled_std
        } else {
            0.0
        };

        SignificanceResult {
            p_value,
            is_significant_at_05: p_value < 0.05,
            is_significant_at_01: p_value < 0.01,
            is_significant_at_001: p_value < 0.001,
            effect_size,
            effect_interpretation: EffectSizeInterpretation::from_cohens_d(effect_size),
            test_name: "Welch's t-test".to_string(),
            test_statistic: t_stat,
            degrees_of_freedom: Some(df),
        }
    }

    fn name(&self) -> &'static str {
        "Welch's t-test"
    }
}

/// Mann-Whitney U test (non-parametric)
#[derive(Debug, Clone, Default)]
pub struct MannWhitneyU;

impl MannWhitneyU {
    pub fn new() -> Self {
        Self
    }

    /// Calculate U statistic
    fn calculate_u(sample1: &[f64], sample2: &[f64]) -> (f64, f64) {
        let n1 = sample1.len();
        let n2 = sample2.len();

        // Count how many times sample2 values are greater than sample1 values
        let mut u1 = 0.0;
        for &x1 in sample1 {
            for &x2 in sample2 {
                if x2 > x1 {
                    u1 += 1.0;
                } else if x2 == x1 {
                    u1 += 0.5;
                }
            }
        }

        let u2 = (n1 * n2) as f64 - u1;
        (u1, u2)
    }
}

impl SignificanceCalculator for MannWhitneyU {
    fn calculate(
        &self,
        baseline_samples: &[f64],
        experimental_samples: &[f64],
    ) -> SignificanceResult {
        let n1 = baseline_samples.len() as f64;
        let n2 = experimental_samples.len() as f64;

        if n1 < 1.0 || n2 < 1.0 {
            return SignificanceResult {
                p_value: 1.0,
                is_significant_at_05: false,
                is_significant_at_01: false,
                is_significant_at_001: false,
                effect_size: 0.0,
                effect_interpretation: EffectSizeInterpretation::Negligible,
                test_name: "Mann-Whitney U".to_string(),
                test_statistic: 0.0,
                degrees_of_freedom: None,
            };
        }

        let (u1, u2) = Self::calculate_u(baseline_samples, experimental_samples);
        let u = u1.min(u2);

        // Normal approximation for large samples
        let mean_u = n1 * n2 / 2.0;
        let std_u = (n1 * n2 * (n1 + n2 + 1.0) / 12.0).sqrt();

        let z = if std_u > 0.0 {
            (u - mean_u) / std_u
        } else {
            0.0
        };

        // Two-tailed p-value using normal approximation
        let normal = Normal::new(0.0, 1.0).unwrap();
        let p_value = 2.0 * (1.0 - normal.cdf(z.abs()));

        // Effect size: r = Z / sqrt(N)
        // Common Language Effect Size (probability that x2 > x1)
        let effect_size = u1 / (n1 * n2);

        // Convert to Cohen's d approximation
        // d = 2 * (CLES - 0.5) / sqrt(1 - (2*CLES - 1)^2)
        let cles = effect_size;
        let cohens_d = if cles > 0.0 && cles < 1.0 {
            let term = 2.0 * cles - 1.0;
            let denom = (1.0 - term * term).sqrt();
            if denom > 0.0 {
                2.0 * (cles - 0.5) / denom
            } else {
                0.0
            }
        } else {
            0.0
        };

        SignificanceResult {
            p_value,
            is_significant_at_05: p_value < 0.05,
            is_significant_at_01: p_value < 0.01,
            is_significant_at_001: p_value < 0.001,
            effect_size: cohens_d,
            effect_interpretation: EffectSizeInterpretation::from_cohens_d(cohens_d),
            test_name: "Mann-Whitney U".to_string(),
            test_statistic: z,
            degrees_of_freedom: None,
        }
    }

    fn name(&self) -> &'static str {
        "Mann-Whitney U"
    }
}

/// Permutation test (non-parametric, exact for small samples)
#[derive(Debug, Clone)]
pub struct PermutationTest {
    n_permutations: usize,
    seed: Option<u64>,
}

impl PermutationTest {
    pub fn new(n_permutations: usize) -> Self {
        Self {
            n_permutations,
            seed: None,
        }
    }

    pub fn with_seed(mut self, seed: u64) -> Self {
        self.seed = Some(seed);
        self
    }
}

impl Default for PermutationTest {
    fn default() -> Self {
        Self::new(10000)
    }
}

impl SignificanceCalculator for PermutationTest {
    fn calculate(
        &self,
        baseline_samples: &[f64],
        experimental_samples: &[f64],
    ) -> SignificanceResult {
        use rand::prelude::*;
        use rand::SeedableRng;

        let n1 = baseline_samples.len();
        let n2 = experimental_samples.len();

        if n1 < 2 || n2 < 2 {
            return SignificanceResult {
                p_value: 1.0,
                is_significant_at_05: false,
                is_significant_at_01: false,
                is_significant_at_001: false,
                effect_size: 0.0,
                effect_interpretation: EffectSizeInterpretation::Negligible,
                test_name: "Permutation test".to_string(),
                test_statistic: 0.0,
                degrees_of_freedom: None,
            };
        }

        // Observed difference in means
        let mean1 = baseline_samples.iter().sum::<f64>() / n1 as f64;
        let mean2 = experimental_samples.iter().sum::<f64>() / n2 as f64;
        let observed_diff = mean2 - mean1;

        // Combine samples
        let mut combined: Vec<f64> = baseline_samples
            .iter()
            .chain(experimental_samples.iter())
            .copied()
            .collect();

        let mut rng = match self.seed {
            Some(s) => rand::rngs::StdRng::seed_from_u64(s),
            None => rand::rngs::StdRng::from_entropy(),
        };

        // Count permutations with difference >= observed
        let mut count_extreme = 0;
        for _ in 0..self.n_permutations {
            combined.shuffle(&mut rng);
            let perm_mean1: f64 = combined[..n1].iter().sum::<f64>() / n1 as f64;
            let perm_mean2: f64 = combined[n1..].iter().sum::<f64>() / n2 as f64;
            let perm_diff = perm_mean2 - perm_mean1;

            if perm_diff.abs() >= observed_diff.abs() {
                count_extreme += 1;
            }
        }

        let p_value = count_extreme as f64 / self.n_permutations as f64;

        // Effect size (Cohen's d)
        let var1 = baseline_samples
            .iter()
            .map(|x| (x - mean1).powi(2))
            .sum::<f64>()
            / (n1 - 1) as f64;
        let var2 = experimental_samples
            .iter()
            .map(|x| (x - mean2).powi(2))
            .sum::<f64>()
            / (n2 - 1) as f64;
        let pooled_std = ((var1 + var2) / 2.0).sqrt();
        let effect_size = if pooled_std > 0.0 {
            observed_diff / pooled_std
        } else {
            0.0
        };

        SignificanceResult {
            p_value,
            is_significant_at_05: p_value < 0.05,
            is_significant_at_01: p_value < 0.01,
            is_significant_at_001: p_value < 0.001,
            effect_size,
            effect_interpretation: EffectSizeInterpretation::from_cohens_d(effect_size),
            test_name: "Permutation test".to_string(),
            test_statistic: observed_diff,
            degrees_of_freedom: None,
        }
    }

    fn name(&self) -> &'static str {
        "Permutation test"
    }
}

/// Welch-Satterthwaite degrees of freedom approximation
fn welch_df(var1: f64, n1: f64, var2: f64, n2: f64) -> f64 {
    let s1 = var1 / n1;
    let s2 = var2 / n2;
    let numerator = (s1 + s2).powi(2);
    let denominator = s1.powi(2) / (n1 - 1.0) + s2.powi(2) / (n2 - 1.0);

    if denominator == 0.0 {
        (n1 + n2 - 2.0).max(1.0)
    } else {
        (numerator / denominator).max(1.0)
    }
}

/// Calculate Cohen's d effect size between two samples
pub fn cohens_d(sample1: &[f64], sample2: &[f64]) -> f64 {
    let n1 = sample1.len() as f64;
    let n2 = sample2.len() as f64;

    if n1 < 2.0 || n2 < 2.0 {
        return 0.0;
    }

    let mean1 = sample1.iter().sum::<f64>() / n1;
    let mean2 = sample2.iter().sum::<f64>() / n2;

    let var1 = sample1.iter().map(|x| (x - mean1).powi(2)).sum::<f64>() / (n1 - 1.0);
    let var2 = sample2.iter().map(|x| (x - mean2).powi(2)).sum::<f64>() / (n2 - 1.0);

    // Pooled standard deviation
    let pooled_std = (((n1 - 1.0) * var1 + (n2 - 1.0) * var2) / (n1 + n2 - 2.0)).sqrt();

    if pooled_std > 0.0 {
        (mean2 - mean1) / pooled_std
    } else {
        0.0
    }
}

/// Calculate Glass's delta (uses only control group SD)
pub fn glass_delta(control: &[f64], treatment: &[f64]) -> f64 {
    let n1 = control.len() as f64;
    let n2 = treatment.len() as f64;

    if n1 < 2.0 || n2 < 1.0 {
        return 0.0;
    }

    let mean1 = control.iter().sum::<f64>() / n1;
    let mean2 = treatment.iter().sum::<f64>() / n2;

    let var1 = control.iter().map(|x| (x - mean1).powi(2)).sum::<f64>() / (n1 - 1.0);
    let std1 = var1.sqrt();

    if std1 > 0.0 {
        (mean2 - mean1) / std1
    } else {
        0.0
    }
}

/// Factory function to create significance calculator by name
pub fn create_significance_calculator(
    name: &str,
    n_permutations: Option<usize>,
) -> Box<dyn SignificanceCalculator> {
    match name.to_lowercase().as_str() {
        "welch" | "t" | "ttest" | "parametric" => Box::new(WelchTTest::new()),
        "mann_whitney" | "mannwhitney" | "u" | "nonparametric" => Box::new(MannWhitneyU::new()),
        "permutation" | "exact" => Box::new(PermutationTest::new(n_permutations.unwrap_or(10000))),
        _ => Box::new(WelchTTest::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_welch_equal_samples() {
        let a: Vec<f64> = (0..100).map(|x| x as f64).collect();
        let b: Vec<f64> = (0..100).map(|x| x as f64).collect();

        let test = WelchTTest::new();
        let result = test.calculate(&a, &b);

        // Same samples: p-value should be 1.0, effect size ~0
        assert!((result.p_value - 1.0).abs() < 0.01);
        assert!(result.effect_size.abs() < 0.01);
        assert!(!result.is_significant_at_05);
    }

    #[test]
    fn test_welch_different_samples() {
        let a: Vec<f64> = (0..100).map(|x| x as f64).collect(); // mean ~49.5
        let b: Vec<f64> = (50..150).map(|x| x as f64).collect(); // mean ~99.5

        let test = WelchTTest::new();
        let result = test.calculate(&a, &b);

        // Clearly different: should be highly significant
        assert!(result.p_value < 0.001);
        assert!(result.is_significant_at_001);
        // Large effect size (d > 0.8)
        assert!(result.effect_size > 0.8);
        assert_eq!(
            result.effect_interpretation,
            EffectSizeInterpretation::Large
        );
    }

    #[test]
    fn test_mann_whitney() {
        let a: Vec<f64> = (0..50).map(|x| x as f64).collect();
        let b: Vec<f64> = (30..80).map(|x| x as f64).collect();

        let test = MannWhitneyU::new();
        let result = test.calculate(&a, &b);

        // Shifted samples: should be significant
        assert!(result.p_value < 0.05);
        assert!(result.is_significant_at_05);
    }

    #[test]
    fn test_permutation_test() {
        let a: Vec<f64> = (0..30).map(|x| x as f64).collect();
        let b: Vec<f64> = (20..50).map(|x| x as f64).collect();

        let test = PermutationTest::new(1000).with_seed(42);
        let result = test.calculate(&a, &b);

        // Shifted samples: should be significant
        assert!(result.p_value < 0.05);
    }

    #[test]
    fn test_cohens_d() {
        let a: Vec<f64> = (0..100).map(|x| x as f64).collect();
        let b: Vec<f64> = (0..100).map(|x| x as f64).collect();

        // Same samples
        let d = cohens_d(&a, &b);
        assert!(d.abs() < 0.01);

        // Shifted samples
        let c: Vec<f64> = (50..150).map(|x| x as f64).collect();
        let d2 = cohens_d(&a, &c);
        assert!(d2 > 0.8); // Large effect
    }

    #[test]
    fn test_effect_size_interpretation() {
        assert_eq!(
            EffectSizeInterpretation::from_cohens_d(0.1),
            EffectSizeInterpretation::Negligible
        );
        assert_eq!(
            EffectSizeInterpretation::from_cohens_d(0.3),
            EffectSizeInterpretation::Small
        );
        assert_eq!(
            EffectSizeInterpretation::from_cohens_d(0.6),
            EffectSizeInterpretation::Medium
        );
        assert_eq!(
            EffectSizeInterpretation::from_cohens_d(1.0),
            EffectSizeInterpretation::Large
        );
        // Negative values
        assert_eq!(
            EffectSizeInterpretation::from_cohens_d(-0.9),
            EffectSizeInterpretation::Large
        );
    }

    #[test]
    fn test_empty_samples() {
        let test = WelchTTest::new();
        let result = test.calculate(&[], &[1.0, 2.0, 3.0]);

        assert_eq!(result.p_value, 1.0);
        assert!(!result.is_significant_at_05);
    }

    #[test]
    fn test_factory() {
        let welch = create_significance_calculator("welch", None);
        assert_eq!(welch.name(), "Welch's t-test");

        let mw = create_significance_calculator("mann_whitney", None);
        assert_eq!(mw.name(), "Mann-Whitney U");

        let perm = create_significance_calculator("permutation", Some(5000));
        assert_eq!(perm.name(), "Permutation test");
    }
}
