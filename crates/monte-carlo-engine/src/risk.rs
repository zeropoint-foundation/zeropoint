//! Risk assessment calculations for Monte Carlo simulations
//!
//! This module provides risk metrics including:
//! - Value at Risk (VaR)
//! - Conditional Value at Risk (CVaR / Expected Shortfall)
//! - Maximum Drawdown
//! - Risk-adjusted scores (Sharpe-like ratios)

use crate::traits::RiskAssessor;
use crate::types::{OutcomeDistribution, RiskAssessment};

/// Standard risk assessor implementing VaR, CVaR, and related metrics
#[derive(Debug, Clone, Default)]
pub struct StandardRiskAssessor;

impl StandardRiskAssessor {
    pub fn new() -> Self {
        Self
    }
}

impl RiskAssessor for StandardRiskAssessor {
    fn assess(
        &self,
        baseline: &OutcomeDistribution,
        experimental: &OutcomeDistribution,
        confidence_level: f64,
    ) -> RiskAssessment {
        // Calculate relative outcomes (experimental - baseline)
        // Positive = improvement, Negative = loss
        let mean_diff = experimental.mean - baseline.mean;
        let pooled_std = ((baseline.variance + experimental.variance) / 2.0).sqrt();

        // Probability of loss (experimental worse than baseline)
        // Assuming approximately normal differences
        let probability_of_loss = if pooled_std > 0.0 {
            use statrs::distribution::{ContinuousCDF, Normal};
            let normal = Normal::new(0.0, 1.0).unwrap();
            let z = -mean_diff / pooled_std;
            normal.cdf(z)
        } else if mean_diff < 0.0 {
            1.0
        } else {
            0.0
        };

        // Value at Risk (worst loss at confidence level)
        // VaR is the loss that won't be exceeded with probability = confidence_level
        let var_percentile = format!("p{}", ((1.0 - confidence_level) * 100.0) as u32);
        let value_at_risk = if let Some(&exp_var) = experimental.percentiles.get(&var_percentile) {
            baseline.mean - exp_var
        } else {
            // Parametric VaR using normal approximation
            use statrs::distribution::{ContinuousCDF, Normal};
            let normal = Normal::new(0.0, 1.0).unwrap();
            let z = normal.inverse_cdf(1.0 - confidence_level);
            -mean_diff + z * pooled_std
        };

        // Conditional VaR (Expected Shortfall)
        // Average loss given that loss exceeds VaR
        let conditional_var =
            calculate_expected_shortfall(experimental, baseline.mean, confidence_level);

        // Maximum drawdown (worst observed loss)
        let max_drawdown = baseline.mean - experimental.min;

        // Risk-adjusted score (Sharpe-like ratio)
        // Expected improvement / volatility of improvement
        let risk_adjusted_score = if pooled_std > 0.0 {
            mean_diff / pooled_std
        } else if mean_diff > 0.0 {
            f64::INFINITY
        } else if mean_diff < 0.0 {
            f64::NEG_INFINITY
        } else {
            0.0
        };

        RiskAssessment {
            probability_of_loss,
            value_at_risk: value_at_risk.max(0.0), // VaR is typically reported as positive
            conditional_var: conditional_var.max(0.0),
            max_drawdown: max_drawdown.max(0.0),
            risk_adjusted_score,
            confidence_level,
        }
    }

    fn name(&self) -> &'static str {
        "Standard"
    }
}

/// Conservative risk assessor with more pessimistic estimates
#[derive(Debug, Clone, Default)]
pub struct ConservativeRiskAssessor;

impl ConservativeRiskAssessor {
    pub fn new() -> Self {
        Self
    }
}

impl RiskAssessor for ConservativeRiskAssessor {
    fn assess(
        &self,
        baseline: &OutcomeDistribution,
        experimental: &OutcomeDistribution,
        confidence_level: f64,
    ) -> RiskAssessment {
        // Start with standard assessment
        let standard = StandardRiskAssessor::new();
        let mut assessment = standard.assess(baseline, experimental, confidence_level);

        // Apply conservative adjustments

        // Use higher percentile for VaR (more pessimistic)
        // If confidence is 95%, use 97.5% instead
        let conservative_cl = confidence_level + (1.0 - confidence_level) / 2.0;
        let conservative_var_key = format!("p{}", ((1.0 - conservative_cl) * 100.0) as u32);

        if let Some(&conservative_var) = experimental.percentiles.get(&conservative_var_key) {
            let conservative_value_at_risk = baseline.mean - conservative_var;
            assessment.value_at_risk = assessment.value_at_risk.max(conservative_value_at_risk);
        }

        // Increase probability of loss estimate by uncertainty factor
        let uncertainty_factor = 1.0 / (experimental.sample_count as f64 + 1.0).sqrt();
        assessment.probability_of_loss =
            (assessment.probability_of_loss + uncertainty_factor).min(1.0);

        // Reduce risk-adjusted score to account for estimation uncertainty
        assessment.risk_adjusted_score *= 1.0 - uncertainty_factor;

        assessment
    }

    fn name(&self) -> &'static str {
        "Conservative"
    }
}

/// Calculate Expected Shortfall (CVaR)
/// Average of outcomes below VaR threshold
fn calculate_expected_shortfall(
    distribution: &OutcomeDistribution,
    baseline_mean: f64,
    confidence_level: f64,
) -> f64 {
    // Using percentile approximation
    // Get outcomes below the (1 - confidence_level) percentile
    let tail_percentage = (1.0 - confidence_level) * 100.0;

    // Look for percentiles at or below the tail
    let mut tail_percentiles: Vec<f64> = Vec::new();

    for (key, &value) in &distribution.percentiles {
        if let Some(stripped) = key.strip_prefix('p') {
            if let Ok(p) = stripped.parse::<f64>() {
                if p <= tail_percentage {
                    tail_percentiles.push(value);
                }
            }
        }
    }

    // If we have tail percentiles, average them
    if !tail_percentiles.is_empty() {
        let avg_tail = tail_percentiles.iter().sum::<f64>() / tail_percentiles.len() as f64;
        (baseline_mean - avg_tail).max(0.0)
    } else {
        // Parametric approximation for CVaR under normal distribution
        // CVaR = μ - σ * φ(Φ⁻¹(α)) / α where α = 1 - confidence_level
        use statrs::distribution::{Continuous, ContinuousCDF, Normal};
        let alpha = 1.0 - confidence_level;
        let normal = Normal::new(0.0, 1.0).unwrap();
        let quantile = normal.inverse_cdf(alpha);
        let pdf_at_quantile = normal.pdf(quantile);

        let std_dev = distribution.std_dev;
        let loss = std_dev * pdf_at_quantile / alpha;

        loss.max(0.0)
    }
}

/// Calculate risk metrics from raw simulation outcomes
pub fn assess_outcomes(
    baseline_outcomes: &[f64],
    experimental_outcomes: &[f64],
    confidence_level: f64,
) -> RiskAssessment {
    use crate::distribution::EmpiricalEstimator;
    use crate::traits::DistributionEstimator;

    let estimator = EmpiricalEstimator::new();
    let baseline_dist = estimator.estimate(baseline_outcomes);
    let experimental_dist = estimator.estimate(experimental_outcomes);

    let assessor = StandardRiskAssessor::new();
    assessor.assess(&baseline_dist, &experimental_dist, confidence_level)
}

/// Sortino ratio - risk-adjusted return using downside deviation
pub fn sortino_ratio(outcomes: &[f64], target_return: f64) -> f64 {
    if outcomes.is_empty() {
        return 0.0;
    }

    let mean = outcomes.iter().sum::<f64>() / outcomes.len() as f64;
    let excess_return = mean - target_return;

    // Downside deviation (only negative deviations)
    let downside_squares: f64 = outcomes
        .iter()
        .filter(|&&x| x < target_return)
        .map(|x| (x - target_return).powi(2))
        .sum();

    let downside_count = outcomes.iter().filter(|&&x| x < target_return).count();

    if downside_count == 0 {
        return f64::INFINITY; // No downside risk
    }

    let downside_deviation = (downside_squares / downside_count as f64).sqrt();

    if downside_deviation > 0.0 {
        excess_return / downside_deviation
    } else {
        f64::INFINITY
    }
}

/// Calmar ratio - return over maximum drawdown
pub fn calmar_ratio(outcomes: &[f64]) -> f64 {
    if outcomes.is_empty() {
        return 0.0;
    }

    let mean = outcomes.iter().sum::<f64>() / outcomes.len() as f64;
    let min = outcomes
        .iter()
        .copied()
        .min_by(|a, b| a.partial_cmp(b).unwrap())
        .unwrap_or(mean);

    let max_drawdown = mean - min;

    if max_drawdown > 0.0 {
        mean / max_drawdown
    } else {
        f64::INFINITY
    }
}

/// Factory function to create risk assessor by name
pub fn create_risk_assessor(name: &str) -> Box<dyn RiskAssessor> {
    match name.to_lowercase().as_str() {
        "standard" | "default" => Box::new(StandardRiskAssessor::new()),
        "conservative" | "pessimistic" => Box::new(ConservativeRiskAssessor::new()),
        _ => Box::new(StandardRiskAssessor::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_distribution(
        mean: f64,
        std_dev: f64,
        min: f64,
        max: f64,
        sample_count: usize,
    ) -> OutcomeDistribution {
        let mut percentiles = HashMap::new();
        // Approximate normal percentiles
        percentiles.insert("p1".to_string(), mean - 2.33 * std_dev);
        percentiles.insert("p5".to_string(), mean - 1.645 * std_dev);
        percentiles.insert("p10".to_string(), mean - 1.28 * std_dev);
        percentiles.insert("p25".to_string(), mean - 0.674 * std_dev);
        percentiles.insert("p50".to_string(), mean);
        percentiles.insert("p75".to_string(), mean + 0.674 * std_dev);
        percentiles.insert("p90".to_string(), mean + 1.28 * std_dev);
        percentiles.insert("p95".to_string(), mean + 1.645 * std_dev);
        percentiles.insert("p99".to_string(), mean + 2.33 * std_dev);

        OutcomeDistribution {
            mean,
            median: mean,
            std_dev,
            variance: std_dev * std_dev,
            skewness: 0.0,
            kurtosis: 0.0,
            min,
            max,
            percentiles,
            sample_count,
        }
    }

    #[test]
    fn test_equal_distributions() {
        let dist = create_test_distribution(100.0, 10.0, 70.0, 130.0, 1000);
        let assessor = StandardRiskAssessor::new();
        let assessment = assessor.assess(&dist, &dist, 0.95);

        // Equal distributions: ~50% probability of loss
        assert!((assessment.probability_of_loss - 0.5).abs() < 0.1);
        // Risk-adjusted score should be ~0
        assert!(assessment.risk_adjusted_score.abs() < 0.1);
    }

    #[test]
    fn test_improved_distribution() {
        let baseline = create_test_distribution(100.0, 10.0, 70.0, 130.0, 1000);
        let experimental = create_test_distribution(110.0, 10.0, 80.0, 140.0, 1000);

        let assessor = StandardRiskAssessor::new();
        let assessment = assessor.assess(&baseline, &experimental, 0.95);

        // Improved distribution: lower probability of loss
        assert!(assessment.probability_of_loss < 0.5);
        // Positive risk-adjusted score
        assert!(assessment.risk_adjusted_score > 0.0);
    }

    #[test]
    fn test_worse_distribution() {
        let baseline = create_test_distribution(100.0, 10.0, 70.0, 130.0, 1000);
        let experimental = create_test_distribution(90.0, 10.0, 60.0, 120.0, 1000);

        let assessor = StandardRiskAssessor::new();
        let assessment = assessor.assess(&baseline, &experimental, 0.95);

        // Worse distribution: higher probability of loss
        assert!(assessment.probability_of_loss > 0.5);
        // Negative risk-adjusted score
        assert!(assessment.risk_adjusted_score < 0.0);
    }

    #[test]
    fn test_var_is_positive() {
        let baseline = create_test_distribution(100.0, 10.0, 70.0, 130.0, 1000);
        let experimental = create_test_distribution(95.0, 15.0, 50.0, 140.0, 1000);

        let assessor = StandardRiskAssessor::new();
        let assessment = assessor.assess(&baseline, &experimental, 0.95);

        // VaR should be non-negative
        assert!(assessment.value_at_risk >= 0.0);
    }

    #[test]
    fn test_conservative_assessor() {
        let baseline = create_test_distribution(100.0, 10.0, 70.0, 130.0, 1000);
        let experimental = create_test_distribution(105.0, 10.0, 75.0, 135.0, 1000);

        let standard = StandardRiskAssessor::new();
        let conservative = ConservativeRiskAssessor::new();

        let std_assessment = standard.assess(&baseline, &experimental, 0.95);
        let cons_assessment = conservative.assess(&baseline, &experimental, 0.95);

        // Conservative should have higher probability of loss
        assert!(cons_assessment.probability_of_loss >= std_assessment.probability_of_loss);
        // Conservative should have lower risk-adjusted score
        assert!(cons_assessment.risk_adjusted_score <= std_assessment.risk_adjusted_score);
    }

    #[test]
    fn test_sortino_ratio() {
        let outcomes = vec![10.0, 15.0, 8.0, 12.0, 5.0, 20.0, 3.0];
        let target = 10.0;
        let sortino = sortino_ratio(&outcomes, target);

        // Mean is ~10.43, there are downside values
        assert!(sortino.is_finite());
    }

    #[test]
    fn test_sortino_no_downside() {
        let outcomes = vec![10.0, 15.0, 20.0, 12.0, 25.0];
        let target = 5.0;
        let sortino = sortino_ratio(&outcomes, target);

        // No values below target, infinite Sortino
        assert!(sortino.is_infinite());
    }

    #[test]
    fn test_calmar_ratio() {
        let outcomes = vec![10.0, 15.0, 8.0, 12.0, 5.0, 20.0];
        let calmar = calmar_ratio(&outcomes);

        // Mean ~11.67, min 5, max_drawdown ~6.67
        assert!(calmar > 0.0);
        assert!(calmar.is_finite());
    }

    #[test]
    fn test_assess_outcomes() {
        let baseline: Vec<f64> = (90..110).map(|x| x as f64).collect();
        let experimental: Vec<f64> = (95..115).map(|x| x as f64).collect();

        let assessment = assess_outcomes(&baseline, &experimental, 0.95);

        // Experimental is slightly better
        assert!(assessment.probability_of_loss < 0.5);
    }

    #[test]
    fn test_factory() {
        let standard = create_risk_assessor("standard");
        assert_eq!(standard.name(), "Standard");

        let conservative = create_risk_assessor("conservative");
        assert_eq!(conservative.name(), "Conservative");
    }
}
