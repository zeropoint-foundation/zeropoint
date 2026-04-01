//! # Monte Carlo Engine
//!
//! An extensible Monte Carlo simulation engine for ZeroPoint.
//!
//! This crate provides a flexible framework for running probabilistic simulations,
//! comparing distributions, assessing risk, and testing statistical significance.
//!
//! ## Features
//!
//! - **Pluggable Sampling Strategies**: Random, Latin Hypercube, Sobol (quasi-Monte Carlo)
//! - **Distribution Estimation**: Empirical, Kernel Density, Robust (MAD-based)
//! - **Risk Assessment**: VaR, CVaR, Maximum Drawdown, Risk-adjusted scores
//! - **Significance Testing**: Welch's t-test, Mann-Whitney U, Permutation tests
//! - **Confidence Intervals**: Standard (t-distribution), Bootstrap
//! - **Convergence Monitoring**: Early stopping when estimates stabilize
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use monte_carlo_engine::{MonteCarloEngine, MonteCarloConfig, ParameterBounds};
//!
//! #[tokio::main]
//! async fn main() {
//!     // Create engine with custom configuration
//!     let engine = MonteCarloEngine::with_config(
//!         MonteCarloConfig::default()
//!             .with_num_simulations(10000)
//!             .with_confidence_level(0.95)
//!     );
//!
//!     // Define parameter space
//!     let bounds = vec![
//!         ParameterBounds::new("price", 80.0, 120.0),
//!         ParameterBounds::new("quantity", 100.0, 500.0),
//!     ];
//!
//!     // Run simulation
//!     let results = engine.simulate(&bounds, |params| {
//!         let price = params.get("price").unwrap_or(100.0);
//!         let quantity = params.get("quantity").unwrap_or(200.0);
//!         price * quantity  // Revenue
//!     }).await.unwrap();
//!
//!     println!("Mean revenue: {:.2}", results.experimental_distribution.mean);
//!     println!("95% CI: ({:.2}, {:.2})",
//!         results.confidence_intervals.mean_ci.0,
//!         results.confidence_intervals.mean_ci.1
//!     );
//! }
//! ```
//!
//! ## Comparing Distributions (A/B Testing)
//!
//! ```rust,no_run
//! use monte_carlo_engine::MonteCarloEngine;
//!
//! #[tokio::main]
//! async fn main() {
//!     let engine = MonteCarloEngine::new();
//!
//!     let baseline: Vec<f64> = vec![100.0, 105.0, 98.0, 102.0, 99.0];
//!     let experimental: Vec<f64> = vec![110.0, 112.0, 108.0, 115.0, 109.0];
//!
//!     let results = engine.compare(&baseline, &experimental).await.unwrap();
//!
//!     if let Some(sig) = &results.significance {
//!         println!("p-value: {:.4}", sig.p_value);
//!         println!("Effect size (Cohen's d): {:.2}", sig.effect_size);
//!         println!("Significant at 0.05: {}", sig.is_significant_at_05);
//!     }
//!
//!     if let Some(risk) = &results.risk_assessment {
//!         println!("Probability of loss: {:.2}%", risk.probability_of_loss * 100.0);
//!         println!("Value at Risk (95%): {:.2}", risk.value_at_risk);
//!     }
//! }
//! ```
//!
//! ## Extensibility
//!
//! The engine uses trait-based extensibility. You can provide custom implementations:
//!
//! ```rust,no_run
//! use monte_carlo_engine::{
//!     MonteCarloEngine,
//!     traits::{SamplingStrategy, DistributionEstimator},
//!     types::{ParameterBounds, SampledParameters, OutcomeDistribution},
//! };
//!
//! // Custom sampler
//! #[derive(Debug)]
//! struct MySampler;
//!
//! impl SamplingStrategy for MySampler {
//!     fn sample(&self, n_samples: usize, bounds: &[ParameterBounds]) -> Vec<SampledParameters> {
//!         // Custom sampling logic
//!         vec![]
//!     }
//!
//!     fn name(&self) -> &'static str {
//!         "My Custom Sampler"
//!     }
//! }
//!
//! let engine = MonteCarloEngine::new()
//!     .with_sampler(Box::new(MySampler));
//! ```

pub mod confidence;
pub mod config;
pub mod distribution;
pub mod engine;
pub mod risk;
pub mod sampling;
pub mod significance;
pub mod traits;
pub mod types;

// Re-export main types at crate root for convenience
pub use config::MonteCarloConfig;
pub use engine::MonteCarloEngine;
pub use types::{
    ConfidenceIntervals, ConvergenceInfo, DistributionHint, EffectSizeInterpretation,
    MonteCarloError, MonteCarloResult, OutcomeDistribution, ParameterBounds, RiskAssessment,
    SampledParameters, SignificanceResult, SimulationResults, SimulationRun,
};

// Re-export trait module
pub use traits::{
    ConfidenceIntervalCalculator, DistributionEstimator, RiskAssessor, SamplingStrategy,
    SignificanceCalculator,
};

// Re-export factory functions
pub use confidence::create_ci_calculator;
pub use distribution::create_estimator;
pub use risk::create_risk_assessor;
pub use sampling::create_sampler;
pub use significance::create_significance_calculator;

// Re-export specific implementations for direct use
pub use confidence::{BootstrapCICalculator, StandardCICalculator};
pub use distribution::{EmpiricalEstimator, KernelDensityEstimator, RobustEstimator};
pub use risk::{ConservativeRiskAssessor, StandardRiskAssessor};
pub use sampling::{LatinHypercubeSampler, RandomSampler, SobolSampler};
pub use significance::{MannWhitneyU, PermutationTest, WelchTTest};
