//! # MLE STAR Engine
//!
//! An expertise pre-learning engine inspired by MLE STAR methodology for ZeroPoint.
//!
//! This crate implements the principle of "never go in without competency" by building
//! expertise profiles (mental models) of tools/capabilities before they are used in production.
//!
//! ## Features
//!
//! - **Observation Recording**: Track tool/capability executions with success, quality, and performance metrics
//! - **Expertise Building**: Build statistical profiles from accumulated observations using MLE
//! - **Task Affinity**: Understand which tasks a tool is best suited for
//! - **Hypothesis Generation**: Generate testable hypotheses from expertise
//! - **Readiness Assessment**: Determine if a tool is ready for production use
//! - **Pattern Detection**: Identify performance patterns from historical data
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use mle_star_engine::{MLEStarEngine, MLEStarConfig, Observation, LearningContext};
//!
//! #[tokio::main]
//! async fn main() {
//!     // Create engine
//!     let engine = MLEStarEngine::with_config(
//!         MLEStarConfig::default()
//!             .with_min_observations(10)
//!             .with_confidence_threshold(0.7)
//!     );
//!
//!     // Record observations from tool usage
//!     for _ in 0..20 {
//!         let obs = Observation::new("my_tool", "code_generation")
//!             .with_success(true)
//!             .with_quality(0.85)
//!             .with_duration(150);
//!         engine.observe(obs).await.unwrap();
//!     }
//!
//!     // Pre-learn before production use
//!     let context = LearningContext::new();
//!     let result = engine.prelearn("my_tool", &context).await.unwrap();
//!
//!     if result.readiness.production_ready {
//!         println!("Tool is ready for production!");
//!         println!("Confidence: {:.2}", result.expertise.profile_confidence);
//!         println!("Success rate: {:.1}%", result.expertise.overall_success_rate * 100.0);
//!     } else {
//!         println!("Not ready: {:?}", result.readiness.data_gaps);
//!     }
//!
//!     // Review generated hypotheses
//!     for hypothesis in &result.hypotheses {
//!         println!("Hypothesis: {}", hypothesis.statement);
//!         println!("  Confidence: {:.2}", hypothesis.confidence);
//!     }
//! }
//! ```
//!
//! ## Recording Observations
//!
//! ```rust,no_run
//! use mle_star_engine::{MLEStarEngine, Observation};
//!
//! #[tokio::main]
//! async fn main() {
//!     let engine = MLEStarEngine::new();
//!
//!     // Record a successful tool execution
//!     let obs = Observation::new("code_generator", "code_generation")
//!         .with_success(true)
//!         .with_quality(0.9)
//!         .with_duration(250)
//!         .with_input_feature("complexity", 0.7)
//!         .with_output_metric("tokens", 500.0);
//!
//!     engine.observe(obs).await.unwrap();
//!
//!     // Record a failed execution
//!     let obs = Observation::new("code_generator", "code_generation")
//!         .with_success(false)
//!         .with_quality(0.2)
//!         .with_duration(100)
//!         .with_input_feature("complexity", 0.95);
//!
//!     engine.observe(obs).await.unwrap();
//! }
//! ```
//!
//! ## Extensibility
//!
//! The engine uses trait-based extensibility for:
//! - Custom MLE estimators (Basic, Bayesian)
//! - Custom hypothesis generators
//! - Custom observation stores
//! - Custom expertise stores

pub mod config;
pub mod engine;
pub mod estimation;
pub mod hypothesis;
pub mod stores;
pub mod traits;
pub mod types;

// Re-export main types at crate root
pub use config::MLEStarConfig;
pub use engine::MLEStarEngine;
pub use types::{
    CapabilityEstimate, EffectDirection, ExpertiseProfile, Hypothesis, HypothesisType,
    LearningContext, MLEStarError, MLEStarResult, Observation, ParameterSensitivity,
    PerformancePattern, PreLearningResult, PredictedEffect, ReadinessAssessment,
    SensitivityDirection, TaskAffinity,
};

// Re-export traits
pub use traits::{
    ConfidenceCalculator, ExpertiseStore, HypothesisGenerator, MLEstimator, ObservationStore,
    PatternDetector,
};

// Re-export factories
pub use estimation::create_estimator;
pub use hypothesis::create_hypothesis_generator;

// Re-export concrete implementations
pub use estimation::{BasicEstimator, BayesianEstimator};
pub use hypothesis::{ConservativeHypothesisGenerator, StandardHypothesisGenerator};
pub use stores::{CombinedStore, InMemoryExpertiseStore, InMemoryObservationStore};
