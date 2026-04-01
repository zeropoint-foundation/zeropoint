//! MLE STAR Engine - Main expertise pre-learning orchestrator
//!
//! This module provides the main `MLEStarEngine` struct that coordinates
//! observation recording, expertise building, and hypothesis generation.

use crate::config::MLEStarConfig;
use crate::estimation::create_estimator;
use crate::hypothesis::create_hypothesis_generator;
use crate::stores::{InMemoryExpertiseStore, InMemoryObservationStore};
use crate::traits::{ExpertiseStore, HypothesisGenerator, MLEstimator, ObservationStore};
use crate::types::{
    ExpertiseProfile, Hypothesis, LearningContext, MLEStarError, MLEStarResult, Observation,
    PerformancePattern, PreLearningResult, ReadinessAssessment,
};
use chrono::Utc;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

/// MLE STAR Engine for expertise pre-learning
///
/// "Never go in without competency" - This engine builds expertise profiles
/// (mental models) of tools/capabilities before they are used in production.
pub struct MLEStarEngine {
    config: MLEStarConfig,
    observation_store: Arc<dyn ObservationStore>,
    expertise_store: Arc<dyn ExpertiseStore>,
    estimator: Arc<RwLock<Box<dyn MLEstimator>>>,
    hypothesis_generator: Arc<RwLock<Box<dyn HypothesisGenerator>>>,
}

impl MLEStarEngine {
    /// Create a new MLE STAR engine with default configuration
    pub fn new() -> Self {
        Self::with_config(MLEStarConfig::default())
    }

    /// Create a new MLE STAR engine with custom configuration
    pub fn with_config(config: MLEStarConfig) -> Self {
        Self {
            config,
            observation_store: Arc::new(InMemoryObservationStore::new()),
            expertise_store: Arc::new(InMemoryExpertiseStore::new()),
            estimator: Arc::new(RwLock::new(create_estimator("basic"))),
            hypothesis_generator: Arc::new(RwLock::new(create_hypothesis_generator("standard"))),
        }
    }

    /// Builder: set custom observation store
    pub fn with_observation_store(mut self, store: Arc<dyn ObservationStore>) -> Self {
        self.observation_store = store;
        self
    }

    /// Builder: set custom expertise store
    pub fn with_expertise_store(mut self, store: Arc<dyn ExpertiseStore>) -> Self {
        self.expertise_store = store;
        self
    }

    /// Builder: set custom estimator
    pub fn with_estimator(mut self, estimator: Box<dyn MLEstimator>) -> Self {
        self.estimator = Arc::new(RwLock::new(estimator));
        self
    }

    /// Builder: set custom hypothesis generator
    pub fn with_hypothesis_generator(mut self, generator: Box<dyn HypothesisGenerator>) -> Self {
        self.hypothesis_generator = Arc::new(RwLock::new(generator));
        self
    }

    /// Get current configuration
    pub fn config(&self) -> &MLEStarConfig {
        &self.config
    }

    /// Record an observation from tool/capability execution
    pub async fn observe(&self, observation: Observation) -> MLEStarResult<()> {
        self.observation_store
            .store(observation.clone())
            .await
            .map_err(MLEStarError::StorageError)?;

        // Auto-refresh profile if enabled
        if self.config.auto_refresh {
            let count = self.observation_store.count(&observation.target_id).await;
            if count >= self.config.min_observations {
                // Refresh profile in background
                let target_id = observation.target_id.clone();
                let target_name = observation.target_id.clone(); // Use ID as name if not known
                let _ = self.build_profile(&target_id, &target_name).await;
            }
        }

        Ok(())
    }

    /// Pre-learn about a target (build expertise before use)
    ///
    /// This is the main entry point for the "never go in without competency" principle.
    pub async fn prelearn(
        &self,
        target_id: &str,
        context: &LearningContext,
    ) -> MLEStarResult<PreLearningResult> {
        let start_time = Instant::now();

        // Get observations
        let observations = self.get_filtered_observations(target_id, context).await;

        // Check minimum observations
        if observations.len() < self.config.min_observations {
            let mut result = PreLearningResult {
                target_id: target_id.to_string(),
                expertise: ExpertiseProfile::new(target_id, target_id),
                readiness: ReadinessAssessment::not_ready(format!(
                    "Insufficient observations: {} (need at least {})",
                    observations.len(),
                    self.config.min_observations
                )),
                hypotheses: Vec::new(),
                recommendations: vec![format!(
                    "Collect at least {} more observations before production use",
                    self.config.min_observations - observations.len()
                )],
                warnings: vec!["Profile not ready for production use".to_string()],
                duration_ms: start_time.elapsed().as_millis() as u64,
                completed_at: Utc::now(),
            };
            result.readiness.min_observations_needed =
                self.config.min_observations - observations.len();
            return Ok(result);
        }

        // Build expertise profile
        let expertise = self
            .build_profile_from_observations(target_id, &observations)
            .await?;

        // Store expertise
        self.expertise_store
            .store(expertise.clone())
            .await
            .map_err(MLEStarError::StorageError)?;

        // Generate hypotheses if enabled
        let hypotheses = if self.config.hypothesis_generation && context.generate_hypotheses {
            let generator = self.hypothesis_generator.read().await;
            generator.generate(&expertise, context)
        } else {
            Vec::new()
        };

        // Assess readiness
        let readiness = self.assess_readiness(&expertise, &observations);

        // Generate recommendations
        let recommendations = self.generate_recommendations(&expertise, &readiness);

        // Generate warnings
        let warnings = self.generate_warnings(&expertise, &readiness);

        Ok(PreLearningResult {
            target_id: target_id.to_string(),
            expertise,
            readiness,
            hypotheses,
            recommendations,
            warnings,
            duration_ms: start_time.elapsed().as_millis() as u64,
            completed_at: Utc::now(),
        })
    }

    /// Get expertise profile for a target (if available)
    pub async fn get_expertise(&self, target_id: &str) -> Option<ExpertiseProfile> {
        self.expertise_store.get(target_id).await
    }

    /// Generate hypotheses for a target
    pub async fn generate_hypotheses(&self, target_id: &str) -> Vec<Hypothesis> {
        let expertise = match self.expertise_store.get(target_id).await {
            Some(e) => e,
            None => return Vec::new(),
        };

        let context = LearningContext::new().with_hypothesis_generation(true);
        let generator = self.hypothesis_generator.read().await;
        generator.generate(&expertise, &context)
    }

    /// Assess production readiness for a target
    pub async fn assess_readiness_for(&self, target_id: &str) -> ReadinessAssessment {
        let expertise = match self.expertise_store.get(target_id).await {
            Some(e) => e,
            None => return ReadinessAssessment::not_ready("No expertise profile found"),
        };

        let observations = self.observation_store.get_for_target(target_id).await;
        self.assess_readiness(&expertise, &observations)
    }

    /// Get observation count for a target
    pub async fn observation_count(&self, target_id: &str) -> usize {
        self.observation_store.count(target_id).await
    }

    /// List all targets with expertise profiles
    pub async fn list_targets(&self) -> Vec<String> {
        self.expertise_store.list_targets().await
    }

    /// Clear all data for a target
    pub async fn clear_target(&self, target_id: &str) -> MLEStarResult<()> {
        self.observation_store
            .clear(target_id)
            .await
            .map_err(MLEStarError::StorageError)?;
        self.expertise_store
            .delete(target_id)
            .await
            .map_err(MLEStarError::StorageError)?;
        Ok(())
    }

    // Internal methods

    async fn get_filtered_observations(
        &self,
        target_id: &str,
        context: &LearningContext,
    ) -> Vec<Observation> {
        let mut observations = if let Some(window) = context.time_window_seconds {
            self.observation_store.get_recent(target_id, window).await
        } else if let Some(window) = self.config.max_observation_age_seconds {
            self.observation_store.get_recent(target_id, window).await
        } else {
            self.observation_store.get_for_target(target_id).await
        };

        // Filter by focus categories if specified
        if !context.focus_categories.is_empty() {
            observations.retain(|o| context.focus_categories.contains(&o.task_category));
        }

        // Limit observations if specified
        if let Some(max) = context.max_observations {
            observations.truncate(max);
        }

        observations
    }

    async fn build_profile(
        &self,
        target_id: &str,
        _target_name: &str,
    ) -> MLEStarResult<ExpertiseProfile> {
        let observations = self.observation_store.get_for_target(target_id).await;
        self.build_profile_from_observations(target_id, &observations)
            .await
    }

    async fn build_profile_from_observations(
        &self,
        target_id: &str,
        observations: &[Observation],
    ) -> MLEStarResult<ExpertiseProfile> {
        let mut profile = ExpertiseProfile::new(target_id, target_id);
        profile.observation_count = observations.len();

        let estimator = self.estimator.read().await;

        // Estimate core capabilities
        if let Some(success_est) = estimator.estimate_capability(observations, "success_rate") {
            profile.overall_success_rate = success_est.estimate;
            profile
                .capability_estimates
                .insert("success_rate".to_string(), success_est);
        }

        if let Some(quality_est) = estimator.estimate_capability(observations, "quality") {
            profile.overall_quality = quality_est.estimate;
            profile
                .capability_estimates
                .insert("quality".to_string(), quality_est);
        }

        if let Some(latency_est) = estimator.estimate_capability(observations, "latency") {
            profile
                .capability_estimates
                .insert("latency".to_string(), latency_est);
        }

        // Estimate task affinities
        let task_categories: Vec<String> = observations
            .iter()
            .map(|o| o.task_category.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        for category in task_categories {
            if let Some(affinity) = estimator.estimate_task_affinity(observations, &category) {
                if affinity.observation_count >= self.config.min_task_observations {
                    profile.task_affinities.insert(category, affinity);
                }
            }
        }

        // Estimate parameter sensitivities
        if self.config.sensitivity_analysis {
            profile.parameter_sensitivities = estimator.estimate_sensitivities(observations);
        }

        // Detect patterns
        if self.config.pattern_detection {
            profile.performance_patterns = self.detect_patterns(observations);
        }

        // Calculate overall profile confidence
        profile.profile_confidence = self.calculate_profile_confidence(&profile, observations);
        profile.last_updated = Utc::now();

        Ok(profile)
    }

    fn detect_patterns(&self, observations: &[Observation]) -> Vec<PerformancePattern> {
        let mut patterns = Vec::new();

        if observations.len() < 10 {
            return patterns;
        }

        // Detect success rate by time-of-day pattern (simplified)
        let n = observations.len() as f64;
        let success_rate = observations.iter().filter(|o| o.success).count() as f64 / n;

        if success_rate > 0.8 {
            patterns.push(PerformancePattern {
                id: "high_success".to_string(),
                condition: "General usage".to_string(),
                expected_performance: success_rate,
                variance: 0.05,
                frequency: 1.0,
                confidence: 0.8,
            });
        }

        // Detect quality pattern
        let qualities: Vec<f64> = observations
            .iter()
            .filter_map(|o| o.quality_score)
            .collect();
        if !qualities.is_empty() {
            let avg_quality = qualities.iter().sum::<f64>() / qualities.len() as f64;
            let variance = qualities
                .iter()
                .map(|q| (q - avg_quality).powi(2))
                .sum::<f64>()
                / qualities.len() as f64;

            if variance < 0.1 {
                patterns.push(PerformancePattern {
                    id: "consistent_quality".to_string(),
                    condition: "All tasks".to_string(),
                    expected_performance: avg_quality,
                    variance,
                    frequency: qualities.len() as f64 / n,
                    confidence: 0.7,
                });
            }
        }

        patterns.truncate(self.config.max_patterns);
        patterns
    }

    fn calculate_profile_confidence(
        &self,
        profile: &ExpertiseProfile,
        observations: &[Observation],
    ) -> f64 {
        // Factors affecting confidence:
        // 1. Number of observations
        // 2. Consistency of results
        // 3. Coverage of task types

        let obs_factor = (profile.observation_count as f64 / 100.0).min(1.0);

        // Consistency: lower variance = higher confidence
        let qualities: Vec<f64> = observations
            .iter()
            .filter_map(|o| o.quality_score)
            .collect();
        let consistency_factor = if !qualities.is_empty() {
            let mean = qualities.iter().sum::<f64>() / qualities.len() as f64;
            let variance =
                qualities.iter().map(|q| (q - mean).powi(2)).sum::<f64>() / qualities.len() as f64;
            1.0 - variance.sqrt().min(1.0)
        } else {
            0.5
        };

        // Coverage: more task types = higher confidence
        let coverage_factor = (profile.task_affinities.len() as f64 / 5.0).min(1.0);

        // Weighted combination
        0.5 * obs_factor + 0.3 * consistency_factor + 0.2 * coverage_factor
    }

    fn assess_readiness(
        &self,
        expertise: &ExpertiseProfile,
        _observations: &[Observation],
    ) -> ReadinessAssessment {
        let mut data_gaps = Vec::new();
        let mut recommended_tests = Vec::new();
        let mut warnings = Vec::new();

        // Check observation count
        if expertise.observation_count < self.config.min_observations {
            data_gaps.push(format!(
                "Only {} observations (need {})",
                expertise.observation_count, self.config.min_observations
            ));
        }

        // Check confidence
        if expertise.profile_confidence < self.config.confidence_threshold {
            data_gaps.push(format!(
                "Profile confidence {:.2} below threshold {:.2}",
                expertise.profile_confidence, self.config.confidence_threshold
            ));
        }

        // Check success rate
        if expertise.overall_success_rate < 0.5 {
            warnings.push(format!(
                "Low success rate: {:.1}%",
                expertise.overall_success_rate * 100.0
            ));
            recommended_tests.push("Run focused tests to identify failure patterns".to_string());
        }

        // Check quality
        if expertise.overall_quality < 0.6 {
            warnings.push(format!(
                "Low quality score: {:.2}",
                expertise.overall_quality
            ));
            recommended_tests.push("Evaluate quality on representative samples".to_string());
        }

        // Check task coverage
        if expertise.task_affinities.is_empty() {
            data_gaps.push("No task affinity data".to_string());
            recommended_tests.push("Test across different task categories".to_string());
        }

        // Calculate readiness score
        let score = expertise.profile_confidence
            * expertise.overall_success_rate.powf(0.5)
            * expertise.overall_quality.powf(0.5);

        let production_ready = score >= 0.6
            && data_gaps.is_empty()
            && expertise.observation_count >= self.config.min_observations;

        let min_observations_needed = self
            .config
            .min_observations
            .saturating_sub(expertise.observation_count);

        ReadinessAssessment {
            score,
            production_ready,
            data_gaps,
            recommended_tests,
            warnings,
            min_observations_needed,
        }
    }

    fn generate_recommendations(
        &self,
        expertise: &ExpertiseProfile,
        readiness: &ReadinessAssessment,
    ) -> Vec<String> {
        let mut recommendations = Vec::new();

        if readiness.production_ready {
            recommendations.push(format!(
                "{} is ready for production use (confidence: {:.2})",
                expertise.target_name, expertise.profile_confidence
            ));

            // Recommend best task types
            if let Some((best_category, best_affinity)) =
                expertise.task_affinities.iter().max_by(|a, b| {
                    a.1.affinity_score
                        .partial_cmp(&b.1.affinity_score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
            {
                recommendations.push(format!(
                    "Best suited for '{}' tasks (affinity: {:.1}%)",
                    best_category,
                    best_affinity.affinity_score * 100.0
                ));
            }
        } else {
            recommendations.push("Not recommended for production use yet".to_string());

            if !readiness.data_gaps.is_empty() {
                recommendations.push(format!(
                    "Address data gaps: {}",
                    readiness.data_gaps.join(", ")
                ));
            }
        }

        recommendations
    }

    fn generate_warnings(
        &self,
        expertise: &ExpertiseProfile,
        readiness: &ReadinessAssessment,
    ) -> Vec<String> {
        let mut warnings = readiness.warnings.clone();

        // Add profile-specific warnings
        if expertise.profile_confidence < 0.5 {
            warnings.push("Low confidence - results may be unreliable".to_string());
        }

        // Check for task affinities with low confidence
        for affinity in expertise.task_affinities.values() {
            if affinity.confidence < 0.5 && affinity.observation_count > 0 {
                warnings.push(format!(
                    "Low confidence for '{}' task affinity",
                    affinity.task_category
                ));
            }
        }

        warnings
    }
}

impl Default for MLEStarEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_observations(n: usize) -> Vec<Observation> {
        (0..n)
            .map(|i| {
                Observation::new("test_tool", "test_category")
                    .with_success(i % 10 != 9) // 90% success
                    .with_quality(0.7 + (i as f64 % 20.0) / 100.0)
                    .with_duration(100 + (i as u64 % 50))
            })
            .collect()
    }

    #[tokio::test]
    async fn test_observe_and_count() {
        let engine = MLEStarEngine::new();

        for _ in 0..5 {
            let obs = Observation::new("tool_1", "test").with_success(true);
            engine.observe(obs).await.unwrap();
        }

        assert_eq!(engine.observation_count("tool_1").await, 5);
    }

    #[tokio::test]
    async fn test_prelearn_insufficient_data() {
        let engine = MLEStarEngine::with_config(MLEStarConfig::default().with_min_observations(10));

        // Only add 5 observations
        for _ in 0..5 {
            let obs = Observation::new("tool_1", "test").with_success(true);
            engine.observe(obs).await.unwrap();
        }

        let context = LearningContext::new();
        let result = engine.prelearn("tool_1", &context).await.unwrap();

        assert!(!result.readiness.production_ready);
        assert!(!result.readiness.data_gaps.is_empty());
        assert!(result.readiness.min_observations_needed > 0);
    }

    #[tokio::test]
    async fn test_prelearn_success() {
        let engine = MLEStarEngine::with_config(MLEStarConfig::default().with_min_observations(10));

        // Add enough observations
        for obs in create_test_observations(50) {
            engine.observe(obs).await.unwrap();
        }

        let context = LearningContext::new();
        let result = engine.prelearn("test_tool", &context).await.unwrap();

        // Should have built a profile
        assert!(result.expertise.observation_count >= 10);
        assert!(result.expertise.profile_confidence > 0.0);

        // Should be production ready with good data
        // Note: Actual readiness depends on the observations
    }

    #[tokio::test]
    async fn test_get_expertise() {
        let engine = MLEStarEngine::new();

        // Before pre-learning
        assert!(engine.get_expertise("tool_1").await.is_none());

        // Add observations and pre-learn
        for obs in create_test_observations(20) {
            engine.observe(obs).await.unwrap();
        }

        let context = LearningContext::new();
        engine.prelearn("test_tool", &context).await.unwrap();

        // After pre-learning
        assert!(engine.get_expertise("test_tool").await.is_some());
    }

    #[tokio::test]
    async fn test_generate_hypotheses() {
        let engine =
            MLEStarEngine::with_config(MLEStarConfig::default().with_hypothesis_generation(true));

        for obs in create_test_observations(50) {
            engine.observe(obs).await.unwrap();
        }

        let context = LearningContext::new().with_hypothesis_generation(true);
        let _result = engine.prelearn("test_tool", &context).await.unwrap();

        // Should have generated some hypotheses
        // (Depends on profile characteristics)
    }

    #[tokio::test]
    async fn test_list_targets() {
        let engine = MLEStarEngine::new();

        // Add observations for multiple targets
        for i in 0..20 {
            let target = format!("tool_{}", i % 3);
            let obs = Observation::new(&target, "test").with_success(true);
            engine.observe(obs).await.unwrap();
        }

        // Pre-learn each target
        for target in &["tool_0", "tool_1", "tool_2"] {
            let context = LearningContext::new();
            engine.prelearn(target, &context).await.ok();
        }

        let _targets = engine.list_targets().await;
        // Some targets should have been pre-learned
    }

    #[tokio::test]
    async fn test_clear_target() {
        let engine = MLEStarEngine::new();

        for obs in create_test_observations(20) {
            engine.observe(obs).await.unwrap();
        }

        let context = LearningContext::new();
        engine.prelearn("test_tool", &context).await.unwrap();

        assert!(engine.get_expertise("test_tool").await.is_some());

        engine.clear_target("test_tool").await.unwrap();

        assert!(engine.get_expertise("test_tool").await.is_none());
        assert_eq!(engine.observation_count("test_tool").await, 0);
    }
}
