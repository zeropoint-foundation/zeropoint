//! Hypothesis generation from expertise profiles
//!
//! This module provides generators that create testable hypotheses
//! based on accumulated expertise and observed patterns.

use crate::traits::HypothesisGenerator;
use crate::types::{
    EffectDirection, ExpertiseProfile, Hypothesis, HypothesisType, LearningContext,
    PredictedEffect, SensitivityDirection,
};

/// Standard hypothesis generator
#[derive(Debug, Clone, Default)]
pub struct StandardHypothesisGenerator {
    max_hypotheses: usize,
}

impl StandardHypothesisGenerator {
    pub fn new() -> Self {
        Self { max_hypotheses: 10 }
    }

    pub fn with_max_hypotheses(mut self, max: usize) -> Self {
        self.max_hypotheses = max;
        self
    }

    /// Generate performance improvement hypotheses
    fn generate_performance_hypotheses(&self, profile: &ExpertiseProfile) -> Vec<Hypothesis> {
        let mut hypotheses = Vec::new();

        // If success rate is moderate, hypothesize improvement
        if profile.overall_success_rate > 0.5 && profile.overall_success_rate < 0.9 {
            hypotheses.push(
                Hypothesis::new(
                    HypothesisType::Performance,
                    format!(
                        "Optimizing input parameters could improve {} success rate from {:.1}% to {:.1}%",
                        profile.target_name,
                        profile.overall_success_rate * 100.0,
                        (profile.overall_success_rate * 1.15).min(0.95) * 100.0
                    ),
                    PredictedEffect {
                        metric: "success_rate".to_string(),
                        direction: EffectDirection::Increase,
                        magnitude: 15.0,
                        magnitude_ci: (5.0, 25.0),
                    },
                    0.6,
                )
                .with_evidence(format!(
                    "Current success rate is {:.1}% based on {} observations",
                    profile.overall_success_rate * 100.0,
                    profile.observation_count
                )),
            );
        }

        hypotheses
    }

    /// Generate quality improvement hypotheses
    fn generate_quality_hypotheses(&self, profile: &ExpertiseProfile) -> Vec<Hypothesis> {
        let mut hypotheses = Vec::new();

        // If quality is moderate, hypothesize improvement
        if profile.overall_quality > 0.5 && profile.overall_quality < 0.85 {
            let improvement = (0.9 - profile.overall_quality) * 100.0;
            hypotheses.push(
                Hypothesis::new(
                    HypothesisType::Quality,
                    format!(
                        "Refining prompts/parameters could improve {} output quality by {:.0}%",
                        profile.target_name, improvement
                    ),
                    PredictedEffect {
                        metric: "quality".to_string(),
                        direction: EffectDirection::Increase,
                        magnitude: improvement,
                        magnitude_ci: (improvement * 0.5, improvement * 1.5),
                    },
                    0.5,
                )
                .with_evidence(format!(
                    "Current quality score is {:.2} ({} observations)",
                    profile.overall_quality, profile.observation_count
                )),
            );
        }

        hypotheses
    }

    /// Generate task affinity hypotheses
    fn generate_affinity_hypotheses(&self, profile: &ExpertiseProfile) -> Vec<Hypothesis> {
        let mut hypotheses = Vec::new();

        // Find best and worst task affinities
        let affinities: Vec<_> = profile.task_affinities.values().collect();
        if affinities.len() >= 2 {
            let best = affinities.iter().max_by(|a, b| {
                a.affinity_score
                    .partial_cmp(&b.affinity_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            let worst = affinities.iter().min_by(|a, b| {
                a.affinity_score
                    .partial_cmp(&b.affinity_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

            if let (Some(best), Some(worst)) = (best, worst) {
                if best.affinity_score - worst.affinity_score > 0.2 {
                    hypotheses.push(
                        Hypothesis::new(
                            HypothesisType::TaskAffinity,
                            format!(
                                "{} performs significantly better on '{}' tasks ({:.0}%) compared to '{}' tasks ({:.0}%)",
                                profile.target_name,
                                best.task_category,
                                best.affinity_score * 100.0,
                                worst.task_category,
                                worst.affinity_score * 100.0
                            ),
                            PredictedEffect {
                                metric: "task_performance_gap".to_string(),
                                direction: EffectDirection::Increase,
                                magnitude: (best.affinity_score - worst.affinity_score) * 100.0,
                                magnitude_ci: (10.0, 50.0),
                            },
                            0.7,
                        )
                        .with_evidence(format!(
                            "Based on {} '{}' observations and {} '{}' observations",
                            best.observation_count,
                            best.task_category,
                            worst.observation_count,
                            worst.task_category
                        ))
                        .with_test_procedure(
                            "Run A/B test comparing performance on both task types"
                        ),
                    );
                }
            }
        }

        hypotheses
    }

    /// Generate parameter optimization hypotheses
    fn generate_parameter_hypotheses(&self, profile: &ExpertiseProfile) -> Vec<Hypothesis> {
        let mut hypotheses = Vec::new();

        for sensitivity in &profile.parameter_sensitivities {
            if sensitivity.confidence > 0.5 && sensitivity.sensitivity > 0.3 {
                let direction_text = match sensitivity.direction {
                    SensitivityDirection::Positive => "increasing",
                    SensitivityDirection::Negative => "decreasing",
                    _ => continue,
                };

                hypotheses.push(
                    Hypothesis::new(
                        HypothesisType::ParameterOptimization,
                        format!(
                            "{} '{}' parameter could improve {} performance (sensitivity: {:.2})",
                            direction_text,
                            sensitivity.parameter,
                            profile.target_name,
                            sensitivity.sensitivity
                        ),
                        PredictedEffect {
                            metric: "performance".to_string(),
                            direction: if matches!(
                                sensitivity.direction,
                                SensitivityDirection::Positive
                            ) {
                                EffectDirection::Increase
                            } else {
                                EffectDirection::Decrease
                            },
                            magnitude: sensitivity.sensitivity * 20.0,
                            magnitude_ci: (5.0, sensitivity.sensitivity * 40.0),
                        },
                        sensitivity.confidence,
                    )
                    .with_evidence(format!(
                        "Parameter sensitivity analysis shows {:.2} correlation",
                        sensitivity.sensitivity
                    ))
                    .with_test_procedure(format!(
                        "Test with {} set to extreme values",
                        sensitivity.parameter
                    )),
                );
            }
        }

        hypotheses
    }
}

impl HypothesisGenerator for StandardHypothesisGenerator {
    fn generate(&self, profile: &ExpertiseProfile, context: &LearningContext) -> Vec<Hypothesis> {
        if !context.generate_hypotheses {
            return Vec::new();
        }

        let mut all_hypotheses = Vec::new();

        // Generate different types of hypotheses
        all_hypotheses.extend(self.generate_performance_hypotheses(profile));
        all_hypotheses.extend(self.generate_quality_hypotheses(profile));
        all_hypotheses.extend(self.generate_affinity_hypotheses(profile));
        all_hypotheses.extend(self.generate_parameter_hypotheses(profile));

        // Filter by focus categories if specified
        if !context.focus_categories.is_empty() {
            // Keep hypotheses that are relevant to focus categories
            // For now, keep all hypotheses as they may be relevant
        }

        // Sort by confidence and limit
        all_hypotheses.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        all_hypotheses.truncate(self.max_hypotheses);
        all_hypotheses
    }

    fn name(&self) -> &'static str {
        "Standard"
    }
}

/// Conservative hypothesis generator (higher confidence thresholds)
#[derive(Debug, Clone, Default)]
pub struct ConservativeHypothesisGenerator {
    inner: StandardHypothesisGenerator,
    min_confidence: f64,
}

impl ConservativeHypothesisGenerator {
    pub fn new() -> Self {
        Self {
            inner: StandardHypothesisGenerator::new(),
            min_confidence: 0.7,
        }
    }

    pub fn with_min_confidence(mut self, confidence: f64) -> Self {
        self.min_confidence = confidence.clamp(0.0, 1.0);
        self
    }
}

impl HypothesisGenerator for ConservativeHypothesisGenerator {
    fn generate(&self, profile: &ExpertiseProfile, context: &LearningContext) -> Vec<Hypothesis> {
        let hypotheses = self.inner.generate(profile, context);

        // Filter by minimum confidence
        hypotheses
            .into_iter()
            .filter(|h| h.confidence >= self.min_confidence)
            .collect()
    }

    fn name(&self) -> &'static str {
        "Conservative"
    }
}

/// Factory function to create hypothesis generator by name
pub fn create_hypothesis_generator(name: &str) -> Box<dyn HypothesisGenerator> {
    match name.to_lowercase().as_str() {
        "standard" | "default" => Box::new(StandardHypothesisGenerator::new()),
        "conservative" | "cautious" => Box::new(ConservativeHypothesisGenerator::new()),
        _ => Box::new(StandardHypothesisGenerator::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TaskAffinity;

    fn create_test_profile() -> ExpertiseProfile {
        let mut profile = ExpertiseProfile::new("test_tool", "Test Tool");
        profile.overall_success_rate = 0.75;
        profile.overall_quality = 0.7;
        profile.observation_count = 100;
        profile.profile_confidence = 0.8;

        // Add task affinities
        profile.task_affinities.insert(
            "code_generation".to_string(),
            TaskAffinity {
                task_category: "code_generation".to_string(),
                affinity_score: 0.9,
                success_rate: 0.85,
                average_quality: 0.9,
                observation_count: 50,
                confidence: 0.8,
            },
        );
        profile.task_affinities.insert(
            "analysis".to_string(),
            TaskAffinity {
                task_category: "analysis".to_string(),
                affinity_score: 0.6,
                success_rate: 0.55,
                average_quality: 0.65,
                observation_count: 30,
                confidence: 0.7,
            },
        );

        profile
    }

    #[test]
    fn test_standard_generator() {
        let profile = create_test_profile();
        let context = LearningContext::new();
        let generator = StandardHypothesisGenerator::new();

        let hypotheses = generator.generate(&profile, &context);

        // Should generate some hypotheses
        assert!(!hypotheses.is_empty());

        // All hypotheses should have confidence > 0
        for h in &hypotheses {
            assert!(h.confidence > 0.0);
        }
    }

    #[test]
    fn test_hypothesis_generation_disabled() {
        let profile = create_test_profile();
        let context = LearningContext::new().with_hypothesis_generation(false);
        let generator = StandardHypothesisGenerator::new();

        let hypotheses = generator.generate(&profile, &context);
        assert!(hypotheses.is_empty());
    }

    #[test]
    fn test_conservative_generator() {
        let profile = create_test_profile();
        let context = LearningContext::new();

        let standard = StandardHypothesisGenerator::new();
        let conservative = ConservativeHypothesisGenerator::new().with_min_confidence(0.65);

        let standard_hypotheses = standard.generate(&profile, &context);
        let conservative_hypotheses = conservative.generate(&profile, &context);

        // Conservative should have fewer or equal hypotheses
        assert!(conservative_hypotheses.len() <= standard_hypotheses.len());

        // All conservative hypotheses should meet threshold
        for h in &conservative_hypotheses {
            assert!(h.confidence >= 0.65);
        }
    }

    #[test]
    fn test_max_hypotheses_limit() {
        let profile = create_test_profile();
        let context = LearningContext::new();
        let generator = StandardHypothesisGenerator::new().with_max_hypotheses(3);

        let hypotheses = generator.generate(&profile, &context);
        assert!(hypotheses.len() <= 3);
    }

    #[test]
    fn test_factory() {
        let standard = create_hypothesis_generator("standard");
        assert_eq!(standard.name(), "Standard");

        let conservative = create_hypothesis_generator("conservative");
        assert_eq!(conservative.name(), "Conservative");
    }
}
