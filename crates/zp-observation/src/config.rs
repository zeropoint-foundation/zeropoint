//! Configuration for the observational memory system.

use serde::{Deserialize, Serialize};

/// Configuration for observation and reflection thresholds.
///
/// These values control when the Observer and Reflector agents activate.
/// Defaults are calibrated to match Mastra's proven settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservationConfig {
    /// Token threshold that triggers the Observer agent.
    /// When the conversation's estimated token count reaches this level,
    /// the Observer compresses unprocessed receipts into observations.
    ///
    /// Mastra default: 30,000
    pub observation_threshold: usize,

    /// Buffer fraction: Observer activates at
    /// `(1 - buffer_fraction) * observation_threshold`.
    /// This gives the Observer room to work before the hard limit.
    ///
    /// Mastra default: 0.20 (activates at 80% of threshold = 24,000)
    pub buffer_fraction: f64,

    /// Token threshold that triggers the Reflector agent.
    /// When the total observation store tokens reach this level,
    /// the Reflector consolidates observations.
    ///
    /// Mastra default: 40,000
    pub reflection_threshold: usize,

    /// Maximum number of active observations to retain.
    /// The Reflector will aggressively prune beyond this limit.
    pub max_observations: usize,

    /// Maximum turns allowed for the Observer sub-agent.
    pub observer_max_turns: usize,

    /// Maximum turns allowed for the Reflector sub-agent.
    pub reflector_max_turns: usize,

    /// Target compression ratio for reflection passes.
    /// Reflector should aim to reduce observation tokens to this
    /// fraction of input tokens (e.g., 0.6 = 60%).
    pub reflection_target_ratio: f64,
}

impl ObservationConfig {
    /// The effective token count at which the Observer activates.
    pub fn observer_activation_threshold(&self) -> usize {
        ((1.0 - self.buffer_fraction) * self.observation_threshold as f64) as usize
    }

    /// Whether the Observer should activate given current token usage.
    pub fn should_observe(&self, current_tokens: usize) -> bool {
        current_tokens >= self.observer_activation_threshold()
    }

    /// Whether the Reflector should activate given current observation tokens.
    pub fn should_reflect(&self, observation_tokens: usize) -> bool {
        observation_tokens >= self.reflection_threshold
    }
}

impl Default for ObservationConfig {
    fn default() -> Self {
        Self {
            observation_threshold: 30_000,
            buffer_fraction: 0.20,
            reflection_threshold: 40_000,
            max_observations: 200,
            observer_max_turns: 5,
            reflector_max_turns: 5,
            reflection_target_ratio: 0.6,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let cfg = ObservationConfig::default();
        assert_eq!(cfg.observation_threshold, 30_000);
        assert_eq!(cfg.reflection_threshold, 40_000);
        assert_eq!(cfg.max_observations, 200);
    }

    #[test]
    fn observer_activation() {
        let cfg = ObservationConfig::default();
        // 30_000 * (1 - 0.20) = 24_000
        assert_eq!(cfg.observer_activation_threshold(), 24_000);
        assert!(!cfg.should_observe(23_999));
        assert!(cfg.should_observe(24_000));
    }

    #[test]
    fn reflector_activation() {
        let cfg = ObservationConfig::default();
        assert!(!cfg.should_reflect(39_999));
        assert!(cfg.should_reflect(40_000));
    }

    #[test]
    fn custom_config() {
        let cfg = ObservationConfig {
            observation_threshold: 10_000,
            buffer_fraction: 0.10,
            ..Default::default()
        };
        assert_eq!(cfg.observer_activation_threshold(), 9_000);
    }

    #[test]
    fn serde_roundtrip() {
        let cfg = ObservationConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let deserialized: ObservationConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deserialized.observation_threshold,
            cfg.observation_threshold
        );
    }
}
