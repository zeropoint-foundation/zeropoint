//! H3 — Token entropy anomaly.
//!
//! Per REGENT-DOOM-LOOP-DETECTION-2026-07.md §Heuristic 3:
//! if the backend exposes per-token log-probabilities, compute mean
//! per-token surprise (`-log P(chosen)`) across the response. Compare
//! against a rolling baseline for this model (from the model dossier's
//! `entropy_baseline` field). If surprise collapses more than 2σ below
//! baseline, flag.
//!
//! Note on terminology: the doc uses "entropy" but with per-chosen-token
//! log-probabilities we can't compute true Shannon entropy over the
//! vocabulary distribution. We compute mean(-log P(chosen)) as a proxy —
//! a "confidence surprise" metric. Both signal the same underlying
//! phenomenon: doom-looped output has near-deterministic distributions,
//! so both the true entropy AND the surprise-on-chosen-token are low.

use crate::{EntropyBaseline, Finding, HeuristicName, Severity};

/// The doc's threshold: flag when observed mean is 2σ below baseline.
const SIGMA_MULTIPLIER: f64 = 2.0;

pub fn token_entropy_anomaly(log_probs: &[f64], baseline: &EntropyBaseline) -> Option<Finding> {
    if log_probs.is_empty() {
        return None;
    }
    if baseline.std_dev <= 0.0 {
        // Degenerate baseline; can't meaningfully compare.
        return None;
    }
    // Surprise = -log P(chosen). Log-probs come in as negative numbers
    // (or zero for prob=1), so surprise = -log_p is >= 0.
    let n = log_probs.len() as f64;
    let mean_surprise: f64 = log_probs.iter().map(|&lp| -lp).sum::<f64>() / n;
    let sigmas_below = (baseline.mean - mean_surprise) / baseline.std_dev;
    if sigmas_below < SIGMA_MULTIPLIER {
        return None;
    }
    // Severity: 3σ+ below baseline is Critical, 2-3σ is Warning.
    let severity = if sigmas_below >= 3.0 {
        Severity::Critical
    } else {
        Severity::Warning
    };
    Some(Finding {
        name: HeuristicName::TokenEntropyAnomaly,
        severity,
        evidence: serde_json::json!({
            "response_token_count": log_probs.len(),
            "observed_mean_surprise": mean_surprise,
            "baseline_mean": baseline.mean,
            "baseline_std_dev": baseline.std_dev,
            "sigmas_below_baseline": sigmas_below,
            "sigma_threshold": SIGMA_MULTIPLIER,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline() -> EntropyBaseline {
        EntropyBaseline {
            mean: 2.0,
            std_dev: 0.5,
        }
    }

    #[test]
    fn healthy_entropy_no_flag() {
        // log_probs around -2.0 → surprise around 2.0 → matches baseline.
        let log_probs = vec![-2.0, -2.1, -1.9, -2.0, -2.2, -1.8];
        assert!(token_entropy_anomaly(&log_probs, &baseline()).is_none());
    }

    #[test]
    fn collapsed_entropy_flags_critical() {
        // Log-probs near 0 → surprise ~0 → many sigmas below 2.0.
        let log_probs = vec![-0.01; 20];
        let f = token_entropy_anomaly(&log_probs, &baseline()).unwrap();
        assert_eq!(f.name, HeuristicName::TokenEntropyAnomaly);
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn borderline_2sigma_flags_warning() {
        // Baseline=2.0, std=0.5. 2σ below = 1.0. Surprise ~1.0 → flags.
        // Surprise ~1.0 with baseline 2.0, std 0.5 = exactly 2σ below.
        // Test slightly past: surprise 0.95 → 2.1σ below → Warning.
        let log_probs = vec![-0.95; 10];
        let f = token_entropy_anomaly(&log_probs, &baseline()).unwrap();
        assert_eq!(f.severity, Severity::Warning);
    }

    #[test]
    fn empty_log_probs_no_flag() {
        assert!(token_entropy_anomaly(&[], &baseline()).is_none());
    }

    #[test]
    fn degenerate_baseline_no_flag() {
        let bad = EntropyBaseline {
            mean: 2.0,
            std_dev: 0.0,
        };
        let log_probs = vec![-0.01; 10];
        assert!(token_entropy_anomaly(&log_probs, &bad).is_none());
    }
}
