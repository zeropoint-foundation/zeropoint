//! H2 — Response length distribution collapse across cycles.
//!
//! Per REGENT-DOOM-LOOP-DETECTION-2026-07.md §Heuristic 2:
//! track response length over a rolling window of N cycles (default N=20).
//! Flag when:
//!   coefficient of variation < threshold (default 0.15)
//!   AND (mean approaches min-token-floor OR mean approaches a highly-round
//!        number: 100, 200, 500, 1000, 2048)
//!
//! CV = std_dev / mean. Low CV = tight distribution. Combined with the
//! mean being at a suspicious value = "the model is producing the same
//! kind of response every cycle" — either always-minimal or always-hitting-cap.

use std::collections::VecDeque;

use crate::{Finding, HeuristicName, Severity};

/// Highly-round token counts that healthy cycles rarely converge on.
/// A window mean within ROUND_TOLERANCE of any of these, combined with
/// low CV, is the doc's "collapse to a pole" signature.
const ROUND_NUMBERS: &[usize] = &[100, 200, 500, 1000, 2048];
const ROUND_TOLERANCE: f64 = 0.05; // ±5% of the target value

/// Minimum plausible token floor — a window mean this low with tight CV
/// is the "always-minimal" pole of collapse. Model-specific in practice;
/// a defensible default is "shorter than any reasonable single-sentence
/// response would be."
const MIN_TOKEN_FLOOR: usize = 24;

pub fn length_distribution_collapse(
    window: &VecDeque<usize>,
    cv_threshold: f64,
    required_window_size: usize,
) -> Option<Finding> {
    if window.len() < required_window_size {
        // Not enough samples yet.
        return None;
    }

    let n = window.len() as f64;
    let sum: f64 = window.iter().map(|&l| l as f64).sum();
    let mean = sum / n;
    if mean <= 0.0 {
        return None;
    }
    let variance: f64 = window
        .iter()
        .map(|&l| {
            let d = l as f64 - mean;
            d * d
        })
        .sum::<f64>()
        / n;
    let std_dev = variance.sqrt();
    let cv = std_dev / mean;

    if cv >= cv_threshold {
        return None; // distribution not tight — no collapse
    }

    // CV is tight. Now: is the mean near a suspicious value?
    let near_floor = mean as usize <= MIN_TOKEN_FLOOR;

    let near_round = ROUND_NUMBERS.iter().find_map(|&r| {
        let r_f = r as f64;
        let tol = r_f * ROUND_TOLERANCE;
        if (mean - r_f).abs() <= tol {
            Some(r)
        } else {
            None
        }
    });

    if !near_floor && near_round.is_none() {
        return None;
    }

    let pole = if near_floor {
        "min_token_floor".to_string()
    } else {
        format!("round_number_{}", near_round.unwrap())
    };
    let severity = Severity::Critical;

    Some(Finding {
        name: HeuristicName::ResponseLengthCollapse,
        severity,
        evidence: serde_json::json!({
            "window_size": window.len(),
            "mean_length": mean,
            "std_dev": std_dev,
            "coefficient_of_variation": cv,
            "cv_threshold": cv_threshold,
            "pole": pole,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(lengths: &[usize]) -> VecDeque<usize> {
        lengths.iter().copied().collect()
    }

    #[test]
    fn healthy_variable_window_no_flag() {
        let lengths: Vec<usize> = vec![
            40, 78, 120, 45, 89, 200, 55, 92, 130, 60, 88, 165, 44, 77, 110, 92, 130, 44, 68, 100,
        ];
        assert!(length_distribution_collapse(&window(&lengths), 0.15, 20).is_none());
    }

    #[test]
    fn small_window_no_flag() {
        let lengths: Vec<usize> = vec![100, 100, 100];
        assert!(length_distribution_collapse(&window(&lengths), 0.15, 20).is_none());
    }

    #[test]
    fn collapse_to_round_number_flags() {
        // 20 cycles all at 100 tokens — CV=0, mean=100.
        let lengths: Vec<usize> = vec![100; 20];
        let f = length_distribution_collapse(&window(&lengths), 0.15, 20).unwrap();
        assert_eq!(f.name, HeuristicName::ResponseLengthCollapse);
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn collapse_to_floor_flags() {
        // All-short responses at 20 tokens.
        let lengths: Vec<usize> = vec![20; 20];
        let f = length_distribution_collapse(&window(&lengths), 0.15, 20).unwrap();
        assert_eq!(f.name, HeuristicName::ResponseLengthCollapse);
    }

    #[test]
    fn low_cv_but_non_suspicious_mean_does_not_flag() {
        // Tight but at 63 tokens (not near floor, not a round number).
        let lengths: Vec<usize> = vec![63; 20];
        assert!(length_distribution_collapse(&window(&lengths), 0.15, 20).is_none());
    }
}
