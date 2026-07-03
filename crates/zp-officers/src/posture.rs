//! Posture score — composite system health metric.
//!
//! Four domain scores (integrity, security, operations, governance) each
//! 0.0–1.0. Composite = minimum of the four. Recomputed each sweep.
//! Emitted as a `posture:computed` receipt.

use serde::{Deserialize, Serialize};

use crate::finding::{Finding, Severity};

/// System posture score — the single number that answers "how healthy?"
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureScore {
    /// Integrity domain score (Steward's domain). 0.0 = compromised, 1.0 = clean.
    pub integrity: f64,
    /// Security domain score (Sentinel's domain).
    pub security: f64,
    /// Operations domain score (Forge's domain).
    pub operations: f64,
    /// Governance domain score (Cleo's domain).
    pub governance: f64,
    /// Composite score = min(integrity, security, operations, governance).
    /// The weakest domain sets the ceiling.
    pub composite: f64,
    /// Direction of movement since last sweep.
    pub trend: PostureTrend,
}

/// Direction the posture score is moving.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostureTrend {
    /// First computation — no prior to compare against.
    Initial,
    /// Score improved since last sweep.
    Improving,
    /// Score unchanged.
    Stable,
    /// Score degraded since last sweep.
    Degrading,
}

impl PostureScore {
    /// Compute posture from a set of findings.
    ///
    /// Scoring method: start at 1.0 per domain, subtract penalties
    /// based on finding severity. Critical findings drive the score
    /// toward 0 fast; warnings are a gentle drag.
    pub fn compute(findings: &[Finding]) -> Self {
        let integrity = domain_score(findings, "integrity");
        let security = domain_score(findings, "security");
        let operations = domain_score(findings, "operations");
        let governance = domain_score(findings, "governance");
        let composite = integrity.min(security).min(operations).min(governance);

        Self {
            integrity,
            security,
            operations,
            governance,
            composite,
            trend: PostureTrend::Initial,
        }
    }

    /// Update trend by comparing with a prior score.
    pub fn with_trend(mut self, prior: Option<&PostureScore>) -> Self {
        self.trend = match prior {
            None => PostureTrend::Initial,
            Some(prev) => {
                let delta = self.composite - prev.composite;
                if delta > 0.01 {
                    PostureTrend::Improving
                } else if delta < -0.01 {
                    PostureTrend::Degrading
                } else {
                    PostureTrend::Stable
                }
            }
        };
        self
    }
}

/// Compute a single domain's score from its findings.
///
/// Starts at 1.0 and subtracts penalties:
/// - Critical: -0.4 each (two criticals = 0.2)
/// - Error:    -0.2 each
/// - Warning:  -0.05 each
/// - Info/Ok:  no penalty
///
/// Clamped to [0.0, 1.0]. If no findings exist for a domain,
/// score is 1.0 (no news is good news for that domain).
fn domain_score(findings: &[Finding], domain: &str) -> f64 {
    let mut score = 1.0_f64;

    for f in findings.iter().filter(|f| f.domain == domain) {
        let penalty = match f.severity {
            Severity::Critical => 0.4,
            Severity::Error => 0.2,
            Severity::Warning => 0.05,
            Severity::Info | Severity::Ok => 0.0,
        };
        score -= penalty;
    }

    score.clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;

    fn make_finding(domain: &'static str, severity: Severity) -> Finding {
        Finding {
            officer: "std",
            domain,
            finding_type: "test".into(),
            severity,
            summary: "test".into(),
            detail: json!({}),
            timestamp: Utc::now(),
            cross_domain_depth: 0,
        }
    }

    #[test]
    fn clean_system_scores_one() {
        let findings = vec![
            make_finding("integrity", Severity::Ok),
            make_finding("security", Severity::Ok),
        ];
        let score = PostureScore::compute(&findings);
        assert_eq!(score.integrity, 1.0);
        assert_eq!(score.security, 1.0);
        assert_eq!(score.operations, 1.0);
        assert_eq!(score.governance, 1.0);
        assert_eq!(score.composite, 1.0);
    }

    #[test]
    fn critical_finding_drops_score() {
        let findings = vec![make_finding("integrity", Severity::Critical)];
        let score = PostureScore::compute(&findings);
        assert!((score.integrity - 0.6).abs() < 0.001);
        assert_eq!(score.composite, 0.6);
    }

    #[test]
    fn composite_is_minimum() {
        let findings = vec![
            make_finding("integrity", Severity::Ok),
            make_finding("security", Severity::Critical),
            make_finding("security", Severity::Critical),
            make_finding("operations", Severity::Warning),
        ];
        let score = PostureScore::compute(&findings);
        assert_eq!(score.integrity, 1.0);
        assert!((score.security - 0.2).abs() < 0.001);
        assert!((score.operations - 0.95).abs() < 0.001);
        assert!((score.composite - 0.2).abs() < 0.001);
    }

    #[test]
    fn score_clamps_at_zero() {
        let findings = vec![
            make_finding("integrity", Severity::Critical),
            make_finding("integrity", Severity::Critical),
            make_finding("integrity", Severity::Critical),
        ];
        let score = PostureScore::compute(&findings);
        assert_eq!(score.integrity, 0.0);
    }

    #[test]
    fn trend_detection() {
        let prior = PostureScore {
            integrity: 1.0,
            security: 0.8,
            operations: 1.0,
            governance: 1.0,
            composite: 0.8,
            trend: PostureTrend::Initial,
        };

        let improving = PostureScore {
            integrity: 1.0,
            security: 1.0,
            operations: 1.0,
            governance: 1.0,
            composite: 1.0,
            trend: PostureTrend::Initial,
        }
        .with_trend(Some(&prior));
        assert_eq!(improving.trend, PostureTrend::Improving);

        let degrading = PostureScore {
            integrity: 0.6,
            security: 0.6,
            operations: 0.6,
            governance: 0.6,
            composite: 0.6,
            trend: PostureTrend::Initial,
        }
        .with_trend(Some(&prior));
        assert_eq!(degrading.trend, PostureTrend::Degrading);

        let stable = PostureScore {
            integrity: 1.0,
            security: 0.8,
            operations: 1.0,
            governance: 1.0,
            composite: 0.8,
            trend: PostureTrend::Initial,
        }
        .with_trend(Some(&prior));
        assert_eq!(stable.trend, PostureTrend::Stable);
    }
}
