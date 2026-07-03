//! Officer findings — the structured output of officer sweeps and watches.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Severity level for officer findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Routine check passed. Chain-only, no notification.
    Ok,
    /// Something worth noting but not actionable.
    Info,
    /// Degraded state that may require attention.
    Warning,
    /// Integrity or security violation requiring operator attention.
    Error,
    /// Active compromise or data loss indicator.
    Critical,
}

/// A single finding emitted by an officer.
///
/// Findings are the unit of officer output. Each becomes a chain receipt
/// with event format `officer:{officer_name}:{domain}:{finding_type}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Which officer emitted this finding.
    pub officer: &'static str,
    /// Domain of the finding (integrity, security, operations).
    pub domain: &'static str,
    /// Machine-readable finding type (e.g., "hash_discontinuity", "gap_detected").
    pub finding_type: String,
    /// Severity level.
    pub severity: Severity,
    /// Human-readable summary.
    pub summary: String,
    /// Machine-readable detail for downstream consumers.
    pub detail: serde_json::Value,
    /// When this finding was produced.
    pub timestamp: DateTime<Utc>,
    /// Cross-domain depth counter for loop prevention.
    /// Starts at 0 for original findings. Incremented when a finding
    /// triggers a cross-domain officer activation.
    pub cross_domain_depth: u32,
}

impl Finding {
    /// Build the chain event string: `officer:{name}:{domain}:{type}`.
    pub fn event_key(&self) -> String {
        format!(
            "officer:{}:{}:{}",
            self.officer, self.domain, self.finding_type
        )
    }
}
