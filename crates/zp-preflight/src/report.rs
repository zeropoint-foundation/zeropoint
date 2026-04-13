//! Report data model — the structured output of a preflight run.

use crate::platform::Platform;
use chrono::Utc;
use serde::Serialize;
use std::time::Duration;

// ─── Check result ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub enum Status {
    /// Check passed.
    Pass,
    /// Check failed — installation will fail without action.
    Fail,
    /// Check inconclusive but installation may still work.
    Warn,
    /// Check was skipped (not applicable on this platform).
    Skip,
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    /// Machine-readable identifier, e.g. `"libssl"`.
    pub id: String,
    /// Human-readable label, e.g. `"OpenSSL development headers"`.
    pub label: String,
    pub status: Status,
    /// Detail string shown on pass/warn.
    pub detail: String,
    /// Exact fix command on failure, or empty string.
    pub fix: String,
}

impl CheckResult {
    pub fn pass(
        id: impl Into<String>,
        label: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            status: Status::Pass,
            detail: detail.into(),
            fix: String::new(),
        }
    }

    pub fn fail(
        id: impl Into<String>,
        label: impl Into<String>,
        detail: impl Into<String>,
        fix: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            status: Status::Fail,
            detail: detail.into(),
            fix: fix.into(),
        }
    }

    pub fn warn(
        id: impl Into<String>,
        label: impl Into<String>,
        detail: impl Into<String>,
        fix: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            status: Status::Warn,
            detail: detail.into(),
            fix: fix.into(),
        }
    }

    pub fn skip(
        id: impl Into<String>,
        label: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            status: Status::Skip,
            detail: reason.into(),
            fix: String::new(),
        }
    }

    pub fn is_fail(&self) -> bool {
        matches!(self.status, Status::Fail)
    }

    pub fn is_warn(&self) -> bool {
        matches!(self.status, Status::Warn)
    }
}

// ─── Full report ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct PreflightReport {
    pub timestamp: String,
    pub platform: Platform,
    pub checks: Vec<CheckResult>,
    pub elapsed_ms: u64,
    pub summary: ReportSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportSummary {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub warnings: usize,
    pub skipped: usize,
    pub ready: bool,
}

impl PreflightReport {
    pub fn build(platform: Platform, checks: Vec<CheckResult>, elapsed: Duration) -> Self {
        let summary = ReportSummary {
            total: checks.len(),
            passed: checks
                .iter()
                .filter(|c| matches!(c.status, Status::Pass))
                .count(),
            failed: checks
                .iter()
                .filter(|c| matches!(c.status, Status::Fail))
                .count(),
            warnings: checks
                .iter()
                .filter(|c| matches!(c.status, Status::Warn))
                .count(),
            skipped: checks
                .iter()
                .filter(|c| matches!(c.status, Status::Skip))
                .count(),
            ready: !checks.iter().any(|c| matches!(c.status, Status::Fail)),
        };
        Self {
            timestamp: Utc::now().to_rfc3339(),
            platform,
            checks,
            elapsed_ms: elapsed.as_millis() as u64,
            summary,
        }
    }
}
