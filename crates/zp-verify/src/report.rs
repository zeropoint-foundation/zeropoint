//! Report types: which catalog rules were checked, what passed, what failed.
//!
//! The shape is intentionally narrow — every violation has a rule id, an
//! index into the chain, and a human-readable message. The verifier does
//! not produce remediations or severities; those are concerns of the
//! caller (e.g. the pentest report categorizer, or the CI failure
//! formatter).

use serde::{Deserialize, Serialize};

/// Identifier for a catalog rule. Strings are stable; the v0 set is
/// limited to the rules implemented in this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuleId {
    /// P1 — Chain extension. A chain extended by R is well-formed iff R.pr
    /// links the previous receipt and R.ch matches its body.
    P1,
    /// M3 — Hash-chain continuity. No gaps; every parent reference resolves;
    /// the chain is a connected sequence from a root to the tip.
    M3,
    /// M4 — Trajectory monotonicity. Timestamps along the chain are
    /// non-decreasing.
    M4,
}

impl std::fmt::Display for RuleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleId::P1 => f.write_str("P1"),
            RuleId::M3 => f.write_str("M3"),
            RuleId::M4 => f.write_str("M4"),
        }
    }
}

/// A single violation: which rule failed, where in the chain, and why.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    /// The catalog rule that was violated.
    pub rule: RuleId,
    /// The index in the chain at which the violation was detected.
    pub index: usize,
    /// The id of the receipt at `index`, if available — useful for cross-
    /// referencing against external audit logs.
    pub receipt_id: Option<String>,
    /// Human-readable explanation. Should match the catalog's reject-
    /// condition wording where possible.
    pub message: String,
}

/// Report from a verifier run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyReport {
    /// Number of receipts the verifier was given.
    pub receipts_checked: usize,
    violations: Vec<Violation>,
}

impl VerifyReport {
    pub(crate) fn new(receipts_checked: usize) -> Self {
        Self {
            receipts_checked,
            violations: Vec::new(),
        }
    }

    pub(crate) fn push(&mut self, v: Violation) {
        self.violations.push(v);
    }

    /// `true` iff no rule produced a violation.
    pub fn is_well_formed(&self) -> bool {
        self.violations.is_empty()
    }

    /// All violations, in the order the rules produced them.
    pub fn violations(&self) -> &[Violation] {
        &self.violations
    }

    /// Number of violations of a particular rule.
    pub fn count(&self, rule: RuleId) -> usize {
        self.violations.iter().filter(|v| v.rule == rule).count()
    }
}
