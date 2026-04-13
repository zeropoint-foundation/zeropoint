//! Epistemic status — the trust level of knowledge within ZeroPoint.
//!
//! Phase 3.1 of the hardening roadmap. Every entity that can change status
//! carries an `EpistemicStatus` field plus a `status_receipt_id` linking to the
//! receipt that authorized the transition. Promotions and demotions are fully
//! auditable via the receipt chain.
//!
//! The status lattice (from least to most trusted):
//!
//! ```text
//!   Observed → Interpreted → Admitted → Trusted → Remembered
//!                                                      ↓
//!                                              IdentityBearing
//!                                                      ↓
//!                                                 Delegable
//!                                                      ↓
//!                                                 Executable
//! ```
//!
//! Demotion can occur at any level (quarantine, revocation). Every transition
//! requires a typed receipt with the appropriate claim semantics and authority.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The epistemic status of an entity within ZeroPoint.
///
/// This determines what the system is willing to do with a piece of knowledge,
/// a capability, or an observation. Status transitions are governed by policy
/// and require receipts with appropriate claim semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpistemicStatus {
    /// Raw observation, uninterpreted. The system recorded it but makes no
    /// claims about its meaning or validity.
    Observed = 0,

    /// An agent has interpreted the observation and assigned meaning.
    /// Still not admitted as actionable knowledge.
    Interpreted = 1,

    /// Admitted into the working knowledge base after policy review.
    /// Can influence agent behavior but is not yet trusted for promotion.
    Admitted = 2,

    /// Verified against external evidence or multiple independent observations.
    /// Can be used for decision-making and is eligible for memory promotion.
    Trusted = 3,

    /// Promoted to durable memory. Persists across sessions and influences
    /// future behavior. Requires a TruthAssertion receipt.
    Remembered = 4,

    /// Identity-bearing: this knowledge is part of an agent's or operator's
    /// identity. Modification requires operator-level authority.
    IdentityBearing = 5,

    /// Can be delegated to other agents. The knowledge carries enough trust
    /// to be shared across trust boundaries.
    Delegable = 6,

    /// Executable: the system will act on this knowledge autonomously.
    /// The highest trust level. Requires Tier 2 auth and policy approval.
    Executable = 7,
}

impl EpistemicStatus {
    /// The minimum trust tier required to promote to this status.
    pub fn required_trust_tier(&self) -> u8 {
        match self {
            EpistemicStatus::Observed => 0,
            EpistemicStatus::Interpreted => 0,
            EpistemicStatus::Admitted => 1,
            EpistemicStatus::Trusted => 1,
            EpistemicStatus::Remembered => 1,
            EpistemicStatus::IdentityBearing => 2,
            EpistemicStatus::Delegable => 2,
            EpistemicStatus::Executable => 2,
        }
    }

    /// Whether promotion to this status requires TruthAssertion claim semantics.
    pub fn requires_truth_assertion(&self) -> bool {
        matches!(
            self,
            EpistemicStatus::Remembered
                | EpistemicStatus::IdentityBearing
                | EpistemicStatus::Delegable
                | EpistemicStatus::Executable
        )
    }

    /// Whether this status allows the entity to influence agent behavior.
    pub fn is_actionable(&self) -> bool {
        *self >= EpistemicStatus::Admitted
    }

    /// Whether this status allows delegation across trust boundaries.
    pub fn is_delegable(&self) -> bool {
        *self >= EpistemicStatus::Delegable
    }
}

impl std::fmt::Display for EpistemicStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EpistemicStatus::Observed => write!(f, "observed"),
            EpistemicStatus::Interpreted => write!(f, "interpreted"),
            EpistemicStatus::Admitted => write!(f, "admitted"),
            EpistemicStatus::Trusted => write!(f, "trusted"),
            EpistemicStatus::Remembered => write!(f, "remembered"),
            EpistemicStatus::IdentityBearing => write!(f, "identity_bearing"),
            EpistemicStatus::Delegable => write!(f, "delegable"),
            EpistemicStatus::Executable => write!(f, "executable"),
        }
    }
}

/// A tracked epistemic entity — anything whose trust status can change.
///
/// Wraps any value with its current epistemic status and the receipt chain
/// that authorized each transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Epistemic<T> {
    /// The underlying value.
    pub value: T,

    /// Current epistemic status.
    pub status: EpistemicStatus,

    /// Receipt ID that authorized the current status.
    pub status_receipt_id: String,

    /// When the current status was assigned.
    pub status_changed_at: DateTime<Utc>,

    /// Full history of status transitions (most recent first).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<StatusTransition>,
}

/// A record of a single status transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusTransition {
    /// The status before this transition.
    pub from: EpistemicStatus,

    /// The status after this transition.
    pub to: EpistemicStatus,

    /// Receipt ID that authorized this transition.
    pub receipt_id: String,

    /// When this transition occurred.
    pub transitioned_at: DateTime<Utc>,

    /// Who authorized the transition (actor ID from the receipt).
    pub authorized_by: String,
}

/// Errors that can occur during epistemic status transitions.
#[derive(Debug, Clone, thiserror::Error)]
pub enum EpistemicError {
    /// The requested promotion skips intermediate statuses.
    #[error("Cannot promote from {from} to {to}: must traverse intermediate statuses")]
    SkippedStatus {
        from: EpistemicStatus,
        to: EpistemicStatus,
    },

    /// The caller's trust tier is insufficient for this promotion.
    #[error("Trust tier {have} insufficient for promotion to {target} (requires {need})")]
    InsufficientTrust {
        have: u8,
        need: u8,
        target: EpistemicStatus,
    },

    /// The receipt's claim semantics don't match the required semantics.
    #[error("Promotion to {target} requires TruthAssertion claim semantics")]
    WrongClaimSemantics { target: EpistemicStatus },

    /// Attempted to promote a quarantined entity.
    #[error("Entity is quarantined and cannot be promoted without review")]
    Quarantined,
}

impl<T> Epistemic<T> {
    /// Create a new epistemic entity at the Observed level.
    pub fn new(value: T, receipt_id: &str) -> Self {
        Self {
            value,
            status: EpistemicStatus::Observed,
            status_receipt_id: receipt_id.to_string(),
            status_changed_at: Utc::now(),
            history: Vec::new(),
        }
    }

    /// Promote to the next epistemic status.
    ///
    /// Validates that:
    /// 1. The new status is strictly higher than the current status.
    /// 2. The caller's trust tier meets the requirement.
    /// 3. If TruthAssertion semantics are required, `is_truth_assertion` is true.
    ///
    /// Returns `Ok(())` if the promotion succeeds, recording the transition
    /// in the history.
    pub fn promote(
        &mut self,
        new_status: EpistemicStatus,
        receipt_id: &str,
        authorized_by: &str,
        trust_tier: u8,
        is_truth_assertion: bool,
    ) -> Result<(), EpistemicError> {
        // Must be a promotion (higher status)
        if new_status <= self.status {
            return Err(EpistemicError::SkippedStatus {
                from: self.status,
                to: new_status,
            });
        }

        // Check trust tier
        let required_tier = new_status.required_trust_tier();
        if trust_tier < required_tier {
            return Err(EpistemicError::InsufficientTrust {
                have: trust_tier,
                need: required_tier,
                target: new_status,
            });
        }

        // Check claim semantics
        if new_status.requires_truth_assertion() && !is_truth_assertion {
            return Err(EpistemicError::WrongClaimSemantics {
                target: new_status,
            });
        }

        let transition = StatusTransition {
            from: self.status,
            to: new_status,
            receipt_id: receipt_id.to_string(),
            transitioned_at: Utc::now(),
            authorized_by: authorized_by.to_string(),
        };

        self.history.insert(0, transition);
        self.status = new_status;
        self.status_receipt_id = receipt_id.to_string();
        self.status_changed_at = Utc::now();
        Ok(())
    }

    /// Demote (quarantine) this entity to a lower status.
    ///
    /// Unlike promotion, demotion can skip levels (e.g., Executable → Observed).
    /// Always succeeds if the new status is lower than the current one.
    pub fn demote(
        &mut self,
        new_status: EpistemicStatus,
        receipt_id: &str,
        authorized_by: &str,
    ) -> Result<(), EpistemicError> {
        if new_status >= self.status {
            return Err(EpistemicError::SkippedStatus {
                from: self.status,
                to: new_status,
            });
        }

        let transition = StatusTransition {
            from: self.status,
            to: new_status,
            receipt_id: receipt_id.to_string(),
            transitioned_at: Utc::now(),
            authorized_by: authorized_by.to_string(),
        };

        self.history.insert(0, transition);
        self.status = new_status;
        self.status_receipt_id = receipt_id.to_string();
        self.status_changed_at = Utc::now();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epistemic_status_ordering() {
        assert!(EpistemicStatus::Observed < EpistemicStatus::Interpreted);
        assert!(EpistemicStatus::Interpreted < EpistemicStatus::Admitted);
        assert!(EpistemicStatus::Admitted < EpistemicStatus::Trusted);
        assert!(EpistemicStatus::Trusted < EpistemicStatus::Remembered);
        assert!(EpistemicStatus::Remembered < EpistemicStatus::IdentityBearing);
        assert!(EpistemicStatus::IdentityBearing < EpistemicStatus::Delegable);
        assert!(EpistemicStatus::Delegable < EpistemicStatus::Executable);
    }

    #[test]
    fn test_promotion_happy_path() {
        let mut entity = Epistemic::new("test-knowledge", "rcpt-001");
        assert_eq!(entity.status, EpistemicStatus::Observed);

        entity
            .promote(EpistemicStatus::Interpreted, "rcpt-002", "agent-1", 0, false)
            .unwrap();
        assert_eq!(entity.status, EpistemicStatus::Interpreted);

        entity
            .promote(EpistemicStatus::Admitted, "rcpt-003", "agent-1", 1, false)
            .unwrap();
        assert_eq!(entity.status, EpistemicStatus::Admitted);

        assert_eq!(entity.history.len(), 2);
    }

    #[test]
    fn test_promotion_requires_truth_assertion() {
        let mut entity = Epistemic::new("test", "rcpt-001");
        entity
            .promote(EpistemicStatus::Interpreted, "rcpt-002", "a", 0, false)
            .unwrap();
        entity
            .promote(EpistemicStatus::Admitted, "rcpt-003", "a", 1, false)
            .unwrap();
        entity
            .promote(EpistemicStatus::Trusted, "rcpt-004", "a", 1, false)
            .unwrap();

        // Remembered requires TruthAssertion
        let err = entity
            .promote(EpistemicStatus::Remembered, "rcpt-005", "a", 1, false)
            .unwrap_err();
        assert!(matches!(err, EpistemicError::WrongClaimSemantics { .. }));

        // With truth assertion, it works
        entity
            .promote(EpistemicStatus::Remembered, "rcpt-005", "a", 1, true)
            .unwrap();
        assert_eq!(entity.status, EpistemicStatus::Remembered);
    }

    #[test]
    fn test_demotion_skips_levels() {
        let mut entity = Epistemic::new("test", "rcpt-001");
        entity
            .promote(EpistemicStatus::Interpreted, "rcpt-002", "a", 0, false)
            .unwrap();
        entity
            .promote(EpistemicStatus::Admitted, "rcpt-003", "a", 1, false)
            .unwrap();

        // Demote directly from Admitted to Observed
        entity
            .demote(EpistemicStatus::Observed, "rcpt-004", "admin")
            .unwrap();
        assert_eq!(entity.status, EpistemicStatus::Observed);
        assert_eq!(entity.history.len(), 3);
    }

    #[test]
    fn test_insufficient_trust_tier() {
        let mut entity = Epistemic::new("test", "rcpt-001");
        entity
            .promote(EpistemicStatus::Interpreted, "rcpt-002", "a", 0, false)
            .unwrap();
        entity
            .promote(EpistemicStatus::Admitted, "rcpt-003", "a", 1, false)
            .unwrap();
        entity
            .promote(EpistemicStatus::Trusted, "rcpt-004", "a", 1, false)
            .unwrap();
        entity
            .promote(EpistemicStatus::Remembered, "rcpt-005", "a", 1, true)
            .unwrap();

        // IdentityBearing requires trust tier 2
        let err = entity
            .promote(EpistemicStatus::IdentityBearing, "rcpt-006", "a", 1, true)
            .unwrap_err();
        assert!(matches!(err, EpistemicError::InsufficientTrust { .. }));
    }
}
