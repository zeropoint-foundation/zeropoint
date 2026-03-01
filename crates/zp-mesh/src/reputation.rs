//! Peer Reputation — governance receipts aggregated into trust scores.
//!
//! Each peer in the mesh accumulates a reputation based on verifiable
//! governance events: successful audit attestations, valid delegation
//! chains, policy agreement compliance, and receipt exchange history.
//!
//! ## Design
//!
//! Reputation is *evidence-based*, not opinion-based. Every reputation
//! signal is backed by a cryptographically signed governance artifact:
//!
//! - **Audit attestations** → Did the peer's audit chain verify?
//! - **Delegation chains** → Did delegations stay within scope/depth?
//! - **Policy agreements** → Did the peer honour negotiated policies?
//! - **Receipt exchange** → Did the peer provide valid receipts?
//!
//! Scores are computed locally by each node — there is no global
//! reputation oracle. Peers can share attestations to help the mesh
//! converge, but each node makes its own trust decisions.
//!
//! ## Scoring
//!
//! The `ReputationScore` is a composite of weighted signal categories,
//! normalised to a 0.0–1.0 range. The `ReputationGrade` maps this
//! to a human-readable tier (Excellent / Good / Fair / Poor / Unknown).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Maximum number of events to retain per peer per signal category.
/// Older events are evicted in FIFO order.
pub const MAX_EVENTS_PER_CATEGORY: usize = 100;

/// Default decay half-life in days — older signals count less.
pub const DECAY_HALF_LIFE_DAYS: f64 = 30.0;

// ============================================================================
// Reputation types
// ============================================================================

/// A single reputation signal — one piece of evidence about a peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationSignal {
    /// What kind of evidence this is.
    pub category: SignalCategory,
    /// Positive (trust-building) or negative (trust-eroding).
    pub polarity: SignalPolarity,
    /// When this signal was recorded.
    pub timestamp: DateTime<Utc>,
    /// Governance artifact that backs this signal (receipt ID, attestation ID, etc.).
    pub evidence_id: String,
    /// Optional free-text note (e.g., "chain_valid: true, 5 entries").
    pub detail: Option<String>,
}

/// Categories of reputation evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignalCategory {
    /// Peer's audit chain was verified (or failed verification).
    AuditAttestation,
    /// Peer sent a valid (or invalid) delegation chain.
    DelegationChain,
    /// Peer honoured (or violated) a policy agreement.
    PolicyCompliance,
    /// Peer provided a valid (or invalid) receipt.
    ReceiptExchange,
}

/// Whether the signal is trust-building or trust-eroding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignalPolarity {
    Positive,
    Negative,
}

/// Human-readable reputation tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ReputationGrade {
    /// No data — peer is unknown.
    Unknown,
    /// Score < 0.25
    Poor,
    /// Score 0.25–0.50
    Fair,
    /// Score 0.50–0.75
    Good,
    /// Score >= 0.75
    Excellent,
}

impl std::fmt::Display for ReputationGrade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReputationGrade::Unknown => write!(f, "Unknown"),
            ReputationGrade::Poor => write!(f, "Poor"),
            ReputationGrade::Fair => write!(f, "Fair"),
            ReputationGrade::Good => write!(f, "Good"),
            ReputationGrade::Excellent => write!(f, "Excellent"),
        }
    }
}

/// Weights for each signal category (must sum to 1.0 for normalised scoring).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationWeights {
    pub audit_attestation: f64,
    pub delegation_chain: f64,
    pub policy_compliance: f64,
    pub receipt_exchange: f64,
}

impl Default for ReputationWeights {
    fn default() -> Self {
        Self {
            audit_attestation: 0.35,
            delegation_chain: 0.20,
            policy_compliance: 0.25,
            receipt_exchange: 0.20,
        }
    }
}

impl ReputationWeights {
    /// Get the weight for a given category.
    pub fn weight_for(&self, category: SignalCategory) -> f64 {
        match category {
            SignalCategory::AuditAttestation => self.audit_attestation,
            SignalCategory::DelegationChain => self.delegation_chain,
            SignalCategory::PolicyCompliance => self.policy_compliance,
            SignalCategory::ReceiptExchange => self.receipt_exchange,
        }
    }
}

/// Computed reputation score for a single peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationScore {
    /// The peer's destination hash (hex).
    pub peer: String,
    /// Overall score (0.0–1.0).
    pub score: f64,
    /// Human-readable grade.
    pub grade: ReputationGrade,
    /// Per-category breakdown.
    pub breakdown: Vec<CategoryScore>,
    /// Total positive signals considered.
    pub positive_signals: usize,
    /// Total negative signals considered.
    pub negative_signals: usize,
    /// When this score was computed.
    pub computed_at: DateTime<Utc>,
}

/// Score for a single signal category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryScore {
    pub category: SignalCategory,
    pub score: f64,
    pub weight: f64,
    pub weighted_score: f64,
    pub signal_count: usize,
}

// ============================================================================
// Peer reputation ledger
// ============================================================================

/// Per-peer reputation ledger that accumulates signals and computes scores.
#[derive(Debug, Clone, Default)]
pub struct PeerReputation {
    /// Signals organised by category.
    signals: Vec<ReputationSignal>,
}

impl PeerReputation {
    pub fn new() -> Self {
        Self {
            signals: Vec::new(),
        }
    }

    /// Record a reputation signal.
    ///
    /// Evicts the oldest signal in the same category if we've hit the cap.
    pub fn record(&mut self, signal: ReputationSignal) {
        // Evict oldest in same category if at capacity
        let category = signal.category;
        let count = self
            .signals
            .iter()
            .filter(|s| s.category == category)
            .count();
        if count >= MAX_EVENTS_PER_CATEGORY {
            // Remove the oldest signal in this category
            if let Some(idx) = self.signals.iter().position(|s| s.category == category) {
                self.signals.remove(idx);
            }
        }
        self.signals.push(signal);
    }

    /// Compute the reputation score using the given weights.
    ///
    /// Each category score is the time-decayed ratio of positive to total
    /// signals. The overall score is the weighted sum of category scores.
    pub fn compute_score(
        &self,
        peer_hex: &str,
        weights: &ReputationWeights,
        now: DateTime<Utc>,
    ) -> ReputationScore {
        let categories = [
            SignalCategory::AuditAttestation,
            SignalCategory::DelegationChain,
            SignalCategory::PolicyCompliance,
            SignalCategory::ReceiptExchange,
        ];

        let mut breakdown = Vec::new();
        let mut total_score = 0.0;
        let mut total_positive = 0;
        let mut total_negative = 0;

        for &cat in &categories {
            let cat_signals: Vec<&ReputationSignal> =
                self.signals.iter().filter(|s| s.category == cat).collect();

            let weight = weights.weight_for(cat);
            let count = cat_signals.len();

            let cat_score = if cat_signals.is_empty() {
                // No data → neutral (0.5) so unknowns don't drag score down
                0.5
            } else {
                // Time-decayed positive ratio
                let mut weighted_positive = 0.0f64;
                let mut weighted_total = 0.0f64;

                for sig in &cat_signals {
                    let age_days = (now - sig.timestamp).num_seconds() as f64 / 86400.0;
                    let decay = (-age_days * (2.0f64.ln()) / DECAY_HALF_LIFE_DAYS).exp();

                    weighted_total += decay;
                    if sig.polarity == SignalPolarity::Positive {
                        weighted_positive += decay;
                        total_positive += 1;
                    } else {
                        total_negative += 1;
                    }
                }

                if weighted_total > 0.0 {
                    weighted_positive / weighted_total
                } else {
                    0.5
                }
            };

            let weighted_score = cat_score * weight;
            total_score += weighted_score;

            breakdown.push(CategoryScore {
                category: cat,
                score: cat_score,
                weight,
                weighted_score,
                signal_count: count,
            });
        }

        // Clamp to [0, 1]
        let score = total_score.clamp(0.0, 1.0);

        let grade = if self.signals.is_empty() {
            ReputationGrade::Unknown
        } else {
            score_to_grade(score)
        };

        ReputationScore {
            peer: peer_hex.to_string(),
            score,
            grade,
            breakdown,
            positive_signals: total_positive,
            negative_signals: total_negative,
            computed_at: now,
        }
    }

    /// Total number of signals recorded.
    pub fn signal_count(&self) -> usize {
        self.signals.len()
    }

    /// All signals, most recent first.
    pub fn signals(&self) -> &[ReputationSignal] {
        &self.signals
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Map a numeric score to a grade.
pub fn score_to_grade(score: f64) -> ReputationGrade {
    if score >= 0.75 {
        ReputationGrade::Excellent
    } else if score >= 0.50 {
        ReputationGrade::Good
    } else if score >= 0.25 {
        ReputationGrade::Fair
    } else {
        ReputationGrade::Poor
    }
}

/// Create a positive audit attestation signal from a `PeerAuditAttestation`.
pub fn signal_from_attestation(attestation: &zp_audit::PeerAuditAttestation) -> ReputationSignal {
    let polarity = if attestation.chain_valid {
        SignalPolarity::Positive
    } else {
        SignalPolarity::Negative
    };

    ReputationSignal {
        category: SignalCategory::AuditAttestation,
        polarity,
        timestamp: attestation.timestamp,
        evidence_id: attestation.id.clone(),
        detail: Some(format!(
            "entries: {}, sigs: {}",
            attestation.entries_verified, attestation.signatures_valid
        )),
    }
}

/// Create a delegation chain signal from a verification result.
pub fn signal_from_delegation(grant_id: &str, valid: bool, now: DateTime<Utc>) -> ReputationSignal {
    ReputationSignal {
        category: SignalCategory::DelegationChain,
        polarity: if valid {
            SignalPolarity::Positive
        } else {
            SignalPolarity::Negative
        },
        timestamp: now,
        evidence_id: grant_id.to_string(),
        detail: None,
    }
}

/// Create a policy compliance signal.
pub fn signal_from_policy_compliance(
    agreement_id: &str,
    compliant: bool,
    now: DateTime<Utc>,
) -> ReputationSignal {
    ReputationSignal {
        category: SignalCategory::PolicyCompliance,
        polarity: if compliant {
            SignalPolarity::Positive
        } else {
            SignalPolarity::Negative
        },
        timestamp: now,
        evidence_id: agreement_id.to_string(),
        detail: None,
    }
}

/// Create a receipt exchange signal.
pub fn signal_from_receipt(receipt_id: &str, valid: bool, now: DateTime<Utc>) -> ReputationSignal {
    ReputationSignal {
        category: SignalCategory::ReceiptExchange,
        polarity: if valid {
            SignalPolarity::Positive
        } else {
            SignalPolarity::Negative
        },
        timestamp: now,
        evidence_id: receipt_id.to_string(),
        detail: None,
    }
}

// ============================================================================
// Compact wire format for reputation sharing
// ============================================================================

/// Compact reputation summary for sharing over the mesh.
///
/// Peers can broadcast their view of other peers' reputations
/// so the mesh can converge on a shared understanding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactReputationSummary {
    /// Peer being rated (destination hash hex).
    pub peer: String,
    /// Overall score (0.0–1.0).
    pub sc: f64,
    /// Grade as string: "E"=Excellent, "G"=Good, "F"=Fair, "P"=Poor, "U"=Unknown.
    pub gr: String,
    /// Number of positive signals.
    pub ps: usize,
    /// Number of negative signals.
    pub ns: usize,
    /// When this summary was computed (Unix timestamp).
    pub ts: i64,
}

impl CompactReputationSummary {
    /// Build from a full ReputationScore.
    pub fn from_score(score: &ReputationScore) -> Self {
        let gr = match score.grade {
            ReputationGrade::Excellent => "E",
            ReputationGrade::Good => "G",
            ReputationGrade::Fair => "F",
            ReputationGrade::Poor => "P",
            ReputationGrade::Unknown => "U",
        };
        Self {
            peer: score.peer.clone(),
            sc: score.score,
            gr: gr.to_string(),
            ps: score.positive_signals,
            ns: score.negative_signals,
            ts: score.computed_at.timestamp(),
        }
    }

    /// Reconstruct a grade from the compact string.
    pub fn grade(&self) -> ReputationGrade {
        match self.gr.as_str() {
            "E" => ReputationGrade::Excellent,
            "G" => ReputationGrade::Good,
            "F" => ReputationGrade::Fair,
            "P" => ReputationGrade::Poor,
            _ => ReputationGrade::Unknown,
        }
    }

    /// Encode to msgpack bytes.
    pub fn to_msgpack(&self) -> crate::error::MeshResult<Vec<u8>> {
        rmp_serde::to_vec_named(self)
            .map_err(|e| crate::error::MeshError::Serialization(e.to_string()))
    }

    /// Decode from msgpack bytes.
    pub fn from_msgpack(data: &[u8]) -> crate::error::MeshResult<Self> {
        rmp_serde::from_slice(data)
            .map_err(|e| crate::error::MeshError::Serialization(e.to_string()))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn now() -> DateTime<Utc> {
        Utc::now()
    }

    #[test]
    fn test_empty_peer_reputation_is_unknown() {
        let rep = PeerReputation::new();
        let score = rep.compute_score("abc123", &ReputationWeights::default(), now());
        assert_eq!(score.grade, ReputationGrade::Unknown);
        // With no signals, categories default to 0.5 → overall 0.5
        assert!((score.score - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_all_positive_signals_excellent() {
        let mut rep = PeerReputation::new();
        let n = now();

        // Add positive signals in all categories
        rep.record(signal_from_receipt("r1", true, n));
        rep.record(signal_from_receipt("r2", true, n));
        rep.record(signal_from_delegation("d1", true, n));
        rep.record(signal_from_policy_compliance("p1", true, n));

        let att = zp_audit::PeerAuditAttestation {
            id: "att-1".to_string(),
            peer: "abc123".to_string(),
            oldest_hash: "a".to_string(),
            newest_hash: "b".to_string(),
            entries_verified: 5,
            chain_valid: true,
            signatures_valid: 3,
            timestamp: n,
            signature: None,
        };
        rep.record(signal_from_attestation(&att));

        let score = rep.compute_score("abc123", &ReputationWeights::default(), n);
        assert_eq!(score.grade, ReputationGrade::Excellent);
        assert!(score.score > 0.9);
        assert_eq!(score.positive_signals, 5);
        assert_eq!(score.negative_signals, 0);
    }

    #[test]
    fn test_all_negative_signals_poor() {
        let mut rep = PeerReputation::new();
        let n = now();

        rep.record(signal_from_receipt("r1", false, n));
        rep.record(signal_from_delegation("d1", false, n));
        rep.record(signal_from_policy_compliance("p1", false, n));

        let att = zp_audit::PeerAuditAttestation {
            id: "att-bad".to_string(),
            peer: "bad_peer".to_string(),
            oldest_hash: "a".to_string(),
            newest_hash: "b".to_string(),
            entries_verified: 2,
            chain_valid: false,
            signatures_valid: 0,
            timestamp: n,
            signature: None,
        };
        rep.record(signal_from_attestation(&att));

        let score = rep.compute_score("bad_peer", &ReputationWeights::default(), n);
        assert_eq!(score.grade, ReputationGrade::Poor);
        assert!(score.score < 0.25);
    }

    #[test]
    fn test_mixed_signals_fair_or_good() {
        let mut rep = PeerReputation::new();
        let n = now();

        // 2 positive, 2 negative
        rep.record(signal_from_receipt("r1", true, n));
        rep.record(signal_from_receipt("r2", false, n));
        rep.record(signal_from_delegation("d1", true, n));
        rep.record(signal_from_delegation("d2", false, n));

        let score = rep.compute_score("mixed", &ReputationWeights::default(), n);
        // With 50/50 mix, each populated category → 0.5, empty categories → 0.5
        // So overall should be ~0.5
        assert!(score.score >= 0.4 && score.score <= 0.6);
    }

    #[test]
    fn test_time_decay_favours_recent_signals() {
        let mut rep = PeerReputation::new();
        let n = now();

        // Old negative signal (60 days ago = 2 half-lives)
        rep.record(ReputationSignal {
            category: SignalCategory::ReceiptExchange,
            polarity: SignalPolarity::Negative,
            timestamp: n - Duration::days(60),
            evidence_id: "old-bad".to_string(),
            detail: None,
        });

        // Recent positive signal
        rep.record(signal_from_receipt("new-good", true, n));

        let score = rep.compute_score("peer", &ReputationWeights::default(), n);
        // The recent positive should outweigh the old negative
        // Receipt category should be > 0.5
        let receipt_cat = score
            .breakdown
            .iter()
            .find(|c| c.category == SignalCategory::ReceiptExchange)
            .unwrap();
        assert!(
            receipt_cat.score > 0.6,
            "Recent positive should dominate: {}",
            receipt_cat.score
        );
    }

    #[test]
    fn test_eviction_at_capacity() {
        let mut rep = PeerReputation::new();
        let n = now();

        // Fill to max in one category
        for i in 0..MAX_EVENTS_PER_CATEGORY {
            rep.record(signal_from_receipt(&format!("r{}", i), true, n));
        }
        assert_eq!(rep.signal_count(), MAX_EVENTS_PER_CATEGORY);

        // Adding one more should evict the oldest
        rep.record(signal_from_receipt("overflow", true, n));
        assert_eq!(rep.signal_count(), MAX_EVENTS_PER_CATEGORY);
    }

    #[test]
    fn test_score_to_grade_boundaries() {
        assert_eq!(score_to_grade(1.0), ReputationGrade::Excellent);
        assert_eq!(score_to_grade(0.75), ReputationGrade::Excellent);
        assert_eq!(score_to_grade(0.74), ReputationGrade::Good);
        assert_eq!(score_to_grade(0.50), ReputationGrade::Good);
        assert_eq!(score_to_grade(0.49), ReputationGrade::Fair);
        assert_eq!(score_to_grade(0.25), ReputationGrade::Fair);
        assert_eq!(score_to_grade(0.24), ReputationGrade::Poor);
        assert_eq!(score_to_grade(0.0), ReputationGrade::Poor);
    }

    #[test]
    fn test_reputation_grade_ordering() {
        assert!(ReputationGrade::Excellent > ReputationGrade::Good);
        assert!(ReputationGrade::Good > ReputationGrade::Fair);
        assert!(ReputationGrade::Fair > ReputationGrade::Poor);
        assert!(ReputationGrade::Poor > ReputationGrade::Unknown);
    }

    #[test]
    fn test_reputation_grade_display() {
        assert_eq!(ReputationGrade::Excellent.to_string(), "Excellent");
        assert_eq!(ReputationGrade::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn test_custom_weights() {
        let mut rep = PeerReputation::new();
        let n = now();

        // Only audit signals — all positive
        rep.record(signal_from_attestation(&zp_audit::PeerAuditAttestation {
            id: "a1".to_string(),
            peer: "p".to_string(),
            oldest_hash: "x".to_string(),
            newest_hash: "y".to_string(),
            entries_verified: 3,
            chain_valid: true,
            signatures_valid: 1,
            timestamp: n,
            signature: None,
        }));

        // Heavy weight on audit
        let weights = ReputationWeights {
            audit_attestation: 0.90,
            delegation_chain: 0.0,
            policy_compliance: 0.0,
            receipt_exchange: 0.10,
        };

        let score = rep.compute_score("p", &weights, n);
        // Audit = 1.0 * 0.9 = 0.9, Receipt = 0.5 * 0.1 = 0.05 → total = 0.95
        assert!(score.score > 0.9);
        assert_eq!(score.grade, ReputationGrade::Excellent);
    }

    #[test]
    fn test_signal_from_attestation_positive() {
        let att = zp_audit::PeerAuditAttestation {
            id: "att-ok".to_string(),
            peer: "p".to_string(),
            oldest_hash: "a".to_string(),
            newest_hash: "b".to_string(),
            entries_verified: 3,
            chain_valid: true,
            signatures_valid: 2,
            timestamp: now(),
            signature: None,
        };
        let sig = signal_from_attestation(&att);
        assert_eq!(sig.polarity, SignalPolarity::Positive);
        assert_eq!(sig.category, SignalCategory::AuditAttestation);
        assert_eq!(sig.evidence_id, "att-ok");
    }

    #[test]
    fn test_signal_from_attestation_negative() {
        let att = zp_audit::PeerAuditAttestation {
            id: "att-fail".to_string(),
            peer: "p".to_string(),
            oldest_hash: "a".to_string(),
            newest_hash: "b".to_string(),
            entries_verified: 2,
            chain_valid: false,
            signatures_valid: 0,
            timestamp: now(),
            signature: None,
        };
        let sig = signal_from_attestation(&att);
        assert_eq!(sig.polarity, SignalPolarity::Negative);
    }

    #[test]
    fn test_compact_reputation_summary_roundtrip() {
        let mut rep = PeerReputation::new();
        let n = now();
        rep.record(signal_from_receipt("r1", true, n));
        rep.record(signal_from_receipt("r2", true, n));

        let score = rep.compute_score("abc", &ReputationWeights::default(), n);
        let compact = CompactReputationSummary::from_score(&score);

        assert_eq!(compact.peer, "abc");
        assert_eq!(compact.ps, 2);
        assert_eq!(compact.ns, 0);

        // Msgpack roundtrip
        let bytes = compact.to_msgpack().unwrap();
        let decoded = CompactReputationSummary::from_msgpack(&bytes).unwrap();
        assert_eq!(decoded.peer, "abc");
        assert_eq!(decoded.ps, 2);
        assert_eq!(decoded.grade(), score.grade);
    }

    #[test]
    fn test_compact_summary_grade_mapping() {
        let check = |g: ReputationGrade, s: &str| {
            let score = ReputationScore {
                peer: "p".to_string(),
                score: 0.5,
                grade: g,
                breakdown: vec![],
                positive_signals: 0,
                negative_signals: 0,
                computed_at: now(),
            };
            let c = CompactReputationSummary::from_score(&score);
            assert_eq!(c.gr, s);
            assert_eq!(c.grade(), g);
        };
        check(ReputationGrade::Excellent, "E");
        check(ReputationGrade::Good, "G");
        check(ReputationGrade::Fair, "F");
        check(ReputationGrade::Poor, "P");
        check(ReputationGrade::Unknown, "U");
    }

    #[test]
    fn test_per_category_breakdown() {
        let mut rep = PeerReputation::new();
        let n = now();

        rep.record(signal_from_receipt("r1", true, n));
        rep.record(signal_from_delegation("d1", false, n));

        let score = rep.compute_score("peer", &ReputationWeights::default(), n);
        assert_eq!(score.breakdown.len(), 4);

        let receipt_cat = score
            .breakdown
            .iter()
            .find(|c| c.category == SignalCategory::ReceiptExchange)
            .unwrap();
        assert_eq!(receipt_cat.signal_count, 1);
        assert!((receipt_cat.score - 1.0).abs() < 0.01); // All positive

        let delegation_cat = score
            .breakdown
            .iter()
            .find(|c| c.category == SignalCategory::DelegationChain)
            .unwrap();
        assert_eq!(delegation_cat.signal_count, 1);
        assert!(delegation_cat.score < 0.01); // All negative
    }
}
