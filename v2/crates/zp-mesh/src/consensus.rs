//! Distributed consensus — receipt-based agreement between mesh peers.
//!
//! When an action requires peer validation (e.g., high-trust operations,
//! capability grants, or governance changes), the acting agent proposes
//! the action's receipt to a set of peers. Each peer votes to accept or
//! reject. The consensus coordinator tallies votes against a threshold.
//!
//! ```text
//! Proposer                     Peer 1        Peer 2        Peer 3
//!     │                          │              │              │
//!     │── Proposal ────────────▶│              │              │
//!     │── Proposal ─────────────────────────▶ │              │
//!     │── Proposal ──────────────────────────────────────▶  │
//!     │                          │              │              │
//!     │◀── Vote(accept) ────────│              │              │
//!     │◀── Vote(reject) ────────────────────── │              │
//!     │◀── Vote(accept) ─────────────────────────────────── │
//!     │                          │              │              │
//!     │  tally: 2/3 accept → Majority reached                │
//! ```
//!
//! Design constraints:
//! - Proposals carry the receipt hash, not the full receipt (peers verify independently)
//! - Votes are signed by the voting peer
//! - Timeouts prevent indefinite waiting
//! - The coordinator is local — no global state required

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use zp_core::governance::ConsensusThreshold;

/// A proposal for peer consensus.
///
/// The proposer broadcasts this to the required set of peers.
/// Each peer independently decides whether to accept.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    /// Unique proposal identifier ("prop-" prefix).
    pub id: String,
    /// The receipt hash being proposed for consensus.
    pub receipt_hash: String,
    /// Who is proposing (mesh address hex).
    pub proposer: String,
    /// Description of what's being proposed.
    pub description: String,
    /// Consensus threshold required.
    pub threshold: ConsensusThreshold,
    /// Peers who must vote (mesh address hex values).
    pub voters: Vec<String>,
    /// When the proposal was created.
    pub created_at: DateTime<Utc>,
    /// Deadline for votes (None = no timeout).
    pub deadline: Option<DateTime<Utc>>,
}

impl Proposal {
    /// Create a new proposal.
    pub fn new(
        receipt_hash: String,
        proposer: String,
        description: String,
        threshold: ConsensusThreshold,
        voters: Vec<String>,
        timeout_secs: Option<u64>,
    ) -> Self {
        let now = Utc::now();
        let deadline = timeout_secs.map(|s| now + Duration::seconds(s as i64));

        Self {
            id: format!("prop-{}", uuid::Uuid::now_v7()),
            receipt_hash,
            proposer,
            description,
            threshold,
            voters,
            created_at: now,
            deadline,
        }
    }

    /// Whether this proposal has expired.
    pub fn is_expired(&self) -> bool {
        self.deadline.is_some_and(|d| Utc::now() > d)
    }

    /// Number of voters required.
    pub fn voter_count(&self) -> usize {
        self.voters.len()
    }
}

/// A vote on a proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    /// The proposal this vote is for.
    pub proposal_id: String,
    /// Who is voting (mesh address hex).
    pub voter: String,
    /// Accept or reject.
    pub accept: bool,
    /// Optional reason.
    pub reason: Option<String>,
    /// When the vote was cast.
    pub cast_at: DateTime<Utc>,
    /// Ed25519 signature over (proposal_id ‖ voter ‖ accept) — hex.
    pub signature: Option<String>,
}

impl Vote {
    /// Create an accepting vote.
    pub fn accept(proposal_id: &str, voter: &str) -> Self {
        Self {
            proposal_id: proposal_id.to_string(),
            voter: voter.to_string(),
            accept: true,
            reason: None,
            cast_at: Utc::now(),
            signature: None,
        }
    }

    /// Create a rejecting vote.
    pub fn reject(proposal_id: &str, voter: &str, reason: &str) -> Self {
        Self {
            proposal_id: proposal_id.to_string(),
            voter: voter.to_string(),
            accept: false,
            reason: Some(reason.to_string()),
            cast_at: Utc::now(),
            signature: None,
        }
    }
}

/// The outcome of a consensus round.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusOutcome {
    /// Consensus reached: enough peers accepted.
    Accepted,
    /// Consensus failed: too many rejections to ever reach threshold.
    Rejected,
    /// Still waiting for votes.
    Pending,
    /// Deadline passed before enough votes arrived.
    TimedOut,
}

/// Tracks the state of a single consensus round.
#[derive(Debug, Clone)]
pub struct ConsensusRound {
    /// The proposal being voted on.
    pub proposal: Proposal,
    /// Votes received so far (voter address → vote).
    pub votes: HashMap<String, Vote>,
    /// Current outcome.
    pub outcome: ConsensusOutcome,
}

impl ConsensusRound {
    /// Create a new round from a proposal.
    pub fn new(proposal: Proposal) -> Self {
        Self {
            proposal,
            votes: HashMap::new(),
            outcome: ConsensusOutcome::Pending,
        }
    }

    /// Record a vote. Returns the updated outcome.
    ///
    /// Ignores duplicate votes from the same voter,
    /// and votes from non-listed voters.
    pub fn record_vote(&mut self, vote: Vote) -> ConsensusOutcome {
        // Ignore if already decided
        if self.outcome != ConsensusOutcome::Pending {
            return self.outcome.clone();
        }

        // Ignore if voter isn't in the voter list
        if !self.proposal.voters.contains(&vote.voter) {
            return self.outcome.clone();
        }

        // Ignore duplicate votes
        if self.votes.contains_key(&vote.voter) {
            return self.outcome.clone();
        }

        self.votes.insert(vote.voter.clone(), vote);
        self.evaluate()
    }

    /// Evaluate the current state against the threshold.
    pub fn evaluate(&mut self) -> ConsensusOutcome {
        if self.outcome != ConsensusOutcome::Pending {
            return self.outcome.clone();
        }

        // Check timeout
        if self.proposal.is_expired() {
            self.outcome = ConsensusOutcome::TimedOut;
            return self.outcome.clone();
        }

        let total = self.proposal.voters.len() as u32;
        let accepts = self.votes.values().filter(|v| v.accept).count() as u32;
        let rejects = self.votes.values().filter(|v| !v.accept).count() as u32;

        let required = match &self.proposal.threshold {
            ConsensusThreshold::Unanimous => total,
            ConsensusThreshold::Majority => (total / 2) + 1,
            ConsensusThreshold::Threshold { required, .. } => *required,
        };

        if accepts >= required {
            self.outcome = ConsensusOutcome::Accepted;
        } else if rejects > (total - required) {
            // Can't possibly reach threshold even if all remaining vote accept
            self.outcome = ConsensusOutcome::Rejected;
        }

        self.outcome.clone()
    }

    /// Number of votes received.
    pub fn votes_received(&self) -> usize {
        self.votes.len()
    }

    /// Number of accept votes.
    pub fn accepts(&self) -> usize {
        self.votes.values().filter(|v| v.accept).count()
    }

    /// Number of reject votes.
    pub fn rejects(&self) -> usize {
        self.votes.values().filter(|v| !v.accept).count()
    }
}

/// Coordinator that manages multiple concurrent consensus rounds.
///
/// Each node runs its own coordinator. Proposals are tracked by ID.
#[derive(Debug, Default)]
pub struct ConsensusCoordinator {
    /// Active rounds (proposal_id → round).
    rounds: HashMap<String, ConsensusRound>,
}

impl ConsensusCoordinator {
    pub fn new() -> Self {
        Self {
            rounds: HashMap::new(),
        }
    }

    /// Start a new consensus round.
    ///
    /// Returns the proposal ID for tracking.
    pub fn propose(&mut self, proposal: Proposal) -> String {
        let id = proposal.id.clone();
        self.rounds
            .insert(id.clone(), ConsensusRound::new(proposal));
        id
    }

    /// Record a vote on a proposal.
    ///
    /// Returns None if the proposal doesn't exist, or the current outcome.
    pub fn vote(&mut self, vote: Vote) -> Option<ConsensusOutcome> {
        self.rounds
            .get_mut(&vote.proposal_id)
            .map(|round| round.record_vote(vote))
    }

    /// Get the outcome of a proposal.
    pub fn outcome(&self, proposal_id: &str) -> Option<&ConsensusOutcome> {
        self.rounds.get(proposal_id).map(|r| &r.outcome)
    }

    /// Get a round by proposal ID.
    pub fn round(&self, proposal_id: &str) -> Option<&ConsensusRound> {
        self.rounds.get(proposal_id)
    }

    /// Remove completed (non-pending) rounds. Returns the number removed.
    pub fn gc(&mut self) -> usize {
        let before = self.rounds.len();
        self.rounds
            .retain(|_, r| r.outcome == ConsensusOutcome::Pending);
        before - self.rounds.len()
    }

    /// Number of active (pending) rounds.
    pub fn active_count(&self) -> usize {
        self.rounds
            .values()
            .filter(|r| r.outcome == ConsensusOutcome::Pending)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_proposal(voters: Vec<&str>, threshold: ConsensusThreshold) -> Proposal {
        Proposal::new(
            "hash-abc123".to_string(),
            "proposer-addr".to_string(),
            "Test proposal".to_string(),
            threshold,
            voters.into_iter().map(|s| s.to_string()).collect(),
            None,
        )
    }

    #[test]
    fn test_unanimous_accept() {
        let proposal = make_proposal(vec!["a", "b", "c"], ConsensusThreshold::Unanimous);
        let mut round = ConsensusRound::new(proposal);

        assert_eq!(
            round.record_vote(Vote::accept("", "a")),
            ConsensusOutcome::Pending
        );
        assert_eq!(
            round.record_vote(Vote::accept("", "b")),
            ConsensusOutcome::Pending
        );
        assert_eq!(
            round.record_vote(Vote::accept("", "c")),
            ConsensusOutcome::Accepted
        );
    }

    #[test]
    fn test_unanimous_reject_on_single_reject() {
        let proposal = make_proposal(vec!["a", "b", "c"], ConsensusThreshold::Unanimous);
        let mut round = ConsensusRound::new(proposal);

        assert_eq!(
            round.record_vote(Vote::accept("", "a")),
            ConsensusOutcome::Pending
        );
        // One reject means unanimous is impossible
        assert_eq!(
            round.record_vote(Vote::reject("", "b", "disagree")),
            ConsensusOutcome::Rejected
        );
    }

    #[test]
    fn test_majority_accept() {
        let proposal = make_proposal(vec!["a", "b", "c"], ConsensusThreshold::Majority);
        let mut round = ConsensusRound::new(proposal);

        assert_eq!(
            round.record_vote(Vote::accept("", "a")),
            ConsensusOutcome::Pending
        );
        // 2 of 3 = majority
        assert_eq!(
            round.record_vote(Vote::accept("", "b")),
            ConsensusOutcome::Accepted
        );
    }

    #[test]
    fn test_majority_reject() {
        let proposal = make_proposal(vec!["a", "b", "c"], ConsensusThreshold::Majority);
        let mut round = ConsensusRound::new(proposal);

        assert_eq!(
            round.record_vote(Vote::reject("", "a", "no")),
            ConsensusOutcome::Pending
        );
        // 2 rejects out of 3 — majority can't be reached
        assert_eq!(
            round.record_vote(Vote::reject("", "b", "no")),
            ConsensusOutcome::Rejected
        );
    }

    #[test]
    fn test_threshold_k_of_n() {
        let proposal = make_proposal(
            vec!["a", "b", "c", "d", "e"],
            ConsensusThreshold::Threshold {
                required: 3,
                total: 5,
            },
        );
        let mut round = ConsensusRound::new(proposal);

        assert_eq!(
            round.record_vote(Vote::accept("", "a")),
            ConsensusOutcome::Pending
        );
        assert_eq!(
            round.record_vote(Vote::reject("", "b", "no")),
            ConsensusOutcome::Pending
        );
        assert_eq!(
            round.record_vote(Vote::accept("", "c")),
            ConsensusOutcome::Pending
        );
        assert_eq!(
            round.record_vote(Vote::accept("", "d")),
            ConsensusOutcome::Accepted
        );
    }

    #[test]
    fn test_threshold_impossible() {
        let proposal = make_proposal(
            vec!["a", "b", "c", "d", "e"],
            ConsensusThreshold::Threshold {
                required: 4,
                total: 5,
            },
        );
        let mut round = ConsensusRound::new(proposal);

        assert_eq!(
            round.record_vote(Vote::reject("", "a", "no")),
            ConsensusOutcome::Pending
        );
        // 2 rejects → only 3 possible accepts, need 4 → impossible
        assert_eq!(
            round.record_vote(Vote::reject("", "b", "no")),
            ConsensusOutcome::Rejected
        );
    }

    #[test]
    fn test_duplicate_vote_ignored() {
        let proposal = make_proposal(vec!["a", "b"], ConsensusThreshold::Unanimous);
        let mut round = ConsensusRound::new(proposal);

        round.record_vote(Vote::accept("", "a"));
        // Duplicate from "a" should be ignored
        round.record_vote(Vote::reject("", "a", "changed mind"));
        assert_eq!(round.accepts(), 1);
        assert_eq!(round.rejects(), 0);
    }

    #[test]
    fn test_unknown_voter_ignored() {
        let proposal = make_proposal(vec!["a", "b"], ConsensusThreshold::Unanimous);
        let mut round = ConsensusRound::new(proposal);

        round.record_vote(Vote::accept("", "intruder"));
        assert_eq!(round.votes_received(), 0);
    }

    #[test]
    fn test_vote_after_decision_ignored() {
        let proposal = make_proposal(vec!["a", "b", "c"], ConsensusThreshold::Majority);
        let mut round = ConsensusRound::new(proposal);

        round.record_vote(Vote::accept("", "a")); // 1/3 — pending
        assert_eq!(round.outcome, ConsensusOutcome::Pending);
        round.record_vote(Vote::accept("", "b")); // 2/3 = majority reached
        assert_eq!(round.outcome, ConsensusOutcome::Accepted);

        round.record_vote(Vote::reject("", "c", "too late"));
        // Still accepted, late vote ignored
        assert_eq!(round.outcome, ConsensusOutcome::Accepted);
        assert_eq!(round.votes_received(), 2); // only 2 counted
    }

    #[test]
    fn test_proposal_timeout() {
        let mut proposal = make_proposal(vec!["a", "b", "c"], ConsensusThreshold::Unanimous);
        // Set deadline in the past
        proposal.deadline = Some(Utc::now() - Duration::seconds(10));

        let mut round = ConsensusRound::new(proposal);
        let outcome = round.evaluate();
        assert_eq!(outcome, ConsensusOutcome::TimedOut);
    }

    #[test]
    fn test_coordinator_propose_and_vote() {
        let mut coord = ConsensusCoordinator::new();

        let proposal = make_proposal(vec!["a", "b", "c"], ConsensusThreshold::Majority);
        let prop_id = coord.propose(proposal);

        assert_eq!(coord.active_count(), 1);
        assert_eq!(coord.outcome(&prop_id), Some(&ConsensusOutcome::Pending));

        coord.vote(Vote::accept(&prop_id, "a"));
        assert_eq!(coord.outcome(&prop_id), Some(&ConsensusOutcome::Pending));

        let outcome = coord.vote(Vote::accept(&prop_id, "b")).unwrap();
        assert_eq!(outcome, ConsensusOutcome::Accepted);
        assert_eq!(coord.outcome(&prop_id), Some(&ConsensusOutcome::Accepted));
    }

    #[test]
    fn test_coordinator_multiple_proposals() {
        let mut coord = ConsensusCoordinator::new();

        let p1 = make_proposal(vec!["a", "b"], ConsensusThreshold::Unanimous);
        let p2 = make_proposal(vec!["c", "d", "e"], ConsensusThreshold::Majority);
        let id1 = coord.propose(p1);
        let id2 = coord.propose(p2);

        assert_eq!(coord.active_count(), 2);

        coord.vote(Vote::accept(&id1, "a"));
        coord.vote(Vote::accept(&id1, "b")); // p1 accepted (unanimous 2/2)
        coord.vote(Vote::accept(&id2, "c"));
        coord.vote(Vote::accept(&id2, "d")); // p2 accepted (majority 2/3)

        assert_eq!(coord.outcome(&id1), Some(&ConsensusOutcome::Accepted));
        assert_eq!(coord.outcome(&id2), Some(&ConsensusOutcome::Accepted));
    }

    #[test]
    fn test_coordinator_vote_unknown_proposal() {
        let mut coord = ConsensusCoordinator::new();
        assert!(coord.vote(Vote::accept("nonexistent", "a")).is_none());
    }

    #[test]
    fn test_coordinator_gc() {
        let mut coord = ConsensusCoordinator::new();

        let p1 = make_proposal(vec!["a"], ConsensusThreshold::Majority);
        let p2 = make_proposal(vec!["b", "c"], ConsensusThreshold::Unanimous);
        let id1 = coord.propose(p1);
        let _id2 = coord.propose(p2);

        // Complete p1
        coord.vote(Vote::accept(&id1, "a"));
        assert_eq!(coord.active_count(), 1); // p2 still pending

        let removed = coord.gc();
        assert_eq!(removed, 1); // p1 removed
        assert_eq!(coord.rounds.len(), 1); // only p2 remains
    }

    #[test]
    fn test_round_counts() {
        let proposal = make_proposal(vec!["a", "b", "c", "d"], ConsensusThreshold::Majority);
        let mut round = ConsensusRound::new(proposal);

        round.record_vote(Vote::accept("", "a"));
        round.record_vote(Vote::reject("", "b", "no"));
        round.record_vote(Vote::accept("", "c"));

        assert_eq!(round.votes_received(), 3);
        assert_eq!(round.accepts(), 2);
        assert_eq!(round.rejects(), 1);
    }

    #[test]
    fn test_proposal_serialization() {
        let proposal = make_proposal(vec!["a", "b"], ConsensusThreshold::Majority);
        let json = serde_json::to_string(&proposal).unwrap();
        let restored: Proposal = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.receipt_hash, "hash-abc123");
        assert_eq!(restored.voters.len(), 2);
        assert_eq!(restored.proposer, "proposer-addr");
    }

    #[test]
    fn test_vote_serialization() {
        let vote = Vote::reject("prop-123", "voter-a", "disagree");
        let json = serde_json::to_string(&vote).unwrap();
        let restored: Vote = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.proposal_id, "prop-123");
        assert!(!restored.accept);
        assert_eq!(restored.reason, Some("disagree".to_string()));
    }
}
