//! Bridges `agent_zp::QuorumPolicy` → `zp_mesh::ConsensusCoordinator`.
//!
//! Maps agent-zp's quorum types to ZP's native consensus system, enabling
//! M-of-N approval for high-risk agent operations.

use std::sync::Mutex;

use async_trait::async_trait;
use chrono::Utc;

use agent_zp::quorum::{
    ProposedAction, QuorumError, QuorumOutcome, QuorumPolicy, QuorumProposal, QuorumThreshold,
    QuorumVote, VoterRef,
};

use zp_core::ConsensusThreshold as ZpThreshold;
use zp_mesh::consensus::{ConsensusCoordinator, ConsensusOutcome, Proposal, Vote};

/// Concrete `QuorumPolicy` backed by ZP's `ConsensusCoordinator`.
///
/// Maps agent-zp's quorum types to ZP's native consensus system.
/// Maintains a coordinator instance and voter-address mapping.
pub struct ZpQuorumPolicy {
    coordinator: Mutex<ConsensusCoordinator>,

    /// Risk threshold: actions at or above this level require quorum
    risk_threshold: agent_zp::RiskLevel,

    /// Default voters for quorum decisions
    default_voters: Vec<VoterRef>,

    /// Default threshold
    default_threshold: QuorumThreshold,

    /// Default deadline in seconds
    default_deadline_secs: Option<u64>,
}

impl ZpQuorumPolicy {
    pub fn new(
        risk_threshold: agent_zp::RiskLevel,
        default_voters: Vec<VoterRef>,
        default_threshold: QuorumThreshold,
    ) -> Self {
        Self {
            coordinator: Mutex::new(ConsensusCoordinator::new()),
            risk_threshold,
            default_voters,
            default_threshold,
            default_deadline_secs: Some(300), // 5 minute default
        }
    }

    pub fn with_deadline(mut self, secs: u64) -> Self {
        self.default_deadline_secs = Some(secs);
        self
    }

    /// Map agent-zp threshold → ZP threshold.
    fn map_threshold(threshold: &QuorumThreshold) -> ZpThreshold {
        match threshold {
            QuorumThreshold::Unanimous => ZpThreshold::Unanimous,
            QuorumThreshold::Majority => ZpThreshold::Majority,
            QuorumThreshold::Threshold { required, total } => ZpThreshold::Threshold {
                required: *required,
                total: *total,
            },
        }
    }

    /// Map ZP outcome → agent-zp outcome.
    fn map_outcome(
        outcome: &ConsensusOutcome,
        round: &zp_mesh::consensus::ConsensusRound,
    ) -> QuorumOutcome {
        let total = round.proposal.voters.len() as u32;
        let approvals = round.accepts() as u32;
        let rejections = round.rejects() as u32;

        match outcome {
            ConsensusOutcome::Accepted => QuorumOutcome::Approved { approvals, total },
            ConsensusOutcome::Rejected => {
                let reasons: Vec<String> = round
                    .votes
                    .values()
                    .filter(|v| !v.accept)
                    .filter_map(|v| v.reason.clone())
                    .collect();
                QuorumOutcome::Rejected {
                    approvals,
                    rejections,
                    total,
                    reasons,
                }
            }
            ConsensusOutcome::Pending => QuorumOutcome::Pending {
                approvals,
                rejections,
                remaining: total - approvals - rejections,
            },
            ConsensusOutcome::TimedOut => QuorumOutcome::TimedOut { approvals, total },
        }
    }

    /// Resolve a VoterRef to a mesh-addressable string.
    fn voter_address(voter: &VoterRef) -> String {
        match voter {
            VoterRef::SovereigntyProvider { mode, device_id } => {
                format!(
                    "sovereignty:{}:{}",
                    mode,
                    device_id.as_deref().unwrap_or("default")
                )
            }
            VoterRef::Human { id } => format!("human:{}", id),
            VoterRef::Agent { agent_id } => format!("agent:{}", agent_id),
            VoterRef::MeshPeer { address } => address.clone(),
        }
    }

    /// Check if an action's risk level meets or exceeds the threshold.
    fn risk_meets_threshold(&self, risk: &agent_zp::RiskLevel) -> bool {
        use agent_zp::RiskLevel;
        let risk_ord = match risk {
            RiskLevel::Low => 0,
            RiskLevel::Medium => 1,
            RiskLevel::High => 2,
            RiskLevel::Critical => 3,
        };
        let threshold_ord = match self.risk_threshold {
            RiskLevel::Low => 0,
            RiskLevel::Medium => 1,
            RiskLevel::High => 2,
            RiskLevel::Critical => 3,
        };
        risk_ord >= threshold_ord
    }
}

#[async_trait]
impl QuorumPolicy for ZpQuorumPolicy {
    async fn requires_quorum(
        &self,
        action: &ProposedAction,
    ) -> Option<(QuorumThreshold, Vec<VoterRef>)> {
        if self.risk_meets_threshold(&action.risk_level) && !self.default_voters.is_empty() {
            Some((self.default_threshold.clone(), self.default_voters.clone()))
        } else {
            None
        }
    }

    async fn propose(
        &self,
        proposer: &str,
        action: ProposedAction,
        threshold: QuorumThreshold,
        voters: Vec<VoterRef>,
        deadline_secs: Option<u64>,
    ) -> Result<QuorumProposal, QuorumError> {
        let voter_addresses: Vec<String> = voters.iter().map(Self::voter_address).collect();

        let action_hash = {
            let canonical = serde_json::json!({
                "action_type": action.action_type,
                "target": action.target,
                "description": action.description,
            });
            blake3::hash(canonical.to_string().as_bytes())
                .to_hex()
                .to_string()
        };

        let zp_threshold = Self::map_threshold(&threshold);
        let deadline = deadline_secs
            .or(self.default_deadline_secs)
            .map(|s| Utc::now() + chrono::Duration::seconds(s as i64));

        let proposal = Proposal::new(
            action_hash.clone(),
            proposer.to_string(),
            action.description.clone(),
            zp_threshold,
            voter_addresses,
            deadline_secs.or(self.default_deadline_secs),
        );

        let proposal_id = {
            let mut coord = self
                .coordinator
                .lock()
                .map_err(|e| QuorumError::Other(e.to_string()))?;
            coord.propose(proposal)
        };

        Ok(QuorumProposal {
            proposal_id,
            proposer: proposer.to_string(),
            action,
            threshold,
            voters,
            created_at: Utc::now(),
            deadline,
            action_hash,
        })
    }

    async fn vote(&self, vote: QuorumVote) -> Result<QuorumOutcome, QuorumError> {
        let voter_address = Self::voter_address(&vote.voter);

        let zp_vote = if vote.approve {
            Vote::accept(&vote.proposal_id, &voter_address)
        } else {
            Vote::reject(
                &vote.proposal_id,
                &voter_address,
                vote.reason.as_deref().unwrap_or("no reason given"),
            )
        };

        let mut coord = self
            .coordinator
            .lock()
            .map_err(|e| QuorumError::Other(e.to_string()))?;

        let outcome = coord
            .vote(zp_vote)
            .ok_or_else(|| QuorumError::ProposalNotFound(vote.proposal_id.clone()))?;

        let round = coord
            .round(&vote.proposal_id)
            .ok_or_else(|| QuorumError::ProposalNotFound(vote.proposal_id.clone()))?;

        Ok(Self::map_outcome(&outcome, round))
    }

    async fn check_outcome(&self, proposal_id: &str) -> Result<QuorumOutcome, QuorumError> {
        let coord = self
            .coordinator
            .lock()
            .map_err(|e| QuorumError::Other(e.to_string()))?;

        let round = coord
            .round(proposal_id)
            .ok_or_else(|| QuorumError::ProposalNotFound(proposal_id.to_string()))?;

        Ok(Self::map_outcome(&round.outcome, round))
    }

    async fn cancel(&self, _proposal_id: &str) -> Result<(), QuorumError> {
        // ConsensusCoordinator doesn't have explicit cancel — use GC
        let mut coord = self
            .coordinator
            .lock()
            .map_err(|e| QuorumError::Other(e.to_string()))?;
        coord.gc();
        Ok(())
    }
}
