//! Skill proposals — the bridge between pattern detection and skill adoption.
//!
//! When the PatternDetector identifies a recurring pattern, a SkillProposal is
//! created. Proposals must be approved by a human before the skill is adopted.
//! This enforces Tenet IV: "The Human Is The Root".

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;
use tracing::{debug, info};
use uuid::Uuid;

use zp_core::episode::Pattern;

/// Errors that can occur in the proposal store.
#[derive(Debug, Error)]
pub enum ProposalError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("proposal not found")]
    NotFound,

    #[error("invalid data: {0}")]
    InvalidData(String),
}

pub type Result<T> = std::result::Result<T, ProposalError>;

/// The status of a skill proposal in the approval workflow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProposalStatus {
    /// Newly created, awaiting human review.
    Pending,
    /// Approved by human — skill can be adopted.
    Approved {
        approved_by: String,
        approved_at: DateTime<Utc>,
    },
    /// Rejected by human — pattern noted but skill not adopted.
    Rejected {
        rejected_by: String,
        rejected_at: DateTime<Utc>,
        reason: String,
    },
    /// Superseded by a newer proposal for the same pattern.
    Superseded { superseded_by: String },
}

impl ProposalStatus {
    /// Returns true if the proposal is in Pending status.
    pub fn is_pending(&self) -> bool {
        matches!(self, ProposalStatus::Pending)
    }

    /// Returns true if the proposal has been approved.
    pub fn is_approved(&self) -> bool {
        matches!(self, ProposalStatus::Approved { .. })
    }

    /// Returns true if the proposal has been rejected.
    pub fn is_rejected(&self) -> bool {
        matches!(self, ProposalStatus::Rejected { .. })
    }

    /// Returns true if the proposal has been superseded.
    pub fn is_superseded(&self) -> bool {
        matches!(self, ProposalStatus::Superseded { .. })
    }
}

/// A proposal to create a new skill from a detected pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillProposal {
    /// Unique proposal ID.
    pub id: String,
    /// The pattern that triggered this proposal.
    pub pattern_id: String,
    /// Proposed skill name (human-readable).
    pub proposed_name: String,
    /// Description of what the skill does.
    pub description: String,
    /// The tool sequence that defines this skill.
    pub tool_sequence: Vec<String>,
    /// How many episodes exhibited this pattern.
    pub evidence_count: usize,
    /// Pattern confidence score (0.0-1.0).
    pub confidence: f64,
    /// When this proposal was created.
    pub created_at: DateTime<Utc>,
    /// Current status.
    pub status: ProposalStatus,
    /// The category this pattern belongs to.
    pub category: String,
}

impl SkillProposal {
    /// Creates a new skill proposal from a detected pattern.
    pub fn from_pattern(pattern: &Pattern, category: String) -> Self {
        let tool_names = pattern.tool_sequence.join("_");
        let proposed_name = format!("skill_{}", tool_names);
        let description = pattern.description.clone();

        Self {
            id: Uuid::now_v7().to_string(),
            pattern_id: pattern.id.clone(),
            proposed_name,
            description,
            tool_sequence: pattern.tool_sequence.clone(),
            evidence_count: pattern.occurrence_count,
            confidence: pattern.confidence,
            created_at: Utc::now(),
            status: ProposalStatus::Pending,
            category,
        }
    }
}

/// The proposal store — persists proposals and manages the approval workflow.
pub struct ProposalStore {
    conn: Connection,
}

impl ProposalStore {
    /// Opens or creates a proposal store at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)?;

        // Enable WAL mode for better concurrency
        conn.execute_batch("PRAGMA journal_mode = WAL;")?;

        // Create the proposals table if it doesn't exist
        conn.execute(
            "CREATE TABLE IF NOT EXISTS proposals (
                id TEXT PRIMARY KEY,
                pattern_id TEXT NOT NULL,
                proposed_name TEXT NOT NULL,
                description TEXT NOT NULL,
                tool_sequence TEXT NOT NULL,
                evidence_count INTEGER NOT NULL,
                confidence REAL NOT NULL,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL,
                category TEXT NOT NULL
            ) STRICT",
            [],
        )?;

        // Create indexes for common queries
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_pattern_id ON proposals(pattern_id)",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_status ON proposals(status)",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_category ON proposals(category)",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_created_at ON proposals(created_at DESC)",
            [],
        )?;

        info!("opened proposal store");

        Ok(Self { conn })
    }

    /// Creates a new proposal from a pattern and stores it.
    pub fn create_proposal(&self, pattern: &Pattern, category: &str) -> Result<SkillProposal> {
        let proposal = SkillProposal::from_pattern(pattern, category.to_string());

        let status_json = serde_json::to_string(&proposal.status)?;
        let tool_sequence_json = serde_json::to_string(&proposal.tool_sequence)?;
        let created_at = proposal.created_at.to_rfc3339();

        self.conn.execute(
            "INSERT INTO proposals (id, pattern_id, proposed_name, description, tool_sequence,
                                   evidence_count, confidence, created_at, status, category)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                &proposal.id,
                &proposal.pattern_id,
                &proposal.proposed_name,
                &proposal.description,
                &tool_sequence_json,
                proposal.evidence_count,
                proposal.confidence,
                &created_at,
                &status_json,
                &proposal.category
            ],
        )?;

        debug!(proposal_id = %proposal.id, pattern_id = %pattern.id, "created proposal");

        Ok(proposal)
    }

    /// Retrieves a proposal by its ID.
    pub fn get_proposal(&self, id: &str) -> Result<Option<SkillProposal>> {
        let result = self
            .conn
            .query_row(
                "SELECT id, pattern_id, proposed_name, description, tool_sequence,
                        evidence_count, confidence, created_at, status, category
                 FROM proposals WHERE id = ?1",
                params![id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, usize>(5)?,
                        row.get::<_, f64>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, String>(9)?,
                    ))
                },
            )
            .optional()?;

        match result {
            Some((id, pattern_id, proposed_name, description, tool_sequence_json, evidence_count, confidence, created_at, status_json, category)) => {
                let tool_sequence = serde_json::from_str(&tool_sequence_json)?;
                let status = serde_json::from_str(&status_json)?;
                let created_at = DateTime::parse_from_rfc3339(&created_at)
                    .map_err(|_| ProposalError::InvalidData("invalid timestamp".to_string()))?
                    .with_timezone(&Utc);

                Ok(Some(SkillProposal {
                    id,
                    pattern_id,
                    proposed_name,
                    description,
                    tool_sequence,
                    evidence_count,
                    confidence,
                    created_at,
                    status,
                    category,
                }))
            }
            None => Ok(None),
        }
    }

    /// Retrieves all pending proposals.
    pub fn pending_proposals(&self) -> Result<Vec<SkillProposal>> {
        let pending_status = serde_json::to_string(&ProposalStatus::Pending)?;

        let mut stmt = self.conn.prepare(
            "SELECT id, pattern_id, proposed_name, description, tool_sequence,
                    evidence_count, confidence, created_at, status, category
             FROM proposals WHERE status = ?1
             ORDER BY created_at DESC",
        )?;

        let proposals = stmt
            .query_map(params![&pending_status], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, usize>(5)?,
                    row.get::<_, f64>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let mut result = Vec::new();
        for (id, pattern_id, proposed_name, description, tool_sequence_json, evidence_count, confidence, created_at, status_json, category) in proposals {
            let tool_sequence = serde_json::from_str(&tool_sequence_json)?;
            let status = serde_json::from_str(&status_json)?;
            let created_at = DateTime::parse_from_rfc3339(&created_at)
                .map_err(|_| ProposalError::InvalidData("invalid timestamp".to_string()))?
                .with_timezone(&Utc);

            result.push(SkillProposal {
                id,
                pattern_id,
                proposed_name,
                description,
                tool_sequence,
                evidence_count,
                confidence,
                created_at,
                status,
                category,
            });
        }

        debug!(count = result.len(), "retrieved pending proposals");

        Ok(result)
    }

    /// Approves a proposal by transitioning it to Approved status.
    pub fn approve(&self, id: &str, approved_by: &str) -> Result<SkillProposal> {
        let mut proposal = self
            .get_proposal(id)?
            .ok_or(ProposalError::NotFound)?;

        if !proposal.status.is_pending() {
            return Err(ProposalError::InvalidData(
                "proposal must be in pending status to approve".to_string(),
            ));
        }

        let approved_at = Utc::now();
        proposal.status = ProposalStatus::Approved {
            approved_by: approved_by.to_string(),
            approved_at,
        };

        let status_json = serde_json::to_string(&proposal.status)?;

        self.conn.execute(
            "UPDATE proposals SET status = ?1 WHERE id = ?2",
            params![&status_json, id],
        )?;

        info!(proposal_id = %id, approved_by, "approved proposal");

        Ok(proposal)
    }

    /// Rejects a proposal by transitioning it to Rejected status.
    pub fn reject(&self, id: &str, rejected_by: &str, reason: &str) -> Result<SkillProposal> {
        let mut proposal = self
            .get_proposal(id)?
            .ok_or(ProposalError::NotFound)?;

        if !proposal.status.is_pending() {
            return Err(ProposalError::InvalidData(
                "proposal must be in pending status to reject".to_string(),
            ));
        }

        let rejected_at = Utc::now();
        proposal.status = ProposalStatus::Rejected {
            rejected_by: rejected_by.to_string(),
            rejected_at,
            reason: reason.to_string(),
        };

        let status_json = serde_json::to_string(&proposal.status)?;

        self.conn.execute(
            "UPDATE proposals SET status = ?1 WHERE id = ?2",
            params![&status_json, id],
        )?;

        info!(proposal_id = %id, rejected_by, reason, "rejected proposal");

        Ok(proposal)
    }

    /// Retrieves all proposals for a specific pattern.
    pub fn proposals_for_pattern(&self, pattern_id: &str) -> Result<Vec<SkillProposal>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, pattern_id, proposed_name, description, tool_sequence,
                    evidence_count, confidence, created_at, status, category
             FROM proposals WHERE pattern_id = ?1
             ORDER BY created_at DESC",
        )?;

        let proposals = stmt
            .query_map(params![pattern_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, usize>(5)?,
                    row.get::<_, f64>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let mut result = Vec::new();
        for (id, pattern_id, proposed_name, description, tool_sequence_json, evidence_count, confidence, created_at, status_json, category) in proposals {
            let tool_sequence = serde_json::from_str(&tool_sequence_json)?;
            let status = serde_json::from_str(&status_json)?;
            let created_at = DateTime::parse_from_rfc3339(&created_at)
                .map_err(|_| ProposalError::InvalidData("invalid timestamp".to_string()))?
                .with_timezone(&Utc);

            result.push(SkillProposal {
                id,
                pattern_id,
                proposed_name,
                description,
                tool_sequence,
                evidence_count,
                confidence,
                created_at,
                status,
                category,
            });
        }

        debug!(pattern_id, count = result.len(), "retrieved proposals for pattern");

        Ok(result)
    }

    /// Returns the total number of proposals in the store.
    pub fn count(&self) -> Result<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM proposals", [], |row| row.get(0))?;

        Ok(count as usize)
    }

    /// Returns the number of pending proposals.
    pub fn pending_count(&self) -> Result<usize> {
        let pending_status = serde_json::to_string(&ProposalStatus::Pending)?;
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM proposals WHERE status = ?1",
            params![&pending_status],
            |row| row.get(0),
        )?;

        Ok(count as usize)
    }
}

/// The LearningLoop — coordinates episode recording, pattern detection,
/// and skill proposal creation.
///
/// This is the high-level API that the pipeline uses to drive continuous
/// improvement while keeping humans in control.
pub struct LearningLoop {
    episode_store: crate::EpisodeStore,
    proposal_store: ProposalStore,
    detector: crate::PatternDetector,
}

impl LearningLoop {
    /// Opens or creates the learning loop with episode and proposal stores.
    pub fn open<P: AsRef<Path>>(episodes_path: P, proposals_path: P) -> Result<Self> {
        let episode_store = crate::EpisodeStore::open(&episodes_path)
            .map_err(|e| ProposalError::InvalidData(format!("failed to open episode store: {}", e)))?;

        let proposal_store = ProposalStore::open(&proposals_path)?;
        let detector = crate::PatternDetector::new();

        Ok(Self {
            episode_store,
            proposal_store,
            detector,
        })
    }

    /// Records an episode, detects patterns, and creates a proposal if a pattern is found.
    pub fn record_and_detect(
        &self,
        episode: &zp_core::episode::Episode,
    ) -> Result<Option<SkillProposal>> {
        // Record the episode
        self.episode_store
            .record(episode)
            .map_err(|e| ProposalError::InvalidData(format!("failed to record episode: {}", e)))?;

        // Try to detect a pattern
        if let Some(pattern) = self
            .detector
            .check(episode, &self.episode_store)
            .map_err(|e| ProposalError::InvalidData(format!("detection error: {}", e)))?
        {
            // Create a proposal from the detected pattern
            let proposal = self.proposal_store.create_proposal(&pattern, &episode.request_category)?;
            info!(proposal_id = %proposal.id, "created proposal from detected pattern");
            Ok(Some(proposal))
        } else {
            Ok(None)
        }
    }

    /// Retrieves all pending proposals.
    pub fn pending_proposals(&self) -> Result<Vec<SkillProposal>> {
        self.proposal_store.pending_proposals()
    }

    /// Approves a proposal by its ID.
    pub fn approve_proposal(&self, id: &str, approved_by: &str) -> Result<SkillProposal> {
        self.proposal_store.approve(id, approved_by)
    }

    /// Rejects a proposal by its ID.
    pub fn reject_proposal(&self, id: &str, rejected_by: &str, reason: &str) -> Result<SkillProposal> {
        self.proposal_store.reject(id, rejected_by, reason)
    }

    /// Gets a reference to the episode store.
    pub fn episode_store(&self) -> &crate::EpisodeStore {
        &self.episode_store
    }

    /// Gets a reference to the proposal store.
    pub fn proposal_store(&self) -> &ProposalStore {
        &self.proposal_store
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zp_core::episode::{EpisodeId, Outcome};
    use zp_core::types::{ConversationId, ToolCall};

    fn create_test_pattern() -> Pattern {
        Pattern {
            id: Uuid::now_v7().to_string(),
            episode_ids: vec![],
            description: "Test pattern".to_string(),
            tool_sequence: vec!["tool_a".to_string(), "tool_b".to_string()],
            confidence: 0.85,
            occurrence_count: 5,
        }
    }

    fn create_test_episode(
        conversation_id: &ConversationId,
        category: &str,
        tools: Vec<&str>,
    ) -> zp_core::episode::Episode {
        zp_core::episode::Episode {
            id: EpisodeId::new(),
            conversation_id: conversation_id.clone(),
            timestamp: Utc::now(),
            request_hash: "test_hash".to_string(),
            request_category: category.to_string(),
            tools_used: tools
                .iter()
                .map(|name| ToolCall {
                    tool_name: name.to_string(),
                    arguments: serde_json::json!({}),
                    result: None,
                })
                .collect(),
            active_skills: vec![],
            model_used: "test_model".to_string(),
            outcome: Outcome::Success,
            feedback: None,
            duration_ms: 100,
            policy_decisions: vec![],
        }
    }

    #[test]
    fn test_create_proposal() {
        let store = ProposalStore::open(":memory:").unwrap();
        let pattern = create_test_pattern();

        let proposal = store
            .create_proposal(&pattern, "search")
            .unwrap();

        assert_eq!(proposal.pattern_id, pattern.id);
        assert_eq!(proposal.confidence, pattern.confidence);
        assert_eq!(proposal.evidence_count, pattern.occurrence_count);
        assert!(proposal.status.is_pending());
    }

    #[test]
    fn test_get_proposal() {
        let store = ProposalStore::open(":memory:").unwrap();
        let pattern = create_test_pattern();

        let created = store
            .create_proposal(&pattern, "search")
            .unwrap();

        let retrieved = store
            .get_proposal(&created.id)
            .unwrap();

        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, created.id);
    }

    #[test]
    fn test_pending_proposals() {
        let store = ProposalStore::open(":memory:").unwrap();
        let pattern1 = create_test_pattern();
        let pattern2 = create_test_pattern();

        store.create_proposal(&pattern1, "search").unwrap();
        store.create_proposal(&pattern2, "analysis").unwrap();

        let pending = store.pending_proposals().unwrap();
        assert_eq!(pending.len(), 2);
        assert!(pending.iter().all(|p| p.status.is_pending()));
    }

    #[test]
    fn test_approve_proposal() {
        let store = ProposalStore::open(":memory:").unwrap();
        let pattern = create_test_pattern();

        let proposal = store
            .create_proposal(&pattern, "search")
            .unwrap();

        let approved = store
            .approve(&proposal.id, "alice")
            .unwrap();

        assert!(approved.status.is_approved());

        match &approved.status {
            ProposalStatus::Approved { approved_by, .. } => {
                assert_eq!(approved_by, "alice");
            }
            _ => panic!("expected approved status"),
        }
    }

    #[test]
    fn test_reject_proposal() {
        let store = ProposalStore::open(":memory:").unwrap();
        let pattern = create_test_pattern();

        let proposal = store
            .create_proposal(&pattern, "search")
            .unwrap();

        let rejected = store
            .reject(&proposal.id, "bob", "not a good fit")
            .unwrap();

        assert!(rejected.status.is_rejected());

        match &rejected.status {
            ProposalStatus::Rejected { rejected_by, reason, .. } => {
                assert_eq!(rejected_by, "bob");
                assert_eq!(reason, "not a good fit");
            }
            _ => panic!("expected rejected status"),
        }
    }

    #[test]
    fn test_cannot_approve_non_pending() {
        let store = ProposalStore::open(":memory:").unwrap();
        let pattern = create_test_pattern();

        let proposal = store
            .create_proposal(&pattern, "search")
            .unwrap();

        // Approve it once
        store.approve(&proposal.id, "alice").unwrap();

        // Try to approve again — should fail
        let result = store.approve(&proposal.id, "bob");
        assert!(result.is_err());
    }

    #[test]
    fn test_proposals_for_pattern() {
        let store = ProposalStore::open(":memory:").unwrap();
        let pattern = create_test_pattern();
        let pattern_id = pattern.id.clone();

        store.create_proposal(&pattern, "search").unwrap();
        let pattern2 = create_test_pattern();
        store.create_proposal(&pattern2, "analysis").unwrap();

        let proposals = store
            .proposals_for_pattern(&pattern_id)
            .unwrap();

        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].pattern_id, pattern_id);
    }

    #[test]
    fn test_learning_loop_full_workflow() {
        let episode_store = crate::EpisodeStore::open(":memory:").unwrap();
        let proposal_store = ProposalStore::open(":memory:").unwrap();
        let detector = crate::PatternDetector::with_min_occurrences(2);

        let loop_obj = LearningLoop {
            episode_store,
            proposal_store,
            detector,
        };

        let conversation_id = ConversationId::new();

        // Record first episode
        let ep1 = create_test_episode(&conversation_id, "search", vec!["query", "parse"]);
        let result1 = loop_obj.record_and_detect(&ep1);
        assert!(result1.is_ok());
        // No pattern yet (only 1 episode)
        assert!(result1.unwrap().is_none());

        // Record second episode with same sequence
        let ep2 = create_test_episode(&conversation_id, "search", vec!["query", "parse"]);
        let result2 = loop_obj.record_and_detect(&ep2);
        assert!(result2.is_ok());
        // Pattern should be detected (2 episodes with same sequence)
        let proposal = result2.unwrap();
        assert!(proposal.is_some());

        let prop = proposal.unwrap();
        assert!(prop.status.is_pending());
        assert_eq!(prop.category, "search");
        assert_eq!(prop.tool_sequence, vec!["query", "parse"]);

        // Approve the proposal
        let approved = loop_obj
            .approve_proposal(&prop.id, "human_reviewer")
            .unwrap();
        assert!(approved.status.is_approved());

        // Check pending count decreased
        let pending = loop_obj.pending_proposals().unwrap();
        assert_eq!(pending.len(), 0);
    }

    #[test]
    fn test_learning_loop_rejection() {
        let episode_store = crate::EpisodeStore::open(":memory:").unwrap();
        let proposal_store = ProposalStore::open(":memory:").unwrap();
        let detector = crate::PatternDetector::with_min_occurrences(1);

        let loop_obj = LearningLoop {
            episode_store,
            proposal_store,
            detector,
        };

        let conversation_id = ConversationId::new();

        // Record episode and detect pattern
        let ep = create_test_episode(&conversation_id, "test", vec!["a", "b"]);
        let proposal = loop_obj
            .record_and_detect(&ep)
            .unwrap()
            .unwrap();

        // Reject the proposal
        let rejected = loop_obj
            .reject_proposal(&proposal.id, "reviewer", "not useful")
            .unwrap();

        assert!(rejected.status.is_rejected());
        match &rejected.status {
            ProposalStatus::Rejected { reason, .. } => {
                assert_eq!(reason, "not useful");
            }
            _ => panic!("expected rejected status"),
        }
    }

    #[test]
    fn test_proposal_status_predicates() {
        let pattern = create_test_pattern();

        let pending_prop = SkillProposal::from_pattern(&pattern, "test".to_string());
        assert!(pending_prop.status.is_pending());
        assert!(!pending_prop.status.is_approved());
        assert!(!pending_prop.status.is_rejected());
        assert!(!pending_prop.status.is_superseded());

        let mut approved_prop = pending_prop.clone();
        approved_prop.status = ProposalStatus::Approved {
            approved_by: "alice".to_string(),
            approved_at: Utc::now(),
        };
        assert!(!approved_prop.status.is_pending());
        assert!(approved_prop.status.is_approved());
        assert!(!approved_prop.status.is_rejected());

        let mut rejected_prop = pending_prop.clone();
        rejected_prop.status = ProposalStatus::Rejected {
            rejected_by: "bob".to_string(),
            rejected_at: Utc::now(),
            reason: "test".to_string(),
        };
        assert!(!rejected_prop.status.is_pending());
        assert!(!rejected_prop.status.is_approved());
        assert!(rejected_prop.status.is_rejected());

        let mut superseded_prop = pending_prop.clone();
        superseded_prop.status = ProposalStatus::Superseded {
            superseded_by: "other_id".to_string(),
        };
        assert!(superseded_prop.status.is_superseded());
    }
}
