//! Ontology object types — the five materialized primitives Cartographer
//! produces from chain receipts.
//!
//! Per `docs/design/ONTOLOGY-AND-CARTOGRAPHER-2026-07.md` Phase 1 shapes.
//!
//! Phase 2+ fields (importance, momentum, confidence, pros/cons, etc.) are
//! commented in the parent spec but not part of P1 implementation. This
//! module ships the deliberately-minimal shapes that can be populated from
//! deterministic rules; richer fields land as later phases materialize the
//! machinery to fill them.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zp_core::{AuditId, ConversationId};

use crate::id::{ObjectId, ObjectType};

// ── OntologyObject trait ───────────────────────────────────────────────────

/// Common interface implemented by all five ontology object types.
///
/// Used by generic store methods (`insert_object`, `get_object`,
/// `update_object`) so the storage layer doesn't need per-type CRUD.
pub trait OntologyObject: Serialize + for<'de> Deserialize<'de> + Clone {
    /// Object type discriminator — determines table row's `object_type` column.
    const OBJECT_TYPE: ObjectType;

    fn id(&self) -> &ObjectId;

    /// Trajectory this object belongs to. Trajectory returns None (it IS
    /// the trajectory); other types return Some pointing to their parent.
    fn trajectory_id(&self) -> Option<&ObjectId>;

    fn title(&self) -> &str;

    /// Serialized status string for the `status` indexed column.
    /// Format: snake_case variant name (e.g., "active", "dormant", "superseded").
    fn status_str(&self) -> String;

    fn created_at(&self) -> DateTime<Utc>;

    fn last_active(&self) -> DateTime<Utc>;

    /// Only Trajectory overrides this. Populates the `boundary_confidence`
    /// column for trajectory rows; NULL for other types.
    fn boundary_confidence(&self) -> Option<f32> {
        None
    }
}

// ── Trajectory ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Trajectory {
    pub id: ObjectId,
    pub title: String,
    pub status: TrajectoryStatus,
    pub boundary_confidence: f32,
    pub parent_id: Option<ObjectId>,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub last_active: DateTime<Utc>,
    pub receipt_refs: Vec<AuditId>,

    // ── P4 boundary-detection state ─────────────────────────────────────
    //
    // These fields carry per-trajectory context needed by S1 (conversation)
    // and S4 (domain clustering) signals. Populated on trajectory creation
    // and updated by Cartographer on each receipt assignment.
    //
    // `#[serde(default)]` on each so older ontology.db payloads (without
    // these fields) deserialize without error — the fields default to
    // empty/nil and populate correctly on subsequent updates.
    /// Most recent receipt's conversation_id in this trajectory. Approximates
    /// "dominant" per design doc §Section 1 note (P4 simplification).
    #[serde(default = "default_nil_conversation_id")]
    pub dominant_conversation_id: ConversationId,
    /// All distinct conversation_ids seen in this trajectory, capped at 32
    /// (excess is a strong boundary-suggestive signal on its own).
    /// Used to derive `multi_conversation_history` bool for S1.
    #[serde(default)]
    pub seen_conversation_ids: Vec<ConversationId>,
    /// Per-event-prefix receipt counts. Prefix = first two colon-separated
    /// segments of the event string (e.g., "officer:std", "delegation:granted").
    /// Used by S4 to compute dominant + top-3 domain prefixes.
    /// Bounded at 20 distinct prefixes tracked.
    #[serde(default)]
    pub event_prefix_counts: BTreeMap<String, u32>,
}

fn default_nil_conversation_id() -> ConversationId {
    ConversationId(uuid::Uuid::nil())
}

impl Trajectory {
    /// True if this trajectory has seen receipts from more than one distinct
    /// conversation_id. Derived from `seen_conversation_ids` for S1 signal.
    pub fn has_multi_conversation_history(&self) -> bool {
        self.seen_conversation_ids.len() > 1
    }

    /// The event prefix with the highest receipt count, if any. Used as the
    /// "dominant" domain for S4 signal.
    pub fn dominant_event_prefix(&self) -> Option<String> {
        self.event_prefix_counts
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(prefix, _)| prefix.clone())
    }

    /// The top-N event prefixes by receipt count. Used by S4 to check if a
    /// new receipt's prefix is "in the trajectory's top-3 distribution".
    pub fn top_event_prefixes(&self, n: usize) -> Vec<String> {
        let mut entries: Vec<(&String, &u32)> = self.event_prefix_counts.iter().collect();
        entries.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
        entries.into_iter().take(n).map(|(p, _)| p.clone()).collect()
    }

    /// Record a new receipt's contribution to boundary-detection state.
    /// Cartographer calls this on each `ContinueTrajectory` decision.
    ///
    /// Bounded: seen_conversation_ids capped at 32, event_prefix_counts at 20.
    pub fn record_receipt_context(&mut self, conv_id: ConversationId, event_prefix: Option<&str>) {
        // Update conversation-id set (bounded).
        if !self.seen_conversation_ids.contains(&conv_id)
            && self.seen_conversation_ids.len() < 32 {
                self.seen_conversation_ids.push(conv_id.clone());
            }
        // Dominant is always the most-recent (P4 v1 approximation).
        self.dominant_conversation_id = conv_id;

        // Update event-prefix counts (bounded).
        if let Some(prefix) = event_prefix {
            let key = prefix.to_string();
            if self.event_prefix_counts.contains_key(&key) {
                *self.event_prefix_counts.get_mut(&key).unwrap() += 1;
            } else if self.event_prefix_counts.len() < 20 {
                self.event_prefix_counts.insert(key, 1);
            }
            // If at cap and prefix is new, silently drop — bounded state.
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrajectoryStatus {
    Active,
    Dormant,
    Completed,
    Abandoned,
}

impl TrajectoryStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            TrajectoryStatus::Active => "active",
            TrajectoryStatus::Dormant => "dormant",
            TrajectoryStatus::Completed => "completed",
            TrajectoryStatus::Abandoned => "abandoned",
        }
    }
}

impl OntologyObject for Trajectory {
    const OBJECT_TYPE: ObjectType = ObjectType::Trajectory;
    fn id(&self) -> &ObjectId { &self.id }
    fn trajectory_id(&self) -> Option<&ObjectId> { None }
    fn title(&self) -> &str { &self.title }
    fn status_str(&self) -> String { self.status.as_str().into() }
    fn created_at(&self) -> DateTime<Utc> { self.created_at }
    fn last_active(&self) -> DateTime<Utc> { self.last_active }
    fn boundary_confidence(&self) -> Option<f32> { Some(self.boundary_confidence) }
}

// ── Decision ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Decision {
    pub id: ObjectId,
    pub trajectory_id: ObjectId,
    pub title: String,
    pub description: String,
    pub status: DecisionStatus,
    pub superseded_by: Option<ObjectId>,
    pub created_at: DateTime<Utc>,
    pub receipt_refs: Vec<AuditId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionStatus {
    Active,
    Superseded,
    Reverted,
}

impl DecisionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            DecisionStatus::Active => "active",
            DecisionStatus::Superseded => "superseded",
            DecisionStatus::Reverted => "reverted",
        }
    }
}

impl OntologyObject for Decision {
    const OBJECT_TYPE: ObjectType = ObjectType::Decision;
    fn id(&self) -> &ObjectId { &self.id }
    fn trajectory_id(&self) -> Option<&ObjectId> { Some(&self.trajectory_id) }
    fn title(&self) -> &str { &self.title }
    fn status_str(&self) -> String { self.status.as_str().into() }
    fn created_at(&self) -> DateTime<Utc> { self.created_at }
    // Decisions don't have their own last_active — track by created_at.
    // P2+ may add a distinct field if update-timestamp tracking becomes useful.
    fn last_active(&self) -> DateTime<Utc> { self.created_at }
}

// ── Insight ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Insight {
    pub id: ObjectId,
    pub trajectory_id: ObjectId,
    pub title: String,
    pub description: String,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub receipt_refs: Vec<AuditId>,
}

impl OntologyObject for Insight {
    const OBJECT_TYPE: ObjectType = ObjectType::Insight;
    fn id(&self) -> &ObjectId { &self.id }
    fn trajectory_id(&self) -> Option<&ObjectId> { Some(&self.trajectory_id) }
    fn title(&self) -> &str { &self.title }
    // Insights have no lifecycle status; use fixed "recorded".
    fn status_str(&self) -> String { "recorded".into() }
    fn created_at(&self) -> DateTime<Utc> { self.created_at }
    fn last_active(&self) -> DateTime<Utc> { self.created_at }
}

// ── Artifact ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Artifact {
    pub id: ObjectId,
    pub trajectory_id: ObjectId,
    pub title: String,
    pub artifact_type: ArtifactType,
    pub location: String,
    pub author: zp_core::ActorId,
    pub status: ArtifactStatus,
    pub related_decision: Option<ObjectId>,
    pub created_at: DateTime<Utc>,
    pub receipt_refs: Vec<AuditId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactType {
    Code,
    Document,
    Design,
    Spec,
    Config,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactStatus {
    Current,
    Superseded,
    Deprecated,
}

impl ArtifactStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ArtifactStatus::Current => "current",
            ArtifactStatus::Superseded => "superseded",
            ArtifactStatus::Deprecated => "deprecated",
        }
    }
}

impl OntologyObject for Artifact {
    const OBJECT_TYPE: ObjectType = ObjectType::Artifact;
    fn id(&self) -> &ObjectId { &self.id }
    fn trajectory_id(&self) -> Option<&ObjectId> { Some(&self.trajectory_id) }
    fn title(&self) -> &str { &self.title }
    fn status_str(&self) -> String { self.status.as_str().into() }
    fn created_at(&self) -> DateTime<Utc> { self.created_at }
    fn last_active(&self) -> DateTime<Utc> { self.created_at }
}

// ── Friction ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Friction {
    pub id: ObjectId,
    pub trajectory_id: ObjectId,
    pub title: String,
    pub description: String,
    pub severity: FrictionSeverity,
    pub status: FrictionStatus,
    pub occurrences: u32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub workaround: Option<String>,
    pub created_at: DateTime<Utc>,
    pub receipt_refs: Vec<AuditId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrictionSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrictionStatus {
    Active,
    Mitigated,
    Resolved,
}

impl FrictionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            FrictionStatus::Active => "active",
            FrictionStatus::Mitigated => "mitigated",
            FrictionStatus::Resolved => "resolved",
        }
    }
}

impl OntologyObject for Friction {
    const OBJECT_TYPE: ObjectType = ObjectType::Friction;
    fn id(&self) -> &ObjectId { &self.id }
    fn trajectory_id(&self) -> Option<&ObjectId> { Some(&self.trajectory_id) }
    fn title(&self) -> &str { &self.title }
    fn status_str(&self) -> String { self.status.as_str().into() }
    fn created_at(&self) -> DateTime<Utc> { self.created_at }
    fn last_active(&self) -> DateTime<Utc> { self.last_seen }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::derive_trajectory_id;

    fn sample_trajectory() -> Trajectory {
        let id = derive_trajectory_id("hash-abc", r#"{"time_gap":0.6}"#);
        let now = Utc::now();
        Trajectory {
            id,
            title: "Test Trajectory".into(),
            status: TrajectoryStatus::Active,
            boundary_confidence: 0.85,
            parent_id: None,
            tags: vec!["test".into()],
            created_at: now,
            last_active: now,
            receipt_refs: vec![AuditId::new()],
            dominant_conversation_id: ConversationId(uuid::Uuid::nil()),
            seen_conversation_ids: vec![],
            event_prefix_counts: BTreeMap::new(),
        }
    }

    #[test]
    fn trajectory_serde_roundtrip() {
        let t = sample_trajectory();
        let json = serde_json::to_string(&t).unwrap();
        let restored: Trajectory = serde_json::from_str(&json).unwrap();
        assert_eq!(t, restored);
    }

    #[test]
    fn trajectory_trait_implementation() {
        let t = sample_trajectory();
        assert_eq!(Trajectory::OBJECT_TYPE, ObjectType::Trajectory);
        assert_eq!(t.trajectory_id(), None); // Trajectory IS the trajectory
        assert_eq!(t.status_str(), "active");
        assert_eq!(t.boundary_confidence(), Some(0.85));
    }

    #[test]
    fn decision_serde_and_trait() {
        let traj_id = derive_trajectory_id("t", "{}");
        let dec_id = crate::id::derive_object_id(ObjectType::Decision, "receipt-1", "authorize");
        let d = Decision {
            id: dec_id,
            trajectory_id: traj_id,
            title: "Approve X".into(),
            description: "Operator approved capability X".into(),
            status: DecisionStatus::Active,
            superseded_by: None,
            created_at: Utc::now(),
            receipt_refs: vec![],
        };
        let json = serde_json::to_string(&d).unwrap();
        let restored: Decision = serde_json::from_str(&json).unwrap();
        assert_eq!(d, restored);
        assert_eq!(Decision::OBJECT_TYPE, ObjectType::Decision);
        assert_eq!(d.trajectory_id(), Some(&traj_id));
        assert_eq!(d.status_str(), "active");
        assert_eq!(d.boundary_confidence(), None);
    }

    #[test]
    fn insight_status_is_recorded() {
        let traj_id = derive_trajectory_id("t", "{}");
        let ins_id = crate::id::derive_object_id(ObjectType::Insight, "receipt-1", "observe");
        let i = Insight {
            id: ins_id,
            trajectory_id: traj_id,
            title: "Realization".into(),
            description: "Noticed pattern X".into(),
            tags: vec![],
            created_at: Utc::now(),
            receipt_refs: vec![],
        };
        assert_eq!(i.status_str(), "recorded");
        assert_eq!(Insight::OBJECT_TYPE, ObjectType::Insight);
    }

    #[test]
    fn artifact_serde_roundtrip() {
        let traj_id = derive_trajectory_id("t", "{}");
        let art_id = crate::id::derive_object_id(ObjectType::Artifact, "receipt-1", "produce");
        let a = Artifact {
            id: art_id,
            trajectory_id: traj_id,
            title: "Design doc".into(),
            artifact_type: ArtifactType::Spec,
            location: "docs/design/foo.md".into(),
            author: zp_core::ActorId::System("regent".into()),
            status: ArtifactStatus::Current,
            related_decision: None,
            created_at: Utc::now(),
            receipt_refs: vec![],
        };
        let json = serde_json::to_string(&a).unwrap();
        let restored: Artifact = serde_json::from_str(&json).unwrap();
        assert_eq!(a, restored);
        assert_eq!(a.status_str(), "current");
    }

    #[test]
    fn friction_uses_last_seen_for_last_active() {
        let traj_id = derive_trajectory_id("t", "{}");
        let fri_id = crate::id::derive_object_id(ObjectType::Friction, "receipt-1", "block");
        let created = Utc::now();
        let seen_later = created + chrono::Duration::hours(24);
        let f = Friction {
            id: fri_id,
            trajectory_id: traj_id,
            title: "Recurring issue".into(),
            description: "Same problem three times".into(),
            severity: FrictionSeverity::High,
            status: FrictionStatus::Active,
            occurrences: 3,
            first_seen: created,
            last_seen: seen_later,
            workaround: None,
            created_at: created,
            receipt_refs: vec![],
        };
        assert_eq!(f.last_active(), seen_later);
        assert_eq!(f.status_str(), "active");
    }

    #[test]
    fn all_status_enum_string_forms_stable() {
        // Lock in the string forms — these become row column values, changing
        // them silently breaks query filters.
        assert_eq!(TrajectoryStatus::Active.as_str(), "active");
        assert_eq!(TrajectoryStatus::Dormant.as_str(), "dormant");
        assert_eq!(TrajectoryStatus::Completed.as_str(), "completed");
        assert_eq!(TrajectoryStatus::Abandoned.as_str(), "abandoned");
        assert_eq!(DecisionStatus::Active.as_str(), "active");
        assert_eq!(DecisionStatus::Superseded.as_str(), "superseded");
        assert_eq!(DecisionStatus::Reverted.as_str(), "reverted");
        assert_eq!(ArtifactStatus::Current.as_str(), "current");
        assert_eq!(FrictionStatus::Active.as_str(), "active");
        assert_eq!(FrictionStatus::Resolved.as_str(), "resolved");
    }
}
