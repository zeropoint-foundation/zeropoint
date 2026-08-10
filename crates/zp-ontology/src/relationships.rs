//! Ontology relationships — typed directional edges between ontology objects.
//!
//! Per `docs/design/ONTOLOGY-AND-CARTOGRAPHER-2026-07.md` §Relationships.
//!
//! Every relationship traces back to chain entries via `receipt_refs`.
//! The relationship exists because specific receipts justify it — not because
//! an inference model guessed. Deterministic materialization means rebuild
//! produces identical relationships from the same chain.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zp_core::AuditId;

use crate::id::{ObjectId, ObjectType};

/// Directional reference to an ontology object.
///
/// Relationships are typed at both endpoints — a `contributes_to` from an
/// Artifact to a Trajectory has different meaning than the reverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectRef {
    pub object_type: ObjectType,
    pub object_id: ObjectId,
}

impl ObjectRef {
    pub fn new(object_type: ObjectType, object_id: ObjectId) -> Self {
        ObjectRef { object_type, object_id }
    }
}

/// A typed directional edge in the ontology.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Relationship {
    pub id: ObjectId,
    pub source: ObjectRef,
    pub target: ObjectRef,
    pub kind: RelationshipKind,
    pub created_at: DateTime<Utc>,
    pub receipt_refs: Vec<AuditId>,
}

/// The set of typed relationship kinds Cartographer materializes.
///
/// Per parent spec §Relationships. Extension via canonicalization ceremony.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipKind {
    // ── Trajectory relationships ──
    /// Artifact → Trajectory (artifact was produced in service of trajectory)
    ContributesTo,
    /// Decision / Insight / Friction → Trajectory (object belongs to trajectory)
    BelongsTo,
    /// Trajectory → parent Trajectory (nesting)
    SubTrajectoryOf,

    // ── Decision relationships ──
    /// Decision → newer Decision (this decision was superseded)
    SupersededBy,
    /// Decision → prior Decision or Insight (this decision was informed by)
    InfluencedBy,
    /// gate-decision → Delegation-decision (this gate decision was authorized by delegation)
    AuthorizedBy,

    // ── Friction relationships ──
    /// Trajectory → Friction (this trajectory is currently blocked by friction)
    BlockedBy,
    /// Friction → Decision (this friction was addressed by decision)
    MitigatedBy,
    /// Friction → Insight (this insight explains the friction)
    RelatedTo,

    // ── Artifact relationships ──
    /// Artifact → Decision (artifact was produced by decision)
    ProducedBy,
    /// Artifact → Artifact (artifact depends on other artifact)
    DependsOn,
}

impl RelationshipKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            RelationshipKind::ContributesTo => "contributes_to",
            RelationshipKind::BelongsTo => "belongs_to",
            RelationshipKind::SubTrajectoryOf => "sub_trajectory_of",
            RelationshipKind::SupersededBy => "superseded_by",
            RelationshipKind::InfluencedBy => "influenced_by",
            RelationshipKind::AuthorizedBy => "authorized_by",
            RelationshipKind::BlockedBy => "blocked_by",
            RelationshipKind::MitigatedBy => "mitigated_by",
            RelationshipKind::RelatedTo => "related_to",
            RelationshipKind::ProducedBy => "produced_by",
            RelationshipKind::DependsOn => "depends_on",
        }
    }
}

impl Relationship {
    /// Construct a Relationship with a deterministic content-addressed ID
    /// derived from (source, target, kind).
    pub fn new(
        source: ObjectRef,
        target: ObjectRef,
        kind: RelationshipKind,
        receipt_refs: Vec<AuditId>,
    ) -> Self {
        let id = crate::id::derive_relationship_id(
            source.object_type,
            &source.object_id,
            target.object_type,
            &target.object_id,
            kind.as_str(),
        );
        Relationship {
            id,
            source,
            target,
            kind,
            created_at: Utc::now(),
            receipt_refs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::derive_trajectory_id;

    #[test]
    fn relationship_serde_roundtrip() {
        let traj = derive_trajectory_id("t1", "{}");
        let dec = crate::id::derive_object_id(ObjectType::Decision, "r1", "d");
        let r = Relationship::new(
            ObjectRef::new(ObjectType::Trajectory, traj),
            ObjectRef::new(ObjectType::Decision, dec),
            RelationshipKind::BelongsTo,
            vec![AuditId::new()],
        );
        let json = serde_json::to_string(&r).unwrap();
        let restored: Relationship = serde_json::from_str(&json).unwrap();
        assert_eq!(r, restored);
    }

    #[test]
    fn relationship_id_is_deterministic() {
        let traj = derive_trajectory_id("t1", "{}");
        let dec = crate::id::derive_object_id(ObjectType::Decision, "r1", "d");
        let r1 = Relationship::new(
            ObjectRef::new(ObjectType::Trajectory, traj),
            ObjectRef::new(ObjectType::Decision, dec),
            RelationshipKind::BelongsTo,
            vec![],
        );
        let r2 = Relationship::new(
            ObjectRef::new(ObjectType::Trajectory, traj),
            ObjectRef::new(ObjectType::Decision, dec),
            RelationshipKind::BelongsTo,
            vec![],
        );
        assert_eq!(r1.id, r2.id);
    }

    #[test]
    fn kind_string_forms_stable() {
        // Lock in — these values land in the DB as row column values.
        assert_eq!(RelationshipKind::BelongsTo.as_str(), "belongs_to");
        assert_eq!(RelationshipKind::ContributesTo.as_str(), "contributes_to");
        assert_eq!(RelationshipKind::SupersededBy.as_str(), "superseded_by");
        assert_eq!(RelationshipKind::ProducedBy.as_str(), "produced_by");
        assert_eq!(RelationshipKind::DependsOn.as_str(), "depends_on");
        assert_eq!(RelationshipKind::MitigatedBy.as_str(), "mitigated_by");
    }

    #[test]
    fn object_ref_serde_roundtrip() {
        let r = ObjectRef::new(ObjectType::Friction, ObjectId::from_hash_input(b"fri"));
        let json = serde_json::to_string(&r).unwrap();
        let restored: ObjectRef = serde_json::from_str(&json).unwrap();
        assert_eq!(r, restored);
    }
}
