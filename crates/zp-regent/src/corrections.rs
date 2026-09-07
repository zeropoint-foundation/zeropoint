//! Standing corrections — chain-anchored operator claims about Regent's cognitive layer.
//!
//! Standing corrections make operator corrections a persistent trust corpus rather than
//! repeatedly-forgotten instructions. Every cognitive cycle's Tier 1 context includes
//! active standing corrections. Regent's outputs that contradict standing corrections
//! are structurally flagged by Cognitive Self-Observer (P2.2).
//!
//! Spec: `docs/design/STANDING-CORRECTION-RECEIPT-SCHEMA-2026-07.md`
//! Consumed by: Cognitive Input Plane per `docs/design/COGNITIVE-INPUT-PLANE-2026-07.md`
//!              Tier 1 assembly (top priority, chain-anchored persistent state).
//!
//! ## Chain representation
//!
//! Standing corrections are chain-anchored via `SystemEvent { event }` receipts with
//! the event string encoding both the verb prefix and the JSON payload:
//!
//! ```text
//! cognitive:correction:standing {"correction_id":"...","correction_type":"factual",...}
//! ```
//!
//! This is the pragmatic composition with existing chain-query infrastructure
//! (keyword-based `search_chain_by_action_keyword`). Migration path to a dedicated
//! `AuditAction::CognitiveCorrectionIssued { correction }` variant is straightforward
//! once the pattern is proven load-bearing.
//!
//! Revocations use event prefix `cognitive:correction:revoked` referencing a prior
//! correction_id. Supersession is expressed via the `supersedes` field on the new
//! correction rather than a separate event verb.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zp_core::{AuditAction, AuditEntry};

/// The four canonical correction types per spec §"Field specifications".
///
/// Each type has different semantics for how Cognitive Self-Observer treats the
/// correction post-emission (P2.2 territory — this crate only defines the type).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CorrectionType {
    /// Correction about a fact of the world.
    /// Example: "Regent is running Sonnet 4.6, not GLM 5.2."
    Factual,
    /// Correction about scope of Regent's authority or behavior.
    /// Example: "Regent may not initiate credential probing tasks."
    Boundary,
    /// Correction about what Regent should not do.
    /// Example: "Do not narrate day-shape on your own initiative."
    Prohibition,
    /// Correction about operator preference for Regent behavior.
    /// Example: "Prefer 'current state' vs 'stated destination' framing."
    Preference,
}

/// Which cognitive-context classes and output surfaces a correction applies to.
///
/// Enables narrow scoping — a prohibition on day-shape narration can apply to
/// `chat` and `dashboard_display` surfaces but not to internal-reasoning receipts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrectionScope {
    /// Cognitive context classes this correction applies to.
    /// Examples: `regent.dispatch_response`, `regent.narration.operator_facing`,
    /// `regent.narration.internal`, `officer.*`, `dashboard.copy`.
    /// Empty vec is treated as "applies to all classes".
    #[serde(default)]
    pub applies_to: Vec<String>,
    /// Output surfaces this correction affects.
    /// Examples: `chat`, `receipt_content`, `dashboard_display`, `narration_stream`.
    /// Empty vec is treated as "applies to all surfaces".
    #[serde(default)]
    pub surface: Vec<String>,
}

impl CorrectionScope {
    /// A scope that applies broadly with no narrowing hints.
    pub fn broad() -> Self {
        Self {
            applies_to: Vec::new(),
            surface: Vec::new(),
        }
    }

    /// Returns true if this scope matches the given context class + surface hints.
    /// Empty scope fields are treated as wildcards.
    pub fn matches(&self, applies_to: &str, surface: &str) -> bool {
        let class_match = self.applies_to.is_empty()
            || self.applies_to.iter().any(|c| c == applies_to || c == "*");
        let surface_match =
            self.surface.is_empty() || self.surface.iter().any(|s| s == surface || s == "*");
        class_match && surface_match
    }
}

/// The correction content itself — the "what is authoritative, what is not".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrectionContent {
    /// What is authoritative (the operator's claim).
    pub assertion: String,
    /// What Regent should not claim (optional negation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub negation: Option<String>,
    /// Why this correction exists (optional context).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
}

/// A standing correction receipt as issued by the operator.
///
/// Chain-anchored via `SystemEvent { event: "cognitive:correction:standing {json}" }`.
/// See module docs for the encoding rationale.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StandingCorrection {
    /// Content-derived stable identifier for supersession + revocation references.
    pub correction_id: String,
    /// When the correction was issued.
    pub issued_at: DateTime<Utc>,
    /// Operator's Genesis public key that authored this correction.
    pub issued_by: String,
    /// Correction type — factual / boundary / prohibition / preference.
    pub correction_type: CorrectionType,
    /// Hierarchical domain string for lookup and conflict detection.
    /// Examples: `cognitive.self_reference.model_state`,
    ///           `cognitive.narration.tone.day_shape`,
    ///           `cognitive.boundary.credential_probing`.
    pub domain: String,
    /// Scope narrowing hints.
    pub scope: CorrectionScope,
    /// The correction itself.
    pub content: CorrectionContent,
    /// Priority for Tier 1 assembly (higher = more prominent).
    /// Default scale: 100=existential, 50-99=high, 10-49=moderate, 1-9=soft.
    pub priority: u32,
    /// Optional expiry timestamp; most corrections have no expiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry: Option<DateTime<Utc>>,
    /// Correction IDs this receipt supersedes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supersedes: Vec<String>,
}

impl StandingCorrection {
    /// Encode as the event string for a `SystemEvent { event }` chain entry.
    /// Format: `cognitive:correction:standing {json}` (single space separator).
    pub fn to_event_string(&self) -> String {
        // Unwrap is fine — the struct only contains serializable primitives.
        let json =
            serde_json::to_string(self).expect("StandingCorrection JSON serialization cannot fail");
        format!("{} {}", EVENT_PREFIX_STANDING, json)
    }

    /// Parse a `StandingCorrection` from an event string.
    /// Returns `None` if the string doesn't start with the standing-correction prefix
    /// or the JSON tail is malformed.
    pub fn from_event_string(event: &str) -> Option<Self> {
        let tail = event.strip_prefix(EVENT_PREFIX_STANDING)?.trim_start();
        serde_json::from_str(tail).ok()
    }

    /// Returns true if the correction is currently within its lifetime
    /// (issued in the past, not expired).
    pub fn is_time_active(&self, now: DateTime<Utc>) -> bool {
        if self.issued_at > now {
            return false;
        }
        match self.expiry {
            Some(exp) => exp > now,
            None => true,
        }
    }
}

/// Event prefix for a standing-correction issuance receipt.
pub const EVENT_PREFIX_STANDING: &str = "cognitive:correction:standing";

/// Event prefix for a standing-correction revocation receipt.
pub const EVENT_PREFIX_REVOKED: &str = "cognitive:correction:revoked";

/// Compose the event string for a revocation receipt.
/// Format: `cognitive:correction:revoked {"correction_id":"...","revoked_at":"..."}`
pub fn revocation_event_string(correction_id: &str, revoked_at: DateTime<Utc>) -> String {
    let payload = serde_json::json!({
        "correction_id": correction_id,
        "revoked_at": revoked_at.to_rfc3339(),
    });
    format!("{} {}", EVENT_PREFIX_REVOKED, payload)
}

/// Extract a correction_id from a revocation event string.
pub fn parse_revocation(event: &str) -> Option<String> {
    let tail = event.strip_prefix(EVENT_PREFIX_REVOKED)?.trim_start();
    let v: serde_json::Value = serde_json::from_str(tail).ok()?;
    v.get("correction_id")?.as_str().map(String::from)
}

/// An active standing correction — post-supersession, post-revocation, post-expiry filtering.
///
/// Wraps the raw correction with a reference to the chain entry it was loaded from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveStandingCorrection {
    /// The correction content.
    pub correction: StandingCorrection,
    /// Chain entry hash that carried this correction.
    pub entry_hash: String,
}

/// In-memory index of active standing corrections.
///
/// Built fresh from chain state at cognitive-cycle assembly. Supports the four
/// query patterns from the spec §"Storage and query":
///   - Domain-indexed lookup
///   - Scope-indexed lookup
///   - Priority-sorted retrieval
///   - Recency-sorted retrieval
///
/// The index does not persist beyond a cycle — chain is truth; index is a
/// derived view rebuilt per assembly.
#[derive(Debug, Clone, Default)]
pub struct CorrectionIndex {
    active: Vec<ActiveStandingCorrection>,
    /// Domain string → indices into `active` (multiple corrections per domain possible).
    by_domain: HashMap<String, Vec<usize>>,
}

impl CorrectionIndex {
    /// Build an empty index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build an index from a set of chain entries, applying:
    ///   1. Filter for standing-correction issuance events
    ///   2. Supersession — if a correction is superseded by a later one, drop it
    ///   3. Revocation — if a correction is revoked, drop it
    ///   4. Expiry — if a correction has expired at `now`, drop it
    ///   5. Time validity — if issued_at is in the future, drop it
    ///
    /// Entries can be provided in any order — the loader sorts by timestamp before
    /// applying supersession semantics.
    pub fn build(entries: &[AuditEntry], now: DateTime<Utc>) -> Self {
        // Collect all issuance and revocation events with their chain metadata.
        let mut issuances: Vec<(StandingCorrection, String, DateTime<Utc>)> = Vec::new();
        let mut revocations: Vec<String> = Vec::new();

        for entry in entries {
            let AuditAction::SystemEvent { event } = &entry.action else {
                continue;
            };
            if let Some(correction) = StandingCorrection::from_event_string(event) {
                issuances.push((correction, entry.entry_hash.clone(), entry.timestamp));
            } else if let Some(revoked_id) = parse_revocation(event) {
                revocations.push(revoked_id);
            }
        }

        // Sort issuances by timestamp ascending so later-timestamp corrections
        // supersede earlier ones per the spec's chronological semantics.
        issuances.sort_by_key(|(_, _, ts)| *ts);

        // Track superseded IDs. A correction that supersedes another marks the
        // older one as inactive regardless of the newer one's own active state.
        let mut superseded_ids: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        for (correction, _, _) in &issuances {
            for prior_id in &correction.supersedes {
                superseded_ids.insert(prior_id.clone());
            }
        }

        // Deduplicate by correction_id — keep the most recent issuance for each id
        // (re-issuance of the same content_hash id is idempotent but timestamps
        // should be the latest).
        let mut by_id: HashMap<String, (StandingCorrection, String)> = HashMap::new();
        for (correction, entry_hash, _) in issuances {
            by_id.insert(correction.correction_id.clone(), (correction, entry_hash));
        }

        // Convert revocations into a set for O(1) lookup.
        let revoked_set: std::collections::HashSet<String> = revocations.into_iter().collect();

        // Apply supersession, revocation, and expiry filters.
        let mut active: Vec<ActiveStandingCorrection> = Vec::new();
        for (id, (correction, entry_hash)) in by_id {
            if superseded_ids.contains(&id) {
                continue;
            }
            if revoked_set.contains(&id) {
                continue;
            }
            if !correction.is_time_active(now) {
                continue;
            }
            active.push(ActiveStandingCorrection {
                correction,
                entry_hash,
            });
        }

        // Sort active corrections by priority descending, then by issued_at descending
        // for stable ordering. Priority sort is the primary Tier 1 assembly interest.
        active.sort_by(|a, b| {
            b.correction
                .priority
                .cmp(&a.correction.priority)
                .then_with(|| b.correction.issued_at.cmp(&a.correction.issued_at))
        });

        // Build the domain index.
        let mut by_domain: HashMap<String, Vec<usize>> = HashMap::new();
        for (idx, entry) in active.iter().enumerate() {
            by_domain
                .entry(entry.correction.domain.clone())
                .or_default()
                .push(idx);
        }

        Self { active, by_domain }
    }

    /// Total count of active corrections.
    pub fn len(&self) -> usize {
        self.active.len()
    }

    /// True if no corrections are active.
    pub fn is_empty(&self) -> bool {
        self.active.is_empty()
    }

    /// All active corrections in priority-descending order.
    pub fn all(&self) -> &[ActiveStandingCorrection] {
        &self.active
    }

    /// Top-K corrections by priority (descending).
    /// Used by Tier 1 assembly to bound context window impact.
    pub fn top_k_by_priority(&self, k: usize) -> Vec<&ActiveStandingCorrection> {
        self.active.iter().take(k).collect()
    }

    /// Corrections matching the given cognitive-context class and output surface.
    /// Empty-scope corrections match all contexts (wildcard semantics).
    pub fn matching_scope(
        &self,
        applies_to: &str,
        surface: &str,
    ) -> Vec<&ActiveStandingCorrection> {
        self.active
            .iter()
            .filter(|c| c.correction.scope.matches(applies_to, surface))
            .collect()
    }

    /// Corrections in the given domain (exact match).
    pub fn by_domain(&self, domain: &str) -> Vec<&ActiveStandingCorrection> {
        self.by_domain
            .get(domain)
            .map(|indices| indices.iter().filter_map(|i| self.active.get(*i)).collect())
            .unwrap_or_default()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use zp_core::{ActorId, AuditId, ConversationId, PolicyDecision};

    fn mock_entry(event: &str, timestamp: DateTime<Utc>) -> AuditEntry {
        AuditEntry {
            id: AuditId::new(),
            timestamp,
            prev_hash: "prev".into(),
            entry_hash: format!("hash-{}", timestamp.timestamp_nanos_opt().unwrap_or(0)),
            actor: ActorId::Operator,
            action: AuditAction::SystemEvent {
                event: event.to_string(),
            },
            conversation_id: ConversationId(uuid::Uuid::nil()),
            policy_decision: PolicyDecision::Allow {
                conditions: Vec::new(),
            },
            policy_module: "test".into(),
            receipt: None,
            signatures: Vec::new(),
        }
    }

    fn mock_correction(id: &str, priority: u32, issued_at: DateTime<Utc>) -> StandingCorrection {
        StandingCorrection {
            correction_id: id.to_string(),
            issued_at,
            issued_by: "operator-pubkey".to_string(),
            correction_type: CorrectionType::Factual,
            domain: format!("test.{}", id),
            scope: CorrectionScope::broad(),
            content: CorrectionContent {
                assertion: format!("Assertion for {}", id),
                negation: None,
                context: None,
            },
            priority,
            expiry: None,
            supersedes: Vec::new(),
        }
    }

    #[test]
    fn event_string_roundtrip_preserves_correction() {
        let now = Utc::now();
        let correction = mock_correction("c1", 50, now);
        let event = correction.to_event_string();
        assert!(event.starts_with(EVENT_PREFIX_STANDING));
        let parsed = StandingCorrection::from_event_string(&event)
            .expect("roundtrip should decode successfully");
        assert_eq!(parsed.correction_id, "c1");
        assert_eq!(parsed.priority, 50);
    }

    #[test]
    fn event_string_rejects_wrong_prefix() {
        assert!(StandingCorrection::from_event_string("some:other:event {\"foo\":1}").is_none());
    }

    #[test]
    fn event_string_rejects_malformed_json() {
        let event = format!("{} not json", EVENT_PREFIX_STANDING);
        assert!(StandingCorrection::from_event_string(&event).is_none());
    }

    #[test]
    fn revocation_event_roundtrip() {
        let now = Utc::now();
        let event = revocation_event_string("c-target", now);
        assert!(event.starts_with(EVENT_PREFIX_REVOKED));
        assert_eq!(parse_revocation(&event).as_deref(), Some("c-target"));
    }

    #[test]
    fn index_loads_active_corrections() {
        let now = Utc::now();
        let c1 = mock_correction("c1", 50, now - chrono::Duration::hours(2));
        let c2 = mock_correction("c2", 80, now - chrono::Duration::hours(1));
        let entries = vec![
            mock_entry(&c1.to_event_string(), c1.issued_at),
            mock_entry(&c2.to_event_string(), c2.issued_at),
        ];
        let index = CorrectionIndex::build(&entries, now);
        assert_eq!(index.len(), 2);
        // Sorted by priority descending — c2 (priority 80) should come first.
        assert_eq!(index.all()[0].correction.correction_id, "c2");
        assert_eq!(index.all()[1].correction.correction_id, "c1");
    }

    #[test]
    fn index_drops_superseded_corrections() {
        let now = Utc::now();
        let c_v1 = mock_correction("c-v1", 50, now - chrono::Duration::hours(2));
        let mut c_v2 = mock_correction("c-v2", 50, now - chrono::Duration::hours(1));
        c_v2.supersedes = vec!["c-v1".to_string()];

        let entries = vec![
            mock_entry(&c_v1.to_event_string(), c_v1.issued_at),
            mock_entry(&c_v2.to_event_string(), c_v2.issued_at),
        ];
        let index = CorrectionIndex::build(&entries, now);
        assert_eq!(index.len(), 1);
        assert_eq!(index.all()[0].correction.correction_id, "c-v2");
    }

    #[test]
    fn index_drops_revoked_corrections() {
        let now = Utc::now();
        let c1 = mock_correction("c1", 50, now - chrono::Duration::hours(2));
        let revocation_event = revocation_event_string("c1", now - chrono::Duration::minutes(30));

        let entries = vec![
            mock_entry(&c1.to_event_string(), c1.issued_at),
            mock_entry(&revocation_event, now - chrono::Duration::minutes(30)),
        ];
        let index = CorrectionIndex::build(&entries, now);
        assert!(
            index.is_empty(),
            "revoked correction must not appear in index"
        );
    }

    #[test]
    fn index_drops_expired_corrections() {
        let now = Utc::now();
        let mut c1 = mock_correction("c1", 50, now - chrono::Duration::hours(2));
        c1.expiry = Some(now - chrono::Duration::hours(1));

        let entries = vec![mock_entry(&c1.to_event_string(), c1.issued_at)];
        let index = CorrectionIndex::build(&entries, now);
        assert!(
            index.is_empty(),
            "expired correction must not appear in index"
        );
    }

    #[test]
    fn index_drops_future_dated_corrections() {
        let now = Utc::now();
        let future_correction = mock_correction("c-future", 50, now + chrono::Duration::hours(1));

        let entries = vec![mock_entry(
            &future_correction.to_event_string(),
            future_correction.issued_at,
        )];
        let index = CorrectionIndex::build(&entries, now);
        assert!(
            index.is_empty(),
            "future-dated correction must not be active yet"
        );
    }

    #[test]
    fn top_k_by_priority_returns_highest_first_and_bounds_length() {
        let now = Utc::now();
        let entries: Vec<AuditEntry> = (0..10u32)
            .map(|i| {
                let c = mock_correction(
                    &format!("c{}", i),
                    i * 10,
                    now - chrono::Duration::minutes((10 - i as i64) * 5),
                );
                mock_entry(&c.to_event_string(), c.issued_at)
            })
            .collect();

        let index = CorrectionIndex::build(&entries, now);
        let top3 = index.top_k_by_priority(3);
        assert_eq!(top3.len(), 3);
        assert_eq!(top3[0].correction.priority, 90);
        assert_eq!(top3[1].correction.priority, 80);
        assert_eq!(top3[2].correction.priority, 70);
    }

    #[test]
    fn scope_matching_wildcards_and_narrow_scoping() {
        let now = Utc::now();
        let mut broad = mock_correction("broad", 50, now - chrono::Duration::hours(2));
        broad.scope = CorrectionScope::broad();

        let mut narrow = mock_correction("narrow", 50, now - chrono::Duration::hours(1));
        narrow.scope = CorrectionScope {
            applies_to: vec!["regent.narration.operator_facing".to_string()],
            surface: vec!["chat".to_string()],
        };

        let entries = vec![
            mock_entry(&broad.to_event_string(), broad.issued_at),
            mock_entry(&narrow.to_event_string(), narrow.issued_at),
        ];
        let index = CorrectionIndex::build(&entries, now);

        // Both should match the specific scope the narrow correction targets.
        let matches_narrow_scope = index.matching_scope("regent.narration.operator_facing", "chat");
        assert_eq!(matches_narrow_scope.len(), 2);

        // Only the broad correction should match a different specific scope.
        let matches_different =
            index.matching_scope("regent.narration.internal", "receipt_content");
        assert_eq!(matches_different.len(), 1);
        assert_eq!(matches_different[0].correction.correction_id, "broad");
    }

    #[test]
    fn by_domain_returns_all_matching_corrections() {
        let now = Utc::now();
        let mut a1 = mock_correction("a1", 50, now - chrono::Duration::hours(3));
        a1.domain = "cognitive.narration.tone".to_string();
        let mut a2 = mock_correction("a2", 40, now - chrono::Duration::hours(2));
        a2.domain = "cognitive.narration.tone".to_string();
        let mut b = mock_correction("b", 30, now - chrono::Duration::hours(1));
        b.domain = "cognitive.self_reference.model_state".to_string();

        let entries = vec![
            mock_entry(&a1.to_event_string(), a1.issued_at),
            mock_entry(&a2.to_event_string(), a2.issued_at),
            mock_entry(&b.to_event_string(), b.issued_at),
        ];
        let index = CorrectionIndex::build(&entries, now);

        let tone_matches = index.by_domain("cognitive.narration.tone");
        assert_eq!(tone_matches.len(), 2);
        let model_matches = index.by_domain("cognitive.self_reference.model_state");
        assert_eq!(model_matches.len(), 1);
        assert_eq!(model_matches[0].correction.correction_id, "b");
    }

    #[test]
    fn non_correction_entries_are_ignored() {
        let now = Utc::now();
        let entries = vec![
            mock_entry(
                "regent:tool:completed:something",
                now - chrono::Duration::hours(1),
            ),
            mock_entry(
                "officer:std:integrity:chain_link_broken",
                now - chrono::Duration::hours(1),
            ),
        ];
        let index = CorrectionIndex::build(&entries, now);
        assert!(index.is_empty());
    }
}
