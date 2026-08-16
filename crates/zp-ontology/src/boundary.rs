//! Boundary detection — the Tier 1 algorithm that decides which receipts
//! belong to which Trajectory.
//!
//! Per `docs/design/CARTOGRAPHER-IMPLEMENTATION-DESIGN-2026-07.md` §Section 1.
//!
//! ## P2 scope
//!
//! This module implements three of the five signals plus the confidence fusion
//! formula. The three P2 signals are the ones that require no ontology-side
//! context beyond a single trajectory's summary state:
//!
//! - **S1 — Conversation continuity** (per-receipt structural signal)
//! - **S2 — Time gap** (per-receipt temporal signal)
//! - **S5 — Explicit markers** (operator or cockpit-emitted receipts with
//!   `ontology:trajectory:started` / `ended` / `continued` events)
//!
//! Deferred to P4:
//!
//! - **S3 — Actor transition** (requires tracking dominant-actor distribution)
//! - **S4 — Domain clustering** (requires tracking event-prefix distribution)
//! - **Resumption from dormancy** (requires dormant-trajectory index)
//!
//! ## Determinism
//!
//! All signal scoring is pure over `(receipt, trajectory_context, config)`.
//! Given identical inputs, `evaluate_boundary` always returns identical
//! output — the load-bearing property that enables rebuild-consistent IDs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zp_core::ConversationId;

// ── Config ─────────────────────────────────────────────────────────────────

/// Runtime-tunable boundary-detection parameters.
///
/// Defaults from `CARTOGRAPHER-IMPLEMENTATION-DESIGN-2026-07.md` §Section 1.
/// Empirical tuning phase (per P4) will adjust these against real substrate
/// chain data.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct BoundaryConfig {
    /// Below this fused score, no boundary declared (continuity assumed).
    pub boundary_threshold: f32,

    /// Scales fused score into 0.0-1.0 confidence.
    pub confidence_scale: f32,

    /// Trajectory receipt count above which "never-before-seen conversation_id"
    /// becomes a boundary signal (before capacity, it's exploration).
    pub s1_capacity_threshold: u32,

    /// Time thresholds in seconds for S2 signal bucketing.
    pub s2_short_secs: i64,
    pub s2_medium_secs: i64,
    pub s2_long_secs: i64,
    pub s2_dormant_secs: i64,
    pub s2_extended_dormancy_secs: i64,

    /// Trajectory receipt-count cap — when a trajectory reaches this many
    /// receipts, the next receipt forces a boundary regardless of signal
    /// scores. Prevents unbounded trajectories on chatty substrate chains
    /// where the signal-based boundary detection may not fire (per 2026-08
    /// empirical finding: 10K+ receipts merged into 1 trajectory when S2
    /// time-gap continuity dominates).
    ///
    /// Set to 0 to disable cadence-forcing.
    pub trajectory_receipt_cap: u32,
}

impl Default for BoundaryConfig {
    fn default() -> Self {
        BoundaryConfig {
            boundary_threshold: 0.5,
            confidence_scale: 1.5,
            s1_capacity_threshold: 20,
            s2_short_secs: 300,                 // 5 min
            s2_medium_secs: 3600,               // 1 hr
            s2_long_secs: 14_400,               // 4 hr
            s2_dormant_secs: 86_400,            // 24 hr
            s2_extended_dormancy_secs: 604_800, // 7 days
            trajectory_receipt_cap: 250,        // per 2026-08 empirical recalibration
        }
    }
}

// ── Trajectory context ─────────────────────────────────────────────────────

/// Minimal state a boundary-signal computation needs from the current trajectory.
///
/// Kept narrow so signal functions are testable without materializing a full
/// Trajectory. Cartographer populates this from the trajectory being extended.
#[derive(Debug, Clone, PartialEq)]
pub struct TrajectoryContext {
    /// Immediately-preceding receipt's conversation_id, treated as trajectory's
    /// dominant per design doc §Section 1 P4-simplification note.
    pub dominant_conversation_id: ConversationId,

    /// True if the trajectory has ever contained receipts from more than one
    /// distinct conversation_id (signals multi-conversation history).
    pub multi_conversation_history: bool,

    /// Timestamp of the trajectory's most recent activity.
    pub last_active: DateTime<Utc>,

    /// How many receipts have been assigned to this trajectory so far.
    pub receipt_count: u32,

    /// Dominant event prefix (highest-count of first-two colon-segments)
    /// in the trajectory. Used by S4 domain-clustering signal.
    /// None if trajectory has no SystemEvent receipts yet.
    pub dominant_event_prefix: Option<String>,

    /// Top-3 event prefixes by count. Used by S4 to check if a new receipt's
    /// prefix is "in the trajectory's distribution" vs completely foreign.
    pub top_prefixes: Vec<String>,
}

// ── Boundary input (per-receipt) ───────────────────────────────────────────

/// Minimal per-receipt data boundary detection needs.
///
/// Decoupled from full AuditEntry so signal computation is testable without
/// constructing the full chain-receipt type. Cartographer projects each
/// receipt into this shape at ingestion time.
#[derive(Debug, Clone, PartialEq)]
pub struct BoundaryInput {
    pub conversation_id: ConversationId,
    pub timestamp: DateTime<Utc>,
    /// The receipt's SystemEvent event string, if applicable.
    /// Used for explicit-marker detection. Non-SystemEvent receipts pass None.
    pub event: Option<String>,
}

// ── Signal outputs ─────────────────────────────────────────────────────────

/// Per-signal score contributions for a single boundary evaluation.
///
/// Serializable for chain-anchored evidence in `ontology:trajectory:created`
/// receipts. Also used as input to canonical ID derivation via
/// `canonicalize_boundary_signals`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct BoundarySignals {
    pub conversation: f32,
    pub time_gap: f32,
    /// P4 addition: domain-clustering signal (S4). Non-optional at rest —
    /// defaults to 0.0 (neutral) when trajectory has no event-prefix history.
    #[serde(default)]
    pub domain: f32,
    pub explicit_marker: Option<f32>,
}

impl BoundarySignals {
    /// Sum non-marker signals into raw fusion score. Explicit markers are
    /// veto-only and handled separately (not summed).
    pub fn raw_score(&self) -> f32 {
        self.conversation + self.time_gap + self.domain
    }
}

/// Result of a boundary evaluation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BoundaryDecision {
    /// The receipt continues the current trajectory. Confidence is 0.0-1.0
    /// (how confident we are that it's continuity, not a missed boundary).
    ContinueTrajectory {
        confidence: f32,
        signals: BoundarySignals,
    },
    /// The receipt starts a new trajectory. Confidence is 0.0-1.0.
    NewTrajectory {
        confidence: f32,
        signals: BoundarySignals,
        reason: BoundaryReason,
    },
}

/// Why a boundary was declared. Useful for operator inspection and for
/// chain-anchored evidence in the `ontology:trajectory:created` receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryReason {
    /// Fused signal score crossed the boundary threshold.
    FusedSignalThreshold,
    /// Operator/cockpit emitted `ontology:trajectory:started` (definitive).
    ExplicitStartMarker,
    /// Operator/cockpit emitted `ontology:trajectory:ended` (definitive).
    ExplicitEndMarker,
    /// Trajectory reached configured receipt-count cap — cadence-forced
    /// boundary regardless of signal scores. Prevents unbounded trajectory
    /// growth on chatty substrate chains per 2026-08 empirical recalibration.
    ReceiptCountCap,
}

// ── Signal computations (S1, S2, S5) ───────────────────────────────────────

/// S1 — Conversation continuity signal.
///
/// Compares receipt's conversation_id to the trajectory's dominant. Scores:
/// - Same as dominant: -0.6 (strong continuity)
/// - Different, multi-conversation trajectory: -0.2 (weak continuity)
/// - Different, single-conversation trajectory below capacity: +0.3 (weak boundary)
/// - Different, single-conversation trajectory at/above capacity: +0.5 (medium boundary)
pub fn signal_conversation_continuity(
    input: &BoundaryInput,
    ctx: &TrajectoryContext,
    config: &BoundaryConfig,
) -> f32 {
    if input.conversation_id == ctx.dominant_conversation_id {
        -0.6
    } else if ctx.multi_conversation_history {
        -0.2
    } else if ctx.receipt_count >= config.s1_capacity_threshold {
        0.5
    } else {
        0.3
    }
}

/// S2 — Time gap signal.
///
/// Compares receipt's timestamp to trajectory's last_active. Six buckets from
/// the design doc; strong continuity when very recent, strong boundary when
/// extended dormancy. Negative timestamps (receipt before trajectory's
/// last_active — should not happen with rowid-ordered processing but handled
/// defensively) treated as zero gap.
pub fn signal_time_gap(
    input: &BoundaryInput,
    ctx: &TrajectoryContext,
    config: &BoundaryConfig,
) -> f32 {
    let gap_secs = (input.timestamp - ctx.last_active).num_seconds().max(0);
    // Continuity strengths downweighted per 2026-08 empirical finding:
    // substrate chains have continuous background activity (canary 60s,
    // officer heartbeats 15min), so recent-gap continuity was drowning
    // out every other signal. Boundary buckets (positive) unchanged —
    // dormancy is still a strong signal when it happens.
    if gap_secs < config.s2_short_secs {
        -0.2 // was -0.4
    } else if gap_secs < config.s2_medium_secs {
        -0.05 // was -0.1
    } else if gap_secs < config.s2_long_secs {
        0.0
    } else if gap_secs < config.s2_dormant_secs {
        0.2
    } else if gap_secs < config.s2_extended_dormancy_secs {
        0.4
    } else {
        0.6
    }
}

/// S5 — Explicit marker signal.
///
/// Returns Some(±1.0) if the receipt is an operator/cockpit-emitted trajectory
/// marker; None otherwise. When Some, the value veto-overrides all other
/// signals per the confidence-fusion algorithm.
///
/// Event patterns matched:
/// - `ontology:trajectory:started[:*]` → Some(+1.0) — definitive boundary
/// - `ontology:trajectory:ended[:*]` → Some(+1.0) — definitive boundary
/// - `ontology:trajectory:continued[:*]` → Some(-1.0) — definitive continuity
pub fn signal_explicit_marker(input: &BoundaryInput) -> Option<f32> {
    let event = input.event.as_deref()?;
    if event.starts_with("ontology:trajectory:started")
        || event.starts_with("ontology:trajectory:ended")
    {
        Some(1.0)
    } else if event.starts_with("ontology:trajectory:continued") {
        Some(-1.0)
    } else {
        None
    }
}

/// Classify the explicit-marker kind (start vs end vs continue) for
/// downstream boundary-reason attribution. Returns None if not a marker.
pub fn classify_explicit_marker(input: &BoundaryInput) -> Option<ExplicitMarkerKind> {
    let event = input.event.as_deref()?;
    if event.starts_with("ontology:trajectory:started") {
        Some(ExplicitMarkerKind::Start)
    } else if event.starts_with("ontology:trajectory:ended") {
        Some(ExplicitMarkerKind::End)
    } else if event.starts_with("ontology:trajectory:continued") {
        Some(ExplicitMarkerKind::Continue)
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExplicitMarkerKind {
    Start,
    End,
    Continue,
}

// ── S4 — Domain clustering signal ─────────────────────────────────────────

/// Extract the event prefix from an event string.
///
/// The prefix is the first two colon-separated segments. Examples:
/// - `"officer:std:heartbeat"` → `"officer:std"`
/// - `"delegation:granted:foo"` → `"delegation:granted"`
/// - `"chain:canary:written"` → `"chain:canary"`
/// - `"system:startup"` → `"system:startup"` (only 2 segments total)
/// - `"single_word"` → `"single_word"` (< 2 segments — return as-is)
pub fn extract_event_prefix(event: &str) -> String {
    event.split(':').take(2).collect::<Vec<_>>().join(":")
}

/// Extract just the top-level namespace (first colon-segment) from an event.
/// Used by S4 to compare across trajectories with different prefix mixes.
fn top_level_namespace(event_prefix: &str) -> &str {
    event_prefix.split(':').next().unwrap_or(event_prefix)
}

/// S4 — Domain clustering signal.
///
/// Compares receipt's event prefix to the trajectory's dominant + top-3.
/// Scores per design doc §Section 1:
/// - Exact match with dominant: -0.3 (strong continuity)
/// - In top-3 distribution: -0.1 (weak continuity)
/// - Different prefix but same top-level namespace: 0.0 (neutral)
/// - Different top-level namespace than any tracked: +0.4 (medium boundary)
///
/// Receipts without SystemEvent (e.g., ToolInvocation) return 0.0 (neutral —
/// no domain signal to contribute).
pub fn signal_domain_clustering(input: &BoundaryInput, ctx: &TrajectoryContext) -> f32 {
    let event = match &input.event {
        Some(e) => e,
        None => return 0.0, // non-SystemEvent → no domain contribution
    };
    let input_prefix = extract_event_prefix(event);

    // Case 1: exact match with dominant prefix — strong continuity.
    if Some(&input_prefix) == ctx.dominant_event_prefix.as_ref() {
        return -0.3;
    }

    // Case 2: match with any prefix in top-3 distribution — weak continuity.
    if ctx.top_prefixes.iter().any(|p| p == &input_prefix) {
        return -0.1;
    }

    // Case 3: different prefix but same top-level namespace as ANY tracked.
    // Bumped from 0.0 to +0.3 per 2026-08 empirical recalibration —
    // sub-domain shifts within a namespace are genuine boundary signals
    // (e.g., officer:std run followed by officer:cleo run).
    let input_ns = top_level_namespace(&input_prefix);
    let namespace_match = ctx
        .top_prefixes
        .iter()
        .any(|p| top_level_namespace(p) == input_ns);
    if namespace_match {
        return 0.3;
    }

    // Case 4: completely foreign top-level namespace — strong boundary.
    // Bumped from +0.4 to +0.8 per 2026-08 empirical finding — namespace
    // shifts are the load-bearing boundary signal for substrate chains.
    0.8
}

// ── Fusion ─────────────────────────────────────────────────────────────────

/// Compute all P2 signals and fuse into a boundary decision.
///
/// Per design doc §Section 1 §Confidence fusion:
/// 1. Explicit markers pre-empt with definitive ±1.0
/// 2. Otherwise, sum S1+S2, compare to threshold
///
/// The returned decision includes the raw signal set for chain-anchoring
/// and downstream operator inspection.
pub fn evaluate_boundary(
    input: &BoundaryInput,
    ctx: &TrajectoryContext,
    config: &BoundaryConfig,
) -> BoundaryDecision {
    let s1 = signal_conversation_continuity(input, ctx, config);
    let s2 = signal_time_gap(input, ctx, config);
    let s4 = signal_domain_clustering(input, ctx);
    let s5 = signal_explicit_marker(input);

    let signals = BoundarySignals {
        conversation: s1,
        time_gap: s2,
        domain: s4,
        explicit_marker: s5,
    };

    // Step 0: cadence-forced boundary. If the trajectory has grown past
    // the configured cap, force a boundary regardless of signal scores.
    // Prevents unbounded trajectory growth on chatty substrate chains
    // where signal-based detection may never fire. Explicit markers still
    // pre-empt (step 1) — operator continuity vetoes still win.
    if config.trajectory_receipt_cap > 0
        && ctx.receipt_count >= config.trajectory_receipt_cap
        && s5 != Some(-1.0)
    {
        return BoundaryDecision::NewTrajectory {
            confidence: 1.0,
            signals,
            reason: BoundaryReason::ReceiptCountCap,
        };
    }

    // Step 1: check for definitive markers (veto everything else).
    if let Some(marker_score) = s5 {
        if marker_score >= 1.0 {
            let reason = match classify_explicit_marker(input) {
                Some(ExplicitMarkerKind::Start) => BoundaryReason::ExplicitStartMarker,
                Some(ExplicitMarkerKind::End) => BoundaryReason::ExplicitEndMarker,
                // classify_explicit_marker None branch only reachable if s5
                // was Some(+1.0) but classification returned None — impossible
                // per implementation coherence. Defensive fallback.
                _ => BoundaryReason::ExplicitStartMarker,
            };
            return BoundaryDecision::NewTrajectory {
                confidence: 1.0,
                signals,
                reason,
            };
        }
        if marker_score <= -1.0 {
            return BoundaryDecision::ContinueTrajectory {
                confidence: 1.0,
                signals,
            };
        }
    }

    // Step 2: threshold + confidence formula on fused non-marker score.
    let raw = signals.raw_score();
    if raw >= config.boundary_threshold {
        let confidence = (raw / config.confidence_scale).min(1.0);
        BoundaryDecision::NewTrajectory {
            confidence,
            signals,
            reason: BoundaryReason::FusedSignalThreshold,
        }
    } else {
        // Confidence in continuity is inverse — the more negative the raw
        // score, the more confident we are in continuity.
        // Map raw in [threshold, -infinity) → confidence in [0, 1].
        // Simplest: confidence = 1.0 - min(max(raw, 0.0) / scale, 1.0),
        // which gives 1.0 for raw <= 0, decreasing toward 0 as raw approaches
        // threshold from below.
        let confidence = 1.0 - (raw.max(0.0) / config.confidence_scale).min(1.0);
        BoundaryDecision::ContinueTrajectory {
            confidence,
            signals,
        }
    }
}

// ── Canonicalization for deterministic ID derivation ───────────────────────

/// Produce a canonical, deterministic JSON string representation of the
/// signals — used as input to `derive_trajectory_id` so that identical
/// boundary decisions produce identical trajectory IDs across rebuilds.
///
/// Emits keys in fixed order: conversation, time_gap, explicit_marker.
/// Floats formatted with 4-decimal-place precision to prevent floating-point
/// representation drift from producing different IDs on different platforms.
pub fn canonicalize_boundary_signals(signals: &BoundarySignals) -> String {
    let marker_str = match signals.explicit_marker {
        Some(v) => format!("{v:.4}"),
        None => "null".into(),
    };
    format!(
        r#"{{"conversation":{:.4},"time_gap":{:.4},"domain":{:.4},"explicit_marker":{}}}"#,
        signals.conversation, signals.time_gap, signals.domain, marker_str,
    )
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone};

    fn conv(seed: u128) -> ConversationId {
        ConversationId(uuid::Uuid::from_u128(seed))
    }

    fn ref_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 25, 12, 0, 0).unwrap()
    }

    fn ctx_at(dominant: ConversationId, last: DateTime<Utc>, receipts: u32) -> TrajectoryContext {
        TrajectoryContext {
            dominant_conversation_id: dominant,
            multi_conversation_history: false,
            last_active: last,
            receipt_count: receipts,
            dominant_event_prefix: None,
            top_prefixes: vec![],
        }
    }

    fn ctx_with_domain(
        dominant: ConversationId,
        last: DateTime<Utc>,
        receipts: u32,
        dominant_prefix: &str,
        top_prefixes: Vec<&str>,
    ) -> TrajectoryContext {
        TrajectoryContext {
            dominant_conversation_id: dominant,
            multi_conversation_history: false,
            last_active: last,
            receipt_count: receipts,
            dominant_event_prefix: Some(dominant_prefix.into()),
            top_prefixes: top_prefixes.into_iter().map(String::from).collect(),
        }
    }

    fn input_at(cid: ConversationId, ts: DateTime<Utc>) -> BoundaryInput {
        BoundaryInput {
            conversation_id: cid,
            timestamp: ts,
            event: None,
        }
    }

    // ── S1 conversation continuity ──

    #[test]
    fn s1_same_conversation_strong_continuity() {
        let c = conv(1);
        let ctx = ctx_at(c.clone(), ref_now(), 5);
        let input = input_at(c, ref_now());
        let cfg = BoundaryConfig::default();
        assert_eq!(signal_conversation_continuity(&input, &ctx, &cfg), -0.6);
    }

    #[test]
    fn s1_different_conversation_multi_history_weak_continuity() {
        let mut ctx = ctx_at(conv(1), ref_now(), 5);
        ctx.multi_conversation_history = true;
        let input = input_at(conv(99), ref_now());
        let cfg = BoundaryConfig::default();
        assert_eq!(signal_conversation_continuity(&input, &ctx, &cfg), -0.2);
    }

    #[test]
    fn s1_different_conversation_single_history_below_capacity_weak_boundary() {
        let ctx = ctx_at(conv(1), ref_now(), 5); // below default capacity (20)
        let input = input_at(conv(99), ref_now());
        let cfg = BoundaryConfig::default();
        assert_eq!(signal_conversation_continuity(&input, &ctx, &cfg), 0.3);
    }

    #[test]
    fn s1_different_conversation_at_capacity_medium_boundary() {
        let ctx = ctx_at(conv(1), ref_now(), 25); // above default capacity (20)
        let input = input_at(conv(99), ref_now());
        let cfg = BoundaryConfig::default();
        assert_eq!(signal_conversation_continuity(&input, &ctx, &cfg), 0.5);
    }

    // ── S2 time gap ──

    #[test]
    fn s2_recent_activity_weak_continuity() {
        let now = ref_now();
        let ctx = ctx_at(conv(1), now, 5);
        let input = input_at(conv(1), now + Duration::minutes(2)); // < 5 min
        let cfg = BoundaryConfig::default();
        // Downweighted from -0.4 to -0.2 per 2026-08 recalibration.
        assert_eq!(signal_time_gap(&input, &ctx, &cfg), -0.2);
    }

    #[test]
    fn s2_thirty_minutes_very_weak_continuity() {
        let now = ref_now();
        let ctx = ctx_at(conv(1), now, 5);
        let input = input_at(conv(1), now + Duration::minutes(30)); // 5m-1h
        let cfg = BoundaryConfig::default();
        // Downweighted from -0.1 to -0.05.
        assert_eq!(signal_time_gap(&input, &ctx, &cfg), -0.05);
    }

    #[test]
    fn s2_two_hours_neutral() {
        let now = ref_now();
        let ctx = ctx_at(conv(1), now, 5);
        let input = input_at(conv(1), now + Duration::hours(2)); // 1h-4h
        let cfg = BoundaryConfig::default();
        assert_eq!(signal_time_gap(&input, &ctx, &cfg), 0.0);
    }

    #[test]
    fn s2_twelve_hours_weak_boundary() {
        let now = ref_now();
        let ctx = ctx_at(conv(1), now, 5);
        let input = input_at(conv(1), now + Duration::hours(12)); // 4h-24h
        let cfg = BoundaryConfig::default();
        assert_eq!(signal_time_gap(&input, &ctx, &cfg), 0.2);
    }

    #[test]
    fn s2_three_days_medium_boundary() {
        let now = ref_now();
        let ctx = ctx_at(conv(1), now, 5);
        let input = input_at(conv(1), now + Duration::days(3)); // 24h-7d
        let cfg = BoundaryConfig::default();
        assert_eq!(signal_time_gap(&input, &ctx, &cfg), 0.4);
    }

    #[test]
    fn s2_two_weeks_strong_boundary() {
        let now = ref_now();
        let ctx = ctx_at(conv(1), now, 5);
        let input = input_at(conv(1), now + Duration::days(14)); // > 7d
        let cfg = BoundaryConfig::default();
        assert_eq!(signal_time_gap(&input, &ctx, &cfg), 0.6);
    }

    #[test]
    fn s2_negative_gap_treated_as_zero() {
        // Defensive: receipt timestamp before trajectory's last_active
        // (shouldn't happen with rowid-ordered processing).
        let now = ref_now();
        let ctx = ctx_at(conv(1), now, 5);
        let input = input_at(conv(1), now - Duration::hours(1)); // negative
        let cfg = BoundaryConfig::default();
        // Zero gap → short-continuity bucket (now -0.2 per recalibration)
        assert_eq!(signal_time_gap(&input, &ctx, &cfg), -0.2);
    }

    // ── S5 explicit markers ──

    #[test]
    fn s5_start_marker_definitive_boundary() {
        let mut input = input_at(conv(1), ref_now());
        input.event = Some("ontology:trajectory:started:some-id".into());
        assert_eq!(signal_explicit_marker(&input), Some(1.0));
        assert_eq!(
            classify_explicit_marker(&input),
            Some(ExplicitMarkerKind::Start)
        );
    }

    #[test]
    fn s5_end_marker_definitive_boundary() {
        let mut input = input_at(conv(1), ref_now());
        input.event = Some("ontology:trajectory:ended:xyz".into());
        assert_eq!(signal_explicit_marker(&input), Some(1.0));
        assert_eq!(
            classify_explicit_marker(&input),
            Some(ExplicitMarkerKind::End)
        );
    }

    #[test]
    fn s5_continued_marker_definitive_continuity() {
        let mut input = input_at(conv(1), ref_now());
        input.event = Some("ontology:trajectory:continued:foo".into());
        assert_eq!(signal_explicit_marker(&input), Some(-1.0));
        assert_eq!(
            classify_explicit_marker(&input),
            Some(ExplicitMarkerKind::Continue)
        );
    }

    #[test]
    fn s5_non_marker_event_returns_none() {
        let mut input = input_at(conv(1), ref_now());
        input.event = Some("officer:std:heartbeat".into());
        assert_eq!(signal_explicit_marker(&input), None);
        assert_eq!(classify_explicit_marker(&input), None);
    }

    #[test]
    fn s5_none_event_returns_none() {
        let input = input_at(conv(1), ref_now()); // event = None
        assert_eq!(signal_explicit_marker(&input), None);
    }

    // ── Fusion ──

    #[test]
    fn fusion_same_conversation_recent_produces_strong_continuity() {
        let c = conv(1);
        let now = ref_now();
        let ctx = ctx_at(c.clone(), now, 5);
        let input = input_at(c, now + Duration::minutes(1));
        let cfg = BoundaryConfig::default();

        let decision = evaluate_boundary(&input, &ctx, &cfg);
        match decision {
            BoundaryDecision::ContinueTrajectory {
                confidence,
                signals,
            } => {
                // event=None → S4=0.0. S1=-0.6 (same conv), S2=-0.2 (recent, retuned).
                // Raw = -0.8. Strong continuity.
                assert!(confidence >= 0.99);
                assert!((signals.raw_score() - (-0.8)).abs() < 0.001);
            }
            other => panic!("expected ContinueTrajectory, got {other:?}"),
        }
    }

    #[test]
    fn fusion_different_conversation_and_long_gap_produces_new_trajectory() {
        let now = ref_now();
        let ctx = ctx_at(conv(1), now, 25); // above capacity
        let input = input_at(conv(99), now + Duration::days(3));
        let cfg = BoundaryConfig::default();

        let decision = evaluate_boundary(&input, &ctx, &cfg);
        match decision {
            BoundaryDecision::NewTrajectory {
                confidence,
                reason,
                signals,
            } => {
                // S1=0.5 (conv change at capacity) + S2=0.4 (3-day gap) = 0.9
                assert_eq!(signals.raw_score(), 0.9);
                assert!((confidence - 0.6).abs() < 0.001); // 0.9 / 1.5 = 0.6
                assert_eq!(reason, BoundaryReason::FusedSignalThreshold);
            }
            other => panic!("expected NewTrajectory, got {other:?}"),
        }
    }

    #[test]
    fn fusion_explicit_start_marker_vetoes_negative_signals() {
        let c = conv(1);
        let now = ref_now();
        let ctx = ctx_at(c.clone(), now, 5);
        // Same conversation + recent → normally strong continuity
        let mut input = input_at(c, now + Duration::minutes(1));
        // But explicit start marker vetoes
        input.event = Some("ontology:trajectory:started:new-arc".into());
        let cfg = BoundaryConfig::default();

        let decision = evaluate_boundary(&input, &ctx, &cfg);
        match decision {
            BoundaryDecision::NewTrajectory {
                confidence, reason, ..
            } => {
                assert_eq!(confidence, 1.0);
                assert_eq!(reason, BoundaryReason::ExplicitStartMarker);
            }
            other => panic!("expected NewTrajectory from marker, got {other:?}"),
        }
    }

    #[test]
    fn fusion_explicit_continue_marker_vetoes_positive_signals() {
        let now = ref_now();
        let ctx = ctx_at(conv(1), now, 25); // above capacity
                                            // Different conversation + long gap → normally new trajectory
        let mut input = input_at(conv(99), now + Duration::days(14));
        // But explicit continue marker vetoes
        input.event = Some("ontology:trajectory:continued:same-arc".into());
        let cfg = BoundaryConfig::default();

        let decision = evaluate_boundary(&input, &ctx, &cfg);
        match decision {
            BoundaryDecision::ContinueTrajectory { confidence, .. } => {
                assert_eq!(confidence, 1.0);
            }
            other => panic!("expected ContinueTrajectory from marker, got {other:?}"),
        }
    }

    #[test]
    fn fusion_boundary_at_exact_threshold() {
        // Construct signals that sum to exactly the threshold (0.5).
        // S1=0.3 (diff conv, below capacity) + S2=0.2 (12-hour gap) = 0.5
        let now = ref_now();
        let ctx = ctx_at(conv(1), now, 5); // below capacity
        let input = input_at(conv(99), now + Duration::hours(12));
        let cfg = BoundaryConfig::default();

        let decision = evaluate_boundary(&input, &ctx, &cfg);
        match decision {
            BoundaryDecision::NewTrajectory { signals, .. } => {
                assert!((signals.raw_score() - 0.5).abs() < 0.0001);
            }
            other => panic!("expected NewTrajectory at threshold, got {other:?}"),
        }
    }

    #[test]
    fn fusion_below_threshold_produces_continuity() {
        // S1=0.3 + S2=0.0 = 0.3, below 0.5 threshold
        let now = ref_now();
        let ctx = ctx_at(conv(1), now, 5);
        let input = input_at(conv(99), now + Duration::hours(2)); // neutral time
        let cfg = BoundaryConfig::default();

        let decision = evaluate_boundary(&input, &ctx, &cfg);
        assert!(matches!(
            decision,
            BoundaryDecision::ContinueTrajectory { .. }
        ));
    }

    // ── Determinism ──

    #[test]
    fn evaluate_boundary_is_deterministic() {
        let c = conv(1);
        let now = ref_now();
        let ctx = ctx_at(c.clone(), now, 5);
        let input = input_at(c, now + Duration::minutes(2));
        let cfg = BoundaryConfig::default();

        let d1 = evaluate_boundary(&input, &ctx, &cfg);
        let d2 = evaluate_boundary(&input, &ctx, &cfg);
        assert_eq!(d1, d2);
    }

    // ── Canonicalization ──

    #[test]
    fn canonicalize_signals_deterministic_json() {
        let s = BoundarySignals {
            conversation: -0.6,
            time_gap: -0.4,
            domain: -0.3,
            explicit_marker: None,
        };
        let json = canonicalize_boundary_signals(&s);
        assert_eq!(
            json,
            r#"{"conversation":-0.6000,"time_gap":-0.4000,"domain":-0.3000,"explicit_marker":null}"#
        );
    }

    #[test]
    fn canonicalize_signals_with_marker() {
        let s = BoundarySignals {
            conversation: 0.3,
            time_gap: 0.2,
            domain: 0.0,
            explicit_marker: Some(1.0),
        };
        let json = canonicalize_boundary_signals(&s);
        assert_eq!(
            json,
            r#"{"conversation":0.3000,"time_gap":0.2000,"domain":0.0000,"explicit_marker":1.0000}"#
        );
    }

    #[test]
    fn canonicalize_identical_signals_produce_identical_strings() {
        let s1 = BoundarySignals {
            conversation: 0.5,
            time_gap: 0.4,
            domain: 0.4,
            explicit_marker: None,
        };
        let s2 = BoundarySignals {
            conversation: 0.5,
            time_gap: 0.4,
            domain: 0.4,
            explicit_marker: None,
        };
        assert_eq!(
            canonicalize_boundary_signals(&s1),
            canonicalize_boundary_signals(&s2)
        );
    }

    // ── S4 domain clustering ──

    #[test]
    fn s4_exact_dominant_prefix_strong_continuity() {
        let now = ref_now();
        let ctx = ctx_with_domain(
            conv(1),
            now,
            10,
            "officer:std",
            vec!["officer:std", "officer:sen"],
        );
        let mut input = input_at(conv(1), now);
        input.event = Some("officer:std:heartbeat".into());
        assert_eq!(signal_domain_clustering(&input, &ctx), -0.3);
    }

    #[test]
    fn s4_in_top_prefixes_weak_continuity() {
        let now = ref_now();
        let ctx = ctx_with_domain(
            conv(1),
            now,
            10,
            "officer:std",
            vec!["officer:std", "officer:sen", "officer:forge"],
        );
        let mut input = input_at(conv(1), now);
        input.event = Some("officer:sen:finding".into());
        assert_eq!(signal_domain_clustering(&input, &ctx), -0.1);
    }

    #[test]
    fn s4_same_namespace_different_prefix_weak_boundary() {
        // Trajectory dominated by officer:std / officer:sen; new receipt is
        // officer:cleo (same top-level namespace "officer", different prefix
        // and not in top-3). Per 2026-08 recalibration: sub-domain shifts
        // within a namespace now score +0.3 (was 0.0 neutral).
        let now = ref_now();
        let ctx = ctx_with_domain(
            conv(1),
            now,
            10,
            "officer:std",
            vec!["officer:std", "officer:sen"],
        );
        let mut input = input_at(conv(1), now);
        input.event = Some("officer:cleo:governance".into());
        assert_eq!(signal_domain_clustering(&input, &ctx), 0.3);
    }

    #[test]
    fn s4_completely_foreign_namespace_strong_boundary() {
        // Trajectory dominated by officer:*, new receipt is delegation:granted.
        // Per 2026-08 recalibration: foreign namespaces now score +0.8
        // (was +0.4) — the load-bearing boundary signal for substrate chains.
        let now = ref_now();
        let ctx = ctx_with_domain(
            conv(1),
            now,
            10,
            "officer:std",
            vec!["officer:std", "officer:sen"],
        );
        let mut input = input_at(conv(1), now);
        input.event = Some("delegation:granted:foo".into());
        assert_eq!(signal_domain_clustering(&input, &ctx), 0.8);
    }

    #[test]
    fn s4_non_system_event_neutral() {
        let now = ref_now();
        let ctx = ctx_with_domain(conv(1), now, 10, "officer:std", vec!["officer:std"]);
        let input = input_at(conv(1), now); // event = None
        assert_eq!(signal_domain_clustering(&input, &ctx), 0.0);
    }

    #[test]
    fn s4_empty_context_strong_boundary() {
        // Cold-ish trajectory with no domain history yet.
        let now = ref_now();
        let ctx = ctx_at(conv(1), now, 0);
        let mut input = input_at(conv(1), now);
        input.event = Some("officer:std:heartbeat".into());
        // No dominant prefix, no top prefixes → falls through to case 4
        // (foreign namespace = +0.8 per recalibration).
        assert_eq!(signal_domain_clustering(&input, &ctx), 0.8);
    }

    #[test]
    fn extract_event_prefix_takes_first_two_segments() {
        assert_eq!(extract_event_prefix("officer:std:heartbeat"), "officer:std");
        assert_eq!(
            extract_event_prefix("delegation:granted:foo"),
            "delegation:granted"
        );
        assert_eq!(extract_event_prefix("system:startup"), "system:startup");
        assert_eq!(extract_event_prefix("solo"), "solo");
        assert_eq!(extract_event_prefix(""), "");
    }

    // ── Fusion including S4 ──

    #[test]
    fn fusion_s4_domain_shift_produces_boundary_under_recalibrated_weights() {
        // Scenario: substrate chain with regular officer heartbeats.
        // Trajectory dominated by officer:*. New receipt is
        // tool:started (foreign namespace) with recent activity.
        //
        // Under 2026-08 recalibration:
        //   S1: diff conv, multi-history = -0.2
        //   S2: 2 min = -0.2 (downweighted from -0.4)
        //   S4: foreign namespace = +0.8 (bumped from +0.4)
        //   Raw = -0.2 + -0.2 + 0.8 = +0.4 → still continuity (below 0.5)
        //
        // This is intentional: multi-history + recent + foreign-domain is
        // still ambiguous. S4 alone doesn't force a boundary when S1 is
        // negative — the cadence-cap (250 receipts) covers the pathological
        // "always continues" case in a substrate chain.
        let c = conv(1);
        let now = ref_now();
        let mut ctx = ctx_with_domain(
            c.clone(),
            now,
            10,
            "officer:std",
            vec!["officer:std", "officer:sen"],
        );
        ctx.multi_conversation_history = true;
        let mut input = input_at(conv(99), now + Duration::minutes(2));
        input.event = Some("tool:started:mytool".into());
        let cfg = BoundaryConfig::default();

        let decision = evaluate_boundary(&input, &ctx, &cfg);
        match decision {
            BoundaryDecision::ContinueTrajectory { signals, .. } => {
                assert!((signals.raw_score() - 0.4).abs() < 0.001);
                assert_eq!(signals.domain, 0.8);
            }
            other => panic!("expected ContinueTrajectory, got {other:?}"),
        }
    }

    #[test]
    fn fusion_s4_boundary_when_other_signals_neutral() {
        // Different conversation + time gap in the 1h-4h range (neutral)
        // + foreign domain namespace. Under recalibration:
        //   S1: diff conv, below capacity = +0.3
        //   S2: 2h neutral = 0.0
        //   S4: foreign namespace = +0.8 (bumped)
        //   Raw = 0.3 + 0.0 + 0.8 = 1.1 → strong boundary (~0.73 confidence)
        let now = ref_now();
        let ctx = ctx_with_domain(conv(1), now, 10, "officer:std", vec!["officer:std"]);
        let mut input = input_at(conv(99), now + Duration::hours(2));
        input.event = Some("delegation:granted:foo".into());
        let cfg = BoundaryConfig::default();

        let decision = evaluate_boundary(&input, &ctx, &cfg);
        match decision {
            BoundaryDecision::NewTrajectory {
                confidence,
                signals,
                ..
            } => {
                assert!((signals.raw_score() - 1.1).abs() < 0.001);
                assert!((confidence - 0.7333).abs() < 0.01); // 1.1 / 1.5
            }
            other => panic!("expected NewTrajectory, got {other:?}"),
        }
    }

    // ── Cadence-forced boundary (P4 recalibration) ──

    #[test]
    fn cadence_cap_forces_boundary_regardless_of_signals() {
        // Trajectory at cap even with strong continuity signals should
        // force a boundary. This is the safety net for chatty substrate
        // chains where signal-based detection never fires.
        let c = conv(1);
        let now = ref_now();
        let ctx = ctx_at(c.clone(), now, 250); // at default cap
        let input = input_at(c, now + Duration::minutes(1)); // recent, same conv
        let cfg = BoundaryConfig::default();

        let decision = evaluate_boundary(&input, &ctx, &cfg);
        match decision {
            BoundaryDecision::NewTrajectory {
                confidence, reason, ..
            } => {
                assert_eq!(confidence, 1.0);
                assert_eq!(reason, BoundaryReason::ReceiptCountCap);
            }
            other => panic!("expected NewTrajectory (cap), got {other:?}"),
        }
    }

    #[test]
    fn cadence_cap_zero_disables_forcing() {
        let c = conv(1);
        let now = ref_now();
        let ctx = ctx_at(c.clone(), now, 250);
        let input = input_at(c, now + Duration::minutes(1));
        let cfg = BoundaryConfig {
            trajectory_receipt_cap: 0, // disabled
            ..BoundaryConfig::default()
        };
        let decision = evaluate_boundary(&input, &ctx, &cfg);
        // No cap → falls through to normal signal flow → continuity.
        assert!(matches!(
            decision,
            BoundaryDecision::ContinueTrajectory { .. }
        ));
    }

    #[test]
    fn cadence_cap_yields_to_explicit_continue_marker() {
        // Operator override should still win against the cap. Explicit
        // continuity marker vetoes the cadence-forcing.
        let c = conv(1);
        let now = ref_now();
        let ctx = ctx_at(c.clone(), now, 250);
        let mut input = input_at(c, now + Duration::minutes(1));
        input.event = Some("ontology:trajectory:continued:override".into());
        let cfg = BoundaryConfig::default();

        let decision = evaluate_boundary(&input, &ctx, &cfg);
        // Explicit continue marker (-1.0) wins.
        assert!(matches!(
            decision,
            BoundaryDecision::ContinueTrajectory { .. }
        ));
    }

    #[test]
    fn cadence_cap_below_threshold_not_triggered() {
        let c = conv(1);
        let now = ref_now();
        let ctx = ctx_at(c.clone(), now, 249); // one below cap
        let input = input_at(c, now + Duration::minutes(1));
        let cfg = BoundaryConfig::default();
        let decision = evaluate_boundary(&input, &ctx, &cfg);
        assert!(matches!(
            decision,
            BoundaryDecision::ContinueTrajectory { .. }
        ));
    }

    #[test]
    fn config_defaults_match_design_doc() {
        // Lock in defaults from CARTOGRAPHER-IMPLEMENTATION-DESIGN §Section 1
        // + 2026-08 empirical recalibration.
        let c = BoundaryConfig::default();
        assert_eq!(c.boundary_threshold, 0.5);
        assert_eq!(c.confidence_scale, 1.5);
        assert_eq!(c.s1_capacity_threshold, 20);
        assert_eq!(c.s2_short_secs, 300);
        assert_eq!(c.s2_medium_secs, 3600);
        assert_eq!(c.s2_long_secs, 14_400);
        assert_eq!(c.s2_dormant_secs, 86_400);
        assert_eq!(c.s2_extended_dormancy_secs, 604_800);
        assert_eq!(c.trajectory_receipt_cap, 250);
    }
}
