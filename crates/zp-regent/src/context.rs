//! Cognitive context — the Regent's working memory for a single reasoning cycle.
//!
//! Each cycle, the Regent assembles a `CognitiveContext` from chain state,
//! officer findings, operator input, and prior memory. This context is the
//! input to the reasoning step — everything the Regent knows right now,
//! structured for the inference backend.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zp_core::AuditEntry;
use zp_officers::finding::{Finding, Severity};

use crate::corrections::ActiveStandingCorrection;

/// The sovereign operator's identity — read once from Genesis at startup.
///
/// This is the Regent's answer to "who do I serve?" It never changes
/// during a process lifetime (Genesis is permanent). The Regent uses
/// this to address the operator by name, cite its own authority source,
/// and ground its identity in the chain's cryptographic root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SovereignIdentity {
    /// Operator's name as declared at Genesis ceremony.
    pub operator_name: String,
    /// Genesis public key (hex). The root of all trust.
    pub genesis_pubkey: String,
    /// Sovereignty mode (e.g. "TouchId", "Trezor", "FileBased").
    pub sovereignty_mode: Option<String>,
}

impl SovereignIdentity {
    /// Load from ~/ZeroPoint/genesis.json. Returns None if genesis
    /// hasn't been established or the file is malformed.
    pub fn load(zp_home: &std::path::Path) -> Option<Self> {
        let genesis_path = zp_home.join("genesis.json");
        let data = std::fs::read_to_string(&genesis_path).ok()?;
        let parsed: serde_json::Value = serde_json::from_str(&data).ok()?;

        let operator_name = parsed["operator"].as_str()?.to_string();
        let genesis_pubkey = parsed["genesis_public_key"].as_str()?.to_string();
        let sovereignty_mode = parsed["sovereignty_mode"].as_str().map(|s| s.to_string());

        Some(Self {
            operator_name,
            genesis_pubkey,
            sovereignty_mode,
        })
    }
}

/// A single cycle's cognitive context.
///
/// Built fresh each cycle from substrate state. Not persisted directly —
/// the Regent's memory system decides what to retain across cycles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CognitiveContext {
    /// When this context was assembled.
    pub assembled_at: DateTime<Utc>,

    /// The sovereign operator this Regent serves. Read from Genesis
    /// at startup; present in every cycle's context.
    pub sovereign: Option<SovereignIdentity>,

    /// Recent chain entries (tail window). The Regent sees what happened,
    /// not what it remembers happening.
    pub recent_chain: Vec<ChainSnapshot>,

    /// Active officer findings from the latest sweep cycle.
    /// Officers are the Regent's senses — these findings are what the
    /// substrate is currently reporting.
    pub officer_findings: Vec<FindingSummary>,

    /// Current governance posture summary.
    pub posture_summary: Option<String>,

    /// Operator input waiting for response, if any.
    pub pending_input: Option<OperatorInput>,

    /// Retrieved memory fragments relevant to current context.
    pub memory_fragments: Vec<MemoryFragment>,

    /// Active standing corrections — Tier 1 cognitive input per
    /// `docs/design/COGNITIVE-INPUT-PLANE-2026-07.md`. Chain-anchored operator
    /// claims about Regent's cognitive layer that persist across cycles.
    /// Priority-sorted (highest first); bounded to top-K by assembly config.
    /// See `docs/design/STANDING-CORRECTION-RECEIPT-SCHEMA-2026-07.md` for the
    /// receipt shape and lifecycle discipline.
    #[serde(default)]
    pub standing_corrections: Vec<ActiveStandingCorrection>,

    /// Bedrock invariants — whether the substrate itself is intact.
    ///
    /// Tier 1, alongside standing corrections and above officer findings: these
    /// are the premises every other input rests on. One entry per distinct
    /// invariant, carrying its most recent observation. See [`GroundFinding`].
    #[serde(default)]
    pub substrate_ground: Vec<GroundFinding>,

    /// Active delegations the Regent currently holds.
    pub active_delegations: Vec<DelegationSummary>,

    /// System awareness — resource pressure, loaded models, background tasks.
    /// The Regent uses this to maintain harmony: yielding to the operator,
    /// deferring maintenance under load, reclaiming resources under pressure.
    pub system_awareness: Option<SystemAwareness>,

    /// Tool results from prior turns within this cycle.
    /// Enables multi-turn cycles: the Regent executes a tool, sees the result,
    /// and composes a narration — all within one cognitive cycle.
    pub tool_results: Vec<ToolResult>,

    /// Active work arc, if the Regent is mid-task across cycles.
    /// None on the first cycle of a new wake; Some when Continue has been
    /// emitted and the loop runner re-enters immediately.
    pub work_arc: Option<WorkArc>,

    /// Mirror: the Regent's own prior response, if any.
    /// Fed back into the next cycle so she can see what she said and
    /// evaluate whether it addressed the operator's question. This is
    /// the minimal self-reflection surface — confabulation becomes
    /// visible as a gap between what was asked and what was answered.
    pub prior_response: Option<PriorResponse>,

    /// The operator question this cycle is answering, carried across every
    /// turn of it.
    ///
    /// `pending_input` is consumed once, on turn 0, so that a tool-dispatch
    /// turn is not re-read as a fresh directive. The side effect was that
    /// every later turn of the same cycle lost the question entirely: both
    /// the OPERATOR REQUEST block and the CONVERSATION SO FAR block are
    /// gated on `pending_input.is_some()`, and `prior_response` is only
    /// passed on turn 0. The narration turn therefore received a tool result
    /// and an instruction to answer, with nothing saying what had been asked.
    ///
    /// Observed 2026-07-31: the operator asked what the start of the receipt
    /// chain was. `chain_query` ran, the narration turn arrived with no
    /// question attached, the router dispatched `chain_query` again — three
    /// times, to MAX_TOOL_TURNS — and the max-turns fallback handed the
    /// operator the raw JSON of the last call. A model told to answer, and
    /// not told the question, acts instead.
    ///
    /// Deliberately not part of `CompositionSummary`: `pending_input` is not
    /// summarised either, so adding this would change what
    /// `cognitive:input:composed` anchors and move the matrix version for a
    /// field the receipt has never carried on turn 0 either. The receipt
    /// already distinguishes these turns by `reason=tool_dispatch_narration`.
    pub cycle_directive: Option<String>,

    /// Composition provenance — per-class source hashes and matrix version.
    /// Populated by `perceive()`; consumed by the caller when emitting the
    /// `cognitive:input:composed` chain receipt per COGNITIVE-INPUT-PLANE spec.
    /// None only if the composition summary couldn't be computed (should not
    /// happen in normal operation).
    #[serde(default)]
    pub composition_summary: Option<CompositionSummary>,
}

/// Composition provenance for a single cognitive-cycle context assembly.
///
/// Fields are structural hashes and counts — not content — so they can be
/// chain-anchored via `cognitive:input:composed` receipts without bloating
/// the chain with prompt content on every cycle. If Regent later claims a
/// piece of context wasn't provided, the chain shows the composition it
/// received (hash-verifiable against reconstruction from the same sources).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompositionSummary {
    /// Matrix specification version. Bumped when the composition rules change
    /// via canonicalization ceremony (per COGNITIVE-INPUT-PLANE-2026-07.md §"Layer A / Layer B split").
    pub matrix_version: String,
    /// Number of standing corrections included in Tier 1.
    pub standing_correction_count: usize,
    /// Hash of the top-K standing corrections (in the order presented to Regent).
    /// Empty string when the correction set is empty.
    pub standing_corrections_hash: String,
    /// Authorship provenance for the standing-corrections class (Tier 1).
    /// Per ZEP-self-referential-authorship-2026-07.md §4: "provenance on every
    /// artifact."
    #[serde(default)]
    pub standing_correction_authorship: ClassAuthorship,
    /// Number of bedrock invariants in Tier 1, and how many of them failed.
    ///
    /// Both counted because they answer different questions. The total says the
    /// check ran and how much of the substrate it covered; the violation count
    /// says whether Regent was reasoning over intact premises. A cycle with
    /// `substrate_ground_count: 0` is not a healthy substrate — it is one where
    /// nothing checked, which is the state that let a missing vault go unnoticed
    /// for months and is worth being able to distinguish afterwards.
    #[serde(default)]
    pub substrate_ground_count: usize,
    #[serde(default)]
    pub substrate_ground_violations: usize,
    /// Hash of the ground findings in presented order.
    #[serde(default)]
    pub substrate_ground_hash: String,
    /// Number of officer findings included in Tier 2.
    pub officer_finding_count: usize,
    /// Hash of the officer findings (in the order presented).
    pub officer_findings_hash: String,
    /// Authorship provenance for the officer-findings class (Tier 2).
    #[serde(default)]
    pub officer_finding_authorship: ClassAuthorship,
    /// Number of recent chain entries in Tier 2 context.
    pub recent_chain_count: usize,
    /// Number of active delegations in Tier 2 context.
    pub active_delegation_count: usize,
    /// Cycle invocation reason — hint for downstream analysis.
    pub invocation_reason: String,
    /// Tier-weighted fraction of this cycle's composed context that is
    /// self-authored (Regent-authored, directly or via an adopted proposal).
    /// Computed per ZEP-self-referential-authorship-2026-07.md §III.27 /
    /// §4 ("the ratio is the instrument"). Always `0.0` today — every
    /// composed class is operator- or officer-authored; no Regent corpus
    /// authorship (Class 2/3) exists yet in the runtime. That is the
    /// expected baseline, not a bug — see the axiom's §10 prerequisite.
    #[serde(default)]
    pub self_authorship_ratio: f64,
}

/// Who authored an item of composed context, per
/// ZEP-self-referential-authorship-2026-07.md's ontology term
/// "self-referential authorship." Only `Operator` and `Officer` are
/// reachable in the runtime today — `Regent` is forward-declared so the
/// ratio computation is meaningful the moment Regent corpus authorship
/// (Class 2/3 per §III.27) exists, and should not be constructed anywhere
/// yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorClass {
    /// Authored by the sovereign operator (e.g. a standing correction
    /// `issued_by` the operator's Genesis key).
    Operator,
    /// Authored by an officer (e.g. an officer finding).
    Officer,
    /// Authored by the Regent herself. Not reachable today.
    Regent,
}

/// Authorship provenance for one contributing class of composed context.
///
/// Counts, not content — consistent with `CompositionSummary`'s
/// structural-only discipline; nothing here bloats the chain receipt.
///
/// `proposed_by_regent` is tracked separately from `authored_by` per
/// ZEP-self-referential-authorship-2026-07.md §4: "`proposed_by` is
/// separate from `authored_by` and never stripped. Where material was
/// Regent-proposed and operator-adopted, both fields persist and the item
/// still counts toward the ratio." An adopted proposal is counted in both
/// its `authored_by` bucket (the adopting author — operator or officer)
/// *and* in `proposed_by_regent`, so it still contributes to the
/// self-authorship ratio numerator via [`ClassAuthorship::self_authored`]
/// without inflating the class total.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassAuthorship {
    /// Count of items in this class with `authored_by == operator`.
    pub operator_authored: usize,
    /// Count of items in this class with `authored_by == officer`.
    pub officer_authored: usize,
    /// Count of items in this class with `authored_by == regent`. Always
    /// `0` until Regent corpus authorship exists.
    pub regent_authored: usize,
    /// Of the items counted above (any `authored_by`), how many additionally
    /// carry `proposed_by == regent` — an operator- or officer-authored item
    /// that adopted a Regent proposal. Never stripped; always `0` until
    /// the proposal/adoption mechanism exists (out of scope for this slice).
    pub regent_proposed_adopted: usize,
}

impl ClassAuthorship {
    /// All items in this class authored by the operator.
    pub fn all_operator(count: usize) -> Self {
        Self {
            operator_authored: count,
            ..Default::default()
        }
    }

    /// All items in this class authored by an officer.
    pub fn all_officer(count: usize) -> Self {
        Self {
            officer_authored: count,
            ..Default::default()
        }
    }

    /// Count of items in this class attributed to the given [`AuthorClass`].
    /// Does not include `regent_proposed_adopted` — that's cross-cutting
    /// metadata over items already counted here, not its own author class.
    pub fn count(&self, author: AuthorClass) -> usize {
        match author {
            AuthorClass::Operator => self.operator_authored,
            AuthorClass::Officer => self.officer_authored,
            AuthorClass::Regent => self.regent_authored,
        }
    }

    /// Total items in this class, across all `authored_by` values.
    /// `regent_proposed_adopted` is not added — it's metadata on items
    /// already counted in `operator_authored`/`officer_authored`, not a
    /// separate population.
    pub fn total(&self) -> usize {
        self.operator_authored + self.officer_authored + self.regent_authored
    }

    /// Items counting toward the self-authorship ratio numerator: directly
    /// Regent-authored, plus operator/officer-authored items that adopted a
    /// Regent proposal (proposed_by is never stripped and still counts, per
    /// ZEP-self-referential-authorship-2026-07.md §III.27 / §4).
    pub fn self_authored(&self) -> usize {
        self.regent_authored + self.regent_proposed_adopted
    }
}

/// Relative weight of Tier 1 context (standing corrections) vs Tier 2
/// (officer findings) in the self-authorship ratio.
///
/// Per ZEP-self-referential-authorship-2026-07.md §4: "Weight by tier, not
/// by item count. A self-authored Tier 1 standing correction conditions the
/// cycle far more than a self-authored Tier 2 finding. Item-count weighting
/// understates exactly the case the ratio exists to catch." 2:1 reflects
/// Tier 1's status as persistent, load-bearing context per
/// COGNITIVE-INPUT-PLANE-2026-07.md §"Priority tier summary" (Tier 1 is what
/// Regent "must remember across cycles"; Tier 2 is "current context"). These
/// are placeholder magnitudes, not derived from evidence — re-tune once the
/// ratio has an observed distribution (open position: "Breaker thresholds
/// for the ratio").
const TIER1_AUTHORSHIP_WEIGHT: f64 = 2.0;
const TIER2_AUTHORSHIP_WEIGHT: f64 = 1.0;

/// Compute the tier-weighted self-authorship ratio across the two
/// contributing classes currently tracked (standing corrections = Tier 1,
/// officer findings = Tier 2). Returns `0.0` when there is no composed
/// context to weight (avoids division by zero) — which is also the
/// universal result today, since no class has any Regent-authored or
/// Regent-proposed-and-adopted items yet.
pub fn tier_weighted_self_authorship_ratio(
    tier1: &ClassAuthorship,
    tier2: &ClassAuthorship,
) -> f64 {
    let weighted_total = TIER1_AUTHORSHIP_WEIGHT * tier1.total() as f64
        + TIER2_AUTHORSHIP_WEIGHT * tier2.total() as f64;
    if weighted_total == 0.0 {
        return 0.0;
    }
    let weighted_self = TIER1_AUTHORSHIP_WEIGHT * tier1.self_authored() as f64
        + TIER2_AUTHORSHIP_WEIGHT * tier2.self_authored() as f64;
    weighted_self / weighted_total
}

impl CompositionSummary {
    /// Compute a stable content hash for a set of standing corrections.
    /// Serializes to canonical JSON then SHA-256's the bytes.
    pub fn hash_corrections(
        corrections: &[crate::corrections::ActiveStandingCorrection],
    ) -> String {
        if corrections.is_empty() {
            return String::new();
        }
        // Deterministic serialization via serde_json (field order matches struct order).
        let bytes = serde_json::to_vec(corrections).unwrap_or_default();
        hex_sha256(&bytes)
    }

    /// Compute a stable content hash for the bedrock-invariant list.
    ///
    /// No authorship counterpart: `ClassAuthorship` distinguishes operator,
    /// officer and Regent, and bedrock invariants are none of those. They are
    /// the substrate reporting on itself — a fourth author class that does not
    /// exist and should not be invented for one use. The provenance that
    /// matters here is the count and the hash: that the check ran, over what,
    /// and with what result.
    pub fn hash_ground(ground: &[GroundFinding]) -> String {
        if ground.is_empty() {
            return String::new();
        }
        let bytes = serde_json::to_vec(ground).unwrap_or_default();
        hex_sha256(&bytes)
    }

    /// Compute a stable content hash for the officer-findings summary list.
    pub fn hash_findings(findings: &[FindingSummary]) -> String {
        if findings.is_empty() {
            return String::new();
        }
        let bytes = serde_json::to_vec(findings).unwrap_or_default();
        hex_sha256(&bytes)
    }

    /// Number of composition classes that contributed at least one item to
    /// this cycle's context — the structural attention signal for the
    /// cognitive-act receipt's `attended=` field, at "current receipt
    /// granularity" per COGNITIVE-ACT-ACCOUNTING-2026-07.md §6 (v0 scope;
    /// per-class content hashing across all seven classes is deferred, per
    /// that doc's §3.1 `attended` status note).
    pub fn attended_class_count(&self) -> usize {
        [
            self.standing_correction_count > 0,
            self.officer_finding_count > 0,
            self.recent_chain_count > 0,
            self.active_delegation_count > 0,
        ]
        .iter()
        .filter(|&&present| present)
        .count()
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// What the Regent said on her last cycle — the mirror.
///
/// Carried into the next cycle's context so she can self-evaluate.
/// Not persisted beyond one cycle — this is working memory, not chain state.
/// If the self-evaluation detects confabulation, that event goes on the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorResponse {
    /// What the operator asked (if anything) when this response was generated.
    pub operator_question: Option<String>,
    /// What the Regent actually said.
    pub response_content: String,
    /// Which model generated this response.
    pub model_used: String,
}

/// A multi-cycle task arc the Regent is working through.
///
/// Persists across cognitive cycles within a single arc. The loop runner
/// creates this on the first Continue intent and threads it through
/// subsequent cycles until the Regent emits Done (Respond/Observe) or
/// the budget is exhausted.
///
/// The `progress` field is the design-critical surface: it must be a
/// one-line glanceable summary that answers "what did she just do,
/// what's next" without the operator digging. This is a hard constraint
/// from the operator (2026-07-06), not a nice-to-have.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkArc {
    /// One-line progress summary. Updated by the Regent each Continue.
    /// Rendered directly in cockpit surfaces. If an operator has to
    /// query, scroll, or interpret to understand this, the design failed.
    pub progress: String,

    /// How many cognitive cycles this arc has consumed.
    pub cycles_completed: u32,

    /// Maximum cycles allowed before forced termination.
    pub max_cycles: u32,

    /// Tool results accumulated across all cycles in this arc.
    /// Grows monotonically — the Regent sees the full history.
    pub tool_history: Vec<ToolResult>,

    /// The operator directive this arc was opened to satisfy.
    ///
    /// `cycle_directive` is derived from a cycle's own input, and an arc
    /// continuation has none — `arc_input.take()` yields the message once, to
    /// the opening cycle. So every later cycle of an arc forgot what it was
    /// for, which showed up in a queued proposal reading "attempted in
    /// service of: (no operator directive this cycle)".
    ///
    /// The arc is the right owner: the directive is what the arc exists to
    /// satisfy, and it should outlive any single cycle within it.
    pub directive: Option<String>,

    /// Consecutive cycles that changed nothing.
    ///
    /// A `Continue` is a claim that the arc advanced. When the progress
    /// string is byte-identical to the last one and no new tool result
    /// arrived, nothing advanced — the arc restated its intention and
    /// consumed a cycle.
    ///
    /// Observed 2026-08-01: an arc opened on "compact the chain down to the
    /// last 1000 entries" ran its full ten-cycle budget emitting that exact
    /// string ten times, dispatched no tool, and terminated with "Work arc
    /// stopped after 10 cycles (budget)" — which reads to an operator like
    /// work was attempted. The budget was the only thing that stopped it,
    /// and a budget is a backstop, not a detector: it bounds the damage
    /// without ever naming what went wrong.
    pub stall_count: u32,

    /// Trajectory-map waypoint set. Empty for arc-shaped work (the vast
    /// majority of WorkArcs); non-empty when the arc has grown into a
    /// map per TRAJECTORY-MAP-PRIMITIVE-2026-08.
    ///
    /// Framing per that sketch: **every WorkArc is a map with zero
    /// waypoints**. Waypoint-set growth is what promotes an arc into map
    /// mode. This field is `#[serde(default)]` so existing serialized
    /// WorkArcs deserialize as arc-shaped (empty waypoint set) without
    /// migration.
    ///
    /// No dispatch behaviour reads this field yet — this landing is
    /// data-structure-only. The dispatch loop, receipt-emission, and
    /// operator surface come in follow-on commits.
    #[serde(default)]
    pub waypoints: Vec<Waypoint>,

    /// Destination hypotheses proposed for this map. Empty for arc-
    /// shaped work OR for map-shaped work in pure-fog state (heading
    /// declared, no destination has crystallized yet).
    ///
    /// Per the sketch's load-bearing principle: **destination is a
    /// diagnostic, not a goal**. The current destination is a query
    /// over this vector — the most recent hypothesis that is
    /// `accepted` and not `superseded_by` any later one. That query
    /// returns `None` when the trajectory hasn't converged to a
    /// nameable target, which is a valid state.
    ///
    /// `#[serde(default)]` for backward compat.
    #[serde(default)]
    pub destination_hypotheses: Vec<DestinationHypothesis>,

    /// Terminal-state marker for the map (or arc — arc-shaped work
    /// simply stays `Open` for its whole lifetime, which is fine).
    /// Three terminal states per the sketch: settled with destination,
    /// settled without destination, abandoned.
    ///
    /// `#[serde(default)]` — defaults to `Open` for backward compat
    /// with any WorkArc serialized before this field existed.
    #[serde(default)]
    pub settlement: SettlementState,
}

// ── Trajectory map primitives (data-structure landing) ─────────────────

/// The type of work a waypoint represents. Dispatch mechanism varies per
/// type; the enum is a scheduling signal for the future dispatch loop.
///
/// - `Research` — investigation task, dispatches to builder per
///   SUBSTRATE-SELF-CONSTRUCTION-2026-07 §"builder dispatch."
/// - `Prototype` — shadow-eval-shaped waypoint, dispatches to
///   SHADOW-EVALUATION-PRIMITIVE-2026-07 for high-fidelity feedback.
/// - `Grilling` — operator conversation, dispatches to the approval-
///   request machinery for interactive dialogue.
/// - `Task` — concrete construction work, dispatches to builder like
///   Research but produces artifacts rather than findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WaypointKind {
    Research,
    Prototype,
    Grilling,
    Task,
}

/// A waypoint in a trajectory map. Scoped sub-arc of work with typed
/// dispatch, explicit blocking relationships, and (once resolved)
/// an outcome that may open new waypoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Waypoint {
    /// Stable id within the parent WorkArc. Used by other waypoints'
    /// `blocking` sets to name this waypoint as a prerequisite.
    pub id: String,

    /// Dispatch-scheduling signal. See `WaypointKind`.
    pub waypoint_kind: WaypointKind,

    /// Human-readable rationale — why this waypoint, what fog it clears.
    /// One-line preferred; the Regent uses this as the waypoint's cockpit
    /// label.
    pub rationale: String,

    /// Other waypoints in this map that must resolve before this one is
    /// takable. Named by their `id`. Empty vec means the waypoint is on
    /// the frontier immediately.
    #[serde(default)]
    pub blocking: Vec<String>,

    /// What the waypoint's resolution receipt is expected to contain.
    /// Used by future Aegis integration to detect trajectory divergence
    /// when actual outcomes don't match. Optional — some waypoints are
    /// open-ended exploration where an expected outcome would be
    /// premature.
    #[serde(default)]
    pub expected_outcome: Option<String>,

    /// Resolution state. `None` while the waypoint is unresolved
    /// (frontier or fog); `Some` when the dispatched work completed.
    #[serde(default)]
    pub resolution: Option<WaypointResolution>,
}

/// A resolved waypoint's outcome. Captured when the dispatched work
/// completes; the resolution receipt (in the future) references this
/// snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaypointResolution {
    /// Wall-clock time the waypoint resolved.
    pub resolved_at: DateTime<Utc>,

    /// One-line outcome summary. What was learned, decided, or produced.
    pub outcome_summary: String,

    /// Receipt id (or entry hash) of the `arc:waypoint:resolved` receipt
    /// that anchored this resolution on chain. Optional today because
    /// receipt emission for map primitives hasn't landed yet; will be
    /// required once the receipt families are live.
    #[serde(default)]
    pub resolution_receipt_id: Option<String>,
}

/// A proposed destination for a trajectory map. Multiple hypotheses may
/// coexist (proposed but not-yet-accepted, or accepted-then-superseded);
/// the current destination is a query over this vector — see
/// `WorkArc::current_destination`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestinationHypothesis {
    /// Stable id within the parent WorkArc.
    pub id: String,

    /// Description of the target — spec artifact reference, code-change
    /// target, operator-facing goal. Free-form today; will type-check
    /// against ARTIFACT-LIBRARY in the future.
    pub description: String,

    /// Wall-clock time the hypothesis was proposed.
    pub proposed_at: DateTime<Utc>,

    /// Whether an operator signature has accepted this hypothesis. A
    /// hypothesis can be proposed but unaccepted (the substrate has
    /// noted a candidate direction; the operator hasn't confirmed) —
    /// which is a valid state.
    #[serde(default)]
    pub accepted: bool,

    /// If this hypothesis has been superseded by a later one, the id
    /// of the superseding hypothesis. `None` while current.
    #[serde(default)]
    pub superseded_by: Option<String>,
}

impl WorkArc {
    /// True if this arc has grown into a map — has any waypoints OR any
    /// destination hypotheses. Arc-shaped work (the vast majority of
    /// WorkArcs) returns false; map-shaped work returns true.
    pub fn is_map_shaped(&self) -> bool {
        !self.waypoints.is_empty() || !self.destination_hypotheses.is_empty()
    }

    /// Waypoints currently takable — empty `blocking` set AND unresolved.
    /// This is the primary "what can we do next in this map" query.
    pub fn frontier(&self) -> Vec<&Waypoint> {
        self.waypoints
            .iter()
            .filter(|t| t.resolution.is_none() && t.blocking.is_empty())
            .collect()
    }

    /// Waypoints in fog — non-empty `blocking` set AND unresolved. Named
    /// uncertainty awaiting blocker resolution. Legitimate state per
    /// the sketch (not a defect).
    pub fn fog(&self) -> Vec<&Waypoint> {
        self.waypoints
            .iter()
            .filter(|t| t.resolution.is_none() && !t.blocking.is_empty())
            .collect()
    }

    /// Waypoints that have resolved. Contributes to the trajectory
    /// projection Aegis will observe.
    pub fn resolved_waypoints(&self) -> Vec<&Waypoint> {
        self.waypoints
            .iter()
            .filter(|t| t.resolution.is_some())
            .collect()
    }

    /// The current destination, if the trajectory has converged enough
    /// to name one. Query definition: the most recent accepted
    /// hypothesis that has no `superseded_by`. Returns `None` when the
    /// map is in pure-fog state (no accepted destination yet), which is
    /// a valid state per the sketch.
    ///
    /// "Most recent" is by position in the vector — hypotheses are
    /// appended in chronological order, so the last matching entry
    /// wins.
    pub fn current_destination(&self) -> Option<&DestinationHypothesis> {
        self.destination_hypotheses
            .iter()
            .rev()
            .find(|h| h.accepted && h.superseded_by.is_none())
    }

    /// Look up a waypoint by id. Utility for blocking-set resolution and
    /// operator queries.
    pub fn waypoint_by_id(&self, id: &str) -> Option<&Waypoint> {
        self.waypoints.iter().find(|t| t.id == id)
    }

    /// Look up a destination hypothesis by id.
    pub fn destination_by_id(&self, id: &str) -> Option<&DestinationHypothesis> {
        self.destination_hypotheses.iter().find(|h| h.id == id)
    }

    /// True if the map has reached a terminal state (settled or
    /// abandoned). Mutations that would advance map state error with
    /// `MapAlreadySettled` when this returns true.
    pub fn is_settled(&self) -> bool {
        !matches!(self.settlement, SettlementState::Open)
    }
}

// ── Trajectory-map settlement + receipt-shape helpers (A2) ─────────────
//
// The methods below mutate WorkArc AND return a `MapReceipt` describing
// the event+detail the caller should pipe through `emit_receipt`. This
// preserves the pure-data spirit of WorkArc (no audit-store access from
// context.rs) while giving the future dispatch layer a single canonical
// place to look up "what does opening a waypoint look like on the chain."
//
// Receipt event names follow the RESERVED_RECEIPT_PREFIXES additions in
// crates/zp-server/src/substrate_validate.rs (commit 0389792):
//   arc:map:destination_proposed
//   arc:map:destination_accepted
//   arc:map:destination_superseded
//   arc:map:settled_with_destination
//   arc:map:settled_without_destination
//   arc:map:abandoned
//   arc:waypoint:opened
//   arc:waypoint:resolved
//
// Timestamps are caller-provided (parameter `now: DateTime<Utc>`) so
// tests can be deterministic and callers control the anchor time.

/// Terminal-state marker for a trajectory map. `Open` is the working
/// state (default); the three variants below are the three ways a map
/// closes per TRAJECTORY-MAP-PRIMITIVE-2026-08 §"Closing a map".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
#[derive(Default)]
pub enum SettlementState {
    /// Map is still working (or arc-shaped — same variant covers both).
    #[default]
    Open,
    /// Destination reached and signed. Downstream work proceeds under
    /// a new arc; this map is preserved as evidence.
    SettledWithDestination {
        destination_id: String,
        settled_at: DateTime<Utc>,
    },
    /// Exploration converged; operator learned enough about the heading
    /// area to close the map without a destination. Rationale is
    /// operator-authored — what was learned, why no destination
    /// crystallized.
    SettledWithoutDestination {
        rationale: String,
        settled_at: DateTime<Utc>,
    },
    /// Map closed without settlement — operator changed priorities, the
    /// space turned out to be different than expected, etc. Rationale
    /// distinguishes abandonment-with-reason from silent dropping.
    Abandoned {
        rationale: String,
        abandoned_at: DateTime<Utc>,
    },
}


/// The event+detail pair a WorkArc mutation produces for chain
/// anchoring. The caller (typically the dispatch layer) pipes this
/// through `emit_receipt(event, Some(detail))` to actually write to
/// the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapReceipt {
    pub event: String,
    pub detail: String,
}

/// Errors from map-lifecycle mutations. Every method that could fail
/// returns `Result<MapReceipt, MapError>`; the caller decides whether
/// to propagate, escalate, or narrate the failure.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum MapError {
    #[error("waypoint id already exists in this arc: {0}")]
    DuplicateWaypoint(String),
    #[error("waypoint not found in this arc: {0}")]
    WaypointNotFound(String),
    #[error("waypoint already resolved: {0}")]
    WaypointAlreadyResolved(String),
    #[error("destination hypothesis id already exists in this arc: {0}")]
    DuplicateDestination(String),
    #[error("destination not found in this arc: {0}")]
    DestinationNotFound(String),
    #[error("destination not accepted (cannot settle on unaccepted hypothesis): {0}")]
    DestinationNotAccepted(String),
    #[error("destination already superseded: {0}")]
    DestinationAlreadySuperseded(String),
    #[error("map is already settled or abandoned; mutation refused")]
    MapAlreadySettled,
}

impl WorkArc {
    /// Open a new waypoint. Waypoint id must be unique within this arc.
    /// Errors on duplicate id or if the map is already settled.
    pub fn open_waypoint(
        &mut self,
        waypoint: Waypoint,
    ) -> Result<MapReceipt, MapError> {
        if self.is_settled() {
            return Err(MapError::MapAlreadySettled);
        }
        if self.waypoints.iter().any(|t| t.id == waypoint.id) {
            return Err(MapError::DuplicateWaypoint(waypoint.id));
        }
        let id = waypoint.id.clone();
        let waypoint_kind = waypoint.waypoint_kind;
        let blocking = waypoint.blocking.join(",");
        let rationale = waypoint.rationale.clone();
        self.waypoints.push(waypoint);
        let type_str = match waypoint_kind {
            WaypointKind::Research => "research",
            WaypointKind::Prototype => "prototype",
            WaypointKind::Grilling => "grilling",
            WaypointKind::Task => "task",
        };
        Ok(MapReceipt {
            event: "arc:waypoint:opened".to_string(),
            detail: format!(
                "id={}, type={}, blocking=[{}], rationale={}",
                id, type_str, blocking, rationale
            ),
        })
    }

    /// Resolve a waypoint. Errors if the waypoint doesn't exist, is
    /// already resolved, or if the map is already settled.
    pub fn resolve_waypoint(
        &mut self,
        id: &str,
        outcome_summary: String,
        now: DateTime<Utc>,
    ) -> Result<MapReceipt, MapError> {
        if self.is_settled() {
            return Err(MapError::MapAlreadySettled);
        }
        let waypoint = self
            .waypoints
            .iter_mut()
            .find(|t| t.id == id)
            .ok_or_else(|| MapError::WaypointNotFound(id.to_string()))?;
        if waypoint.resolution.is_some() {
            return Err(MapError::WaypointAlreadyResolved(id.to_string()));
        }
        waypoint.resolution = Some(WaypointResolution {
            resolved_at: now,
            outcome_summary: outcome_summary.clone(),
            resolution_receipt_id: None,
        });
        Ok(MapReceipt {
            event: "arc:waypoint:resolved".to_string(),
            detail: format!("id={}, outcome={}", id, outcome_summary),
        })
    }

    /// Propose a destination hypothesis. Hypothesis id must be unique.
    /// The hypothesis is stored `accepted: false`; a subsequent
    /// `accept_destination` promotes it. Errors on duplicate id or
    /// settled map.
    pub fn propose_destination(
        &mut self,
        hypothesis: DestinationHypothesis,
    ) -> Result<MapReceipt, MapError> {
        if self.is_settled() {
            return Err(MapError::MapAlreadySettled);
        }
        if self.destination_hypotheses.iter().any(|h| h.id == hypothesis.id) {
            return Err(MapError::DuplicateDestination(hypothesis.id));
        }
        let id = hypothesis.id.clone();
        let description = hypothesis.description.clone();
        // Force accepted=false on proposal — acceptance is a separate ceremony.
        let mut h = hypothesis;
        h.accepted = false;
        h.superseded_by = None;
        self.destination_hypotheses.push(h);
        Ok(MapReceipt {
            event: "arc:map:destination_proposed".to_string(),
            detail: format!("id={}, description={}", id, description),
        })
    }

    /// Accept a proposed destination. The hypothesis must exist, not
    /// be superseded, and the map must not be settled. Idempotent —
    /// accepting an already-accepted hypothesis succeeds without
    /// changing state (but still emits a receipt for the operator's
    /// signature).
    pub fn accept_destination(
        &mut self,
        id: &str,
    ) -> Result<MapReceipt, MapError> {
        if self.is_settled() {
            return Err(MapError::MapAlreadySettled);
        }
        let hypothesis = self
            .destination_hypotheses
            .iter_mut()
            .find(|h| h.id == id)
            .ok_or_else(|| MapError::DestinationNotFound(id.to_string()))?;
        if hypothesis.superseded_by.is_some() {
            return Err(MapError::DestinationAlreadySuperseded(id.to_string()));
        }
        hypothesis.accepted = true;
        Ok(MapReceipt {
            event: "arc:map:destination_accepted".to_string(),
            detail: format!("id={}", id),
        })
    }

    /// Supersede a destination with a newer one. Both must exist; the
    /// superseder must not itself be superseded. Marks the older as
    /// `superseded_by = new_id`. Emits the receipt naming both.
    pub fn supersede_destination(
        &mut self,
        old_id: &str,
        new_id: &str,
    ) -> Result<MapReceipt, MapError> {
        if self.is_settled() {
            return Err(MapError::MapAlreadySettled);
        }
        // Both must exist.
        if !self.destination_hypotheses.iter().any(|h| h.id == new_id) {
            return Err(MapError::DestinationNotFound(new_id.to_string()));
        }
        let old = self
            .destination_hypotheses
            .iter_mut()
            .find(|h| h.id == old_id)
            .ok_or_else(|| MapError::DestinationNotFound(old_id.to_string()))?;
        if old.superseded_by.is_some() {
            return Err(MapError::DestinationAlreadySuperseded(old_id.to_string()));
        }
        old.superseded_by = Some(new_id.to_string());
        Ok(MapReceipt {
            event: "arc:map:destination_superseded".to_string(),
            detail: format!("old_id={}, new_id={}", old_id, new_id),
        })
    }

    /// Settle the map with an accepted destination. Terminal state
    /// transition. The destination must exist and be `accepted` and
    /// not superseded.
    pub fn settle_with_destination(
        &mut self,
        destination_id: &str,
        now: DateTime<Utc>,
    ) -> Result<MapReceipt, MapError> {
        if self.is_settled() {
            return Err(MapError::MapAlreadySettled);
        }
        let hypothesis = self
            .destination_hypotheses
            .iter()
            .find(|h| h.id == destination_id)
            .ok_or_else(|| MapError::DestinationNotFound(destination_id.to_string()))?;
        if hypothesis.superseded_by.is_some() {
            return Err(MapError::DestinationAlreadySuperseded(
                destination_id.to_string(),
            ));
        }
        if !hypothesis.accepted {
            return Err(MapError::DestinationNotAccepted(destination_id.to_string()));
        }
        self.settlement = SettlementState::SettledWithDestination {
            destination_id: destination_id.to_string(),
            settled_at: now,
        };
        Ok(MapReceipt {
            event: "arc:map:settled_with_destination".to_string(),
            detail: format!("destination_id={}", destination_id),
        })
    }

    /// Settle the map without a destination. Exploration converged;
    /// no build follows. Rationale is operator-authored, captures what
    /// was learned about the heading area.
    pub fn settle_without_destination(
        &mut self,
        rationale: String,
        now: DateTime<Utc>,
    ) -> Result<MapReceipt, MapError> {
        if self.is_settled() {
            return Err(MapError::MapAlreadySettled);
        }
        let detail = format!("rationale={}", rationale);
        self.settlement = SettlementState::SettledWithoutDestination {
            rationale,
            settled_at: now,
        };
        Ok(MapReceipt {
            event: "arc:map:settled_without_destination".to_string(),
            detail,
        })
    }

    /// Abandon the map. Rationale distinguishes abandonment-with-reason
    /// from silent dropping. Terminal state; no further mutations.
    pub fn abandon_map(
        &mut self,
        rationale: String,
        now: DateTime<Utc>,
    ) -> Result<MapReceipt, MapError> {
        if self.is_settled() {
            return Err(MapError::MapAlreadySettled);
        }
        let detail = format!("rationale={}", rationale);
        self.settlement = SettlementState::Abandoned {
            rationale,
            abandoned_at: now,
        };
        Ok(MapReceipt {
            event: "arc:map:abandoned".to_string(),
            detail,
        })
    }
}

#[cfg(test)]
mod ground_finding_tests {
    use super::*;

    /// Fixtures are verbatim from the operator's chain on 2026-08-06 rather
    /// than invented. `GroundFinding::parse` reads a format defined in
    /// `zp-server`'s `bedrock` module, and a parser written against a
    /// remembered shape is the seam that breaks silently — it yields `None`,
    /// the section renders empty, and an intact-looking substrate is
    /// indistinguishable from one nothing checked.
    const VERIFIED: &str =
        "invariant:vault_custody:verified severity=ok vault holds 176 secrets";
    const VIOLATED: &str = "invariant:vault_custody:violated severity=CRITICAL \
         the vault holds nothing, on an established substrate — custody was set \
         up and has been lost, or was never completed";
    /// Emitted before `emit_tool_receipt` carried detail in the event string.
    /// These are on the chain permanently — forward-only recovery — so the
    /// parser has to keep reading them.
    const BARE_LEGACY: &str = "invariant:vault_persisted:verified";

    fn at(secs_ago: i64) -> (DateTime<Utc>, DateTime<Utc>) {
        let now = Utc::now();
        (now - chrono::Duration::seconds(secs_ago), now)
    }

    #[test]
    fn parses_a_verified_receipt() {
        let (obs, now) = at(0);
        let g = GroundFinding::parse(VERIFIED, obs, now).expect("should parse");
        assert_eq!(g.invariant, "vault_custody");
        assert!(g.holds);
        assert!(!g.is_violation());
        assert_eq!(g.severity, "ok");
        assert_eq!(g.detail, "vault holds 176 secrets");
    }

    #[test]
    fn parses_a_violation_with_its_detail_and_age() {
        let (obs, now) = at(3600);
        let g = GroundFinding::parse(VIOLATED, obs, now).expect("should parse");
        assert_eq!(g.invariant, "vault_custody");
        assert!(g.is_violation());
        assert_eq!(g.severity, "CRITICAL");
        assert!(g.detail.starts_with("the vault holds nothing"));
        assert_eq!(g.age_secs, 3600);
    }

    /// An invariant name containing no colon must not be confused with the
    /// verdict segment — `rsplit_once` takes the *last* colon, so a future
    /// namespaced name like `vault:custody` still parses correctly.
    #[test]
    fn namespaced_invariant_names_keep_their_colons() {
        let (obs, now) = at(0);
        let g = GroundFinding::parse("invariant:vault:custody:violated severity=CRITICAL x", obs, now)
            .expect("should parse");
        assert_eq!(g.invariant, "vault:custody");
        assert!(g.is_violation());
    }

    #[test]
    fn legacy_payloadless_receipts_still_parse() {
        let (obs, now) = at(0);
        let g = GroundFinding::parse(BARE_LEGACY, obs, now).expect("should parse");
        assert_eq!(g.invariant, "vault_persisted");
        assert!(g.holds);
        assert_eq!(g.severity, "ok");
        assert!(g.detail.is_empty());
    }

    /// Unrecognised shapes yield `None` rather than a plausible-looking
    /// finding. A malformed receipt should be invisible here and caught by the
    /// receipt-type inventory — not reshaped into something that reads as
    /// authoritative in Tier 1.
    #[test]
    fn unrecognised_shapes_are_rejected() {
        let (obs, now) = at(0);
        for bad in [
            "officer:sen:security:unauthorized_listener detail",
            "invariant:vault_custody:maybe severity=ok x",
            "invariant:no_verdict",
            "",
        ] {
            assert!(
                GroundFinding::parse(bad, obs, now).is_none(),
                "should not have parsed: {bad:?}"
            );
        }
    }

    /// The composition record must distinguish "checked and clean" from
    /// "nothing checked" — a cycle with no ground findings is not a healthy
    /// substrate, it is one where the premises were never examined.
    #[test]
    fn ground_hash_is_empty_only_when_nothing_was_checked() {
        let (obs, now) = at(0);
        let g = GroundFinding::parse(VERIFIED, obs, now).unwrap();
        assert!(CompositionSummary::hash_ground(&[]).is_empty());
        assert!(!CompositionSummary::hash_ground(&[g]).is_empty());
    }
}

#[cfg(test)]
mod trajectory_map_tests {
    use super::*;

    fn empty_arc() -> WorkArc {
        WorkArc {
            progress: String::new(),
            cycles_completed: 0,
            max_cycles: 10,
            tool_history: Vec::new(),
            directive: None,
            stall_count: 0,
            waypoints: Vec::new(),
            destination_hypotheses: Vec::new(),
            settlement: SettlementState::Open,
        }
    }

    fn t0() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-08-02T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn mk_dest(id: &str, description: &str) -> DestinationHypothesis {
        DestinationHypothesis {
            id: id.to_string(),
            description: description.to_string(),
            proposed_at: t0(),
            accepted: false,
            superseded_by: None,
        }
    }

    fn mk_waypoint(id: &str, blocking: Vec<&str>) -> Waypoint {
        Waypoint {
            id: id.to_string(),
            waypoint_kind: WaypointKind::Research,
            rationale: format!("test waypoint {}", id),
            blocking: blocking.into_iter().map(|s| s.to_string()).collect(),
            expected_outcome: None,
            resolution: None,
        }
    }

    fn mk_resolution() -> WaypointResolution {
        WaypointResolution {
            resolved_at: Utc::now(),
            outcome_summary: "resolved".to_string(),
            resolution_receipt_id: None,
        }
    }

    #[test]
    fn empty_arc_is_not_map_shaped() {
        assert!(!empty_arc().is_map_shaped());
    }

    #[test]
    fn arc_with_waypoint_is_map_shaped() {
        let mut a = empty_arc();
        a.waypoints.push(mk_waypoint("t1", vec![]));
        assert!(a.is_map_shaped());
    }

    #[test]
    fn arc_with_only_destination_hypothesis_is_map_shaped() {
        let mut a = empty_arc();
        a.destination_hypotheses.push(DestinationHypothesis {
            id: "d1".to_string(),
            description: "target".to_string(),
            proposed_at: Utc::now(),
            accepted: false,
            superseded_by: None,
        });
        assert!(a.is_map_shaped());
    }

    #[test]
    fn frontier_contains_only_unblocked_unresolved_waypoints() {
        let mut a = empty_arc();
        a.waypoints.push(mk_waypoint("t1", vec![]));         // frontier
        a.waypoints.push(mk_waypoint("t2", vec!["t1"]));      // fog
        let mut t3 = mk_waypoint("t3", vec![]);
        t3.resolution = Some(mk_resolution());            // resolved
        a.waypoints.push(t3);

        let frontier: Vec<&str> = a.frontier().iter().map(|t| t.id.as_str()).collect();
        assert_eq!(frontier, vec!["t1"]);
    }

    #[test]
    fn fog_contains_only_blocked_unresolved_waypoints() {
        let mut a = empty_arc();
        a.waypoints.push(mk_waypoint("t1", vec![]));         // frontier
        a.waypoints.push(mk_waypoint("t2", vec!["t1"]));      // fog
        a.waypoints.push(mk_waypoint("t3", vec!["t1", "t2"])); // fog

        let fog: Vec<&str> = a.fog().iter().map(|t| t.id.as_str()).collect();
        assert_eq!(fog, vec!["t2", "t3"]);
    }

    #[test]
    fn resolved_waypoint_appears_in_neither_frontier_nor_fog() {
        let mut a = empty_arc();
        let mut t = mk_waypoint("t1", vec![]);
        t.resolution = Some(mk_resolution());
        a.waypoints.push(t);

        assert!(a.frontier().is_empty());
        assert!(a.fog().is_empty());
        assert_eq!(a.resolved_waypoints().len(), 1);
    }

    #[test]
    fn current_destination_returns_none_when_no_hypothesis_accepted() {
        let mut a = empty_arc();
        a.destination_hypotheses.push(DestinationHypothesis {
            id: "d1".to_string(),
            description: "candidate".to_string(),
            proposed_at: Utc::now(),
            accepted: false,       // proposed but not accepted
            superseded_by: None,
        });
        assert!(a.current_destination().is_none());
    }

    #[test]
    fn current_destination_returns_accepted_unsuperseded() {
        let mut a = empty_arc();
        a.destination_hypotheses.push(DestinationHypothesis {
            id: "d1".to_string(),
            description: "first".to_string(),
            proposed_at: Utc::now(),
            accepted: true,
            superseded_by: None,
        });
        assert_eq!(a.current_destination().map(|h| h.id.as_str()), Some("d1"));
    }

    #[test]
    fn current_destination_skips_superseded_hypothesis() {
        let mut a = empty_arc();
        a.destination_hypotheses.push(DestinationHypothesis {
            id: "d1".to_string(),
            description: "first".to_string(),
            proposed_at: Utc::now(),
            accepted: true,
            superseded_by: Some("d2".to_string()),
        });
        a.destination_hypotheses.push(DestinationHypothesis {
            id: "d2".to_string(),
            description: "second".to_string(),
            proposed_at: Utc::now(),
            accepted: true,
            superseded_by: None,
        });
        assert_eq!(a.current_destination().map(|h| h.id.as_str()), Some("d2"));
    }

    #[test]
    fn current_destination_prefers_latest_when_multiple_current() {
        // Guards the "most recent by position" semantic — if two
        // hypotheses are both accepted+unsuperseded (should be rare;
        // suggests ceremony bug), we pick the latest-appended.
        let mut a = empty_arc();
        a.destination_hypotheses.push(DestinationHypothesis {
            id: "d1".to_string(),
            description: "earlier".to_string(),
            proposed_at: Utc::now(),
            accepted: true,
            superseded_by: None,
        });
        a.destination_hypotheses.push(DestinationHypothesis {
            id: "d2".to_string(),
            description: "later".to_string(),
            proposed_at: Utc::now(),
            accepted: true,
            superseded_by: None,
        });
        assert_eq!(a.current_destination().map(|h| h.id.as_str()), Some("d2"));
    }

    #[test]
    fn waypoint_by_id_lookup() {
        let mut a = empty_arc();
        a.waypoints.push(mk_waypoint("t1", vec![]));
        a.waypoints.push(mk_waypoint("t2", vec![]));
        assert!(a.waypoint_by_id("t1").is_some());
        assert!(a.waypoint_by_id("t2").is_some());
        assert!(a.waypoint_by_id("t3").is_none());
    }

    #[test]
    fn destination_by_id_lookup() {
        let mut a = empty_arc();
        a.destination_hypotheses.push(DestinationHypothesis {
            id: "d1".to_string(),
            description: "target".to_string(),
            proposed_at: Utc::now(),
            accepted: false,
            superseded_by: None,
        });
        assert!(a.destination_by_id("d1").is_some());
        assert!(a.destination_by_id("d2").is_none());
    }

    #[test]
    fn workarc_deserializes_without_new_fields() {
        // Guards backward compat: a serialized WorkArc from before
        // the trajectory-map extension landed should still deserialize
        // (missing fields default to empty vecs, settlement = Open).
        let json = r#"{
            "progress": "",
            "cycles_completed": 0,
            "max_cycles": 10,
            "tool_history": [],
            "directive": null,
            "stall_count": 0
        }"#;
        let arc: WorkArc = serde_json::from_str(json).expect("deserialize");
        assert!(!arc.is_map_shaped());
        assert!(arc.waypoints.is_empty());
        assert!(arc.destination_hypotheses.is_empty());
        assert_eq!(arc.settlement, SettlementState::Open);
        assert!(!arc.is_settled());
    }

    // ── Lifecycle mutations + receipt-shape helpers (A2) ───────────

    #[test]
    fn open_waypoint_appends_and_returns_receipt() {
        let mut a = empty_arc();
        let r = a.open_waypoint(mk_waypoint("t1", vec![])).unwrap();
        assert_eq!(r.event, "arc:waypoint:opened");
        assert!(r.detail.contains("id=t1"));
        assert!(r.detail.contains("type=research"));
        assert_eq!(a.waypoints.len(), 1);
    }

    #[test]
    fn open_waypoint_rejects_duplicate_id() {
        let mut a = empty_arc();
        a.open_waypoint(mk_waypoint("t1", vec![])).unwrap();
        let err = a.open_waypoint(mk_waypoint("t1", vec![])).unwrap_err();
        assert_eq!(err, MapError::DuplicateWaypoint("t1".to_string()));
    }

    #[test]
    fn open_waypoint_rejected_on_settled_map() {
        let mut a = empty_arc();
        a.abandon_map("done".to_string(), t0()).unwrap();
        let err = a.open_waypoint(mk_waypoint("t1", vec![])).unwrap_err();
        assert_eq!(err, MapError::MapAlreadySettled);
    }

    #[test]
    fn resolve_waypoint_marks_resolution_and_returns_receipt() {
        let mut a = empty_arc();
        a.open_waypoint(mk_waypoint("t1", vec![])).unwrap();
        let r = a
            .resolve_waypoint("t1", "found it".to_string(), t0())
            .unwrap();
        assert_eq!(r.event, "arc:waypoint:resolved");
        assert!(r.detail.contains("id=t1"));
        assert!(r.detail.contains("outcome=found it"));
        assert!(a.waypoint_by_id("t1").unwrap().resolution.is_some());
    }

    #[test]
    fn resolve_waypoint_not_found() {
        let mut a = empty_arc();
        let err = a
            .resolve_waypoint("nope", "x".to_string(), t0())
            .unwrap_err();
        assert_eq!(err, MapError::WaypointNotFound("nope".to_string()));
    }

    #[test]
    fn resolve_waypoint_already_resolved() {
        let mut a = empty_arc();
        a.open_waypoint(mk_waypoint("t1", vec![])).unwrap();
        a.resolve_waypoint("t1", "first".to_string(), t0()).unwrap();
        let err = a
            .resolve_waypoint("t1", "second".to_string(), t0())
            .unwrap_err();
        assert_eq!(err, MapError::WaypointAlreadyResolved("t1".to_string()));
    }

    #[test]
    fn propose_destination_appends_and_forces_unaccepted() {
        let mut a = empty_arc();
        let mut h = mk_dest("d1", "the target");
        h.accepted = true; // caller lies; propose_destination must reset
        let r = a.propose_destination(h).unwrap();
        assert_eq!(r.event, "arc:map:destination_proposed");
        assert!(r.detail.contains("id=d1"));
        assert!(r.detail.contains("description=the target"));
        // Even though caller passed accepted=true, propose forces false.
        assert!(!a.destination_by_id("d1").unwrap().accepted);
    }

    #[test]
    fn propose_destination_rejects_duplicate() {
        let mut a = empty_arc();
        a.propose_destination(mk_dest("d1", "x")).unwrap();
        let err = a.propose_destination(mk_dest("d1", "y")).unwrap_err();
        assert_eq!(err, MapError::DuplicateDestination("d1".to_string()));
    }

    #[test]
    fn accept_destination_flips_flag_and_returns_receipt() {
        let mut a = empty_arc();
        a.propose_destination(mk_dest("d1", "target")).unwrap();
        let r = a.accept_destination("d1").unwrap();
        assert_eq!(r.event, "arc:map:destination_accepted");
        assert!(r.detail.contains("id=d1"));
        assert!(a.destination_by_id("d1").unwrap().accepted);
        assert_eq!(a.current_destination().map(|h| h.id.as_str()), Some("d1"));
    }

    #[test]
    fn accept_destination_not_found() {
        let mut a = empty_arc();
        let err = a.accept_destination("nope").unwrap_err();
        assert_eq!(err, MapError::DestinationNotFound("nope".to_string()));
    }

    #[test]
    fn accept_destination_rejects_superseded() {
        let mut a = empty_arc();
        a.propose_destination(mk_dest("d1", "old")).unwrap();
        a.propose_destination(mk_dest("d2", "new")).unwrap();
        a.supersede_destination("d1", "d2").unwrap();
        let err = a.accept_destination("d1").unwrap_err();
        assert_eq!(
            err,
            MapError::DestinationAlreadySuperseded("d1".to_string())
        );
    }

    #[test]
    fn supersede_destination_marks_old_and_returns_receipt() {
        let mut a = empty_arc();
        a.propose_destination(mk_dest("d1", "old")).unwrap();
        a.propose_destination(mk_dest("d2", "new")).unwrap();
        let r = a.supersede_destination("d1", "d2").unwrap();
        assert_eq!(r.event, "arc:map:destination_superseded");
        assert!(r.detail.contains("old_id=d1"));
        assert!(r.detail.contains("new_id=d2"));
        assert_eq!(
            a.destination_by_id("d1").unwrap().superseded_by.as_deref(),
            Some("d2")
        );
    }

    #[test]
    fn supersede_destination_errors_when_new_missing() {
        let mut a = empty_arc();
        a.propose_destination(mk_dest("d1", "old")).unwrap();
        let err = a.supersede_destination("d1", "d2").unwrap_err();
        assert_eq!(err, MapError::DestinationNotFound("d2".to_string()));
    }

    #[test]
    fn settle_with_destination_requires_accepted() {
        let mut a = empty_arc();
        a.propose_destination(mk_dest("d1", "target")).unwrap();
        // d1 exists but not accepted yet.
        let err = a.settle_with_destination("d1", t0()).unwrap_err();
        assert_eq!(err, MapError::DestinationNotAccepted("d1".to_string()));
        // After acceptance, settle succeeds.
        a.accept_destination("d1").unwrap();
        let r = a.settle_with_destination("d1", t0()).unwrap();
        assert_eq!(r.event, "arc:map:settled_with_destination");
        assert!(r.detail.contains("destination_id=d1"));
        assert!(a.is_settled());
    }

    #[test]
    fn settle_with_destination_rejects_superseded() {
        let mut a = empty_arc();
        a.propose_destination(mk_dest("d1", "old")).unwrap();
        a.propose_destination(mk_dest("d2", "new")).unwrap();
        a.accept_destination("d1").unwrap();
        a.supersede_destination("d1", "d2").unwrap();
        let err = a.settle_with_destination("d1", t0()).unwrap_err();
        assert_eq!(
            err,
            MapError::DestinationAlreadySuperseded("d1".to_string())
        );
    }

    #[test]
    fn settle_without_destination_terminates() {
        let mut a = empty_arc();
        let r = a
            .settle_without_destination(
                "exploration converged, no build".to_string(),
                t0(),
            )
            .unwrap();
        assert_eq!(r.event, "arc:map:settled_without_destination");
        assert!(r.detail.contains("rationale=exploration converged"));
        assert!(a.is_settled());
        match a.settlement {
            SettlementState::SettledWithoutDestination { ref rationale, .. } => {
                assert!(rationale.contains("converged"));
            }
            _ => panic!("expected SettledWithoutDestination"),
        }
    }

    #[test]
    fn abandon_map_terminates() {
        let mut a = empty_arc();
        let r = a
            .abandon_map("space turned out different".to_string(), t0())
            .unwrap();
        assert_eq!(r.event, "arc:map:abandoned");
        assert!(r.detail.contains("rationale=space turned out different"));
        assert!(a.is_settled());
        match a.settlement {
            SettlementState::Abandoned { ref rationale, .. } => {
                assert!(rationale.contains("different"));
            }
            _ => panic!("expected Abandoned"),
        }
    }

    #[test]
    fn settled_map_refuses_further_mutations() {
        let mut a = empty_arc();
        a.settle_without_destination("done exploring".to_string(), t0())
            .unwrap();
        assert_eq!(
            a.open_waypoint(mk_waypoint("t1", vec![])).unwrap_err(),
            MapError::MapAlreadySettled
        );
        assert_eq!(
            a.resolve_waypoint("t1", "x".to_string(), t0()).unwrap_err(),
            MapError::MapAlreadySettled
        );
        assert_eq!(
            a.propose_destination(mk_dest("d1", "x")).unwrap_err(),
            MapError::MapAlreadySettled
        );
        assert_eq!(
            a.abandon_map("try again".to_string(), t0()).unwrap_err(),
            MapError::MapAlreadySettled
        );
    }

    #[test]
    fn full_lifecycle_walkthrough() {
        // Represents a plausible map lifecycle end-to-end. Verifies the
        // receipt sequence a caller would emit through emit_receipt.
        let mut a = empty_arc();
        a.directive = Some("figure out how Layer 2 should behave".to_string());

        let receipts = [a.open_waypoint(mk_waypoint("t1", vec![])).unwrap(),
            a.open_waypoint(mk_waypoint("t2", vec!["t1"])).unwrap(),
            a.resolve_waypoint("t1", "found precedent".to_string(), t0())
                .unwrap(),
            a.resolve_waypoint("t2", "candidate design emerged".to_string(), t0())
                .unwrap(),
            a.propose_destination(mk_dest("d1", "the Layer 2 spec"))
                .unwrap(),
            a.accept_destination("d1").unwrap(),
            a.settle_with_destination("d1", t0()).unwrap()];

        let events: Vec<&str> = receipts.iter().map(|r| r.event.as_str()).collect();
        assert_eq!(
            events,
            vec![
                "arc:waypoint:opened",
                "arc:waypoint:opened",
                "arc:waypoint:resolved",
                "arc:waypoint:resolved",
                "arc:map:destination_proposed",
                "arc:map:destination_accepted",
                "arc:map:settled_with_destination",
            ]
        );
        assert!(a.is_settled());
    }
}

/// A tool execution result from a prior turn in the same cycle.
///
/// The Regent sees these on subsequent turns so it can reason about
/// what it did and compose a narration for the operator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    /// Which tool was called.
    pub tool: String,
    /// What it returned (pretty-printed).
    pub output: String,
    /// Whether the tool succeeded.
    pub succeeded: bool,

    /// The exact call, when this result was a refusal an operator signature
    /// would lift.
    ///
    /// Carried so the proposal that follows can be *this* call rather than a
    /// re-derivation of it. The operator then signs what was actually
    /// attempted — same tool, same parameters — instead of a second model's
    /// paraphrase of what the first one wanted.
    pub refused_call: Option<crate::intent::Enactment>,
}

/// Compressed chain entry for context window efficiency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainSnapshot {
    pub timestamp: DateTime<Utc>,
    pub action_summary: String,
    pub actor: String,
    pub signed: bool,
}

impl ChainSnapshot {
    /// Build from an AuditEntry, compressing to context-efficient form.
    pub fn from_entry(entry: &AuditEntry) -> Self {
        let action_summary = match &entry.action {
            zp_core::AuditAction::SystemEvent { event } => event.clone(),
            zp_core::AuditAction::ToolInvoked { tool_name, .. } => {
                format!("tool:{}", tool_name)
            }
            zp_core::AuditAction::ToolCompleted { tool_name, success, .. } => {
                format!("tool_done:{}:{}", tool_name, if *success { "ok" } else { "fail" })
            }
            zp_core::AuditAction::PolicyInteraction { decision_type, .. } => {
                format!("policy:{}", decision_type)
            }
            _ => "other".to_string(),
        };

        let actor = match &entry.actor {
            zp_core::ActorId::User(name) => name.clone(),
            zp_core::ActorId::Operator => "operator".to_string(),
            zp_core::ActorId::System(name) => format!("system:{}", name),
            zp_core::ActorId::Skill(name) => format!("skill:{}", name),
        };

        Self {
            timestamp: entry.timestamp,
            action_summary,
            actor,
            signed: entry.receipt.as_ref().is_some_and(|r| r.signature.is_some()),
        }
    }
}

/// Chain-event prefix for bedrock invariant results, emitted by the server's
/// `bedrock` module. Declared here because Regent is the consumer that queries
/// for it — naming it on the reading side keeps the two ends from drifting.
pub const GROUND_EVENT_PREFIX: &str = "invariant:";

/// A bedrock invariant as Regent last observed it on the chain.
///
/// # Why this is Tier 1
///
/// Bedrock invariants are not findings about the world; they are facts about
/// whether the substrate Regent is running on is intact. *Your vault is gone*
/// outranks any officer sweep result, because every downstream conclusion rests
/// on premises these describe.
///
/// The operator put it directly on 2026-08-06, after a session in which the
/// credential vault was found to have been empty for months: *"the same goes
/// for everything else Regent needs to be aware of. Her agency and
/// responsibility starts here."* An agent that cannot tell whether its own
/// substrate is whole cannot be responsible for anything built on top of it —
/// and, more practically, should be able to decline to act on premises that do
/// not hold rather than reasoning confidently over a broken foundation.
///
/// # Why read them from the chain rather than plumb them through
///
/// `bedrock::check` runs in `AppState::init` and chain-anchors each result as
/// `invariant:<name>:verified|violated`. Regent already reads the chain, so
/// surfacing these needs no new channel between server and cognitive layer —
/// the chain is the integration point, which is what §III.13 means by it being
/// truth. It also means she sees exactly what the operator sees, from the same
/// evidence, rather than a separately-maintained view that could drift.
///
/// Carries `age_secs` for the same reason `FindingSummary` does: a violation
/// observed at the last boot and one observed three days ago are different
/// claims, and the summary text is present-tense in both cases.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundFinding {
    /// Invariant name, e.g. `vault_custody`.
    pub invariant: String,
    /// True when the last observation was `:verified`.
    pub holds: bool,
    /// Severity as recorded by the emitter (`ok`, `warning`, `CRITICAL`).
    pub severity: String,
    /// Human-readable detail from the receipt.
    pub detail: String,
    /// When the invariant was last evaluated.
    pub observed_at: DateTime<Utc>,
    /// Age of that evaluation at composition time. Bedrock currently runs only
    /// at boot, so a large age means the substrate has been up a long while,
    /// not that the check is failing — worth knowing when reading a violation.
    pub age_secs: i64,
}

impl GroundFinding {
    /// Parse one `invariant:<name>:<verdict> severity=<sev> <detail>` event.
    ///
    /// Returns `None` for anything that does not match, rather than guessing.
    /// A malformed bedrock receipt should be invisible here and caught by the
    /// receipt-type inventory, not silently reshaped into a finding that reads
    /// as authoritative.
    pub fn parse(event: &str, observed_at: DateTime<Utc>, now: DateTime<Utc>) -> Option<Self> {
        let rest = event.strip_prefix("invariant:")?;
        // Split off the payload; the verdict is the last colon-segment of the
        // prefix, so parse the prefix and payload separately.
        let (prefix, payload) = match rest.split_once(' ') {
            Some((p, d)) => (p, d),
            None => (rest, ""),
        };
        let (name, verdict) = prefix.rsplit_once(':')?;
        let holds = match verdict {
            "verified" => true,
            "violated" => false,
            _ => return None,
        };

        let (severity, detail) = match payload.strip_prefix("severity=") {
            Some(tail) => match tail.split_once(' ') {
                Some((s, d)) => (s.to_string(), d.to_string()),
                None => (tail.to_string(), String::new()),
            },
            None => (
                if holds { "ok".to_string() } else { "unknown".to_string() },
                payload.to_string(),
            ),
        };

        Some(Self {
            invariant: name.to_string(),
            holds,
            severity,
            detail,
            observed_at,
            age_secs: (now - observed_at).num_seconds(),
        })
    }

    /// True when this is a violation Regent should weigh before acting.
    pub fn is_violation(&self) -> bool {
        !self.holds
    }
}

/// Compressed finding for context window efficiency.
///
/// # Recency is part of the finding
///
/// A finding is an observation made at a moment, and its summary is written in
/// the present tense — Steward's `chain_silence` reads *"No chain entries in the
/// last 78 minutes"*. Delivered without a timestamp that sentence is not a
/// stale fact, it is a **false** one: it asserts about now, and it was true
/// about then.
///
/// This type dropped `Finding::timestamp` until 2026-08-06. Observed that day: a
/// posture check reported *"std (Steward): ... no entries in last 78 minutes"*
/// alongside *"std: 12 heartbeats last hour, last seen 28 seconds ago"* — the
/// two clauses contradicted each other in one paragraph, and Regent was right
/// to render both, because nothing in her context distinguished a live
/// observation from an hour-old one. The substrate had been accurate and the
/// narration had been wrong, and the missing field was the whole difference.
///
/// Both `observed_at` and `age_secs` are carried. The absolute timestamp is the
/// ground truth; the precomputed age is what makes staleness legible without
/// asking a language model to do date arithmetic against an implicit "now",
/// which is a step it can get wrong silently.
///
/// Per `METACOGNITIVE-FIDELITY-HARNESS-2026-08.md` §4 — the `(value, source,
/// as_of)` shape, applied at the surface where its absence was observed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingSummary {
    pub officer: String,
    pub domain: String,
    pub finding_type: String,
    pub severity: String,
    pub summary: String,
    /// When the officer made this observation.
    ///
    /// `#[serde(default)]` so composition receipts written before this field
    /// existed still deserialize — the chain is append-only and those receipts
    /// are history, not a migration target.
    #[serde(default)]
    pub observed_at: Option<DateTime<Utc>>,
    /// Age of the observation, in seconds, at the moment the context was
    /// composed. Derived from `observed_at`; carried explicitly so the
    /// staleness of a present-tense summary is readable without arithmetic.
    #[serde(default)]
    pub age_secs: Option<i64>,
}

impl FindingSummary {
    /// Summarise a finding as of `now`.
    ///
    /// Takes `now` rather than reading the clock so a composed context is a
    /// deterministic function of its inputs — the same discipline
    /// `CorrectionIndex::build` follows, and what makes the composition hash
    /// reproducible for a given cycle.
    pub fn from_finding_at(f: &Finding, now: DateTime<Utc>) -> Self {
        Self {
            officer: f.officer.to_string(),
            domain: f.domain.to_string(),
            finding_type: f.finding_type.clone(),
            // Pinned spelling, not an incidental format. See `Severity`'s type
            // docs — this string is on the chain going back to the beginning.
            severity: f.severity.as_context_str().to_string(),
            summary: f.summary.clone(),
            observed_at: Some(f.timestamp),
            age_secs: Some((now - f.timestamp).num_seconds()),
        }
    }

    /// Convenience wrapper reading the wall clock. Prefer
    /// [`FindingSummary::from_finding_at`] anywhere the cycle already has a
    /// `now` in hand.
    pub fn from_finding(f: &Finding) -> Self {
        Self::from_finding_at(f, Utc::now())
    }

    /// The typed severity, or `None` if the carried string is unrecognised.
    ///
    /// Prefer [`FindingSummary::demands_attention`] and
    /// [`FindingSummary::interrupts`] over matching on this — they encode
    /// which floor governs which decision, and they fail in the safe
    /// direction on an unparseable value.
    pub fn severity_level(&self) -> Option<Severity> {
        Severity::from_context_str(&self.severity)
    }

    /// Should an in-flight cycle reason about this rather than just observe?
    ///
    /// An unrecognised severity counts as *yes*. A finding whose severity
    /// cannot be read is a defect in the composition path, and the failure
    /// that costs least is the one that wakes someone — KEEL §III.19.
    pub fn demands_attention(&self) -> bool {
        match self.severity_level() {
            Some(s) => s.demands_attention(),
            None => true,
        }
    }

    /// Should this preempt the timer, and survive compression while the
    /// operator is mid-conversation?
    ///
    /// Unlike [`FindingSummary::demands_attention`], an unrecognised severity
    /// counts as *no*. Interrupting is the costlier action, and the attention
    /// path above already guarantees a malformed finding is not silently
    /// dropped — it will be reasoned about on the next cycle either way.
    pub fn interrupts(&self) -> bool {
        self.severity_level().is_some_and(|s| s.interrupts())
    }
}

/// Operator input awaiting Regent processing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorInput {
    /// The operator's message or command.
    pub content: String,
    /// When it was received.
    pub received_at: DateTime<Utc>,
    /// Which cockpit surface it came from.
    pub source: CockpitSource,
}

/// Which cockpit surface delivered the operator input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CockpitSource {
    /// Regent conversational interface (apex observer).
    Regent,
    /// CLI command.
    Cli,
    /// Browser harness.
    Browser,
    /// Autonomous wake (no operator input — self-initiated cycle).
    Autonomous,
}

/// A fragment retrieved from the Regent's persistent memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryFragment {
    pub key: String,
    pub content: String,
    pub relevance_score: f32,
    pub stored_at: DateTime<Utc>,
}

/// Summary of an active delegation the Regent holds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationSummary {
    pub capability: String,
    pub scope: String,
    pub granted_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,

    /// Parameters this capability requires, if any.
    ///
    /// Carried on the delegation rather than declared here, because the
    /// dispatch arms in `zp-server` are the only place that knows what a tool
    /// actually reads. A fourth copy of tool knowledge in this crate would
    /// drift the way the other three did.
    ///
    /// Empty means "unknown, do not validate" rather than "takes nothing" —
    /// a delegation assembled without a contract must not cause a legitimate
    /// call to be rejected.
    #[serde(default)]
    pub required_params: Vec<String>,

    /// Parameters this capability accepts beyond the required ones.
    #[serde(default)]
    pub optional_params: Vec<String>,
}

impl DelegationSummary {
    /// Check a proposed parameter set against this capability's contract.
    ///
    /// Returns the reason it fails, or `None` if it holds. Silent when no
    /// contract is declared: absence of a contract is absence of knowledge,
    /// and refusing on that basis would break every tool not yet described.
    ///
    /// # Why an enactment is validated at all
    ///
    /// Observed 2026-08-04. Asked to record a preferred name, the compose
    /// tier produced a proposal whose enactment was
    /// `self_configure {"config": "...\"value\": \"Ken,rom\"..."}`.
    /// `self_configure` has no `config` parameter — it reads `endpoint`,
    /// `model`, `api_key`, `routing_model` — so granting it would have
    /// reached the no-parameters branch, returned the current configuration,
    /// and reported success while recording nothing. The operator's name was
    /// also corrupted inside it.
    ///
    /// `compose_proposal` checked that the *tool* was held and nothing about
    /// the parameters, so a signature could be requested for a call the tool
    /// could not perform. Unknown-field rejection catches that whole class:
    /// no schema can tell "Ken,rom" from "Kenrom", but a payload living
    /// entirely inside a field that does not exist is decidable.
    pub fn params_violation(&self, params: &serde_json::Value) -> Option<String> {
        if self.required_params.is_empty() && self.optional_params.is_empty() {
            return None;
        }
        let obj = match params.as_object() {
            Some(o) => o,
            // Null or a bare value where an object is expected.
            None if params.is_null() && self.required_params.is_empty() => return None,
            None => {
                return Some(format!(
                    "{} takes named parameters; got {}",
                    self.capability, params
                ))
            }
        };
        let unknown: Vec<&str> = obj
            .keys()
            .map(|k| k.as_str())
            .filter(|k| {
                !self.required_params.iter().any(|r| r == k)
                    && !self.optional_params.iter().any(|o| o == k)
            })
            .collect();
        if !unknown.is_empty() {
            return Some(format!(
                "{} has no parameter{} {:?} — it takes {:?}",
                self.capability,
                if unknown.len() == 1 { "" } else { "s" },
                unknown,
                [&self.required_params[..], &self.optional_params[..]].concat()
            ));
        }
        let missing: Vec<&String> = self
            .required_params
            .iter()
            .filter(|r| !obj.contains_key(r.as_str()))
            .collect();
        if !missing.is_empty() {
            return Some(format!(
                "{} requires {:?}, which {} missing",
                self.capability,
                missing,
                if missing.len() == 1 { "is" } else { "are" }
            ));
        }
        None
    }
}

// ── System Awareness ──────────────────────────────────────────────────

/// The Regent's awareness of the system she governs.
///
/// Assembled each cognitive cycle alongside chain state and findings.
/// This is the Regent's instrument panel — she perceives resource
/// pressure, running processes, loaded models, and her own background
/// tasks, then makes harmony decisions: yield to the operator, defer
/// maintenance, reclaim memory, or act on idle time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemAwareness {
    /// Seconds since the operator last interacted. The Regent uses this
    /// to distinguish "operator is active" from "system is idle."
    pub idle_secs: u64,

    /// System memory state.
    pub memory: MemoryPressure,

    /// Models currently loaded in Ollama (from /api/ps).
    /// Each entry is (model_name, size_bytes).
    pub loaded_models: Vec<LoadedModel>,

    /// Background tasks the Regent has spawned.
    pub active_tasks: Vec<BackgroundTaskStatus>,

    /// The previous session's profile, read from chain at startup.
    /// `None` on a first run, or when no prior profile is on chain.
    ///
    /// Phase 6's long window: "structural drift — invisible within any
    /// single session — becomes detectable."
    #[serde(default)]
    pub prior_session: Option<SessionProfile>,

    /// Medium-window trends across recent cycles, when enough samples
    /// exist. `None` on the first cycles of a session.
    ///
    /// Per `EXECUTION-AUTHORITY-MODEL-2026-07.md` Phase 6: the short
    /// window is this snapshot; the medium window is rolling aggregation
    /// across cycles, "where operational drift becomes visible."
    #[serde(default)]
    pub trends: Option<SystemTrends>,
}

/// A completed session's medium window, emitted at shutdown and read
/// back at startup for cross-session comparison.
///
/// Structural only — counts and deltas, no content — matching the
/// no-chain-bloat discipline the composition receipt follows.
///
/// Phase 6's worked example is "boot-to-ready time is 3x what it was
/// last epoch." That is deliberately absent: boot-to-ready is not
/// measured anywhere, and emitting a field for it would be inventing a
/// measurement. The profile carries what the medium window actually has.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionProfile {
    /// Cognitive cycles completed in that session.
    pub cycles: u64,
    /// Samples the medium window held at shutdown.
    pub samples: usize,
    /// Memory usage change across that session's window.
    pub memory_usage_delta: f64,
    /// Whether memory rose at every step.
    pub memory_monotonic_rising: bool,
    /// Change in resident model count.
    pub loaded_model_delta: i64,
    /// Change in the Regent's background task count.
    pub active_task_delta: i64,
}

/// Medium-window trends — Phase 6's rolling aggregation.
///
/// Deltas are computed oldest-to-newest across the retained window.
/// Aggregation is deliberately simple statistics, not inference, per the
/// phase's implementation note.
///
/// # What is missing, and why it is not invented here
///
/// Phase 6 names `latency_delta` and `accuracy_delta` alongside memory.
/// Neither has a source: `SystemAwareness` carries no latency and no
/// accuracy, and the only latency the Regent records lives in
/// `evaluation.rs`, off the cognitive-cycle path entirely. Adding a
/// field for either would be inventing a measurement rather than
/// aggregating one. Recorded as a tie-off in the execution-authority
/// model instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemTrends {
    /// How many cycles the window covers.
    pub samples: usize,

    /// Change in memory usage fraction across the window
    /// (newest − oldest). Positive means pressure is rising.
    pub memory_usage_delta: f64,

    /// True when memory usage rose at every step. A steady climb is a
    /// different signal from a noisy one with the same endpoints, and
    /// the endpoints alone cannot distinguish them.
    pub memory_monotonic_rising: bool,

    /// Change in the number of models resident in the inference backend.
    pub loaded_model_delta: i64,

    /// Change in the count of the Regent's own background tasks.
    pub active_task_delta: i64,
}

/// System memory pressure — the Regent's view of available resources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryPressure {
    /// Total system memory in bytes.
    pub total_bytes: u64,
    /// Available (free + reclaimable) memory in bytes.
    pub available_bytes: u64,
    /// Usage as a fraction (0.0–1.0).
    pub usage_fraction: f64,
    /// Qualitative pressure level derived from usage.
    pub level: PressureLevel,
}

/// Qualitative memory pressure — what the Regent reasons about.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PressureLevel {
    /// < 60% usage. Safe for background work.
    Low,
    /// 60–80% usage. Defer non-essential background tasks.
    Moderate,
    /// 80–90% usage. Consider unloading idle models.
    High,
    /// > 90% usage. Actively reclaim resources.
    Critical,
}

/// A model currently loaded in Ollama.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadedModel {
    pub name: String,
    pub size_bytes: u64,
    /// When this model expires from Ollama's cache (if not pinned).
    pub expires_at: Option<String>,
}

/// Status of a background task the Regent spawned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackgroundTaskStatus {
    /// What the task is doing.
    pub kind: BackgroundTaskKind,
    /// When it started.
    pub started_at: DateTime<Utc>,
    /// Progress, if known.
    pub progress: Option<String>,
}

/// Kinds of background work the Regent manages.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BackgroundTaskKind {
    /// Evaluating candidate models against the validation battery.
    ModelEvaluation,
    /// Future: other maintenance tasks.
    Maintenance(String),
}
