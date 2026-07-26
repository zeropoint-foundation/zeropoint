//! Cognitive context — the Regent's working memory for a single reasoning cycle.
//!
//! Each cycle, the Regent assembles a `CognitiveContext` from chain state,
//! officer findings, operator input, and prior memory. This context is the
//! input to the reasoning step — everything the Regent knows right now,
//! structured for the inference backend.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zp_core::AuditEntry;
use zp_officers::finding::Finding;

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
            signed: entry.receipt.as_ref().map_or(false, |r| r.signature.is_some()),
        }
    }
}

/// Compressed finding for context window efficiency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingSummary {
    pub officer: String,
    pub domain: String,
    pub finding_type: String,
    pub severity: String,
    pub summary: String,
}

impl FindingSummary {
    pub fn from_finding(f: &Finding) -> Self {
        Self {
            officer: f.officer.to_string(),
            domain: f.domain.to_string(),
            finding_type: f.finding_type.clone(),
            severity: format!("{:?}", f.severity),
            summary: f.summary.clone(),
        }
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
